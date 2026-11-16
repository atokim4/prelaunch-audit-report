import type { Action, Finding, ProbePolicy, Proof, TenantLink } from "../types.ts";
import type { FileEdit } from "./diff.ts";
import { identPart, publicRel, tableColumns, qualify, type SqlFile } from "./sql.ts";

/**
 * Patch for a table whose rows belong to an organization (team, workspace): two SECURITY DEFINER helpers
 * that read the membership table (so the membership table's own policies never recurse), and every policy
 * that let the probe's leaks through rewritten to ask "is the caller a member (or an admin) of this row's
 * organization". On the membership table, writes go to admins only and the organization and user columns
 * are locked, so nobody can join another organization or move their own row there.
 */

export interface TenantPatchContext {
  probeSql: SqlFile[];
  newMigration(slug: string): string;
}

export interface TenantDraft {
  edits: FileEdit[];
  summary: string;
  caveats: string[];
  partial?: string;
}

const PRIVILEGED =
  /^(plan|tier|role|roles|is_admin|admin|credits|balance|is_pro|is_premium|is_verified|verified|subscription\w*|stripe_\w+)$/;

const definesFunction = (sql: SqlFile[], name: string): boolean =>
  sql.some((f) => new RegExp(String.raw`function\s+(?:"?public"?\.)?"?${name}"?\s*\(`, "i").test(f.text));

/** Helper names: is_org_member / has_org_role, unless the schema already has functions with those names. */
export function helperNames(sql: SqlFile[]): { member: string; role: string } {
  const taken = definesFunction(sql, "is_org_member") || definesFunction(sql, "has_org_role");
  return taken
    ? { member: "is_member_of_org", role: "has_role_in_org" }
    : { member: "is_org_member", role: "has_org_role" };
}

function helpers(link: TenantLink, names: { member: string; role: string }, withRole: boolean): string[] {
  const m = link.members;
  const type = link.tenantKeyType;
  const table = publicRel(m.table);
  const match = `m.${identPart(m.tenantColumn)} = target_org and m.${identPart(m.userColumn)} = (select auth.uid())`;
  const out = [
    "-- Membership helpers. SECURITY DEFINER so they read the membership table without its policies",
    "-- (a policy that queries its own table recurses); search_path pinned; not callable by visitors.",
    `create or replace function public.${names.member}(target_org ${type})`,
    "returns boolean",
    "language sql stable security definer",
    "set search_path = ''",
    "as $$",
    `  select exists (select 1 from ${table} m where ${match});`,
    "$$;",
    `revoke execute on function public.${names.member}(${type}) from public, anon;`,
    `grant execute on function public.${names.member}(${type}) to authenticated;`,
  ];
  if (!withRole || !m.roleColumn || !m.adminRoles.length) return out;
  return [
    ...out,
    "",
    `create or replace function public.${names.role}(target_org ${type}, allowed text[])`,
    "returns boolean",
    "language sql stable security definer",
    "set search_path = ''",
    "as $$",
    `  select exists (select 1 from ${table} m where ${match} and m.${identPart(m.roleColumn)}::text = any (allowed));`,
    "$$;",
    `revoke execute on function public.${names.role}(${type}, text[]) from public, anon;`,
    `grant execute on function public.${names.role}(${type}, text[]) to authenticated;`,
  ];
}

const sqlArray = (values: string[]): string => `array[${values.map((v) => `'${v.replace(/'/g, "''")}'`).join(", ")}]`;

/** The column of this table that names the organization, as SQL on the row; undefined two levels down. */
function orgOf(proof: Proof, link: TenantLink, member: string): string | undefined {
  const via = link.via;
  const self = publicRel(proof.table);
  if (via.kind === "tenant") return `${member}(${identPart(link.tenantKey)})`;
  if (via.kind === "members") return `${member}(${identPart(link.members.tenantColumn)})`;
  if (via.kind === "column") return `${member}(${identPart(via.column)})`;
  if (!via.parentTenantColumn) return undefined;
  return `exists (\n    select 1 from ${publicRel(via.parent)} p\n    where p.${identPart(via.parentColumn)} = ${self}.${identPart(via.column)}\n      and public.${member}(p.${identPart(via.parentTenantColumn)})\n  )`;
}

const ROLE_OF = { anon: "anon", "other-user": "authenticated", owner: "authenticated", "non-member": "authenticated" };

/** Permissive policies for a command and role that let one of the leaks through (all of them: they OR). */
function leakingPolicies(proof: Proof): ProbePolicy[] {
  const out = new Map<string, ProbePolicy>();
  for (const leak of proof.leaks) {
    for (const policy of proof.policies) {
      if (policy.command !== leak.action && policy.command !== "all") continue;
      if (!policy.roles.includes("public") && !policy.roles.includes(ROLE_OF[leak.actor])) continue;
      out.set(policy.name, policy);
    }
  }
  return [...out.values()];
}

const COMMANDS: Action[] = ["select", "insert", "update", "delete"];

function policySql(table: string, name: string, command: Action, condition: string): string[] {
  const clause =
    command === "insert"
      ? `with check (${condition})`
      : command === "select" || command === "delete"
        ? `using (${condition})`
        : `using (${condition})\n  with check (${condition})`;
  return ["", `create policy ${identPart(name)}`, `  on ${table} for ${command}`, "  to authenticated", `  ${clause};`];
}

export function tenantPatch(finding: Finding, ctx: TenantPatchContext): TenantDraft | undefined {
  const proof = finding.proof;
  const link = proof?.tenant;
  if (!proof || !link || proof.kind !== "table" || !proof.leaks.length) return undefined;
  const names = helperNames(ctx.probeSql);
  const member = orgOf(proof, link, `public.${names.member}`);
  if (!member) return undefined;
  const m = link.members;
  const admins = m.roleColumn && m.adminRoles.length ? m.adminRoles : undefined;
  const admin = admins
    ? orgOf(proof, link, `public.${names.role}`)?.replace(/\)$/, `, ${sqlArray(admins)})`)
    : undefined;
  const via = link.via.kind;
  const table = publicRel(proof.table);
  const rlsOff = finding.rule === "rls-disabled";

  // Who may do what: members read; on the organization and membership tables only admins write (no admin
  // role in the schema: membership writes only from the server); a signed-in user may create an organization.
  const condition = (command: Action): string | undefined => {
    if (command === "select") return member;
    if (via === "members") return admin;
    if (via === "tenant") {
      if (command === "insert")
        return proof.ownerColumns.length
          ? proof.ownerColumns.map((c) => `${identPart(c)} = (select auth.uid())`).join(" or ")
          : "(select auth.uid()) is not null";
      return admin ?? member;
    }
    return member;
  };

  const leaking = rlsOff ? [] : leakingPolicies(proof);
  // Owner-only leaks (a member changing a role or plan) come through update policies.
  if (!rlsOff && proof.leaks.some((c) => c.actor === "owner")) {
    for (const p of proof.policies) if (p.command === "update" || p.command === "all") leaking.push(p);
  }
  const rewrite = [...new Map(leaking.map((p) => [p.name, p])).values()];
  if (!rlsOff && !rewrite.length && !proof.leaks.some((c) => c.column)) return undefined;

  const body: string[] = [];
  if (rlsOff) body.push(`alter table ${table} enable row level security;`);
  const made: string[] = [];
  let usesAdmin = false;
  // New names say what the rule now is; a kept name ("Users can join organizations") would describe the hole.
  const commands = rlsOff
    ? COMMANDS
    : [...new Set(rewrite.flatMap((p) => (p.command === "all" ? COMMANDS : [p.command as Action])))];
  const bare = proof.table.replace(/^public\./, "");
  const VERB: Record<Action, string> = { select: "read", insert: "add", update: "change", delete: "delete" };
  const nameOf = (command: Action, cond: string): string =>
    via === "tenant" && command === "insert"
      ? `Signed-in users can create ${bare}`
      : `${cond === admin ? "Org admins" : "Org members"} can ${VERB[command]} ${bare}`;
  for (const p of rewrite) body.push(`drop policy if exists ${identPart(p.name)} on ${table};`);
  for (const command of COMMANDS.filter((c) => commands.includes(c))) {
    const cond = condition(command);
    if (!cond) continue; // that write is left to the server (service role), which RLS does not limit
    const name = nameOf(command, cond);
    body.push(
      "",
      `drop policy if exists ${identPart(name)} on ${table};`,
      ...policySql(table, name, command, cond).slice(1),
    );
    made.push(`"${name}"`);
    if (cond === admin) usesAdmin = true;
  }
  body.unshift(...helpers(link, names, usesAdmin), "");

  // Columns nobody may change from the browser: the organization and user of a membership row; plan and
  // billing fields of the organization.
  const columns = tableColumns(ctx.probeSql, qualify(proof.table))?.map((c) => c.name);
  let locked: string[] = [];
  if (via === "members") locked = [m.tenantColumn, m.userColumn];
  else if (via === "tenant")
    locked = proof.leaks.filter((c) => c.actor === "owner" && c.column).map((c) => c.column ?? "");
  if (locked.length && columns) {
    const editable = columns.filter(
      (c) =>
        !locked.includes(c) &&
        c !== "id" &&
        !(via === "tenant" && PRIVILEGED.test(c)) &&
        !/^(created_?at|inserted_?at)$/i.test(c),
    );
    body.push("", `revoke update on ${table} from anon, authenticated;`);
    if (editable.length)
      body.push(`grant update (${editable.map(identPart).join(", ")}) on ${table} to authenticated;`);
  }

  const kind = via === "members" ? "membership" : via === "tenant" ? "organization" : "organization-owned";
  const summary = [
    `Adds \`${names.member}(org)\`${usesAdmin ? ` and \`${names.role}(org, roles)\`` : ""} (SECURITY DEFINER, search_path pinned, not callable by visitors) and ${rlsOff ? "turns on Row Level Security with" : "rewrites"} the ${kind} policies on ${proof.table}${made.length ? `: ${made.join(", ")}` : ""}.`,
    via === "members"
      ? admin
        ? `Only admins (${admins?.join(", ")}) of an organization can add, change or remove its members; nobody can change ${m.tenantColumn} or ${m.userColumn} of a membership row.`
        : `Membership rows can only be written from the server; nobody can change ${m.tenantColumn} or ${m.userColumn} of one.`
      : via === "tenant"
        ? `Members read their own organization; ${admin ? "only its admins" : "members"} change it${locked.length ? `; ${locked.join(", ")} change only from the server` : ""}.`
        : "Only members of the row's organization can read or change it.",
  ].join(" ");
  const caveats = [
    /invit/i.test(proof.table)
      ? "The invited person is not a member yet: look the invite up by its token in a SECURITY DEFINER function or an edge function that returns only that one invite, instead of a select policy."
      : via === "members"
        ? "Invites and onboarding: if the browser inserts the first membership row of a new organization or accepts an invite by inserting its own row, move that into a SECURITY DEFINER function or an edge function that checks the invite token."
        : "If some rows of this table are meant to be public (a published page), add a separate select policy for exactly those rows.",
    ...(m.roleColumn && !m.adminRoles.length
      ? [
          `The schema does not say which ${m.roleColumn} values are admins, so membership writes are left to the server. Add a has-role helper once that is decided.`,
        ]
      : []),
    ...(via !== "members" && via !== "tenant" && proof.ownerColumns.length
      ? [
          `Every member can now edit the organization's rows. If only the author (${proof.ownerColumns.join(", ")}) should edit, add \`and ${proof.ownerColumns[0]} = (select auth.uid())\` to the update and delete policies.`,
        ]
      : []),
    "Pending invitations: if membership rows also hold invites (a status column), add the active status to the helper's where clause.",
  ];
  return {
    edits: [
      {
        path: ctx.newMigration(`org_policies_${proof.table.replace(/^public\./, "").replace(/[^a-z0-9]+/gi, "_")}`),
        after: [
          `-- ${finding.id}: rows of ${proof.table} belong to an organization (${link.tenant}); tie every policy to membership.`,
          "-- Generated by prelaunch-audit. Review before applying.",
          ...body,
          "",
        ].join("\n"),
      },
    ],
    summary,
    caveats,
  };
}
