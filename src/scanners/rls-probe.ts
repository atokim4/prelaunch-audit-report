import {
  accessVerdict,
  isOwned,
  leaks,
  probeRls,
  PROBE_VERSION,
  type ProbeResult,
  type TableProbe,
} from "../probe/rls-probe.ts";
import { weakPolicies } from "../patches/fixers.ts";
import type { SqlFile } from "../patches/sql.ts";
import { phiKind } from "../phi/columns.ts";
import type { Actor, Location, Proof, RawFinding, ToolRun } from "../types.ts";
import { PERSONAL_COLUMN } from "./static-context.ts";

/** Static rules about one table or view; the probe's proof is attached to these instead of a new finding. */
export const TABLE_RULES = new Set([
  "rls-disabled",
  "rls-permissive-policy",
  "rls-no-policy",
  "rls-update-privileged-column",
  "view-bypasses-rls",
  "auth-users-exposed",
]);

export function toProof(table: TableProbe): Proof {
  return {
    table: table.table,
    kind: table.kind,
    ownerColumns: table.ownerColumns,
    ...(table.ownedVia ? { ownedVia: table.ownedVia } : {}),
    ...(table.tenant ? { tenant: table.tenant } : {}),
    checks: table.checks,
    leaks: leaks(table),
    access: table.access,
    verdict: accessVerdict(table),
    ...publicListingOf(table),
    ...anonInsertOf(table),
    policies: table.policies,
  };
}

/**
 * A policy name that says the read is for everyone on purpose. Supabase's dashboard template "Enable read
 * access for all users" is left out: it is the one most often pasted onto private tables.
 */
const PUBLIC_POLICY_NAME = /^(public|anyone|everyone|visitors?|guests?|anon\w*)\b/i;

/** Columns that mark a row as meant for everyone: an active organizer, a published page. */
const VISIBILITY_COLUMN = /^(?:is_)?(?:active|public|published|visible|listed|live)$/i;
const VISIBLE_STATUS = /^(?:published|public|active|live|approved|listed)$/i;

/** Top-level OR terms of a policy expression as Postgres prints it: `(is_active OR (id IN ( SELECT …)))`. */
function orTerms(expression: string): string[] {
  let text = expression.trim();
  const wrapped = (t: string): boolean => {
    if (!t.startsWith("(") || !t.endsWith(")")) return false;
    let depth = 0;
    for (let i = 0; i < t.length; i++) {
      if (t[i] === "(") depth++;
      else if (t[i] === ")" && --depth === 0 && i < t.length - 1) return false;
    }
    return true;
  };
  while (wrapped(text)) text = text.slice(1, -1).trim();
  const terms: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") depth--;
    else if (depth === 0 && /^\sOR\s/i.test(text.slice(i, i + 4))) {
      terms.push(text.slice(start, i).trim());
      start = i + 4;
    }
  }
  terms.push(text.slice(start).trim());
  return terms;
}

/**
 * The visibility column a read policy opens rows on by itself, as one OR term: `is_active`,
 * `(is_public = true)`, `(status = 'published'::text)`. Only columns of this table count.
 */
export function visibilityFlag(using: string | undefined, columns: string[]): string | undefined {
  if (!using) return undefined;
  const has = new Set(columns.map((c) => c.toLowerCase()));
  for (const term of orTerms(using)) {
    const bare = term.replace(/^\(+|\)+$/g, "").trim();
    const flag = bare.match(/^(?:\w+\.)?(\w+)(?:\s*=\s*true)?$/i)?.[1];
    if (flag && VISIBILITY_COLUMN.test(flag) && has.has(flag.toLowerCase())) return flag;
    const status = bare.match(/^(?:\w+\.)?(\w+)\s*=\s*'(\w+)'(?:::[\w ]+)?$/i);
    if (status?.[1] && has.has(status[1].toLowerCase()) && VISIBLE_STATUS.test(status[2] ?? "")) {
      return `${status[1]} = '${status[2]}'`;
    }
  }
  return undefined;
}

/** See Proof.publicListing. Any write, membership trick or personal column keeps the full rating. */
function publicListingOf(table: TableProbe): Pick<Proof, "publicListing" | "publicListingFlag"> {
  const found = leaks(table);
  if (!table.tenant || !found.length) return {};
  if (found.some((c) => c.action !== "select" || c.column || c.scenario)) return {};
  if (table.columns.some((c) => PERSONAL_COLUMN.test(c) || phiKind(table.name, c))) return {};
  const open = table.policies.find(
    (p) =>
      (p.command === "select" || p.command === "all") &&
      (p.roles.includes("anon") || (p.roles.includes("public") && PUBLIC_POLICY_NAME.test(p.name))),
  );
  if (open) return { publicListing: open.name };
  // A policy that opens the rows marked active or published to everyone (`to public`, the default).
  for (const p of table.policies) {
    if (p.command !== "select" && p.command !== "all") continue;
    if (!p.roles.includes("anon") && !p.roles.includes("public")) continue;
    const flag = visibilityFlag(p.using, table.columns);
    if (flag) return { publicListing: p.name, publicListingFlag: flag };
  }
  return {};
}

/** See Proof.anonInsertByDesign. */
function anonInsertOf(table: TableProbe): Pick<Proof, "anonInsertByDesign"> {
  const found = leaks(table);
  if (!table.anonColumnInsert || isOwned(table) || !found.length) return {};
  return found.every((c) => c.action === "insert") ? { anonInsertByDesign: true } : {};
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** First match of `pattern` in the migrations, newest last; the last match wins for policies (re-created later). */
function findIn(migrations: SqlFile[], pattern: RegExp, last: boolean): Location | undefined {
  let found: Location | undefined;
  for (const file of [...migrations].sort((a, b) => a.path.localeCompare(b.path))) {
    const index = file.text.search(pattern);
    if (index < 0) continue;
    found = { kind: "file", file: file.path, line: file.text.slice(0, index).split("\n").length };
    if (!last) return found;
  }
  return found;
}

/** Where a probe-only finding points: the policy that let the leak through, else where the table is created. */
function locate(migrations: SqlFile[], table: string, policy: string | undefined): Location {
  const name = escapeRegExp(table.replace(/^public\./, ""));
  if (policy) {
    const at = findIn(migrations, new RegExp(String.raw`create\s+policy\s+"${escapeRegExp(policy)}"`, "i"), true);
    if (at) return at;
  }
  const created = new RegExp(
    String.raw`create\s+(?:or\s+replace\s+)?(?:materialized\s+)?(?:table|view)\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?${name}"?[\s(]`,
    "i",
  );
  return (
    findIn(migrations, created, false) ?? { kind: "file", file: migrations[0]?.path ?? "supabase/migrations", line: 1 }
  );
}

const ACTOR_WORD: Record<Actor, string> = {
  anon: "a visitor without an account",
  "other-user": "user B",
  owner: "the row's owner",
  "non-member": "user C",
};

/** With an organization model the same actors are named by where they belong. */
const TENANT_WORD: Record<Actor, string> = {
  anon: "a visitor without an account",
  "other-user": "an admin of another organization",
  owner: "a plain member",
  "non-member": "a signed-in user in no organization",
};

/** One line of evidence: what got through, in counts. */
export function describeLeaks(proof: Proof): string {
  const word = !proof.tenant
    ? ACTOR_WORD
    : proof.tenant.members.globalAdmin
      ? { ...TENANT_WORD, "other-user": "a member of another organization" }
      : TENANT_WORD;
  const whose = proof.tenant ? "organization A's" : "user A's";
  const parts = proof.leaks.map((c) =>
    c.scenario === "self-join"
      ? `${word[c.actor]} added themselves to organization A`
      : c.scenario === "move-tenant"
        ? `${word[c.actor]} moved their own membership to another organization`
        : c.action === "insert"
          ? proof.tenant
            ? `${word[c.actor]} inserted a row into organization A`
            : `${word[c.actor]} inserted a row in user A's name`
          : c.column
            ? `${word[c.actor]} changed \`${c.column}\``
            : `${word[c.actor]} could ${c.action} ${c.rows} of ${c.of} of ${whose} rows`,
  );
  return `RLS probe on \`${proof.table}\`: ${parts.join("; ")}.`;
}

/**
 * Adds the probe's proof to the static findings about the same table, and turns leaks no static rule
 * explains into findings of their own.
 */
export function mergeProbe(raws: RawFinding[], result: ProbeResult, migrations: SqlFile[]): RawFinding[] {
  const out: RawFinding[] = [];
  const members = result.tables.find((t) => t.tenant?.members.globalAdmin)?.tenant?.members;
  if (members?.globalAdmin) {
    const fn = members.globalAdmin.match(/^([\w$]+)\(\)$/)?.[1];
    const at = fn
      ? findIn(
          migrations,
          new RegExp(
            String.raw`create\s+(?:or\s+replace\s+)?function\s+(?:"?\w+"?\.)?"?${escapeRegExp(fn)}"?\s*\(`,
            "i",
          ),
          true,
        )
      : findIn(
          migrations,
          new RegExp(
            String.raw`create\s+policy\s+"${escapeRegExp(members.globalAdmin.replace(/^policy "|"$/g, ""))}"`,
            "i",
          ),
          true,
        );
    out.push({
      source: "rls-probe",
      rule: "tenant-global-admin",
      toolSeverity: "info",
      message: `${members.globalAdmin} decides admin access from \`${members.table}.${members.roleColumn ?? "role"}\` without \`${members.tenantColumn}\`, so an admin of one organization is an admin of all. The probe tested other organizations as a plain member of organization B, not as its admin.`,
      location: at ?? { kind: "file", file: migrations[0]?.path ?? "supabase/migrations", line: 1 },
      subject: members.table,
    });
  }
  for (const table of result.tables) {
    if (table.skipped) continue;
    const proof = toProof(table);
    const covering = raws.filter((r) => r.subject === table.table && TABLE_RULES.has(r.rule));
    for (const raw of covering) {
      raw.proof = proof;
      // On organization data the probe's words say more than the policy text (a self-join next to a role edit).
      if (proof.tenant && proof.leaks.length) raw.message = `${raw.message} ${describeLeaks(proof)}`;
    }
    if (covering.length || !proof.leaks.length) continue;
    const weak = weakPolicies(proof);
    const through = weak.length
      ? ` Let through by ${weak.map((p) => `policy "${p.name}" (${p.command}, \`${p.withCheck && p.command === "insert" ? `with check ${p.withCheck}` : `using ${p.using ?? "true"}`}\`)`).join(" and ")}.`
      : "";
    out.push({
      source: "rls-probe",
      rule: "rls-probe-leak",
      toolSeverity: proof.leaks[0]?.actor ?? "anon",
      message: `${describeLeaks(proof)}${through}`,
      location: locate(migrations, table.table, weak[0]?.name),
      subject: table.table,
      proof,
    });
  }
  return out;
}

export async function runRlsProbe(
  migrations: SqlFile[],
  tolerant = false,
): Promise<{ result?: ProbeResult; tool: ToolRun; note?: string }> {
  const command = "prelaunch-audit rls-probe (PGlite + Supabase shim, rolled-back tries as anon and a second user)";
  const tool: ToolRun = { name: "rls-probe", version: PROBE_VERSION, command, status: "ok" };
  if (!migrations.length) {
    return {
      tool: {
        ...tool,
        status: "skipped",
        note: "No SQL schema files (supabase/migrations, schema.sql, sql/, prisma/migrations).",
      },
    };
  }
  let result: ProbeResult;
  try {
    result = await probeRls(migrations, tolerant);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    result = {
      tables: [],
      migrations: migrations.length,
      skippedExtensions: [],
      failedStatements: [],
      error: `the probe crashed: ${reason}`,
    };
  }
  if (result.error) {
    return {
      tool: { ...tool, status: "failed", note: result.error },
      note: `Row Level Security was not tested by behaviour: ${result.error} Only the static checks ran.`,
    };
  }
  const skipped = result.tables.filter((t) => t.skipped);
  const tested = result.tables.length - skipped.length;
  return {
    result,
    tool: {
      ...tool,
      note: [
        `${tested} tables and views tried as anon and as a second user.`,
        skipped.length ? `Not tried: ${skipped.map((t) => `${t.table} (${t.skipped})`).join("; ")}.` : "",
        result.failedStatements.length
          ? `Stepped over ${result.failedStatements.length} statement(s) that Postgres rejected (${[...new Set(result.failedStatements.map((f) => f.file))].join(", ")}); tables they name were not tried.`
          : "",
        result.skippedExtensions.length
          ? `Stepped over platform extensions: ${result.skippedExtensions.join(", ")}.`
          : "",
      ]
        .filter(Boolean)
        .join(" "),
    },
  };
}
