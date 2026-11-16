import { createdTables, qualify, statements, type SqlFile } from "../patches/sql.ts";
import type { AdminGate, RawFinding } from "../types.ts";

/**
 * Role columns that decide admin access. A user who can write their own `role` is a free-plan problem on
 * a SaaS app, but when a policy hands every row to whoever has `role = 'admin'` (directly, or through a
 * helper such as `is_admin()`, `current_role()` or `private.current_uid()`-style wrappers), that one
 * update opens the whole database to any account. Read from the SQL only.
 */

const ROLE_COLUMN =
  /^(role|roles|user_role|app_role|is_admin|admin|is_staff|is_superuser|is_super_admin|account_type|user_type|access_level)$/i;
/** A literal that names an admin-level role. */
const ADMIN_LITERAL = /'(?:super[_ -]?)?admin(?:istrator)?'|'superuser'|'staff'/i;
/** Helper names that say they decide access by role. */
const ADMIN_NAME = /admin|staff|super|role|permission|privilege/i;

const CREATE_FUNCTION = /^create\s+(?:or\s+replace\s+)?function\s+((?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))?)\s*\(/i;
const CREATE_POLICY = /^create\s+policy\s+(?:"([^"]+)"|(\w+))\s+on\s+((?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))?)/i;

interface Stmt {
  file: string;
  text: string;
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const word = (name: string): RegExp =>
  new RegExp(String.raw`(?:"${escapeRegExp(name)}"|\b${escapeRegExp(name)}\b)`, "i");

/** Tables a body reads: `from x` and `join x`, schema optional, quotes removed. */
function tablesRead(body: string): string[] {
  const out = new Set<string>();
  for (const m of body.matchAll(/\b(?:from|join)\s+((?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))?)/gi)) {
    out.add(qualify(m[1] ?? ""));
  }
  return [...out];
}

function lineOf(file: SqlFile | undefined, pattern: RegExp): number {
  if (!file) return 1;
  const index = file.text.search(pattern);
  return index < 0 ? 1 : file.text.slice(0, index).split("\n").length;
}

export function adminGates(sql: SqlFile[]): AdminGate[] {
  const tables = new Map([...createdTables(sql)].map(([name, columns]) => [name.toLowerCase(), columns]));
  const roleColumns = (table: string): string[] =>
    (tables.get(table) ?? []).map((c) => c.name.replace(/"/g, "")).filter((n) => ROLE_COLUMN.test(n));
  const all: Stmt[] = sql.flatMap((f) => statements(f.text).map((text) => ({ file: f.path, text })));
  const policies = all.filter((s) => CREATE_POLICY.test(s.text));
  const byPath = new Map(sql.map((f) => [f.path, f]));
  const out: AdminGate[] = [];
  const add = (gate: AdminGate): void => {
    if (!out.some((g) => g.table === gate.table && g.column === gate.column)) out.push(gate);
  };

  // A helper function that reads a role column and is used by a policy.
  for (const fn of all) {
    const match = fn.text.match(CREATE_FUNCTION);
    if (!match?.[1]) continue;
    const name = match[1].replace(/"/g, "");
    const bare = name.split(".").pop() ?? name;
    const body = fn.text.match(/\$([A-Za-z_]*)\$([\s\S]*)\$\1\$/)?.[2] ?? "";
    const call = new RegExp(String.raw`\b${escapeRegExp(bare)}\s*\(`, "i");
    const users = policies.filter((p) => call.test(p.text));
    if (!users.length) continue;
    const adminish = ADMIN_NAME.test(bare) || ADMIN_LITERAL.test(body) || users.some((p) => ADMIN_LITERAL.test(p.text));
    if (!adminish) continue;
    for (const table of tablesRead(body)) {
      for (const column of roleColumns(table)) {
        if (!word(column).test(body)) continue;
        const policy = users[0]?.text.match(CREATE_POLICY);
        add({
          table,
          column,
          via: `\`${name}()\` reads it and policy "${policy?.[1] ?? policy?.[2] ?? ""}" uses that function`,
          location: {
            kind: "file",
            file: fn.file,
            line: lineOf(
              byPath.get(fn.file),
              new RegExp(String.raw`function\s+[\w".]*${escapeRegExp(bare)}"?\s*\(`, "i"),
            ),
          },
        });
      }
    }
  }

  // A policy that checks the role column of another row with a subquery: `(select role from profiles …) = 'admin'`.
  for (const policy of policies) {
    const match = policy.text.match(CREATE_POLICY);
    const name = match?.[1] ?? match?.[2] ?? "";
    for (const table of tablesRead(policy.text)) {
      for (const column of roleColumns(table)) {
        const literal = ADMIN_LITERAL.test(policy.text) || /^is_|admin/i.test(column);
        if (!literal || !word(column).test(policy.text)) continue;
        add({
          table,
          column,
          via: `policy "${name}" on ${qualify(match?.[3] ?? "")} checks it`,
          location: {
            kind: "file",
            file: policy.file,
            line: lineOf(
              byPath.get(policy.file),
              new RegExp(String.raw`create\s+policy\s+"?${escapeRegExp(name)}`, "i"),
            ),
          },
        });
      }
    }
  }
  return out;
}

/**
 * Marks findings where the row's owner can write a column that decides admin access: the static
 * update-privileged-column rule (unless the probe showed the update blocked) and probe escalations.
 */
export function markAdminGates(raws: RawFinding[], sql: SqlFile[]): void {
  const gates = adminGates(sql);
  if (!gates.length) return;
  const gateFor = (table: string, column: string): AdminGate | undefined =>
    gates.find((g) => g.table === table.toLowerCase() && g.column.toLowerCase() === column.toLowerCase());
  for (const raw of raws) {
    const table = (raw.proof?.table ?? raw.subject ?? "").replace(/"/g, "");
    if (!table) continue;
    const escalated = raw.proof?.leaks.filter((c) => c.actor === "owner" && c.column).map((c) => c.column ?? "") ?? [];
    let gate: AdminGate | undefined;
    if (raw.rule === "rls-update-privileged-column") {
      const column = raw.message.match(/including `(\w+)`/)?.[1] ?? "";
      if (!raw.proof || escalated.includes(column)) gate = gateFor(table, column);
    } else if (raw.source === "rls-probe" || raw.proof) {
      gate = escalated.map((column) => gateFor(table, column)).find(Boolean);
    }
    if (gate) raw.adminGate = gate;
  }
}

/** Title and prose for a finding whose column decides admin access; they replace the paid-plan wording. */
export const ADMIN_GATE_TEXT = {
  title: "Users can make themselves an admin",
  whyItMatters:
    "The row's owner may update the column that the admin policies trust. One request from the browser console sets it to admin, and from then on that account reads and changes every row the admin policies open, which on most apps is all of them.",
  fix: "Revoke update on the role column from `authenticated` (grant update only on the columns users may edit), or block changes to it in a trigger unless the caller is the service role. Set roles only from the server or the dashboard.",
} as const;

/** The evidence sentence for a finding that lets a user make themselves an admin. */
export function adminGateNote(raw: RawFinding): string | undefined {
  const gate = raw.adminGate;
  if (!gate) return undefined;
  const at = gate.location.kind === "file" ? ` (${gate.location.file}:${gate.location.line})` : "";
  return `\`${gate.column}\` decides admin access: ${gate.via}${at}. A user who sets it on their own row gets every row those admin policies allow.`;
}
