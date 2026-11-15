import { statements, type SqlFile } from "../patches/sql.ts";
import type { TableProbe } from "../probe/rls-probe.ts";

/** Lovable and `supabase gen types typescript` write the schema here; the live probe reads table names from it. */
export const TYPES_FILES = [
  "src/integrations/supabase/types.ts",
  "src/types/supabase.ts",
  "src/lib/database.types.ts",
  "lib/database.types.ts",
  "types/supabase.ts",
  "database.types.ts",
];

const OWNER_NAME = /^(user_id|owner_id|created_by|author_id|profile_id|customer_id|account_id)$/;

export interface GeneratedSchema {
  tables: { name: string; columns: string[] }[];
  views: { name: string; columns: string[] }[];
  functions: string[];
}

/** Index just past the `{` that closes the block opened at `open` (the index of a `{`). */
function closeOf(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return text.length;
}

/** Top-level `key: { … }` members of an object literal body, in order. Other members are skipped. */
function members(body: string): { key: string; body: string }[] {
  const out: { key: string; body: string }[] = [];
  const key = /(?:^|[\s;,])(?:"([^"]+)"|'([^']+)'|([A-Za-z_$][\w$]*))\??\s*:\s*\{/y;
  let i = 0;
  while (i < body.length) {
    key.lastIndex = i;
    const match = key.exec(body);
    if (match) {
      const open = key.lastIndex - 1;
      const end = closeOf(body, open);
      out.push({ key: match[1] ?? match[2] ?? match[3] ?? "", body: body.slice(open + 1, end - 1) });
      i = end;
      continue;
    }
    const ch = body[i];
    i = ch === "{" ? closeOf(body, i) : i + 1;
  }
  return out;
}

const member = (body: string, name: string): string | undefined => members(body).find((m) => m.key === name)?.body;

/** Column names of a `Row: { … }` block (`id: string`, `"full name": string | null`). */
function rowColumns(row: string | undefined): string[] {
  if (!row) return [];
  const out: string[] = [];
  const column = /(?:^|[\s;,])(?:"([^"]+)"|([A-Za-z_$][\w$]*))\??\s*:/g;
  let depth = 0;
  let last = 0;
  for (const match of row.matchAll(column)) {
    for (const ch of row.slice(last, match.index)) depth += ch === "{" ? 1 : ch === "}" ? -1 : 0;
    last = match.index;
    if (depth === 0) out.push(match[1] ?? match[2] ?? "");
  }
  return out;
}

/**
 * Reads the `public` schema of a generated `Database` type: tables and views with their columns, and
 * function names. Returns undefined when the file has no `public: { Tables: … }` block.
 */
export function parseGeneratedTypes(text: string): GeneratedSchema | undefined {
  const anchor = /(?:^|[\s,{])public\s*:\s*\{/m.exec(text);
  if (!anchor) return undefined;
  const open = anchor.index + anchor[0].length - 1;
  const schema = text.slice(open + 1, closeOf(text, open) - 1);
  const tables = member(schema, "Tables");
  if (tables === undefined) return undefined;
  const relations = (body: string | undefined) =>
    members(body ?? "").map((m) => ({ name: m.key, columns: rowColumns(member(m.body, "Row")) }));
  return {
    tables: relations(tables),
    views: relations(member(schema, "Views")),
    functions: members(member(schema, "Functions") ?? "").map((m) => m.key),
  };
}

/** Public functions created by the migrations, with their SECURITY DEFINER flag (latest definition wins). */
export function migrationFunctions(migrations: SqlFile[]): Map<string, boolean> {
  const out = new Map<string, boolean>();
  const header =
    /^create\s+(?:or\s+replace\s+)?function\s+(?:"?public"?\.)?(?:"([^"]+)"|([A-Za-z_][\w$]*))\s*\(([\s\S]*?)\)\s*returns\s+([\s\S]*?)\s+(?:as|language)\b/i;
  for (const file of [...migrations].sort((a, b) => a.path.localeCompare(b.path))) {
    for (const statement of statements(file.text)) {
      const match = header.exec(statement.trim());
      if (!match || /\btrigger\b/i.test(match[4] ?? "")) continue; // trigger functions are not callable over the API
      const qualified = /^create\s+(?:or\s+replace\s+)?function\s+("?[A-Za-z_][\w$]*"?)\./i.exec(statement.trim());
      if (qualified && qualified[1]?.replaceAll('"', "") !== "public") continue;
      out.set(match[1] ?? match[2] ?? "", /\bsecurity\s+definer\b/i.test(statement));
    }
  }
  return out;
}

/** A table or view the live probe will count rows in. */
export interface LiveTarget {
  name: string;
  relation: "table" | "view";
  foundIn: ("migrations" | "types")[];
  ownerColumns: string[];
  /** Owned through a foreign key to a parent with its own owner column (one level only). */
  ownedVia?: { column: string; parent: string; parentColumn: string; parentOwner: string };
  /** What the PGlite probe saw for the same table, for the drift check. */
  local?: TableProbe;
}

/**
 * The tables and views to probe: every one the migrations create (with the owner columns the PGlite
 * probe worked out) plus the ones only the generated types know about, which were created outside
 * the migrations (an owner column there is guessed from its name).
 */
export function liveTargets(local: TableProbe[] | undefined, generated: GeneratedSchema | undefined): LiveTarget[] {
  const out = new Map<string, LiveTarget>();
  for (const table of local ?? []) {
    const via = table.ownedVia;
    const parentOwner = via?.parentOwners[0];
    out.set(table.name, {
      name: table.name,
      relation: table.kind,
      foundIn: ["migrations"],
      ownerColumns: table.ownerColumns,
      ...(via && parentOwner
        ? { ownedVia: { column: via.column, parent: via.parent, parentColumn: via.parentColumn, parentOwner } }
        : {}),
      local: table,
    });
  }
  const fromTypes = [
    ...(generated?.tables ?? []).map((t) => ({ ...t, relation: "table" as const })),
    ...(generated?.views ?? []).map((t) => ({ ...t, relation: "view" as const })),
  ];
  for (const { name, columns, relation } of fromTypes) {
    const known = out.get(name);
    if (known) {
      known.foundIn.push("types");
      continue;
    }
    out.set(name, {
      name,
      relation,
      foundIn: ["types"],
      ownerColumns: columns.filter((c) => OWNER_NAME.test(c)),
    });
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}
