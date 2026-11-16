import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { PGlite, type Extensions, type Transaction } from "@electric-sql/pglite";
import type { SqlFile } from "../patches/sql.ts";
import type { Actor, OwnedVia, ProbeCheck, ProbePolicy } from "../types.ts";

/**
 * Behavioural Row Level Security check. Loads the repo's migrations into PGlite (Postgres in
 * WebAssembly) on top of a small Supabase shim, creates two users, gives user A one row in every
 * table, then tries every action as a visitor without an account (anon) and as user B. Each try runs
 * in a transaction that is rolled back, so the counts are what the API roles really get, not what a
 * policy looks like. A try that fails for a reason other than a refusal (a constraint the guessed
 * values break) is recorded as inconclusive, never as "blocked".
 */

export const PROBE_VERSION = "1.1.0";
export const SHIM_PATH = new URL("./supabase-shim.sql", import.meta.url);

export const USER_A = "00000000-0000-4000-8000-00000000000a";
export const USER_B = "00000000-0000-4000-8000-00000000000b";

export interface TableProbe {
  /** Display name, always `public.<name>`. */
  table: string;
  /** The bare relation name (may contain dots or capitals; always quoted in SQL). */
  name: string;
  kind: "table" | "view";
  rls: boolean;
  /** Every column name, in table order. */
  columns: string[];
  /** Columns that tie a row to a user directly. */
  ownerColumns: string[];
  /** No owner column, but a foreign key to a table that has one: the row belongs to the parent's owner. */
  ownedVia?: OwnedVia;
  checks: ProbeCheck[];
  policies: ProbePolicy[];
  /** Set when the table could not be seeded or probed; no checks then. */
  skipped?: string;
}

export interface ProbeResult {
  tables: TableProbe[];
  migrations: number;
  /** Supabase platform extensions the probe could not load and stepped over. */
  skippedExtensions: string[];
  /** Set when the migrations did not load; no tables then. */
  error?: string;
}

/** True when rows belong to someone: an owner column, or a parent that has one. */
export const isOwned = (t: { ownerColumns: string[]; ownedVia?: OwnedVia }): boolean =>
  t.ownerColumns.length > 0 || t.ownedVia !== undefined;

/** A check that got through: the actor read or changed rows it should not. */
export function leaks(probe: Pick<TableProbe, "checks" | "ownerColumns" | "ownedVia">): ProbeCheck[] {
  return probe.checks.filter((check) => {
    if (check.rows === 0) return false;
    if (check.actor === "owner") return true; // escalation checks only run on privileged columns
    if (!isOwned(probe)) return check.action !== "select"; // shared data is often public on purpose
    return true;
  });
}

interface ColumnInfo {
  name: string;
  type: string;
  notNull: boolean;
  hasDefault: boolean;
  generated: boolean;
  primaryKey: boolean;
  /** Primary key or a single-column unique index: every insert needs a fresh value. */
  unique: boolean;
  /** References auth.users(id). */
  user: boolean;
  /** References a table in public. */
  parent?: { name: string; column: string };
  enumLabels?: string[];
}

const OWNER_NAME = /^(user_id|owner_id|created_by|author_id|profile_id|customer_id|account_id)$/;
export const PRIVILEGED_COLUMN =
  /^(plan|tier|role|roles|is_admin|admin|credits|balance|is_pro|is_premium|is_verified|verified|subscription\w*|stripe_\w+)$/;

const quote = (name: string): string => `"${name.replaceAll('"', '""')}"`;
const rel = (name: string): string => `"public".${quote(name)}`;
const lit = (value: string): string => `'${value.replaceAll("'", "''")}'`;

async function columnsOf(db: PGlite, oid: number): Promise<ColumnInfo[]> {
  const { rows } = await db.query<{
    name: string;
    type: string;
    not_null: boolean;
    has_default: boolean;
    generated: boolean;
    primary_key: boolean;
    unique_col: boolean;
    user_ref: boolean;
    parent_table: string | null;
    parent_column: string | null;
    enum_labels: string[] | null;
  }>(
    `select a.attname as name, format_type(a.atttypid, a.atttypmod) as type,
            a.attnotnull as not_null, a.atthasdef as has_default,
            (a.attidentity <> '' or a.attgenerated <> '') as generated,
            exists (select 1 from pg_constraint p where p.conrelid = a.attrelid and p.contype = 'p' and a.attnum = any (p.conkey)) as primary_key,
            exists (select 1 from pg_index i where i.indrelid = a.attrelid and i.indisunique and i.indnkeyatts = 1
                    and i.indkey[0] = a.attnum and i.indpred is null) as unique_col,
            exists (select 1 from pg_constraint f where f.conrelid = a.attrelid and f.contype = 'f'
                    and f.confrelid = 'auth.users'::regclass and f.conkey = array[a.attnum]) as user_ref,
            (select fc.relname::text from pg_constraint f join pg_class fc on fc.oid = f.confrelid join pg_namespace fn on fn.oid = fc.relnamespace
              where f.conrelid = a.attrelid and f.contype = 'f' and f.conkey = array[a.attnum] and fn.nspname = 'public' limit 1) as parent_table,
            (select fa.attname::text from pg_constraint f join pg_attribute fa on fa.attrelid = f.confrelid and fa.attnum = f.confkey[1]
              join pg_class fc on fc.oid = f.confrelid join pg_namespace fn on fn.oid = fc.relnamespace
              where f.conrelid = a.attrelid and f.contype = 'f' and f.conkey = array[a.attnum] and fn.nspname = 'public' limit 1) as parent_column,
            (select array_agg(e.enumlabel::text order by e.enumsortorder) from pg_enum e where e.enumtypid = a.atttypid) as enum_labels
       from pg_attribute a
      where a.attrelid = $1 and a.attnum > 0 and not a.attisdropped
      order by a.attnum`,
    [oid],
  );
  return rows.map((r) => ({
    name: r.name,
    type: r.type,
    notNull: r.not_null,
    hasDefault: r.has_default,
    generated: r.generated,
    primaryKey: r.primary_key,
    unique: r.primary_key || r.unique_col,
    user: r.user_ref,
    parent: r.parent_table && r.parent_column ? { name: r.parent_table, column: r.parent_column } : undefined,
    enumLabels: r.enum_labels ?? undefined,
  }));
}

const baseType = (column: ColumnInfo): string => column.type.replace(/\(.*\)/, "").trim();
const isText = (type: string): boolean => /^(text|character varying|character|citext|name)$/.test(type);
const isNumber = (type: string): boolean => /^(smallint|integer|bigint|numeric|real|double precision)$/.test(type);

/** A value Postgres accepts for the column type, as text to cast; undefined when there is no safe guess. */
function sampleValue(column: ColumnInfo): string | undefined {
  if (column.enumLabels?.length) return column.enumLabels[0];
  const type = baseType(column);
  if (type.endsWith("[]")) return "{}";
  // Unique columns need a fresh value per insert, or a second insert fails on the index, not on RLS.
  if (isText(type)) return column.unique ? `probe-${randomUUID().slice(0, 8)}` : "probe";
  if (type === "uuid") return randomUUID();
  if (isNumber(type)) return column.unique ? String(10_000 + Math.floor(Math.random() * 1_000_000)) : "1";
  if (type === "boolean") return "false";
  if (type === "date") return "2026-01-01";
  if (/^timestamp/.test(type)) return "2026-01-01T00:00:00Z";
  if (/^jsonb?$/.test(type)) return "{}";
  if (type === "inet") return "127.0.0.1";
  return undefined;
}

interface TableInfo {
  name: string;
  oid: number;
  kind: "table" | "view";
  rls: boolean;
  columns: ColumnInfo[];
  ownerColumns: string[];
  ownedVia?: OwnedVia;
  /** SQL condition true for user A's rows, fixed after seeding (literal values, no RLS-dependent subquery). */
  mine: string;
}

function ownerColumnsOf(columns: ColumnInfo[]): string[] {
  const linked = columns.filter((c) => c.user).map((c) => c.name);
  if (linked.length) return linked;
  return columns.filter((c) => OWNER_NAME.test(c.name) && c.type === "uuid").map((c) => c.name);
}

async function tablesOf(db: PGlite): Promise<TableInfo[]> {
  const { rows } = await db.query<{ name: string; oid: number; relkind: string; rls: boolean }>(
    `select c.relname::text as name, c.oid::int as oid, c.relkind::text as relkind, c.relrowsecurity as rls
       from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm') and not c.relispartition
      order by c.relname`,
  );
  const out: TableInfo[] = [];
  for (const row of rows) {
    const columns = await columnsOf(db, row.oid);
    out.push({
      name: row.name,
      oid: row.oid,
      kind: row.relkind === "v" || row.relkind === "m" ? "view" : "table",
      rls: row.rls,
      columns,
      ownerColumns: ownerColumnsOf(columns),
      mine: "false",
    });
  }
  // Views have no foreign keys: an owner column there is one that carries a base table's owner column name.
  const baseOwners = new Set(out.filter((t) => t.kind === "table").flatMap((t) => t.ownerColumns));
  for (const view of out.filter((t) => t.kind === "view")) {
    const named = view.columns.filter((c) => baseOwners.has(c.name) && c.type === "uuid").map((c) => c.name);
    // "id" is an owner column only in tables keyed by the user (profiles); in a view next to owner_id it is the row id.
    view.ownerColumns = named.length > 1 ? named.filter((n) => n !== "id") : named;
  }
  return out;
}

/** Parents first, so a child row can point at the parent row seeded before it. */
function seedOrder(tables: TableInfo[]): TableInfo[] {
  const byName = new Map(tables.map((t) => [t.name, t]));
  const done = new Set<string>();
  const out: TableInfo[] = [];
  const visit = (info: TableInfo, path: Set<string>): void => {
    if (done.has(info.name) || path.has(info.name)) return;
    path.add(info.name);
    for (const column of info.columns) {
      const parent = column.parent && byName.get(column.parent.name);
      if (parent && parent !== info) visit(parent, path);
    }
    done.add(info.name);
    out.push(info);
  };
  for (const info of tables) visit(info, new Set());
  return out;
}

/** A table without owner columns is owned through its first foreign key to an owned table. */
function linkOwnership(ordered: TableInfo[]): void {
  const byName = new Map(ordered.map((t) => [t.name, t]));
  for (const info of ordered) {
    if (info.ownerColumns.length) continue;
    for (const column of info.columns) {
      const parent = column.parent && byName.get(column.parent.name);
      if (!parent || parent === info || !isOwned(parent) || !column.parent) continue;
      info.ownedVia = {
        column: column.name,
        parent: `public.${parent.name}`,
        parentColumn: column.parent.column,
        parentOwners: parent.ownerColumns,
      };
      break;
    }
  }
}

/** Freezes "user A's rows" into literal SQL, so the condition means the same for every actor. */
async function fixMine(db: PGlite, info: TableInfo, byName: Map<string, TableInfo>): Promise<void> {
  if (info.ownerColumns.length) {
    info.mine = `(${info.ownerColumns.map((c) => `${quote(c)} = '${USER_A}'::uuid`).join(" or ")})`;
    return;
  }
  const via = info.ownedVia;
  const parent = via && byName.get(via.parent.replace(/^public\./, ""));
  if (!via || !parent) {
    info.mine = "true"; // shared data: every row counts
    return;
  }
  const { rows } = await db.query<{ v: string }>(
    `select distinct ${quote(via.parentColumn)}::text as v from ${rel(parent.name)} where ${parent.mine}`,
  );
  info.mine = rows.length ? `${quote(via.column)}::text in (${rows.map((r) => lit(r.v)).join(", ")})` : "false";
}

/** Column values for one new row of user A, or the reason it cannot be built. */
async function rowFor(
  db: PGlite | Transaction,
  info: TableInfo,
  byName: Map<string, TableInfo>,
): Promise<{ columns: string[]; values: string[]; casts: string[] } | string> {
  const columns: string[] = [];
  const values: string[] = [];
  const casts: string[] = [];
  for (const column of info.columns) {
    if (column.generated) continue;
    let value: string | undefined;
    if (info.ownerColumns.includes(column.name)) value = USER_A;
    else if (column.parent) {
      const parent = byName.get(column.parent.name);
      const own = parent ? parent.mine : "true";
      const pick = async (where: string) =>
        (
          await db.query<{ v: string }>(
            `select ${quote(column.parent?.column ?? "")}::text as v from ${rel(column.parent?.name ?? "")} where ${where} limit 1`,
          )
        ).rows[0]?.v;
      value = (await pick(own)) ?? (info.ownedVia?.column === column.name ? undefined : await pick("true"));
      if (value === undefined && (column.notNull || info.ownedVia?.column === column.name)) {
        return `no row of user A in public.${column.parent.name} to point ${column.name} at`;
      }
    } else if (column.hasDefault && !column.unique) continue;
    else if (column.hasDefault && column.primaryKey) continue;
    else if (column.notNull || column.unique) {
      value = sampleValue(column);
      if (value === undefined && column.notNull) return `no sample value for ${column.name} (${column.type})`;
    }
    if (value === undefined) continue;
    columns.push(quote(column.name));
    values.push(value);
    casts.push(column.type);
  }
  return { columns, values, casts };
}

function insertSql(info: TableInfo, row: { columns: string[]; casts: string[] }): string {
  const placeholders = row.casts.map((cast, i) => `$${i + 1}::${cast}`);
  return `insert into ${rel(info.name)} (${row.columns.join(", ")}) values (${placeholders.join(", ")})`;
}

const CLAIMS: Record<Actor, { role: string; claims: string }> = {
  anon: { role: "anon", claims: JSON.stringify({ role: "anon" }) },
  "other-user": { role: "authenticated", claims: JSON.stringify({ sub: USER_B, role: "authenticated" }) },
  owner: { role: "authenticated", claims: JSON.stringify({ sub: USER_A, role: "authenticated" }) },
};

interface Outcome {
  rows: number;
  refused?: string;
  inconclusive?: string;
  code?: string;
}

/** Postgres refused the actor: missing privilege or an RLS check, the outcomes that mean "blocked". */
function isRefusal(code: string | undefined, message: string): boolean {
  return code === "42501" || /row-level security/i.test(message);
}

/**
 * Runs `sql` as `actor` in a transaction that is always rolled back. `prepare` runs first as the
 * superuser in the same transaction (to clear a unique slot the insert needs).
 */
async function tryAs(
  db: PGlite,
  actor: Actor,
  sql: string,
  params: unknown[] = [],
  prepare?: string,
): Promise<Outcome> {
  let outcome: Outcome = { rows: 0 };
  const { role, claims } = CLAIMS[actor];
  await db
    .transaction(async (tx) => {
      try {
        if (prepare) await tx.exec(prepare);
        await tx.query(`select set_config('request.jwt.claims', $1, true)`, [claims]);
        await tx.exec(`set local role ${role}`);
        const result = await tx.query<{ n: number }>(sql, params);
        outcome = { rows: Number(result.rows[0]?.n ?? 0) };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const code = (error as { code?: string }).code;
        outcome = isRefusal(code, message)
          ? { rows: 0, refused: message, code }
          : { rows: 0, inconclusive: message, code };
      }
      await tx.rollback();
    })
    .catch(() => undefined); // rollback() ends the transaction by throwing inside PGlite; nothing to keep
  return outcome;
}

const toCheck = (actor: Actor, action: ProbeCheck["action"], of: number, o: Outcome, column?: string): ProbeCheck => ({
  actor,
  action,
  ...(column ? { column } : {}),
  rows: o.rows,
  of,
  ...(o.refused ? { refused: o.refused } : {}),
  ...(o.inconclusive ? { inconclusive: o.inconclusive } : {}),
});

async function seed(db: PGlite, info: TableInfo, byName: Map<string, TableInfo>): Promise<string | undefined> {
  const { rows } = await db.query<{ n: number }>(`select count(*)::int as n from ${rel(info.name)} where ${info.mine}`);
  if ((rows[0]?.n ?? 0) > 0) return undefined; // a trigger already gave A a row (profiles), or shared data exists
  const row = await rowFor(db, info, byName);
  if (typeof row === "string") return row;
  try {
    await db.query(insertSql(info, row), row.values);
    return undefined;
  } catch (error) {
    return `seed insert failed: ${error instanceof Error ? error.message : String(error)}`;
  }
}

/** First column a no-op `set x = x` can touch: not an owner column, not the primary key, not generated. */
function touchColumn(info: TableInfo): string | undefined {
  const plain = info.columns.find((c) => !c.generated && !c.primaryKey && !info.ownerColumns.includes(c.name));
  return (plain ?? info.columns.find((c) => !c.generated))?.name;
}

/** Values to try for an escalation: different from the current one, most plausible first. */
function escalationValues(column: ColumnInfo, current: string | null): string[] {
  const type = baseType(column);
  if (column.enumLabels?.length) return column.enumLabels.filter((l) => l !== current).reverse();
  if (type === "boolean") return [current === "true" ? "false" : "true"];
  if (isNumber(type)) return [String(Number(current ?? 0) + 1000)];
  if (isText(type)) return ["pro", "premium", "admin", "enterprise", "probe-escalated"].filter((v) => v !== current);
  return [];
}

/** User A writes a new value into a paid column of their own row; counts only rows whose stored value changed. */
async function escalation(db: PGlite, info: TableInfo, column: ColumnInfo, of: number): Promise<ProbeCheck> {
  const target = rel(info.name);
  const { rows } = await db.query<{ v: string | null }>(
    `select ${quote(column.name)}::text as v from ${target} where ${info.mine} limit 1`,
  );
  const candidates = escalationValues(column, rows[0]?.v ?? null);
  let last: Outcome = { rows: 0, inconclusive: `no value to try for ${column.type}` };
  for (const value of candidates) {
    const o = await tryAs(
      db,
      "owner",
      `with u as (update ${target} set ${quote(column.name)} = $1::${column.type} where ${info.mine}
         returning (${quote(column.name)} is not distinct from $1::${column.type}) as changed)
       select (count(*) filter (where changed))::int as n from u`,
      [value],
    );
    // A trigger that raises (P0001) is a refusal for this purpose; a check constraint means: try another value.
    if (!o.refused && o.code === "P0001")
      return toCheck("owner", "update", of, { rows: 0, refused: o.inconclusive }, column.name);
    if (!o.inconclusive) return toCheck("owner", "update", of, o, column.name);
    last = o;
  }
  return toCheck("owner", "update", of, last, column.name);
}

async function probeTable(db: PGlite, info: TableInfo, byName: Map<string, TableInfo>): Promise<ProbeCheck[]> {
  const target = rel(info.name);
  const where = info.mine;
  const { rows } = await db.query<{ n: number }>(`select count(*)::int as n from ${target} where ${where}`);
  const of = rows[0]?.n ?? 0;
  const checks: ProbeCheck[] = [];
  const touch = touchColumn(info);
  // An insert in A's name collides with A's seeded row when the owner column is unique (profiles keyed by user).
  const ownerUnique = info.columns.some((c) => info.ownerColumns.includes(c.name) && c.unique);
  const clearSlot = ownerUnique ? `delete from ${target} where ${where}` : undefined;

  for (const actor of ["anon", "other-user"] as const) {
    checks.push(
      toCheck(actor, "select", of, await tryAs(db, actor, `select count(*)::int as n from ${target} where ${where}`)),
    );
    if (info.kind === "view") continue;

    const row = await rowFor(db, info, byName);
    if (typeof row === "string") {
      checks.push(toCheck(actor, "insert", 1, { rows: 0, inconclusive: row }));
    } else {
      const insert = await tryAs(
        db,
        actor,
        `with i as (${insertSql(info, row)} returning 1) select count(*)::int as n from i`,
        row.values,
        clearSlot,
      );
      checks.push(toCheck(actor, "insert", 1, insert));
    }
    if (touch) {
      const update = await tryAs(
        db,
        actor,
        `with u as (update ${target} set ${quote(touch)} = ${quote(touch)} where ${where} returning 1) select count(*)::int as n from u`,
      );
      checks.push(toCheck(actor, "update", of, update));
    }
    const remove = await tryAs(
      db,
      actor,
      `with d as (delete from ${target} where ${where} returning 1) select count(*)::int as n from d`,
    );
    checks.push(toCheck(actor, "delete", of, remove));
  }

  if (info.kind === "table" && info.ownerColumns.length) {
    for (const column of info.columns.filter((c) => PRIVILEGED_COLUMN.test(c.name) && !c.generated)) {
      checks.push(await escalation(db, info, column, of));
    }
  }
  return checks;
}

async function policiesOf(db: PGlite, name: string): Promise<ProbePolicy[]> {
  const { rows } = await db.query<{
    policyname: string;
    cmd: string;
    roles: string[];
    qual: string | null;
    with_check: string | null;
  }>(
    `select policyname, cmd, roles::text[] as roles, qual, with_check
       from pg_policies where schemaname = 'public' and tablename = $1 and permissive = 'PERMISSIVE'
      order by policyname`,
    [name],
  );
  return rows.map((r) => ({
    name: r.policyname,
    command: r.cmd.toLowerCase() as ProbePolicy["command"],
    roles: r.roles,
    using: r.qual ?? undefined,
    withCheck: r.with_check ?? undefined,
  }));
}

/** Extensions PGlite ships as contrib modules, by the name used in `create extension`. */
const CONTRIB: Record<string, string> = {
  "uuid-ossp": "uuid_ossp",
  pgcrypto: "pgcrypto",
  pg_trgm: "pg_trgm",
  citext: "citext",
  hstore: "hstore",
  ltree: "ltree",
  fuzzystrmatch: "fuzzystrmatch",
  unaccent: "unaccent",
  btree_gin: "btree_gin",
  btree_gist: "btree_gist",
  cube: "cube",
  earthdistance: "earthdistance",
  moddatetime: "moddatetime",
  tablefunc: "tablefunc",
  isn: "isn",
  seg: "seg",
  intarray: "intarray",
  lo: "lo",
};

/**
 * Supabase platform extensions that matter for the hosted service, not for row access. Their
 * `create extension` lines are skipped (the shim stubs `cron.schedule`); a migration that then uses one
 * of them for a table still fails to load, and the report says so.
 */
const PLATFORM = new Set([
  "pg_net",
  "pg_cron",
  "pg_graphql",
  "pgsodium",
  "supabase_vault",
  "pgjwt",
  "pg_stat_statements",
  "http",
  "wrappers",
  "index_advisor",
  "hypopg",
  "plpgsql_check",
  "pg_stat_monitor",
  "pg_jsonschema",
]);

const CREATE_EXTENSION = /create\s+extension\s+(?:if\s+not\s+exists\s+)?"?([\w-]+)"?[^;]*;/gi;

async function extensionsFor(migrations: SqlFile[]): Promise<Extensions> {
  const wanted = new Set(
    migrations.flatMap((m) => [...m.text.matchAll(CREATE_EXTENSION)].map((x) => (x[1] ?? "").toLowerCase())),
  );
  const out: Extensions = {};
  for (const name of wanted) {
    const module = CONTRIB[name];
    if (!module) continue;
    const loaded = (await import(`@electric-sql/pglite/contrib/${module}`)) as Record<string, Extensions[string]>;
    const ext = loaded[module];
    if (ext) out[module] = ext;
  }
  return out;
}

function stepOverPlatformExtensions(text: string, skipped: Set<string>): string {
  return text.replace(CREATE_EXTENSION, (statement, name: string) => {
    if (!PLATFORM.has(name.toLowerCase())) return statement;
    skipped.add(name.toLowerCase());
    return `-- prelaunch-audit probe: skipped ${statement.replace(/\s+/g, " ")}`;
  });
}

export async function probeRls(migrations: SqlFile[]): Promise<ProbeResult> {
  const ordered = [...migrations].sort((a, b) => a.path.localeCompare(b.path));
  const skippedExtensions = new Set<string>();
  const db = await PGlite.create({ extensions: await extensionsFor(ordered) });
  const fail = (error: string): ProbeResult => ({
    tables: [],
    migrations: ordered.length,
    skippedExtensions: [...skippedExtensions],
    error,
  });
  try {
    await db.exec(await readFile(SHIM_PATH, "utf8"));
    for (const migration of ordered) {
      try {
        await db.exec(stepOverPlatformExtensions(migration.text, skippedExtensions));
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        return fail(`${migration.path} did not load in PGlite: ${reason}.`);
      }
    }
    await db.query(
      `insert into auth.users (id, email, raw_user_meta_data) values
         ($1, 'user-a@example.invalid', '{"full_name":"User A"}'), ($2, 'user-b@example.invalid', '{"full_name":"User B"}')`,
      [USER_A, USER_B],
    );

    const tables = await tablesOf(db);
    const byName = new Map(tables.map((t) => [t.name, t]));
    const ordering = seedOrder(tables.filter((t) => t.kind === "table"));
    linkOwnership(ordering);
    const skipped = new Map<string, string>();
    for (const info of ordering) {
      await fixMine(db, info, byName);
      const reason = await seed(db, info, byName);
      if (reason) skipped.set(info.name, reason);
    }
    for (const view of tables.filter((t) => t.kind === "view")) await fixMine(db, view, byName);

    const out: TableProbe[] = [];
    for (const info of tables) {
      const base = {
        table: `public.${info.name}`,
        name: info.name,
        kind: info.kind,
        rls: info.rls,
        columns: info.columns.map((c) => c.name),
        ownerColumns: info.ownerColumns,
        ...(info.ownedVia ? { ownedVia: info.ownedVia } : {}),
        policies: info.kind === "table" ? await policiesOf(db, info.name) : [],
      };
      const reason = skipped.get(info.name);
      out.push(
        reason ? { ...base, checks: [], skipped: reason } : { ...base, checks: await probeTable(db, info, byName) },
      );
    }
    return { tables: out, migrations: ordered.length, skippedExtensions: [...skippedExtensions] };
  } catch (error) {
    return fail(`the probe stopped: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    await db.close();
  }
}
