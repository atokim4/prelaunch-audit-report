import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { PGlite, type Extensions, type Transaction } from "@electric-sql/pglite";
import { statements, type SqlFile } from "../patches/sql.ts";
import { isStrict, loadOrder } from "./sources.ts";
import { detectTenancy, type Tenancy } from "./tenancy.ts";
import type { Actor, OwnedVia, ProbeCheck, ProbePolicy, TenantLink } from "../types.ts";

/**
 * Behavioural Row Level Security check. Loads the repo's migrations into PGlite (Postgres in
 * WebAssembly) on top of a small Supabase shim, creates two users, gives user A one row in every
 * table, then tries every action as a visitor without an account (anon) and as user B. Each try runs
 * in a transaction that is rolled back, so the counts are what the API roles really get, not what a
 * policy looks like. A try that fails for a reason other than a refusal (a constraint the guessed
 * values break) is recorded as inconclusive, never as "blocked".
 */

export const PROBE_VERSION = "1.3.0";
export const SHIM_PATH = new URL("./supabase-shim.sql", import.meta.url);

export const USER_A = "00000000-0000-4000-8000-00000000000a";
export const USER_B = "00000000-0000-4000-8000-00000000000b";
/** Only with an organization model: C is signed in and belongs to no organization; D founded organization A. */
export const USER_C = "00000000-0000-4000-8000-00000000000c";
export const USER_D = "00000000-0000-4000-8000-00000000000d";

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
  /** Rows belong to an organization (team, workspace) through this link. */
  tenant?: TenantLink;
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
  /** Statements of schema files outside supabase/migrations that Postgres rejected (stepped over). */
  failedStatements: FailedStatement[];
  /** SECURITY DEFINER functions in public after the load, and whether anon may execute any overload. */
  definerFunctions?: { name: string; anon: boolean }[];
  /** Set when the migrations did not load; no tables then. */
  error?: string;
}

export interface FailedStatement {
  file: string;
  /** 1-based index of the statement in the file. */
  index: number;
  message: string;
  /** The statement text, for telling which tables it was about. */
  text: string;
}

/** True when rows belong to someone: an owner column, a parent that has one, or an organization. */
export const isOwned = (t: { ownerColumns: string[]; ownedVia?: OwnedVia; tenant?: TenantLink }): boolean =>
  t.ownerColumns.length > 0 || t.ownedVia !== undefined || t.tenant !== undefined;

/** A check that got through: the actor read or changed rows it should not. */
export function leaks(probe: Pick<TableProbe, "checks" | "ownerColumns" | "ownedVia" | "tenant">): ProbeCheck[] {
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
    checks: string[] | null;
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
            (select array_agg(e.enumlabel::text order by e.enumsortorder) from pg_enum e where e.enumtypid = a.atttypid) as enum_labels,
            (select array_agg(pg_get_constraintdef(k.oid)) from pg_constraint k
              where k.conrelid = a.attrelid and k.contype = 'c' and k.conkey = array[a.attnum]) as checks
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
    enumLabels: r.enum_labels ?? allowedValues(r.checks ?? []),
  }));
}

/**
 * The values a one-column CHECK allows, when it is a list: Postgres stores `role in ('owner', 'member')`
 * as `CHECK ((role = ANY (ARRAY['owner'::text, 'member'::text])))`. Undefined for any other check.
 */
export function allowedValues(checks: string[]): string[] | undefined {
  for (const def of checks) {
    if (!/=\s*ANY\s*\(\s*\(?\s*ARRAY\[/i.test(def) || /\b(AND|OR|NOT)\b/.test(def)) continue;
    const values = [...def.matchAll(/'((?:[^']|'')*)'::/g)].map((m) => (m[1] ?? "").replaceAll("''", "'"));
    if (values.length) return values;
  }
  return undefined;
}

const baseType = (column: ColumnInfo): string => column.type.replace(/\(.*\)/, "").trim();
const isText = (type: string): boolean => /^(text|character varying|character|citext|name)$/.test(type);
const isNumber = (type: string): boolean => /^(smallint|integer|bigint|numeric|real|double precision)$/.test(type);

/** A value Postgres accepts for the column type, as text to cast; undefined when there is no safe guess. */
/** Enum labels that grant something: user A must start without them, or an escalation check proves nothing. */
const PRIVILEGED_LABEL = /admin|super|owner|staff|manager|moderator|root|pro|premium|enterprise|paid|business/i;

function sampleValue(column: ColumnInfo): string | undefined {
  if (column.enumLabels?.length) {
    const plain = PRIVILEGED_COLUMN.test(column.name)
      ? column.enumLabels.find((l) => !PRIVILEGED_LABEL.test(l))
      : /^(status|state)$/i.test(column.name)
        ? column.enumLabels.find((l) => /^(active|accepted|approved|enabled|joined)$/i.test(l))
        : undefined;
    return plain ?? column.enumLabels[0];
  }
  const type = baseType(column);
  if (type.endsWith("[]")) return "{}";
  // Unique columns need a fresh value per insert, or a second insert fails on the index, not on RLS.
  // Email columns often carry a format CHECK; a valid address passes it.
  if (isText(type) && /e_?mail/i.test(column.name)) return `probe-${randomUUID().slice(0, 8)}@example.com`;
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
  tenant?: TenantLink;
  /** Foreign keys over more than one column: their values have to come from the same parent row. */
  compositeKeys: CompositeKey[];
  /** SQL condition true for user A's rows, fixed after seeding (literal values, no RLS-dependent subquery). */
  mine: string;
}

interface CompositeKey {
  columns: string[];
  parent: string;
  parentColumns: string[];
}

async function compositeKeysOf(db: PGlite, oid: number): Promise<CompositeKey[]> {
  const { rows } = await db.query<{ columns: string[]; parent: string; parent_columns: string[] }>(
    `select array(select a.attname::text from unnest(f.conkey) with ordinality k(n, i)
                    join pg_attribute a on a.attrelid = f.conrelid and a.attnum = k.n order by k.i) as columns,
            fc.relname::text as parent,
            array(select a.attname::text from unnest(f.confkey) with ordinality k(n, i)
                    join pg_attribute a on a.attrelid = f.confrelid and a.attnum = k.n order by k.i) as parent_columns
       from pg_constraint f join pg_class fc on fc.oid = f.confrelid join pg_namespace fn on fn.oid = fc.relnamespace
      where f.conrelid = $1 and f.contype = 'f' and array_length(f.conkey, 1) > 1 and fn.nspname = 'public'`,
    [oid],
  );
  return rows.map((r) => ({ columns: r.columns, parent: r.parent, parentColumns: r.parent_columns }));
}

function ownerColumnsOf(columns: ColumnInfo[]): string[] {
  const linked = columns.filter((c) => c.user).map((c) => c.name);
  if (linked.length) return linked;
  return columns.filter((c) => OWNER_NAME.test(c.name) && c.type === "uuid").map((c) => c.name);
}

/**
 * Functions without arguments that return the caller's id: `auth.uid()` behind a wrapper such as
 * `private.current_uid()` (no table read in the body). Policies that compare a column to one of them own
 * rows by that column.
 */
async function callerIdFunctions(db: PGlite): Promise<string[]> {
  const { rows } = await db.query<{ name: string }>(
    `select p.proname::text as name from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where p.pronargs = 0 and n.nspname not in ('pg_catalog', 'information_schema', 'auth')
        and p.prorettype in ('uuid'::regtype, 'text'::regtype)
        and p.prosrc ~* 'auth\\.uid\\s*\\(' and p.prosrc !~* '\\mfrom\\M'`,
  );
  return rows.map((r) => r.name);
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Owner columns read from the table's policies, for tables with no column tied to auth.users (ids kept as
 * text, as Prisma does): a uuid or text column compared with `auth.uid()` or a caller-id wrapper.
 */
async function ownerColumnsFromPolicies(db: PGlite, info: TableInfo, wrappers: string[]): Promise<string[]> {
  const { rows } = await db.query<{ expr: string }>(
    `select coalesce(qual, '') || ' ' || coalesce(with_check, '') as expr
       from pg_policies where schemaname = 'public' and tablename = $1`,
    [info.name],
  );
  const caller = [String.raw`auth\.uid\(\)`, ...wrappers.map((w) => String.raw`(?:\w+\.)?${escapeRegExp(w)}\(\)`)].join(
    "|",
  );
  // `col = auth.uid()`, `col = ( SELECT auth.uid() AS uid)`, `col = (auth.uid())::text`, and the reverse.
  const call = String.raw`[(\s]*(?:select\s+)?[(\s]*(?:${caller})`;
  const column = String.raw`(?:"((?:[^"]|"")+)"|([a-z_]\w*))`;
  const patterns = [
    new RegExp(`${column}\\s*=\\s*${call}`, "gi"),
    new RegExp(`(?:${caller})[^=]{0,40}=\\s*\\(*\\s*${column}`, "gi"),
  ];
  const names = new Set<string>();
  for (const { expr } of rows) {
    for (const pattern of patterns) {
      for (const m of expr.matchAll(pattern)) names.add((m[1] ?? m[2] ?? "").replaceAll('""', '"'));
    }
  }
  return info.columns.filter((c) => names.has(c.name) && (c.type === "uuid" || isText(baseType(c)))).map((c) => c.name);
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
      compositeKeys: await compositeKeysOf(db, row.oid),
      mine: "false",
    });
  }
  const wrappers = await callerIdFunctions(db);
  for (const info of out.filter((t) => t.kind === "table" && !t.ownerColumns.length)) {
    info.ownerColumns = await ownerColumnsFromPolicies(db, info, wrappers);
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
    const parents = [...info.columns.map((c) => c.parent?.name), ...info.compositeKeys.map((k) => k.parent)];
    for (const name of parents) {
      const parent = name ? byName.get(name) : undefined;
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
async function fixMine(db: PGlite, info: TableInfo, byName: Map<string, TableInfo>, orgs?: TenantSeed): Promise<void> {
  if (info.tenant) {
    info.mine = await tenantMine(db, info.tenant, byName, orgs);
    return;
  }
  if (info.ownerColumns.length) {
    info.mine = `(${info.ownerColumns.map((c) => `${quote(c)}::text = '${USER_A}'`).join(" or ")})`;
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

/** The two organizations the probe made: A has user A as a plain member, B has user B as an admin. */
interface TenantSeed {
  tenancy: Tenancy;
  orgA?: string;
  orgB?: string;
}

/** "Organization A's rows" as literal SQL. */
async function tenantMine(
  db: PGlite,
  link: TenantLink,
  byName: Map<string, TableInfo>,
  orgs: TenantSeed | undefined,
): Promise<string> {
  if (!orgs?.orgA) return "false";
  const org = lit(orgs.orgA);
  const via = link.via;
  if (via.kind === "tenant") return `${quote(link.tenantKey)}::text = ${org}`;
  if (via.kind === "members") return `${quote(link.members.tenantColumn)}::text = ${org}`;
  if (via.kind === "column") return `${quote(via.column)}::text = ${org}`;
  const parent = byName.get(via.parent.replace(/^public\./, ""));
  if (!parent) return "false";
  const { rows } = await db.query<{ v: string }>(
    `select distinct ${quote(via.parentColumn)}::text as v from ${rel(parent.name)} where ${parent.mine}`,
  );
  return rows.length ? `${quote(via.column)}::text in (${rows.map((r) => lit(r.v)).join(", ")})` : "false";
}

/**
 * Column values for one new row, or the reason it cannot be built. Owner columns get `owner` (user A
 * unless said otherwise); `overrides` pins columns by name (the organization and user of a membership).
 */
async function rowFor(
  db: PGlite | Transaction,
  info: TableInfo,
  byName: Map<string, TableInfo>,
  owner: string = USER_A,
  overrides: Record<string, string> = {},
): Promise<{ columns: string[]; values: string[]; casts: string[] } | string> {
  const columns: string[] = [];
  const values: string[] = [];
  const casts: string[] = [];
  // A composite foreign key (project_id, tenant_id) -> projects (id, tenant_id) takes every value from one
  // parent row, user A's (or organization A's) when there is one; pinned values narrow the choice.
  const pinned: Record<string, string> = { ...overrides };
  for (const key of info.compositeKeys) {
    const parent = byName.get(key.parent);
    const fixed = key.columns
      .map((c, i) => (c in pinned ? `${quote(key.parentColumns[i] ?? "")}::text = ${lit(pinned[c] ?? "")}` : ""))
      .filter(Boolean);
    const pick = async (where: string) =>
      (
        await db.query<Record<string, string>>(
          `select ${key.parentColumns.map((c, i) => `${quote(c)}::text as c${i}`).join(", ")} from ${rel(key.parent)}
            where (${where})${fixed.length ? ` and ${fixed.join(" and ")}` : ""} limit 1`,
        )
      ).rows[0];
    const row = (await pick(parent?.mine ?? "true")) ?? (await pick("true"));
    if (!row) return `no row in public.${key.parent} to point ${key.columns.join(", ")} at`;
    key.columns.forEach((c, i) => {
      const v = row[`c${i}`];
      if (v !== undefined && v !== null) pinned[c] = v;
    });
  }
  for (const column of info.columns) {
    if (column.generated) continue;
    let value: string | undefined;
    if (column.name in pinned) value = pinned[column.name];
    else if (info.ownerColumns.includes(column.name)) value = owner;
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
  // Every column has a default (a settings table keyed by 'default'): there is nothing to list.
  if (!row.columns.length) return `insert into ${rel(info.name)} default values`;
  const placeholders = row.casts.map((cast, i) => `$${i + 1}::${cast}`);
  return `insert into ${rel(info.name)} (${row.columns.join(", ")}) values (${placeholders.join(", ")})`;
}

const CLAIMS: Record<Actor, { role: string; claims: string }> = {
  anon: { role: "anon", claims: JSON.stringify({ role: "anon" }) },
  "other-user": { role: "authenticated", claims: JSON.stringify({ sub: USER_B, role: "authenticated" }) },
  owner: { role: "authenticated", claims: JSON.stringify({ sub: USER_A, role: "authenticated" }) },
  "non-member": { role: "authenticated", claims: JSON.stringify({ sub: USER_C, role: "authenticated" }) },
};

/**
 * Per database: claims to send instead of the plain ones, when the schema reads the organization from the
 * token (`auth.jwt() -> 'app_metadata' ->> 'org_id'`, set by a custom access token hook).
 */
const JWT_EXTRA = new WeakMap<PGlite, Partial<Record<Actor, string>>>();

/** app_metadata keys the functions and policies read, sorted into organization and role keys. */
async function tokenKeys(db: PGlite): Promise<{ org: string[]; role: string[] }> {
  const { rows } = await db.query<{ src: string }>(
    `select p.prosrc as src from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname not in ('pg_catalog', 'information_schema', 'auth', 'storage', 'extensions')
     union all select coalesce(qual, '') || ' ' || coalesce(with_check, '') from pg_policies`,
  );
  const keys = new Set<string>();
  for (const { src } of rows) {
    for (const m of src.matchAll(/app_metadata'(?:::text)?\s*->>?\s*'(\w+)'/g)) keys.add(m[1] ?? "");
  }
  const all = [...keys];
  return {
    org: all.filter((k) => /org|tenant|team|workspace|account|company|unit/i.test(k)),
    role: all.filter((k) => /role/i.test(k)),
  };
}

async function tenantClaims(db: PGlite, orgs: TenantSeed): Promise<void> {
  const keys = await tokenKeys(db);
  if (!keys.org.length || !orgs.orgA || !orgs.orgB) return;
  const m = orgs.tenancy.members;
  const meta = (org: string, role: string | undefined) =>
    Object.fromEntries([...keys.org.map((k) => [k, org]), ...keys.role.map((k) => [k, role ?? "member"])]);
  const token = (sub: string, appMetadata: Record<string, string>) =>
    JSON.stringify({ sub, role: "authenticated", app_metadata: appMetadata });
  JWT_EXTRA.set(db, {
    owner: token(USER_A, meta(orgs.orgA, m.memberRole)),
    "other-user": token(USER_B, meta(orgs.orgB, m.adminRoles[0] ?? m.memberRole)),
    "non-member": token(USER_C, {}),
  });
}

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
 * superuser in the same transaction (to clear a unique slot the insert needs). With `verify`, `sql` returns
 * nothing (no RETURNING, as supabase-js sends a plain update) and `verify` counts the result afterwards as
 * the superuser, in the same transaction: RETURNING would also apply the select policies to the new row.
 */
async function tryAs(
  db: PGlite,
  actor: Actor,
  sql: string,
  params: unknown[] = [],
  prepare?: string,
  verify?: string,
): Promise<Outcome> {
  let outcome: Outcome = { rows: 0 };
  const { role } = CLAIMS[actor];
  const claims = JWT_EXTRA.get(db)?.[actor] ?? CLAIMS[actor].claims;
  await db
    .transaction(async (tx) => {
      try {
        if (prepare) await tx.exec(prepare);
        await tx.query(`select set_config('request.jwt.claims', $1, true)`, [claims]);
        await tx.exec(`set local role ${role}`);
        const result = await tx.query<{ n: number }>(sql, params);
        if (verify) {
          await tx.exec("reset role");
          outcome = { rows: Number((await tx.query<{ n: number }>(verify)).rows[0]?.n ?? 0) };
        } else outcome = { rows: Number(result.rows[0]?.n ?? 0) };
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

const toCheck = (
  actor: Actor,
  action: ProbeCheck["action"],
  of: number,
  o: Outcome,
  column?: string,
  scenario?: ProbeCheck["scenario"],
): ProbeCheck => ({
  actor,
  action,
  ...(column ? { column } : {}),
  ...(scenario ? { scenario } : {}),
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

/** Runs `sql` as the superuser with `auth.uid()` = `uid`, so triggers that record the creator see one. */
async function insertAs(db: PGlite, uid: string, sql: string, params: string[]): Promise<{ k: string }[]> {
  return db.transaction(async (tx) => {
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [
      JSON.stringify({ sub: uid, role: "authenticated" }),
    ]);
    return (await tx.query<{ k: string }>(sql, params)).rows;
  });
}

const errorText = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** Organization A (founded by D) and organization B (founded by user B). */
async function seedTenants(
  db: PGlite,
  info: TableInfo,
  byName: Map<string, TableInfo>,
  orgs: TenantSeed,
): Promise<string | undefined> {
  const key = quote(orgs.tenancy.tenantKey);
  const made: string[] = [];
  for (const founder of [USER_D, USER_B]) {
    const row = await rowFor(db, info, byName, founder);
    if (typeof row === "string") return row;
    try {
      const rows = await insertAs(db, founder, `${insertSql(info, row)} returning ${key}::text as k`, row.values);
      if (rows[0]) made.push(rows[0].k);
    } catch (error) {
      return `seed insert of an organization failed: ${errorText(error)}`;
    }
  }
  [orgs.orgA, orgs.orgB] = made;
  return made.length === 2 ? undefined : "the organization rows did not come back";
}

/** User A joins organization A as a plain member, user B joins organization B as an admin. */
async function seedMembers(
  db: PGlite,
  info: TableInfo,
  byName: Map<string, TableInfo>,
  orgs: TenantSeed,
): Promise<string | undefined> {
  const m = orgs.tenancy.members;
  if (!orgs.orgA || !orgs.orgB) return "no organization rows to add members to";
  const tries: [string, string, string | undefined][] = [
    [orgs.orgA, USER_A, m.memberRole],
    [orgs.orgB, USER_B, m.adminRoles[0] ?? m.memberRole],
  ];
  for (const [org, user, role] of tries) {
    const pinned: Record<string, string> = { [m.tenantColumn]: org, [m.userColumn]: user };
    if (m.roleColumn && role) pinned[m.roleColumn] = role;
    const row = await rowFor(db, info, byName, user, pinned);
    if (typeof row === "string") return row;
    try {
      await insertAs(db, user, `${insertSql(info, row)} on conflict do nothing returning 1 as k`, row.values);
      // A trigger may already have added the user with another role: A has to be a plain member.
      if (m.roleColumn && role) {
        await db.query(
          `update ${rel(info.name)} set ${quote(m.roleColumn)} = $1::text::${info.columns.find((c) => c.name === m.roleColumn)?.type ?? "text"}
            where ${quote(m.tenantColumn)}::text = $2 and ${quote(m.userColumn)}::text = $3`,
          [role, org, user],
        );
      }
    } catch (error) {
      return `seed insert of a membership failed: ${errorText(error)}`;
    }
  }
  return undefined;
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
async function escalation(
  db: PGlite,
  info: TableInfo,
  column: ColumnInfo,
  of: number,
  own: string = info.mine,
): Promise<ProbeCheck> {
  const target = rel(info.name);
  const { rows } = await db.query<{ v: string | null }>(
    `select ${quote(column.name)}::text as v from ${target} where ${own} limit 1`,
  );
  const candidates = escalationValues(column, rows[0]?.v ?? null);
  let last: Outcome = { rows: 0, inconclusive: `no value to try for ${column.type}` };
  for (const value of candidates) {
    const o = await tryAs(
      db,
      "owner",
      `with u as (update ${target} set ${quote(column.name)} = $1::${column.type} where ${own}
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

/** Membership tries: user B adds themselves to organization A; user A moves their own row to organization B. */
async function membershipChecks(
  db: PGlite,
  info: TableInfo,
  byName: Map<string, TableInfo>,
  orgs: TenantSeed,
  own: string,
): Promise<ProbeCheck[]> {
  const m = orgs.tenancy.members;
  if (!orgs.orgA || !orgs.orgB) return [];
  const target = rel(info.name);
  const pinned: Record<string, string> = { [m.tenantColumn]: orgs.orgA, [m.userColumn]: USER_B };
  if (m.roleColumn && m.memberRole) pinned[m.roleColumn] = m.memberRole;
  const row = await rowFor(db, info, byName, USER_B, pinned);
  const join =
    typeof row === "string"
      ? { rows: 0, inconclusive: row }
      : await tryAs(
          db,
          "other-user",
          `with i as (${insertSql(info, row)} returning 1) select count(*)::int as n from i`,
          row.values,
        );
  const type = info.columns.find((c) => c.name === m.tenantColumn)?.type ?? "text";
  const move = await tryAs(
    db,
    "owner",
    `update ${target} set ${quote(m.tenantColumn)} = $1::text::${type} where ${own}`,
    [orgs.orgB],
    undefined,
    `select count(*)::int as n from ${target}
      where ${quote(m.userColumn)}::text = '${USER_A}' and ${quote(m.tenantColumn)}::text = ${lit(orgs.orgB)}`,
  );
  return [
    toCheck("other-user", "insert", 1, join, undefined, "self-join"),
    toCheck("owner", "update", 1, move, m.tenantColumn, "move-tenant"),
  ];
}

async function probeTable(
  db: PGlite,
  info: TableInfo,
  byName: Map<string, TableInfo>,
  orgs?: TenantSeed,
): Promise<ProbeCheck[]> {
  const target = rel(info.name);
  const where = info.mine;
  const { rows } = await db.query<{ n: number }>(`select count(*)::int as n from ${target} where ${where}`);
  const of = rows[0]?.n ?? 0;
  const checks: ProbeCheck[] = [];
  const touch = touchColumn(info);
  // An insert in A's name collides with A's seeded row when the owner column is unique (profiles keyed by user).
  const ownerUnique = info.columns.some((c) => info.ownerColumns.includes(c.name) && c.unique);
  const clearSlot = ownerUnique ? `delete from ${target} where ${where}` : undefined;
  const via = info.tenant?.via.kind;
  const actors: Actor[] = info.tenant ? ["anon", "other-user", "non-member"] : ["anon", "other-user"];

  for (const actor of actors) {
    checks.push(
      toCheck(actor, "select", of, await tryAs(db, actor, `select count(*)::int as n from ${target} where ${where}`)),
    );
    // User C stands for "any signed-in account": reads only; user B covers writes from outside.
    if (info.kind === "view" || actor === "non-member") continue;

    // Joining organization A is its own try (membershipChecks). Creating a new organization is normal, and
    // one that names user A as its creator gives B nothing of A's, so B does not try it.
    const skipInsert = actor === "other-user" && (via === "members" || via === "tenant");
    const row = skipInsert ? undefined : await rowFor(db, info, byName);
    if (typeof row === "string") {
      checks.push(toCheck(actor, "insert", 1, { rows: 0, inconclusive: row }));
    } else if (row) {
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

  if (info.kind === "table" && (info.ownerColumns.length || info.tenant)) {
    const m = info.tenant?.members;
    // On a membership table, user A may only touch their own row; elsewhere, user A's (or organization A's) rows.
    const own =
      via === "members" && m && orgs?.orgA
        ? `${quote(m.userColumn)}::text = '${USER_A}' and ${quote(m.tenantColumn)}::text = ${lit(orgs.orgA)}`
        : where;
    const privileged = info.columns.filter(
      (c) => !c.generated && (PRIVILEGED_COLUMN.test(c.name) || (via === "members" && c.name === m?.roleColumn)),
    );
    for (const column of privileged) checks.push(await escalation(db, info, column, of, own));
    if (via === "members" && orgs) checks.push(...(await membershipChecks(db, info, byName, orgs, own)));
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

/** Error codes for an object that already exists: a second copy of the schema (install bundle + baseline). */
const ALREADY_THERE = new Set(["42P07", "42710", "42P06", "42723", "42701", "42P16", "42P05"]);

/**
 * Loads one schema file that does not live in supabase/migrations statement by statement. Such files are
 * often dumps or bundles that repeat objects, or use a psql command; a statement Postgres rejects is
 * stepped over and recorded, so the tables it was about can be left out of the probe instead of tested in
 * a state the real database is not in.
 */
async function loadTolerant(db: PGlite, file: SqlFile, text: string, failed: FailedStatement[]): Promise<void> {
  const list = statements(text);
  for (const [i, statement] of list.entries()) {
    try {
      await db.exec(statement);
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code && ALREADY_THERE.has(code)) continue;
      const message = error instanceof Error ? error.message : String(error);
      failed.push({ file: file.path, index: i + 1, message, text: statement });
    }
  }
}

const NAME = String.raw`((?:"(?:[^"]|"")+"|[\w$]+)(?:\s*\.\s*(?:"(?:[^"]|"")+"|[\w$]+))?)`;
/** What a statement is about: create/alter table, a policy, trigger, index or grant on it. */
const TARGETS = [
  new RegExp(String.raw`^\s*create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${NAME}`, "i"),
  new RegExp(String.raw`^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${NAME}`, "i"),
  new RegExp(String.raw`^\s*create\s+policy\s+(?:"(?:[^"]|"")+"|\w+)\s+on\s+${NAME}`, "i"),
  new RegExp(
    String.raw`^\s*(?:create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger|create\s+(?:unique\s+)?index|grant|revoke|comment)\b[\s\S]*?\bon\s+(?:table\s+)?(?:only\s+)?${NAME}`,
    "i",
  ),
];

/** The bare table name a DDL statement is about, or undefined when it is something else (a DO block). */
export function statementTarget(statement: string): string | undefined {
  const body = statement.replace(/^(?:\s*--[^\n]*\n)+/, "");
  for (const pattern of TARGETS) {
    const raw = body.match(pattern)?.[1];
    if (!raw) continue;
    const last = raw.split(/\s*\.\s*(?=(?:"|[\w$]))/).pop() ?? raw;
    return last.startsWith('"') ? last.slice(1, -1).replaceAll('""', '"') : last.toLowerCase();
  }
  return undefined;
}

/**
 * The statement is about the table: its target when the statement has one (a failed `create table x
 * (... references organizations)` is about x, not organizations), else any mention of the name (quoted
 * names exactly, plain names in any case).
 */
function mentions(statement: string, table: string): boolean {
  const target = statementTarget(statement);
  if (target !== undefined) return target === table;
  const name = escapeRegExp(table);
  const plain = /^[a-z_][a-z0-9_]*$/.test(table) ? `|\\b${name}\\b` : "";
  return new RegExp(`"${name}"${plain}`, plain ? "i" : "").test(statement);
}

/**
 * `tolerant` loads every file statement by statement, supabase/migrations included: used for the retry
 * with a base schema file, where migrations may repeat objects the base file already made.
 */
export async function probeRls(migrations: SqlFile[], tolerant = false): Promise<ProbeResult> {
  const ordered = loadOrder(migrations);
  const skippedExtensions = new Set<string>();
  const failedStatements: FailedStatement[] = [];
  const db = await PGlite.create({ extensions: await extensionsFor(ordered) });
  const fail = (error: string): ProbeResult => ({
    tables: [],
    migrations: ordered.length,
    skippedExtensions: [...skippedExtensions],
    failedStatements,
    error,
  });
  try {
    await db.exec(await readFile(SHIM_PATH, "utf8"));
    for (const migration of ordered) {
      const text = stepOverPlatformExtensions(migration.text, skippedExtensions);
      if (tolerant || !isStrict(migration.path)) {
        await loadTolerant(db, migration, text, failedStatements);
        continue;
      }
      try {
        await db.exec(text);
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
    const { rows: definerFunctions } = await db.query<{ name: string; anon: boolean }>(
      `select p.proname::text as name, bool_or(has_function_privilege('anon', p.oid, 'execute')) as anon
         from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.prosecdef group by p.proname order by 1`,
    );
    const byName = new Map(tables.map((t) => [t.name, t]));
    const ordering = seedOrder(tables.filter((t) => t.kind === "table"));
    linkOwnership(ordering);
    // An organization model decides who owns the rows it reaches, ahead of a creator column or a parent.
    const tenancy = detectTenancy(tables);
    const orgs: TenantSeed | undefined = tenancy ? { tenancy } : undefined;
    if (tenancy) {
      for (const info of tables) {
        const link = tenancy.links.get(info.name);
        if (!link) continue;
        info.tenant = link;
        delete info.ownedVia;
      }
      await db.query(
        `insert into auth.users (id, email, raw_user_meta_data) values
           ($1, 'user-c@example.invalid', '{"full_name":"User C"}'), ($2, 'user-d@example.invalid', '{"full_name":"User D"}')`,
        [USER_C, USER_D],
      );
    }
    const skipped = new Map<string, string>();
    // A table a rejected statement was about (its RLS switch, a policy) is not in the state the real database
    // is in, so the probe leaves it out rather than report what that missing statement would have blocked.
    for (const info of tables) {
      const hit = failedStatements.find((f) => mentions(f.text, info.name));
      if (hit)
        skipped.set(info.name, `statement ${hit.index} of ${hit.file} that names it did not load: ${hit.message}`);
    }
    for (const info of ordering) {
      if (skipped.has(info.name)) continue;
      const via = info.tenant?.via.kind;
      const first =
        orgs && via === "tenant"
          ? await seedTenants(db, info, byName, orgs)
          : orgs && via === "members"
            ? await seedMembers(db, info, byName, orgs)
            : undefined;
      if (first) {
        skipped.set(info.name, first);
        continue;
      }
      await fixMine(db, info, byName, orgs);
      const reason = await seed(db, info, byName);
      if (reason) skipped.set(info.name, reason);
    }
    for (const view of tables.filter((t) => t.kind === "view")) await fixMine(db, view, byName, orgs);
    if (orgs) await tenantClaims(db, orgs);

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
        ...(info.tenant ? { tenant: info.tenant } : {}),
        policies: info.kind === "table" ? await policiesOf(db, info.name) : [],
      };
      const reason = skipped.get(info.name);
      out.push(
        reason
          ? { ...base, checks: [], skipped: reason }
          : { ...base, checks: await probeTable(db, info, byName, orgs) },
      );
    }
    return {
      tables: out,
      migrations: ordered.length,
      skippedExtensions: [...skippedExtensions],
      failedStatements,
      definerFunctions,
    };
  } catch (error) {
    return fail(`the probe stopped: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    await db.close();
  }
}
