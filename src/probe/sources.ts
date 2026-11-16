import type { SqlFile } from "../patches/sql.ts";

/**
 * Which SQL files the RLS probe loads, and in what order. Supabase migrations are the schema when they
 * exist; tables an ORM creates (Prisma, Drizzle) load before them, because the Supabase migrations put
 * policies on those tables. A repo without supabase/migrations keeps its schema elsewhere (a schema.sql,
 * sql/, db/migrations): base files load first, then each migrations folder in path order.
 */

export const SUPABASE_MIGRATIONS = /^supabase\/migrations\/[^/]+\.sql$/;

/** Migrations an ORM writes: they create the tables, Supabase SQL then adds RLS to them. */
const ORM_MIGRATIONS = /(?:^|\/)(?:prisma\/migrations\/[^/]+\/migration\.sql$|drizzle\/[^/]+\.sql$)/;

/** Folders and names of SQL that is not schema: seeds, demos, tests, rollbacks, read-only diagnostics, docs. */
const NOT_SCHEMA_DIR =
  /(?:^|\/)(?:docs?|examples?|tests?|__tests__|spec|scripts|diagnostics?|seeds?|fixtures?|optional|manual)\//i;
const NOT_SCHEMA_NAME =
  /(?:^|[-_.])(?:seeds?|demo|samples?|fixtures?|rollback|down|revert|teardown|diagnostics?|verify|verification|queries)(?:[-_.]|$)/i;

const inMigrationsFolder = (path: string): boolean => /(?:^|\/)migrations\//i.test(path);

export function isSchemaSql(path: string): boolean {
  const name = path.split("/").pop() ?? "";
  return !NOT_SCHEMA_DIR.test(path) && !NOT_SCHEMA_NAME.test(name.replace(/\.sql$/i, ""));
}

/** True for files the probe must load without an error (the Supabase CLI would refuse them too). */
export const isStrict = (path: string): boolean => SUPABASE_MIGRATIONS.test(path);

/**
 * The probe's input. `schemaSql` is every non-archived .sql file of the repo. Returns them in load order;
 * an empty list means there is nothing to load. `withBase` also loads base files (a schema.sql) before
 * supabase/migrations: the retry for repos whose migrations only add to a schema kept in one file.
 */
export function probeSources(schemaSql: SqlFile[], withBase = false): SqlFile[] {
  const byPath = (a: SqlFile, b: SqlFile): number => a.path.localeCompare(b.path);
  const supabase = schemaSql.filter((f) => SUPABASE_MIGRATIONS.test(f.path)).sort(byPath);
  const orm = schemaSql.filter((f) => ORM_MIGRATIONS.test(f.path) && isSchemaSql(f.path)).sort(byPath);
  const rest = schemaSql.filter(
    (f) => !ORM_MIGRATIONS.test(f.path) && !SUPABASE_MIGRATIONS.test(f.path) && isSchemaSql(f.path),
  );
  const base = rest.filter((f) => !inMigrationsFolder(f.path)).sort(byPath);
  if (supabase.length) return withBase ? [...orm, ...base, ...supabase] : [...orm, ...supabase];
  const folders = rest.filter((f) => inMigrationsFolder(f.path)).sort(byPath);
  return [...orm, ...base, ...folders];
}

/** Probe order for a list that may come unsorted (patched files, tests): ORM, base files, migrations folders. */
export function loadOrder(files: SqlFile[]): SqlFile[] {
  const rank = (path: string): number =>
    ORM_MIGRATIONS.test(path) ? 0 : SUPABASE_MIGRATIONS.test(path) ? 3 : inMigrationsFolder(path) ? 2 : 1;
  return [...files].sort((a, b) => rank(a.path) - rank(b.path) || a.path.localeCompare(b.path));
}
