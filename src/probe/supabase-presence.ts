import type { SqlFile } from "../patches/sql.ts";

type Read = (path: string) => Promise<string | undefined>;

/**
 * Whether the repo's database is a Supabase project, so its tables can be reached straight from the
 * browser through the Data API (PostgREST) as `anon` or a signed-in user. Only then do the RLS probe's
 * "a visitor without an account changed user A's rows" findings describe something real. A plain Postgres
 * app (Prisma or Drizzle migrations behind its own Express or Nest server) has no `anon` role on the wire:
 * who reads a table is decided by its API code, which the probe does not see.
 *
 * Returns the first piece of evidence found, or undefined when there is none.
 */
export async function supabaseEvidence(files: string[], read: Read, schemaSql: SqlFile[]): Promise<string | undefined> {
  const folder = files.find((f) => /(?:^|\/)supabase\/(?:migrations\/|functions\/|config\.toml$)/.test(f));
  if (folder) return folder;

  const sql = schemaSql.find((f) => SUPABASE_SQL.test(f.text));
  if (sql) return sql.path;

  for (const path of files.filter((f) => /(?:^|\/)package\.json$/.test(f))) {
    if (SUPABASE_PACKAGE.test((await read(path)) ?? "")) return path;
  }
  for (const path of files.filter((f) => CONFIG_FILE.test(f))) {
    if (SUPABASE_CONFIG.test((await read(path)) ?? "")) return path;
  }
  for (const path of files.filter((f) => SOURCE_FILE.test(f))) {
    if (SUPABASE_IMPORT.test((await read(path)) ?? "")) return path;
  }
  return undefined;
}

/** Roles, schemas and helpers only a Supabase database has. `enable row level security` alone is plain Postgres. */
const SUPABASE_SQL =
  /\bauth\.(?:uid|jwt|role|email)\s*\(|\bauth\.users\b|\b(?:to|from)\s+(?:[\w", ]+,\s*)?"?(?:anon|authenticated|service_role)\b|\bstorage\.(?:buckets|objects)\b/i;

/** A supabase-js / @supabase/* dependency (any workspace of a monorepo). */
const SUPABASE_PACKAGE = /"(?:@supabase\/[\w-]+|supabase)"\s*:/;

/** Env examples, ORM and compose files that name the Supabase host or its keys; Python dependency lists. */
const CONFIG_FILE =
  /(?:^|\/)(?:\.env[\w.-]*|[\w.-]*\.env|schema\.prisma|drizzle\.config\.\w+|docker-compose[\w.-]*\.ya?ml|requirements[\w.-]*\.txt|pyproject\.toml)$/i;
const SUPABASE_CONFIG = /\.supabase\.(?:co|com)\b|\bSUPABASE_[A-Z_]+\s*=|^\s*supabase\b/im;

const SOURCE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|py|dart|kt|swift)$/;
const SUPABASE_IMPORT =
  /(?:from\s+|import\s*\(\s*|require\s*\(\s*)["'](?:npm:|jsr:|https:\/\/esm\.sh\/)?@supabase\/|^\s*(?:from\s+supabase\s+import|import\s+supabase\b)|package:supabase_flutter\//m;
