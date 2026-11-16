import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { SEVERITY_RANK, type Finding } from "../types.ts";
import { applies, unifiedDiff, type FileEdit } from "./diff.ts";
import { FIXERS, probeLeak, type FixContext } from "./fixers.ts";
import { probeSources } from "../probe/sources.ts";
import type { SqlFile } from "./sql.ts";

const MIGRATIONS_DIR = "supabase/migrations";

/** Folders of SQL that no longer runs: old schema copies kept for reference. */
export const ARCHIVED_SQL = /(?:^|\/)(?:archives?|archived|deprecated|old|backups?|legacy|unused)\//i;

function stamp(date: Date): string {
  return date.toISOString().replace(/[-:T]/g, "").slice(0, 14);
}

/** Context for the fixers: cached reads, the migration files, and new migration names after the newest one. */
export async function fixContext(repo: string, files: string[], now: Date): Promise<FixContext> {
  const cache = new Map<string, string | undefined>();
  const read = async (path: string): Promise<string | undefined> => {
    if (!cache.has(path)) cache.set(path, await readFile(join(repo, path), "utf8").catch(() => undefined));
    return cache.get(path);
  };
  const migrationFiles = files.filter((f) => f.startsWith(`${MIGRATIONS_DIR}/`) && f.endsWith(".sql"));
  const migrations = [];
  for (const path of migrationFiles) migrations.push({ path, text: (await read(path)) ?? "" });
  const schemaSql = [];
  for (const path of files.filter((f) => f.endsWith(".sql") && !ARCHIVED_SQL.test(f))) {
    schemaSql.push({ path, text: (await read(path)) ?? "" });
  }

  const newest = migrationFiles
    .map((f) => f.slice(MIGRATIONS_DIR.length + 1).match(/^(\d{14})_/)?.[1])
    .filter((v): v is string => Boolean(v))
    .sort()
    .pop();
  let next = Math.max(
    now.getTime(),
    newest ? Date.parse(newest.replace(/^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/, "$1-$2-$3T$4:$5:$6Z")) + 1000 : 0,
  );
  return {
    read,
    files,
    migrations,
    schemaSql,
    probeSql: probeSources(schemaSql),
    newMigration(slug) {
      const name = `${MIGRATIONS_DIR}/${stamp(new Date(next))}_${slug}.sql`;
      next += 1000;
      return name;
    },
  };
}

/**
 * Adds a patch to every finding a fixer knows how to fix (always tried for Critical and High, also for
 * Medium when a fixer exists). Each diff is checked with `git apply --check` against the files as they are.
 * Returns the edits of the verified patches, for the RLS re-probe.
 */
export async function attachPatches(findings: Finding[], ctx: FixContext, repo: string): Promise<FileEdit[]> {
  const verified: FileEdit[] = [];
  for (const finding of findings) {
    if (SEVERITY_RANK[finding.severity] < SEVERITY_RANK.medium) continue;
    const fixer = FIXERS[finding.rule];
    let draft = fixer ? await fixer(finding, ctx) : undefined;
    // A static rule's fixer may not know the table's shape (a child table has no owner column); the
    // probe's proof can still say which policies leaked and who owns the rows.
    if (!draft && finding.proof?.leaks.length) draft = await probeLeak(finding, ctx);
    if (!draft) continue;
    const diff = await unifiedDiff(draft.edits);
    const ok = await applies(repo, draft.edits, diff);
    finding.patch = { diff, summary: draft.summary, caveats: draft.caveats, verified: ok, partial: draft.partial };
    if (ok) verified.push(...draft.edits);
  }
  return verified;
}

/** The migration set after the patches: edited files replaced, new files added. */
export function patchedMigrations(migrations: SqlFile[], edits: FileEdit[]): SqlFile[] {
  const byPath = new Map(migrations.map((m) => [m.path, m.text]));
  for (const edit of edits) {
    if (edit.path.startsWith(`${MIGRATIONS_DIR}/`) && edit.path.endsWith(".sql")) byPath.set(edit.path, edit.after);
  }
  return [...byPath].map(([path, text]) => ({ path, text }));
}
