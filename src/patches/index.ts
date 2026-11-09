import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { SEVERITY_RANK, type Finding } from "../types.ts";
import { applies, unifiedDiff } from "./diff.ts";
import { FIXERS, type FixContext } from "./fixers.ts";

const MIGRATIONS_DIR = "supabase/migrations";

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
 */
export async function attachPatches(findings: Finding[], ctx: FixContext, repo: string): Promise<void> {
  for (const finding of findings) {
    if (SEVERITY_RANK[finding.severity] < SEVERITY_RANK.medium) continue;
    const fixer = FIXERS[finding.rule];
    if (!fixer) continue;
    const draft = await fixer(finding, ctx);
    if (!draft) continue;
    const diff = await unifiedDiff(draft.edits);
    finding.patch = {
      diff,
      summary: draft.summary,
      caveats: draft.caveats,
      verified: await applies(repo, draft.edits, diff),
    };
  }
}
