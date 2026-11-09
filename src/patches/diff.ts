import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { run } from "../exec.ts";

/** One file a patch changes. `before` is undefined for a new file. */
export interface FileEdit {
  path: string;
  before?: string;
  after: string;
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "prelaunch-audit-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function put(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, text);
}

/** A git-style unified diff (a/ b/ prefixes, applies with `git apply` from the repo root). */
export async function unifiedDiff(edits: FileEdit[]): Promise<string> {
  return withTempDir(async (dir) => {
    const parts: string[] = [];
    for (const edit of edits) {
      await put(join(dir, "b", edit.path), edit.after);
      let from = "/dev/null";
      if (edit.before !== undefined) {
        await put(join(dir, "a", edit.path), edit.before);
        from = `a/${edit.path}`;
      }
      const result = await run("git", ["diff", "--no-index", "--no-prefix", "--no-color", from, `b/${edit.path}`], {
        cwd: dir,
      });
      if (result.code > 1) throw new Error(`git diff failed: ${result.stderr.trim()}`);
      parts.push(
        result.stdout
          .replace(/^index [0-9a-f]+\.\.[0-9a-f]+(?: \d+)?\n/m, "")
          .replace(/^diff --git b\/(\S+) b\//, "diff --git a/$1 b/"),
      );
    }
    return parts.join("");
  });
}

/**
 * `git apply --check` against a scratch copy of the files the diff touches, as they are in `repo` now.
 * A scratch copy keeps the check independent of where the repo's own git root is.
 */
export async function applies(repo: string, edits: FileEdit[], diff: string): Promise<boolean> {
  return withTempDir(async (dir) => {
    for (const edit of edits) {
      const current = await readFile(join(repo, edit.path), "utf8").catch(() => undefined);
      if (edit.before === undefined) {
        if (current !== undefined) return false; // the new file would clash with an existing one
        continue;
      }
      if (current === undefined) return false;
      await put(join(dir, edit.path), current);
    }
    await writeFile(join(dir, "fix.diff"), diff);
    const result = await run("git", ["apply", "--check", "fix.diff"], { cwd: dir });
    return result.code === 0;
  });
}
