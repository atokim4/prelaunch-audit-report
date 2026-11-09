import { readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { run } from "./exec.ts";

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "out", ".vercel", ".turbo", "coverage"]);

export async function isGitRepo(repo: string): Promise<boolean> {
  const result = await run("git", ["-C", repo, "rev-parse", "--is-inside-work-tree"]).catch(() => undefined);
  return result?.code === 0 && result.stdout.trim() === "true";
}

/**
 * Files that would ship with the repo, relative to `repo` with forward slashes: tracked plus untracked
 * files git does not ignore, or every file when it is not a git repo. Dependency and build folders are skipped.
 */
export async function listFiles(repo: string, git: boolean): Promise<string[]> {
  let files: string[] = [];
  if (git) {
    const result = await run("git", ["-C", repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard"]);
    if (result.code !== 0) throw new Error(`git ls-files failed: ${result.stderr.trim()}`);
    files = [...new Set(result.stdout.split("\0").filter(Boolean))];
  } else {
    const walk = async (dir: string): Promise<void> => {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) await walk(path);
        else if (entry.isFile()) files.push(relative(repo, path).split(sep).join("/"));
      }
    };
    await walk(repo);
  }
  return files.filter((file) => !file.split("/").some((part) => SKIP_DIRS.has(part))).sort();
}
