import { readFile, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { isGitRepo, listFiles } from "./files.ts";
import { countBySeverity, normalize } from "./normalize.ts";
import { attachPatches, fixContext } from "./patches/index.ts";
import { runLaunchAudit } from "./scanners/launch-audit.ts";
import { runPreflight } from "./scanners/preflight.ts";
import { runSecretScan } from "./scanners/secrets.ts";
import type { AuditResult, RawFinding, ToolRun } from "./types.ts";

export interface AuditOptions {
  repo: string;
  url?: string;
  launchAuditCli?: string;
  launchAuditJson?: string;
  /** Report name; defaults to package.json "name", then the folder name. */
  name?: string;
  /** Fixed clock, for reproducible reports and tests. */
  now?: Date;
}

/** What no scanner here looks at. Printed on the cover so nobody reads the report as a full pentest. */
const ALWAYS_NOT_CHECKED = [
  "Business logic and authorization inside your own API routes and server actions (beyond the Stripe webhook).",
  "The live database: policies or grants changed in the Supabase dashboard and not saved as migrations are invisible to a repo scan.",
  "Dependencies with known CVEs (run `npm audit` or Dependabot for that).",
  "Rate limiting, abuse and brute-force protection, email/auth settings in the Supabase dashboard.",
  "Manual penetration testing: every finding here comes from automated scanners and was not exploited against a running app.",
];

async function appName(repo: string): Promise<string> {
  try {
    const pkg = JSON.parse(await readFile(join(repo, "package.json"), "utf8")) as { name?: unknown };
    if (typeof pkg.name === "string" && pkg.name) return pkg.name;
  } catch {
    // no package.json: fall back to the folder name
  }
  return basename(repo);
}

export async function audit(options: AuditOptions): Promise<AuditResult> {
  const repo = resolve(options.repo);
  const info = await stat(repo).catch(() => undefined);
  if (!info?.isDirectory()) throw new Error(`not a folder: ${options.repo}`);
  const now = options.now ?? new Date();

  const tools: ToolRun[] = [];
  const raws: RawFinding[] = [];
  const notChecked = [...ALWAYS_NOT_CHECKED];

  const [preflight, secrets] = await Promise.all([runPreflight(repo), runSecretScan(repo)]);
  for (const result of [preflight, secrets]) {
    raws.push(...result.findings);
    tools.push(result.tool);
  }
  if (secrets.tool.note) notChecked.unshift(secrets.tool.note);

  if (options.url) {
    const live = await runLaunchAudit({
      url: options.url,
      cliPath: options.launchAuditCli,
      jsonPath: options.launchAuditJson,
    });
    raws.push(...live.findings);
    tools.push(live.tool);
  } else {
    notChecked.unshift(
      "The deployed site: no URL was given, so HTTPS, security headers, cookies and the built JavaScript bundles were not checked.",
    );
  }

  const { findings } = await normalize(repo, raws);
  const git = await isGitRepo(repo);
  await attachPatches(findings, await fixContext(repo, await listFiles(repo, git), now), repo);

  return {
    schema: "prelaunch-audit/v1",
    app: { name: options.name ?? (await appName(repo)), repo: basename(repo), url: options.url },
    generatedAt: now.toISOString(),
    counts: countBySeverity(findings),
    findings,
    tools,
    notChecked,
  };
}
