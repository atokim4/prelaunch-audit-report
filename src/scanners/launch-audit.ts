import { readFile } from "node:fs/promises";
import { run } from "../exec.ts";
import type { RawFinding, ToolRun } from "../types.ts";

interface LaunchAuditSite {
  url: string;
  finalUrl?: string;
  error?: string;
  findings: { id: string; severity: string; title: string; detail: string; fix: string; evidence?: string[] }[];
}

function isSiteList(value: unknown): value is LaunchAuditSite[] {
  return (
    Array.isArray(value) &&
    value.every(
      (site: Partial<LaunchAuditSite>) =>
        typeof site.url === "string" &&
        Array.isArray(site.findings) &&
        site.findings.every((f) => typeof f.id === "string" && typeof f.severity === "string"),
    )
  );
}

export function parseLaunchAudit(json: string): RawFinding[] {
  const parsed: unknown = JSON.parse(json);
  if (!isSiteList(parsed)) throw new Error("launch-audit JSON is not a list of audited sites");
  return parsed.flatMap((site) => {
    if (site.error) throw new Error(`launch-audit could not audit ${site.url}: ${site.error}`);
    return site.findings.map((f): RawFinding => ({
      source: "launch-audit",
      rule: f.id,
      toolSeverity: f.severity,
      title: f.title,
      message: f.detail,
      fix: f.fix,
      location: { kind: "url", url: site.finalUrl ?? site.url },
      subject: f.evidence?.join("\n"),
    }));
  });
}

export interface LaunchAuditOptions {
  url: string;
  /** Path to apify-launch-audit's dist/cli.js. */
  cliPath?: string;
  /** A saved `--json` run to use instead of running the tool. */
  jsonPath?: string;
}

export async function runLaunchAudit(opts: LaunchAuditOptions): Promise<{ findings: RawFinding[]; tool: ToolRun }> {
  if (opts.jsonPath) {
    return {
      findings: parseLaunchAudit(await readFile(opts.jsonPath, "utf8")),
      tool: {
        name: "apify-launch-audit",
        version: "saved run",
        command: `launch-audit ${opts.url} --json (read from a saved file)`,
        status: "ok",
      },
    };
  }
  if (!opts.cliPath) {
    throw new Error(
      "--url needs the launch-audit CLI: pass --launch-audit-cli <path to dist/cli.js> or set LAUNCH_AUDIT_CLI",
    );
  }
  const result = await run(process.execPath, [opts.cliPath, opts.url, "--json"], { timeoutMs: 180_000 });
  if (result.code !== 0)
    throw new Error(`launch-audit exited with ${result.code}: ${result.stderr.trim().slice(0, 500)}`);
  const version = await cliVersion(opts.cliPath);
  return {
    findings: parseLaunchAudit(result.stdout),
    tool: { name: "apify-launch-audit", version, command: `launch-audit ${opts.url} --json`, status: "ok" },
  };
}

async function cliVersion(cliPath: string): Promise<string> {
  try {
    const pkg = JSON.parse(await readFile(new URL("../package.json", `file://${cliPath}`), "utf8")) as {
      version?: string;
    };
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}
