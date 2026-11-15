import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { run } from "../exec.ts";
import type { RawFinding, ToolRun } from "../types.ts";

/** One advisory npm reports for a package (an entry of `via` that is an object, not a package name). */
interface Advisory {
  source: number;
  name: string;
  title: string;
  url: string;
  severity: string;
  cwe?: string[];
  range: string;
}

interface Vulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: (string | Advisory)[];
  range: string;
  nodes: string[];
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
}

interface AuditJson {
  auditReportVersion: number;
  vulnerabilities: Record<string, Vulnerability>;
  error?: { code?: string; summary?: string };
}

const isAdvisory = (via: string | Advisory): via is Advisory => typeof via === "object" && via !== null;

function isAuditJson(value: unknown): value is AuditJson {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Partial<AuditJson>;
  return v.auditReportVersion === 2 && typeof v.vulnerabilities === "object" && v.vulnerabilities !== null;
}

/** Line of `"name":` in package.json (direct dependencies) or of `"node_modules/name"` in the lockfile. */
function lineOf(text: string | undefined, needle: string): number {
  if (!text) return 1;
  const index = text.indexOf(needle);
  return index < 0 ? 1 : text.slice(0, index).split("\n").length;
}

function fixLine(v: Vulnerability): string {
  if (v.fixAvailable === true) return "`npm audit fix` updates it within the allowed version range.";
  if (v.fixAvailable && typeof v.fixAvailable === "object") {
    const { name, version, isSemVerMajor } = v.fixAvailable;
    return `Update ${name} to ${version}${isSemVerMajor ? " (a major version: read its changelog first)" : ""}.`;
  }
  return "No fixed version yet: check whether your code uses the affected feature, and watch the advisory.";
}

/**
 * One finding per package that carries an advisory itself. Packages that are listed only because they
 * depend on a vulnerable one are folded into it (npm lists the whole chain).
 */
export function parseNpmAudit(json: string, files: { pkg?: string; lock?: string }): RawFinding[] {
  const parsed: unknown = JSON.parse(json);
  const failure = (parsed as Partial<AuditJson> | null)?.error;
  if (failure) throw new Error(`npm audit failed: ${failure.summary ?? failure.code ?? "unknown error"}`);
  if (!isAuditJson(parsed)) throw new Error("npm audit printed JSON in an unexpected shape");
  const out: RawFinding[] = [];
  for (const v of Object.values(parsed.vulnerabilities)) {
    const advisories = v.via.filter(isAdvisory);
    if (!advisories.length) continue;
    const worst = advisories[0] as Advisory;
    const ids = advisories.map((a) => a.url.split("/").pop() ?? String(a.source));
    out.push({
      source: "npm-audit",
      rule: "dependency-advisory",
      toolSeverity: v.severity,
      title: `${v.name} ${v.range}: ${worst.title}`,
      message: `\`${v.name}\` ${v.range} has ${advisories.length === 1 ? "a published advisory" : `${advisories.length} published advisories`} (${ids.join(", ")}). npm rates it ${v.severity}.`,
      fix: fixLine(v),
      location: v.isDirect
        ? { kind: "file", file: "package.json", line: lineOf(files.pkg, `"${v.name}"`) }
        : { kind: "file", file: "package-lock.json", line: lineOf(files.lock, `"node_modules/${v.name}"`) },
      subject: v.name,
      cwe: worst.cwe?.[0],
    });
  }
  return out;
}

export async function runNpmAudit(repo: string): Promise<{ findings: RawFinding[]; tool: ToolRun; note?: string }> {
  const command = "npm audit --json --package-lock-only --omit=dev";
  const npm = await run("npm", ["--version"]).catch(() => undefined);
  const tool: ToolRun = { name: "npm audit", version: npm?.stdout.trim() || "unknown", command, status: "ok" };
  const lock = await readFile(join(repo, "package-lock.json"), "utf8").catch(() => undefined);
  if (!lock) {
    return {
      findings: [],
      tool: { ...tool, status: "skipped", note: "No package-lock.json, so npm audit cannot resolve versions." },
      note: "Dependencies with known CVEs: the repo has no package-lock.json, so npm audit did not run.",
    };
  }
  const pkg = await readFile(join(repo, "package.json"), "utf8").catch(() => undefined);
  const result = await run("npm", ["audit", "--json", "--package-lock-only", "--omit=dev"], {
    cwd: repo,
    timeoutMs: 90_000,
  }).catch((error: unknown) => ({ code: -1, stdout: "", stderr: String(error) }));
  try {
    const findings = parseNpmAudit(result.stdout, { pkg, lock });
    return {
      findings,
      tool: { ...tool, note: `${findings.length} packages with advisories (runtime dependencies only).` },
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      findings: [],
      tool: { ...tool, status: "failed", note: reason },
      note: `Dependencies with known CVEs: npm audit did not finish (${reason}). Run it yourself with network access.`,
    };
  }
}
