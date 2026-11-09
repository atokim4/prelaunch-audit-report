import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../exec.ts";
import type { RawFinding, ToolRun } from "../types.ts";

export const PREFLIGHT_VERSION = "1.3.0";
export const PREFLIGHT_SHA256 = "64adfc4ec55731cd8b909cc473d0a0a6716fab16618bb78d30c70b217ea6d35c";
export const PREFLIGHT_PATH = fileURLToPath(new URL("../../vendor/vibe-preflight/preflight.mjs", import.meta.url));

interface PreflightJson {
  tool: string;
  version: string;
  findings: { rule: string; severity: string; message: string; file: string; line: number }[];
}

function isPreflightJson(value: unknown): value is PreflightJson {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Partial<PreflightJson>;
  return (
    v.tool === "vibe-preflight" &&
    Array.isArray(v.findings) &&
    v.findings.every(
      (f) =>
        typeof f.rule === "string" &&
        typeof f.severity === "string" &&
        typeof f.message === "string" &&
        typeof f.file === "string" &&
        typeof f.line === "number",
    )
  );
}

/** Names the scanner puts in backticks: `public.audit_log`, `public.admin_set_plan()`, `NEXT_PUBLIC_X`. */
export function subjectOf(message: string): string | undefined {
  const quoted = message.match(/`([^`]+)`/)?.[1];
  return quoted?.replace(/\(\)$/, "");
}

export async function verifyBundle(path = PREFLIGHT_PATH): Promise<void> {
  const hash = createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
  if (hash !== PREFLIGHT_SHA256) {
    throw new Error(`vendored vibe-preflight bundle changed (sha256 ${hash}); refusing to run it`);
  }
}

export function parsePreflight(stdout: string): RawFinding[] {
  const parsed: unknown = JSON.parse(stdout);
  if (!isPreflightJson(parsed)) throw new Error("vibe-preflight printed JSON in an unexpected shape");
  return parsed.findings.map((f) => ({
    source: "vibe-preflight",
    rule: f.rule,
    toolSeverity: f.severity,
    message: f.message,
    location: { kind: "file", file: f.file, line: f.line },
    subject: subjectOf(f.message),
  }));
}

export async function runPreflight(repo: string): Promise<{ findings: RawFinding[]; tool: ToolRun }> {
  const command = `node vendor/vibe-preflight/preflight.mjs ${basename(repo)} --format json --fail-on never`;
  const tool: ToolRun = { name: "vibe-preflight", version: PREFLIGHT_VERSION, command, status: "ok" };
  await verifyBundle();
  const result = await run(process.execPath, [PREFLIGHT_PATH, repo, "--format", "json", "--fail-on", "never"]);
  if (result.code !== 0) {
    throw new Error(`vibe-preflight exited with ${result.code}: ${result.stderr.trim().slice(0, 500)}`);
  }
  return { findings: parsePreflight(result.stdout), tool };
}
