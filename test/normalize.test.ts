import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { normalize } from "../src/normalize.ts";
import { parseLaunchAudit } from "../src/scanners/launch-audit.ts";
import { parsePreflight } from "../src/scanners/preflight.ts";
import type { RawFinding } from "../src/types.ts";

const raw = (rule: string, toolSeverity: string, file: string, line: number, subject?: string): RawFinding => ({
  source: "vibe-preflight",
  rule,
  toolSeverity,
  message: `message for ${rule}`,
  location: { kind: "file", file, line },
  subject,
});

describe("normalize", () => {
  it("folds two rules on the same object into one finding, keeping the more specific rule", async () => {
    const { findings } = await normalize("/nonexistent", [
      raw("view-bypasses-rls", "error", "m.sql", 2, "public.user_directory"),
      raw("auth-users-exposed", "error", "m.sql", 2, "public.user_directory"),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "PA-01",
      rule: "auth-users-exposed",
      severity: "critical",
      alsoFlaggedBy: ["view-bypasses-rls"],
    });
  });

  it("applies the rubric by tool level and sorts by severity", async () => {
    const { findings } = await normalize("/nonexistent", [
      raw("rls-no-policy", "warning", "a.sql", 1, "public.flags"),
      raw("rls-permissive-policy", "warning", "b.sql", 1, "public.messages"),
      raw("rls-permissive-policy", "error", "c.sql", 1, "public.posts"),
    ]);
    expect(findings.map((f) => [f.id, f.severity, f.location.kind === "file" && f.location.file])).toEqual([
      ["PA-01", "critical", "c.sql"],
      ["PA-02", "high", "b.sql"],
      ["PA-03", "low", "a.sql"],
    ]);
    expect(findings[0]?.cwe?.id).toBe(863);
  });

  it("drops unknown rules instead of guessing a severity", async () => {
    const { findings, dropped } = await normalize("/nonexistent", [raw("brand-new-rule", "error", "x.ts", 1)]);
    expect(findings).toEqual([]);
    expect(dropped).toBe(1);
  });
});

describe("scanner parsers", () => {
  it("reads vibe-preflight JSON and takes the backticked name as the subject", () => {
    const parsed = parsePreflight(
      JSON.stringify({
        tool: "vibe-preflight",
        version: "1.3.0",
        findings: [
          { rule: "rls-disabled", severity: "error", message: "`public.t` has RLS off.", file: "m.sql", line: 3 },
        ],
      }),
    );
    expect(parsed[0]).toMatchObject({ subject: "public.t", location: { file: "m.sql", line: 3 } });
  });

  it("rejects output in another shape", () => {
    expect(() => parsePreflight('{"findings": 1}')).toThrow(/unexpected shape/);
  });

  it("maps a saved launch-audit run and leaves out info lines", async () => {
    const raws = parseLaunchAudit(await readFile("test/fixtures/launch-audit/example.com.json", "utf8"));
    const { findings } = await normalize("/nonexistent", raws);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.location.kind === "url")).toBe(true);
    const hsts = findings.find((f) => f.rule === "transport.hsts-missing");
    expect(hsts).toMatchObject({ severity: "medium", cwe: { id: 319 } });
  });
});
