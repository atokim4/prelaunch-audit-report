import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { normalize } from "../src/normalize.ts";
import { parseNpmAudit, runNpmAudit } from "../src/scanners/npm-audit.ts";

// Real `npm audit --json` output (this project's own dev tree, 2026-11-15), cut to three packages.
const json = await readFile("test/fixtures/npm-audit/dev-tree.json", "utf8");
const lock = '{\n  "packages": {\n    "node_modules/eslint": {},\n    "node_modules/minimatch": {}\n  }\n}\n';

describe("npm audit adapter", () => {
  it("keeps the package with the advisory and folds the packages that only depend on it", () => {
    const raws = parseNpmAudit(json, { lock });
    expect(raws.map((r) => [r.subject, r.toolSeverity, r.location, r.cwe])).toEqual([
      ["minimatch", "moderate", { kind: "file", file: "package-lock.json", line: 4 }, "CWE-405"],
    ]);
    expect(raws[0]?.message).toContain("GHSA-g3hv-75wg-m249");
    expect(raws[0]?.fix).toBe("Update typescript-eslint to 8.36.0 (a major version: read its changelog first).");
  });

  it("rates an advisory one level below npm, with its CWE", async () => {
    const { findings } = await normalize(".", parseNpmAudit(json, { lock }));
    expect(findings.map((f) => [f.severity, f.cwe?.id, f.effort])).toEqual([["low", 405, "1-4 hours"]]);
  });

  it("passes on npm's own error and refuses other JSON", () => {
    expect(() => parseNpmAudit('{"error":{"code":"ENOLOCK"}}', {})).toThrow("npm audit failed: ENOLOCK");
    expect(() => parseNpmAudit('{"vulnerabilities":{}}', {})).toThrow(/unexpected shape/);
  });

  it("skips a repo without a lockfile and says so", async () => {
    const result = await runNpmAudit("test/fixtures/broken-notes-app");
    expect(result.tool.status).toBe("skipped");
    expect(result.note).toMatch(/no package-lock\.json/);
  });
});
