import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { effortRange, renderHtml } from "../src/report/html.ts";
import { chromePath, renderPdf } from "../src/report/pdf.ts";
import type { AuditResult, Finding } from "../src/types.ts";

const result = await audit({ repo: "test/fixtures/broken-notes-app", now: new Date("2026-11-09T09:00:00Z") });

const hasChrome = (() => {
  try {
    return existsSync(chromePath());
  } catch {
    return false;
  }
})();

describe("HTML report", () => {
  it("has the cover note, every finding and its patch", async () => {
    const html = await renderHtml(result, { note: "Sample run on a demo app." });
    expect(html).toContain("Sample run on a demo app.");
    for (const f of result.findings) expect(html).toContain(`id="${f.id}"`);
    expect(html.match(/class="patch"/g)).toHaveLength(result.findings.filter((f) => f.patch).length);
    expect(html).toContain("What was not checked");
  });

  it("escapes scanner text", async () => {
    const hostile: AuditResult = {
      ...result,
      app: { ...result.app, name: "<script>alert(1)</script>" },
      findings: result.findings.slice(0, 1).map((f) => ({ ...f, evidence: 'policy "<img src=x onerror=alert(1)>"' })),
    };
    const html = await renderHtml(hostile);
    expect(html).not.toContain("<script>alert(1)");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("adds up effort bands", () => {
    const f = (effort: Finding["effort"]) => ({ effort }) as Finding;
    expect(effortRange([f("under 1 hour"), f("1-4 hours"), f("half a day to a day")])).toEqual([5.5, 13]);
  });
});

describe.skipIf(!hasChrome)("PDF report", () => {
  it("prints an A4 PDF", async () => {
    const pdf = await renderPdf(await renderHtml(result), "test");
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.toString("latin1")).toMatch(/\/MediaBox \[0 0 59[45]\.\d+ 84[12]\.\d+\]/);
  });
});

describe("audit with a live URL", () => {
  it("merges a saved launch-audit run and drops the 'no URL' caveat", async () => {
    const live = await audit({
      repo: "test/fixtures/broken-notes-app",
      url: "https://example.com",
      launchAuditJson: "test/fixtures/launch-audit/example.com.json",
      now: new Date("2026-11-09T09:00:00Z"),
    });
    const urlFindings = live.findings.filter((f) => f.location.kind === "url");
    expect(urlFindings.length).toBeGreaterThan(0);
    expect(live.notChecked.join(" ")).not.toMatch(/no URL was given/);
    expect(live.tools.map((t) => t.name)).toContain("apify-launch-audit");
    const html = await renderHtml(live);
    expect(html).toContain("The live site: HTTPS, security headers");
  });

  it("explains how to get the live scanner when it is missing", async () => {
    await expect(audit({ repo: "test/fixtures/broken-notes-app", url: "https://example.com" })).rejects.toThrow(
      /--launch-audit-cli/,
    );
  });
});
