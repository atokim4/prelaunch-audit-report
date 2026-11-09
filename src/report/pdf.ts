import { existsSync } from "node:fs";
import { chromium } from "playwright-core";

const CANDIDATES = [
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
];

export function chromePath(): string {
  const found = [process.env.CHROME_PATH, ...CANDIDATES].find((p): p is string => Boolean(p && existsSync(p)));
  if (!found) throw new Error("PDF output needs Google Chrome or Chromium: set CHROME_PATH");
  return found;
}

const escapeHtml = (value: string): string =>
  value.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch] ?? ch);

/** Prints the report HTML to an A4 PDF with a running footer. */
export async function renderPdf(html: string, footerLabel: string): Promise<Buffer> {
  // Containers often run Chrome without a usable sandbox; opt in with CHROME_NO_SANDBOX=1 (or as root).
  const noSandbox = process.env.CHROME_NO_SANDBOX === "1" || process.getuid?.() === 0;
  const browser = await chromium.launch({ executablePath: chromePath(), args: noSandbox ? ["--no-sandbox"] : [] });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "load" });
    await page.evaluate("document.fonts.ready.then(() => true)");
    return await page.pdf({
      format: "A4",
      printBackground: true,
      preferCSSPageSize: true,
      displayHeaderFooter: true,
      headerTemplate: "<span></span>",
      footerTemplate: `<div style="width:100%;padding:0 17mm;font:8px 'IBM Plex Sans',sans-serif;color:#4d5463;display:flex;justify-content:space-between"><span>${escapeHtml(footerLabel)}</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`,
    });
  } finally {
    await browser.close();
  }
}
