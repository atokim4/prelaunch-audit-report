#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { audit } from "./audit.ts";
import { renderHtml } from "./report/html.ts";
import { renderPdf } from "./report/pdf.ts";
import { SEVERITIES } from "./types.ts";

const HELP = `Usage: prelaunch-audit <repo> [options]

Runs vibe-preflight (repo checks for Supabase + Stripe), a credential scan of the files and git
history and, with --url, a passive scan of the live site. Writes a severity-rated report with
a patch for each finding it can fix.

Options:
  --out <dir>                 where to write the report (default: ./audit-out)
  --url <url>                 also audit the deployed site (needs the launch-audit CLI)
  --launch-audit-cli <path>   apify-launch-audit dist/cli.js (default: $LAUNCH_AUDIT_CLI)
  --launch-audit-json <file>  use a saved "launch-audit <url> --json" run instead of running it
  --format <list>             any of json,html,pdf (default: json,html,pdf)
  --note <text>               a line for the cover (scope, sample notice)
  --name <name>               app name on the report (default: package.json name)
  --date <ISO date>           report date (default: now), for reproducible output
  -h, --help                  show this help

Output: <out>/findings.json, report.html, report.pdf and patches/PA-xx.diff.
PDF needs Google Chrome or Chromium (CHROME_PATH; CHROME_NO_SANDBOX=1 inside containers).
`;

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      out: { type: "string", default: "audit-out" },
      url: { type: "string" },
      "launch-audit-cli": { type: "string", default: process.env.LAUNCH_AUDIT_CLI },
      "launch-audit-json": { type: "string" },
      name: { type: "string" },
      format: { type: "string", default: "json,html,pdf" },
      note: { type: "string" },
      date: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  const repo = positionals[0];
  if (values.help || !repo) {
    process.stdout.write(HELP);
    process.exitCode = values.help ? 0 : 2;
    return;
  }
  const formats = new Set(values.format.split(",").map((f) => f.trim()));
  const unknown = [...formats].filter((f) => !["json", "html", "pdf"].includes(f));
  if (unknown.length) throw new Error(`unknown --format: ${unknown.join(", ")}`);
  const now = values.date ? new Date(values.date) : undefined;
  if (now && Number.isNaN(now.getTime())) throw new Error(`--date is not a date: ${values.date}`);

  const result = await audit({
    repo,
    url: values.url,
    launchAuditCli: values["launch-audit-cli"],
    launchAuditJson: values["launch-audit-json"],
    name: values.name,
    now,
  });

  const out = resolve(values.out);
  await mkdir(join(out, "patches"), { recursive: true });
  if (formats.has("json")) await writeFile(join(out, "findings.json"), `${JSON.stringify(result, null, 2)}\n`);
  if (formats.has("html") || formats.has("pdf")) {
    const html = await renderHtml(result, { note: values.note });
    if (formats.has("html")) await writeFile(join(out, "report.html"), html);
    if (formats.has("pdf")) {
      await writeFile(join(out, "report.pdf"), await renderPdf(html, `Pre-launch security audit · ${result.app.name}`));
    }
  }
  for (const finding of result.findings) {
    if (finding.patch) await writeFile(join(out, "patches", `${finding.id}.diff`), finding.patch.diff);
  }

  const counts = SEVERITIES.map((s) => `${result.counts[s]} ${s}`).join(", ");
  const patched = result.findings.filter((f) => f.patch?.verified).length;
  process.stdout.write(`${result.app.name}: ${counts}. ${patched} verified patches.\nWrote ${out}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`prelaunch-audit: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
