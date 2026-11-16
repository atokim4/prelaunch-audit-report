#!/usr/bin/env node
import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { audit } from "./audit.ts";
import { keyKind, projectOrigin } from "./live/probe.ts";
import type { LiveOptions } from "./scanners/live-probe.ts";
import { renderHtml } from "./report/html.ts";
import { renderPdf } from "./report/pdf.ts";
import { SEVERITIES } from "./types.ts";

const HELP = `Usage: prelaunch-audit <repo> [options]

Runs vibe-preflight (repo checks for Supabase + Stripe), a credential scan of the files and git
history, a Row Level Security probe of the migrations in PGlite, npm audit and, with --url, a
passive scan of the live site. Writes a severity-rated report with a patch for each finding it
can fix.

Options:
  --out <dir>                 where to write the report (default: ./audit-out)
  --url <url>                 also audit the deployed site (needs the launch-audit CLI)
  --launch-audit-cli <path>   apify-launch-audit dist/cli.js (default: $LAUNCH_AUDIT_CLI)
  --launch-audit-json <file>  use a saved "launch-audit <url> --json" run instead of running it
  --format <list>             any of json,html,pdf (default: json,html,pdf)
  --note <text>               a line for the cover (scope, sample notice)
  --name <name>               app name on the report (default: package.json name)
  --date <ISO date>           report date (default: now), for reproducible output
  --skip-npm-audit            do not run npm audit (it needs network and a package-lock.json)
  --phi                       health-data mode: map PHI columns, rate any read of them by
                              others Critical, flag PHI sent to analytics, AI, email or SMS
                              vendors, PHI in logs and public buckets, add an audit-trail
                              patch and the Supabase HIPAA checklist
  -h, --help                  show this help

Live project (read-only, only with the owner's consent):
  --live <project url>        also count rows on the Supabase project, as a visitor and as two
                              test users the owner created (https://<ref>.supabase.co)
  --i-own-this-project        required with --live: you own the project or have written permission
  --live-env <file>           read the key and the test logins from this file (see .env.example)
  --live-rate <n>             requests per second, at most (default 5)
  --live-max-requests <n>     stop after this many requests (default 600)
  The key and logins come from the environment: LIVE_SUPABASE_KEY (anon or publishable key,
  never the secret or service_role key), LIVE_USER_A_EMAIL, LIVE_USER_A_PASSWORD,
  LIVE_USER_B_EMAIL, LIVE_USER_B_PASSWORD.

Output: <out>/findings.json, report.html, report.pdf and patches/PA-xx.diff.
PDF needs Google Chrome or Chromium (CHROME_PATH; CHROME_NO_SANDBOX=1 inside containers).
`;

function positive(name: string, value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`${name} must be a positive number: ${value}`);
  return n;
}

function liveOptions(values: {
  live?: string;
  "i-own-this-project": boolean;
  "live-env"?: string;
  "live-rate"?: string;
  "live-max-requests"?: string;
}): LiveOptions {
  if (!values["i-own-this-project"]) {
    throw new Error(
      `--live sends requests to ${values.live}. Run it only on a project you own or have written permission to test, and say so with --i-own-this-project`,
    );
  }
  if (values["live-env"]) process.loadEnvFile(values["live-env"]);
  const env = (name: string): string => {
    const value = process.env[name];
    if (!value) throw new Error(`--live needs ${name} in the environment (or in --live-env <file>)`);
    return value;
  };
  const project = projectOrigin(values.live ?? "");
  const key = env("LIVE_SUPABASE_KEY");
  keyKind(key); // refuses a secret or service_role key before anything is sent
  return {
    project,
    key,
    userA: { email: env("LIVE_USER_A_EMAIL"), password: env("LIVE_USER_A_PASSWORD") },
    userB: { email: env("LIVE_USER_B_EMAIL"), password: env("LIVE_USER_B_PASSWORD") },
    rate: positive("--live-rate", values["live-rate"]),
    maxRequests: positive("--live-max-requests", values["live-max-requests"]),
  };
}

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
      "skip-npm-audit": { type: "boolean", default: false },
      phi: { type: "boolean", default: false },
      live: { type: "string" },
      "i-own-this-project": { type: "boolean", default: false },
      "live-env": { type: "string" },
      "live-rate": { type: "string" },
      "live-max-requests": { type: "string" },
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

  const live = values.live ? liveOptions(values) : undefined;

  const result = await audit({
    repo,
    url: values.url,
    launchAuditCli: values["launch-audit-cli"],
    launchAuditJson: values["launch-audit-json"],
    name: values.name,
    now,
    npmAudit: !values["skip-npm-audit"],
    live,
    phi: values.phi,
  });

  const out = resolve(values.out);
  await mkdir(join(out, "patches"), { recursive: true });
  // Ids are renumbered on every run: a patch file left from an earlier run would sit under the wrong finding.
  for (const file of await readdir(join(out, "patches"))) {
    if (/^PA-\d+\.diff$/.test(file)) await rm(join(out, "patches", file));
  }
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
