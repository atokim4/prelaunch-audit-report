/**
 * Builds examples/sample-report-vite-supabase: the full audit of the pipeline-crm demo, including the
 * live probe against a local stand-in for its Supabase project (test/live/stand-in.ts: real PostgREST
 * on PGlite, with "dashboard" changes and sample rows from test/fixtures/pipeline-crm-live).
 * Needs PostgREST: run scripts/fetch-postgrest.sh first.
 */
import { spawn } from "node:child_process";
import { hasPostgrest, startStandIn } from "../test/live/stand-in.ts";

const ROOT = new URL("..", import.meta.url).pathname;
const LIVE = `${ROOT}test/fixtures/pipeline-crm-live/`;

const NOTE =
  "Sample report. pipeline-crm is a small Vite + React + Supabase Edge Functions demo, shaped like the apps AI builders generate, written with security holes on purpose for this repo's tests (test/fixtures/pipeline-crm-app). " +
  "The live project is a local stand-in on port 54321: real PostgREST over PGlite with the demo's migrations, a few changes made as if in the dashboard and made-up rows. " +
  "Every finding below is real tool output on that code and that stand-in. It is not a client project.";

if (!hasPostgrest()) {
  process.stderr.write("PostgREST is missing: run scripts/fetch-postgrest.sh first.\n");
  process.exit(1);
}

const site = await startStandIn({
  app: `${ROOT}test/fixtures/pipeline-crm-app`,
  extraSql: [`${LIVE}dashboard-drift.sql`, `${LIVE}seed.sql`],
  port: 54321,
});
try {
  const child = spawn(
    process.execPath,
    [
      "src/cli.ts",
      "test/fixtures/pipeline-crm-app",
      "--out",
      "examples/sample-report-vite-supabase",
      "--date",
      "2026-11-16T09:00:00Z",
      "--live",
      site.url,
      "--i-own-this-project",
      "--note",
      NOTE,
      ...process.argv.slice(2),
    ],
    {
      cwd: ROOT,
      stdio: "inherit",
      env: {
        ...process.env,
        LIVE_SUPABASE_KEY: site.publishableKey,
        LIVE_USER_A_EMAIL: site.users.a.email,
        LIVE_USER_A_PASSWORD: site.users.a.password,
        LIVE_USER_B_EMAIL: site.users.b.email,
        LIVE_USER_B_PASSWORD: site.users.b.password,
      },
    },
  );
  const code = await new Promise<number | null>((resolve) => child.on("exit", resolve));
  process.exitCode = code ?? 1;
} finally {
  await site.stop();
}
