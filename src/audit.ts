import { readFile, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { isGitRepo, listFiles } from "./files.ts";
import { countBySeverity, normalize } from "./normalize.ts";
import { leaks, probeRls, type ProbeResult } from "./probe/rls-probe.ts";
import { ARCHIVED_SQL, attachPatches, fixContext, patchedMigrations } from "./patches/index.ts";
import { runLaunchAudit } from "./scanners/launch-audit.ts";
import { mergeLive, runLiveProbe, type LiveOptions } from "./scanners/live-probe.ts";
import { runNpmAudit } from "./scanners/npm-audit.ts";
import { markPhi, runPhiScan } from "./scanners/phi.ts";
import { filterPreflight, runPreflight } from "./scanners/preflight.ts";
import { addStaticContext, dynamicRlsTables } from "./scanners/static-context.ts";
import { probeSources } from "./probe/sources.ts";
import { markAdminGates } from "./scanners/admin-gate.ts";
import { mergeProbe, runRlsProbe, toProof } from "./scanners/rls-probe.ts";
import { runSecretScan } from "./scanners/secrets.ts";
import { detectShape, edgeConfigFindings } from "./shape.ts";
import type { AuditResult, LiveResult, PhiResult, Proof, RawFinding, ToolRun } from "./types.ts";

export interface AuditOptions {
  repo: string;
  url?: string;
  launchAuditCli?: string;
  launchAuditJson?: string;
  /** Report name; defaults to package.json "name", then the folder name. */
  name?: string;
  /** Fixed clock, for reproducible reports and tests. */
  now?: Date;
  /** Run `npm audit` (needs network). Default true. */
  npmAudit?: boolean;
  /** Read-only probe of the client's own Supabase project. The CLI asks for explicit consent first. */
  live?: LiveOptions;
  /** Health-data mode: PHI map, PHI leaving for vendors, logs and buckets, audit trail, HIPAA checklist. */
  phi?: boolean;
}

const PHI_NOT_CHECKED = [
  "HIPAA compliance as a whole: this report finds technical gaps in the code. Compliance also needs a risk analysis, policies, staff training and signed agreements, and only a qualified person can sign it off. Nothing here is legal advice.",
  "Health data under column names the map does not know: PHI is found by names such as diagnosis, date_of_birth or mrn. Check the PHI map against your schema.",
  "Who reads health records: Postgres triggers log changes, not reads. Read logging needs pgaudit or server-side code.",
];

const LIVE_NOT_CHECKED =
  "The live database: policies or grants changed in the Supabase dashboard and not saved as migrations are invisible to a repo scan. The RLS probe runs your migrations in a local Postgres, not against your project.";
const LIVE_LIMITS =
  "On the live project, only reads were tried: inserts, updates, deletes and RPC calls were not, so a write hole that exists only in the dashboard is not in this report. Tables the repo does not name were not probed.";

/** What no scanner here looks at. Printed on the cover so nobody reads the report as a full pentest. */
const ALWAYS_NOT_CHECKED = [
  "Business logic and authorization inside your own API routes, server actions and edge functions (beyond the Stripe webhook).",
  "Rate limiting, abuse and brute-force protection, email/auth settings in the Supabase dashboard.",
];
const NO_PENTEST =
  "Manual penetration testing: every finding here comes from automated scanners and a local probe, and nothing was tried against your running app.";
const NO_PENTEST_LIVE =
  "Manual penetration testing: every finding here comes from automated scanners, a local probe and read-only counts on your project. Nobody tried to break in by hand.";

async function appName(repo: string): Promise<string> {
  try {
    const pkg = JSON.parse(await readFile(join(repo, "package.json"), "utf8")) as { name?: unknown };
    if (typeof pkg.name === "string" && pkg.name) return pkg.name;
  } catch {
    // no package.json: fall back to the folder name
  }
  return basename(repo);
}

export async function audit(options: AuditOptions): Promise<AuditResult> {
  const repo = resolve(options.repo);
  const info = await stat(repo).catch(() => undefined);
  if (!info?.isDirectory()) throw new Error(`not a folder: ${options.repo}`);
  const now = options.now ?? new Date();

  const tools: ToolRun[] = [];
  const raws: RawFinding[] = [];
  const notChecked = [...ALWAYS_NOT_CHECKED];

  const git = await isGitRepo(repo);
  const ctx = await fixContext(repo, await listFiles(repo, git), now);
  const shape = await detectShape(ctx.files, ctx.read);

  const [preflight, secrets, first, deps] = await Promise.all([
    runPreflight(repo),
    runSecretScan(repo),
    runRlsProbe(ctx.probeSql),
    options.npmAudit === false ? undefined : runNpmAudit(repo),
  ]);
  // supabase/migrations that build on a schema.sql (the first migration was never saved) fail alone: try
  // again with the base file loaded first, every statement stepped over on error.
  let probe = first;
  let tolerant = false;
  const wider = probeSources(ctx.schemaSql, true);
  if (first.tool.status === "failed" && wider.length > ctx.probeSql.length) {
    const retry = await runRlsProbe(wider, true);
    if (retry.tool.status === "ok") {
      const added = wider.filter((f) => !ctx.probeSql.some((m) => m.path === f.path)).map((f) => f.path);
      probe = retry;
      tolerant = true;
      ctx.probeSql = wider;
      probe.tool.note =
        `${probe.tool.note ?? ""} supabase/migrations alone did not load (${first.tool.note ?? ""}), so the probe ran again with ${added.join(", ")} loaded first.`.trim();
    }
  }
  // Still failing: the migrations themselves do not run in order on an empty database (a table used before
  // the file that creates it). Load what loads, statement by statement; the tables a rejected statement
  // names are left out of the probe and listed.
  if (probe.tool.status === "failed") {
    const retry = await runRlsProbe(ctx.probeSql, true);
    if (retry.tool.status === "ok") {
      probe = retry;
      tolerant = true;
      probe.tool.note =
        `${probe.tool.note ?? ""} The migrations did not load in order (${first.tool.note ?? ""}), so the probe loaded them statement by statement.`.trim();
    }
  }
  const kept = await filterPreflight(preflight.findings, ctx.read, ARCHIVED_SQL);
  preflight.findings = kept.findings;
  if (kept.archived.length) {
    notChecked.push(
      `SQL in archive folders (${kept.archived.join(", ")}): treated as old copies that no longer run. If any of them still runs, it needs a review.`,
    );
  }
  const dynamicRls = dynamicRlsTables(ctx.schemaSql);
  const covered = preflight.findings.filter(
    (f) => f.rule === "rls-disabled" && dynamicRls.has((f.subject ?? "").toLowerCase()),
  );
  if (covered.length) {
    preflight.findings = preflight.findings.filter((f) => !covered.includes(f));
    notChecked.push(
      `Row Level Security turned on by a loop of dynamic SQL (${covered.map((f) => `\`${f.subject ?? ""}\``).join(", ")}): not reported as off, and the policies that loop creates were not read.`,
    );
  }
  // The static rule reads grants line by line and misses `revoke … from public, anon` in some layouts; the
  // probe's database has the real privileges after every migration ran, so it settles the question.
  const revoked = new Set(
    (probe.result?.definerFunctions ?? []).filter((f) => !f.anon).map((f) => `public.${f.name}`.toLowerCase()),
  );
  const notCallable = preflight.findings.filter(
    (f) => f.rule === "definer-function-anon" && revoked.has((f.subject ?? "").toLowerCase()),
  );
  if (notCallable.length) {
    preflight.findings = preflight.findings.filter((f) => !notCallable.includes(f));
    probe.tool.note =
      `${probe.tool.note ?? ""} ${notCallable.length} SECURITY DEFINER function(s) the static rule called open to visitors are not executable by anon once the schema is loaded (${notCallable.map((f) => `\`${f.subject ?? ""}\``).join(", ")}); not reported.`.trim();
  }
  // The static rule reads "an update policy and a role column" as "users can promote themselves". When the
  // probe tried exactly that column as a plain user and Postgres refused (an admin-only policy, a trigger),
  // and nothing else leaked on the table, the claim is disproved.
  const probed = new Map((probe.result?.tables ?? []).filter((t) => !t.skipped).map((t) => [t.table, t]));
  const disproved = preflight.findings.filter((f) => {
    if (f.rule !== "rls-update-privileged-column") return false;
    const table = probed.get((f.subject ?? "").toLowerCase());
    const column = f.message.match(/including `(\w+)`/)?.[1];
    if (!table || !column || leaks(table).length) return false;
    const tries = table.checks.filter((c) => c.actor === "owner" && c.column);
    return tries.some((c) => c.column === column) && tries.every((c) => c.refused || (c.rows === 0 && !c.inconclusive));
  });
  if (disproved.length) {
    preflight.findings = preflight.findings.filter((f) => !disproved.includes(f));
    probe.tool.note =
      `${probe.tool.note ?? ""} ${disproved.length} update polic${disproved.length === 1 ? "y" : "ies"} the static rule read as "users can edit their own role or plan" did not let a plain signed-in user change those columns in the probe (${disproved.map((f) => `\`${f.subject ?? ""}\``).join(", ")}); not reported.`.trim();
  }
  for (const result of [preflight, secrets, ...(deps ? [deps] : [])]) {
    raws.push(...result.findings);
    tools.push(result.tool);
  }
  if (deps?.note) notChecked.push(deps.note);
  if (!deps) notChecked.push("Dependencies with known CVEs: npm audit was turned off for this run.");
  tools.push(probe.tool);
  raws.push(...(await edgeConfigFindings(shape, ctx.read)));
  if (probe.result) raws.push(...mergeProbe(raws, probe.result, ctx.probeSql));
  if (probe.note) notChecked.unshift(probe.note);

  let live: LiveResult | undefined;
  if (options.live) {
    const run = await runLiveProbe(options.live, ctx, probe.result);
    tools.push(run.tool);
    live = run.result;
    if (live) raws.push(...mergeLive(raws, live));
    notChecked.push(run.note ?? LIVE_LIMITS, live ? NO_PENTEST_LIVE : NO_PENTEST);
  } else {
    notChecked.push(LIVE_NOT_CHECKED, NO_PENTEST);
  }
  if (secrets.tool.note) notChecked.unshift(secrets.tool.note);

  let phi: PhiResult | undefined;
  if (options.phi) {
    const scan = await runPhiScan(
      ctx,
      (probe.result?.tables ?? []).filter((t) => !t.skipped),
    );
    tools.push(scan.tool);
    markPhi(raws, scan.result.tables);
    raws.push(...scan.findings);
    phi = scan.result;
    notChecked.push(...PHI_NOT_CHECKED);
  }

  addStaticContext(raws, ctx.schemaSql);
  markAdminGates(raws, ctx.schemaSql);

  if (options.url) {
    const live = await runLaunchAudit({
      url: options.url,
      cliPath: options.launchAuditCli,
      jsonPath: options.launchAuditJson,
    });
    raws.push(...live.findings);
    tools.push(live.tool);
  } else {
    notChecked.unshift(
      "The deployed site: no URL was given, so HTTPS, security headers, cookies and the built JavaScript bundles were not checked.",
    );
  }

  const { findings } = await normalize(repo, raws);
  const edits = await attachPatches(findings, ctx, repo);

  // Re-run the probe with every verified patch applied: a patch for a leak has to bring it to zero.
  let matrix: Proof[] | undefined;
  if (probe.result) {
    const after = await probeRls(patchedMigrations(ctx.probeSql, edits), tolerant).catch(
      (error: unknown): ProbeResult => ({
        tables: [],
        migrations: 0,
        skippedExtensions: [],
        failedStatements: [],
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    const afterByTable = new Map(after.tables.map((t) => [t.table, t]));
    matrix = probe.result.tables.filter((t) => !t.skipped).map(toProof);
    if (after.error) {
      probe.tool.note = `${probe.tool.note ?? ""} The re-run with the patches applied failed: ${after.error}`.trim();
    } else {
      for (const proof of [...matrix, ...findings.flatMap((f) => (f.proof ? [f.proof] : []))]) {
        const table = afterByTable.get(proof.table);
        proof.afterPatches = table && !table.skipped ? leaks(table) : [];
      }
    }
  }

  return {
    schema: "prelaunch-audit/v1",
    app: { name: options.name ?? (await appName(repo)), repo: basename(repo), url: options.url, shape },
    generatedAt: now.toISOString(),
    counts: countBySeverity(findings),
    findings,
    tools,
    probe: matrix,
    ...(live ? { live } : {}),
    ...(phi ? { phi } : {}),
    notChecked,
  };
}
