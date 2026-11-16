import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { run } from "../src/exec.ts";
import { leaks, probeRls } from "../src/probe/rls-probe.ts";
import { runPreflight } from "../src/scanners/preflight.ts";
import { SEVERITY_RANK, type AuditResult, type Finding } from "../src/types.ts";

/**
 * pipeline-crm-app: a Lovable-shaped demo (Vite SPA, Supabase migrations, Deno edge functions) with
 * seeded holes and controls. See the holes file for what each one is.
 */
const APP = "test/fixtures/pipeline-crm-app";
interface Target {
  id: string;
  target: { object: string; file: string };
}
const truth = JSON.parse(await readFile("test/fixtures/pipeline-crm-app.holes.json", "utf8")) as {
  holes: Target[];
  controls: Target[];
};

let result: AuditResult;
let patched = "";

beforeAll(async () => {
  result = await audit({ repo: APP, now: new Date("2026-11-15T09:00:00Z"), npmAudit: false });
  patched = await mkdtemp(join(tmpdir(), "patched-crm-"));
  await cp(APP, patched, { recursive: true });
  for (const finding of result.findings) {
    if (!finding.patch) continue;
    const file = join(patched, `${finding.id}.diff`);
    await writeFile(file, finding.patch.diff);
    const applied = await run("git", ["apply", file], { cwd: patched });
    if (applied.code !== 0) throw new Error(`${finding.id} did not apply: ${applied.stderr}`);
    await rm(file);
  }
}, 120_000);

afterAll(async () => {
  if (patched) await rm(patched, { recursive: true, force: true });
});

/** A finding is about a target when it sits in the target's file and names the object (database targets). */
function about(f: Finding, t: Target): boolean {
  if (f.location.kind !== "file" || f.location.file !== t.target.file) return false;
  if (!t.target.object.startsWith("public.")) return true;
  return f.subject === t.target.object || f.evidence.includes(`\`${t.target.object}`);
}

describe("audit of the Lovable-shaped bench app", () => {
  it("recognises the project shape and the JWT setting of each edge function", () => {
    expect(result.app.shape).toMatchObject({ framework: "vite-react", migrations: 7 });
    expect(result.app.shape.edgeFunctions.map((f) => [f.name, f.verifyJwt])).toEqual([
      ["create-checkout", true],
      ["stripe-webhook", false],
    ]);
  });

  it("finds every seeded hole", () => {
    const missed = truth.holes.filter((h) => !result.findings.some((f) => about(f, h))).map((h) => h.id);
    expect(missed).toEqual([]);
  });

  it("finds the two holes no static rule sees only through the probe", () => {
    const probeOnly = result.findings.filter((f) => f.source === "rls-probe").map((f) => f.subject);
    expect(probeOnly).toEqual(["public.deals", "public.activities"]);
  });

  it("flags no control at Medium or above", () => {
    const flagged = truth.controls
      .filter((c) =>
        result.findings.some((f) => about(f, c) && SEVERITY_RANK[f.severity] >= SEVERITY_RANK.medium && !isHoleToo(f)),
      )
      .map((c) => c.id);
    expect(flagged).toEqual([]);
  });

  it("rates the public price list Low because the probe saw no owner and no write", () => {
    const plans = result.findings.find((f) => f.subject === "public.plans");
    expect(plans).toMatchObject({ severity: "low", rule: "rls-permissive-policy" });
    expect(plans?.proof?.ownerColumns).toEqual([]);
    expect(plans?.proof?.leaks).toEqual([]);
  });

  it("raises the open leads policy to Critical because visitors really read the rows", () => {
    const leads = result.findings.find((f) => f.subject === "public.leads" && f.rule === "rls-permissive-policy");
    expect(leads?.severity).toBe("critical");
    expect(leads?.proof?.leaks.map((c) => `${c.actor}:${c.action}:${c.rows}/${c.of}`)).toEqual([
      "anon:select:1/1",
      "other-user:select:1/1",
    ]);
  });

  it("rates the findings with the rubric", () => {
    expect(result.counts).toEqual({ critical: 5, high: 4, medium: 0, low: 1 });
  });

  it("has a verified patch for every Critical and High finding", () => {
    const serious = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high);
    expect(serious.filter((f) => !f.patch?.verified).map((f) => f.id)).toEqual([]);
  });

  it("closes every leak the probe found, in the same harness", () => {
    const before = (result.probe ?? []).filter((p) => p.leaks.length).map((p) => p.table);
    expect(before).toEqual([
      "public.activities",
      "public.deals",
      "public.invoices",
      "public.leads",
      "public.pipeline_summary",
      "public.profiles",
    ]);
    expect((result.probe ?? []).filter((p) => p.afterPatches?.length).map((p) => p.table)).toEqual([]);
  });

  it("keeps user A reading their own rows on every patched table (positive check)", () => {
    const probe = result.probe ?? [];
    expect(probe.filter((p) => p.lockedOut).map((p) => p.table)).toEqual([]);
    const owned = probe.filter((p) => p.verdict !== "shared");
    expect(owned.length).toBeGreaterThan(0);
    for (const p of owned) {
      const own = p.afterAccess?.find((a) => a.who === "owner" && a.action === "select");
      expect(own?.rows, p.table).toBeGreaterThan(0);
    }
    // invoices had RLS off: the patch turns it on and adds a read policy for the owner, writes go server-side
    expect(probe.find((p) => p.table === "public.invoices")?.writesLost?.map((a) => a.action)).toEqual(["update"]);
  });
});

/** The profiles file holds hole H03 and control C06; a finding about H03 is not a false positive on C06. */
function isHoleToo(f: Finding): boolean {
  return truth.holes.some((h) => about(f, h));
}

describe("the Lovable-shaped app after applying every patch with git apply", () => {
  it("passes vibe-preflight except for the browser code the partial patch says still has to move", async () => {
    const { findings } = await runPreflight(patched);
    expect(findings.map((f) => [f.rule, f.subject])).toEqual([
      // PA-01 is marked partial: the key left the bundle, the Stripe call still lives in browser code.
      ["server-secret-in-client", "STRIPE_SECRET_KEY"],
      // invoices now has RLS on and an owner read policy (no "rls-no-policy" left there).
      ["rls-permissive-policy", "public.plans"],
    ]);
    const pa01 = result.findings.find((f) => f.subject === "VITE_STRIPE_SECRET_KEY");
    expect(pa01?.patch?.partial).toMatch(/still runs in the browser/);
    expect(await readFile(join(patched, "src/lib/billing.ts"), "utf8")).not.toContain("VITE_STRIPE_SECRET_KEY");
  });

  it("leaks nothing when probed again from the patched files", async () => {
    const dir = join(patched, "supabase/migrations");
    const migrations = [];
    for (const name of (await readdir(dir)).filter((n) => n.endsWith(".sql"))) {
      migrations.push({ path: name, text: await readFile(join(dir, name), "utf8") });
    }
    const after = await probeRls(migrations);
    expect(after.error).toBeUndefined();
    expect(after.tables.flatMap((t) => leaks(t).map((c) => `${t.table}:${c.actor}:${c.action}`))).toEqual([]);
    // the controls still work for their owner: user A reads their own tasks through the invoker view
    expect(after.tables.find((t) => t.table === "public.open_tasks")?.skipped).toBeUndefined();
  });
});
