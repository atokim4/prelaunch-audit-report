/**
 * End to end against a real PostgREST (scripts/fetch-postgrest.sh) on PGlite, behind a small gateway
 * that plays Supabase's auth and API key check. Skipped when the PostgREST binary is not there.
 */
import { spawn } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { probeLive } from "../src/live/probe.ts";
import type { AuditResult, LiveResult, LiveTable } from "../src/types.ts";
import { hasPostgrest, startStandIn, type StandIn } from "./live/stand-in.ts";

const APP = new URL("./fixtures/pipeline-crm-app", import.meta.url).pathname;
const LIVE = new URL("./fixtures/pipeline-crm-live/", import.meta.url).pathname;

/** Row content in seed.sql; none of it may show up in a result. */
const SAMPLE_VALUES = [
  "Sample lead",
  "lead1@example.invalid",
  "INV-0001",
  "sample-contract",
  "Sample note body",
  "120000",
];

const ALLOWED = [
  /^HEAD \/rest\/v1\/[\w%-]+\?/,
  /^GET \/rest\/v1\/[\w%-]+\?.*&limit=0$/,
  /^GET \/storage\/v1\/bucket$/,
  /^POST \/storage\/v1\/object\/list\/[\w-]+$/,
  /^POST \/auth\/v1\/token\?grant_type=password$/,
  /^POST \/auth\/v1\/logout\?scope=local$/,
];

describe.skipIf(!hasPostgrest())("live probe on a PostgREST stand-in", () => {
  let site: StandIn;
  let before: string;
  let result: AuditResult;
  let live: LiveResult;
  const table = (name: string): LiveTable => {
    const found = live.tables.find((t) => t.table === `public.${name}`);
    if (!found) throw new Error(`no live result for ${name}`);
    return found;
  };

  beforeAll(async () => {
    site = await startStandIn({
      app: APP,
      extraSql: [`${LIVE}dashboard-drift.sql`, `${LIVE}seed.sql`, `${LIVE}test-only.sql`],
    });
    before = await site.fingerprint();
    result = await audit({
      repo: APP,
      npmAudit: false,
      now: new Date("2026-11-16T09:00:00Z"),
      live: { project: site.url, key: site.publishableKey, userA: site.users.a, userB: site.users.b, rate: 100 },
    });
    if (!result.live) throw new Error(`live probe did not run: ${JSON.stringify(result.tools.at(-1))}`);
    live = result.live;
  });
  afterAll(async () => site?.stop());

  it("counts what each person sees and calls it right", () => {
    expect(Object.fromEntries(live.tables.map((t) => [t.table.replace("public.", ""), t.verdict]))).toEqual({
      activities: "protected",
      deals: "leak",
      invoices: "leak",
      leads: "protected",
      notes: "protected",
      open_tasks: "leak",
      pipeline_summary: "leak",
      plans: "shared",
      profiles: "protected",
      tasks: "leak",
    });
    expect(table("invoices").leaks).toEqual(["anon", "user-b"]);
    expect(table("invoices").rowsOfA).toEqual({ "user-b": { status: "count", n: 1 }, anon: { status: "count", n: 1 } });
    expect(table("deals").leaks).toEqual(["user-b"]);
    expect(table("deals").summary).toBe("User B can read user A's 1 row.");
    expect(table("leads").ownRowsA).toEqual({ status: "count", n: 2 });
    expect(table("leads").rowsOfA?.["user-b"]).toEqual({ status: "count", n: 0 });
  });

  it("finds the drift between the dashboard and the migrations", () => {
    expect(live.drift.map((d) => [d.table, d.kind])).toEqual([
      ["public.leads", "fixed-outside-migrations"],
      ["public.notes", "not-in-migrations"],
      ["public.open_tasks", "opened-outside-migrations"],
      ["public.tasks", "opened-outside-migrations"],
    ]);
  });

  it("lists user A's storage folder as user B", () => {
    expect(live.buckets).toHaveLength(1);
    expect(live.buckets[0]).toMatchObject({
      bucket: "attachments",
      public: false,
      verdict: "leak",
      leaks: ["user-b"],
      folderOfA: {
        anon: { status: "count", n: 0 },
        "user-a": { status: "count", n: 1 },
        "user-b": { status: "count", n: 1 },
      },
    });
  });

  it("turns only the leaks the repo does not explain into new findings", () => {
    const liveFindings = result.findings.filter((f) => f.source === "live-probe");
    expect(liveFindings.map((f) => [f.rule, f.subject, f.severity])).toEqual([
      ["live-rls-leak", "public.open_tasks", "high"],
      ["live-rls-leak", "public.tasks", "high"],
      ["live-storage-leak", "storage:attachments", "high"],
    ]);
    const leads = result.findings.find((f) => f.subject === "public.leads");
    expect(leads?.live).toMatchObject({ verdict: "protected" });
    expect(leads?.severity).toBe("critical"); // the migrations still have the hole
    const invoices = result.findings.find((f) => f.subject === "public.invoices");
    expect(invoices?.live).toMatchObject({ verdict: "leak" });
  });

  it("writes nothing, reads no row and signs both users out", async () => {
    expect(await site.fingerprint()).toBe(before);
    for (const entry of site.log) {
      const line = `${entry.method} ${entry.path}`;
      expect(
        ALLOWED.some((re) => re.test(line)),
        line,
      ).toBe(true);
    }
    expect(site.logouts).toBe(2);
    expect(live.requests).toBe(site.log.length);
    const text = JSON.stringify(result);
    for (const value of SAMPLE_VALUES) expect(text).not.toContain(value);
    expect(text).not.toContain(site.publishableKey);
    expect(live.rpcs).toEqual([{ name: "delete_lead", securityDefiner: true, foundIn: ["migrations", "types"] }]);
  });

  it("writes patches for the live-only leaks that close them on the live project", async () => {
    const live = result.findings.filter((f) => f.source === "live-probe");
    expect(live.map((f) => [f.subject, Boolean(f.patch?.verified)])).toEqual([
      ["public.open_tasks", false], // a view: fixed through its table
      ["public.tasks", true],
      ["storage:attachments", true],
    ]);
    const added = (diff: string) =>
      diff
        .split("\n")
        .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
        .map((line) => line.slice(1))
        .join("\n");
    // Same as `supabase db push` of the two new migrations, then the probe again, on a copy of the stand-in.
    const copy = await startStandIn({
      app: APP,
      extraSql: [`${LIVE}dashboard-drift.sql`, `${LIVE}seed.sql`],
    });
    try {
      for (const f of live) if (f.patch) await copy.exec(added(f.patch.diff));
      const again = await audit({
        repo: APP,
        npmAudit: false,
        live: { project: copy.url, key: copy.publishableKey, userA: copy.users.a, userB: copy.users.b, rate: 100 },
      });
      const verdicts = Object.fromEntries(
        [...(again.live?.tables ?? []), ...(again.live?.buckets ?? [])].map((t) => [
          t.kind === "live-table" ? t.table : t.bucket,
          t.verdict,
        ]),
      );
      expect(verdicts).toMatchObject({
        "public.tasks": "protected",
        "public.open_tasks": "protected",
        attachments: "protected",
        "public.leads": "protected",
      });
    } finally {
      await copy.stop();
    }
  });

  it("calls a 42501 blocked, a missing table missing, and follows a parent row for ownership", async () => {
    const probe = await probeLive({
      project: site.url,
      key: site.anonKey,
      userA: site.users.a,
      userB: site.users.b,
      targets: [
        { name: "audit_log", relation: "table", foundIn: ["types"], ownerColumns: ["user_id"] },
        {
          name: "lead_files",
          relation: "table",
          foundIn: ["migrations"],
          ownerColumns: [],
          ownedVia: { column: "lead_id", parent: "leads", parentColumn: "id", parentOwner: "owner_id" },
        },
        { name: "gone", relation: "table", foundIn: ["migrations"], ownerColumns: ["user_id"] },
      ],
      buckets: [],
      rpcs: [],
      http: { rate: 100 },
    });
    const [auditLog, leadFiles, gone] = probe.tables;
    expect(probe.keyKind).toBe("anon");
    expect(auditLog?.visible.anon).toEqual({ status: "blocked", code: "42501" });
    expect(auditLog?.verdict).toBe("inconclusive");
    expect(gone?.verdict).toBe("missing");
    expect(probe.drift).toContainEqual(expect.objectContaining({ table: "public.gone", kind: "not-deployed" }));
    expect(leadFiles).toMatchObject({
      verdict: "leak",
      leaks: ["user-b"],
      ownRowsA: { status: "count", n: 1 },
      ownRowsB: { status: "count", n: 1 },
      visible: { "user-b": { status: "count", n: 2 } },
    });
    expect(leadFiles?.summary).toBe("User B can read 1 row that belongs to other users.");
  });

  it("stops at a bad login and refuses a service_role key before sending anything", async () => {
    const options = { project: site.url, targets: [], buckets: [], rpcs: [], http: { rate: 100 } };
    await expect(
      probeLive({
        ...options,
        key: site.publishableKey,
        userA: { ...site.users.a, password: "wrong" },
        userB: site.users.b,
      }),
    ).rejects.toThrow("user A could not sign in (HTTP 400: Invalid login credentials)");
    const sent = site.log.length;
    await expect(
      probeLive({ ...options, key: site.serviceRoleKey, userA: site.users.a, userB: site.users.b }),
    ).rejects.toThrow(/service_role/);
    expect(site.log.length).toBe(sent);
  });
});

describe("CLI consent", () => {
  it("refuses --live without --i-own-this-project", async () => {
    const child = spawn(process.execPath, ["src/cli.ts", APP, "--live", "https://abcd.supabase.co"], {
      cwd: new URL("..", import.meta.url).pathname,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    const code = await new Promise((resolve) => child.on("exit", resolve));
    expect(code).toBe(1);
    expect(stderr).toContain("--i-own-this-project");
  });
});
