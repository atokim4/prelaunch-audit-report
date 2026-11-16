import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { run } from "../src/exec.ts";
import { phiColumns } from "../src/phi/columns.ts";
import { SHIM_PATH, USER_A, USER_B } from "../src/probe/rls-probe.ts";
import { auditedTables, bucketsOf, codeOnly } from "../src/scanners/phi.ts";
import { SEVERITY_RANK, type AuditResult, type Finding } from "../src/types.ts";

/**
 * clinic-intake-app: a Lovable-shaped clinic demo with health-data holes seeded on purpose. The holes
 * file says what each hole and control is.
 */
const APP = "test/fixtures/clinic-intake-app";
interface Target {
  id: string;
  rule?: string;
  target: { object: string; file: string };
}
const truth = JSON.parse(await readFile("test/fixtures/clinic-intake-app.holes.json", "utf8")) as {
  holes: Target[];
  controls: Target[];
};
const NOW = new Date("2026-11-16T09:00:00Z");

const names = (columns: { name: string }[]) => columns.map((c) => c.name);

describe("PHI column map", () => {
  it("finds health and identifier columns on a patient table, and the person fields with them", () => {
    const columns = phiColumns("patients", ["id", "full_name", "date_of_birth", "mrn", "diagnosis", "created_at"]);
    expect(columns).toEqual([
      { name: "date_of_birth", kind: "identifier" },
      { name: "mrn", kind: "identifier" },
      { name: "diagnosis", kind: "health" },
      { name: "full_name", kind: "identifier" },
    ]);
  });

  it("reads free text as clinical only on a clinical table", () => {
    expect(names(phiColumns("appointments", ["id", "reason", "notes"]))).toEqual(["reason", "notes"]);
    expect(phiColumns("invoices", ["id", "notes", "amount_cents"])).toEqual([]);
  });

  it("does not call a birthday on a plain profile health data", () => {
    expect(phiColumns("profiles", ["id", "full_name", "date_of_birth"])).toEqual([]);
  });

  it("finds clinical columns on a table with any name", () => {
    expect(names(phiColumns("user_settings", ["id", "user_id", "medications", "allergies"]))).toEqual([
      "medications",
      "allergies",
    ]);
  });
});

describe("bucket and trigger reading", () => {
  it("reads bucket rows whose other values hold commas", () => {
    const sql = `insert into storage.buckets (name, allowed_mime_types, id, public) values ('x', ARRAY['image/png', 'application/pdf'], 'scans', true);`;
    expect(bucketsOf([{ path: "m.sql", text: sql }], undefined).map((b) => [b.id, b.public])).toEqual([
      ["scans", true],
    ]);
  });

  it("keeps template literal expressions when it drops string contents from log arguments", () => {
    expect(
      codeOnly("`visit ${visit.reason} for ${patient}`, 'diagnosis text', \"mrn\"").split(/\s+/).filter(Boolean),
    ).toEqual(["visit.reason", "patient", ",", ","]);
  });

  it("follows a later migration that makes a bucket private", () => {
    const files = [
      { path: "1.sql", text: `insert into storage.buckets (id, name, public) values ('scans', 'scans', true);` },
      { path: "2.sql", text: `update storage.buckets set public = false where id = 'scans';` },
    ];
    expect(bucketsOf(files, undefined).map((b) => [b.id, b.public])).toEqual([["scans", false]]);
  });

  it("reads every bucket of a multi-row insert and public buckets in config.toml", () => {
    const sql = `insert into storage.buckets (id, name, public)\nvalues ('scans', 'scans', true), ('avatars', 'avatars', false);`;
    const toml = `[storage.buckets.intake-docs]\npublic = true\nfile_size_limit = "50MiB"\n\n[storage.buckets.logos]\npublic = false\n`;
    expect(bucketsOf([{ path: "m.sql", text: sql }], toml)).toEqual([
      { id: "scans", public: true, file: "m.sql", line: 1 },
      { id: "avatars", public: false, file: "m.sql", line: 1 },
      { id: "intake-docs", public: true, file: "supabase/config.toml", line: 1 },
    ]);
  });

  it("counts a trigger as an audit trail by its name or by a function that inserts into an audit table", () => {
    const sql = `
      create function public.track() returns trigger language plpgsql as $$ begin insert into public.change_audit values (1); return null; end $$;
      create trigger t1 after update on public.patients for each row execute function public.track();
      create trigger visits_history after insert on public.visits for each row execute function public.anything();
      create trigger touch before update on public.labs for each row execute function public.set_updated_at();`;
    expect([...auditedTables([{ path: "m.sql", text: sql }])].sort()).toEqual(["patients", "visits"]);
  });
});

let result: AuditResult;
let plain: AuditResult;
let patched = "";

beforeAll(async () => {
  [result, plain] = await Promise.all([
    audit({ repo: APP, now: NOW, npmAudit: false, phi: true }),
    audit({ repo: APP, now: NOW, npmAudit: false }),
  ]);
  patched = await mkdtemp(join(tmpdir(), "patched-clinic-"));
  await cp(APP, patched, { recursive: true });
  for (const finding of result.findings) {
    if (!finding.patch) continue;
    const file = join(patched, `${finding.id}.diff`);
    await writeFile(file, finding.patch.diff);
    const applied = await run("git", ["apply", file], { cwd: patched });
    if (applied.code !== 0) throw new Error(`${finding.id} did not apply: ${applied.stderr}`);
    await rm(file);
  }
}, 180_000);

afterAll(async () => {
  if (patched) await rm(patched, { recursive: true, force: true });
});

function about(f: Finding, t: Target): boolean {
  if (f.location.kind !== "file" || f.location.file !== t.target.file) return false;
  return (
    f.subject === t.target.object ||
    (f.subject ?? "").startsWith(`${t.target.object} `) ||
    f.subject === `${t.target.object} (${t.target.file})`
  );
}

describe("audit of the clinic app with --phi", () => {
  it("maps the tables and the view with health data", () => {
    expect(result.phi?.tables.map((t) => [t.table, t.relation, t.foundIn.join("+"), t.readBy])).toEqual([
      ["public.appointments", "table", "migrations+types", []],
      ["public.intake_forms", "table", "types", undefined],
      ["public.patients", "table", "migrations+types", ["other-user"]],
      ["public.prescriptions", "table", "migrations+types", []],
      // the view only shows today's visits and the probe's seeded visit is on another day
      ["public.todays_schedule", "view", "migrations+types", undefined],
    ]);
  });

  it("says why a table's access was not measured", () => {
    const untested = result.phi?.tables.filter((t) => t.untested).map((t) => [t.table, t.untested]);
    expect(untested).toEqual([
      ["public.intake_forms", "not in migrations"],
      ["public.todays_schedule", "no rows to test"],
    ]);
  });

  it("finds every seeded hole with the expected rule", () => {
    const missed = truth.holes.filter((h) => !result.findings.some((f) => about(f, h) && f.rule === h.rule));
    expect(missed.map((h) => h.id)).toEqual([]);
  });

  it("gives no control a PHI finding", () => {
    const flagged = truth.controls.filter((c) =>
      result.findings.some((f) => about(f, c) && (f.source === "phi-scan" || f.phi?.length)),
    );
    expect(flagged.map((c) => c.id)).toEqual([]);
    const pages = result.phi?.trackers.flatMap((t) => t.pages) ?? [];
    expect(pages).not.toContain("src/pages/Locations.tsx");
    const prescriptions = result.probe?.find((p) => p.table === "public.prescriptions");
    expect(prescriptions?.leaks).toEqual([]);
  });

  it("rates a second user reading patient records Critical, where the same leak is High without --phi", () => {
    const withPhi = result.findings.find((f) => f.subject === "public.patients");
    const without = plain.findings.find((f) => f.subject === "public.patients");
    expect(withPhi).toMatchObject({ severity: "critical", rule: "rls-probe-leak" });
    expect(withPhi?.phi).toContain("diagnosis");
    expect(without).toMatchObject({ severity: "high", rule: "rls-probe-leak" });
    expect(without?.phi).toBeUndefined();
  });

  it("rates the RLS-skipping PHI view Critical because the probe had no row to disprove it", () => {
    const view = result.findings.find((f) => f.subject === "public.todays_schedule");
    expect(view?.severity).toBe("critical");
    expect(view?.proof?.checks.every((c) => c.of === 0)).toBe(true);
  });

  it("runs no PHI rule without --phi", () => {
    expect(plain.findings.filter((f) => f.source === "phi-scan")).toEqual([]);
    expect(plain.phi).toBeUndefined();
  });

  it("rates the findings with the PHI rubric", () => {
    expect(result.counts).toEqual({ critical: 3, high: 4, medium: 4, low: 1 });
    // without --phi: patients and the view are High, both public buckets vibe-preflight's Medium
    expect(plain.counts).toEqual({ critical: 0, high: 2, medium: 2, low: 1 });
  });

  it("says why the logs finding fired and where", () => {
    const logs = result.findings.find((f) => f.rule === "phi-in-logs");
    expect(logs?.evidence).toBe(
      "`supabase/functions/send-reminder/index.ts` writes `appointment`, `patients` to the function log (lines 11, 24).",
    );
  });

  it("has a verified patch for every Critical, and says which High findings need a decision instead", () => {
    const serious = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high);
    expect(serious.filter((f) => f.severity === "critical" && !f.patch?.verified).map((f) => f.id)).toEqual([]);
    expect(serious.filter((f) => !f.patch).map((f) => f.rule)).toEqual([
      "phi-table-unmanaged",
      "phi-vendor-egress",
      "phi-vendor-egress",
    ]);
  });

  it("fills the HIPAA checklist from what the scan saw", () => {
    const repo = result.phi?.controls.filter((c) => c.where === "repo").map((c) => [c.status, c.detail]);
    expect(repo).toEqual([
      ["gap", "Public buckets that hold health files: lab-results."],
      [
        "gap",
        "The code sends health data to, or loads on health pages: Google Analytics, PostHog, Resend, OpenAI. Each needs a signed BAA or has to stop getting the data.",
      ],
      ["gap", "No audit trigger on public.appointments, public.patients, public.prescriptions."],
    ]);
    expect(result.phi?.controls.filter((c) => c.where === "dashboard").length).toBe(9);
  });
});

describe("the clinic app after applying every patch", () => {
  it("leaves only the findings that need a person's decision", async () => {
    const again = await audit({ repo: patched, now: NOW, npmAudit: false, phi: true });
    expect(again.findings.map((f) => `${f.severity}:${f.rule}`)).toEqual([
      "high:phi-table-unmanaged",
      "high:phi-vendor-egress",
      "high:phi-vendor-egress",
      // PostHog without replay is still analytics on the patient pages
      "medium:phi-analytics",
      "medium:phi-analytics",
      "medium:phi-in-logs",
      "low:rls-permissive-policy",
      "low:rls-no-policy",
    ]);
    expect(
      again.phi?.tables.filter((t) => t.relation === "table" && t.foundIn.includes("migrations") && !t.audited),
    ).toEqual([]);
    expect(again.phi?.trackers.find((t) => t.vendor === "PostHog")?.replay).toBe(false);
  }, 120_000);
});

describe("the audit-log migration, run in PGlite", () => {
  let db: PGlite;

  beforeAll(async () => {
    db = await PGlite.create();
    await db.exec(await readFile(SHIM_PATH, "utf8"));
    const dir = join(patched, "supabase/migrations");
    for (const name of (await readdir(dir)).filter((n) => n.endsWith(".sql")).sort()) {
      await db.exec(await readFile(join(dir, name), "utf8"));
    }
    await db.query(`insert into auth.users (id, email) values ($1, 'a@example.invalid'), ($2, 'b@example.invalid')`, [
      USER_A,
      USER_B,
    ]);
  }, 60_000);

  afterAll(async () => {
    await db?.close();
  });

  /** Runs `sql` as an API role inside a transaction; returns the SQLSTATE when Postgres refuses. */
  async function as(
    role: "anon" | "authenticated" | "service_role",
    sql: string,
    user = USER_A,
  ): Promise<string | undefined> {
    try {
      await db.transaction(async (tx) => {
        await tx.query(`select set_config('request.jwt.claims', $1, true)`, [JSON.stringify({ sub: user, role })]);
        await tx.exec(`set local role ${role}`);
        await tx.exec(sql);
      });
      return undefined;
    } catch (error) {
      return (error as { code?: string }).code ?? String(error);
    }
  }

  it("logs every write to a PHI table with the user, the operation and the row id, and no PHI", async () => {
    const id = "11111111-1111-4111-8111-111111111111";
    expect(
      await as(
        "authenticated",
        `insert into public.patients (id, clinician_id, full_name, diagnosis) values ('${id}', '${USER_A}', 'Sample Patient', 'sample diagnosis');
         update public.patients set diagnosis = 'changed' where id = '${id}';
         insert into public.appointments (patient_id, scheduled_at, reason) values ('${id}', now(), 'checkup');`,
      ),
    ).toBeUndefined();
    // the service role key carries no user: the log says service_role and has no actor (the patch's caveat)
    expect(await as("service_role", `delete from public.patients where id = '${id}';`, "")).toBeUndefined();

    const { rows } = await db.query<{
      actor: string | null;
      actor_role: string;
      table_name: string;
      op: string;
      row_id: string;
    }>(`select actor, actor_role, table_name, op, row_id from public.phi_audit_log order by id`);
    expect(rows.map((r) => [r.actor, r.actor_role, r.table_name, r.op])).toEqual([
      [USER_A, "authenticated", "public.patients", "INSERT"],
      [USER_A, "authenticated", "public.patients", "UPDATE"],
      [USER_A, "authenticated", "public.appointments", "INSERT"],
      // the cascade from the patient delete is logged too
      [null, "service_role", "public.patients", "DELETE"],
      [null, "service_role", "public.appointments", "DELETE"],
    ]);
    expect(rows.filter((r) => r.table_name === "public.patients").every((r) => r.row_id === id)).toBe(true);
    const text = JSON.stringify((await db.query(`select * from public.phi_audit_log`)).rows);
    expect(text).not.toMatch(/Sample Patient|diagnosis|checkup/);
  });

  it("refuses to change or read the log for the API roles with 42501", async () => {
    for (const role of ["anon", "authenticated"] as const) {
      expect(await as(role, `select * from public.phi_audit_log`)).toBe("42501");
      expect(
        await as(role, `insert into public.phi_audit_log (actor_role, table_name, op) values ('x', 'y', 'INSERT')`),
      ).toBe("42501");
      expect(await as(role, `update public.phi_audit_log set op = 'DELETE'`)).toBe("42501");
      expect(await as(role, `delete from public.phi_audit_log`)).toBe("42501");
    }
    expect(await as("service_role", `update public.phi_audit_log set op = 'DELETE'`)).toBe("42501");
    expect(await as("service_role", `delete from public.phi_audit_log`)).toBe("42501");
  });

  it("stops the table owner too, with the append-only guard", async () => {
    for (const sql of [
      "update public.phi_audit_log set op = 'DELETE'",
      "delete from public.phi_audit_log",
      "truncate public.phi_audit_log",
    ]) {
      const code = await db.exec(sql).then(
        () => undefined,
        (error: { code?: string; message?: string }) => `${error.code}: ${error.message}`,
      );
      expect(code).toBe("42501: phi_audit_log is append-only");
    }
    expect((await db.query<{ n: number }>(`select count(*)::int as n from public.phi_audit_log`)).rows[0]?.n).toBe(5);
  });
});
