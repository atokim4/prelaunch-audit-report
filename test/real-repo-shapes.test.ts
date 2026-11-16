import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { run } from "../src/exec.ts";
import { listFiles } from "../src/files.ts";
import { fixContext } from "../src/patches/index.ts";
import { phiColumns } from "../src/phi/columns.ts";
import { probeRls } from "../src/probe/rls-probe.ts";
import { appAuditWriter, runPhiScan } from "../src/scanners/phi.ts";
import { addStaticContext, dynamicRlsTables } from "../src/scanners/static-context.ts";
import type { AuditResult, Finding, RawFinding } from "../src/types.ts";

/**
 * Shapes seen when the audit ran on public open-source clinic repos (2026-11-16): schema files outside
 * supabase/migrations, RLS turned on by a loop of dynamic SQL, archived SQL, a committed node_modules, a
 * Supabase key under an unusual name, public content tables. Each case is a small app written here, with a
 * control next to it that must still be reported, so a check that went blind cannot pass.
 */
const NOW = new Date("2026-11-16T09:00:00Z");
const dirs: string[] = [];

afterAll(async () => {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
});

async function app(files: Record<string, string>, git = false): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pa-shapes-"));
  dirs.push(dir);
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), text);
  }
  if (git) {
    for (const args of [
      ["init", "-q"],
      ["add", "-A"],
      ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "init"],
    ]) {
      const result = await run("git", ["-C", dir, ...args]);
      if (result.code !== 0) throw new Error(result.stderr);
    }
  }
  return dir;
}

const pkg = JSON.stringify({ name: "shape-app", dependencies: { "@supabase/supabase-js": "2.0.0" } });
const rules = (result: AuditResult): string[] => result.findings.map((f) => `${f.rule}:${f.subject ?? ""}`);
const find = (result: AuditResult, rule: string, subject: string): Finding | undefined =>
  result.findings.find((f) => f.rule === rule && f.subject?.toLowerCase() === subject.toLowerCase());

const VAULT_TABLES = `
create table if not exists public.family_members (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  name text not null,
  allergies text
);
create table if not exists public.medical_records (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  file_url text not null,
  extracted_data jsonb
);
create table if not exists public.reminders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  title text
);
`;

const DYNAMIC_RLS = `
do $$
declare
  t text;
begin
  foreach t in array array['family_members', 'medical_records']
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format($p$create policy "own rows" on public.%I for all to authenticated
      using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id)$p$, t);
  end loop;
end
$$;
`;

describe("schema SQL outside supabase/migrations", () => {
  it("does not report RLS off for tables a DO loop turns it on for, and still reports the one it skips", async () => {
    const dir = await app({ "package.json": pkg, "supabase/schema.sql": VAULT_TABLES + DYNAMIC_RLS });
    const result = await audit({ repo: dir, now: NOW, npmAudit: false, phi: true });
    expect(find(result, "rls-disabled", "public.family_members")).toBeUndefined();
    expect(find(result, "rls-disabled", "public.medical_records")).toBeUndefined();
    // Control: reminders is not in the loop's list.
    expect(find(result, "rls-disabled", "public.reminders")?.severity).toBe("critical");
    expect(result.notChecked.join("\n")).toMatch(/dynamic SQL \(`public\.family_members`, `public\.medical_records`\)/);
  });

  it("maps PHI tables from schema.sql when the probe has nothing to load", async () => {
    const dir = await app({ "package.json": pkg, "supabase/schema.sql": VAULT_TABLES });
    const result = await audit({ repo: dir, now: NOW, npmAudit: false, phi: true });
    const tables = result.phi?.tables ?? [];
    expect(tables.map((t) => [t.table, t.untested])).toEqual([
      ["public.family_members", "not probed"],
      ["public.medical_records", "not probed"],
    ]);
    // With RLS off, a PHI table read by anyone is Critical and carries its columns.
    expect(find(result, "rls-disabled", "public.medical_records")?.phi).toEqual(["file_url", "extracted_data"]);
  });

  it("reads quoted Prisma names and maps them like any table", async () => {
    const dir = await app({
      "package.json": pkg,
      "prisma/migrations/20250101000000_init/migration.sql": `CREATE TABLE "Appointment" ("id" TEXT NOT NULL, "patientId" TEXT NOT NULL, "symptoms" TEXT, CONSTRAINT "Appointment_pkey" PRIMARY KEY ("id"));`,
    });
    const ctx = await fixContext(dir, await listFiles(dir, false), NOW);
    const scan = await runPhiScan(ctx, []);
    expect(scan.result.tables.map((t) => [t.table, t.columns.map((c) => c.name)])).toEqual([
      ["public.appointment", ["symptoms"]],
    ]);
  });

  it("finds the tables in each DO loop list and nothing from a loop that does something else", () => {
    const tables = dynamicRlsTables([
      { path: "a.sql", text: DYNAMIC_RLS },
      {
        path: "b.sql",
        text: `do $$ declare t text; begin foreach t in array array['audit_log'] loop execute format('grant select on public.%I to anon', t); end loop; end $$;`,
      },
    ]);
    expect([...tables].sort()).toEqual(["public.family_members", "public.medical_records"]);
  });
});

describe("PHI column names seen in real schemas", () => {
  it("treats a national id column as a PHI identifier on a patient table", () => {
    expect(phiColumns("patients", ["id", "name", "phone", "tckn"]).map((c) => c.name)).toEqual([
      "tckn",
      "name",
      "phone",
    ]);
  });

  it("maps a health-record table by its name only when its rows belong to a person", () => {
    expect(phiColumns("medical_records", ["id", "user_id", "file_url", "created_at"])).toEqual([
      { name: "file_url", kind: "health" },
    ]);
    // A medications catalogue with no link to a person is reference data.
    expect(phiColumns("medications", ["id", "brand", "generic", "strength"])).toEqual([]);
  });
});

describe("archived SQL", () => {
  const OPEN_INSERT = `create table public.profiles (id uuid primary key references auth.users (id), bio text);
alter table public.profiles enable row level security;
create policy "insert for all" on public.profiles for insert with check (true);
`;

  it("drops findings from SQL in an archive folder and says so; the same SQL in migrations is reported", async () => {
    const archived = await app({
      "package.json": pkg,
      "supabase/archive/20240101000000_old.sql": OPEN_INSERT,
    });
    const result = await audit({ repo: archived, now: NOW, npmAudit: false });
    expect(rules(result).filter((r) => r.startsWith("rls-permissive-policy"))).toEqual([]);
    expect(result.notChecked.join("\n")).toContain("supabase/archive/20240101000000_old.sql");

    const live = await app({ "package.json": pkg, "supabase/migrations/20240101000000_init.sql": OPEN_INSERT });
    const control = await audit({ repo: live, now: NOW, npmAudit: false });
    expect(find(control, "rls-permissive-policy", "public.profiles")).toBeDefined();
  });

  it("reports a policy created again in a later migration once", async () => {
    const dir = await app({
      "package.json": pkg,
      "supabase/migrations/20240101000000_init.sql": OPEN_INSERT,
      "supabase/migrations/20240201000000_again.sql": `create policy "insert for all" on public.profiles for insert with check (true);`,
    });
    const result = await audit({ repo: dir, now: NOW, npmAudit: false });
    expect(result.findings.filter((f) => f.rule === "rls-permissive-policy")).toHaveLength(1);
  });
});

describe("browser env names", () => {
  it("does not call a Supabase key passed to createClient a secret, but keeps a paid API key", async () => {
    const dir = await app({
      "package.json": pkg,
      "src/lib/supabase.js": `import { createClient } from "@supabase/supabase-js";
const url = import.meta.env.VITE_SUPABASE_PROJECT_URL;
const key = import.meta.env.VITE_SUPABASE_API_KEY;
export const supabase = createClient(url, key);
`,
      "src/lib/ai.js": `export const openaiKey = import.meta.env.VITE_OPENAI_API_KEY;\n`,
    });
    const result = await audit({ repo: dir, now: NOW, npmAudit: false });
    const envs = result.findings.filter((f) => f.rule === "public-env-secret").map((f) => f.subject);
    expect(envs).toEqual(["VITE_OPENAI_API_KEY"]);
  });
});

describe("secret scan of history", () => {
  // Built at runtime so this file holds no key header for secret scanners to trip on.
  const label = ["PRIVATE", "KEY"].join(" ");
  const PEM_DOC = `Example:\n-----BEGIN ${label}-----\n...\n-----END ${label}-----\n`;

  /** A repo where `file` was committed and then deleted, so only the history scan can see it. */
  async function historyOnly(file: string): Promise<string[]> {
    const dir = await app({ "package.json": pkg, [file]: PEM_DOC }, true);
    await rm(join(dir, file.split("/")[0] ?? file), { recursive: true });
    for (const args of [
      ["add", "-A"],
      ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "clean"],
    ]) {
      const result = await run("git", ["-C", dir, ...args]);
      if (result.code !== 0) throw new Error(result.stderr);
    }
    const result = await audit({ repo: dir, now: NOW, npmAudit: false });
    return result.findings
      .filter((f) => f.rule === "secret-in-history")
      .map((f) => (f.location.kind === "file" ? f.location.file : ""));
  }

  it("skips a key block in a committed node_modules", async () => {
    expect(await historyOnly("node_modules/some-lib/README.md")).toEqual([]);
  });

  it("still reports the same key block when the app committed it", async () => {
    expect(await historyOnly("certs/server.key")).toEqual(["certs/server.key"]);
  });
});

describe("static context when the probe has no proof", () => {
  const SQL = `
create table public.homepage_sections (id text primary key, title text, content jsonb);
create table public.clinic_contacts (id uuid primary key, email text);
create table public.bookings (id uuid primary key, user_id uuid references auth.users (id), slot text);
create table public.plans (id uuid primary key, doctor_id uuid, name text, target_weight numeric);
create table public.tier_plans (id uuid primary key, name text, price_cents int);
create function public.my_role() returns text language sql security definer as $$ select role from public.staff where id = auth.uid() $$;
create function public.wipe_old() returns void language sql security definer as $$ delete from public.bookings $$;
`;
  const raw = (rule: string, subject: string, message: string): RawFinding => ({
    source: "vibe-preflight",
    rule,
    toolSeverity: "error",
    message,
    location: { kind: "file", file: "supabase/migrations/1_init.sql", line: 1 },
    subject,
  });

  it("sets context only from the SQL, and leaves owned or personal tables and unguarded functions alone", () => {
    const raws = [
      raw("rls-permissive-policy", "public.homepage_sections", 'Policy "p" on `public.homepage_sections` (select) …'),
      raw("rls-permissive-policy", "public.clinic_contacts", 'Policy "p" on `public.clinic_contacts` (select) …'),
      raw("rls-permissive-policy", "public.bookings", 'Policy "p" on `public.bookings` (select) …'),
      raw(
        "definer-function-anon",
        "public.my_role",
        "`public.my_role()` … (Supabase's default grant was never revoked).",
      ),
      raw(
        "definer-function-anon",
        "public.wipe_old",
        "`public.wipe_old()` … (Supabase's default grant was never revoked).",
      ),
      raw("rls-update-privileged-column", "public.patients", "… in `public.patients`, including `plan_id`. …"),
      raw("rls-update-privileged-column", "public.accounts", "… in `public.accounts`, including `tier_plan_id`. …"),
      raw("storage-public-bucket", "public-cms-assets", "Storage bucket `public-cms-assets` is public, …"),
      raw("storage-public-bucket", "lab-results", "Storage bucket `lab-results` is public, …"),
    ];
    addStaticContext(raws, [{ path: "supabase/migrations/1_init.sql", text: SQL }]);
    expect(raws.map((r) => r.context)).toEqual([
      { tableOwned: false, tablePersonal: false },
      { tableOwned: false, tablePersonal: true },
      { tableOwned: true, tablePersonal: false },
      { checksCaller: true },
      { checksCaller: false },
      { carePlan: true },
      { carePlan: false },
      { publicContentBucket: true },
      { publicContentBucket: false },
    ]);
  });

  it("rates a public content table Low and a caller-checking definer function Medium; controls keep their level", async () => {
    const dir = await app({
      "package.json": pkg,
      "supabase/schema.sql": `${SQL}
alter table public.homepage_sections enable row level security;
create policy "read sections" on public.homepage_sections for select using (true);
alter table public.bookings enable row level security;
create policy "read bookings" on public.bookings for select using (true);
`,
    });
    const result = await audit({ repo: dir, now: NOW, npmAudit: false });
    expect(find(result, "rls-permissive-policy", "public.homepage_sections")?.severity).toBe("low");
    expect(find(result, "rls-permissive-policy", "public.homepage_sections")?.evidence).toMatch(
      /looks like public content/,
    );
    expect(find(result, "rls-permissive-policy", "public.bookings")?.severity).toBe("high");
    expect(find(result, "definer-function-anon", "public.my_role")?.severity).toBe("medium");
    expect(find(result, "definer-function-anon", "public.wipe_old")?.severity).toBe("high");
  });
});

describe("RLS probe on a table where every column has a default", () => {
  it("tries the insert with default values instead of an empty column list", async () => {
    const result = await probeRls([
      {
        path: "supabase/migrations/1_settings.sql",
        text: `create table public.site_settings (id text primary key default 'default', site_name text not null default 'Clinic');
alter table public.site_settings enable row level security;
create policy "read" on public.site_settings for select using (true);
grant select, insert on public.site_settings to anon, authenticated;`,
      },
    ]);
    const table = result.tables.find((t) => t.name === "site_settings");
    const inserts = table?.checks.filter((c) => c.action === "insert") ?? [];
    expect(inserts.length).toBeGreaterThan(0);
    expect(inserts.filter((c) => c.inconclusive && /syntax error/.test(c.inconclusive))).toEqual([]);
  });
});

describe("audit trail written by the app", () => {
  it("finds a file that inserts into an audit table, and not one that only reads it", () => {
    const writer = `export async function log(c) { await c.from('audit_logs').insert({ action: 'x' }) }`;
    const reader = `export async function list(c) { return c.from("audit_logs").select("*") }`;
    expect(appAuditWriter(new Map([["lib/read.ts", reader]]))).toBeUndefined();
    expect(
      appAuditWriter(
        new Map([
          ["lib/read.ts", reader],
          ["lib/audit.ts", writer],
        ]),
      ),
    ).toBe("lib/audit.ts");
  });

  it("rates a missing audit trigger Low when the app logs from code, Medium when nothing logs", async () => {
    const files = {
      "package.json": pkg,
      "supabase/migrations/20240101000000_init.sql": `create table public.visits (id uuid primary key, patient_id uuid, diagnosis text);
alter table public.visits enable row level security;
create table public.audit_logs (id uuid primary key, action text);
alter table public.audit_logs enable row level security;`,
    };
    const withApp = await audit({
      repo: await app({
        ...files,
        "lib/audit.ts": `export const log = (c) => c.from("audit_logs").insert({ action: "update" });\n`,
      }),
      now: NOW,
      npmAudit: false,
      phi: true,
    });
    const bare = await audit({ repo: await app(files), now: NOW, npmAudit: false, phi: true });
    const rate = (r: AuditResult) => r.findings.find((f) => f.rule === "phi-no-audit-log");
    expect(rate(withApp)?.severity).toBe("low");
    expect(rate(withApp)?.evidence).toContain("lib/audit.ts");
    expect(rate(bare)?.severity).toBe("medium");
  });
});
