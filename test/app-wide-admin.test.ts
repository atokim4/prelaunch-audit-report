import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import type { AuditResult } from "../src/types.ts";

/**
 * Shapes from re-running the clinic repos with v0.6.0 (2026-11-16, run 9): a hospital whose staff table
 * names a clinic (department) but whose admin role is hospital-wide, public clinic listings, and a definer
 * role helper the app's own policies call. v0.6.0 read the first as seven cross-organization Criticals and
 * its patch revoked the helper from signed-in users, which the positive check showed locks every staff
 * member out. Each case has a control that must keep the old reading.
 */
const NOW = new Date("2026-11-16T09:00:00Z");
const dirs: string[] = [];

afterAll(async () => {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
});

async function run(sql: string): Promise<AuditResult> {
  const dir = await mkdtemp(join(tmpdir(), "pa-admin-"));
  dirs.push(dir);
  const files = { "package.json": '{"name":"hospital"}', "supabase/migrations/1_init.sql": sql };
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), text);
  }
  return audit({ repo: dir, now: NOW, npmAudit: false });
}

const HOSPITAL = (adminCheck: string, readPolicy: string) => `
  create type staff_role as enum ('ADMIN', 'RECEPTIONIST', 'DOCTOR');
  create table public.clinics (id text primary key, name text not null, is_active boolean not null default true);
  create table public.staff_profiles (
    id uuid primary key references auth.users (id) on delete cascade,
    role staff_role not null default 'RECEPTIONIST',
    clinic_id text references public.clinics (id)
  );
  create table public.clinic_services (
    id uuid primary key default gen_random_uuid(),
    clinic_id text not null references public.clinics (id),
    title text not null
  );
  ${adminCheck}
  alter table public.clinics enable row level security;
  alter table public.staff_profiles enable row level security;
  alter table public.clinic_services enable row level security;
  create policy "Staff read own profile" on public.staff_profiles for select to authenticated using (id = (select auth.uid()));
  ${readPolicy}
  create policy "Admins manage services" on public.clinic_services for all to authenticated
    using (public.current_staff_role() = 'ADMIN') with check (public.current_staff_role() = 'ADMIN');
  create policy "Admins manage clinics" on public.clinics for all to authenticated
    using (public.current_staff_role() = 'ADMIN') with check (public.current_staff_role() = 'ADMIN');`;

/** Hospital-wide: the helper reads the role without the clinic. */
const GLOBAL = `create function public.current_staff_role() returns staff_role language sql stable security definer
  set search_path = '' as $$ select role from public.staff_profiles where id = auth.uid() $$;`;
/** Control: the helper is scoped by the clinic of the row (a per-organization admin). */
const SCOPED = `create function public.current_staff_role() returns staff_role language sql stable security definer
  set search_path = '' as $$ select role from public.staff_profiles where id = auth.uid() and clinic_id is not null $$;`;

const PUBLIC_READ = `create policy "Public can view services" on public.clinic_services for select using (true);
  create policy "Public can view active clinics" on public.clinics for select to anon, authenticated using (is_active);`;

const rules = (r: AuditResult) => r.findings.map((f) => `${f.rule}:${f.subject}:${f.severity}`).sort();

describe("app-wide admins, public listings, helpers the policies call", () => {
  it("tests other organizations as a plain member when admins are app-wide, and says so once", async () => {
    const result = await run(HOSPITAL(GLOBAL, PUBLIC_READ));
    const global = result.findings.filter((f) => f.rule === "tenant-global-admin");
    expect(global.map((f) => [f.severity, f.subject])).toEqual([["medium", "public.staff_profiles"]]);
    expect(global[0]?.evidence).toMatch(/current_staff_role\(\) decides admin access/);
    // Admins writing services is the design here: no cross-organization write is reported.
    const services = result.probe?.find((p) => p.table === "public.clinic_services");
    expect(services?.leaks.filter((c) => c.action !== "select")).toEqual([]);
  });

  it("rates clinic listings visitors read through a public policy Low, and keeps the patch from locking staff out", async () => {
    const result = await run(HOSPITAL(GLOBAL, PUBLIC_READ));
    expect(rules(result).filter((r) => /clinic_services|public\.clinics:/.test(r))).toEqual([
      "rls-permissive-policy:public.clinic_services:low",
      "rls-probe-leak:public.clinics:low",
    ]);
    expect(result.findings.find((f) => f.subject === "public.clinic_services")?.evidence).toMatch(/public listing/);
    expect((result.probe ?? []).filter((p) => p.lockedOut)).toEqual([]);
  });

  it("keeps the Critical when the open read has the dashboard's default name or a personal column (controls)", async () => {
    const template = await run(
      HOSPITAL(
        GLOBAL,
        `create policy "Enable read access for all users" on public.clinic_services for select using (true);`,
      ),
    );
    expect(template.findings.find((f) => f.subject === "public.clinic_services")?.severity).toBe("critical");
    const personal = await run(
      HOSPITAL(GLOBAL, PUBLIC_READ).replace("title text not null", "title text not null, phone text"),
    );
    expect(personal.findings.find((f) => f.subject === "public.clinic_services")?.severity).toBe("critical");
  });

  it("does not call a clinic-scoped admin app-wide (control)", async () => {
    const result = await run(HOSPITAL(SCOPED, PUBLIC_READ));
    expect(result.findings.filter((f) => f.rule === "tenant-global-admin")).toEqual([]);
  });

  it("revokes a definer helper from visitors only when the app's policies call it", async () => {
    // Anon keeps Supabase's default execute grant here: nothing revokes it.
    const result = await run(HOSPITAL(GLOBAL, PUBLIC_READ));
    const helper = result.findings.find(
      (f) => f.rule === "definer-function-anon" && /current_staff_role/.test(f.subject ?? ""),
    );
    expect(helper?.patch?.diff).toContain("from public, anon;");
    expect(helper?.patch?.diff).toContain("grant execute on function public.current_staff_role() to authenticated;");
    expect(helper?.patch?.summary).toMatch(/policies call it/);
    // Control: a definer function no policy calls loses every API role.
    const lone = await run(`${HOSPITAL(GLOBAL, PUBLIC_READ)}
      create function public.lone_helper() returns uuid language sql security definer set search_path = ''
        as $$ select auth.uid() $$;`);
    const other = lone.findings.find((f) => f.rule === "definer-function-anon" && /lone_helper/.test(f.subject ?? ""));
    expect(other?.patch?.diff).toContain("from public, anon, authenticated;");
  });
});

describe("probe details from the run-9 re-validation", () => {
  it("tests signed-in users as having finished MFA, so a require-MFA policy decides nothing", async () => {
    const schema = `
      create table public.doctors (id uuid primary key references auth.users (id), full_name text);
      alter table public.doctors enable row level security;
      create policy "own" on public.doctors for all to authenticated using (auth.uid() = id) with check (auth.uid() = id);
      create policy "mfa" on public.doctors as restrictive for select to authenticated using ((auth.jwt() ->> 'aal') = 'aal2');`;
    const result = await run(schema);
    const doctors = result.probe?.find((p) => p.table === "public.doctors");
    expect(doctors?.verdict).toBe("protected");
    // Control: a leak behind the MFA policy is still a leak (user B can enroll MFA too).
    const leaky = await run(`${schema}
      create policy "all staff" on public.doctors for select to authenticated using (true);`);
    expect(leaky.probe?.find((p) => p.table === "public.doctors")?.leaks.map((c) => c.actor)).toEqual(["other-user"]);
  });

  it("does not read a staff member's default chair as an organization (control: a real membership table)", async () => {
    const chairs = await run(`
      create table public.chairs (id uuid primary key default gen_random_uuid(), label text not null);
      create table public.staff (
        id uuid primary key default gen_random_uuid(),
        auth_user_id uuid not null unique references auth.users (id),
        default_chair uuid references public.chairs (id)
      );
      alter table public.chairs enable row level security;
      alter table public.staff enable row level security;
      create policy "staff read chairs" on public.chairs for select to authenticated using (true);
      create policy "own staff row" on public.staff for select to authenticated using (auth_user_id = auth.uid());`);
    expect((chairs.probe ?? []).filter((p) => p.tenant)).toEqual([]);
    const members = await run(`
      create table public.chairs (id uuid primary key default gen_random_uuid(), label text not null);
      create table public.chair_members (
        chair_id uuid not null references public.chairs (id),
        user_id uuid not null references auth.users (id),
        primary key (chair_id, user_id)
      );`);
    expect((members.probe ?? []).filter((p) => p.tenant).map((p) => p.table)).toEqual([
      "public.chair_members",
      "public.chairs",
    ]);
  });
});

describe("precision fixes from the three new held-out repos (run 9)", () => {
  it("grades a key in a test-data folder as test (control: the same key in source stays live)", async () => {
    const { runSecretScan } = await import("../src/scanners/secrets.ts");
    const { phiKind } = await import("../src/phi/columns.ts");
    // Built at runtime so this file never holds a key-shaped literal.
    const pem = ["-----BEGIN", "PRIVATE KEY-----"].join(" ") + "\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n";
    const dir = await mkdtemp(join(tmpdir(), "pa-testdata-"));
    dirs.push(dir);
    await mkdir(join(dir, "supabase/functions/_shared/testdata/jws"), { recursive: true });
    await mkdir(join(dir, "src"), { recursive: true });
    await writeFile(join(dir, "supabase/functions/_shared/testdata/jws/leaf.p8.pem"), pem);
    await writeFile(join(dir, "src/key.pem"), pem);
    const { findings } = await runSecretScan(dir);
    expect(findings.map((f) => [f.location.kind === "file" ? f.location.file : "", f.toolSeverity]).sort()).toEqual([
      ["src/key.pem", "live"],
      ["supabase/functions/_shared/testdata/jws/leaf.p8.pem", "test"],
    ]);
    // A staff role flag is not health data; a clinical column next to it still is.
    expect(phiKind("public.organization_memberships", "clinical_reviewer")).toBeUndefined();
    expect(phiKind("public.organization_memberships", "clinical_notes")).toBe("health");
  });

  it("rates anonymous inserts the schema grants column by column Medium (control: the default table grant)", async () => {
    const table = `
      create table public.onboarding_steps (
        id bigint generated always as identity primary key,
        install_id text not null, page text not null, step int not null
      );
      alter table public.onboarding_steps enable row level security;
      create policy "onboarding_steps: insert" on public.onboarding_steps for insert to anon, authenticated with check (true);`;
    const designed = await run(`${table}
      revoke all on public.onboarding_steps from public, anon, authenticated;
      grant insert (install_id, page, step) on public.onboarding_steps to anon, authenticated;`);
    const finding = designed.findings.find((f) => f.subject === "public.onboarding_steps");
    expect(finding?.severity).toBe("medium");
    expect(finding?.evidence).toMatch(/rate limit/);
    const open = await run(table);
    expect(open.findings.find((f) => f.subject === "public.onboarding_steps")?.severity).toBe("critical");
  });
});
