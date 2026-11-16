import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { probeRls } from "../src/probe/rls-probe.ts";
import { probeSources } from "../src/probe/sources.ts";
import { adminGates } from "../src/scanners/admin-gate.ts";
import type { AuditResult, Finding } from "../src/types.ts";

/**
 * The misses left after the run on seven public clinic repos (2026-11-16): schema SQL outside
 * supabase/migrations that the probe never loaded, a role column behind an admin helper function rated
 * High, and health data sent to an AI vendor from the browser or from a server action. Every case has a
 * control that must come out differently, so a check that stopped working cannot pass.
 */
const NOW = new Date("2026-11-16T09:00:00Z");
const dirs: string[] = [];

afterAll(async () => {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
});

async function app(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pa-misses-"));
  dirs.push(dir);
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), text);
  }
  return dir;
}

const pkg = JSON.stringify({ name: "misses-app", dependencies: { "@supabase/supabase-js": "2.0.0" } });
const run = async (files: Record<string, string>, phi = false): Promise<AuditResult> =>
  audit({ repo: await app({ "package.json": pkg, ...files }), now: NOW, npmAudit: false, phi });
const byRule = (result: AuditResult, rule: string): Finding[] => result.findings.filter((f) => f.rule === rule);
const probeTool = (result: AuditResult) => result.tools.find((t) => t.name === "rls-probe");

// A Prisma-made table with text ids, and Supabase SQL that owns rows through a wrapper around auth.uid().
const PRISMA_USER = `CREATE TYPE "Role" AS ENUM ('PATIENT', 'DOCTOR', 'ADMIN');
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'PATIENT',
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);`;

const WRAPPER = `create schema if not exists private;
grant usage on schema private to anon, authenticated;
create or replace function private.current_uid() returns text language sql stable as $$
  select (select auth.uid())::text;
$$;
alter table public."User" enable row level security;
create policy "user_select" on public."User" for select to authenticated using (id = private.current_uid());
create policy "user_update" on public."User" for update to authenticated
  using (id = private.current_uid()) with check (id = private.current_uid());`;

const IS_ADMIN = `create or replace function private.is_admin() returns boolean language sql stable security definer
set search_path = public as $$
  select exists (select 1 from public."User" where id = (select auth.uid())::text and role = 'ADMIN'::"Role");
$$;
grant execute on function private.is_admin() to authenticated;
create policy "admin_select" on public."User" for select to authenticated using (private.is_admin());`;

describe("which SQL the probe loads", () => {
  it("puts ORM migrations before supabase/migrations, and base files before a migrations folder otherwise", () => {
    const f = (path: string) => ({ path, text: "" });
    expect(
      probeSources([
        f("supabase/migrations/2_rls.sql"),
        f("prisma/migrations/1_init/migration.sql"),
        f("supabase/schema.sql"),
      ]).map((s) => s.path),
    ).toEqual(["prisma/migrations/1_init/migration.sql", "supabase/migrations/2_rls.sql"]);
    expect(
      probeSources([
        f("sql/migrations/20261102_b.sql"),
        f("sql/migrations/20261101_a.sql"),
        f("sql/baseline.sql"),
        f("sql/demo_seed_sales.sql"),
        f("supabase/seed.sql"),
        f("docs/deployment/BUNDLE_1.sql"),
        f("migrations/001_x.rollback.sql"),
      ]).map((s) => s.path),
    ).toEqual(["sql/baseline.sql", "sql/migrations/20261101_a.sql", "sql/migrations/20261102_b.sql"]);
  });

  it("probes a Prisma table whose owner column is matched through a wrapper of auth.uid()", async () => {
    const result = await probeRls([
      { path: "supabase/migrations/20260808120000_rls.sql", text: WRAPPER },
      { path: "prisma/migrations/20250101000000_init/migration.sql", text: PRISMA_USER },
    ]);
    expect(result.error).toBeUndefined();
    const user = result.tables.find((t) => t.name === "User");
    expect(user?.ownerColumns).toEqual(["id"]);
    expect(user?.checks.find((c) => c.actor === "owner" && c.column === "role")?.rows).toBe(1);
    // Control: user B reads none of user A's row.
    expect(user?.checks.find((c) => c.actor === "other-user" && c.action === "select")).toMatchObject({
      rows: 0,
      of: 1,
    });
  });

  it("loads schema.sql without supabase/migrations and leaves out a table a rejected statement names", async () => {
    const result = await run({
      "db/schema.sql": `create table public.notes (id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id), body text);
alter table public.notes enable row level security;
create policy "read all" on public.notes for select using (true);
create table public.vault (id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id), secret text);
\\i other.sql
alter table public.vault enable row level security;
create policy "own" on public.vault for all using (user_id = app.missing_uid());`,
      "db/seed.sql": "insert into public.notes (body) values ('broken seed, must not load');",
    });
    const tool = probeTool(result);
    expect(tool?.status).toBe("ok");
    expect(tool?.note).toMatch(/Stepped over 2 statement\(s\).*db\/schema\.sql/);
    expect(tool?.note).toMatch(/public\.vault \(statement \d+ of db\/schema\.sql that names it did not load/);
    // The open read policy is proven by behaviour; the table whose policy failed to load is not reported as open.
    const notes = result.probe?.find((p) => p.table === "public.notes");
    expect(notes?.leaks.some((c) => c.actor === "anon" && c.action === "select")).toBe(true);
    expect(result.probe?.some((p) => p.table === "public.vault")).toBe(false);
  });

  it("loads a storage bucket insert with the columns real migrations use", async () => {
    const result = await probeRls([
      {
        path: "supabase/schema.sql",
        text: `insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
  values ('scans', 'scans', false, 5242880, array['image/png']);
create table public.t (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users (id));
alter table public.t enable row level security;`,
      },
    ]);
    expect(result.failedStatements).toEqual([]);
    expect(result.tables.map((t) => t.table)).toEqual(["public.t"]);
  });
});

describe("probe on schemas seen in the held-out repos", () => {
  it("retries with supabase/schema.sql first when the migrations only build on it", async () => {
    const result = await run({
      "supabase/schema.sql": `create table public.analyses (id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id), result text);`,
      "supabase/migrations/002_rls.sql": `alter table public.analyses enable row level security;
create policy "read all" on public.analyses for select to authenticated using (true);`,
    });
    const tool = probeTool(result);
    expect(tool?.status).toBe("ok");
    expect(tool?.note).toMatch(/ran again with supabase\/schema\.sql loaded first/);
    const analyses = result.probe?.find((p) => p.table === "public.analyses");
    expect(analyses?.leaks.map((c) => `${c.actor}:${c.action}`)).toEqual(["other-user:select"]);
  });

  it("keeps a care-plan column Low when the probe ran but never tried that column", async () => {
    const sql = `create table public.plans (id uuid primary key default gen_random_uuid(), name text, target_weight numeric);
create table public.patients (id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id), name text, plan_id uuid references public.plans (id));
alter table public.plans enable row level security;
alter table public.patients enable row level security;
create policy "patients_own" on public.patients for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));`;
    const result = await run({ "supabase/migrations/1_init.sql": sql });
    const plan = byRule(result, "rls-update-privileged-column")[0];
    expect(plan?.proof).toBeDefined();
    expect(plan?.severity).toBe("low");
    // Control: a plan table with a price is a paid tier, High.
    const paid = await run({
      "supabase/migrations/1_init.sql": sql.replace("target_weight numeric", "price_cents int"),
    });
    expect(byRule(paid, "rls-update-privileged-column")[0]?.severity).toBe("high");
  });

  it("drops a definer-function finding when the loaded schema shows anon cannot execute it", async () => {
    const result = await run({
      "supabase/migrations/1_init.sql": `create table public.docs (id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id));
alter table public.docs enable row level security;
create function public.can_view(d uuid) returns boolean language sql stable security definer set search_path = ''
  as $$ select exists (select 1 from public.docs where id = d and user_id = auth.uid()) $$;
create function public.can_edit(d uuid) returns boolean language sql stable security definer set search_path = ''
  as $$ select exists (select 1 from public.docs where id = d and user_id = auth.uid()) $$;
create function public.wipe_docs() returns void language sql security definer set search_path = ''
  as $$ delete from public.docs $$;`,
      // One revoke for two functions: the static rule reads only the first name.
      "supabase/migrations/2_lock.sql": `revoke all on function public.can_view(uuid), public.can_edit(uuid) from public, anon;
revoke all on function public.wipe_docs() from public;`,
    });
    const subjects = byRule(result, "definer-function-anon").map((f) => f.subject);
    expect(subjects).not.toContain("public.can_view");
    expect(subjects).not.toContain("public.can_edit");
    // Control: a revoke from PUBLIC alone leaves Supabase's direct grant to anon, so it is still reported.
    expect(subjects).toContain("public.wipe_docs");
    expect(probeTool(result)?.note).toMatch(
      /2 SECURITY DEFINER function\(s\).*not executable by anon once the schema is loaded \(`public\.can_view`, `public\.can_edit`\)/,
    );
  });

  it("seeds a role enum with a plain label, so an admin-only write policy is not read as self-escalation", async () => {
    const staff = `create type staff_role as enum ('admin', 'receptionist', 'dentist');
create table public.staff (id uuid primary key default gen_random_uuid(),
  auth_user_id uuid not null references auth.users (id), name text not null, role staff_role not null);
create or replace function public.current_staff_role() returns staff_role language sql stable security definer
  set search_path = public as $$ select role from public.staff where auth_user_id = auth.uid() $$;
alter table public.staff enable row level security;
create policy staff_read on public.staff for select to authenticated using (auth_user_id = auth.uid());`;
    const admin = `create policy staff_admin_write on public.staff for all to authenticated
  using (current_staff_role() = 'admin') with check (current_staff_role() = 'admin');`;
    const self = `create policy staff_self_write on public.staff for update to authenticated
  using (auth_user_id = auth.uid()) with check (auth_user_id = auth.uid());`;
    const probe = async (text: string) =>
      (await probeRls([{ path: "supabase/migrations/1.sql", text }])).tables.find((t) => t.name === "staff");
    const guarded = await probe(`${staff}\n${admin}`);
    expect(guarded?.checks.find((c) => c.actor === "owner" && c.column === "role")?.rows).toBe(0);
    // Control: a policy that lets the row's owner update it still shows the escalation.
    const open = await probe(`${staff}\n${admin}\n${self}`);
    expect(open?.checks.find((c) => c.actor === "owner" && c.column === "role")?.rows).toBe(1);
  });
});

describe("health data in function logs", () => {
  it("does not count a log line that prints only row ids, and still counts one that prints the row", async () => {
    const fn = (log: string) => `import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async (req) => {
  const supabase = createClient("u", "k");
  const { data: visit, error } = await supabase.from("visits").select("id, diagnosis").single();
  ${log}
  return new Response(visit.diagnosis);
});
`;
    const logs = async (line: string) =>
      byRule(
        await run({ "supabase/migrations/1_init.sql": VISITS, "supabase/functions/v/index.ts": fn(line) }, true),
        "phi-in-logs",
      );
    expect(await logs(`if (error) console.error("visit update failed", visit.id, error.message);`)).toEqual([]);
    expect(await logs(`console.log("fetched", visit?.length ?? 0);`)).toEqual([]);
    // Control: the whole row goes to the log.
    expect((await logs(`console.log("visit", visit);`)).length).toBe(1);
  });
});

describe("role column that decides admin access", () => {
  it("rates a self-update of role Critical when is_admin() reads it, with a patch that brings it to zero", async () => {
    const files = {
      "prisma/migrations/20250101000000_init/migration.sql": PRISMA_USER,
      "supabase/migrations/20260808120000_rls.sql": `${WRAPPER}\n${IS_ADMIN}`,
    };
    const result = await run(files);
    const leak = result.findings.find((f) => f.subject === "public.User");
    expect(leak?.severity).toBe("critical");
    expect(leak?.title).toBe("Users can make themselves an admin");
    expect(leak?.evidence).toMatch(/`role` decides admin access: `private\.is_admin\(\)` reads it/);
    expect(leak?.patch?.verified).toBe(true);
    expect(leak?.patch?.diff).toContain(`revoke update on public."User" from anon, authenticated;`);
    expect(leak?.proof?.afterPatches).toEqual([]);

    // Control: the same self-update with no admin helper is the paid-column case, High.
    const plain = await run({ ...files, "supabase/migrations/20260808120000_rls.sql": WRAPPER });
    const owner = plain.findings.find((f) => f.subject === "public.User");
    expect(owner?.severity).toBe("high");
    expect(owner?.adminGate).toBeUndefined();
  });

  it("finds current_role() and policy subqueries, and ignores a role helper no policy uses", () => {
    const profiles = `create table public.profiles (id uuid primary key references auth.users (id), role user_role not null default 'patient', full_name text);`;
    const helper = `create or replace function public.current_role() returns user_role language sql stable security definer as $$
  select role from public.profiles where id = auth.uid();
$$;`;
    const used = `create policy "admin all" on public.records for all using (public.current_role() = 'admin');`;
    const sub = `create policy "staff read" on public.visits for select using ((select p.role from public.profiles p where p.id = auth.uid()) = 'staff');`;
    expect(adminGates([{ path: "s.sql", text: `${profiles}\n${helper}\n${used}` }]).map((g) => g.column)).toEqual([
      "role",
    ]);
    expect(adminGates([{ path: "s.sql", text: `${profiles}\n${sub}` }])[0]?.via).toBe(
      'policy "staff read" on public.visits checks it',
    );
    // Controls: a helper nobody's policy calls, and a policy that reads profiles without a role literal.
    expect(adminGates([{ path: "s.sql", text: `${profiles}\n${helper}` }])).toEqual([]);
    const own = `create policy "own" on public.visits for select using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.full_name is not null));`;
    expect(adminGates([{ path: "s.sql", text: `${profiles}\n${own}` }])).toEqual([]);
  });
});

const VISITS = `create table public.visits (id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references auth.users (id), diagnosis text, notes text);
alter table public.visits enable row level security;
create policy "own" on public.visits for select to authenticated using ((select auth.uid()) = patient_id);`;

describe("health data sent to AI vendors outside API routes", () => {
  const egress = (result: AuditResult) => byRule(result, "phi-vendor-egress");

  it("reports an AI call from the browser with the key in the page and clinical fields", async () => {
    const browser = `import OpenAI from "openai";
const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });
export async function summarize(patientInfo: string, symptoms: string) {
  return client.chat.completions.create({ model: "x", messages: [{ role: "user", content: patientInfo + symptoms }] });
}
`;
    const result = await run({ "supabase/migrations/1_init.sql": VISITS, "src/lib/ai.ts": browser }, true);
    const [found] = egress(result);
    expect(found?.severity).toBe("high");
    expect(found?.evidence).toMatch(/calls OpenAI from the browser \(`NEXT_PUBLIC_OPENAI_API_KEY`\)/);
    expect(found?.phi).toEqual(["patientInfo", "symptoms"]);

    // Controls: the same SDK with a server-only key, and a browser AI call that handles no clinical text.
    const serverKey = browser
      .replace("NEXT_PUBLIC_OPENAI_API_KEY", "OPENAI_API_KEY")
      .replace(", dangerouslyAllowBrowser: true", "");
    const article = browser.replaceAll("patientInfo", "article").replaceAll("symptoms", "title");
    for (const text of [serverKey, article]) {
      const control = await run({ "supabase/migrations/1_init.sql": VISITS, "src/lib/ai.ts": text }, true);
      expect(egress(control)).toEqual([]);
    }
  });

  it("treats a 'use server' action as server code that sends health data to a vendor", async () => {
    const action = `"use server";
import OpenAI from "openai";
import { createClient } from "@/lib/supabase/server";
export async function explainVisit(id: string) {
  const supabase = await createClient();
  const { data } = await supabase.from("visits").select("diagnosis, notes").eq("id", id).single();
  return new OpenAI().responses.create({ model: "x", input: data.diagnosis });
}
`;
    const result = await run({ "supabase/migrations/1_init.sql": VISITS, "src/app/visits/actions.ts": action }, true);
    expect(egress(result).map((f) => f.subject)).toEqual(["OpenAI (src/app/visits/actions.ts)"]);

    // Control: without the directive the file is a client module, and it has no browser key, so nothing.
    const plain = await run(
      { "supabase/migrations/1_init.sql": VISITS, "src/app/visits/actions.ts": action.replace('"use server";\n', "") },
      true,
    );
    expect(egress(plain)).toEqual([]);
  });
});
