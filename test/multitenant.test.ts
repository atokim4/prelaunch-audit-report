import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { run } from "../src/exec.ts";
import { allowedValues, leaks, probeRls, SHIM_PATH, statementTarget, type TableProbe } from "../src/probe/rls-probe.ts";
import { detectTenancy, type TenancyTable } from "../src/probe/tenancy.ts";
import { SEVERITY_RANK, type AuditResult, type Finding } from "../src/types.ts";

/**
 * Organization (team, workspace) model: the probe finds the membership table, seeds two organizations,
 * and tries cross-organization access, self-join and self-promotion. team-workspace-app is the
 * deliberately broken B2B fixture; its holes file is the ground truth.
 */

const summary = (t: TableProbe | undefined): string[] =>
  t
    ? leaks(t).map(
        (c) => `${c.actor}:${c.action}${c.column ? `:${c.column}` : ""}${c.scenario ? `:${c.scenario}` : ""}`,
      )
    : [];

async function probe(sql: string): Promise<Map<string, TableProbe>> {
  const result = await probeRls([{ path: "supabase/migrations/1_test.sql", text: sql }]);
  if (result.error) throw new Error(result.error);
  return new Map(result.tables.map((t) => [t.name, t]));
}

const ORGS = `
create table public.organizations (id uuid primary key default gen_random_uuid(), name text not null);
create table public.organization_members (
  org_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id),
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  primary key (org_id, user_id)
);
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id),
  name text not null
);
create function public.member_of(org uuid) returns boolean language sql stable security definer set search_path = ''
  as $$ select exists (select 1 from public.organization_members where org_id = org and user_id = (select auth.uid())) $$;
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.projects enable row level security;
create policy "read org" on public.organizations for select to authenticated using (public.member_of(id));
create policy "read members" on public.organization_members for select to authenticated using (public.member_of(org_id));
`;

describe("organization detection", () => {
  const col = (name: string, extra: Partial<TenancyTable["columns"][number]> = {}) => ({
    name,
    type: "uuid",
    user: false,
    ...extra,
  });
  const table = (name: string, columns: TenancyTable["columns"], ownerColumns: string[] = []): TenancyTable => ({
    name,
    kind: "table",
    columns,
    ownerColumns,
  });

  it("takes the top organization, not a project-level membership table", () => {
    const t = detectTenancy([
      table("organizations", [col("id")]),
      table(
        "organization_members",
        [col("org_id", { parent: { name: "organizations", column: "id" } }), col("user_id", { user: true })],
        ["user_id"],
      ),
      table("projects", [col("id"), col("org_id", { parent: { name: "organizations", column: "id" } })]),
      table(
        "project_members",
        [col("project_id", { parent: { name: "projects", column: "id" } }), col("user_id", { user: true })],
        ["user_id"],
      ),
      table("comments", [col("id"), col("project_id", { parent: { name: "projects", column: "id" } })]),
    ]);
    expect(t?.tenant).toBe("public.organizations");
    expect(t?.members.table).toBe("public.organization_members");
    expect(t?.links.get("projects")?.via).toEqual({ kind: "column", column: "org_id" });
    expect(t?.links.get("project_members")?.via).toMatchObject({
      kind: "parent",
      parent: "public.projects",
      parentTenantColumn: "org_id",
    });
    expect(t?.links.get("comments")?.via.kind).toBe("parent");
  });

  it("finds an organization table with an unusual name through its membership table", () => {
    const t = detectTenancy([
      table("business_units", [col("id")]),
      table(
        "memberships",
        [col("business_unit_id", { parent: { name: "business_units", column: "id" } }), col("user_id", { user: true })],
        ["user_id"],
      ),
    ]);
    expect(t?.tenant).toBe("public.business_units");
    expect(t?.members.tenantColumn).toBe("business_unit_id");
  });

  it("is not fooled by a teams table with no membership table (control)", () => {
    const t = detectTenancy([
      table("teams", [col("id"), col("owner_id", { user: true })], ["owner_id"]),
      table("players", [col("id"), col("team_id", { parent: { name: "teams", column: "id" } })]),
    ]);
    expect(t).toBeUndefined();
  });

  it("reads admin and member roles from the enum or CHECK list", () => {
    const t = detectTenancy([
      table("accounts", [col("id")]),
      table(
        "account_user",
        [
          col("account_id", { parent: { name: "accounts", column: "id" } }),
          col("user_id", { user: true }),
          col("account_role", { type: "text" }),
          col("role", { type: "text", enumLabels: ["owner", "member"] }),
        ],
        ["user_id"],
      ),
    ]);
    expect(t?.members).toMatchObject({ roleColumn: "role", adminRoles: ["owner"], memberRole: "member" });
  });
});

describe("CHECK lists as seed values", () => {
  it("reads the values of a one-column IN list and ignores other checks", () => {
    expect(allowedValues(["CHECK ((role = ANY (ARRAY['admin'::text, 'member'::text])))"])).toEqual(["admin", "member"]);
    expect(allowedValues(["CHECK ((char_length(name) > 2))"])).toBeUndefined();
    // run 9: a single allowed value; a comparison inside a larger expression is not a value list (control)
    expect(allowedValues(["CHECK ((role = 'owner'::text))"])).toEqual(["owner"]);
    expect(allowedValues(["CHECK (((role = 'owner'::text) OR (role = 'admin'::text)))"])).toBeUndefined();
    expect(allowedValues(["CHECK (((kind = ANY (ARRAY['a'::text])) OR (x > 1)))"])).toBeUndefined();
  });

  it("seeds a table whose not-null text column only allows a list of values", async () => {
    const tables = await probe(`${ORGS}
      create table public.invites (id uuid primary key default gen_random_uuid(),
        org_id uuid not null references public.organizations (id), role text not null check (role in ('admin', 'member')));
      alter table public.invites enable row level security;
      create policy "read" on public.invites for select to authenticated using (public.member_of(org_id));`);
    expect(tables.get("invites")?.skipped).toBeUndefined();
    expect(summary(tables.get("invites"))).toEqual([]);
  });
});

describe("RLS probe with an organization model", () => {
  it("finds nothing on membership-scoped policies (control)", async () => {
    const tables = await probe(`${ORGS}
      create policy "members" on public.projects for all to authenticated
        using (public.member_of(org_id)) with check (public.member_of(org_id));`);
    expect(tables.get("projects")?.tenant?.via).toEqual({ kind: "column", column: "org_id" });
    expect([...tables.values()].flatMap((t) => summary(t))).toEqual([]);
    // the probe really ran: user B, an admin elsewhere, and user C, in no organization, got nothing
    const reads = tables.get("projects")?.checks.filter((c) => c.action === "select") ?? [];
    expect(reads.map((c) => `${c.actor}:${c.rows}/${c.of}`)).toEqual(["anon:0/1", "other-user:0/1", "non-member:0/1"]);
  });

  it("catches a policy that asks for any membership instead of this organization's", async () => {
    const tables = await probe(`${ORGS}
      create policy "any member" on public.projects for select to authenticated
        using (exists (select 1 from public.organization_members m where m.user_id = auth.uid()));`);
    // B is a member of organization B, so B gets in; C is a member of nothing, so C does not
    expect(summary(tables.get("projects"))).toEqual(["other-user:select"]);
  });

  it("catches self-join and self-promotion", async () => {
    const tables = await probe(`${ORGS}
      create policy "join" on public.organization_members for insert to authenticated with check (user_id = auth.uid());
      create policy "edit own" on public.organization_members for update to authenticated using (user_id = auth.uid());`);
    const members = tables.get("organization_members");
    expect(summary(members)).toEqual(["owner:update:role", "other-user:insert:self-join"]);
    // Moving the row to organization B is refused here: an update with a filter needs the new row to pass
    // the select policy, and user A is not a member of B. PostgREST sends the same filtered update.
    expect(members?.checks.find((c) => c.scenario === "move-tenant")?.refused).toMatch(/row-level security/);
  });

  it("catches a member moving their row to another organization when the member list is open", async () => {
    const open = ORGS.replace("using (public.member_of(org_id));", "using (true);");
    const tables = await probe(`${open}
      create policy "edit own" on public.organization_members for update to authenticated using (user_id = auth.uid());`);
    expect(summary(tables.get("organization_members"))).toEqual([
      "other-user:select",
      "non-member:select",
      "owner:update:role",
      "owner:update:org_id:move-tenant",
    ]);
  });

  it("sees no self-join or promotion when only admins manage members (control)", async () => {
    const tables = await probe(`${ORGS}
      create function public.admin_of(org uuid) returns boolean language sql stable security definer set search_path = ''
        as $$ select exists (select 1 from public.organization_members where org_id = org and user_id = (select auth.uid()) and role in ('owner', 'admin')) $$;
      create policy "admins add" on public.organization_members for insert to authenticated with check (public.admin_of(org_id));
      create policy "admins edit" on public.organization_members for update to authenticated using (public.admin_of(org_id));`);
    const members = tables.get("organization_members");
    expect(summary(members)).toEqual([]);
    // user A is a plain member, so the escalation try was really refused, not skipped
    expect(members?.checks.filter((c) => c.actor === "owner").map((c) => `${c.column}:${c.rows}`)).toEqual([
      "role:0",
      "org_id:0",
    ]);
  });
});

/** Fixes from the run-8 first pass on five public multi-tenant repos (VALIDATION.md), each with a control. */
describe("real multi-tenant schema shapes", () => {
  it("seeds a child whose composite foreign key points at one parent row", async () => {
    const tables = await probe(`${ORGS}
      alter table public.projects add unique (id, org_id);
      create table public.documents (id uuid primary key default gen_random_uuid(), project_id uuid not null, org_id uuid not null
        references public.organizations (id), title text not null,
        foreign key (project_id, org_id) references public.projects (id, org_id));
      alter table public.documents enable row level security;
      create policy "docs" on public.documents for select to authenticated using (true);`);
    expect(tables.get("documents")?.skipped).toBeUndefined();
    expect(summary(tables.get("documents"))).toEqual(["other-user:select", "non-member:select"]);
  });

  it("seeds an email column that has a format CHECK", async () => {
    const tables = await probe(`${ORGS}
      create table public.invitations (id uuid primary key default gen_random_uuid(), org_id uuid not null references public.organizations (id),
        email text not null check (email ~* '^[^@]+@[^@]+\\.[^@]+$'));
      alter table public.invitations enable row level security;`);
    expect(tables.get("invitations")?.skipped).toBeUndefined();
  });

  const JWT = `${ORGS}
    create function public.current_org_id() returns uuid language sql stable
      as $$ select (auth.jwt() -> 'app_metadata' ->> 'org_id')::uuid $$;`;

  it("puts the organization in app_metadata when policies read it from the token", async () => {
    const tables = await probe(`${JWT}
      create policy "same org" on public.projects for all to authenticated using (org_id = public.current_org_id());
      create policy "edit team" on public.organization_members for update to authenticated using (org_id = public.current_org_id());`);
    // the token scoping holds across organizations, but any member can rewrite roles in their own one
    expect(summary(tables.get("projects"))).toEqual([]);
    expect(summary(tables.get("organization_members"))).toEqual(["owner:update:role"]);
    // and the members really were in: user A's own organization's project was there to read
    expect(tables.get("projects")?.checks.find((c) => c.actor === "other-user" && c.action === "select")?.of).toBe(1);
  });

  it("finds no token leak when the policies compare with the token's organization and role (control)", async () => {
    const tables = await probe(`${JWT}
      create policy "admins edit" on public.organization_members for update to authenticated
        using (org_id = public.current_org_id() and (auth.jwt() -> 'app_metadata' ->> 'role') in ('owner', 'admin'));`);
    expect(summary(tables.get("organization_members"))).toEqual([]);
  });

  it("links an organization column that has no foreign key by the membership column's name and type", async () => {
    const tables = await probe(`${ORGS}
      create table public.audit_log (seq bigint generated always as identity primary key, org_id uuid, action text not null);
      create table public.notes (id uuid primary key default gen_random_uuid(), org_id text, body text);
      alter table public.audit_log enable row level security;
      create policy "log" on public.audit_log for insert with check (true);`);
    expect(tables.get("audit_log")?.tenant?.via).toEqual({ kind: "column", column: "org_id" });
    expect(summary(tables.get("audit_log"))).toEqual(["anon:insert", "other-user:insert"]);
    // control: same name, different type (text, not uuid): not linked
    expect(tables.get("notes")?.tenant).toBeUndefined();
  });

  it("reads what a rejected statement was about from its target, not from every name in it", () => {
    expect(statementTarget("CREATE TABLE public.api_keys (org_id uuid references public.organizations (id))")).toBe(
      "api_keys",
    );
    expect(statementTarget('create policy "x" on public.orgs for select using (true)')).toBe("orgs");
    expect(statementTarget("GRANT SELECT ON TABLE public.webhooks TO anon")).toBe("webhooks");
    expect(statementTarget('alter table only "My Table" enable row level security')).toBe("My Table");
    // control: a DO block has no single target, so every name in it still counts
    expect(statementTarget("do $$ begin perform 1; end $$")).toBeUndefined();
  });
});

describe("audit of repos the probe used to give up on", () => {
  let repo = "";
  beforeAll(async () => {
    repo = await mkdtemp(join(tmpdir(), "mt-shapes-"));
    await cp("test/fixtures/team-workspace-app", repo, { recursive: true });
    const dir = join(repo, "supabase/migrations");
    // a profiles table used in the first migration but created in the second, as in one of the five repos
    await writeFile(
      join(dir, "20261116080000_early.sql"),
      `create table public.notes (id uuid primary key default gen_random_uuid(), author_id uuid not null references public.profiles (id), body text);
       create table public.invites_admin (id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations (id), role text not null default 'member');`,
    );
    await writeFile(
      join(dir, "20261116090700_feature_flags.sql"),
      `create table public.feature_flags (key text primary key, enabled boolean not null default false);
       alter table public.feature_flags enable row level security;
       create policy "Allow all on feature_flags" on public.feature_flags for all using (true);`,
    );
    await writeFile(
      join(dir, "20261116090600_org_invites.sql"),
      `create table public.org_invites (id uuid primary key default gen_random_uuid(),
         organization_id uuid not null references public.organizations (id), email text not null, role text not null default 'member');
       alter table public.org_invites enable row level security;
       create policy "Owners edit invites" on public.org_invites for update to authenticated
         using (exists (select 1 from public.organization_members m where m.organization_id = org_invites.organization_id
                        and m.user_id = (select auth.uid()) and m.role = 'owner'));`,
    );
  }, 60_000);
  afterAll(async () => {
    if (repo) await rm(repo, { recursive: true, force: true });
  });

  it("loads migrations that do not run in order statement by statement, and probes the tables that loaded", async () => {
    const out = await audit({ repo, now: new Date("2026-11-16T09:00:00Z"), npmAudit: false });
    const probeTool = out.tools.find((t) => t.name === "rls-probe");
    expect(probeTool?.status).toBe("ok");
    expect(probeTool?.note).toMatch(/statement by statement/);
    // the organization tables still loaded (the early file sorts first and fails, it is not about them)
    expect(out.probe?.map((p) => p.table)).toContain("public.organization_members");
    expect(out.findings.find((f) => f.subject === "public.organization_members")?.severity).toBe("critical");
    // An owner-only update policy on a table with a role column: the static rule reads "users edit their own
    // role", the probe's plain member was refused, so it is not reported. The organizations one leaked: kept.
    expect(out.findings.filter((f) => f.subject === "public.org_invites")).toEqual([]);
    expect(probeTool?.note).toMatch(/`public\.org_invites`\); not reported/);
    expect(out.findings.find((f) => f.subject === "public.organizations")?.rule).toBe("rls-update-privileged-column");
    // Shared data anyone could write: the patch keeps the read and drops the writes, and the re-probe agrees.
    const flags = out.findings.find((f) => f.subject === "public.feature_flags");
    expect(flags?.patch?.verified).toBe(true);
    expect(flags?.patch?.diff).toMatch(/for select\n\+ {2}to public\n\+ {2}using \(true\)/);
    const matrix = out.probe?.find((p) => p.table === "public.feature_flags");
    expect(matrix?.leaks.map((c) => c.action)).toContain("insert");
    expect(matrix?.afterPatches).toEqual([]);
  }, 180_000);
});

const APP = "test/fixtures/team-workspace-app";
interface Target {
  id: string;
  target: { object: string; file: string };
}
const truth = JSON.parse(await readFile("test/fixtures/team-workspace-app.holes.json", "utf8")) as {
  holes: Target[];
  controls: Target[];
};

function about(f: Finding, t: Target): boolean {
  if (f.location.kind !== "file" || f.location.file !== t.target.file) return false;
  if (!t.target.object.startsWith("public.")) return true;
  return f.subject === t.target.object || f.evidence.includes(`\`${t.target.object}`);
}

let result: AuditResult;
let patched = "";

beforeAll(async () => {
  result = await audit({ repo: APP, now: new Date("2026-11-16T09:00:00Z"), npmAudit: false });
  patched = await mkdtemp(join(tmpdir(), "patched-team-"));
  await cp(APP, patched, { recursive: true });
  const applied = new Set<string>();
  for (const finding of result.findings) {
    // a second finding on the same table shares the first one's patch
    if (!finding.patch || applied.has(finding.patch.diff)) continue;
    applied.add(finding.patch.diff);
    const file = join(patched, `${finding.id}.diff`);
    await writeFile(file, finding.patch.diff);
    const done = await run("git", ["apply", file], { cwd: patched });
    if (done.code !== 0) throw new Error(`${finding.id} did not apply: ${done.stderr}`);
    await rm(file);
  }
}, 180_000);

afterAll(async () => {
  if (patched) await rm(patched, { recursive: true, force: true });
});

describe("audit of the B2B team workspace fixture", () => {
  it("finds every seeded hole", () => {
    expect(truth.holes.filter((h) => !result.findings.some((f) => about(f, h))).map((h) => h.id)).toEqual([]);
  });

  it("flags no control at Medium or above", () => {
    const flagged = truth.controls.filter((c) =>
      result.findings.some(
        (f) =>
          about(f, c) && SEVERITY_RANK[f.severity] >= SEVERITY_RANK.medium && !truth.holes.some((h) => about(f, h)),
      ),
    );
    expect(flagged.map((c) => c.id)).toEqual([]);
  });

  it("rates self-join Critical and names the organization holes in organization terms", () => {
    const byTable = (t: string) => result.findings.find((f) => f.subject === t);
    expect(byTable("public.organization_members")).toMatchObject({
      severity: "critical",
      title: "Any signed-in user can join another organization",
    });
    expect(byTable("public.organizations")?.title).toBe(
      "Plain members can change their own role or the organization's billing fields",
    );
    expect(byTable("public.projects")).toMatchObject({ source: "rls-probe", severity: "high" });
    expect(byTable("public.invitations")?.title).toBe("One organization can reach another organization's rows");
    // the view has no security_invoker and exposes organization_id: a visitor reads organization A's row
    expect(byTable("public.org_usage")?.severity).toBe("critical");
    expect(result.counts).toEqual({ critical: 2, high: 3, medium: 0, low: 0 });
  });

  it("has a verified patch for every Critical and High finding and closes every leak in the same harness", () => {
    const serious = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high);
    expect(serious.filter((f) => !f.patch?.verified).map((f) => f.id)).toEqual([]);
    expect((result.probe ?? []).filter((p) => p.leaks.length).map((p) => p.table)).toEqual([
      "public.invitations",
      "public.org_usage",
      "public.organization_members",
      "public.organizations",
      "public.projects",
    ]);
    expect((result.probe ?? []).filter((p) => p.afterPatches?.length).map((p) => p.table)).toEqual([]);
  });

  it("keeps the plain member and the org admin reading their own organization after the patches", () => {
    const probe = result.probe ?? [];
    expect(probe.filter((p) => p.lockedOut).map((p) => p.table)).toEqual([]);
    for (const p of probe) {
      for (const a of p.afterAccess?.filter((x) => x.action === "select") ?? [])
        expect(a.rows, `${p.table} ${a.who}`).toBeGreaterThan(0);
    }
    const admin = probe
      .find((p) => p.table === "public.organizations")
      ?.afterAccess?.find((a) => a.who === "org-admin");
    expect(admin).toMatchObject({ rows: 1, of: 1 });
  });

  it("leaks nothing when probed again from the git-applied files", async () => {
    const dir = join(patched, "supabase/migrations");
    const migrations = [];
    for (const name of (await readdir(dir)).filter((n) => n.endsWith(".sql")).sort()) {
      migrations.push({ path: `supabase/migrations/${name}`, text: await readFile(join(dir, name), "utf8") });
    }
    const after = await probeRls(migrations);
    expect(after.error).toBeUndefined();
    expect(after.tables.flatMap((t) => leaks(t).map((c) => `${t.table}:${c.actor}:${c.action}`))).toEqual([]);
  });
});

/** The patched app still works for the people it is for: members, admins and the founder. */
describe("the patched team workspace in Postgres", () => {
  let db: PGlite;
  const [founder, member, outsider] = [
    "00000000-0000-4000-8000-0000000000f1",
    "00000000-0000-4000-8000-0000000000f2",
    "00000000-0000-4000-8000-0000000000f3",
  ];
  const as = async <T>(user: string, sql: string): Promise<T[]> =>
    db.transaction(async (tx) => {
      await tx.query(`select set_config('request.jwt.claims', $1, true)`, [
        JSON.stringify({ sub: user, role: "authenticated" }),
      ]);
      await tx.exec("set local role authenticated");
      return (await tx.query<T>(sql)).rows;
    });

  beforeAll(async () => {
    db = await PGlite.create();
    await db.exec(await readFile(SHIM_PATH, "utf8"));
    const dir = join(patched, "supabase/migrations");
    for (const name of (await readdir(dir)).filter((n) => n.endsWith(".sql")).sort()) {
      await db.exec(await readFile(join(dir, name), "utf8"));
    }
    await db.query(
      `insert into auth.users (id, email) values ($1, 'f@example.invalid'), ($2, 'm@example.invalid'), ($3, 'o@example.invalid')`,
      [founder, member, outsider],
    );
  }, 60_000);

  afterAll(async () => {
    await db?.close();
  });

  it("lets the founder create an organization and become its owner through the trigger", async () => {
    await as(
      founder,
      `insert into public.organizations (id, name, slug) values ('00000000-0000-4000-8000-0000000000aa', 'Org', 'org')`,
    );
    const rows = await as<{ role: string }>(founder, `select role::text from public.organization_members`);
    expect(rows).toEqual([{ role: "owner" }]);
  });

  it("lets the owner add a member, and the member work with projects", async () => {
    await as(
      founder,
      `insert into public.organization_members (organization_id, user_id) values ('00000000-0000-4000-8000-0000000000aa', '${member}')`,
    );
    await as(
      member,
      `insert into public.projects (organization_id, name) values ('00000000-0000-4000-8000-0000000000aa', 'Launch')`,
    );
    expect(await as(member, `select name from public.projects`)).toEqual([{ name: "Launch" }]);
  });

  it("keeps the outsider out and the member from promoting themselves", async () => {
    expect(await as(outsider, `select name from public.projects`)).toEqual([]);
    await expect(
      as(
        outsider,
        `insert into public.organization_members (organization_id, user_id) values ('00000000-0000-4000-8000-0000000000aa', '${outsider}')`,
      ),
    ).rejects.toThrow(/row-level security/);
    await as(member, `update public.organization_members set role = 'owner' where user_id = '${member}'`);
    expect(
      await as<{ role: string }>(
        founder,
        `select role::text from public.organization_members where user_id = '${member}'`,
      ),
    ).toEqual([{ role: "member" }]);
    await expect(as(member, `update public.organizations set plan = 'business'`)).rejects.toThrow(/permission denied/);
  });

  it("lets the owner rename the organization but not set the plan from the browser", async () => {
    await as(founder, `update public.organizations set name = 'Renamed'`);
    expect(await as(member, `select name from public.organizations`)).toEqual([{ name: "Renamed" }]);
    await expect(as(founder, `update public.organizations set plan = 'business'`)).rejects.toThrow(/permission denied/);
  });
});
