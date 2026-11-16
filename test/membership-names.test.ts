import { readFile } from "node:fs/promises";
import { beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { leaks, probeRls, type TableProbe } from "../src/probe/rls-probe.ts";
import { detectTenancy, type TenancyTable } from "../src/probe/tenancy.ts";
import { SEVERITY_RANK, type AuditResult } from "../src/types.ts";

/**
 * Membership tables named something other than *_members (org_people, workspace_users, team_members) and
 * roles held in a separate lookup table (role_id -> roles.name). workspace-roles-app is the deliberately
 * broken fixture for the second case; its holes file is the ground truth.
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
const to = (name: string) => ({ parent: { name, column: "id" } });

describe("membership tables with other names", () => {
  it.each([
    ["orgs", "org_people", "person_id"],
    ["workspaces", "workspace_users", "user_id"],
    ["teams", "team_members", "member_id"],
    ["accounts", "account_collaborators", "user_id"],
  ])("%s + %s", (tenant, members, user) => {
    const t = detectTenancy([
      table(tenant, [col("id")]),
      table(members, [col("tenant_ref", to(tenant)), col(user, { user: true })], [user]),
    ]);
    expect(t?.tenant).toBe(`public.${tenant}`);
    expect(t?.members.table).toBe(`public.${members}`);
    expect(t?.members.userColumn).toBe(user);
  });

  it("control: a people table that links to something that is not an organization is not a membership", () => {
    const t = detectTenancy([
      table("chairs", [col("id")]),
      table("people", [col("default_chair", to("chairs")), col("user_id", { user: true })], ["user_id"]),
    ]);
    expect(t).toBeUndefined();
  });
});

describe("roles in a separate table", () => {
  const roles = (extra: TenancyTable["columns"] = []) =>
    table("roles", [col("id", { type: "smallint" }), col("name", { type: "text" }), ...extra]);
  const members = table(
    "workspace_users",
    [
      col("workspace_id", to("workspaces")),
      col("user_id", { user: true }),
      col("role_id", { type: "smallint", ...to("roles") }),
    ],
    ["user_id"],
  );

  it("reads role_id -> roles.name as the role", () => {
    const t = detectTenancy([table("workspaces", [col("id")]), roles(), members]);
    expect(t?.members.roleColumn).toBe("role_id");
    expect(t?.members.roleTable).toEqual({ table: "public.roles", key: "id", label: "name" });
  });

  it("control: a roles table owned by each organization is not read as the app-wide role list", () => {
    const t = detectTenancy([
      table("workspaces", [col("id")]),
      roles([col("workspace_id", to("workspaces"))]),
      members,
    ]);
    expect(t?.members.roleTable).toBeUndefined();
    expect(t?.members.roleColumn).toBeUndefined();
  });
});

const ORG_PEOPLE = `
create table public.orgs (id uuid primary key default gen_random_uuid(), name text not null);
create table public.org_people (
  org_id uuid not null references public.orgs (id) on delete cascade,
  person_id uuid not null references auth.users (id),
  role text not null default 'member' check (role in ('admin', 'member')),
  primary key (org_id, person_id)
);
create table public.notes (id uuid primary key default gen_random_uuid(), org_id uuid not null references public.orgs (id), body text not null);
create table public.tasks (id uuid primary key default gen_random_uuid(), org_id uuid not null references public.orgs (id), title text not null);
create function public.in_org(o uuid) returns boolean language sql stable security definer set search_path = ''
  as $$ select exists (select 1 from public.org_people where org_id = o and person_id = (select auth.uid())) $$;
revoke execute on function public.in_org(uuid) from public, anon;
grant execute on function public.in_org(uuid) to authenticated;
alter table public.orgs enable row level security;
alter table public.org_people enable row level security;
alter table public.notes enable row level security;
alter table public.tasks enable row level security;
create policy "read org" on public.orgs for select to authenticated using (public.in_org(id));
create policy "read people" on public.org_people for select to authenticated using (public.in_org(org_id));
create policy "read notes" on public.notes for select to authenticated using (true);
create policy "read tasks" on public.tasks for select to authenticated using (public.in_org(org_id));
`;

describe("probe on org_people", () => {
  let tables: Map<string, TableProbe>;
  beforeAll(async () => {
    tables = await probe(ORG_PEOPLE);
  });

  it("finds the cross-organization read on notes", () => {
    expect(tables.get("notes")?.tenant?.members.table).toBe("public.org_people");
    expect(summary(tables.get("notes"))).toEqual(["other-user:select", "non-member:select"]);
  });

  it("control with a positive check: tasks leak nothing and the member still reads their own task", () => {
    const tasks = tables.get("tasks");
    expect(summary(tasks)).toEqual([]);
    expect(tasks?.access.find((a) => a.who === "owner" && a.action === "select")).toMatchObject({ rows: 1, of: 1 });
  });
});

/** The fixture's schema with the role lookup table renamed so it no longer reads as one. */
async function withoutRoleTable(): Promise<Map<string, TableProbe>> {
  const dir = "test/fixtures/workspace-roles-app/supabase/migrations";
  const sql = [
    await readFile(`${dir}/20261117090000_workspaces.sql`, "utf8"),
    await readFile(`${dir}/20261117090100_policies.sql`, "utf8"),
  ]
    .join("\n")
    .replace(/public\.roles\b/g, "public.access_levels");
  return probe(sql);
}

describe("workspace-roles-app (roles in a lookup table)", () => {
  let result: AuditResult;
  let holes: { holes: { id: string; target: { object: string } }[]; controls: { object: string }[] };
  beforeAll(async () => {
    result = await audit({
      repo: "test/fixtures/workspace-roles-app",
      now: new Date("2026-11-17T09:00:00Z"),
      npmAudit: false,
    });
    holes = JSON.parse(await readFile("test/fixtures/workspace-roles-app.holes.json", "utf8")) as typeof holes;
  });

  it("finds self-promotion through role_id and self-join on workspace_users (Critical)", () => {
    const f = result.findings.find((x) => x.subject === "public.workspace_users");
    expect(f?.severity).toBe("critical");
    const found = f?.proof?.leaks.map((l) => `${l.actor}:${l.action}:${l.column ?? l.scenario ?? ""}`);
    expect(found).toEqual(expect.arrayContaining(["owner:update:role_id", "other-user:insert:self-join"]));
  });

  it("finds the cross-workspace read on documents", () => {
    const f = result.findings.find((x) => x.subject === "public.documents");
    expect(SEVERITY_RANK[f?.severity ?? "low"]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it("flags no control at Medium or above", () => {
    for (const control of holes.controls) {
      const hits = result.findings.filter(
        (f) => f.subject === control.object && SEVERITY_RANK[f.severity] >= SEVERITY_RANK.medium,
      );
      expect(hits, control.object).toEqual([]);
    }
  });

  it("the role helper in the patch joins the roles table and names its admin labels", () => {
    const diff = result.findings.find((x) => x.subject === "public.workspace_users")?.patch?.diff ?? "";
    expect(diff).toContain("join public.roles r on r.id = m.role_id");
    expect(diff).toContain("array['owner', 'admin']");
  });

  it("after every verified patch: 0 leaks anywhere, and members still read their own rows", () => {
    const probed = result.probe ?? [];
    expect(probed.length).toBe(5);
    for (const p of probed) {
      expect(p.afterPatches, p.table).toEqual([]);
      expect(p.lockedOut, p.table).toBeUndefined();
      const read = p.afterAccess?.find((a) => a.who === "owner" && a.action === "select");
      if (p.table !== "public.roles") expect(read, p.table).toMatchObject({ rows: 1, of: 1 });
    }
    expect(
      result.findings.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high).every((f) => f.patch?.verified),
    ).toBe(true);
  });

  it("mutation: with the lookup table renamed, the role_id promotion is no longer found", async () => {
    const tables = await withoutRoleTable();
    const members = tables.get("workspace_users");
    // Still probed (the self-join is found either way), so the missing promotion is not a skipped table.
    expect(members?.skipped).toBeFalsy();
    expect(summary(members)).toContain("other-user:insert:self-join");
    expect(summary(members)).not.toContain("owner:update:role_id");
  });
});
