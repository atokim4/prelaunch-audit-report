import { describe, expect, it } from "vitest";
import { accessVerdict, lostAccess, probeRls, type TableProbe } from "../src/probe/rls-probe.ts";
import type { AccessCheck } from "../src/types.ts";

/**
 * "No leak" is only worth something when the legitimate user still gets in. These tests pin the positive
 * check: user A reading (and no-op updating) their own rows, a plain member reading their organization's
 * rows, an org admin reading their own organization, and the run failing when a patch takes that away.
 */

async function tables(sql: string): Promise<TableProbe[]> {
  const result = await probeRls([{ path: "supabase/migrations/1_test.sql", text: sql }]);
  if (result.error) throw new Error(result.error);
  return result.tables;
}

const OWNED = `create table public.items (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id),
  title text not null
);
alter table public.items enable row level security;`;

const OWN_POLICY = `create policy "own" on public.items for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);`;

const read = (t: TableProbe | undefined, who: AccessCheck["who"] = "owner") =>
  t?.access.find((a) => a.who === who && a.action === "select");

describe("positive access check", () => {
  it("calls an owner-scoped table protected because user A still reads their row", async () => {
    const [items] = await tables(`${OWNED}\n${OWN_POLICY}`);
    expect(read(items)).toMatchObject({ rows: 1, of: 1 });
    expect(items?.access.find((a) => a.action === "update")).toMatchObject({ rows: 1, of: 1 });
    expect(accessVerdict(items as TableProbe)).toBe("protected");
  });

  it("calls RLS with no policy locked (owner cannot read either), not protected (mutation of the case above)", async () => {
    const [items] = await tables(OWNED);
    expect(read(items)).toMatchObject({ rows: 0, of: 1 });
    expect(accessVerdict(items as TableProbe)).toBe("locked");
  });

  it("calls a policy that is false for everyone locked", async () => {
    const [items] = await tables(`${OWNED}
      create policy "nobody" on public.items for select to authenticated using (false);`);
    expect(accessVerdict(items as TableProbe)).toBe("locked");
  });

  it("calls a missing grant locked: the refusal is recorded, not read as protection", async () => {
    const [items] = await tables(`${OWNED}\n${OWN_POLICY}
      revoke select on public.items from authenticated;`);
    expect(read(items)?.refused).toMatch(/permission denied/);
    expect(accessVerdict(items as TableProbe)).toBe("locked");
  });

  it("keeps leak ahead of the positive check", async () => {
    const [items] = await tables(`${OWNED}
      create policy "all" on public.items for select using (true);`);
    expect(read(items)).toMatchObject({ rows: 1 });
    expect(accessVerdict(items as TableProbe)).toBe("leak");
  });

  it("checks the plain member and the other org's admin on organization tables", async () => {
    const schema = `
      create table public.organizations (id uuid primary key default gen_random_uuid(), name text not null);
      create table public.memberships (
        organization_id uuid not null references public.organizations (id) on delete cascade,
        user_id uuid not null references auth.users (id),
        role text not null default 'member' check (role in ('owner', 'admin', 'member')),
        primary key (organization_id, user_id)
      );
      create table public.projects (
        id uuid primary key default gen_random_uuid(),
        organization_id uuid not null references public.organizations (id),
        title text not null
      );
      alter table public.organizations enable row level security;
      alter table public.memberships enable row level security;
      alter table public.projects enable row level security;
      create function public.is_member(org uuid) returns boolean language sql security definer set search_path = ''
        as $$ select exists (select 1 from public.memberships m where m.organization_id = org and m.user_id = (select auth.uid())) $$;
      create policy "members read orgs" on public.organizations for select to authenticated using (public.is_member(id));
      create policy "members read members" on public.memberships for select to authenticated using (public.is_member(organization_id));
      create policy "members read projects" on public.projects for select to authenticated using (public.is_member(organization_id));`;
    const probed = await tables(schema);
    const byName = (n: string) => probed.find((t) => t.name === n);
    for (const name of ["organizations", "memberships"]) {
      expect(read(byName(name))?.rows, name).toBeGreaterThan(0);
      expect(read(byName(name), "org-admin")?.rows, name).toBeGreaterThan(0);
      expect(accessVerdict(byName(name) as TableProbe), name).toBe("protected");
    }
    expect(read(byName("projects"))).toMatchObject({ rows: 1, of: 1 });
    expect(accessVerdict(byName("projects") as TableProbe)).toBe("protected");

    // Mutation: the members policy on projects names the wrong column, so members lose their own org's rows.
    const broken = await tables(
      schema.replace(
        `on public.projects for select to authenticated using (public.is_member(organization_id))`,
        `on public.projects for select to authenticated using (public.is_member(id))`,
      ),
    );
    const projects = broken.find((t) => t.name === "projects");
    expect(read(projects)).toMatchObject({ rows: 0, of: 1 });
    expect(accessVerdict(projects as TableProbe)).toBe("locked");
  });

  it("is untested, not protected, when there are no rows of user A to try", () => {
    const empty: Pick<TableProbe, "checks" | "access" | "ownerColumns"> = {
      checks: [],
      access: [{ who: "owner", action: "select", rows: 0, of: 0 }],
      ownerColumns: ["owner_id"],
    };
    expect(accessVerdict(empty)).toBe("untested");
    expect(accessVerdict({ ...empty, ownerColumns: [] })).toBe("shared");
  });

  it("reports what a patch took away from the legitimate user", async () => {
    const [before] = await tables(`${OWNED}\n${OWN_POLICY}`);
    const [after] = await tables(`${OWNED}\n${OWN_POLICY}\ndrop policy "own" on public.items;`);
    const lost = lostAccess(before?.access ?? [], after?.access ?? []);
    expect(lost.map((a) => `${a.who}:${a.action}`)).toEqual(["owner:select", "owner:update"]);
    // Control: the same schema twice loses nothing.
    const [again] = await tables(`${OWNED}\n${OWN_POLICY}`);
    expect(lostAccess(before?.access ?? [], again?.access ?? [])).toEqual([]);
  });
});
