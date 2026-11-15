import { describe, expect, it } from "vitest";
import { probeLeak, weakPolicies } from "../src/patches/fixers.ts";
import type { Finding } from "../src/types.ts";
import { leaks, probeRls, type TableProbe } from "../src/probe/rls-probe.ts";
import { toProof } from "../src/scanners/rls-probe.ts";

/** One owned table with the given policy lines, probed on its own. */
async function probe(sql: string): Promise<TableProbe[]> {
  const result = await probeRls([{ path: "supabase/migrations/1_test.sql", text: sql }]);
  if (result.error) throw new Error(result.error);
  return result.tables;
}

const OWNED = `create table public.items (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id),
  title text not null
);`;

const summary = (table: TableProbe | undefined) =>
  table ? leaks(table).map((c) => `${c.actor}:${c.action}${c.column ? `:${c.column}` : ""}`) : [];

describe("RLS probe", () => {
  it("lets everyone do everything on a table with RLS off", async () => {
    const [items] = await probe(OWNED);
    expect(items?.ownerColumns).toEqual(["owner_id"]);
    expect(summary(items)).toEqual([
      "anon:select",
      "anon:insert",
      "anon:update",
      "anon:delete",
      "other-user:select",
      "other-user:insert",
      "other-user:update",
      "other-user:delete",
    ]);
  });

  it("finds nothing on owner-scoped policies", async () => {
    const [items] = await probe(`${OWNED}
      alter table public.items enable row level security;
      create policy "own" on public.items for all to authenticated
        using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);`);
    expect(summary(items)).toEqual([]);
    // the probe really ran: every try came back empty or refused
    expect(items?.checks.filter((c) => c.action === "insert").every((c) => c.refused)).toBe(true);
  });

  it("catches a policy that checks the role instead of the owner", async () => {
    const [items] = await probe(`${OWNED}
      alter table public.items enable row level security;
      create policy "signed in" on public.items for select using (auth.role() = 'authenticated');`);
    expect(summary(items)).toEqual(["other-user:select"]);
    expect(weakPolicies(toProof(items as TableProbe)).map((p) => p.name)).toEqual(["signed in"]);
  });

  it("catches an insert check that only asks for a session", async () => {
    const [items] = await probe(`${OWNED}
      alter table public.items enable row level security;
      create policy "log" on public.items for insert to authenticated with check (auth.uid() is not null);`);
    expect(summary(items)).toEqual(["other-user:insert"]);
  });

  it("treats an open read on shared data as fine and an open write as a leak", async () => {
    const tables = await probe(`
      create table public.prices (id text primary key, cents int not null);
      alter table public.prices enable row level security;
      create policy "read" on public.prices for select using (true);
      create table public.banners (id int primary key, body text);
      alter table public.banners enable row level security;
      create policy "read" on public.banners for select using (true);
      create policy "write" on public.banners for update using (true);`);
    const byName = new Map(tables.map((t) => [t.table, t]));
    expect(byName.get("public.prices")?.ownerColumns).toEqual([]);
    expect(summary(byName.get("public.prices"))).toEqual([]);
    expect(summary(byName.get("public.banners"))).toEqual(["anon:update", "other-user:update"]);
  });

  it("sees a user change their own plan unless a column grant stops it", async () => {
    const profiles = `create table public.profiles (
        id uuid primary key references auth.users (id), name text, plan text not null default 'free');
      alter table public.profiles enable row level security;
      create policy "read own" on public.profiles for select to authenticated using (auth.uid() = id);
      create policy "own" on public.profiles for update to authenticated using (auth.uid() = id);`;
    const [open] = await probe(profiles);
    expect(summary(open)).toEqual(["owner:update:plan"]);
    const [locked] = await probe(`${profiles}
      revoke update on public.profiles from anon, authenticated;
      grant update (name) on public.profiles to authenticated;`);
    expect(summary(locked)).toEqual([]);
    expect(locked?.checks.find((c) => c.column === "plan")?.refused).toMatch(/permission denied/);
  });

  it("seeds child rows after their parents", async () => {
    const tables = await probe(`${OWNED}
      create table public.comments (
        id bigint generated always as identity primary key,
        item_id uuid not null references public.items (id),
        author_id uuid not null references auth.users (id),
        body text not null);`);
    const comments = tables.find((t) => t.table === "public.comments");
    expect(comments?.skipped).toBeUndefined();
    expect(comments?.checks.find((c) => c.actor === "anon" && c.action === "select")).toMatchObject({ rows: 1, of: 1 });
  });

  it("reports a migration Postgres cannot load instead of guessing", async () => {
    const result = await probeRls([{ path: "supabase/migrations/1_bad.sql", text: "create extension postgis;" }]);
    expect(result.tables).toEqual([]);
    expect(result.error).toMatch(/^supabase\/migrations\/1_bad\.sql did not load in PGlite/);
  });

  // Regressions from the independent review (2026-11-15): each of these gave a wrong answer before.

  it("sees an open insert on a table with a unique text column (fresh values, not a duplicate-key 'block')", async () => {
    const [coupons] = await probe(`
      create table public.coupons (id uuid primary key default gen_random_uuid(), code text not null unique, cents int);
      alter table public.coupons enable row level security;
      create policy "add" on public.coupons for insert with check (true);`);
    expect(summary(coupons)).toEqual(["anon:insert", "other-user:insert"]);
  });

  it("sees an open insert when the owner column is the primary key", async () => {
    const [settings] = await probe(`
      create table public.settings (user_id uuid primary key references auth.users (id), theme text);
      alter table public.settings enable row level security;
      create policy "add" on public.settings for insert with check (true);`);
    expect(summary(settings)).toEqual(["anon:insert", "other-user:insert"]);
  });

  it("records a try that breaks a constraint as inconclusive, never as blocked", async () => {
    const [items] = await probe(`${OWNED}
      alter table public.items enable row level security;
      create policy "add" on public.items for insert with check (true);
      create policy "own" on public.items for select to authenticated using (auth.uid() = owner_id);
      create function public.validate() returns trigger language plpgsql as $$
      begin
        if current_user <> 'postgres' then raise exception 'title failed validation' using errcode = '23514'; end if;
        return new;
      end $$;
      create trigger validate before insert on public.items for each row execute function public.validate();`);
    const inserts = items?.checks.filter((c) => c.action === "insert") ?? [];
    expect(inserts.map((c) => [c.rows, Boolean(c.inconclusive), Boolean(c.refused)])).toEqual([
      [0, true, false],
      [0, true, false],
    ]);
  });

  it("treats a child row as its parent owner's and closes the leak with a patch through the parent", async () => {
    const sql = `
      create table public.projects (id uuid primary key default gen_random_uuid(), owner_id uuid not null references auth.users (id), name text not null);
      alter table public.projects enable row level security;
      create policy "own" on public.projects for all to authenticated using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
      create table public.messages (id uuid primary key default gen_random_uuid(), project_id uuid not null references public.projects (id), body text not null);
      alter table public.messages enable row level security;
      create policy "read" on public.messages for select using (true);`;
    const tables = await probe(sql);
    const messages = tables.find((t) => t.table === "public.messages");
    expect(messages?.ownedVia).toMatchObject({
      column: "project_id",
      parent: "public.projects",
      parentOwners: ["owner_id"],
    });
    expect(summary(messages)).toEqual(["anon:select", "other-user:select"]);

    const proof = toProof(messages as TableProbe);
    const ctx = { newMigration: () => "supabase/migrations/2_fix.sql" } as never;
    const draft = await probeLeak({ id: "PA-01", proof } as Finding, ctx);
    const fix = draft?.edits[0]?.after ?? "";
    expect(fix).toContain("exists (");
    const after = await probeRls([
      { path: "supabase/migrations/1_test.sql", text: sql },
      { path: "supabase/migrations/2_fix.sql", text: fix },
    ]);
    const fixed = after.tables.find((t) => t.table === "public.messages");
    expect(summary(fixed)).toEqual([]);
    // the owner still reads their own project's messages through the new policy
    expect(fixed?.checks.every((c) => !c.inconclusive)).toBe(true);
  });

  it("does not call a plan change through when a trigger blocks it, and finds one a check constraint allows", async () => {
    const base = `create table public.profiles (
        id uuid primary key references auth.users (id), plan text not null default 'free' check (plan in ('free', 'pro')));
      alter table public.profiles enable row level security;
      create policy "read own" on public.profiles for select to authenticated using (auth.uid() = id);
      create policy "own" on public.profiles for update to authenticated using (auth.uid() = id);
      insert into public.profiles (id) select id from auth.users;`;
    const [open] = await probe(base);
    expect(summary(open)).toEqual(["owner:update:plan"]);
    const [guarded] = await probe(`${base}
      create function public.keep_plan() returns trigger language plpgsql as $$
      begin
        if new.plan is distinct from old.plan and current_user <> 'postgres' then raise exception 'plan is read-only'; end if;
        return new;
      end $$;
      create trigger keep_plan before update on public.profiles for each row execute function public.keep_plan();`);
    expect(summary(guarded)).toEqual([]);
    expect(guarded?.checks.find((c) => c.column === "plan")?.refused).toMatch(/read-only/);
  });

  it("probes a table whose name has a dot in it", async () => {
    const tables = await probe(`create table public."my.items" (id uuid primary key default gen_random_uuid(),
      owner_id uuid not null references auth.users (id));`);
    expect(tables.map((t) => [t.table, summary(t).length > 0])).toEqual([["public.my.items", true]]);
  });

  it("loads migrations that use common extensions, pg_cron and the realtime publication", async () => {
    const result = await probeRls([
      {
        path: "supabase/migrations/1_ext.sql",
        text: `create extension if not exists "uuid-ossp" with schema extensions;
          create extension if not exists pgcrypto with schema extensions;
          create extension if not exists pg_cron;
          create table public.notes (id uuid primary key default extensions.uuid_generate_v4(),
            user_id uuid not null references auth.users (id), body text);
          alter publication supabase_realtime add table public.notes;
          select cron.schedule('cleanup', '0 3 * * *', 'delete from public.notes where false');
          grant select on public.notes to supabase_auth_admin;`,
      },
    ]);
    expect(result.error).toBeUndefined();
    expect(result.skippedExtensions).toEqual(["pg_cron"]);
    expect(result.tables.map((t) => t.table)).toEqual(["public.notes"]);
  });
});
