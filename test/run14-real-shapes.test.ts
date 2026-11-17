import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { supabaseEvidence } from "../src/probe/supabase-presence.ts";
import { filterUnverifiedWebhooks } from "../src/scanners/webhook-context.ts";
import { visibilityFlag } from "../src/scanners/rls-probe.ts";

/**
 * Shapes from the run-14 set: real repos with Stripe webhook fixes, audited at the parent commit of each fix.
 * Four of them are Prisma apps behind their own Express or Nest server; the probe used to run their
 * migrations as if they were a Supabase database and report 201 "a visitor changed user A's rows"
 * Criticals. A GitHub webhook route that stores a stripe_customer_id was read as an unverified Stripe webhook.
 */

const NOW = new Date("2026-11-17T09:00:00Z");

async function repo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "run14-"));
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), text);
  }
  return dir;
}

const PRISMA_MIGRATION = [
  'CREATE TABLE "Order" ("id" TEXT NOT NULL, "userId" TEXT NOT NULL, "total" INTEGER NOT NULL,',
  '  CONSTRAINT "Order_pkey" PRIMARY KEY ("id"));',
].join("\n");
const PRISMA_APP = {
  "package.json": JSON.stringify({ name: "orders-api", dependencies: { "@prisma/client": "6.0.0", express: "5.3.0" } }),
  "prisma/schema.prisma": 'datasource db {\n  provider = "postgresql"\n  url = env("DATABASE_URL")\n}\n',
  "prisma/migrations/20260101000000_init/migration.sql": PRISMA_MIGRATION,
  ".env.example": "DATABASE_URL=postgresql://user:pass@localhost:5432/orders\n",
};

describe("RLS probe only on a Supabase database", () => {
  it("a Prisma app with no Supabase anywhere: probe skipped, no rls-probe findings, said in 'not checked'", async () => {
    const dir = await repo(PRISMA_APP);
    try {
      const result = await audit({ repo: dir, now: NOW, npmAudit: false });
      expect(result.findings.filter((f) => f.rule.startsWith("rls-"))).toEqual([]);
      expect(result.tools.find((t) => t.name === "rls-probe")?.status).toBe("skipped");
      expect(result.notChecked.join(" ")).toContain("not a Supabase project");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("control: the same app with its DATABASE_URL on a Supabase host is probed and the open table reported", async () => {
    const dir = await repo({
      ...PRISMA_APP,
      ".env.example": "DATABASE_URL=postgresql://postgres:pass@db.abcdefghijklmnop.supabase.co:5432/postgres\n",
    });
    try {
      const result = await audit({ repo: dir, now: NOW, npmAudit: false });
      expect(result.tools.find((t) => t.name === "rls-probe")?.status).toBe("ok");
      expect(result.findings.some((f) => f.rule === "rls-probe-leak" || f.rule === "rls-disabled")).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  const read = (files: Record<string, string>) => async (p: string) => files[p];
  const sql = (text: string) => [{ path: "db/schema.sql", text }];

  it.each([
    ["a supabase/ folder", { "supabase/config.toml": "" }, ""],
    [
      "a @supabase dependency in a workspace",
      { "apps/web/package.json": '{"dependencies":{"@supabase/ssr":"1"}}' },
      "",
    ],
    ["auth.uid() in the SQL", {}, "create policy p on t using (auth.uid() = user_id);"],
    ["a grant to anon, public listed first", {}, "grant select on t to public, anon;"],
    ["a Supabase key name in .env.example", { ".env.example": "SUPABASE_URL=\n" }, ""],
    ["supabase-py in requirements.txt", { "requirements.txt": "fastapi\nsupabase==2.9.0\n" }, ""],
    [
      "a Deno import of supabase-js",
      { "fn/index.ts": 'import { createClient } from "npm:@supabase/supabase-js@2";' },
      "",
    ],
  ])("evidence: %s", async (_name, files: Record<string, string>, schema) => {
    expect(await supabaseEvidence(Object.keys(files), read(files), sql(schema))).toBeDefined();
  });

  it.each([
    ["RLS for app-level tenancy only", {}, "alter table t enable row level security;"],
    ["a script that lists supabase.co among email domains", { "scripts/clean.ts": "const d = ['supabase.co'];" }, ""],
    ["a role column named authenticated", {}, "create table t (authenticated boolean);"],
  ])("no evidence: %s", async (_name, files: Record<string, string>, schema) => {
    expect(await supabaseEvidence(Object.keys(files), read(files), sql(schema))).toBeUndefined();
  });
});

describe("an unverified-webhook finding on a file that handles no Stripe event", () => {
  const raw = (file: string) => ({
    source: "vibe-preflight" as const,
    rule: "stripe-webhook-unverified",
    toolSeverity: "error",
    message: "Handles Stripe events without `constructEvent`, so any POST is trusted.",
    location: { kind: "file" as const, file, line: 1 },
  });
  const github = [
    'import { NextResponse } from "next/server";',
    "export async function POST(req: Request) {",
    "  const body = await req.json();",
    '  if (req.headers.get("x-github-event") === "installation") {',
    '    await db.user.create({ data: { login: body.sender.login, stripe_customer_id: "" } });',
    "  }",
    "  return NextResponse.json({ ok: true });",
    "}",
  ].join("\n");
  const filter = (file: string, text: string) => filterUnverifiedWebhooks([raw(file)], [file], async () => text);

  it("a GitHub webhook that stores an empty stripe_customer_id is dropped, with a note", async () => {
    const r = await filter("src/app/api/webhooks/github/route.ts", github);
    expect(r.findings).toEqual([]);
    expect(r.notes.join(" ")).toContain("Webhooks of other services");
  });

  it.each([
    ["a Stripe event type", 'if (body.type === "checkout.session.completed") upgrade(body);'],
    ["the stripe SDK from esm.sh", 'import Stripe from "https://esm.sh/stripe@14?target=deno";'],
    ["the stripe SDK from npm:", 'import Stripe from "npm:stripe@19";'],
    ["require('stripe')", 'const Stripe = require("stripe");'],
  ])("control: a handler with %s keeps the finding", async (_name, line) => {
    const r = await filter("src/app/api/webhooks/stripe/route.ts", `${line}\n${github}`);
    expect(r.findings).toHaveLength(1);
  });
});

/** A Supabase project with an organizations table, its members, and the read policy under test. */
function orgRepo(readPolicy: string): Record<string, string> {
  return {
    "package.json": JSON.stringify({ name: "race-events", dependencies: { "@supabase/supabase-js": "2.0.0" } }),
    "supabase/migrations/20260101000000_orgs.sql": [
      "create table public.organizations (id uuid primary key default gen_random_uuid(), name text not null,",
      "  slug text not null unique, logo_url text, is_active boolean not null default true);",
      "create table public.org_members (org_id uuid not null references public.organizations(id),",
      "  user_id uuid not null references auth.users(id), role text not null default 'member',",
      "  primary key (org_id, user_id));",
      "alter table public.organizations enable row level security;",
      "alter table public.org_members enable row level security;",
      `create policy orgs_read_active on public.organizations for select using (${readPolicy});`,
      "create policy members_read_own on public.org_members for select using (user_id = auth.uid());",
    ].join("\n"),
  };
}

describe("a public organizer directory: read policy on an is_active flag (race-pace shape)", () => {
  const MEMBER = "id in (select org_id from public.org_members where user_id = auth.uid())";
  const orgs = async (policy: string) => {
    const dir = await repo(orgRepo(policy));
    try {
      const result = await audit({ repo: dir, now: NOW, npmAudit: false });
      return result.findings.filter(
        (f) => f.subject === "public.organizations" || f.evidence.includes("public.organizations"),
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  it("`using (is_active or member)` reads as a public listing: Low, with the flag named", async () => {
    const found = await orgs(`is_active or ${MEMBER}`);
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((f) => f.severity === "low")).toBe(true);
    expect(found.some((f) => f.evidence.includes("marked `is_active`"))).toBe(true);
  });

  it("control: `using (true or member)` on the same table keeps its full rating", async () => {
    const found = await orgs(`true or ${MEMBER}`);
    expect(found.some((f) => f.severity === "critical" || f.severity === "high")).toBe(true);
  });
});

describe("visibilityFlag", () => {
  const cols = ["id", "is_active", "status", "name"];
  it.each([
    ["(is_active OR (id IN ( SELECT 1)))", "is_active"],
    ["(is_active = true)", "is_active"],
    ["((status = 'published'::text) OR (auth.uid() IS NOT NULL))", "status = 'published'"],
  ])("%s -> %s", (using, flag) => {
    expect(visibilityFlag(using, cols)).toBe(flag);
  });
  it.each([["(is_active AND (id IN ( SELECT 1)))"], ["(published = true)"], ["((status = 'draft'::text))"], ["true"]])(
    "no flag: %s",
    (using) => {
      expect(visibilityFlag(using, cols)).toBeUndefined();
    },
  );
});

describe("table rules on SQL that never reaches the database", () => {
  const BASE = {
    "package.json": JSON.stringify({ name: "x", dependencies: { "@supabase/supabase-js": "2.0.0" } }),
    "supabase/migrations/20260101000000_init.sql":
      "create table public.notes (id uuid primary key, user_id uuid references auth.users(id));\nalter table public.notes enable row level security;\ncreate policy own on public.notes using (user_id = auth.uid());\n",
  };
  const rlsOff = async (files: Record<string, string>) => {
    const dir = await repo({ ...BASE, ...files });
    try {
      const result = await audit({ repo: dir, now: NOW, npmAudit: false });
      return { found: result.findings.filter((f) => f.rule === "rls-disabled"), notes: result.notChecked.join(" ") };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  it("a table in a QA runbook under docs/ is not 'RLS disabled'", async () => {
    const r = await rlsOff({
      "docs/operations/acceptance/check.sql": "create table public.qa_results(check_name text, result text);\n",
    });
    expect(r.found).toEqual([]);
    expect(r.notes).toContain("`public.qa_results`");
  });

  it("a temporary table inside a migration is not 'RLS disabled' either", async () => {
    const r = await rlsOff({
      "supabase/migrations/20260102000000_tmp.sql":
        "create temp table scratch_rows(id int);\ndrop table scratch_rows;\n",
    });
    expect(r.found.map((f) => f.subject)).not.toContain("public.scratch_rows");
  });

  it("control: a real table without RLS in a migration is still reported", async () => {
    const r = await rlsOff({
      "supabase/migrations/20260102000000_open.sql": "create table public.payouts (id int, amount int);\n",
    });
    expect(r.found.map((f) => f.subject)).toContain("public.payouts");
  });
});

describe("definer function granted to anon on purpose", () => {
  const fn = (returns: string, body: string) => ({
    "package.json": JSON.stringify({ name: "x", dependencies: { "@supabase/supabase-js": "2.0.0" } }),
    "supabase/migrations/20260101000000_fn.sql": [
      "create table public.user_roles (user_id uuid references auth.users(id), org_id uuid, role text);",
      "alter table public.user_roles enable row level security;",
      "create policy own on public.user_roles for select using (user_id = auth.uid());",
      `create or replace function public.can_check_in(p_org uuid) returns ${returns}`,
      `language sql stable security definer set search_path = '' as $$ ${body} $$;`,
      "grant execute on function public.can_check_in(uuid) to anon, authenticated;",
    ].join("\n"),
  });
  const rated = async (files: Record<string, string>) => {
    const dir = await repo(files);
    try {
      const result = await audit({ repo: dir, now: NOW, npmAudit: false });
      return result.findings.find((f) => f.rule === "definer-function-anon")?.severity;
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  it("returns a boolean about auth.uid(): Medium (a permission helper policies call)", async () => {
    const body = "select exists (select 1 from public.user_roles where user_id = auth.uid() and org_id = p_org)";
    expect(await rated(fn("boolean", body))).toBe("medium");
  });

  it("control: returns rows for the org: stays Critical", async () => {
    const body = "select * from public.user_roles where org_id = p_org and auth.uid() is not null";
    expect(await rated(fn("setof public.user_roles", body))).toBe("critical");
  });
});

describe("browser env vars that are settings or public by design", () => {
  const finding = (name: string) => ({
    source: "vibe-preflight" as const,
    rule: "public-env-secret",
    toolSeverity: "error",
    message: `\`${name}\` looks like a secret and is exposed to the browser.`,
    location: { kind: "file" as const, file: "src/env.ts", line: 1 },
    subject: name,
  });
  it("drops on/off flags and the VAPID public key, keeps real key names", async () => {
    const { filterPreflight } = await import("../src/scanners/preflight.ts");
    const names = [
      "VITE_DISABLE_LOGIN_WITH_PASSWORD",
      "NEXT_PUBLIC_VAPID_KEY",
      "VITE_PASSWORD_MIN_LENGTH",
      "VITE_OPENAI_API_KEY",
      "NEXT_PUBLIC_STRIPE_SECRET_KEY",
      "VITE_ADMIN_PASSWORD",
      "VITE_VAPID_PRIVATE_KEY",
    ];
    const r = await filterPreflight(names.map(finding), async () => "", /archive\//);
    expect(r.findings.map((f) => f.subject)).toEqual([
      "VITE_OPENAI_API_KEY",
      "NEXT_PUBLIC_STRIPE_SECRET_KEY",
      "VITE_ADMIN_PASSWORD",
      "VITE_VAPID_PRIVATE_KEY",
    ]);
    expect(r.notSecrets).toEqual([
      "NEXT_PUBLIC_VAPID_KEY",
      "VITE_DISABLE_LOGIN_WITH_PASSWORD",
      "VITE_PASSWORD_MIN_LENGTH",
    ]);
  });
});
