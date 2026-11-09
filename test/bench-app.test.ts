import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { run } from "../src/exec.ts";
import { runPreflight } from "../src/scanners/preflight.ts";
import type { AuditResult } from "../src/types.ts";

/**
 * The deliberately broken app from supabase-scanner-bench, with its ground truth. Holes are seeded
 * on purpose; controls are done right and must not be flagged.
 */
const APP = "test/fixtures/broken-notes-app";
interface Target {
  id: string;
  target: { file: string };
}
const truth = JSON.parse(await readFile("test/fixtures/broken-notes-app.holes.json", "utf8")) as {
  holes: Target[];
  controls: Target[];
};

let result: AuditResult;
let patched = "";

beforeAll(async () => {
  result = await audit({ repo: APP, now: new Date("2026-11-09T09:00:00Z") });
  patched = await mkdtemp(join(tmpdir(), "patched-app-"));
  await cp(APP, patched, { recursive: true });
  for (const finding of result.findings) {
    if (!finding.patch) continue;
    const file = join(patched, `${finding.id}.diff`);
    await writeFile(file, finding.patch.diff);
    const applied = await run("git", ["apply", file], { cwd: patched });
    if (applied.code !== 0) throw new Error(`${finding.id} did not apply: ${applied.stderr}`);
    await rm(file);
  }
});

afterAll(async () => {
  if (patched) await rm(patched, { recursive: true, force: true });
});

const files = (r: AuditResult) => r.findings.flatMap((f) => (f.location.kind === "file" ? [f.location.file] : []));

describe("audit of the broken bench app", () => {
  it("finds every seeded hole", () => {
    const missed = truth.holes.filter((h) => !files(result).includes(h.target.file)).map((h) => h.id);
    expect(missed).toEqual([]);
  });

  it("flags none of the controls", () => {
    const flagged = truth.controls.filter((c) => files(result).includes(c.target.file)).map((c) => c.id);
    expect(flagged).toEqual([]);
  });

  it("rates the findings with the rubric", () => {
    expect(result.counts).toEqual({ critical: 7, high: 3, medium: 1, low: 1 });
  });

  it("has a patch that passes git apply --check for every Critical and High finding", () => {
    const serious = result.findings.filter((f) => f.severity === "critical" || f.severity === "high");
    expect(serious.filter((f) => !f.patch?.verified).map((f) => f.id)).toEqual([]);
  });

  it("never copies a secret value into the report", () => {
    expect(JSON.stringify(result)).not.toMatch(/sk_live_[0-9A-Za-z]{20}/);
  });
});

describe("the bench app after applying every patch", () => {
  it("passes vibe-preflight with no errors left", async () => {
    const { findings } = await runPreflight(patched);
    expect(findings.filter((f) => f.toolSeverity === "error")).toEqual([]);
    // Left on purpose: feature_flags and the patched audit_log have RLS on and no policies, the safe
    // deny-all state (Low). Policies there depend on what the browser should see, so no patch writes them.
    expect(findings.map((f) => [f.rule, f.subject])).toEqual([
      ["rls-no-policy", "public.audit_log"],
      ["rls-no-policy", "public.feature_flags"],
    ]);
  });

  describe("in Postgres (PGlite with a Supabase shim)", () => {
    let db: PGlite;
    const one = async <T>(sql: string): Promise<T> => (await db.query<T>(sql)).rows[0] as T;
    const user = (id: string) =>
      db.exec(
        `set role authenticated; select set_config('request.jwt.claims', '{"sub":"${id}","role":"authenticated"}', false);`,
      );

    beforeAll(async () => {
      db = await PGlite.create();
      await db.exec(await readFile("test/fixtures/supabase-shim.sql", "utf8"));
      const dir = join(patched, "supabase/migrations");
      for (const name of (await readdir(dir)).filter((n) => n.endsWith(".sql")).sort()) {
        await db.exec(await readFile(join(dir, name), "utf8"));
      }
      await db.exec(`
        insert into auth.users (id, email) values
          ('00000000-0000-0000-0000-00000000000a', 'a@example.invalid'),
          ('00000000-0000-0000-0000-00000000000b', 'b@example.invalid'),
          ('00000000-0000-0000-0000-00000000000c', 'c@example.invalid');
        insert into public.messages (sender_id, recipient_id, body) values
          ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b', 'private');
        insert into public.audit_log (action) values ('sign-in');
      `);
    });

    afterAll(async () => {
      await db?.close();
    });

    it("hides audit_log from anon (RLS on, no policies)", async () => {
      await db.exec("set role anon");
      expect(await one<{ n: number }>("select count(*)::int as n from public.audit_log")).toEqual({ n: 0 });
      await db.exec("reset role");
    });

    it("lets only the two people in a conversation read it", async () => {
      await user("00000000-0000-0000-0000-00000000000c");
      expect(await one<{ n: number }>("select count(*)::int as n from public.messages")).toEqual({ n: 0 });
      await user("00000000-0000-0000-0000-00000000000b");
      expect(await one<{ n: number }>("select count(*)::int as n from public.messages")).toEqual({ n: 1 });
      await db.exec("reset role");
    });

    it("blocks a user from setting their own plan but not their display name", async () => {
      await user("00000000-0000-0000-0000-00000000000a");
      await expect(db.exec("update public.profiles set plan = 'pro'")).rejects.toThrow(/permission denied/);
      await expect(db.exec("update public.profiles set display_name = 'A'")).resolves.toBeDefined();
      await db.exec("reset role");
    });

    it("takes the admin RPC and the user directory away from the API roles", async () => {
      const rows = await db.query<{ ok: boolean }>(`
        select has_function_privilege(r, 'public.admin_set_plan(uuid, text)', 'execute') as ok from unnest(array['anon', 'authenticated']) r
        union all
        select has_table_privilege(r, 'public.user_directory', 'select') from unnest(array['anon', 'authenticated']) r`);
      expect(rows.rows.map((r) => r.ok)).toEqual([false, false, false, false]);
    });

    it("makes recent_notes a security_invoker view and the invoices bucket private", async () => {
      expect(await one("select reloptions from pg_class where oid = 'public.recent_notes'::regclass")).toEqual({
        reloptions: ["security_invoker=true"],
      });
      expect(await one("select public from storage.buckets where id = 'invoices'")).toEqual({ public: false });
      expect(
        await one<{ n: number }>(
          "select count(*)::int as n from pg_policies where policyname = 'Anyone can list invoices'",
        ),
      ).toEqual({ n: 0 });
    });

    it("pins the search_path of get_message_stats", async () => {
      expect(await one("select proconfig from pg_proc where proname = 'get_message_stats'")).toEqual({
        proconfig: ['search_path=""'],
      });
    });
  });
});
