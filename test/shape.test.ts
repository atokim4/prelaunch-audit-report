import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applies, unifiedDiff } from "../src/patches/diff.ts";
import { FIXERS } from "../src/patches/fixers.ts";
import { fixContext } from "../src/patches/index.ts";
import { listFiles } from "../src/files.ts";
import { detectShape, edgeConfigFindings, verifyJwtSettings } from "../src/shape.ts";
import type { Finding } from "../src/types.ts";

async function shapeOf(repo: string) {
  const ctx = await fixContext(repo, await listFiles(repo, false), new Date("2026-11-15T09:00:00Z"));
  return { ctx, shape: await detectShape(ctx.files, ctx.read) };
}

describe("project shape", () => {
  it("reads verify_jwt per function and ignores other tables", () => {
    const toml = `[api]\nverify_jwt = true\n\n[functions.hook]\nverify_jwt = false # Stripe\n\n[functions."other-fn"]\nverify_jwt = true\n[db]\nport = 1`;
    expect([...verifyJwtSettings(toml)]).toEqual([
      ["hook", false],
      ["other-fn", true],
    ]);
  });

  it("tells a Next.js App Router repo from a Vite SPA", async () => {
    expect((await shapeOf("test/fixtures/broken-notes-app")).shape).toMatchObject({
      framework: "next-app-router",
      edgeFunctions: [],
    });
    expect((await shapeOf("test/fixtures/pipeline-crm-app")).shape).toMatchObject({
      framework: "vite-react",
      label: "Vite + React single-page app",
      migrations: 7,
    });
  });
});

describe("Stripe webhook behind the JWT gate", () => {
  it("is flagged only once the function checks the signature, and the patch turns the gate off", async () => {
    const dir = await mkdtemp(join(tmpdir(), "jwt-gate-"));
    try {
      await cp("test/fixtures/pipeline-crm-app", dir, { recursive: true });
      const unverified = await shapeOf(dir);
      expect(await edgeConfigFindings(unverified.shape, unverified.ctx.read)).toEqual([]); // the unsigned one is a different, worse finding

      await writeFile(
        join(dir, "supabase/functions/stripe-webhook/index.ts"),
        'Deno.serve(async (req) => {\n  const sig = req.headers.get("stripe-signature");\n  await stripe.webhooks.constructEventAsync(await req.text(), sig!, "");\n  return new Response("ok");\n});\n',
      );
      await writeFile(
        join(dir, "supabase/config.toml"),
        'project_id = "x"\n\n[functions.stripe-webhook]\nverify_jwt = true\n',
      );
      const { ctx, shape } = await shapeOf(dir);
      const raws = await edgeConfigFindings(shape, ctx.read);
      expect(raws.map((r) => [r.rule, r.subject, r.location])).toEqual([
        ["stripe-webhook-jwt-gate", "stripe-webhook", { kind: "file", file: "supabase/config.toml", line: 3 }],
      ]);

      const fixer = FIXERS["stripe-webhook-jwt-gate"];
      const draft = fixer && (await fixer({ id: "PA-01", subject: "stripe-webhook" } as Finding, ctx));
      expect(draft?.edits[0]?.after).toBe('project_id = "x"\n\n[functions.stripe-webhook]\nverify_jwt = false\n');
      const diff = await unifiedDiff(draft?.edits ?? []);
      expect(await applies(dir, draft?.edits ?? [], diff)).toBe(true);

      // a quoted table name is the same TOML table: the fixer edits it instead of adding a duplicate
      await writeFile(join(dir, "supabase/config.toml"), '[functions."stripe-webhook"]\nverify_jwt = true\n');
      const quoted = await shapeOf(dir);
      expect((await edgeConfigFindings(quoted.shape, quoted.ctx.read)).map((r) => r.location)).toEqual([
        { kind: "file", file: "supabase/config.toml", line: 1 },
      ]);
      const requoted = fixer && (await fixer({ id: "PA-01", subject: "stripe-webhook" } as Finding, quoted.ctx));
      expect(requoted?.edits[0]?.after).toBe('[functions."stripe-webhook"]\nverify_jwt = false\n');

      await writeFile(join(dir, "supabase/config.toml"), 'project_id = "x"\n');
      const fresh = await shapeOf(dir); // ctx caches reads, so the rewritten config needs a new one
      const appended = fixer && (await fixer({ id: "PA-01", subject: "stripe-webhook" } as Finding, fresh.ctx));
      expect(appended?.edits[0]?.after).toBe('project_id = "x"\n\n[functions.stripe-webhook]\nverify_jwt = false\n');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
