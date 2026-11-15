import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Stripe from "stripe";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fixContext } from "../src/patches/index.ts";
import { FIXERS } from "../src/patches/fixers.ts";
import { listFiles } from "../src/files.ts";
import type { Finding } from "../src/types.ts";

/**
 * Runs the bench app's Supabase Edge Function (Deno) in Node, before and after the generated patch.
 * The Deno-only imports are swapped for stand-ins: `serve` captures the handler, `createClient` records
 * the database update, `Deno.env` serves test values. Stripe is the real npm package, so the signature
 * check is Stripe's own code with a real HMAC.
 */
const APP = "test/fixtures/pipeline-crm-app";
const FUNCTION = "supabase/functions/stripe-webhook/index.ts";
const TMP = "test/.tmp";
const SECRET = ["whsec", "bench", "signing", "secret"].join("_"); // built at runtime: no key-shaped literal in the repo

type Handler = (req: Request) => Promise<Response>;
interface Harness {
  handler: Handler;
  updates: Record<string, unknown>[];
}

/** Swaps the Deno URL imports for Node stand-ins and loads the module, returning its request handler. */
async function load(source: string, name: string): Promise<Harness> {
  const updates: Record<string, unknown>[] = [];
  const g = globalThis as Record<string, unknown>;
  let handler: Handler | undefined;
  g.__benchServe = (h: Handler) => {
    handler = h;
  };
  g.__benchCreateClient = () => ({
    from: () => ({
      update: (values: Record<string, unknown>) => {
        updates.push(values);
        return { eq: async () => ({ error: null }) };
      },
    }),
  });
  const env: Record<string, string> = {
    SUPABASE_URL: "http://localhost:54321",
    SUPABASE_SERVICE_ROLE_KEY: "service-role-for-tests",
    STRIPE_SECRET_KEY: ["sk", "test", "bench"].join("_"),
    STRIPE_WEBHOOK_SECRET: SECRET,
  };
  g.Deno = { env: { get: (key: string) => env[key] } };

  const rewritten = source
    .replace(
      /^import \{ serve \} from "https:\/\/deno\.land\/[^"]+";$/m,
      "const serve = (globalThis as any).__benchServe;",
    )
    .replace(/^import Stripe from "(?:https:\/\/esm\.sh\/stripe|npm:stripe)[^"]*";$/m, 'import Stripe from "stripe";')
    .replace(
      /^import \{ createClient \} from "https:\/\/esm\.sh\/@supabase\/supabase-js[^"]*";$/m,
      "const createClient = (globalThis as any).__benchCreateClient;",
    );
  expect(rewritten).not.toMatch(/from "https:/);
  const file = join(TMP, `${name}.ts`);
  await writeFile(file, rewritten);
  await import(/* @vite-ignore */ `${join(process.cwd(), file)}?v=${Date.now()}`);
  if (!handler) throw new Error("the function never called serve()");
  return { handler, updates };
}

const completed = JSON.stringify({
  id: "evt_bench",
  object: "event",
  type: "checkout.session.completed",
  data: {
    object: { id: "cs_bench", object: "checkout.session", customer: "cus_bench", client_reference_id: "user-a" },
  },
});

const post = (body: string, headers: Record<string, string> = {}) =>
  new Request("http://localhost/functions/v1/stripe-webhook", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });

let original: Harness;
let patched: Harness;

beforeAll(async () => {
  await mkdir(TMP, { recursive: true });
  const before = await readFile(join(APP, FUNCTION), "utf8");
  const ctx = await fixContext(APP, await listFiles(APP, false), new Date("2026-11-15T09:00:00Z"));
  const finding = {
    id: "PA-02",
    rule: "stripe-webhook-unverified",
    location: { kind: "file", file: FUNCTION, line: 23 },
    evidence: "",
  } as unknown as Finding;
  const fixer = FIXERS["stripe-webhook-unverified"];
  const draft = fixer ? await fixer(finding, ctx) : undefined;
  if (!draft?.edits[0]) throw new Error("no Deno patch was generated");
  original = await load(before, "webhook-original");
  patched = await load(draft.edits[0].after, "webhook-patched");
});

afterAll(async () => {
  await rm(TMP, { recursive: true, force: true });
  delete (globalThis as Record<string, unknown>).Deno;
});

describe("Stripe webhook edge function (Deno)", () => {
  it("as written, upgrades the plan for an unsigned request", async () => {
    const res = await original.handler(post(completed));
    expect(res.status).toBe(200);
    expect(original.updates).toEqual([{ plan: "pro", stripe_customer_id: "cus_bench" }]);
  });

  it("after the patch, refuses a request with no signature", async () => {
    const res = await patched.handler(post(completed));
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing stripe-signature header");
  });

  it("after the patch, refuses a forged signature", async () => {
    const forged = Stripe.webhooks.generateTestHeaderString({ payload: completed, secret: `${SECRET}_wrong` });
    const res = await patched.handler(post(completed, { "stripe-signature": forged }));
    expect(res.status).toBe(400);
    expect(patched.updates).toEqual([]);
  });

  it("after the patch, accepts a correctly signed event on the raw body", async () => {
    const signature = Stripe.webhooks.generateTestHeaderString({ payload: completed, secret: SECRET });
    const res = await patched.handler(post(completed, { "stripe-signature": signature }));
    expect(res.status).toBe(200);
    expect(patched.updates).toEqual([{ plan: "pro", stripe_customer_id: "cus_bench" }]);
  });
});

describe("Deno webhook fixer on other import styles", () => {
  const fix = async (source: string) => {
    const dir = await mkdtemp(join(tmpdir(), "deno-import-"));
    try {
      await mkdir(join(dir, "supabase/functions/hook"), { recursive: true });
      await writeFile(join(dir, "supabase/functions/hook/index.ts"), source);
      const ctx = await fixContext(dir, await listFiles(dir, false), new Date("2026-11-15T09:00:00Z"));
      const finding = {
        id: "PA-01",
        rule: "stripe-webhook-unverified",
        location: { kind: "file", file: "supabase/functions/hook/index.ts", line: 1 },
        evidence: "",
      } as unknown as Finding;
      return (await FIXERS["stripe-webhook-unverified"]?.(finding, ctx))?.edits[0]?.after ?? "";
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };
  const body =
    "Deno.serve(async (req) => {\n  const event = await req.json();\n  return new Response(event.type);\n});\n";

  it("keeps a bare import-map import and adds no second Stripe import", async () => {
    const after = await fix(`import Stripe from "stripe";\n\n${body}`);
    expect(after.match(/^import Stripe/gm)).toHaveLength(1);
    expect(after).toContain("Stripe.createSubtleCryptoProvider()");
  });

  it("turns a type-only Stripe import into a value import", async () => {
    const after = await fix(`import type Stripe from "npm:stripe@19.3.1";\n\n${body}`);
    expect(after).toMatch(/^import Stripe from "npm:stripe@19\.3\.1";$/m);
    expect(after).not.toContain("import type Stripe");
    expect(after.match(/^import /gm)).toHaveLength(1);
  });
});
