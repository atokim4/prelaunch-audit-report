import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import Stripe from "stripe";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { run } from "../src/exec.ts";
import type { Finding } from "../src/types.ts";

/**
 * The Stripe webhook rules on the ways people write a webhook outside the App Router: Express (ESM and
 * CommonJS, app-wide `express.json()` before the route, a mounted router), Next.js pages/api, and
 * Supabase Edge Functions on `Deno.serve`. For each broken fixture: the audit finds it, the patch passes
 * `git apply --check` and then really applies to a copy, and the patched handler is run with real Stripe
 * signatures (Stripe's own npm package does the HMAC). Each patch is then broken on purpose, one piece at
 * a time, to show these requests would catch a patch that misses that piece. The two correct fixtures
 * (controls) must produce no webhook finding.
 */
const FIXTURES = "test/fixtures/webhooks";
const TMP = resolve("test/.tmp/webhooks");
const SECRET = ["whsec", "variants", "signing", "secret"].join("_"); // built at runtime: no key-shaped literal
const NOW = new Date("2026-11-17T09:00:00Z");

process.env.STRIPE_SECRET_KEY = ["sk", "test", "variants"].join("_");
process.env.STRIPE_WEBHOOK_SECRET = SECRET;

// Stripe sends pretty-printed JSON. Parsing and re-serialising it changes the bytes, which is the bug.
const payload = JSON.stringify(
  {
    id: "evt_variants",
    object: "event",
    type: "checkout.session.completed",
    data: { object: { id: "cs_variants", object: "checkout.session", client_reference_id: "user-a" } },
  },
  null,
  2,
);
const signed = (body = payload) => Stripe.webhooks.generateTestHeaderString({ payload: body, secret: SECRET });
const forged = () => Stripe.webhooks.generateTestHeaderString({ payload, secret: `${SECRET}_wrong` });

const webhookFindings = (findings: Finding[]) => findings.filter((f) => f.rule.startsWith("stripe-webhook-"));

/** Audits a fixture, applies the one webhook patch to a fresh copy with git apply, returns both texts. */
async function auditAndApply(name: string, file: string, rule: string) {
  const repo = join(FIXTURES, name);
  const result = await audit({ repo, now: NOW, npmAudit: false });
  const found = webhookFindings(result.findings);
  expect(found.map((f) => f.rule)).toEqual([rule]);
  const patch = found[0]?.patch;
  expect(patch?.verified).toBe(true);
  const copy = join(TMP, name);
  await rm(copy, { recursive: true, force: true });
  await cp(repo, copy, { recursive: true });
  await writeFile(join(copy, "fix.patch"), patch?.diff ?? "");
  // Its own repository: from inside the project's checkout, git apply would read the paths from the
  // project root and silently skip them.
  await run("git", ["init", "-q"], { cwd: copy });
  const applied = await run("git", ["apply", "fix.patch"], { cwd: copy });
  expect(applied.stderr).toBe("");
  expect(applied.code).toBe(0);
  return {
    finding: found[0] as Finding,
    dir: copy,
    before: await readFile(join(repo, file), "utf8"),
    after: await readFile(join(copy, file), "utf8"),
  };
}

/** Writes `source` next to the patched file under another name, so a mutant gets its own module. */
async function variant(dir: string, file: string, name: string, source: string): Promise<string> {
  const ext = file.slice(file.lastIndexOf("."));
  const path = join(dir, file.replace(/[^/]+$/, `${name}${ext}`));
  await writeFile(path, source);
  return path;
}

const servers: Server[] = [];
async function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}
const post = (url: string, headers: Record<string, string> = {}, body = payload) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });

beforeAll(() => mkdir(TMP, { recursive: true }));
afterAll(async () => {
  await Promise.all(servers.map((s) => new Promise((done) => s.close(done))));
  await rm(TMP, { recursive: true, force: true });
  delete (globalThis as Record<string, unknown>).Deno;
});

type ExpressApp = (req: IncomingMessage, res: ServerResponse) => void;
const loadEsm = async <T>(path: string): Promise<T> =>
  (await import(/* @vite-ignore */ `${path}?v=${Date.now()}`)) as T;

describe("Express, app-wide express.json() before an unverified route (TypeScript, ESM)", () => {
  const FILE = "src/server.ts";
  let after = "";
  let dir = "";
  let upgraded: string[] = [];
  let original = "";
  let patched = "";

  beforeAll(async () => {
    const r = await auditAndApply("express-global-json", FILE, "stripe-webhook-unverified");
    ({ after, dir } = r);
    expect(r.finding.severity).toBe("critical");
    ({ upgraded } = (await import(/* @vite-ignore */ join(dir, "src/billing.ts"))) as { upgraded: string[] });
    const loadApp = async (path: string) => listen((await loadEsm<{ app: ExpressApp }>(path)).app);
    original = await loadApp(await variant(dir, FILE, "original", r.before));
    patched = await loadApp(join(dir, FILE));
  });

  it("as written, upgrades the user for a forged, unsigned event", async () => {
    upgraded.length = 0;
    expect((await post(`${original}/api/stripe/webhook`)).status).toBe(200);
    expect(upgraded).toEqual(["user-a"]);
  });

  it("after the patch, refuses unsigned and forged events and accepts a signed one", async () => {
    upgraded.length = 0;
    expect((await post(`${patched}/api/stripe/webhook`)).status).toBe(400);
    expect((await post(`${patched}/api/stripe/webhook`, { "stripe-signature": forged() })).status).toBe(400);
    expect(upgraded).toEqual([]);
    expect((await post(`${patched}/api/stripe/webhook`, { "stripe-signature": signed() })).status).toBe(200);
    expect(upgraded).toEqual(["user-a"]);
  });

  it("after the patch, every other route still gets parsed JSON", async () => {
    const res = await post(`${patched}/api/notes`, {}, JSON.stringify({ title: "groceries" }));
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ title: "groceries" });
  });

  it("mutants: without the skip or without express.raw, a signed event gets the 500 from the Buffer guard", async () => {
    const noSkip = after.replace(
      /\/\/ Stripe webhooks need the raw body[^\n]*\n[\s\S]*?\n\);/,
      "app.use(express.json());",
    );
    const noRaw = after.replace('express.raw({ type: "application/json" }), ', "");
    expect(noSkip).not.toBe(after);
    expect(noRaw).not.toBe(after);
    for (const [name, source] of [
      ["no-skip", noSkip],
      ["no-raw", noRaw],
    ] as const) {
      const url = await listen((await loadEsm<{ app: ExpressApp }>(await variant(dir, FILE, name, source))).app);
      const res = await post(`${url}/api/stripe/webhook`, { "stripe-signature": signed() });
      expect(res.status, name).toBe(500);
    }
  });
});

describe("Express, mounted router, CommonJS, destructured body, no 'stripe' in the file", () => {
  const FILE = "app.js";
  let after = "";
  let dir = "";
  let upgraded: string[] = [];
  let patched = "";
  let require: NodeJS.Require;

  beforeAll(async () => {
    const r = await auditAndApply("express-cjs-router", FILE, "stripe-webhook-unverified");
    ({ after, dir } = r);
    require = createRequire(join(dir, FILE));
    ({ upgraded } = require("./billing.js") as { upgraded: string[] });
    patched = await listen((require(`./${FILE}`) as { app: ExpressApp }).app);
  });

  it("the patch skips JSON parsing for the full mounted path and reads the event from the signed Buffer", () => {
    expect(after).toContain('req.path === "/billing/webhook"');
    expect(after).toContain("const { type, data } = event;");
    expect(after).toContain('const Stripe = require("stripe");');
  });

  it("after the patch, refuses unsigned events, accepts signed ones, other routes still parse JSON", async () => {
    upgraded.length = 0;
    expect((await post(`${patched}/billing/webhook`)).status).toBe(400);
    expect(upgraded).toEqual([]);
    expect((await post(`${patched}/billing/webhook`, { "stripe-signature": signed() })).status).toBe(200);
    expect(upgraded).toEqual(["user-a"]);
    const profile = await post(`${patched}/profile`, {}, JSON.stringify({ name: "Ada" }));
    expect(await profile.json()).toEqual({ name: "Ada" });
  });

  it("mutant: the skip with only the route path (not the mount path) fails the signed event", async () => {
    const wrongPath = after.replace('req.path === "/billing/webhook"', 'req.path === "/webhook"');
    expect(wrongPath).not.toBe(after);
    const path = await variant(dir, FILE, "wrong-path", wrongPath);
    const url = await listen((require(path) as { app: ExpressApp }).app);
    expect((await post(`${url}/billing/webhook`, { "stripe-signature": signed() })).status).toBe(500);
  });
});

describe("Express, verified route with express.raw() behind an earlier app-wide express.json()", () => {
  const FILE = "src/server.ts";
  let after = "";
  let dir = "";
  let original = "";
  let patched = "";

  beforeAll(async () => {
    const r = await auditAndApply("express-raw-after-json", FILE, "stripe-webhook-parsed-body");
    ({ after, dir } = r);
    expect(r.finding.source).toBe("project-config");
    const loadApp = async (path: string) => listen((await loadEsm<{ app: ExpressApp }>(path)).app);
    original = await loadApp(await variant(dir, FILE, "original", r.before));
    patched = await loadApp(join(dir, FILE));
  });

  it("as written, a correctly signed event is rejected (the raw body is already gone)", async () => {
    expect((await post(`${original}/webhooks/stripe`, { "stripe-signature": signed() })).status).toBe(400);
  });

  it("after the patch, the signed event passes and a forged one does not", async () => {
    expect((await post(`${patched}/webhooks/stripe`, { "stripe-signature": signed() })).status).toBe(200);
    expect((await post(`${patched}/webhooks/stripe`, { "stripe-signature": forged() })).status).toBe(400);
  });

  it("mutant: without the skip the guard answers 500 instead of a misleading signature error", async () => {
    const noSkip = after.replace(
      /\/\/ Stripe webhooks need the raw body[^\n]*\n[\s\S]*?\n\);/,
      "app.use(express.json());",
    );
    expect(noSkip).not.toBe(after);
    const url = await listen((await loadEsm<{ app: ExpressApp }>(await variant(dir, FILE, "no-skip", noSkip))).app);
    expect((await post(`${url}/webhooks/stripe`, { "stripe-signature": signed() })).status).toBe(500);
  });
});

/**
 * Next.js pages/api, run on a Node server the way Next's API resolver does it: unless the route exports
 * `config.api.bodyParser = false`, the JSON body is read and parsed into `req.body` before the handler runs.
 */
interface PagesModule {
  default: (req: IncomingMessage & { body?: unknown }, res: unknown) => unknown;
  config?: { api?: { bodyParser?: boolean } };
}
async function servePages(path: string): Promise<string> {
  const mod = await loadEsm<PagesModule>(path);
  return listen((req, res) => {
    void (async () => {
      const r = req as IncomingMessage & { body?: unknown };
      if (mod.config?.api?.bodyParser !== false) {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        r.body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "null");
      }
      const api = Object.assign(res, {
        status(code: number) {
          res.statusCode = code;
          return api;
        },
        json(value: unknown) {
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify(value));
          return api;
        },
      });
      await mod.default(r, api);
    })();
  });
}

describe("Next.js pages/api, unverified handler (TypeScript)", () => {
  const FILE = "pages/api/stripe/webhook.ts";
  let upgraded: string[] = [];
  let original = "";
  let patched = "";
  let after = "";
  let dir = "";

  beforeAll(async () => {
    const r = await auditAndApply("pages-unverified", FILE, "stripe-webhook-unverified");
    ({ after, dir } = r);
    ({ upgraded } = (await import(/* @vite-ignore */ join(dir, "lib/billing.ts"))) as { upgraded: string[] });
    original = await servePages(await variant(dir, FILE, "original", r.before));
    patched = await servePages(join(dir, FILE));
  });

  it("as written, upgrades the user for a forged, unsigned event", async () => {
    upgraded.length = 0;
    expect((await post(original)).status).toBe(200);
    expect(upgraded).toEqual(["user-a"]);
  });

  it("after the patch, refuses unsigned and forged events and accepts a signed one", async () => {
    upgraded.length = 0;
    expect((await post(patched)).status).toBe(400);
    expect((await post(patched, { "stripe-signature": forged() })).status).toBe(400);
    expect(upgraded).toEqual([]);
    expect((await post(patched, { "stripe-signature": signed() })).status).toBe(200);
    expect(upgraded).toEqual(["user-a"]);
  });

  it("mutant: without `bodyParser: false` the signed event fails", async () => {
    const parsed = after.replace("export const config = { api: { bodyParser: false } };", "");
    expect(parsed).not.toBe(after);
    const url = await servePages(await variant(dir, FILE, "parsed", parsed));
    expect((await post(url, { "stripe-signature": signed() })).status).toBe(400);
  });
});

describe("Next.js pages/api, JSON.stringify(req.body) in a sync arrow handler (JavaScript)", () => {
  const FILE = "pages/api/webhook.js";
  let original = "";
  let patched = "";
  let after = "";
  let dir = "";

  beforeAll(async () => {
    const r = await auditAndApply("pages-parsed", FILE, "stripe-webhook-parsed-body");
    ({ after, dir } = r);
    original = await servePages(await variant(dir, FILE, "original", r.before));
    patched = await servePages(join(dir, FILE));
  });

  it("as written, a correctly signed event is rejected", async () => {
    expect((await post(original, { "stripe-signature": signed() })).status).toBe(400);
  });

  it("after the patch (handler made async), the signed event passes and a forged one does not", async () => {
    expect(after).toContain("const handler = async (req, res) =>");
    expect((await post(patched, { "stripe-signature": signed() })).status).toBe(200);
    expect((await post(patched, { "stripe-signature": forged() })).status).toBe(400);
  });

  it("mutant: without `bodyParser: false` the signed event fails again", async () => {
    const parsed = after.replace("export const config = { api: { bodyParser: false } };", "");
    const url = await servePages(await variant(dir, FILE, "parsed", parsed));
    expect((await post(url, { "stripe-signature": signed() })).status).toBe(400);
  });
});

/** Supabase Edge Function on `Deno.serve`: Deno globals stubbed, `npm:stripe` mapped to the npm package. */
type FetchHandler = (req: Request) => Promise<Response>;
async function loadDeno(dir: string, file: string, name: string, source: string): Promise<FetchHandler> {
  let handler: FetchHandler | undefined;
  const env: Record<string, string> = {
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY ?? "",
    STRIPE_WEBHOOK_SECRET: SECRET,
  };
  (globalThis as Record<string, unknown>).Deno = {
    env: { get: (key: string) => env[key] },
    serve: (h: FetchHandler) => {
      handler = h;
    },
  };
  const node = source.replace(/from "npm:stripe@[^"]+"/, 'from "stripe"');
  expect(node).not.toMatch(/from "(?:npm|https?):/);
  await loadEsm(await variant(dir, file, name, node));
  if (!handler) throw new Error("the function never called Deno.serve()");
  return handler;
}
const denoPost = (headers: Record<string, string> = {}) =>
  new Request("http://localhost/functions/v1/fn", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: payload,
  });

describe("Supabase Edge Function, JSON.stringify of a parsed body that is still used later", () => {
  const FILE = "supabase/functions/stripe-webhook/index.ts";
  let r: Awaited<ReturnType<typeof auditAndApply>>;

  beforeAll(async () => {
    r = await auditAndApply("deno-parsed", FILE, "stripe-webhook-parsed-body");
  });

  it("as written, a correctly signed event is rejected", async () => {
    const handler = await loadDeno(r.dir, FILE, "original", r.before);
    expect((await handler(denoPost({ "stripe-signature": signed() }))).status).toBe(400);
  });

  it("after the patch, the signed event passes and the parsed object is still there for later code", async () => {
    expect(r.after).toContain("const body = JSON.parse(rawBody);");
    const handler = await loadDeno(r.dir, FILE, "patched", r.after);
    const res = await handler(denoPost({ "stripe-signature": signed() }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ received: true, type: "checkout.session.completed" });
    expect((await handler(denoPost({ "stripe-signature": forged() }))).status).toBe(400);
  });

  it("mutant: passing JSON.stringify(body) again fails the signed event", async () => {
    const mutant = r.after.replace(/(constructEventAsync\(\s*)rawBody/, "$1JSON.stringify(body)");
    expect(mutant).not.toBe(r.after);
    const handler = await loadDeno(r.dir, FILE, "mutant", mutant);
    expect((await handler(denoPost({ "stripe-signature": signed() }))).status).toBe(400);
  });
});

describe("Supabase Edge Function on Deno.serve, unverified", () => {
  const FILE = "supabase/functions/payments/index.ts";
  let r: Awaited<ReturnType<typeof auditAndApply>>;

  beforeAll(async () => {
    r = await auditAndApply("deno-serve-unverified", FILE, "stripe-webhook-unverified");
  });

  it("as written, a forged event is treated as paid", async () => {
    const handler = await loadDeno(r.dir, FILE, "original", r.before);
    expect(await (await handler(denoPost())).json()).toEqual({ received: true, paid: true });
  });

  it("after the patch, refuses unsigned and forged events and accepts a signed one", async () => {
    const handler = await loadDeno(r.dir, FILE, "patched", r.after);
    expect((await handler(denoPost())).status).toBe(400);
    expect((await handler(denoPost({ "stripe-signature": forged() }))).status).toBe(400);
    expect(await (await handler(denoPost({ "stripe-signature": signed() }))).json()).toEqual({
      received: true,
      paid: true,
    });
  });
});

describe("controls: correct webhooks get no webhook finding", () => {
  it.each(["express-control", "pages-control"])("%s", async (name) => {
    const result = await audit({ repo: join(FIXTURES, name), now: NOW, npmAudit: false });
    expect(webhookFindings(result.findings)).toEqual([]);
  });

  it("a GitHub-style /webhook route in an Express app that never mentions Stripe is not a Stripe webhook", async () => {
    const { expressWebhookFindings } = await import("../src/scanners/express.ts");
    const code = [
      'import express from "express";',
      "const app = express();",
      'app.post("/webhook", express.json(), (req, res) => {',
      "  const event = req.body;",
      '  if (event.action === "opened") res.sendStatus(204);',
      "});",
    ].join("\n");
    expect(await expressWebhookFindings(["server.ts"], async () => code, [])).toEqual([]);
  });

  it("a Clerk webhook route next to Stripe code is not read as the Stripe webhook", async () => {
    const { expressWebhookFindings } = await import("../src/scanners/express.ts");
    const code = [
      'import express from "express";',
      'import Stripe from "stripe";',
      "const app = express();",
      'app.post("/api/clerk/webhook", express.json(), (req, res) => {',
      "  const evt = req.body;",
      '  if (evt.type === "user.created") res.sendStatus(204);',
      "});",
      'app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), (req, res) => {',
      '  const event = Stripe.webhooks.constructEvent(req.body, String(req.headers["stripe-signature"]), "x");',
      "  res.json({ type: event.type });",
      "});",
    ].join("\n");
    expect(await expressWebhookFindings(["server.ts"], async () => code, [])).toEqual([]);
  });

  it("an Express app whose JSON parser lives in another file gets no Express patch (order unknown)", async () => {
    const { FIXERS } = await import("../src/patches/fixers.ts");
    const route = await readFile(join(FIXTURES, "express-global-json/src/server.ts"), "utf8");
    const files: Record<string, string> = {
      "src/webhook.ts": route.replace("app.use(express.json());\n", ""),
      "src/index.ts": 'import express from "express";\nconst app = express();\napp.use(express.json());\n',
    };
    const ctx = {
      read: async (p: string) => files[p],
      files: Object.keys(files),
      migrations: [],
      schemaSql: [],
      probeSql: [],
      newMigration: () => "x.sql",
    };
    const finding = {
      rule: "stripe-webhook-unverified",
      location: { kind: "file", file: "src/webhook.ts", line: 11 },
      evidence: "",
    } as unknown as Finding;
    expect(await FIXERS["stripe-webhook-unverified"]?.(finding, ctx)).toBeUndefined();
    // Same file without the other one: patched.
    const alone = { ...ctx, files: ["src/webhook.ts"] };
    expect(await FIXERS["stripe-webhook-unverified"]?.(finding, alone)).toBeDefined();
  });
});

describe("second look at unverified webhooks (shapes from real Express repos)", () => {
  const raw = (file: string) => ({
    source: "vibe-preflight" as const,
    rule: "stripe-webhook-unverified",
    toolSeverity: "error",
    message: "Handles Stripe events without `constructEvent`, so any POST is trusted.",
    location: { kind: "file" as const, file, line: 1 },
  });
  const route = [
    'import { Router } from "express";',
    'import billing from "../services/billing.js";',
    "const router = Router();",
    'router.post("/stripe", async (req, res) => {',
    "  let event;",
    "  try {",
    '    event = billing.constructWebhookEvent(req.body, req.headers["stripe-signature"]);',
    "  } catch {",
    '    return res.status(400).json({ error: "Invalid signature" });',
    "  }",
    '  if (event.type === "checkout.session.completed") await billing.activate(event);',
    "  res.json({ received: true });",
    "});",
  ].join("\n");
  const service = [
    'import Stripe from "stripe";',
    "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);",
    "export default {",
    "  constructWebhookEvent(payload, signature) {",
    "    return stripe.webhooks.constructEvent(payload, signature, process.env.STRIPE_WEBHOOK_SECRET);",
    "  },",
    "};",
  ].join("\n");
  const filter = async (files: Record<string, string>, file = "src/routes/webhooks.js") => {
    const { filterUnverifiedWebhooks } = await import("../src/scanners/webhook-context.ts");
    return filterUnverifiedWebhooks([raw(file)], Object.keys(files), async (p) => files[p]);
  };

  it("drops it when the signature goes to a helper in another file that calls constructEvent", async () => {
    const r = await filter({ "src/routes/webhooks.js": route, "src/services/billing.js": service });
    expect(r.findings).toEqual([]);
    expect(r.notes.join(" ")).toContain("`constructWebhookEvent()` in `src/services/billing.js`");
  });

  it("mutant: the helper does not call constructEvent, so the finding stays", async () => {
    const unchecked = service.replace(/stripe\.webhooks\.constructEvent\([^)]*\)/, "JSON.parse(payload)");
    const r = await filter({ "src/routes/webhooks.js": route, "src/services/billing.js": unchecked });
    expect(r.findings).toHaveLength(1);
  });

  it("mutant: the signature is read but never handed to the helper, so the finding stays", async () => {
    const ignored = route
      .replace('billing.constructWebhookEvent(req.body, req.headers["stripe-signature"])', "req.body")
      .replace("  let event;", '  const sig = req.headers["stripe-signature"];\n  let event;');
    const r = await filter({ "src/routes/webhooks.js": ignored, "src/services/billing.js": service });
    expect(r.findings).toHaveLength(1);
  });

  it("drops a file that names Stripe events but never reads a request body (a job handler)", async () => {
    const job =
      'export const onEvent = (handler) => async (job) => { if (job.type === "invoice.paid") await handler(job); };';
    const r = await filter({ "src/jobs/hooks.ts": job }, "src/jobs/hooks.ts");
    expect(r.findings).toEqual([]);
    expect(r.notes.join(" ")).toContain("never read a request body");
  });

  it("keeps a real unverified handler (reads req.body, no signature check)", async () => {
    const code = await readFile(join(FIXTURES, "express-global-json/src/server.ts"), "utf8");
    const r = await filter({ "src/server.ts": code }, "src/server.ts");
    expect(r.findings).toHaveLength(1);
  });

  it("an authenticated route that only mentions stripe_customer_id is not read as a webhook", async () => {
    const { expressWebhookFindings } = await import("../src/scanners/express.ts");
    const code = [
      'import { Router } from "express";',
      "const router = Router();",
      'router.post("/portal", requireAuth, asyncHandler(async (req, res) => {',
      "  res.json(await payments.portal({ customerId: req.user.stripe_customer_id }));",
      "}));",
    ].join("\n");
    expect(await expressWebhookFindings(["billing.routes.js"], async () => code, [])).toEqual([]);
  });
});
