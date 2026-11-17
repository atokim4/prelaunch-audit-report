import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
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
 * Express apps that keep `app.use(express.json())` in server.js and the Stripe route in routes/webhooks.js,
 * mounted after the parser. Shapes from two real repos (an events API fixed upstream by skipping the JSON
 * parser for /webhooks, and a booking API with an open issue for the same bug). The route asks for
 * `express.raw()`, but the app-wide parser already ran, so every real Stripe event fails its signature.
 * For each fixture: the audit finds it in the mounting file, the patch applies with git apply, and the
 * patched app is run with real Express and real Stripe signatures. A control mounts the router first.
 */
const FIXTURES = "test/fixtures/webhooks";
const TMP = resolve("test/.tmp/express-mounted");
const SECRET = ["whsec", "mounted", "signing", "secret"].join("_"); // built at runtime: no key-shaped literal
const NOW = new Date("2026-11-17T09:00:00Z");

process.env.STRIPE_SECRET_KEY = ["sk", "test", "mounted"].join("_");
process.env.STRIPE_WEBHOOK_SECRET = SECRET;

const payload = JSON.stringify(
  { id: "evt_mounted", object: "event", type: "checkout.session.completed", data: { object: { id: "cs_1" } } },
  null,
  2,
);
const signed = () => Stripe.webhooks.generateTestHeaderString({ payload, secret: SECRET });
const forged = () => Stripe.webhooks.generateTestHeaderString({ payload, secret: `${SECRET}_wrong` });

type ExpressApp = (req: IncomingMessage, res: ServerResponse) => void;
const servers: Server[] = [];
async function listen(app: ExpressApp): Promise<string> {
  const server = createServer(app);
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
});

const webhookFindings = (findings: Finding[]) => findings.filter((f) => f.rule.startsWith("stripe-webhook-"));

/** Copies the fixture twice (as written, patched with git apply) and returns the finding and both dirs. */
async function auditAndApply(name: string) {
  const repo = join(FIXTURES, name);
  const result = await audit({ repo, now: NOW, npmAudit: false });
  const found = webhookFindings(result.findings);
  expect(found).toHaveLength(1);
  const finding = found[0] as Finding;
  expect(finding.patch?.verified).toBe(true);
  const original = join(TMP, `${name}-original`);
  const patched = join(TMP, `${name}-patched`);
  for (const dir of [original, patched]) {
    await rm(dir, { recursive: true, force: true });
    await cp(repo, dir, { recursive: true });
  }
  await writeFile(join(patched, "fix.patch"), finding.patch?.diff ?? "");
  await run("git", ["init", "-q"], { cwd: patched });
  const applied = await run("git", ["apply", "fix.patch"], { cwd: patched });
  expect(applied.stderr).toBe("");
  expect(applied.code).toBe(0);
  return { finding, original, patched };
}

describe("Express ESM: express.json() in server.js, Stripe route in routes/webhooks.js mounted after it", () => {
  let finding: Finding;
  let original = "";
  let patched = "";
  let dir = "";

  beforeAll(async () => {
    const r = await auditAndApply("express-mounted-esm");
    finding = r.finding;
    dir = r.patched;
    const load = async (d: string) =>
      listen(((await import(/* @vite-ignore */ join(d, "src/server.js"))) as { app: ExpressApp }).app);
    original = await load(r.original);
    patched = await load(r.patched);
  });

  it("is reported at the parser line of the mounting file, with the full mounted path", () => {
    expect(finding.rule).toBe("stripe-webhook-parsed-body");
    expect(finding.location).toMatchObject({ kind: "file", file: "src/server.js", line: 9 });
    expect(finding.evidence).toContain("`POST /webhooks/stripe`");
    expect(finding.evidence).toContain("src/routes/webhooks.js");
  });

  it("the patch skips the JSON parser for that path and adds the Buffer guard to the route", async () => {
    expect(finding.patch?.diff).toContain("+++ b/src/server.js");
    expect(finding.patch?.diff).toContain("+++ b/src/routes/webhooks.js");
    const after = await readFile(join(dir, "src/server.js"), "utf8");
    expect(after).toContain('req.path === "/webhooks/stripe" ? next() : express.json()(req, res, next)');
    expect(await readFile(join(dir, "src/routes/webhooks.js"), "utf8")).toContain("Buffer.isBuffer(req.body)");
  });

  it("a route that already has the guard (the real events API): only the parser line changes", async () => {
    // Outside the project's checkout: listFiles would read a folder inside it through git ls-files.
    const copy = await mkdtemp(join(tmpdir(), "esm-guarded-"));
    await cp(join(FIXTURES, "express-mounted-esm"), copy, { recursive: true });
    const route = join(copy, "src/routes/webhooks.js");
    const text = await readFile(route, "utf8");
    const guarded = text.replace(
      "  let event;\n",
      '  let event;\n  if (!Buffer.isBuffer(req.body)) return res.status(500).send("parsed");\n',
    );
    expect(guarded).not.toBe(text);
    await writeFile(route, guarded);
    const result = await audit({ repo: copy, now: NOW, npmAudit: false });
    const [only] = webhookFindings(result.findings);
    expect(only?.patch?.diff).toContain("+++ b/src/server.js");
    expect(only?.patch?.diff).not.toContain("routes/webhooks.js");
    await rm(copy, { recursive: true, force: true });
  });

  it("as written, a correctly signed event is rejected", async () => {
    expect((await post(`${original}/webhooks/stripe`, { "stripe-signature": signed() })).status).toBe(400);
  });

  it("after the patch, the signed event passes, a forged one does not, other routes still parse JSON", async () => {
    expect((await post(`${patched}/webhooks/stripe`, { "stripe-signature": signed() })).status).toBe(200);
    expect((await post(`${patched}/webhooks/stripe`, { "stripe-signature": forged() })).status).toBe(400);
    const order = await post(`${patched}/orders`, {}, JSON.stringify({ item: "ticket" }));
    expect(await order.json()).toEqual({ parsed: true, item: "ticket" });
  });
});

describe("Express CommonJS: router mounted with an inline require() after express.json()", () => {
  let finding: Finding;
  let original = "";
  let patched = "";
  let dir = "";

  beforeAll(async () => {
    const r = await auditAndApply("express-mounted-cjs");
    finding = r.finding;
    dir = r.patched;
    const serve = (d: string) =>
      listen((createRequire(join(d, "server/index.js"))("./index.js") as { app: ExpressApp }).app);
    original = await serve(r.original);
    patched = await serve(r.patched);
  });

  it("is reported in server/index.js with the mount path of a '/' route", () => {
    expect(finding.location).toMatchObject({ kind: "file", file: "server/index.js" });
    expect(finding.evidence).toContain("`POST /api/webhooks`");
  });

  it("as written the signed event fails; after the patch it passes and bookings still get JSON", async () => {
    expect((await post(`${original}/api/webhooks`, { "stripe-signature": signed() })).status).toBe(400);
    expect((await post(`${patched}/api/webhooks`, { "stripe-signature": signed() })).status).toBe(200);
    expect((await post(`${patched}/api/webhooks`, { "stripe-signature": forged() })).status).toBe(400);
    const booking = await post(`${patched}/api/bookings`, {}, JSON.stringify({ item: "slot" }));
    expect(await booking.json()).toEqual({ parsed: true, item: "slot" });
  });

  it("mutant: skipping only the route path ('/') instead of the mounted path: the guard answers 500", async () => {
    const after = await readFile(join(dir, "server/index.js"), "utf8");
    const wrong = after.replace('req.path === "/api/webhooks"', 'req.path === "/"');
    expect(wrong).not.toBe(after);
    await writeFile(join(dir, "server/wrong.js"), wrong);
    const url = await listen((createRequire(join(dir, "server/wrong.js"))("./wrong.js") as { app: ExpressApp }).app);
    expect((await post(`${url}/api/webhooks`, { "stripe-signature": signed() })).status).toBe(500);
  });
});

describe("control: the webhooks router mounted before the app-wide parser", () => {
  it("gets no webhook finding, and a signed event passes as written", async () => {
    const repo = join(FIXTURES, "express-mounted-control");
    const result = await audit({ repo, now: NOW, npmAudit: false });
    expect(webhookFindings(result.findings)).toEqual([]);
    const app = ((await import(/* @vite-ignore */ resolve(repo, "src/server.js"))) as { app: ExpressApp }).app;
    const url = await listen(app);
    expect((await post(`${url}/webhooks/stripe`, { "stripe-signature": signed() })).status).toBe(200);
  });
});
