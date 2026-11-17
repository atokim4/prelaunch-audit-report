import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import express from "express";
import Stripe from "stripe";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { run } from "../src/exec.ts";
import { withVerify } from "../src/patches/nest.ts";
import type { Finding } from "../src/types.ts";

/**
 * NestJS with `rawBody: true` and its own body parsers (shape of a real API whose maintainers fixed it the
 * same way: a `verify` option on each parser). Nest itself is not installed here: a stub `@nestjs/core`
 * hands main.ts a plain Express app, which is all main.ts touches. That is enough for the question the
 * patch answers: do the parsers main.ts registers keep the bytes on `req.rawBody`? Stripe's own package
 * checks the signature on what they keep. (Nest's parsers would not help either way: body-parser skips a
 * request another parser already read.)
 */
const FIXTURES = "test/fixtures/webhooks";
const TMP = resolve("test/.tmp/nest-rawbody");
const SECRET = ["whsec", "nest", "signing", "secret"].join("_");
const NOW = new Date("2026-11-17T09:00:00Z");
process.env.STRIPE_SECRET_KEY = ["sk", "test", "nest"].join("_");

const payload = JSON.stringify({ id: "evt_nest", object: "event", type: "checkout.session.completed" }, null, 2);
const signature = () => Stripe.webhooks.generateTestHeaderString({ payload, secret: SECRET });

const servers: Server[] = [];
beforeAll(() => mkdir(TMP, { recursive: true }));
afterAll(async () => {
  await Promise.all(servers.map((s) => new Promise((done) => s.close(done))));
  await rm(TMP, { recursive: true, force: true });
});

const STUB = `import express from "express";
export const NestFactory = {
  async create() {
    const app = express();
    globalThis.__nestApp = app;
    return { use: (...args) => app.use(...args), listen: async () => {} };
  },
};
`;

/** Runs the copy's main.ts on the stub and answers the webhook route the way the controller does. */
async function serve(dir: string): Promise<string> {
  await mkdir(join(dir, "node_modules/@nestjs/core"), { recursive: true });
  await writeFile(
    join(dir, "node_modules/@nestjs/core/package.json"),
    '{"name":"@nestjs/core","type":"module","main":"index.js"}',
  );
  await writeFile(join(dir, "node_modules/@nestjs/core/index.js"), STUB);
  await import(/* @vite-ignore */ `${join(dir, "src/main.ts")}?v=${Date.now()}`);
  await new Promise((done) => setTimeout(done, 20));
  const app = (globalThis as { __nestApp?: express.Express }).__nestApp as express.Express;
  app.post("/api/payments/webhook", (req, res) => {
    const raw = (req as IncomingMessage & { rawBody?: Buffer }).rawBody;
    if (!raw) return void res.status(400).send("rawBody not found");
    try {
      Stripe.webhooks.constructEvent(raw, String(req.headers["stripe-signature"]), SECRET);
      res.json({ received: true });
    } catch {
      res.status(400).send("bad signature");
    }
  });
  const server = createServer(app as unknown as (q: IncomingMessage, s: ServerResponse) => void);
  servers.push(server);
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/payments/webhook`;
}
const post = (url: string) =>
  fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "stripe-signature": signature() },
    body: payload,
  });

describe("NestJS rawBody: true with the app's own body parsers", () => {
  let finding: Finding;
  let original = "";
  let patched = "";

  beforeAll(async () => {
    const repo = join(FIXTURES, "nest-rawbody");
    const result = await audit({ repo, now: NOW, npmAudit: false });
    const found = result.findings.filter((f) => f.rule.startsWith("stripe-webhook-"));
    expect(found).toHaveLength(1);
    finding = found[0] as Finding;
    expect(finding.patch?.verified).toBe(true);
    const a = join(TMP, "original");
    const b = join(TMP, "patched");
    for (const dir of [a, b]) {
      await rm(dir, { recursive: true, force: true });
      await cp(repo, dir, { recursive: true });
    }
    await writeFile(join(b, "fix.patch"), finding.patch?.diff ?? "");
    await run("git", ["init", "-q"], { cwd: b });
    const applied = await run("git", ["apply", "fix.patch"], { cwd: b });
    expect(applied.code).toBe(0);
    original = await serve(a);
    patched = await serve(b);
  });

  it("is reported in main.ts and names the controller that reads req.rawBody", () => {
    expect(finding.rule).toBe("stripe-webhook-parsed-body");
    expect(finding.location).toMatchObject({ kind: "file", file: "src/main.ts", line: 11 });
    expect(finding.evidence).toContain("src/payments/payments.controller.ts");
  });

  it("as written, a correctly signed event gets 'rawBody not found'", async () => {
    const res = await post(original);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("rawBody not found");
  });

  it("after the patch, the signed event passes on the bytes the raw parser kept", async () => {
    expect((await post(patched)).status).toBe(200);
    const main = await readFile(join(TMP, "patched/src/main.ts"), "utf8");
    expect(main.match(/verify: keepRawBody/g)).toHaveLength(2);
  });

  it("control: parsers that already keep the bytes get no finding", async () => {
    const result = await audit({ repo: join(FIXTURES, "nest-rawbody-control"), now: NOW, npmAudit: false });
    expect(result.findings.filter((f) => f.rule.startsWith("stripe-webhook-"))).toEqual([]);
  });
});

describe("withVerify", () => {
  it.each([
    ["", "{ verify: keepRawBody }"],
    ["{ limit: '2mb' }", "{ limit: '2mb', verify: keepRawBody }"],
    ["{ limit: '2mb', }", "{ limit: '2mb', verify: keepRawBody }"],
    ["{\n      limit: '16kb'\n    }", "{\n      limit: '16kb',\n      verify: keepRawBody,\n    }"],
  ])("%j", (args, expected) => {
    expect(withVerify(args)).toBe(expected);
  });

  it("gives up on options from a variable", () => {
    expect(withVerify("options")).toBeUndefined();
  });
});
