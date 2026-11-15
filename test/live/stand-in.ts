/**
 * A local stand-in for a hosted Supabase project, for the live-probe tests and the sample report.
 *
 * - Postgres: PGlite (Postgres in WebAssembly) with the Supabase shim, the app's migrations, a
 *   "dashboard drift" file and sample rows, served over the wire protocol by pglite-socket.
 * - REST: the real PostgREST binary (scripts/fetch-postgrest.sh) on top of it, so counts, Range
 *   headers, error codes and RLS behave as they do behind supabase.co/rest/v1.
 * - Auth and the API gateway: a small Node server. It checks the apikey, answers GoTrue's password
 *   grant with HS256 JWTs PostgREST accepts, and forwards /rest/v1 to PostgREST. Storage listing is
 *   emulated through PostgREST on the storage schema (same RLS, simpler answers than Storage's API).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { SHIM_PATH } from "../../src/probe/rls-probe.ts";

const ROOT = new URL("../../", import.meta.url).pathname;

export const POSTGREST_BIN = process.env.POSTGREST_BIN ?? join(ROOT, ".cache/postgrest/postgrest");
export const hasPostgrest = (): boolean => existsSync(POSTGREST_BIN);

export const USER_A_ID = "00000000-0000-4000-8000-0000000000a1";
export const USER_B_ID = "00000000-0000-4000-8000-0000000000b2";

export interface StandInOptions {
  /** The app whose supabase/migrations load first. */
  app: string;
  /** SQL files run after the migrations, in order (dashboard drift, then sample rows). */
  extraSql: string[];
  /** Gateway port; a free one when not given. 54321 matches `supabase start`, for the sample report. */
  port?: number;
}

export interface StandIn {
  url: string;
  /** A legacy anon JWT and a publishable key; the gateway takes either. */
  anonKey: string;
  publishableKey: string;
  /** Signed with the project secret: the probe must refuse it. */
  serviceRoleKey: string;
  users: { a: { email: string; password: string }; b: { email: string; password: string } };
  /** Every request the gateway saw: method and path (no headers, no bodies). */
  log: { method: string; path: string }[];
  logouts: number;
  /** Runs SQL as the database owner, as a `supabase db push` of a migration would. */
  exec(sql: string): Promise<void>;
  /** Fingerprint of every row in public and storage, to prove a run wrote nothing. */
  fingerprint(): Promise<string>;
  stop(): Promise<void>;
}

const b64url = (value: string | Buffer): string => Buffer.from(value).toString("base64url");

function sign(claims: Record<string, unknown>, secret: string): string {
  const head = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(claims));
  return `${head}.${body}.${createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url")}`;
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() =>
        typeof address === "object" && address ? resolve(address.port) : reject(new Error("no port")),
      );
    });
  });
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

const send = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body === undefined ? "" : JSON.stringify(body));
};

async function waitFor(url: string, child: ChildProcess, output: () => string): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`PostgREST exited: ${output()}`);
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`PostgREST did not get ready: ${output()}`);
}

export async function startStandIn(options: StandInOptions): Promise<StandIn> {
  const db = await PGlite.create();
  await db.exec(await readFile(SHIM_PATH, "utf8"));
  const dir = join(options.app, "supabase/migrations");
  for (const file of (await readdir(dir)).filter((f) => f.endsWith(".sql")).sort()) {
    await db.exec(await readFile(join(dir, file), "utf8"));
  }
  for (const file of options.extraSql) await db.exec(await readFile(file, "utf8"));

  const pgPort = await freePort();
  const socket = new PGLiteSocketServer({ db, port: pgPort, host: "127.0.0.1", maxConnections: 4 });
  await socket.start();

  const secret = randomBytes(32).toString("hex");
  const work = await mkdtemp(join(tmpdir(), "pa-standin-"));
  const restPort = await freePort();
  const adminPort = await freePort();
  await writeFile(
    join(work, "postgrest.conf"),
    [
      `db-uri = "postgres://authenticator@127.0.0.1:${pgPort}/postgres?sslmode=disable"`,
      `db-schemas = "public,storage"`,
      `db-anon-role = "anon"`,
      // PGlite is one session behind a multiplexer: one pooled connection, no LISTEN, no named statements.
      `db-pool = 1`,
      `db-channel-enabled = false`,
      `db-prepared-statements = false`,
      `jwt-secret = "${secret}"`,
      `server-host = "127.0.0.1"`,
      `server-port = ${restPort}`,
      `admin-server-port = ${adminPort}`,
      `log-level = "warn"`,
    ].join("\n"),
  );
  let output = "";
  const rest = spawn(POSTGREST_BIN, [join(work, "postgrest.conf")], { stdio: ["ignore", "pipe", "pipe"] });
  rest.stdout?.on("data", (d: Buffer) => (output += d.toString()));
  rest.stderr?.on("data", (d: Buffer) => (output += d.toString()));
  const cleanup = async () => {
    rest.kill("SIGTERM");
    await socket.stop();
    await db.close();
    await rm(work, { recursive: true, force: true });
  };
  try {
    await waitFor(`http://127.0.0.1:${adminPort}/ready`, rest, () => output);
  } catch (error) {
    await cleanup();
    throw error;
  }

  const now = Math.floor(Date.now() / 1000);
  const anonJwt = sign({ role: "anon", iss: "supabase", iat: now, exp: now + 3600 }, secret);
  const publishableKey = `sb_publishable_${randomBytes(12).toString("hex")}`;
  const serviceRoleKey = sign({ role: "service_role", iss: "supabase", iat: now, exp: now + 3600 }, secret);
  const users = {
    a: { email: "user-a@example.invalid", password: randomBytes(9).toString("base64url"), id: USER_A_ID },
    b: { email: "user-b@example.invalid", password: randomBytes(9).toString("base64url"), id: USER_B_ID },
  };
  const log: StandIn["log"] = [];
  const state = { logouts: 0 };
  const revoked = new Set<string>();

  /** A PostgREST call on the storage schema; the storage routes answer with its JSON. */
  const storageQuery = async (path: string, auth: string): Promise<{ status: number; json: unknown }> => {
    const response = await fetch(`http://127.0.0.1:${restPort}${path}`, {
      headers: { authorization: auth, "accept-profile": "storage" },
    });
    const text = await response.text();
    return { status: response.status, json: text ? (JSON.parse(text) as unknown) : undefined };
  };

  const gateway: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? "/", "http://stand-in");
      const method = req.method ?? "GET";
      log.push({ method, path: `${url.pathname}${url.search}` });
      const apikey = req.headers.apikey;
      if (apikey !== anonJwt && apikey !== publishableKey && apikey !== serviceRoleKey) {
        send(res, 401, { message: "Invalid API key" });
        return;
      }
      const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
      if (bearer && revoked.has(bearer)) {
        send(res, 401, { code: "PGRST303", message: "JWT expired" });
        return;
      }
      // Like Supabase's gateway: a publishable key (or none) runs as anon.
      const auth = `Bearer ${bearer && bearer !== publishableKey ? bearer : apikey === serviceRoleKey ? serviceRoleKey : anonJwt}`;

      if (url.pathname === "/auth/v1/token" && method === "POST" && url.searchParams.get("grant_type") === "password") {
        const body = JSON.parse((await readBody(req)) || "{}") as { email?: string; password?: string };
        const user = Object.values(users).find((u) => u.email === body.email && u.password === body.password);
        if (!user) {
          send(res, 400, { error: "invalid_grant", error_description: "Invalid login credentials" });
          return;
        }
        const iat = Math.floor(Date.now() / 1000);
        const token = sign(
          { sub: user.id, role: "authenticated", aud: "authenticated", email: user.email, iat, exp: iat + 3600 },
          secret,
        );
        send(res, 200, {
          access_token: token,
          token_type: "bearer",
          expires_in: 3600,
          user: { id: user.id, email: user.email },
        });
        return;
      }
      if (url.pathname === "/auth/v1/logout" && method === "POST") {
        if (bearer) revoked.add(bearer);
        state.logouts += 1;
        res.writeHead(204).end();
        return;
      }
      if (url.pathname.startsWith("/rest/v1/")) {
        const headers: Record<string, string> = {};
        for (const name of ["prefer", "accept", "range", "content-type"]) {
          const value = req.headers[name];
          if (typeof value === "string") headers[name] = value;
        }
        const body = method === "GET" || method === "HEAD" ? undefined : await readBody(req);
        const response = await fetch(`http://127.0.0.1:${restPort}${url.pathname.slice(8)}${url.search}`, {
          method,
          headers: { ...headers, authorization: auth },
          body,
        });
        const out: Record<string, string> = {};
        for (const name of ["content-type", "content-range"]) {
          const value = response.headers.get(name);
          if (value) out[name] = value;
        }
        res.writeHead(response.status, out);
        res.end(method === "HEAD" ? undefined : Buffer.from(await response.arrayBuffer()));
        return;
      }
      if (url.pathname === "/storage/v1/bucket" && method === "GET") {
        const r = await storageQuery("/buckets?select=id,name,public&order=id", auth);
        send(res, r.status, r.json);
        return;
      }
      const list = /^\/storage\/v1\/object\/list\/([^/]+)$/.exec(url.pathname);
      if (list && method === "POST") {
        const body = JSON.parse((await readBody(req)) || "{}") as { prefix?: string; limit?: number };
        const bucket = decodeURIComponent(list[1] ?? "");
        const query = new URLSearchParams({
          select: "name",
          bucket_id: `eq.${bucket}`,
          name: `like.${(body.prefix ?? "").replace(/[%_*]/g, "")}*`,
          limit: String(body.limit ?? 100),
        });
        const r = await storageQuery(`/objects?${query}`, auth);
        send(
          res,
          r.status === 200 ? 200 : 400,
          r.status === 200 ? r.json : { statusCode: String(r.status), error: "Error", message: "list failed" },
        );
        return;
      }
      send(res, 404, { message: "no route" });
    })().catch((error: unknown) => {
      if (!res.headersSent) send(res, 502, { message: error instanceof Error ? error.message : String(error) });
    });
  });
  const gatewayPort = options.port ?? (await freePort());
  await new Promise<void>((resolve) => gateway.listen(gatewayPort, "127.0.0.1", resolve));

  return {
    url: `http://127.0.0.1:${gatewayPort}`,
    anonKey: anonJwt,
    publishableKey,
    serviceRoleKey,
    users,
    log,
    get logouts() {
      return state.logouts;
    },
    async exec(sql: string) {
      await db.exec(sql);
    },
    async fingerprint() {
      const tables = await db.query<{ schema: string; name: string }>(
        `select n.nspname::text as schema, c.relname::text as name from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where n.nspname in ('public', 'storage', 'auth') and c.relkind = 'r' order by 1, 2`,
      );
      const parts: string[] = [];
      for (const { schema, name } of tables.rows) {
        const r = await db.query<{ h: string | null }>(
          `select md5(string_agg(t::text, '|' order by t::text)) as h from "${schema}"."${name}" t`,
        );
        parts.push(`${schema}.${name}:${r.rows[0]?.h ?? "empty"}`);
      }
      return parts.join("\n");
    },
    async stop() {
      await new Promise<void>((resolve) => gateway.close(() => resolve()));
      await cleanup();
    },
  };
}
