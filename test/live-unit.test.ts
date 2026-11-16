import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { classify, LiveHttp, rangeTotal } from "../src/live/http.ts";
import { keyKind, projectOrigin } from "../src/live/probe.ts";
import { liveTargets, migrationFunctions, parseGeneratedTypes } from "../src/live/targets.ts";
import type { TableProbe } from "../src/probe/rls-probe.ts";

const TYPES = new URL("./fixtures/pipeline-crm-app/src/integrations/supabase/types.ts", import.meta.url);

/** A JWT-shaped string with the given payload; the signature is never checked here. */
const jwt = (claims: object): string =>
  ["e30", Buffer.from(JSON.stringify(claims)).toString("base64url"), "c2ln"].join(".");

const response = (status: number, json: unknown, headers: Record<string, string> = {}) => ({
  status,
  json,
  headers: new Headers(headers),
});

describe("generated types", () => {
  it("reads tables, views and functions of the public schema", async () => {
    const schema = parseGeneratedTypes(await readFile(TYPES, "utf8"));
    expect(schema?.tables.map((t) => t.name)).toEqual([
      "activities",
      "deals",
      "invoices",
      "leads",
      "notes",
      "plans",
      "profiles",
      "tasks",
    ]);
    expect(schema?.views.map((v) => v.name)).toEqual(["open_tasks", "pipeline_summary"]);
    expect(schema?.functions).toEqual(["delete_lead"]);
    expect(schema?.tables.find((t) => t.name === "deals")?.columns).toEqual([
      "amount_cents",
      "created_at",
      "id",
      "lead_id",
      "owner_id",
      "stage",
      "title",
    ]);
  });

  it("handles the multi-line layout, quoted keys and other schemas", () => {
    const text = `export type Database = {
  graphql_public: { Tables: { [_ in never]: never }; Functions: { graphql: { Args: {}; Returns: Json } } }
  public: {
    Tables: {
      "team-members": {
        Row: {
          id: string
          meta: { tags: string[] } | null
          user_id: string
        }
        Insert: { id?: string }
        Relationships: [
          { foreignKeyName: "x"; columns: ["user_id"]; referencedRelation: "users" },
        ]
      }
    }
    Views: { [_ in never]: never }
    Functions: { [_ in never]: never }
  }
}`;
    const schema = parseGeneratedTypes(text);
    expect(schema).toEqual({
      tables: [{ name: "team-members", columns: ["id", "meta", "user_id"] }],
      views: [],
      functions: [],
    });
  });

  it("returns undefined for a file without a public schema", () => {
    expect(parseGeneratedTypes("export const x = 1;")).toBeUndefined();
  });

  it("adds types-only tables with a guessed owner column, after the migration ones", () => {
    const local = {
      table: "public.deals",
      name: "deals",
      kind: "table",
      rls: true,
      columns: ["id", "owner_id"],
      ownerColumns: ["owner_id"],
      checks: [],
      policies: [],
    } satisfies TableProbe;
    const targets = liveTargets([local], {
      tables: [
        { name: "deals", columns: ["id", "owner_id"] },
        { name: "notes", columns: ["id", "user_id", "body"] },
        { name: "settings", columns: ["key", "value"] },
      ],
      views: [],
      functions: [],
    });
    expect(targets.map((t) => [t.name, t.foundIn, t.ownerColumns])).toEqual([
      ["deals", ["migrations", "types"], ["owner_id"]],
      ["notes", ["types"], ["user_id"]],
      ["settings", ["types"], []],
    ]);
  });
});

describe("migration functions", () => {
  it("lists public callable functions with their definer flag, skipping triggers and other schemas", () => {
    const fns = migrationFunctions([
      {
        path: "supabase/migrations/1_a.sql",
        text: `create function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin return new; end; $$;
create function public.delete_lead(lead_id uuid) returns void language sql security definer as $$ delete from public.leads where id = lead_id; $$;
create function private.helper() returns int language sql as $$ select 1 $$;
create or replace function count_things() returns int language sql stable as $$ select 1 $$;`,
      },
      {
        path: "supabase/migrations/2_b.sql",
        text: "create or replace function public.count_things() returns int language sql security definer as $$ select 2 $$;",
      },
    ]);
    expect([...fns.entries()]).toEqual([
      ["delete_lead", true],
      ["count_things", true],
    ]);
  });
});

describe("keys and URLs", () => {
  it("takes only a publishable or anon key", () => {
    expect(keyKind("sb_publishable_abc")).toBe("publishable");
    expect(keyKind(jwt({ role: "anon" }))).toBe("anon");
    expect(() => keyKind(["sb", "secret", "abc"].join("_"))).toThrow(/secret key/);
    expect(() => keyKind(jwt({ role: "service_role" }))).toThrow(/service_role/);
    expect(() => keyKind("not-a-key")).toThrow(/neither/);
  });

  it("wants https, except for a stand-in on this machine", () => {
    expect(projectOrigin("https://abcd.supabase.co/rest/v1/")).toBe("https://abcd.supabase.co");
    expect(projectOrigin("http://127.0.0.1:54321")).toBe("http://127.0.0.1:54321");
    expect(() => projectOrigin("http://abcd.supabase.co")).toThrow(/https/);
    expect(() => projectOrigin("abcd")).toThrow(/not a URL/);
  });
});

describe("answers", () => {
  it("reads the total from Content-Range", () => {
    expect(rangeTotal("*/42")).toBe(42);
    expect(rangeTotal("0-9/120")).toBe(120);
    expect(rangeTotal("0-9/*")).toBeUndefined();
    expect(rangeTotal(null)).toBeUndefined();
  });

  it("calls only 42501 and RLS refusals blocked", () => {
    expect(classify(response(200, undefined, { "content-range": "*/3" }))).toEqual({ status: "count", n: 3 });
    expect(classify(response(206, undefined, { "content-range": "0-0/9" }))).toEqual({ status: "count", n: 9 });
    expect(classify(response(200, []))).toMatchObject({ status: "inconclusive" });
    expect(classify(response(401, { code: "42501", message: "permission denied for table x" }))).toEqual({
      status: "blocked",
      code: "42501",
    });
    expect(classify(response(403, { message: "new row violates row-level security policy" }))).toMatchObject({
      status: "blocked",
    });
    expect(classify(response(404, { code: "PGRST205", message: "Could not find the table" }))).toEqual({
      status: "missing",
      code: "PGRST205",
    });
    expect(classify(response(401, { code: "PGRST301", message: "JWT expired" }))).toEqual({
      status: "inconclusive",
      reason: "HTTP 401 PGRST301 JWT expired",
    });
    expect(classify(response(503, undefined))).toEqual({ status: "inconclusive", reason: "HTTP 503" });
  });
});

describe("the HTTP door", () => {
  const ok = async (): Promise<Response> => new Response("[]", { status: 200 });

  it("refuses POST outside sign-in, sign-out and storage listing", () => {
    const http = new LiveHttp("https://x.supabase.co", { rate: 100, maxRequests: 10, timeoutMs: 1000, fetch: ok });
    expect(() => http.request("POST", "/rest/v1/leads", { headers: {} })).toThrow(/read-only/);
    expect(() => http.request("POST", "/rest/v1/rpc/delete_lead", { headers: {} })).toThrow(/read-only/);
    expect(() => http.request("POST", "/storage/v1/object/attachments/x.pdf", { headers: {} })).toThrow(/read-only/);
  });

  it("keeps to the rate and stops at the request cap", async () => {
    const times: number[] = [];
    const fetch = async (): Promise<Response> => {
      times.push(Date.now());
      return new Response("[]", { status: 200 });
    };
    const http = new LiveHttp("https://x.supabase.co", { rate: 20, maxRequests: 3, timeoutMs: 1000, fetch });
    await Promise.all([1, 2, 3].map(() => http.request("GET", "/storage/v1/bucket", { headers: {} })));
    expect(times.length).toBe(3);
    expect(times[2]! - times[0]!).toBeGreaterThanOrEqual(95);
    await expect(http.request("GET", "/storage/v1/bucket", { headers: {} })).rejects.toThrow(/max-requests 3/);
  });

  it("names the request that timed out", async () => {
    const hang = (_: string | URL | Request, init?: RequestInit): Promise<Response> =>
      new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal?.reason)));
    const http = new LiveHttp("https://x.supabase.co", { rate: 100, maxRequests: 5, timeoutMs: 50, fetch: hang });
    await expect(http.request("HEAD", "/rest/v1/leads?select=*", { headers: {} })).rejects.toThrow(
      "HEAD /rest/v1/leads: no answer in 0.05 s",
    );
  });
});
