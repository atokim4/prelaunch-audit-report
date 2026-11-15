import { leaks as localLeaks } from "../probe/rls-probe.ts";
import type { LiveActor, LiveBucket, LiveCount, LiveDrift, LiveResult, LiveTable, LiveVerdict } from "../types.ts";
import { classify, errorText, LiveHttp, type LiveHttpOptions } from "./http.ts";
import type { LiveTarget } from "./targets.ts";

export const LIVE_PROBE_VERSION = "1.0.0";

export interface LiveUser {
  email: string;
  password: string;
}

export interface LiveProbeOptions {
  /** Project URL, e.g. https://abcd.supabase.co. */
  project: string;
  /** The anon (legacy JWT) or publishable key. A secret or service_role key is refused. */
  key: string;
  userA: LiveUser;
  userB: LiveUser;
  targets: LiveTarget[];
  buckets: string[];
  rpcs: LiveResult["rpcs"];
  http?: Partial<LiveHttpOptions>;
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** https only (http just for a stand-in on this machine); returns the origin with no path. */
export function projectOrigin(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`--live is not a URL: ${raw}`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname))) {
    throw new Error("--live must be an https:// Supabase project URL");
  }
  return url.origin;
}

function jwtRole(key: string): string | undefined {
  const payload = key.split(".")[1];
  if (key.split(".").length !== 3 || !payload) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { role?: unknown };
    return typeof claims.role === "string" ? claims.role : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The probe must see exactly what a visitor's browser sees, so only the public key is accepted. A
 * secret or service_role key skips Row Level Security: every table would look open, and the probe
 * would be holding a key that can change everything.
 */
export function keyKind(key: string): LiveResult["keyKind"] {
  if (key.startsWith("sb_secret_"))
    throw new Error("that is a secret key: the live probe takes only the publishable key");
  if (key.startsWith("sb_publishable_")) return "publishable";
  const role = jwtRole(key);
  if (role === "service_role") {
    throw new Error("that is the service_role key: the live probe takes only the anon or publishable key");
  }
  if (role === "anon") return "anon";
  throw new Error("the key is neither a publishable key (sb_publishable_…) nor an anon JWT");
}

interface Session {
  id: string;
  token: string;
}

const isUuid = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

const counted = (c: LiveCount | undefined): number | undefined => (c?.status === "count" ? c.n : undefined);
/** Refused by Postgres or zero rows: the actor got nothing. */
const nothing = (c: LiveCount | undefined): boolean => c?.status === "blocked" || counted(c) === 0;
const rows = (n: number): string => `${n} row${n === 1 ? "" : "s"}`;

/** "User B can read user A's 2 rows." / "… 1 of user A's 3 rows and 4 rows in all that are not theirs." */
function bLeakText(ofA: number | undefined, ownA: number | undefined, others: number | undefined): string {
  if (!ofA) {
    const n = others ?? 0;
    return `User B can read ${rows(n)} that belong${n === 1 ? "s" : ""} to other users.`;
  }
  const part =
    ownA === ofA ? `user A's ${rows(ofA)}` : `${ofA}${ownA ? ` of user A's ${rows(ownA)}` : ` of user A's rows`}`;
  const more = others !== undefined && others > ofA ? ` and ${rows(others)} in all that are not theirs` : "";
  return `User B can read ${part}${more}.`;
}

const ACTOR_TEXT: Record<"anon" | "user-b", string> = { anon: "A visitor without an account", "user-b": "User B" };

class Prober {
  private readonly http: LiveHttp;
  private readonly key: string;
  private readonly kind: LiveResult["keyKind"];
  private readonly sessions = new Map<LiveActor, Session>();

  constructor(http: LiveHttp, key: string, kind: LiveResult["keyKind"]) {
    this.http = http;
    this.key = key;
    this.kind = kind;
  }

  headers(actor: LiveActor): Record<string, string> {
    const session = this.sessions.get(actor);
    if (session) return { apikey: this.key, authorization: `Bearer ${session.token}` };
    // supabase-js sends a legacy anon JWT as the bearer too; a publishable key goes in apikey only.
    return this.kind === "anon" ? { apikey: this.key, authorization: `Bearer ${this.key}` } : { apikey: this.key };
  }

  user(actor: "user-a" | "user-b"): Session {
    const session = this.sessions.get(actor);
    if (!session) throw new Error(`${actor} is not signed in`);
    return session;
  }

  async signIn(actor: "user-a" | "user-b", user: LiveUser): Promise<void> {
    const label = actor === "user-a" ? "user A" : "user B";
    const response = await this.http.request("POST", "/auth/v1/token?grant_type=password", {
      headers: { apikey: this.key },
      body: { email: user.email, password: user.password },
    });
    const json = (response.json ?? {}) as {
      access_token?: unknown;
      user?: { id?: unknown };
      error_description?: unknown;
      msg?: unknown;
      message?: unknown;
    };
    if (response.status !== 200 || typeof json.access_token !== "string" || !isUuid(json.user?.id)) {
      const why = [json.error_description, json.msg, json.message].find((v) => typeof v === "string");
      throw new Error(`${label} could not sign in (HTTP ${response.status}${why ? `: ${String(why)}` : ""})`);
    }
    this.sessions.set(actor, { id: json.user.id, token: json.access_token });
  }

  /** Revokes the two sessions the probe opened. Best effort: a failure here changes no result. */
  async signOut(): Promise<void> {
    for (const actor of ["user-a", "user-b"] as const) {
      if (!this.sessions.has(actor)) continue;
      await this.http
        .request("POST", "/auth/v1/logout?scope=local", { headers: this.headers(actor) })
        .catch(() => undefined);
      this.sessions.delete(actor);
    }
  }

  /**
   * Rows `actor` can see, as a number. HEAD with `Prefer: count=exact` returns only a Content-Range
   * header, so no row ever crosses the wire; an error is read again with `limit=0` for its code.
   */
  async count(actor: LiveActor, table: string, query: string): Promise<LiveCount> {
    const path = `/rest/v1/${encodeURIComponent(table)}?${query}`;
    const headers = { ...this.headers(actor), prefer: "count=exact" };
    try {
      const head = await this.http.request("HEAD", path, { headers });
      if (head.status >= 200 && head.status < 300) return classify(head);
      return classify(await this.http.request("GET", `${path}&limit=0`, { headers }));
    } catch (error) {
      return { status: "inconclusive", reason: errorText(error).slice(0, 160) };
    }
  }

  /** Entries under `prefix` in a bucket, as a number. Names are counted and dropped. */
  async listCount(actor: LiveActor, bucket: string, prefix: string): Promise<LiveCount> {
    try {
      const response = await this.http.request("POST", `/storage/v1/object/list/${encodeURIComponent(bucket)}`, {
        headers: this.headers(actor),
        body: { prefix, limit: 100, offset: 0 },
      });
      if (response.status === 200 && Array.isArray(response.json)) return { status: "count", n: response.json.length };
      return classify(response);
    } catch (error) {
      return { status: "inconclusive", reason: errorText(error).slice(0, 160) };
    }
  }

  async bucketList(actor: LiveActor): Promise<{ count: LiveCount; buckets: { id: string; public: boolean }[] }> {
    try {
      const response = await this.http.request("GET", "/storage/v1/bucket", { headers: this.headers(actor) });
      if (response.status !== 200 || !Array.isArray(response.json)) return { count: classify(response), buckets: [] };
      const buckets = (response.json as { id?: unknown; public?: unknown }[])
        .filter((b) => typeof b.id === "string")
        .map((b) => ({ id: String(b.id), public: b.public === true }));
      return { count: { status: "count", n: buckets.length }, buckets };
    } catch (error) {
      return { count: { status: "inconclusive", reason: errorText(error).slice(0, 160) }, buckets: [] };
    }
  }
}

const eq = (column: string, value: string): string => `${encodeURIComponent(column)}=eq.${value}`;

/** select + filter that keep only rows owned by `uid`, or undefined when the table has no usable owner. */
function ownedBy(target: LiveTarget, uid: string): string | undefined {
  const direct = target.ownerColumns[0];
  if (direct) return `select=${encodeURIComponent(direct)}&${eq(direct, uid)}`;
  const via = target.ownedVia;
  if (!via) return undefined;
  // Inner-join the parent through this exact foreign key and keep rows whose parent belongs to uid.
  const embed = `owner_parent:${via.parent}!${via.column}!inner(${via.parentOwner})`;
  return `select=${encodeURIComponent(embed)}&${eq(`owner_parent.${via.parentOwner}`, uid)}`;
}

const SELECT_ALL = "select=*";

async function probeTable(p: Prober, target: LiveTarget): Promise<LiveTable> {
  const a = p.user("user-a").id;
  const b = p.user("user-b").id;
  const visible = {
    anon: await p.count("anon", target.name, SELECT_ALL),
    "user-a": await p.count("user-a", target.name, SELECT_ALL),
    "user-b": await p.count("user-b", target.name, SELECT_ALL),
  };
  const base = {
    kind: "live-table" as const,
    table: `public.${target.name}`,
    relation: target.relation,
    foundIn: target.foundIn,
    ownerColumns: target.ownerColumns,
    ...(target.ownedVia ? { ownedVia: target.ownedVia } : {}),
    visible,
  };
  if (Object.values(visible).every((c) => c.status === "missing")) {
    return { ...base, verdict: "missing", summary: "Not found on the live project.", leaks: [] };
  }
  const ofA = ownedBy(target, a);
  const ofB = ownedBy(target, b);
  if (!ofA || !ofB) {
    const anon = counted(visible.anon);
    return {
      ...base,
      verdict: "shared",
      summary: `No owner column, so these rows are treated as shared data${anon === undefined ? "." : `: a visitor sees ${rows(anon)}.`}`,
      leaks: [],
    };
  }

  const ownRowsA = await p.count("user-a", target.name, ofA);
  const ownRowsB = await p.count("user-b", target.name, ofB);
  const rowsOfA = target.ownerColumns.length
    ? { "user-b": await p.count("user-b", target.name, ofA), anon: await p.count("anon", target.name, ofA) }
    : undefined;

  const found: string[] = [];
  const leakSet = new Set<"anon" | "user-b">();
  const anonSees = counted(visible.anon) ?? 0;
  if (anonSees > 0) {
    leakSet.add("anon");
    const fromA = counted(rowsOfA?.anon);
    found.push(`${ACTOR_TEXT.anon} can read ${rows(anonSees)}${fromA ? ` (${fromA} of them user A's)` : ""}.`);
  }
  const bSees = counted(visible["user-b"]);
  const bOwn = counted(ownRowsB);
  const bOfA = counted(rowsOfA?.["user-b"]);
  const others = bSees !== undefined && bOwn !== undefined ? bSees - bOwn : undefined;
  if ((bOfA ?? 0) > 0 || (others ?? 0) > 0) {
    leakSet.add("user-b");
    found.push(bLeakText(bOfA, counted(ownRowsA), others));
  }
  if (found.length)
    return {
      ...base,
      ownRowsA,
      ownRowsB,
      ...(rowsOfA ? { rowsOfA } : {}),
      verdict: "leak",
      summary: found.join(" "),
      leaks: [...leakSet],
    };

  const aOwn = counted(ownRowsA);
  const bClosed = rowsOfA ? nothing(rowsOfA["user-b"]) : others === 0;
  const anonClosed = nothing(visible.anon);
  let verdict: LiveVerdict = "inconclusive";
  let summary: string;
  if (!aOwn) {
    summary =
      aOwn === 0
        ? "User A has no rows here, so there was nothing to protect. Add one in the app and run again."
        : `User A's own rows could not be counted (${reasonOf(ownRowsA)}).`;
  } else if (bClosed && anonClosed) {
    verdict = "protected";
    summary = `User A sees their ${rows(aOwn)}; user B and a visitor see none of them.`;
  } else {
    const unclear = [visible.anon, rowsOfA?.["user-b"] ?? visible["user-b"], ownRowsB].find(
      (c) => c && c.status !== "count" && c.status !== "blocked",
    );
    summary = `Not every try gave an answer (${reasonOf(unclear)}).`;
  }
  return { ...base, ownRowsA, ownRowsB, ...(rowsOfA ? { rowsOfA } : {}), verdict, summary, leaks: [] };
}

function reasonOf(c: LiveCount | undefined): string {
  if (!c) return "no answer";
  if (c.status === "inconclusive") return c.reason;
  if (c.status === "missing" || c.status === "blocked") return c.code;
  return `${c.n}`;
}

async function probeBucket(p: Prober, bucket: string, isPublic: boolean | undefined): Promise<LiveBucket> {
  const prefix = `${p.user("user-a").id}/`;
  const folderOfA = {
    anon: await p.listCount("anon", bucket, prefix),
    "user-a": await p.listCount("user-a", bucket, prefix),
    "user-b": await p.listCount("user-b", bucket, prefix),
  };
  const base = {
    kind: "live-bucket" as const,
    bucket,
    ...(isPublic === undefined ? {} : { public: isPublic }),
    folderOfA,
  };
  const own = counted(folderOfA["user-a"]);
  const leaks = (["anon", "user-b"] as const).filter((actor) => (counted(folderOfA[actor]) ?? 0) > 0);
  if (leaks.length) {
    const parts = leaks.map(
      (actor) => `${ACTOR_TEXT[actor]} can list ${counted(folderOfA[actor])} of the entries in user A's folder.`,
    );
    return { ...base, verdict: "leak", summary: parts.join(" "), leaks: [...leaks] };
  }
  if (!own) {
    return {
      ...base,
      verdict: "inconclusive",
      summary:
        own === 0
          ? `User A has nothing under \`<user A id>/\` in this bucket. Upload a file as user A and run again, or the app stores files another way.`
          : `User A's folder could not be listed (${reasonOf(folderOfA["user-a"])}).`,
      leaks: [],
    };
  }
  const closed = nothing(folderOfA.anon) && nothing(folderOfA["user-b"]);
  return {
    ...base,
    verdict: closed ? "protected" : "inconclusive",
    summary: closed
      ? `User A lists ${own} entr${own === 1 ? "y" : "ies"} in their folder; user B and a visitor list none.`
      : "Not every listing gave an answer.",
    leaks: [],
  };
}

/** Where the live project and the migrations disagree. */
export function driftOf(targets: LiveTarget[], tables: LiveTable[]): LiveDrift[] {
  const out: LiveDrift[] = [];
  const byName = new Map(tables.map((t) => [t.table, t]));
  for (const target of targets) {
    const live = byName.get(`public.${target.name}`);
    if (!live) continue;
    const table = live.table;
    if (live.verdict === "missing") {
      if (target.foundIn.includes("migrations")) {
        out.push({
          table,
          kind: "not-deployed",
          detail: "The migrations create it, the live project does not have it: a migration was not pushed.",
        });
      }
      continue;
    }
    if (!target.foundIn.includes("migrations")) {
      out.push({
        table,
        kind: "not-in-migrations",
        detail:
          "Only the generated types know it: it was made in the dashboard, so the repo scan, the local probe and the patches cannot see its policies.",
      });
      continue;
    }
    const local = target.local;
    if (!local || local.skipped) continue;
    const readLeaks = localLeaks(local).filter((c) => c.action === "select" && c.actor !== "owner");
    if (readLeaks.length && live.verdict === "protected") {
      out.push({
        table,
        kind: "fixed-outside-migrations",
        detail:
          "The migrations let other people read user A's rows, the live project does not. The fix was made in the dashboard: save it as a migration, or the next fresh database (a branch, staging, `db reset`) gets the hole back.",
      });
    } else if (!readLeaks.length && live.verdict === "leak") {
      out.push({
        table,
        kind: "opened-outside-migrations",
        detail:
          "The migrations keep users apart, the live project does not. A policy or grant was changed in the dashboard.",
      });
    }
  }
  return out;
}

export async function probeLive(options: LiveProbeOptions): Promise<LiveResult> {
  const origin = projectOrigin(options.project);
  const kind = keyKind(options.key);
  if (options.userA.email.trim().toLowerCase() === options.userB.email.trim().toLowerCase()) {
    throw new Error("user A and user B must be two different accounts");
  }
  const http = new LiveHttp(origin, { rate: 5, maxRequests: 600, timeoutMs: 15_000, ...options.http });
  const p = new Prober(http, options.key, kind);
  let result: LiveResult;
  try {
    await p.signIn("user-a", options.userA);
    await p.signIn("user-b", options.userB);
    if (p.user("user-a").id === p.user("user-b").id) throw new Error("user A and user B signed in as the same user");

    const tables: LiveTable[] = [];
    for (const target of options.targets) tables.push(await probeTable(p, target));

    const lists = {
      anon: await p.bucketList("anon"),
      "user-a": await p.bucketList("user-a"),
      "user-b": await p.bucketList("user-b"),
    };
    const flags = new Map<string, boolean>();
    for (const list of Object.values(lists)) for (const b of list.buckets) flags.set(b.id, b.public);
    const names = [...new Set([...options.buckets, ...flags.keys()])].sort();
    const buckets: LiveBucket[] = [];
    for (const name of names) buckets.push(await probeBucket(p, name, flags.get(name)));

    result = {
      project: origin,
      keyKind: kind,
      tables,
      buckets,
      bucketsVisible: { anon: lists.anon.count, "user-a": lists["user-a"].count, "user-b": lists["user-b"].count },
      rpcs: options.rpcs,
      drift: driftOf(options.targets, tables),
      requests: 0,
      notes: [],
    };
  } finally {
    await p.signOut();
  }
  // Counted after sign-out, so the report gives every request the probe sent.
  result.requests = http.sent;
  return result;
}
