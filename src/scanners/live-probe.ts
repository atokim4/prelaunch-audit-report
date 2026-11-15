import { LIVE_PROBE_VERSION, probeLive, type LiveUser } from "../live/probe.ts";
import {
  liveTargets,
  migrationFunctions,
  parseGeneratedTypes,
  TYPES_FILES,
  type GeneratedSchema,
} from "../live/targets.ts";
import type { FixContext } from "../patches/fixers.ts";
import type { ProbeResult } from "../probe/rls-probe.ts";
import type { LiveResult, RawFinding, ToolRun } from "../types.ts";
import { TABLE_RULES } from "./rls-probe.ts";

export interface LiveOptions {
  project: string;
  key: string;
  userA: LiveUser;
  userB: LiveUser;
  rate?: number;
  maxRequests?: number;
}

/** Buckets the code or the migrations name: `storage.from("x")`, `insert into storage.buckets … values ('x'`. */
async function bucketNames(ctx: FixContext): Promise<string[]> {
  const out = new Set<string>();
  const code = ctx.files.filter((f) => /\.(m?[jt]sx?)$/.test(f) && !f.includes("node_modules/"));
  for (const file of code) {
    const text = (await ctx.read(file)) ?? "";
    for (const m of text.matchAll(/\.storage\s*\.from\(\s*["'`]([\w.-]+)["'`]\s*\)/g)) if (m[1]) out.add(m[1]);
  }
  for (const { text } of ctx.migrations) {
    for (const m of text.matchAll(/insert\s+into\s+storage\.buckets\s*(?:\([^)]*\))?\s*values\s*\(\s*'([^']+)'/gi)) {
      if (m[1]) out.add(m[1]);
    }
  }
  return [...out].sort();
}

async function generatedTypes(ctx: FixContext): Promise<{ file: string; schema: GeneratedSchema } | undefined> {
  for (const file of TYPES_FILES) {
    const text = await ctx.read(file);
    const schema = text === undefined ? undefined : parseGeneratedTypes(text);
    if (schema) return { file, schema };
  }
  return undefined;
}

const NOTES = [
  "Read-only. Row counts come from HEAD requests with `Prefer: count=exact`, so no row is ever downloaded; storage folders are listed and only the number of entries is kept. Nothing was inserted, updated or deleted, and no RPC function was called.",
  "The two test users signed in with the password grant, which opens a normal session for each; both sessions were signed out at the end.",
  "Only 42501 (permission denied) or a row-level security refusal counts as blocked. A 401, a timeout or any other error is inconclusive and proves nothing either way.",
];

export async function runLiveProbe(
  options: LiveOptions,
  ctx: FixContext,
  local: ProbeResult | undefined,
): Promise<{ result?: LiveResult; tool: ToolRun; note?: string }> {
  const tool: ToolRun = {
    name: "live-probe",
    version: LIVE_PROBE_VERSION,
    command: "prelaunch-audit --live <project> --i-own-this-project (read-only counts as a visitor and two test users)",
    status: "ok",
  };
  const types = await generatedTypes(ctx);
  const targets = liveTargets(local?.error ? undefined : local?.tables, types?.schema);
  if (!targets.length) {
    return {
      tool: {
        ...tool,
        status: "skipped",
        note: `No table list: no migrations loaded and no generated types file (${TYPES_FILES[0]}).`,
      },
      note: "The live project: the repo gave no table list (no migrations that load, no generated types), so it was not probed.",
    };
  }
  const definer = migrationFunctions(ctx.migrations);
  const rpcNames = new Set([...definer.keys(), ...(types?.schema.functions ?? [])]);
  const rpcs = [...rpcNames].sort().map((name) => ({
    name,
    securityDefiner: definer.get(name) ?? false,
    foundIn: [
      ...(definer.has(name) ? (["migrations"] as const) : []),
      ...(types?.schema.functions.includes(name) ? (["types"] as const) : []),
    ],
  }));
  try {
    const result = await probeLive({
      project: options.project,
      key: options.key,
      userA: options.userA,
      userB: options.userB,
      targets,
      buckets: await bucketNames(ctx),
      rpcs,
      http: {
        ...(options.rate ? { rate: options.rate } : {}),
        ...(options.maxRequests ? { maxRequests: options.maxRequests } : {}),
      },
    });
    result.notes = [
      `Tables from ${[local?.tables.length ? "the migrations" : "", types ? types.file : ""].filter(Boolean).join(" and ")}.`,
      ...NOTES,
    ];
    const tried = result.tables.filter((t) => t.verdict !== "missing").length;
    tool.note = `${tried} tables and views and ${result.buckets.length} storage bucket${result.buckets.length === 1 ? "" : "s"} on ${result.project}, ${result.requests} requests.`;
    return { result, tool };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      tool: { ...tool, status: "failed", note: reason },
      note: `The live project was not probed: ${reason}.`,
    };
  }
}

/**
 * Adds what the live project did to the findings about the same table, and turns live leaks that no
 * repo finding explains (changed in the dashboard, or a table the migrations never made) into findings.
 */
export function mergeLive(raws: RawFinding[], live: LiveResult): RawFinding[] {
  const out: RawFinding[] = [];
  for (const table of live.tables) {
    const covering = raws.filter(
      (r) => r.subject === table.table && (TABLE_RULES.has(r.rule) || r.rule === "rls-probe-leak"),
    );
    for (const raw of covering) raw.live = table;
    if (covering.length || table.verdict !== "leak") continue;
    out.push({
      source: "live-probe",
      rule: "live-rls-leak",
      toolSeverity: table.leaks.includes("anon") ? "anon" : "user-b",
      message: `Live project, \`${table.table}\`: ${table.summary}${table.relation === "view" ? " This is a view: it shows what the tables under it let through (or bypasses their policies if it was made without `security_invoker`), so fix it there." : ""}`,
      location: { kind: "url", url: `${live.project}/rest/v1/${table.table.replace(/^public\./, "")}` },
      subject: table.table,
      live: table,
    });
  }
  for (const bucket of live.buckets.filter((b) => b.verdict === "leak")) {
    out.push({
      source: "live-probe",
      rule: "live-storage-leak",
      toolSeverity: bucket.leaks.includes("anon") ? "anon" : "user-b",
      message: `Live project, bucket \`${bucket.bucket}\`: ${bucket.summary}`,
      location: { kind: "url", url: `${live.project}/storage/v1/object/list/${bucket.bucket}` },
      subject: `storage:${bucket.bucket}`,
      live: bucket,
    });
  }
  return out;
}
