import { parseGeneratedTypes, TYPES_FILES } from "../live/targets.ts";
import type { FixContext } from "../patches/fixers.ts";
import { balanced, statements, type SqlFile } from "../patches/sql.ts";
import { phiColumns, searchable } from "../phi/columns.ts";
import type { TableProbe } from "../probe/rls-probe.ts";
import type {
  HipaaControl,
  Location,
  PhiColumn,
  PhiResult,
  PhiTable,
  PhiTracker,
  RawFinding,
  ToolRun,
} from "../types.ts";

/**
 * The --phi pass: where health data lives (by column name), who could read it in the RLS probe, and the
 * code paths that copy it somewhere else: analytics and session replay on pages that show it, server
 * code that sends it to an AI, email or SMS vendor, logs, and public storage buckets. It reads files only.
 */

export const PHI_SCAN_VERSION = "1.0.0";
/** The day the checklist below was copied from Supabase's docs. */
export const HIPAA_DOCS_READ_ON = "2026-11-16";
export const HIPAA_DOCS_URL = "https://supabase.com/docs/guides/deployment/shared-responsibility-model";

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const word = (name: string): RegExp => new RegExp(String.raw`(?<![\w$])${escapeRegExp(name)}(?![\w$])`);
const lineAt = (text: string, index: number): number => text.slice(0, index).split("\n").length;
const bare = (table: string): string => table.replace(/^public\./, "");

const SOURCE = /\.(tsx?|jsx?|mjs|cjs|mts|vue|svelte|astro)$/;
const TEST = /(^|\/)(__tests__|tests?|e2e|__mocks__)\/|\.(test|spec)\.[cm]?[jt]sx?$/;
const TOOLING = /^[^/]*\.config\.[cm]?[jt]s$|(^|\/)scripts\//;
const SERVER =
  /^(supabase\/functions\/|(src\/)?app\/api\/|(src\/)?pages\/api\/|(src\/)?server\/|api\/|netlify\/functions\/)/;
/** Files that load on every page: a script started here runs wherever PHI is shown. */
const GLOBAL =
  /^(index\.html|public\/index\.html|(src\/)?main\.[jt]sx?|(src\/)?App\.[jt]sx?|(src\/)?index\.[jt]sx?|(src\/)?app\/layout\.[jt]sx?|(src\/)?pages\/_(app|document)\.[jt]sx?)$/;

const isServer = (f: string): boolean => SERVER.test(f);
const isClient = (f: string): boolean =>
  (SOURCE.test(f) || /(^|\/)index\.html$/.test(f)) && !isServer(f) && !TEST.test(f) && !TOOLING.test(f);

interface Tracker {
  vendor: string;
  pattern: RegExp;
  /** Session replay or heatmaps: what is on the screen goes to the vendor. */
  replay: (text: string) => boolean;
}

const always = (): boolean => true;
const never = (): boolean => false;

const TRACKERS: Tracker[] = [
  {
    vendor: "PostHog",
    pattern: /\bposthog\.init\s*\(/,
    // Replay is a project setting in PostHog; only `disable_session_recording: true` turns it off in code.
    replay: (text) => !/disable_session_recording\s*:\s*true/.test(text),
  },
  {
    vendor: "Sentry Session Replay",
    pattern: /\breplayIntegration\s*\(|\bnew\s+(?:Sentry\.)?Replay\s*\(/,
    replay: always,
  },
  { vendor: "Hotjar", pattern: /static\.hotjar\.com|@hotjar\/browser|\bHotjar\.init\s*\(/, replay: always },
  { vendor: "Microsoft Clarity", pattern: /clarity\.ms\/tag|@microsoft\/clarity|\bClarity\.init\s*\(/, replay: always },
  { vendor: "FullStory", pattern: /fullstory\.com\/s\/fs\.js|@fullstory\/browser/, replay: always },
  { vendor: "LogRocket", pattern: /\bLogRocket\.init\s*\(|cdn\.logrocket\.io/, replay: always },
  { vendor: "Google Analytics", pattern: /googletagmanager\.com\/gtag\/js|\bReactGA\.initialize\s*\(/, replay: never },
  { vendor: "Google Tag Manager", pattern: /googletagmanager\.com\/gtm\.js/, replay: never },
  { vendor: "Meta Pixel", pattern: /connect\.facebook\.net\/[^"']*fbevents\.js/, replay: never },
  { vendor: "Mixpanel", pattern: /\bmixpanel\.init\s*\(/, replay: never },
  { vendor: "Segment", pattern: /cdn\.segment\.com|@segment\/analytics-next/, replay: never },
  { vendor: "Lovable editor script", pattern: /cdn\.gpteng\.co\/gptengineer\.js/, replay: never },
];

/** Server-side vendors that commonly get app data: AI, email and SMS APIs. */
const VENDORS: { vendor: string; pattern: RegExp }[] = [
  { vendor: "OpenAI", pattern: /api\.openai\.com|from\s+["'](?:npm:)?openai(?:@[^"']*)?["']/ },
  { vendor: "Anthropic", pattern: /api\.anthropic\.com|from\s+["'](?:npm:)?@anthropic-ai\/sdk(?:@[^"']*)?["']/ },
  { vendor: "Google Gemini", pattern: /generativelanguage\.googleapis\.com|from\s+["'](?:npm:)?@google\/genai/ },
  { vendor: "Resend", pattern: /api\.resend\.com|from\s+["'](?:npm:)?resend(?:@[^"']*)?["']/ },
  { vendor: "SendGrid", pattern: /api\.sendgrid\.com|@sendgrid\/mail/ },
  { vendor: "Postmark", pattern: /api\.postmarkapp\.com|from\s+["'](?:npm:)?postmark/ },
  { vendor: "Mailgun", pattern: /api\.mailgun\.net|from\s+["'](?:npm:)?mailgun/ },
  { vendor: "Twilio", pattern: /api\.twilio\.com|from\s+["'](?:npm:)?twilio(?:@[^"']*)?["']/ },
];

/** Bucket names that say what they hold. */
const PHI_BUCKET =
  /(^|[-_])(labs?|lab-results|medical|patients?|records?|health|insurance|scans?|x-?rays?|imaging|prescriptions?|intake|charts?|referrals?)($|[-_])/i;

export interface PhiScan {
  result: PhiResult;
  findings: RawFinding[];
  tool: ToolRun;
}

/** PHI tables from the probe (migrations) and the generated types file; views inherit their columns' kinds. */
async function phiTables(ctx: FixContext, probed: TableProbe[]): Promise<{ tables: PhiTable[]; typesFile?: string }> {
  const byName = new Map<
    string,
    { relation: "table" | "view"; columns: string[]; foundIn: Set<"migrations" | "types"> }
  >();
  for (const t of probed) {
    byName.set(t.name, { relation: t.kind, columns: t.columns, foundIn: new Set(["migrations"]) });
  }
  let typesFile: string | undefined;
  for (const path of TYPES_FILES) {
    const text = await ctx.read(path);
    const schema = text ? parseGeneratedTypes(text) : undefined;
    if (!schema) continue;
    typesFile = path;
    for (const [relation, list] of [
      ["table", schema.tables],
      ["view", schema.views],
    ] as const) {
      for (const { name, columns } of list) {
        const entry = byName.get(name) ?? { relation, columns, foundIn: new Set() };
        entry.foundIn.add("types");
        byName.set(name, entry);
      }
    }
    break;
  }

  const tables: PhiTable[] = [];
  for (const [name, t] of byName) {
    if (t.relation !== "table") continue;
    const columns = phiColumns(name, t.columns);
    if (columns.length) tables.push(phiTable(name, "table", columns, t.foundIn, probed));
  }
  // A view over a PHI table shows the same data under the same column names.
  const known = new Map(tables.flatMap((t) => t.columns.map((c) => [c.name, c.kind] as const)));
  for (const [name, t] of byName) {
    if (t.relation !== "view") continue;
    const own = phiColumns(name, t.columns);
    const inherited = t.columns.flatMap((c): PhiColumn[] => {
      const kind = known.get(c);
      return kind && !own.some((o) => o.name === c) ? [{ name: c, kind }] : [];
    });
    const columns = [...own, ...inherited];
    if (columns.some((c) => c.kind === "health") || columns.filter((c) => c.kind === "identifier").length > 1) {
      tables.push(phiTable(name, "view", columns, t.foundIn, probed));
    }
  }
  tables.sort((a, b) => a.table.localeCompare(b.table));
  return { tables, typesFile };
}

function phiTable(
  name: string,
  relation: "table" | "view",
  columns: PhiColumn[],
  foundIn: Set<"migrations" | "types">,
  probed: TableProbe[],
): PhiTable {
  const probe = probed.find((p) => p.name === name);
  const reads = probe?.checks.filter((c) => c.action === "select" && c.actor !== "owner") ?? [];
  let access: Pick<PhiTable, "readBy" | "untested">;
  if (!probe || probe.skipped) access = { untested: "not in migrations" };
  else if (reads.some((c) => c.rows > 0)) {
    access = { readBy: [...new Set(reads.filter((c) => c.rows > 0).map((c) => c.actor as "anon" | "other-user"))] };
  } else if (reads.length && reads.every((c) => c.of > 0)) access = { readBy: [] };
  else access = { untested: "no rows to test" };
  return {
    table: `public.${name}`,
    relation,
    columns,
    foundIn: [...foundIn].sort(),
    ...access,
    audited: false,
  };
}

/** Triggers in the migrations that write a PHI table's changes to an audit table. */
export function auditedTables(migrations: SqlFile[]): Set<string> {
  const all = [...migrations].sort((a, b) => a.path.localeCompare(b.path)).flatMap((m) => statements(m.text));
  const auditFunctions = new Set(
    all.flatMap((s) => {
      const m = /^create\s+(?:or\s+replace\s+)?function\s+([\w."]+)\s*\(/i.exec(s);
      const name = m?.[1]?.replaceAll('"', "").replace(/^public\./, "");
      return name && /insert\s+into\s+[\w."]*(audit|history)/i.test(s) ? [name] : [];
    }),
  );
  const out = new Set<string>();
  for (const s of all) {
    const m =
      /^create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+("?[\w]+"?)\s+[\s\S]*?\bon\s+([\w."]+)[\s\S]*?\bexecute\s+(?:function|procedure)\s+([\w."]+)/i.exec(
        s,
      );
    if (!m) continue;
    const trigger = (m[1] ?? "").replaceAll('"', "");
    const table = (m[2] ?? "").replaceAll('"', "").replace(/^public\./, "");
    const fn = (m[3] ?? "").replaceAll('"', "").replace(/^public\./, "");
    if (/audit|history/i.test(trigger) || /audit|history/i.test(fn) || auditFunctions.has(fn)) out.add(table);
  }
  return out;
}

/** A source file that reads one of the PHI tables and names at least one PHI column. */
interface PhiUse {
  file: string;
  text: string;
  tables: string[];
  columns: string[];
}

function phiUse(file: string, text: string, tables: PhiTable[]): PhiUse | undefined {
  const read = tables.filter((t) => {
    const name = escapeRegExp(bare(t.table));
    return new RegExp(String.raw`\.from\(\s*["'\`]${name}["'\`]|["'\`(,\s]${name}\s*\(`).test(text);
  });
  if (!read.length) return undefined;
  const columns = [...new Set(read.flatMap((t) => searchable(t.columns)).filter((c) => word(c).test(text)))];
  return columns.length ? { file, text, tables: read.map((t) => t.table), columns } : undefined;
}

const list = (names: string[]): string => names.map((n) => `\`${n}\``).join(", ");
const at = (file: string, line: number): Location => ({ kind: "file", file, line });

function trackerFindings(
  uses: PhiUse[],
  ctx: FixContext,
  texts: Map<string, string>,
): { trackers: PhiTracker[]; findings: RawFinding[] } {
  const trackers: PhiTracker[] = [];
  const findings: RawFinding[] = [];
  const pages = uses.filter((u) => isClient(u.file));
  for (const file of ctx.files.filter(isClient)) {
    const text = texts.get(file);
    if (!text) continue;
    for (const tracker of TRACKERS) {
      const match = tracker.pattern.exec(text);
      if (!match) continue;
      const where = GLOBAL.test(file) ? pages : pages.filter((p) => p.file === file);
      if (!where.length) continue;
      const line = lineAt(text, match.index);
      const replay = tracker.replay(text);
      trackers.push({ vendor: tracker.vendor, file, line, replay, pages: where.map((p) => p.file) });
      const fields = [...new Set(where.flatMap((p) => p.columns))];
      findings.push({
        source: "phi-scan",
        rule: replay ? "phi-session-replay" : "phi-analytics",
        toolSeverity: replay ? "replay" : "analytics",
        message: `${tracker.vendor} loads ${GLOBAL.test(file) ? "on every page" : "on this page"}${replay ? " and can record the screen" : ""}, including ${list(where.map((p) => p.file))}, which show ${list(fields)}.`,
        location: at(file, line),
        subject: tracker.vendor,
        phi: fields,
      });
    }
  }
  return { trackers, findings };
}

function vendorFindings(uses: PhiUse[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const use of uses.filter((u) => isServer(u.file))) {
    for (const { vendor, pattern } of VENDORS) {
      const match = pattern.exec(use.text);
      if (!match) continue;
      out.push({
        source: "phi-scan",
        rule: "phi-vendor-egress",
        toolSeverity: "egress",
        message: `\`${use.file}\` reads ${list(use.tables)} and calls ${vendor}; the code handles ${list(use.columns)}.`,
        location: at(use.file, lineAt(use.text, match.index)),
        subject: `${vendor} (${use.file})`,
        phi: use.columns,
      });
    }
  }
  return out;
}

/** Names that hold PHI rows in a file: `data: appointment`, the PHI table names, and the PHI columns. */
function phiNames(use: PhiUse): string[] {
  const bound = [...use.text.matchAll(/\bdata\s*:\s*([A-Za-z_$][\w$]*)/g)].map((m) => m[1] ?? "");
  const tables = use.tables.flatMap((t) => [bare(t), bare(t).replace(/s$/, "")]);
  return [...new Set([...bound, ...tables, ...use.columns])];
}

/** Code without string contents: quoted text goes, the `${…}` expressions of template literals stay. */
export function codeOnly(code: string): string {
  return code
    .replace(/`(?:\\[\s\S]|[^`\\])*`/g, (t) => [...t.matchAll(/\$\{([^}]*)\}/g)].map((m) => ` ${m[1]} `).join(""))
    .replace(/(["'])(?:\\.|(?!\1).)*\1/g, "");
}

/** Values of one VALUES tuple: commas inside quotes, brackets or parentheses do not split. */
function splitValues(tuple: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quoted = false;
  let current = "";
  for (const ch of tuple) {
    if (ch === "'") quoted = !quoted;
    else if (!quoted && (ch === "(" || ch === "[")) depth += 1;
    else if (!quoted && (ch === ")" || ch === "]")) depth -= 1;
    if (ch === "," && !quoted && depth === 0) {
      out.push(current.trim());
      current = "";
    } else current += ch;
  }
  out.push(current.trim());
  return out;
}

function logFindings(uses: PhiUse[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const use of uses.filter((u) => isServer(u.file))) {
    const names = phiNames(use);
    const calls: number[] = [];
    let logged: string[] = [];
    for (const m of use.text.matchAll(/\bconsole\.(log|info|warn|error|debug)\s*\(/g)) {
      const args = balanced(use.text, m.index + m[0].length - 1) ?? "";
      const hits = names.filter((n) => word(n).test(codeOnly(args)));
      if (!hits.length) continue;
      calls.push(lineAt(use.text, m.index));
      logged = [...new Set([...logged, ...hits])];
    }
    const first = calls[0];
    if (first === undefined) continue;
    out.push({
      source: "phi-scan",
      rule: "phi-in-logs",
      toolSeverity: "log",
      message: `\`${use.file}\` writes ${list(logged)} to the function log (line${calls.length > 1 ? "s" : ""} ${calls.join(", ")}).`,
      location: at(use.file, first),
      subject: `logs (${use.file})`,
      phi: use.columns,
    });
  }
  return out;
}

interface Bucket {
  id: string;
  public: boolean;
  file: string;
  line: number;
}

/** Buckets from `insert into storage.buckets` in the migrations and `[storage.buckets.<id>]` in config.toml. */
export function bucketsOf(migrations: SqlFile[], config: string | undefined): Bucket[] {
  const out: Bucket[] = [];
  for (const file of [...migrations].sort((a, b) => a.path.localeCompare(b.path))) {
    // A later `update storage.buckets set public = … where id = '…'` (a fix migration) wins.
    for (const m of file.text.matchAll(
      /update\s+storage\.buckets\s+set\s+public\s*=\s*(true|false)\s+where\s+id\s*=\s*'([^']+)'/gi,
    )) {
      for (const bucket of out.filter((b) => b.id === m[2])) bucket.public = m[1]?.toLowerCase() === "true";
    }
    const head = /insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*/gi;
    for (const m of file.text.matchAll(head)) {
      const columns = (m[1] ?? "").split(",").map((c) => c.trim().replaceAll('"', "").toLowerCase());
      const idAt = columns.indexOf("id");
      const publicAt = columns.indexOf("public");
      let i = m.index + m[0].length;
      while (file.text[i] === "(") {
        const tuple = balanced(file.text, i) ?? "";
        const values = splitValues(tuple);
        const id = values[idAt]?.replace(/^'|'$/g, "");
        if (id)
          out.push({
            id,
            public: /^true$/i.test(values[publicAt] ?? ""),
            file: file.path,
            line: lineAt(file.text, m.index),
          });
        i += tuple.length + 2;
        while (/[\s,]/.test(file.text[i] ?? "")) i += 1;
      }
    }
  }
  if (config) {
    let current: { id: string; line: number } | undefined;
    config.split(/\r?\n/).forEach((raw, index) => {
      const line = raw.replace(/#.*$/, "").trim();
      const table = /^\[\s*storage\.buckets\.("?)([\w-]+)\1\s*\]$/.exec(line);
      if (table) current = { id: table[2] ?? "", line: index + 1 };
      else if (line.startsWith("[")) current = undefined;
      else if (current && /^public\s*=\s*true$/.test(line)) {
        out.push({ id: current.id, public: true, file: "supabase/config.toml", line: current.line });
      }
    });
  }
  return out;
}

function bucketFindings(
  buckets: Bucket[],
  ctx: FixContext,
  texts: Map<string, string>,
  tables: PhiTable[],
): RawFinding[] {
  const out: RawFinding[] = [];
  const phiWords = tables.flatMap((t) => [bare(t.table), bare(t.table).replace(/s$/, ""), ...searchable(t.columns)]);
  for (const bucket of buckets.filter((b) => b.public)) {
    const uploaders = ctx.files.filter((f) => {
      const text = texts.get(f);
      return text?.includes(`from("${bucket.id}")`) || text?.includes(`from('${bucket.id}')`);
    });
    const phiUploaders = uploaders.filter((f) => {
      const text = texts.get(f) ?? "";
      return phiWords.some((w) => new RegExp(String.raw`(?<![A-Za-z])${escapeRegExp(w)}(?![a-z])`, "i").test(text));
    });
    const byName = PHI_BUCKET.test(bucket.id);
    if (!byName && !phiUploaders.length) continue;
    const why = [
      byName ? "its name says it holds health records" : "",
      phiUploaders.length
        ? `${list(phiUploaders)} upload${phiUploaders.length > 1 ? "" : "s"} patient files to it`
        : "",
    ].filter(Boolean);
    out.push({
      source: "phi-scan",
      rule: "phi-public-bucket",
      toolSeverity: "public",
      message: `Storage bucket \`${bucket.id}\` is public and ${why.join(", and ")}.`,
      location: at(bucket.file, bucket.line),
      subject: bucket.id,
    });
  }
  return out;
}

function auditFinding(tables: PhiTable[], migrations: SqlFile[]): RawFinding | undefined {
  const missing = tables.filter((t) => t.relation === "table" && t.foundIn.includes("migrations") && !t.audited);
  const first = missing[0];
  if (!first) return undefined;
  const created = new RegExp(
    String.raw`create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?${escapeRegExp(bare(first.table))}"?[\s(]`,
    "i",
  );
  const file = [...migrations].sort((a, b) => a.path.localeCompare(b.path)).find((m) => created.test(m.text));
  return {
    source: "phi-scan",
    rule: "phi-no-audit-log",
    toolSeverity: "missing",
    message: `No audit trail of changes to the tables with health data: ${list(missing.map((t) => t.table))}.`,
    location: file
      ? at(file.path, lineAt(file.text, file.text.search(created)))
      : at(migrations[0]?.path ?? "supabase/migrations", 1),
    subject: "phi-audit-log",
  };
}

async function unmanagedFindings(
  tables: PhiTable[],
  ctx: FixContext,
  typesFile: string | undefined,
): Promise<RawFinding[]> {
  if (!typesFile) return [];
  const text = (await ctx.read(typesFile)) ?? "";
  return tables
    .filter((t) => t.relation === "table" && !t.foundIn.includes("migrations"))
    .map((t) => {
      const index = text.search(new RegExp(String.raw`(?<![\w$"])"?${escapeRegExp(bare(t.table))}"?\s*:\s*\{`));
      return {
        source: "phi-scan" as const,
        rule: "phi-table-unmanaged",
        toolSeverity: "unmanaged",
        message: `\`${t.table}\` is in the generated types with ${list(searchable(t.columns))}, but no migration creates it or sets its policies.`,
        location: at(typesFile, index >= 0 ? lineAt(text, index) : 1),
        subject: t.table,
        phi: t.columns.map((c) => c.name),
      };
    });
}

/** Supabase's customer-side list for health data, with what the scan could see for the repo items. */
function hipaaControls(findings: RawFinding[], tables: PhiTable[]): HipaaControl[] {
  const dashboard = (control: string, detail: string): HipaaControl => ({
    control,
    where: "dashboard",
    status: "confirm",
    detail,
  });
  const buckets = findings.filter((f) => f.rule === "phi-public-bucket").map((f) => f.subject ?? "");
  const vendors = [
    ...new Set(
      findings
        .filter((f) => f.rule === "phi-vendor-egress" || f.rule === "phi-session-replay" || f.rule === "phi-analytics")
        .map((f) => (f.subject ?? "").replace(/ \(.*\)$/, "")),
    ),
  ];
  const unaudited = tables.filter((t) => t.relation === "table" && t.foundIn.includes("migrations") && !t.audited);
  return [
    dashboard(
      "Sign a Business Associate Agreement (BAA) with Supabase",
      "Needs the Team plan or above and the HIPAA add-on (request form in the Supabase docs).",
    ),
    dashboard(
      "Mark the project as High Compliance and fix what the Security Advisor raises",
      "Project settings, General.",
    ),
    dashboard("MFA on every Supabase account, enforced for the organization", "Organization settings."),
    dashboard("Point in Time Recovery on", "Database backups settings."),
    dashboard("SSL Enforcement on", "Database settings."),
    dashboard(
      "Network Restrictions on",
      "Database settings: allow only the addresses that need direct database access.",
    ),
    dashboard(
      "Postgres connection logging kept on",
      "Supabase sets log_connections off by default for new projects; the Security Advisor warns when it is off.",
    ),
    dashboard(
      "Encryption as the HIPAA Security Rule asks",
      "Supabase encrypts data at rest and in transit; consider encrypting the most sensitive columns in the app as well.",
    ),
    {
      control: "No PHI in public Storage buckets",
      where: "repo",
      status: buckets.length ? "gap" : "ok",
      detail: buckets.length
        ? `Public buckets that hold health files: ${buckets.join(", ")}.`
        : "No public bucket in the migrations or config.toml looks like it holds health files.",
    },
    dashboard("Never transfer the project to an organization without the HIPAA add-on", "Organization settings."),
    {
      control: "A BAA with every other vendor that receives PHI (beyond the Supabase list)",
      where: "repo",
      status: vendors.length ? "gap" : "ok",
      detail: vendors.length
        ? `The code sends health data to, or loads on health pages: ${vendors.join(", ")}. Each needs a signed BAA or has to stop getting the data.`
        : "No analytics, replay, AI, email or SMS vendor call with PHI fields was found in the code.",
    },
    {
      control: "Audit trail of who changed health records (HIPAA Security Rule, audit controls)",
      where: "repo",
      status: unaudited.length ? "gap" : "ok",
      detail: unaudited.length
        ? `No audit trigger on ${unaudited.map((t) => t.table).join(", ")}.`
        : "Every PHI table in the migrations has an audit trigger.",
    },
  ];
}

/** The PHI pass. `probed` is what the RLS probe loaded from the migrations (empty when it did not run). */
export async function runPhiScan(ctx: FixContext, probed: TableProbe[]): Promise<PhiScan> {
  const { tables, typesFile } = await phiTables(ctx, probed);
  const audited = auditedTables(ctx.migrations);
  for (const t of tables) t.audited = audited.has(bare(t.table));

  const texts = new Map<string, string>();
  for (const file of ctx.files) {
    if ((SOURCE.test(file) || /(^|\/)index\.html$/.test(file)) && !TEST.test(file)) {
      const text = await ctx.read(file);
      if (text !== undefined) texts.set(file, text);
    }
  }
  const uses = [...texts].flatMap(([file, text]) => phiUse(file, text, tables) ?? []);

  const { trackers, findings: trackerRaws } = trackerFindings(uses, ctx, texts);
  const findings: RawFinding[] = [
    ...trackerRaws,
    ...vendorFindings(uses),
    ...logFindings(uses),
    ...bucketFindings(bucketsOf(ctx.migrations, await ctx.read("supabase/config.toml")), ctx, texts, tables),
    ...(await unmanagedFindings(tables, ctx, typesFile)),
  ];
  const audit = auditFinding(tables, ctx.migrations);
  if (audit) findings.push(audit);

  return {
    result: { tables, trackers, controls: hipaaControls(findings, tables), docsReadOn: HIPAA_DOCS_READ_ON },
    findings,
    tool: {
      name: "phi-scan",
      version: PHI_SCAN_VERSION,
      command: "prelaunch-audit --phi (PHI column map by name, trackers, vendor calls, logs, buckets, audit triggers)",
      status: "ok",
      note: `${tables.length} tables and views with health data by column name; ${uses.length} source files read and use them.`,
    },
  };
}

/** Marks findings about PHI tables so the rubric can rate a read of health data as Critical. */
export function markPhi(raws: RawFinding[], tables: PhiTable[]): void {
  const byTable = new Map(tables.map((t) => [t.table, t.columns.map((c) => c.name)]));
  for (const raw of raws) {
    const columns = raw.subject ? byTable.get(raw.subject) : undefined;
    if (columns && !raw.phi) raw.phi = columns;
  }
}
