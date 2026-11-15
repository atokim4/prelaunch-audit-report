export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export type Source = "vibe-preflight" | "launch-audit" | "secret-scan" | "rls-probe" | "project-config" | "npm-audit";

export type Effort = "under 1 hour" | "1-4 hours" | "half a day to a day";

export interface Cwe {
  id: number;
  name: string;
}

/** Where a finding lives: a line in the repo, or a response from the live site. */
export type Location = { kind: "file"; file: string; line: number } | { kind: "url"; url: string };

/** What a scanner reported, before the report layer adds severity, CWE and prose. */
export interface RawFinding {
  source: Source;
  rule: string;
  /** The scanner's own level, kept for the appendix. */
  toolSeverity: string;
  message: string;
  location: Location;
  /** Database object or env name the finding is about, when the scanner names one. Used to dedupe. */
  subject?: string;
  /** Extra detail from the scanner (URL checks carry their own title and fix). */
  title?: string;
  fix?: string;
  /** RLS probe result for the table this finding is about. */
  proof?: Proof;
  /** CWE the scanner itself gives ("CWE-405"), for sources with their own advisories. */
  cwe?: string;
}

export type Actor = "anon" | "other-user" | "owner";
export type Action = "select" | "insert" | "update" | "delete";

/** One try of the RLS probe: an actor doing an action on user A's rows, inside a rolled-back transaction. */
export interface ProbeCheck {
  actor: Actor;
  action: Action;
  /** Column the owner tried to change on their own row (privilege escalation check only). */
  column?: string;
  /** Rows of user A the actor read or changed; for insert, 1 when a row in A's name got in. */
  rows: number;
  /** Rows of user A in the table (for insert: 1). */
  of: number;
  /** Why Postgres refused, when it did (permission denied, policy violation). */
  refused?: string;
  /** The try failed for another reason (a constraint the guessed values broke): neither leak nor block. */
  inconclusive?: string;
}

/** A row with no owner column of its own that belongs to whoever owns its parent row. */
export interface OwnedVia {
  column: string;
  parent: string;
  parentColumn: string;
  /** The parent's own owner columns; empty when the parent is itself owned through a parent. */
  parentOwners: string[];
}

export interface ProbePolicy {
  name: string;
  command: "select" | "insert" | "update" | "delete" | "all";
  roles: string[];
  using?: string;
  withCheck?: string;
}

/** What the RLS probe saw for one table or view. */
export interface Proof {
  table: string;
  kind: "table" | "view";
  /** Columns that tie a row to a user. Empty with no ownedVia: shared data (price list, settings). */
  ownerColumns: string[];
  ownedVia?: OwnedVia;
  checks: ProbeCheck[];
  /** The checks that got through. */
  leaks: ProbeCheck[];
  policies: ProbePolicy[];
  /** Leaks still there after every patch in the report was applied, in the same harness. */
  afterPatches?: ProbeCheck[];
}

export interface Patch {
  /** Unified diff, paths relative to the repo root (applies with `git apply`). */
  diff: string;
  /** What the patch does, one or two sentences. */
  summary: string;
  /** Things to check after applying, because the generator cannot know them. */
  caveats: string[];
  /** `git apply --check` passed against the audited tree. */
  verified: boolean;
  /** Set when the patch closes the exposure but leaves work only a person can do; says what is left. */
  partial?: string;
}

export interface Finding {
  /** Stable within one report: PA-01, PA-02… in severity order. */
  id: string;
  source: Source;
  rule: string;
  severity: Severity;
  title: string;
  cwe?: Cwe;
  location: Location;
  /** The scanner's message, plus the offending line when there is one. */
  evidence: string;
  snippet?: string;
  whyItMatters: string;
  fix: string;
  effort: Effort;
  patch?: Patch;
  /** Subject the scanner named (table, view, function, env name), when it named one. */
  subject?: string;
  /** What the RLS probe could actually do with this table. */
  proof?: Proof;
  /** Other rules that flagged the same thing and were folded into this finding. */
  alsoFlaggedBy: string[];
}

export interface ToolRun {
  name: string;
  version: string;
  command: string;
  status: "ok" | "skipped" | "failed";
  note?: string;
}

export interface EdgeFunction {
  name: string;
  path: string;
  /** From supabase/config.toml; Supabase's default is true. */
  verifyJwt: boolean;
}

export interface ProjectShape {
  framework: "next-app-router" | "next-pages-router" | "vite-react" | "react" | "unknown";
  /** Human label for the cover: "Vite + React single-page app". */
  label: string;
  migrations: number;
  edgeFunctions: EdgeFunction[];
}

export interface AuditResult {
  schema: "prelaunch-audit/v1";
  app: { name: string; repo: string; url?: string; shape: ProjectShape };
  generatedAt: string;
  counts: Record<Severity, number>;
  findings: Finding[];
  tools: ToolRun[];
  /** Every table and view the RLS probe tried, leaking or not (the access matrix). */
  probe?: Proof[];
  notChecked: string[];
}
