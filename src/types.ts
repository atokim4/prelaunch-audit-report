export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export type Source = "vibe-preflight" | "launch-audit" | "secret-scan";

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

export interface AuditResult {
  schema: "prelaunch-audit/v1";
  app: { name: string; repo: string; url?: string };
  generatedAt: string;
  counts: Record<Severity, number>;
  findings: Finding[];
  tools: ToolRun[];
  notChecked: string[];
}
