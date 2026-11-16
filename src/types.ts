export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export type Source =
  | "vibe-preflight"
  | "launch-audit"
  | "secret-scan"
  | "rls-probe"
  | "project-config"
  | "npm-audit"
  | "live-probe"
  | "phi-scan";

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
  /** What the read-only probe of the live Supabase project saw for this table or bucket. */
  live?: LiveTable | LiveBucket;
  /** With --phi: the health-data columns of the table or the code this finding is about. */
  phi?: string[];
  /** What the repo's SQL says about the object, for findings the probe has no proof for. */
  context?: StaticContext;
  /** The column the row's owner can write decides admin access (see scanners/admin-gate.ts). */
  adminGate?: AdminGate;
}

/** A role column that policies use to grant admin access, and where the SQL shows it. */
export interface AdminGate {
  /** `public.<name>`, lower case. */
  table: string;
  column: string;
  /** How it decides access, in words: the helper function and the policy that calls it. */
  via: string;
  location: Location;
}

/** Read from the create table / create function statements, never from running anything. */
export interface StaticContext {
  /** The table has a column that ties rows to a user (references auth.users, user_id, owner_id…). */
  tableOwned?: boolean;
  /** The table has columns the PHI map or the identifier list would call personal (email, phone, dob…). */
  tablePersonal?: boolean;
  /** The function reads the caller's identity (auth.uid() or auth.jwt()) in its body. */
  checksCaller?: boolean;
  /** The user-editable plan column points to a plan table with no pricing column. */
  carePlan?: boolean;
  /** The public bucket's name says it holds site content. */
  publicContentBucket?: boolean;
}

/**
 * "other-user" is user B. With an organization (team, workspace) model, B is an admin of a second
 * organization and "non-member" is a signed-in user C who belongs to none; "owner" is then user A as a
 * plain member of organization A.
 */
export type Actor = "anon" | "other-user" | "owner" | "non-member";
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
  /**
   * Membership tries: "self-join" is user B adding themselves to organization A; "move-tenant" is user A
   * moving their own membership row to organization B.
   */
  scenario?: "self-join" | "move-tenant";
}

/**
 * A positive check: a legitimate user reaching their own rows. Without one, "nobody else got in" could just
 * mean nobody gets in at all. "owner" is user A on their own rows (a plain member on organization A's rows);
 * "org-admin" is user B, an admin of organization B, on organization B's own row and membership.
 */
export interface AccessCheck {
  who: "owner" | "org-admin";
  action: "select" | "update";
  /** Rows the user read or changed. */
  rows: number;
  /** Rows of theirs in the table. */
  of: number;
  refused?: string;
  inconclusive?: string;
}

/**
 * What the probe can say about one table:
 * - leak: someone else got through;
 * - protected: nobody else got through, rows were tried, and the legitimate user still reads their own;
 * - locked: nobody else got through, but the legitimate user cannot read their own rows either (server-only
 *   table, a role the probe did not hold, an over-tight policy, a missing grant), so "no leak" proves little;
 * - shared: no owner column (price lists, settings), only writes count;
 * - untested: no rows of the user to try, or the positive try failed for another reason.
 */
export type AccessVerdict = "leak" | "protected" | "locked" | "shared" | "untested";

/** The membership table of an organization (team, workspace) model. */
export interface Membership {
  /** `public.<name>`. */
  table: string;
  tenantColumn: string;
  userColumn: string;
  roleColumn?: string;
  /** Role values that manage the organization (owner, admin); empty when the schema does not say. */
  adminRoles: string[];
  /** The plain member value the probe gave user A. */
  memberRole?: string;
  /**
   * Set when the schema's admin check reads the role without the organization column (a hospital-wide
   * admin): the function or policy that shows it. User B is then a plain member of organization B, since an
   * app-wide admin reaching every organization is the design, not a leak.
   */
  globalAdmin?: string;
}

/** How one table's rows belong to an organization. */
export interface TenantLink {
  /** The organization table, `public.<name>`, its key column and the key's type. */
  tenant: string;
  tenantKey: string;
  tenantKeyType: string;
  members: Membership;
  via:
    | { kind: "tenant" }
    | { kind: "members" }
    | { kind: "column"; column: string }
    | { kind: "parent"; column: string; parent: string; parentColumn: string; parentTenantColumn?: string };
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
  /** Rows belong to an organization: members of it may reach them, nobody else. */
  tenant?: TenantLink;
  checks: ProbeCheck[];
  /** The checks that got through. */
  leaks: ProbeCheck[];
  policies: ProbePolicy[];
  /** Positive checks: the legitimate user on their own rows. */
  access: AccessCheck[];
  /**
   * Organization rows that visitors only read, through a select policy written for them (`to anon`, or a
   * name such as "Public can view…"), on a table with no personal or health columns: the name of that
   * policy. Reads as a public listing.
   */
  publicListing?: string;
  /** No owner, and the only leak is visitors inserting through a column-limited grant (telemetry, a form). */
  anonInsertByDesign?: boolean;
  verdict: AccessVerdict;
  /** Leaks still there after every patch in the report was applied, in the same harness. */
  afterPatches?: ProbeCheck[];
  /** The positive checks in the patched harness. */
  afterAccess?: AccessCheck[];
  /** Reads that passed before the patches and fail after: a patch locks the legitimate user out. */
  lockedOut?: AccessCheck[];
  /** Updates that passed before the patches and fail after: writes moved to the server (said, not failed). */
  writesLost?: AccessCheck[];
  /** A patch took this relation off the public API on purpose, so lost reads are the fix. */
  offApi?: boolean;
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
  /** The patch takes this relation off the public API on purpose. */
  offApi?: string;
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
  /** What the read-only probe of the live project saw for the same table or bucket. */
  live?: LiveTable | LiveBucket;
  /** With --phi: the health-data columns involved (PHI on a table, or PHI fields the code handles). */
  phi?: string[];
  /** Set when the column the user can write decides admin access. */
  adminGate?: AdminGate;
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
  /** The consented, read-only probe of the client's own Supabase project. */
  live?: LiveResult;
  /** With --phi: where health data lives and the Supabase HIPAA checklist. */
  phi?: PhiResult;
  notChecked: string[];
}

/** "health": clinical content (diagnosis, medication). "identifier": ties a record to a person (dob, MRN, SSN). */
export type PhiKind = "health" | "identifier";

export interface PhiColumn {
  name: string;
  kind: PhiKind;
}

/** A table or view that holds protected health information, by its column names. */
export interface PhiTable {
  table: string;
  relation: "table" | "view";
  columns: PhiColumn[];
  foundIn: ("migrations" | "types")[];
  /** Who could read user A's rows in the local RLS probe; undefined when the probe could not tell. */
  readBy?: ("anon" | "other-user")[];
  /**
   * Why there is no readBy: not in the migrations, in repo SQL the probe could not load (another folder,
   * or a migration that failed in PGlite), or user A had no row to read (a view's filter).
   */
  untested?: "not in migrations" | "not probed" | "no rows to test";
  /** Nobody else read it, but user A could not read their own rows either: no proof the policies work. */
  locked?: boolean;
  /** A trigger in the migrations writes changes of this table to an audit table. */
  audited: boolean;
}

/** A third-party script loaded on pages that show PHI. */
export interface PhiTracker {
  vendor: string;
  file: string;
  line: number;
  /** Records the screen (session replay), not only page views and events. */
  replay: boolean;
  /** Client files that read and show PHI fields, where this script runs too. */
  pages: string[];
}

/** One customer-side control from Supabase's shared responsibility model for health data. */
export interface HipaaControl {
  control: string;
  /** "repo": the scan could check it; "dashboard": only the project owner can confirm it. */
  where: "repo" | "dashboard";
  status: "ok" | "gap" | "confirm";
  detail: string;
}

export interface PhiResult {
  tables: PhiTable[];
  trackers: PhiTracker[];
  controls: HipaaControl[];
  /** When the Supabase docs the checklist follows were read. */
  docsReadOn: string;
}

/** Who made a live request: the public key alone, or one of the two test users the client created. */
export type LiveActor = "anon" | "user-a" | "user-b";

/**
 * One live count. Only Postgres' own refusals (SQLSTATE 42501, an RLS violation) are "blocked"; a
 * 401, a timeout or any other error proves nothing either way and is "inconclusive".
 */
export type LiveCount =
  | { status: "count"; n: number }
  | { status: "blocked"; code: string }
  | { status: "missing"; code: string }
  | { status: "inconclusive"; reason: string };

export type LiveVerdict = "leak" | "protected" | "inconclusive" | "shared" | "missing";

/** What the live probe saw for one table or view. Counts only: no row content is read or kept. */
export interface LiveTable {
  kind: "live-table";
  table: string;
  relation: "table" | "view";
  /** Where the name came from: the migrations, the generated types file, or both. */
  foundIn: ("migrations" | "types")[];
  ownerColumns: string[];
  ownedVia?: { column: string; parent: string; parentColumn: string; parentOwner: string };
  /** Rows each actor can see in the whole table. */
  visible: Record<LiveActor, LiveCount>;
  /** User A's own rows, as user A sees them. */
  ownRowsA?: LiveCount;
  /** User A's rows (owner column = A) as user B and as a visitor; direct owner columns only. */
  rowsOfA?: { "user-b": LiveCount; anon: LiveCount };
  /** User B's own rows, as user B sees them (the visible minus own gap = other people's rows). */
  ownRowsB?: LiveCount;
  verdict: LiveVerdict;
  /** One plain sentence: what got through, or why the result proves nothing. */
  summary: string;
  leaks: ("anon" | "user-b")[];
}

export interface LiveBucket {
  kind: "live-bucket";
  bucket: string;
  /** From the bucket listing; undefined when no actor could list buckets. */
  public?: boolean;
  /** Entries under user A's folder (`<user A id>/`), per actor. */
  folderOfA: Record<LiveActor, LiveCount>;
  verdict: LiveVerdict;
  summary: string;
  leaks: ("anon" | "user-b")[];
}

/** A difference between what the migrations say and what the live project does. */
export interface LiveDrift {
  table: string;
  kind: "fixed-outside-migrations" | "opened-outside-migrations" | "not-in-migrations" | "not-deployed";
  detail: string;
}

export interface LiveResult {
  /** Origin of the project, e.g. https://abcd.supabase.co. Never the key. */
  project: string;
  /** "publishable" (sb_publishable_…) or "anon" (legacy JWT). */
  keyKind: "publishable" | "anon";
  tables: LiveTable[];
  buckets: LiveBucket[];
  /** Bucket listing per actor (bucket configuration, not files). */
  bucketsVisible: Record<LiveActor, LiveCount>;
  /** Public RPC functions found in the repo: listed, never called. */
  rpcs: { name: string; securityDefiner: boolean; foundIn: ("migrations" | "types")[] }[];
  drift: LiveDrift[];
  requests: number;
  /** What the probe did and did not do, for the report. */
  notes: string[];
}
