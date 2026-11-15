import {
  SEVERITY_RANK,
  type Cwe,
  type Effort,
  type LiveBucket,
  type LiveTable,
  type Proof,
  type RawFinding,
  type Severity,
} from "./types.ts";

/**
 * The severity rubric. Every rule below is placed with these four questions, in order;
 * the first "yes" decides. The README and the report appendix print this list.
 */
export const RUBRIC: { severity: Severity; rule: string }[] = [
  {
    severity: "critical",
    rule: "Anyone on the internet, without an account, can read private data, change data, take money-related actions or get a key that does those things.",
  },
  {
    severity: "high",
    rule: "A signed-in user can reach other users' data or give themselves something they did not pay for, or private data is exposed but only under a condition the scanner cannot rule out.",
  },
  {
    severity: "medium",
    rule: "A missing safeguard that makes another bug easier to exploit or worse when it happens (headers, search_path, cookie flags), or a bug that breaks a feature in a way that fails closed.",
  },
  {
    severity: "low",
    rule: "Hygiene and launch polish: worth fixing, no direct path to an attack.",
  },
];

const cwe = (id: number, name: string): Cwe => ({ id, name });

const CWE = {
  missingAuthz: cwe(862, "Missing Authorization"),
  incorrectAuthz: cwe(863, "Incorrect Authorization"),
  wrongSphere: cwe(668, "Exposure of Resource to Wrong Sphere"),
  privateInfo: cwe(359, "Exposure of Private Personal Information to an Unauthorized Actor"),
  authenticity: cwe(345, "Insufficient Verification of Data Authenticity"),
  massAssignment: cwe(915, "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
  searchPath: cwe(426, "Untrusted Search Path"),
  filesExposed: cwe(552, "Files or Directories Accessible to External Parties"),
  cleartextStorage: cwe(312, "Cleartext Storage of Sensitive Information"),
  hardcodedCreds: cwe(798, "Use of Hard-coded Credentials"),
  privilege: cwe(269, "Improper Privilege Management"),
  defaultPerms: cwe(276, "Incorrect Default Permissions"),
  cleartextTransmission: cwe(319, "Cleartext Transmission of Sensitive Information"),
  clickjacking: cwe(1021, "Improper Restriction of Rendered UI Layers or Frames"),
  missingCsp: cwe(693, "Protection Mechanism Failure"),
  sensitiveCookie: cwe(614, "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
  httpOnlyCookie: cwe(1004, "Sensitive Cookie Without 'HttpOnly' Flag"),
  infoExposure: cwe(200, "Exposure of Sensitive Information to an Unauthorized Actor"),
  debugCode: cwe(489, "Active Debug Code"),
  sourceExposure: cwe(540, "Inclusion of Sensitive Information in Source Code"),
} as const;

export interface RuleInfo {
  title: string;
  severity: (raw: RawFinding) => Severity;
  cwe?: Cwe;
  /** Plain words for a non-technical founder: what can happen to them. */
  whyItMatters: string;
  fix: string;
  effort: Effort;
}

const fixed = (severity: Severity) => (): Severity => severity;
const byToolLevel =
  (onError: Severity, onWarning: Severity) =>
  (raw: RawFinding): Severity =>
    raw.toolSeverity === "error" ? onError : onWarning;

/** vibe-preflight rules (repo scan). Keys are the scanner's rule ids. */
const PREFLIGHT: Record<string, RuleInfo> = {
  "rls-disabled": {
    title: "Table open to the public API (Row Level Security off)",
    severity: fixed("critical"),
    cwe: CWE.missingAuthz,
    whyItMatters:
      "Supabase serves every table in the public schema over its REST API, and the key it needs ships in your website. With Row Level Security off, anyone can read, change or delete every row of this table from a browser console.",
    fix: "Enable Row Level Security on the table. With no policies the API gets nothing, and your server code (service role) keeps working. Add policies only for what the browser really needs.",
    effort: "under 1 hour",
  },
  "rls-permissive-policy": {
    title: "Policy lets everyone through (using true)",
    severity: byToolLevel("critical", "high"),
    cwe: CWE.incorrectAuthz,
    whyItMatters:
      "A policy with `using (true)` or `with check (true)` allows the action for every caller, including visitors who are not signed in. If the table holds anything private, it is public.",
    fix: "Replace the policy with one that compares `auth.uid()` to the owner column, and limit it to the `authenticated` role.",
    effort: "under 1 hour",
  },
  "rls-no-policy": {
    title: "Table has Row Level Security on and no policies",
    severity: fixed("low"),
    whyItMatters:
      "This is safe: the API returns nothing. But if the app reads this table from the browser, that read silently comes back empty, which looks like a bug at launch.",
    fix: "If the browser needs the table, add a read policy for the rows it should see. If only the server uses it, leave it and note that on purpose.",
    effort: "under 1 hour",
  },
  "rls-update-privileged-column": {
    title: "Users can edit their own plan or role column",
    severity: fixed("high"),
    cwe: CWE.massAssignment,
    whyItMatters:
      "The update policy lets a signed-in user change any column of their own row, including the one that says what they paid for. One request from the browser console turns a free account into a paid one.",
    fix: "Limit what users may update with column privileges (grant update only on the safe columns) and add `with check` to the policy. Change the plan only from the server, after Stripe confirms payment.",
    effort: "1-4 hours",
  },
  "view-bypasses-rls": {
    title: "View skips Row Level Security",
    severity: fixed("high"),
    cwe: CWE.incorrectAuthz,
    whyItMatters:
      "Postgres views run with the rights of whoever created them, so they ignore the policies of the tables below. Supabase serves the view over the API, which gives every caller the rows your policies were meant to hide.",
    fix: "Set `security_invoker = true` on the view (Postgres 15+), so it runs with the caller's rights and the table policies apply.",
    effort: "under 1 hour",
  },
  "auth-users-exposed": {
    title: "User accounts table exposed through a view",
    severity: fixed("critical"),
    cwe: CWE.privateInfo,
    whyItMatters:
      "`auth.users` holds every account's email and sign-in data. A view over it in the public schema puts that list on the API, so anyone can download your user list.",
    fix: "Revoke API access to the view, and give users the lookup they need through a function that checks the caller and returns only safe columns.",
    effort: "1-4 hours",
  },
  "definer-search-path": {
    title: "SECURITY DEFINER function without a fixed search_path",
    severity: fixed("medium"),
    cwe: CWE.searchPath,
    whyItMatters:
      "The function runs with its owner's rights. Without a fixed `search_path`, a caller who can create objects in a schema on the path can make it run their code with those rights. Supabase's own linter flags this.",
    fix: "Add `set search_path = ''` to the function and schema-qualify every table it uses.",
    effort: "under 1 hour",
  },
  "definer-function-anon": {
    title: "Privileged database function callable by anyone",
    severity: byToolLevel("critical", "high"),
    cwe: CWE.privilege,
    whyItMatters:
      "The function runs with its owner's rights, so it skips Row Level Security. Supabase exposes it at /rest/v1/rpc/, and visitors who are not signed in may call it.",
    fix: "Revoke execute from `public`, `anon` and `authenticated`, grant it only to the roles that need it, and check the caller inside the function.",
    effort: "under 1 hour",
  },
  "storage-public-bucket": {
    title: "Public storage bucket",
    severity: byToolLevel("critical", "medium"),
    cwe: CWE.filesExposed,
    whyItMatters:
      "Files in a public bucket open for anyone with the link. When a select policy on storage.objects also lets anyone list the bucket, the links are no secret either: anyone can download every file.",
    fix: "Make the bucket private, drop the open select policy, and hand out short-lived signed URLs from the server after checking who is asking.",
    effort: "1-4 hours",
  },
  "server-secret-in-client": {
    title: "Server-only key used in browser code",
    severity: fixed("critical"),
    cwe: CWE.wrongSphere,
    whyItMatters:
      "Code in this file runs in the visitor's browser. A Supabase service role key or Stripe secret key there gives full control of the database or the Stripe account to anyone who opens developer tools. If it was ever deployed, treat the key as leaked.",
    fix: "Use only public keys in the browser (the Supabase anon or publishable key, the Stripe publishable key) and keep secret keys in server code. Rotate the key if this was ever deployed.",
    effort: "1-4 hours",
  },
  "public-env-secret": {
    title: "Secret in a browser-exposed environment variable",
    severity: byToolLevel("critical", "high"),
    cwe: CWE.wrongSphere,
    whyItMatters:
      "Next.js copies every `NEXT_PUBLIC_` variable into the JavaScript it sends to visitors (Vite does the same with `VITE_`). A secret under that prefix is public as soon as the site is built.",
    fix: "Rename the variable without the public prefix, read it only in server code, and rotate the key if it was ever deployed.",
    effort: "under 1 hour",
  },
  "stripe-webhook-unverified": {
    title: "Stripe webhook accepts unsigned requests",
    severity: fixed("critical"),
    cwe: CWE.authenticity,
    whyItMatters:
      "The webhook acts on whatever JSON it receives. Anyone who finds the URL can post a fake 'payment completed' event and get the paid plan for free.",
    fix: "Verify the `stripe-signature` header with `stripe.webhooks.constructEvent` on the raw request body before acting on the event.",
    effort: "under 1 hour",
  },
  "stripe-webhook-parsed-body": {
    title: "Stripe signature checked against a parsed body",
    severity: fixed("medium"),
    cwe: CWE.authenticity,
    whyItMatters:
      "Stripe signs the exact bytes it sent. Once the body is parsed and re-serialised the signature no longer matches, so real payment events get rejected and customers who paid may not get access.",
    fix: "Pass the raw body (`await request.text()` in the App Router, `bodyParser: false` in pages/api, `express.raw()` in Express) to `constructEvent`.",
    effort: "under 1 hour",
  },
  "env-file-committed": {
    title: "Environment file with values in git",
    severity: byToolLevel("critical", "low"),
    cwe: CWE.cleartextStorage,
    whyItMatters:
      "Everyone with access to the repository, now or later, can read these values. Keys stay in git history even after the file is deleted.",
    fix: "Add the file to .gitignore, remove it from the index (`git rm --cached`), and rotate every real key it held.",
    effort: "1-4 hours",
  },
};

/** Our own secret scan of the working tree and git history. */
const SECRETS: Record<string, RuleInfo> = {
  "secret-in-tree": {
    title: "Credential in the repository",
    severity: (raw) => (raw.toolSeverity === "live" ? "critical" : "low"),
    cwe: CWE.hardcodedCreds,
    whyItMatters:
      "The key is written in a file that ships with the code. Anyone who can read the repository, or a bundle built from it, can use it.",
    fix: "Move the value to an environment variable on the server, then rotate the key: deleting the line does not un-leak it.",
    effort: "1-4 hours",
  },
  "secret-in-history": {
    title: "Credential left in git history",
    severity: (raw) => (raw.toolSeverity === "live" ? "high" : "low"),
    cwe: CWE.hardcodedCreds,
    whyItMatters:
      "The key is gone from the current files but still in an old commit. Anyone with a clone of the repository can get it back with one git command.",
    fix: "Rotate the key. Rewriting history with git filter-repo helps only if every clone and fork is replaced too.",
    effort: "under 1 hour",
  },
};

/** Our own config check of supabase/config.toml against the edge function code. */
const PROJECT_CONFIG: Record<string, RuleInfo> = {
  "stripe-webhook-jwt-gate": {
    title: "Stripe webhook function behind Supabase's JWT check",
    severity: fixed("medium"),
    whyItMatters:
      "Supabase checks for a signed-in user's token before an edge function runs, and Stripe never sends one. Every real payment event gets a 401, so customers who paid may not get access. It fails closed, which is why this is not rated higher.",
    fix: "Set `verify_jwt = false` for this function in supabase/config.toml (or deploy it with `--no-verify-jwt`). The Stripe signature check in the code is then the gate, so keep it.",
    effort: "under 1 hour",
  },
};

/** The read-only probe of the live project, for leaks the repo does not explain. */
const LIVE: Record<string, RuleInfo> = {
  "live-rls-leak": {
    title: "Live database lets other people read users' rows",
    severity: (raw) => (raw.toolSeverity === "anon" ? "critical" : "high"),
    cwe: CWE.incorrectAuthz,
    whyItMatters:
      "This was measured on the running project, not guessed from code: the probe signed in as a second test user (or as nobody) and counted rows that belong to someone else. The migrations in the repo do not explain it, so the policy or grant that lets it through was changed in the dashboard or the table was made there.",
    fix: "Run `supabase db pull` (or `supabase db diff --linked`) to get the live policies into a migration, fix the select policy so it compares the owner column with `auth.uid()`, push it, and run the live probe again.",
    effort: "1-4 hours",
  },
  "live-storage-leak": {
    title: "Other users can list files in a user's storage folder",
    severity: (raw) => (raw.toolSeverity === "anon" ? "critical" : "high"),
    cwe: CWE.filesExposed,
    whyItMatters:
      "The probe listed user A's folder in this bucket as user B (or as nobody) and got entries back. A file that can be listed can usually be downloaded with the same rights, so uploads such as contracts or ID scans are open to other accounts.",
    fix: "Limit the select policy on `storage.objects` for this bucket to the owner's folder: `bucket_id = '<bucket>' and (storage.foldername(name))[1] = auth.uid()::text`. Do the same for insert, update and delete.",
    effort: "under 1 hour",
  },
};

/** What the RLS probe class means in plain words, for findings no static rule explains. */
const PROBE_CLASS: Record<string, { title: string; why: string; fix: string }> = {
  anon: {
    title: "Visitors without an account can reach users' rows",
    why: "The probe signed in as nobody, with only the public key every visitor has, and read or changed rows that belong to a user. On the real API that is one request from a browser console.",
    fix: "Limit the policies on this table to the `authenticated` role and to rows where the owner column equals `auth.uid()`.",
  },
  "other-user": {
    title: "Policy exists but lets one user reach another user's rows",
    why: "The table has Row Level Security and policies, so a dashboard check passes. The probe signed in as a second user and still read or changed the first user's rows: the policy checks that someone is signed in, not who owns the row.",
    fix: "Compare the owner column with `auth.uid()` in every policy on this table (`using` for reads, updates and deletes, `with check` for inserts and updates).",
  },
  owner: {
    title: "Users can change what they paid for on their own row",
    why: "The probe signed in as the row's owner and changed a plan, role or billing column. A free account can make itself paid with one request.",
    fix: "Revoke update on the table, grant update only on the safe columns, and change paid columns only from the server after Stripe confirms payment.",
  },
  "anon-write": {
    title: "Anyone can change shared data",
    why: "The probe added, changed or deleted rows of a table that belongs to no user (a price list, settings), which every visitor sees.",
    fix: "Keep the public read policy if it is wanted, and allow writes only to the service role (no insert, update or delete policy for anon or authenticated).",
  },
};

/** Rows belong to someone: an owner column, or a parent row that has one. */
const owned = (proof: Proof): boolean => proof.ownerColumns.length > 0 || proof.ownedVia !== undefined;

/** Severity of what the probe could do: the rubric applied to measured access instead of policy text. */
export function proofSeverity(proof: Proof): Severity | undefined {
  if (!proof.leaks.length) return undefined;
  const anon = proof.leaks.some((c) => c.actor === "anon");
  const writes = proof.leaks.some((c) => c.action !== "select");
  if (anon || (!owned(proof) && writes)) return "critical";
  return "high";
}

/** The class of the worst leak, which picks the title for a probe-only finding. */
export function proofClass(proof: Proof): keyof typeof PROBE_CLASS | undefined {
  if (!proof.leaks.length) return undefined;
  if (!owned(proof)) return "anon-write";
  if (proof.leaks.some((c) => c.actor === "anon")) return "anon";
  if (proof.leaks.some((c) => c.actor === "other-user")) return "other-user";
  return "owner";
}

const max = (a: Severity, b: Severity | undefined): Severity => (b && SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a);

/** Severity of what the live probe measured: a visitor reading user rows is Critical, another user High. */
export function liveSeverity(live: LiveTable | LiveBucket | undefined): Severity | undefined {
  if (!live || live.verdict !== "leak") return undefined;
  return live.leaks.includes("anon") ? "critical" : "high";
}

/**
 * Final severity of a raw finding. The probe can raise it (a "warning" policy that really lets visitors
 * read user rows is Critical) and lower one case: an open read policy on a table with no owner column and
 * no write leak is a public reference table, which is Low (confirm it is meant to be public).
 */
export function severityOf(raw: RawFinding, info: RuleInfo): Severity {
  const base = max(info.severity(raw), liveSeverity(raw.live));
  const proof = raw.proof;
  if (!proof) return base;
  const sharedRead =
    raw.rule === "rls-permissive-policy" &&
    /\(select\)/.test(raw.message) &&
    !owned(proof) &&
    !proof.leaks.length &&
    !proof.checks.some((c) => c.inconclusive) &&
    !liveSeverity(raw.live);
  if (sharedRead) return "low";
  return max(base, proofSeverity(proof));
}

/** CWE for launch-audit ids, by exact id or by prefix. */
const LAUNCH_CWE: [string, Cwe][] = [
  ["transport.no-https", CWE.cleartextTransmission],
  ["transport.no-http-redirect", CWE.cleartextTransmission],
  ["transport.hsts", CWE.cleartextTransmission],
  ["transport.mixed-content", CWE.cleartextTransmission],
  ["transport.tls-invalid", cwe(295, "Improper Certificate Validation")],
  ["headers.clickjacking", CWE.clickjacking],
  ["headers.csp", CWE.missingCsp],
  ["headers.nosniff", CWE.missingCsp],
  ["headers.version-disclosure", CWE.infoExposure],
  ["cookies.secure-missing", CWE.sensitiveCookie],
  ["cookies.httponly-missing", CWE.httpOnlyCookie],
  ["cookies.samesite", cwe(1275, "Sensitive Cookie with Improper SameSite Attribute")],
  ["secrets.", CWE.hardcodedCreds],
  ["exposure.source-maps", CWE.sourceExposure],
  ["exposure.env-file", CWE.filesExposed],
  ["exposure.git-dir", CWE.filesExposed],
  ["exposure.dev-server", CWE.debugCode],
  ["backend.supabase-verify-rls", CWE.defaultPerms],
];

const LAUNCH_SEVERITY: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

function launchAuditInfo(raw: RawFinding): RuleInfo | undefined {
  const severity = LAUNCH_SEVERITY[raw.toolSeverity];
  if (!severity) return undefined; // "info" lines are context, not findings
  const category = raw.rule.split(".")[0];
  return {
    title: raw.title ?? raw.rule,
    severity: () => severity,
    cwe: LAUNCH_CWE.find(([key]) => raw.rule === key || raw.rule.startsWith(key))?.[1],
    whyItMatters: raw.message,
    fix: raw.fix ?? "",
    effort: category === "seo" || category === "headers" || category === "cookies" ? "under 1 hour" : "1-4 hours",
  };
}

/** npm's rating, one level down: an advisory says a version is affected, not that your code reaches it. */
const NPM_SEVERITY: Record<string, Severity> = { critical: "high", high: "medium", moderate: "low", low: "low" };

function npmAuditInfo(raw: RawFinding): RuleInfo | undefined {
  const severity = NPM_SEVERITY[raw.toolSeverity];
  if (!severity) return undefined; // "info"
  const id = Number(raw.cwe?.match(/^CWE-(\d+)$/)?.[1]);
  return {
    title: raw.title ?? raw.rule,
    severity: () => severity,
    cwe: id ? cwe(id, "") : undefined,
    whyItMatters:
      "A package your app ships has a published security advisory for this version range. Whether it can be exploited depends on whether your code uses the affected part; the scan does not check that, which is why it is rated one level below npm's rating.",
    fix: raw.fix ?? "",
    effort: raw.fix?.includes("major version") ? "1-4 hours" : "under 1 hour",
  };
}

function probeInfo(raw: RawFinding): RuleInfo | undefined {
  const kind = raw.proof && proofClass(raw.proof);
  const text = kind && PROBE_CLASS[kind];
  if (!raw.proof || !text) return undefined;
  const proof = raw.proof;
  return {
    title: text.title,
    severity: () => proofSeverity(proof) ?? "low",
    cwe: kind === "owner" ? CWE.massAssignment : kind === "other-user" ? CWE.incorrectAuthz : CWE.missingAuthz,
    whyItMatters: text.why,
    fix: text.fix,
    effort: "under 1 hour",
  };
}

/** Rubric entry for a raw finding, or undefined when it is not a finding for the report. */
export function ruleInfo(raw: RawFinding): RuleInfo | undefined {
  switch (raw.source) {
    case "rls-probe":
      return probeInfo(raw);
    case "project-config":
      return PROJECT_CONFIG[raw.rule];
    case "npm-audit":
      return npmAuditInfo(raw);
    case "vibe-preflight":
      return PREFLIGHT[raw.rule];
    case "secret-scan":
      return SECRETS[raw.rule];
    case "launch-audit":
      return launchAuditInfo(raw);
    case "live-probe":
      return LIVE[raw.rule];
  }
}

/** For the appendix: every repo rule with its severity range and CWE. */
export function repoRuleTable(): { source: string; rule: string; title: string; cwe?: Cwe }[] {
  return [
    ...Object.entries(PREFLIGHT).map(([rule, info]) => ({ source: "vibe-preflight", rule, ...info })),
    ...Object.entries(SECRETS).map(([rule, info]) => ({ source: "secret-scan", rule, ...info })),
    ...Object.entries(PROJECT_CONFIG).map(([rule, info]) => ({ source: "project-config", rule, ...info })),
    ...Object.entries(LIVE).map(([rule, info]) => ({ source: "live-probe", rule, ...info })),
    ...Object.entries(PROBE_CLASS).map(([kind, text]) => ({
      source: "rls-probe",
      rule: `rls-probe-leak (${kind})`,
      title: text.title,
      cwe: kind === "owner" ? CWE.massAssignment : kind === "other-user" ? CWE.incorrectAuthz : CWE.missingAuthz,
    })),
  ].map(({ source, rule, title, cwe }) => ({ source, rule, title, cwe }));
}

/** One sentence for the executive summary, written for someone who does not read code. */
const PLAIN_RISK: Record<string, string> = {
  "rls-disabled": "Anyone who opens your site can read and change a whole database table.",
  "rls-permissive-policy": "A database rule lets every visitor through, so private rows can be read by strangers.",
  "rls-no-policy": "A table is locked to the app, so a screen that reads it may come back empty.",
  "rls-update-privileged-column": "A signed-in user can switch their own account to the paid plan without paying.",
  "view-bypasses-rls": "A database view shows every user's rows, ignoring the rules on the table behind it.",
  "auth-users-exposed": "Your full list of user emails can be downloaded by anyone.",
  "definer-search-path": "A privileged database function could be tricked into running someone else's code.",
  "definer-function-anon":
    "A privileged database function, such as changing a customer's plan, can be called by anyone.",
  "storage-public-bucket": "Uploaded files can be listed and downloaded by anyone.",
  "server-secret-in-client": "The master key to your database is sent to every visitor's browser.",
  "public-env-secret": "A secret key (for example your Stripe key) is built into the public website code.",
  "stripe-webhook-unverified": "Anyone can fake a 'payment received' message and get paid features for free.",
  "stripe-webhook-parsed-body": "Real Stripe payment messages may be rejected, so paying customers may not get access.",
  "env-file-committed": "Keys stored in the code repository can be read by anyone with access to it.",
  "secret-in-tree": "A working API key is written in the code.",
  "secret-in-history": "An API key removed from the code can still be recovered from its history.",
  "dependency-advisory": "A library your app ships has a published security advisory for the version you use.",
  "stripe-webhook-jwt-gate": "Supabase turns away Stripe's payment messages, so paying customers may not get access.",
  "live-storage-leak": "One customer can list the files another customer uploaded.",
};

const PROBE_RISK: Record<string, string> = {
  anon: "Visitors without an account can read or change your users' records.",
  "other-user": "Any signed-in user can see or change other customers' records.",
  owner: "A signed-in user can switch their own account to the paid plan without paying.",
  "anon-write": "Anyone can change data every customer sees, such as your prices.",
};

export function plainRisk(finding: {
  source: string;
  severity?: Severity;
  rule: string;
  title: string;
  subject?: string;
  proof?: Proof;
}): string {
  const stripeKey = /STRIPE/i.test(finding.subject ?? "");
  if (stripeKey && finding.rule === "server-secret-in-client") {
    return "Your Stripe secret key is sent to every visitor's browser, so anyone can issue refunds or read your customers.";
  }
  if (stripeKey && finding.rule === "public-env-secret") {
    return "Your Stripe secret key sits in a public variable, so any browser code that reads it ships the key to visitors.";
  }
  if (finding.rule === "live-rls-leak") {
    return finding.severity === "critical"
      ? "On the running app, visitors without an account can read your users' records."
      : "On the running app, one customer can read another customer's records.";
  }
  if (finding.source === "rls-probe") {
    const kind = finding.proof && proofClass(finding.proof);
    return (kind && PROBE_RISK[kind]) ?? finding.title;
  }
  return (finding.source === "launch-audit" ? undefined : PLAIN_RISK[finding.rule]) ?? finding.title;
}
