import type { Cwe, Effort, RawFinding, Severity } from "./types.ts";

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
    fix: "Use the public anon key in the browser and keep the secret key in server code only. Rotate the key if this was ever deployed.",
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

/** Rubric entry for a raw finding, or undefined when it is not a finding for the report. */
export function ruleInfo(raw: RawFinding): RuleInfo | undefined {
  switch (raw.source) {
    case "vibe-preflight":
      return PREFLIGHT[raw.rule];
    case "secret-scan":
      return SECRETS[raw.rule];
    case "launch-audit":
      return launchAuditInfo(raw);
  }
}

/** For the appendix: every repo rule with its severity range and CWE. */
export function repoRuleTable(): { source: string; rule: string; title: string; cwe?: Cwe }[] {
  return [
    ...Object.entries(PREFLIGHT).map(([rule, info]) => ({ source: "vibe-preflight", rule, ...info })),
    ...Object.entries(SECRETS).map(([rule, info]) => ({ source: "secret-scan", rule, ...info })),
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
};

export function plainRisk(finding: { source: string; rule: string; title: string }): string {
  return (finding.source === "launch-audit" ? undefined : PLAIN_RISK[finding.rule]) ?? finding.title;
}
