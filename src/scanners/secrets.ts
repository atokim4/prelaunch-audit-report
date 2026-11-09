import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { isGitRepo, listFiles } from "../files.ts";
import { run } from "../exec.ts";
import type { RawFinding, ToolRun } from "../types.ts";

/**
 * A small credential scanner for the working tree and git history. It looks for key formats with a
 * fixed prefix, so it has few false positives and misses generic "password = ..." strings on purpose.
 */
interface Pattern {
  kind: string;
  label: string;
  regex: RegExp;
  /** "test" keys only reach a sandbox; they are reported as low. */
  grade: (match: string) => "live" | "test" | "ignore";
}

const live = (): "live" => "live";

export const PATTERNS: Pattern[] = [
  {
    kind: "stripe-secret-key",
    label: "Stripe secret or restricted key",
    regex: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{20,}\b/g,
    grade: (m) => (m.includes("_live_") ? "live" : "test"),
  },
  {
    kind: "stripe-webhook-secret",
    label: "Stripe webhook signing secret",
    regex: /\bwhsec_[0-9A-Za-z]{24,}\b/g,
    grade: live,
  },
  {
    kind: "supabase-secret-key",
    label: "Supabase secret API key",
    regex: /\bsb_secret_[0-9A-Za-z_-]{20,}/g,
    grade: live,
  },
  {
    kind: "supabase-service-role-jwt",
    label: "Supabase service_role JWT",
    regex: /\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{20,}/g,
    grade: gradeSupabaseJwt,
  },
  { kind: "aws-access-key", label: "AWS access key id", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, grade: live },
  {
    kind: "github-token",
    label: "GitHub token",
    regex: /\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{60,})\b/g,
    grade: live,
  },
  { kind: "anthropic-key", label: "Anthropic API key", regex: /\bsk-ant-[0-9A-Za-z_-]{30,}/g, grade: live },
  { kind: "openai-key", label: "OpenAI API key", regex: /\bsk-(?:proj-)?[0-9A-Za-z_-]{32,}/g, grade: gradeOpenAi },
  { kind: "slack-token", label: "Slack token", regex: /\bxox[abprs]-[0-9A-Za-z-]{20,}/g, grade: live },
  {
    kind: "private-key",
    label: "Private key block",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    grade: live,
  },
];

function gradeOpenAi(match: string): "live" | "ignore" {
  return match.startsWith("sk-ant-") ? "ignore" : "live";
}

/** Only JWTs whose payload says role=service_role count; the Supabase CLI's local demo key is public knowledge. */
function gradeSupabaseJwt(token: string): "live" | "ignore" {
  const payload = token.split(".")[1];
  if (!payload) return "ignore";
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { role?: unknown; iss?: unknown };
    if (claims.role !== "service_role") return "ignore";
    return claims.iss === "supabase-demo" ? "ignore" : "live";
  } catch {
    return "ignore";
  }
}

/** Placeholders in docs and .env.example files: sk_live_xxxxxxxx, sk_test_your_key_here… */
function isPlaceholder(value: string): boolean {
  const body = value.replace(/^[a-z]+[_-](?:live_|test_|secret_|proj-|ant-)?/i, "");
  if (/x{6,}|your|example|placeholder|changeme|dummy|<|>/i.test(body)) return true;
  return new Set(body).size < 8;
}

export function mask(value: string): string {
  return value.length <= 12 ? `${value.slice(0, 4)}…` : `${value.slice(0, 10)}…(${value.length} chars)`;
}

export interface SecretHit {
  kind: string;
  label: string;
  grade: "live" | "test";
  value: string;
  line: number;
}

export function findSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const lines = text.split("\n");
  lines.forEach((lineText, index) => {
    for (const pattern of PATTERNS) {
      for (const match of lineText.matchAll(pattern.regex)) {
        const value = match[0];
        const grade = pattern.grade(value);
        if (grade === "ignore" || isPlaceholder(value)) continue;
        hits.push({ kind: pattern.kind, label: pattern.label, grade, value, line: index + 1 });
      }
    }
  });
  return hits;
}

const SKIP_FILES =
  /(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$|\.(?:png|jpe?g|gif|webp|ico|pdf|zip|woff2?|ttf|mp4)$/i;
const MAX_BYTES = 1024 * 1024;

async function scanTree(repo: string, git: boolean): Promise<{ findings: RawFinding[]; values: Set<string> }> {
  const findings: RawFinding[] = [];
  const values = new Set<string>();
  for (const file of await listFiles(repo, git)) {
    if (SKIP_FILES.test(file)) continue;
    const path = join(repo, file);
    const info = await stat(path).catch(() => undefined);
    if (!info?.isFile() || info.size > MAX_BYTES) continue;
    for (const hit of findSecrets(await readFile(path, "utf8"))) {
      values.add(hit.value);
      findings.push({
        source: "secret-scan",
        rule: "secret-in-tree",
        toolSeverity: hit.grade,
        message: `${hit.label} (${mask(hit.value)}) in ${file}.`,
        location: { kind: "file", file, line: hit.line },
        subject: `secret:${hit.value}`,
      });
    }
  }
  return { findings, values };
}

/** Parses `git log -p --unified=0` output into added lines with their commit, file and line number. */
export function addedLines(log: string): { commit: string; file: string; line: number; text: string }[] {
  const out: { commit: string; file: string; line: number; text: string }[] = [];
  let commit = "";
  let file = "";
  let line = 0;
  for (const row of log.split("\n")) {
    if (row.startsWith("commit ")) commit = row.slice(7, 19);
    else if (row.startsWith("+++ ")) file = row === "+++ /dev/null" ? "" : row.slice(4).replace(/^b\//, "");
    else if (row.startsWith("@@")) line = Number(row.match(/\+(\d+)/)?.[1] ?? 0);
    else if (row.startsWith("+") && file) {
      out.push({ commit, file, line, text: row.slice(1) });
      line += 1;
    }
  }
  return out;
}

async function scanHistory(repo: string, inTree: Set<string>): Promise<RawFinding[]> {
  const result = await run(
    "git",
    [
      "-C",
      repo,
      "log",
      "-p",
      "--all",
      "--relative",
      "--no-color",
      "--no-ext-diff",
      "--unified=0",
      "--format=commit %H",
      "--",
      ".",
    ],
    { timeoutMs: 300_000 },
  );
  if (result.code !== 0) throw new Error(`git log failed: ${result.stderr.trim()}`);
  const seen = new Set<string>();
  const findings: RawFinding[] = [];
  for (const added of addedLines(result.stdout)) {
    if (SKIP_FILES.test(added.file)) continue;
    for (const hit of findSecrets(added.text)) {
      if (inTree.has(hit.value) || seen.has(hit.value)) continue;
      seen.add(hit.value);
      findings.push({
        source: "secret-scan",
        rule: "secret-in-history",
        toolSeverity: hit.grade,
        message: `${hit.label} (${mask(hit.value)}) added to ${added.file} in commit ${added.commit.slice(0, 7)} and no longer in the current files.`,
        location: { kind: "file", file: added.file, line: added.line },
        subject: `secret:${hit.value}`,
      });
    }
  }
  return findings;
}

export async function runSecretScan(repo: string): Promise<{ findings: RawFinding[]; tool: ToolRun }> {
  const git = await isGitRepo(repo);
  const tree = await scanTree(repo, git);
  const history = git ? await scanHistory(repo, tree.values) : [];
  return {
    findings: [...tree.findings, ...history],
    tool: {
      name: "secret-scan (built in)",
      version: `${PATTERNS.length} patterns`,
      command: git ? "working tree (git ls-files) + git log -p --all" : "working tree only",
      status: "ok",
      note: git ? undefined : "Not a git repository, so history was not scanned.",
    },
  };
}
