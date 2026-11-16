import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ruleInfo, severityOf } from "./rubric.ts";
import { ADMIN_GATE_TEXT, adminGateNote } from "./scanners/admin-gate.ts";
import { contextNote } from "./scanners/static-context.ts";
import { SEVERITIES, SEVERITY_RANK, type Finding, type RawFinding, type Severity } from "./types.ts";

/** When two rules flag the same object with the same severity, the more specific one names the finding. */
const SPECIFICITY = [
  "phi-public-bucket",
  "auth-users-exposed",
  "definer-function-anon",
  "storage-public-bucket",
  "server-secret-in-client",
];

function dedupeKey(raw: RawFinding): string {
  const where = raw.location.kind === "file" ? raw.location.file : raw.location.url;
  if (raw.source === "launch-audit") return `${where}|${raw.rule}`;
  // One webhook handler reading the body wrong is one finding, however many lines the scanners point at.
  if (raw.rule.startsWith("stripe-webhook-") && raw.location.kind === "file") return `${where}|${raw.rule}`;
  // The same policy created again in a later migration is one finding, not one per file.
  const policy = where.endsWith(".sql") ? raw.message.match(/^Policy "([^"]+)"/)?.[1] : undefined;
  if (policy && raw.subject) return `policy|${raw.rule}|${raw.subject.toLowerCase()}|${policy}`;
  if (raw.subject) return `${where}|${raw.subject}`;
  return raw.location.kind === "file" ? `${where}:${raw.location.line}|${raw.rule}` : `${where}|${raw.rule}`;
}

function specificity(rule: string): number {
  const index = SPECIFICITY.indexOf(rule);
  return index === -1 ? SPECIFICITY.length : index;
}

async function snippetFor(
  repo: string,
  raw: RawFinding,
  cache: Map<string, string[] | null>,
): Promise<string | undefined> {
  if (raw.location.kind !== "file" || raw.source === "secret-scan") return undefined; // never print a secret
  const { file, line } = raw.location;
  if (!cache.has(file)) {
    cache.set(
      file,
      await readFile(join(repo, file), "utf8").then(
        (text) => text.split("\n"),
        () => null,
      ),
    );
  }
  const lines = cache.get(file);
  if (!lines || line < 1 || line > lines.length) return undefined;
  const picked: string[] = [];
  for (let n = line; n <= Math.min(lines.length, line + 3); n += 1) {
    const text = lines[n - 1] ?? "";
    if (n > line && text.trim() === "") break;
    picked.push(`${String(n).padStart(4)} | ${text}`);
  }
  return picked.join("\n");
}

/** Live-site findings carry their proof in the evidence lines (the URL is already the location). */
function evidenceOf(raw: RawFinding): string {
  if (raw.source !== "launch-audit") return raw.message;
  return raw.subject?.replace(/\n/g, "; ") ?? "";
}

export function countBySeverity(findings: { severity: Severity }[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

function locationOrder(f: Finding): string {
  return f.location.kind === "file" ? `${f.location.file}:${String(f.location.line).padStart(6, "0")}` : f.location.url;
}

/**
 * Raw scanner output → report findings: rubric severity, CWE and prose, one finding per flagged thing,
 * sorted by severity then location, numbered PA-01…
 */
export async function normalize(repo: string, raws: RawFinding[]): Promise<{ findings: Finding[]; dropped: number }> {
  const groups = new Map<string, { raw: RawFinding; severity: Severity }[]>();
  let dropped = 0;
  for (const raw of raws) {
    const info = ruleInfo(raw);
    if (!info) {
      dropped += 1;
      continue;
    }
    const key = dedupeKey(raw);
    groups.set(key, [...(groups.get(key) ?? []), { raw, severity: severityOf(raw, info) }]);
  }

  const cache = new Map<string, string[] | null>();
  const findings: Finding[] = [];
  for (const group of groups.values()) {
    group.sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || specificity(a.raw.rule) - specificity(b.raw.rule),
    );
    const [lead, ...rest] = group;
    if (!lead) continue;
    const rule = ruleInfo(lead.raw);
    if (!rule) continue;
    const info = lead.raw.adminGate ? { ...rule, ...ADMIN_GATE_TEXT } : rule;
    const others = [...new Set(rest.map((r) => r.raw.rule).filter((rule) => rule !== lead.raw.rule))];
    findings.push({
      id: "",
      source: lead.raw.source,
      rule: lead.raw.rule,
      severity: lead.severity,
      title: info.title,
      cwe: info.cwe,
      location: lead.raw.location,
      evidence: [evidenceOf(lead.raw), contextNote(lead.raw), adminGateNote(lead.raw)].filter(Boolean).join(" "),
      snippet: await snippetFor(repo, lead.raw, cache),
      whyItMatters: info.whyItMatters,
      fix: info.fix,
      effort: info.effort,
      subject: lead.raw.source === "launch-audit" ? undefined : lead.raw.subject,
      proof: group.find((g) => g.raw.proof)?.raw.proof,
      live: group.find((g) => g.raw.live)?.raw.live,
      ...(group.some((g) => g.raw.phi) ? { phi: group.find((g) => g.raw.phi)?.raw.phi } : {}),
      ...(lead.raw.adminGate ? { adminGate: lead.raw.adminGate } : {}),
      alsoFlaggedBy: others,
    });
  }

  findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || locationOrder(a).localeCompare(locationOrder(b)),
  );
  findings.forEach((f, index) => {
    f.id = `PA-${String(index + 1).padStart(2, "0")}`;
  });
  return { findings, dropped };
}
