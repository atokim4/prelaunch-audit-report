import { leaks, probeRls, PROBE_VERSION, type ProbeResult, type TableProbe } from "../probe/rls-probe.ts";
import { weakPolicies } from "../patches/fixers.ts";
import type { SqlFile } from "../patches/sql.ts";
import type { Location, Proof, RawFinding, ToolRun } from "../types.ts";

/** Static rules about one table or view; the probe's proof is attached to these instead of a new finding. */
export const TABLE_RULES = new Set([
  "rls-disabled",
  "rls-permissive-policy",
  "rls-no-policy",
  "rls-update-privileged-column",
  "view-bypasses-rls",
  "auth-users-exposed",
]);

export function toProof(table: TableProbe): Proof {
  return {
    table: table.table,
    kind: table.kind,
    ownerColumns: table.ownerColumns,
    ...(table.ownedVia ? { ownedVia: table.ownedVia } : {}),
    checks: table.checks,
    leaks: leaks(table),
    policies: table.policies,
  };
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** First match of `pattern` in the migrations, newest last; the last match wins for policies (re-created later). */
function findIn(migrations: SqlFile[], pattern: RegExp, last: boolean): Location | undefined {
  let found: Location | undefined;
  for (const file of [...migrations].sort((a, b) => a.path.localeCompare(b.path))) {
    const index = file.text.search(pattern);
    if (index < 0) continue;
    found = { kind: "file", file: file.path, line: file.text.slice(0, index).split("\n").length };
    if (!last) return found;
  }
  return found;
}

/** Where a probe-only finding points: the policy that let the leak through, else where the table is created. */
function locate(migrations: SqlFile[], table: string, policy: string | undefined): Location {
  const name = escapeRegExp(table.replace(/^public\./, ""));
  if (policy) {
    const at = findIn(migrations, new RegExp(String.raw`create\s+policy\s+"${escapeRegExp(policy)}"`, "i"), true);
    if (at) return at;
  }
  const created = new RegExp(
    String.raw`create\s+(?:or\s+replace\s+)?(?:materialized\s+)?(?:table|view)\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?${name}"?[\s(]`,
    "i",
  );
  return (
    findIn(migrations, created, false) ?? { kind: "file", file: migrations[0]?.path ?? "supabase/migrations", line: 1 }
  );
}

const ACTOR_WORD = { anon: "a visitor without an account", "other-user": "user B", owner: "the row's owner" } as const;

/** One line of evidence: what got through, in counts. */
export function describeLeaks(proof: Proof): string {
  const parts = proof.leaks.map((c) =>
    c.action === "insert"
      ? `${ACTOR_WORD[c.actor]} inserted a row in user A's name`
      : c.column
        ? `${ACTOR_WORD[c.actor]} changed \`${c.column}\``
        : `${ACTOR_WORD[c.actor]} could ${c.action} ${c.rows} of ${c.of} of user A's rows`,
  );
  return `RLS probe on \`${proof.table}\`: ${parts.join("; ")}.`;
}

/**
 * Adds the probe's proof to the static findings about the same table, and turns leaks no static rule
 * explains into findings of their own.
 */
export function mergeProbe(raws: RawFinding[], result: ProbeResult, migrations: SqlFile[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const table of result.tables) {
    if (table.skipped) continue;
    const proof = toProof(table);
    const covering = raws.filter((r) => r.subject === table.table && TABLE_RULES.has(r.rule));
    for (const raw of covering) raw.proof = proof;
    if (covering.length || !proof.leaks.length) continue;
    const weak = weakPolicies(proof);
    const through = weak.length
      ? ` Let through by ${weak.map((p) => `policy "${p.name}" (${p.command}, \`${p.withCheck && p.command === "insert" ? `with check ${p.withCheck}` : `using ${p.using ?? "true"}`}\`)`).join(" and ")}.`
      : "";
    out.push({
      source: "rls-probe",
      rule: "rls-probe-leak",
      toolSeverity: proof.leaks[0]?.actor ?? "anon",
      message: `${describeLeaks(proof)}${through}`,
      location: locate(migrations, table.table, weak[0]?.name),
      subject: table.table,
      proof,
    });
  }
  return out;
}

export async function runRlsProbe(
  migrations: SqlFile[],
  tolerant = false,
): Promise<{ result?: ProbeResult; tool: ToolRun; note?: string }> {
  const command = "prelaunch-audit rls-probe (PGlite + Supabase shim, rolled-back tries as anon and a second user)";
  const tool: ToolRun = { name: "rls-probe", version: PROBE_VERSION, command, status: "ok" };
  if (!migrations.length) {
    return {
      tool: {
        ...tool,
        status: "skipped",
        note: "No SQL schema files (supabase/migrations, schema.sql, sql/, prisma/migrations).",
      },
    };
  }
  let result: ProbeResult;
  try {
    result = await probeRls(migrations, tolerant);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    result = {
      tables: [],
      migrations: migrations.length,
      skippedExtensions: [],
      failedStatements: [],
      error: `the probe crashed: ${reason}`,
    };
  }
  if (result.error) {
    return {
      tool: { ...tool, status: "failed", note: result.error },
      note: `Row Level Security was not tested by behaviour: ${result.error} Only the static checks ran.`,
    };
  }
  const skipped = result.tables.filter((t) => t.skipped);
  const tested = result.tables.length - skipped.length;
  return {
    result,
    tool: {
      ...tool,
      note: [
        `${tested} tables and views tried as anon and as a second user.`,
        skipped.length ? `Not tried: ${skipped.map((t) => `${t.table} (${t.skipped})`).join("; ")}.` : "",
        result.failedStatements.length
          ? `Stepped over ${result.failedStatements.length} statement(s) of schema files outside supabase/migrations that Postgres rejected (${[...new Set(result.failedStatements.map((f) => f.file))].join(", ")}); tables they name were not tried.`
          : "",
        result.skippedExtensions.length
          ? `Stepped over platform extensions: ${result.skippedExtensions.join(", ")}.`
          : "",
      ]
        .filter(Boolean)
        .join(" "),
    },
  };
}
