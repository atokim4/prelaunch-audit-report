import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { HIPAA_DOCS_URL } from "../scanners/phi.ts";
import { PHI_RUBRIC, plainRisk, repoRuleTable, RUBRIC } from "../rubric.ts";
import {
  SEVERITIES,
  type Action,
  type Actor,
  type AuditResult,
  type Effort,
  type Finding,
  type LiveBucket,
  type LiveCount,
  type LiveDrift,
  type LiveResult,
  type LiveTable,
  type LiveVerdict,
  type PhiResult,
  type ProbeCheck,
  type Proof,
  type Severity,
} from "../types.ts";

export interface RenderOptions {
  /** Printed on the cover under the title, e.g. that this is a sample run on a demo app. */
  note?: string;
  /** Command lines for the appendix, as the reader would type them. */
  reproduce?: string[];
}

const esc = (value: string): string =>
  value.replace(
    /[&<>"']/g,
    (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch] ?? ch,
  );

/** Inline `code` in rubric prose → <code>. Everything else is escaped. */
const prose = (value: string): string => esc(value).replace(/`([^`]+)`/g, "<code>$1</code>");

const LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

const EFFORT_HOURS: Record<Effort, [number, number]> = {
  "under 1 hour": [0.5, 1],
  "1-4 hours": [1, 4],
  "half a day to a day": [4, 8],
};

export function effortRange(findings: Finding[]): [number, number] {
  return findings.reduce<[number, number]>(
    ([lo, hi], f) => [lo + EFFORT_HOURS[f.effort][0], hi + EFFORT_HOURS[f.effort][1]],
    [0, 0],
  );
}

const where = (f: Finding): string =>
  f.location.kind === "file" ? `${f.location.file}:${f.location.line}` : f.location.url;

const date = (iso: string): string =>
  new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

const tag = (s: Severity): string => `<span class="sev sev-${s}"><i aria-hidden="true"></i>${LABEL[s]}</span>`;

function diffHtml(diff: string): string {
  const rows = diff
    .replace(/\n$/, "")
    .split("\n")
    .filter((line) => !line.startsWith("diff --git") && !line.startsWith("new file mode"))
    .map((line) => {
      const kind =
        line.startsWith("+++") || line.startsWith("---")
          ? "file"
          : line.startsWith("@@")
            ? "hunk"
            : line.startsWith("+")
              ? "add"
              : line.startsWith("-")
                ? "del"
                : "ctx";
      return `<span class="d-${kind}">${esc(line) || " "}</span>`;
    });
  return `<pre class="diff"><code>${rows.join("")}</code></pre>`;
}

const ACTOR_LABEL: Record<Actor, string> = {
  anon: "Visitor, no account",
  "other-user": "Another user",
  owner: "Owner",
};
const ACTIONS: Action[] = ["select", "insert", "update", "delete"];
const ACTION_LABEL: Record<Action, string> = {
  select: "read",
  insert: "insert as A",
  update: "update",
  delete: "delete",
};

function cell(check: ProbeCheck | undefined, leaked: boolean): string {
  if (!check) return `<td class="pc pc-na">–</td>`;
  if (check.inconclusive) return `<td class="pc pc-unknown" title="${esc(check.inconclusive)}">?</td>`;
  const text =
    check.action === "insert" ? (check.rows ? "got in" : "blocked") : check.rows ? `${check.rows}/${check.of}` : "0";
  return `<td class="pc ${leaked ? "pc-leak" : "pc-ok"}">${esc(text)}</td>`;
}

function ownerText(proof: Proof): string {
  if (proof.ownerColumns.length)
    return ` (owner column: <code>${proof.ownerColumns.map(esc).join("</code>, <code>")}</code>)`;
  if (proof.ownedVia) {
    return ` (owned through <code>${esc(proof.ownedVia.column)}</code> → <code>${esc(proof.ownedVia.parent)}</code>)`;
  }
  return ", no owner column (shared data)";
}

/** The probe's tries on one table, as a small grid: actors down, actions across. */
function proofHtml(proof: Proof): string {
  const leaked = new Set(proof.leaks);
  const rows = (["anon", "other-user"] as const)
    .map((actor) => {
      const cells = ACTIONS.map((action) => {
        const check = proof.checks.find((c) => c.actor === actor && c.action === action && !c.column);
        return cell(check, check ? leaked.has(check) : false);
      });
      return `<tr><th scope="row">${ACTOR_LABEL[actor]}</th>${cells.join("")}</tr>`;
    })
    .join("");
  const escalations = proof.checks
    .filter((c) => c.actor === "owner" && c.column)
    .map((c) => `<code>${esc(c.column ?? "")}</code> ${c.rows ? '<b class="pc-leak-text">changed</b>' : "refused"}`);
  const after = proof.afterPatches;
  const verdict =
    after === undefined
      ? ""
      : proof.leaks.length === 0
        ? ""
        : after.length === 0
          ? `<p class="probe-after">Same harness with the report's patches applied: <b>0 leaks</b>.</p>`
          : `<p class="probe-after">Same harness with the report's patches applied: <b>${after.length} still open</b> (${after.map((c) => `${ACTOR_LABEL[c.actor].toLowerCase()} ${c.column ? `changes ${c.column}` : ACTION_LABEL[c.action]}`).join(", ")}).</p>`;
  return `<section class="probe">
    <h4>Tested in Postgres</h4>
    <p class="probe-what">User A owns ${proof.kind === "view" ? "the rows behind this view" : "one row"}; each cell is what the actor got in a rolled-back transaction${ownerText(proof)}.${proof.checks.some((c) => c.inconclusive) ? ` "?" means the try failed for another reason (a constraint the test values broke), so it proves nothing either way.` : ""}</p>
    <table class="probe-grid"><thead><tr><th></th>${ACTIONS.map((a) => `<th>${ACTION_LABEL[a]}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>
    ${escalations.length ? `<p class="probe-what">Owner editing paid columns on their own row: ${escalations.join(", ")}.</p>` : ""}
    ${verdict}
  </section>`;
}

/** Every table the probe tried, one line each: the access matrix for the summary. */
function matrixHtml(matrix: Proof[]): string {
  const rows = matrix
    .map((p) => {
      const read = (actor: Actor) => p.checks.find((c) => c.actor === actor && c.action === "select");
      const write = (actor: Actor) =>
        p.leaks
          .filter((c) => c.actor === actor && c.action !== "select" && !c.column)
          .map((c) => ACTION_LABEL[c.action]);
      const readCell = (actor: Actor) => {
        const check = read(actor);
        return cell(check, check ? p.leaks.includes(check) : false);
      };
      const writeCell = (actor: Actor) => {
        const w = write(actor);
        const text = w.length === 3 ? "all" : w.map((a) => a.replace(" as A", "")).join(", ");
        return `<td class="pc ${w.length ? "pc-leak" : "pc-ok"}">${w.length ? esc(text) : "none"}</td>`;
      };
      const own = p.leaks.filter((c) => c.actor === "owner").map((c) => c.column ?? "");
      const ownText = own.length > 1 ? `${own[0]} +${own.length - 1}` : (own[0] ?? "");
      return `<tr><td><code>${esc(p.table.replace(/^public\./, ""))}</code>${p.kind === "view" ? ' <span class="kind">view</span>' : ""}</td>${readCell("anon")}${writeCell("anon")}${readCell("other-user")}${writeCell("other-user")}<td class="pc ${own.length ? "pc-leak" : "pc-ok"}">${own.length ? esc(ownText) : "none"}</td></tr>`;
    })
    .join("");
  return `<h4>Who can reach user A's rows</h4>
    <p class="probe-what">The RLS probe ran your migrations in a local Postgres, gave user A one row per table and tried every action as a visitor without an account and as a second user. Red cells got through: "1/1" means one of user A's one rows. "Self-upgrade" is user A changing a plan or billing column on their own row. A table with no owner column of its own belongs to the owner of the row its foreign key points at; shared tables with no owner at all (price lists) count only writes. "?" is a try that failed for another reason and proves nothing.</p>
    <table class="matrix"><thead><tr><th>Table</th><th>Visitor read</th><th>Visitor write</th><th>User B read</th><th>User B write</th><th>Self-upgrade</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function liveCell(c: LiveCount | undefined, leaked = false): string {
  if (!c) return `<td class="pc pc-na">–</td>`;
  switch (c.status) {
    case "count":
      return `<td class="pc ${leaked && c.n > 0 ? "pc-leak" : "pc-ok"}">${c.n}</td>`;
    case "blocked":
      return `<td class="pc pc-ok" title="${esc(c.code)}">refused</td>`;
    case "missing":
      return `<td class="pc pc-na" title="${esc(c.code)}">missing</td>`;
    case "inconclusive":
      return `<td class="pc pc-unknown" title="${esc(c.reason)}">?</td>`;
  }
}

const VERDICT_LABEL: Record<LiveVerdict, string> = {
  leak: "leaks",
  protected: "protected",
  inconclusive: "no answer",
  shared: "shared data",
  missing: "not on live",
};
const verdictCell = (v: LiveVerdict): string =>
  `<td class="pc ${v === "leak" ? "pc-leak" : v === "protected" || v === "shared" ? "pc-ok" : "pc-unknown"}">${VERDICT_LABEL[v]}</td>`;

const DRIFT_LABEL: Record<LiveDrift["kind"], string> = {
  "fixed-outside-migrations": "Fixed in the dashboard only",
  "opened-outside-migrations": "Opened in the dashboard",
  "not-in-migrations": "Not in the migrations",
  "not-deployed": "Not deployed",
};

/** Owner-filtered columns: A's own rows, then what user B and a visitor get of them. */
function liveRow(t: LiveTable): string {
  const name = `<code>${esc(t.table.replace(/^public\./, ""))}</code>${t.relation === "view" ? ' <span class="kind">view</span>' : ""}`;
  const repo = t.foundIn.includes("migrations") ? (t.foundIn.includes("types") ? "both" : "migrations") : "types only";
  const bLeak = t.leaks.includes("user-b");
  const bCell = t.rowsOfA ? liveCell(t.rowsOfA["user-b"], bLeak) : liveCell(t.visible["user-b"], bLeak && !t.rowsOfA);
  return `<tr><td>${name}</td><td>${repo}</td>${liveCell(t.visible.anon, t.leaks.includes("anon"))}${liveCell(t.ownRowsA)}${t.ownerColumns.length || t.ownedVia ? bCell : `<td class="pc pc-na">–</td>`}${verdictCell(t.verdict)}</tr>`;
}

function bucketRow(b: LiveBucket): string {
  const access = b.public === undefined ? "?" : b.public ? "public" : "private";
  return `<tr><td><code>${esc(b.bucket)}</code></td><td>${access}</td>${liveCell(b.folderOfA.anon, true)}${liveCell(b.folderOfA["user-a"])}${liveCell(b.folderOfA["user-b"], true)}${verdictCell(b.verdict)}</tr>`;
}

/** The consented probe of the live project: counts per table, storage folders, drift, RPCs listed. */
function liveHtml(live: LiveResult): string {
  const leaking =
    live.tables.filter((t) => t.verdict === "leak").length + live.buckets.filter((b) => b.verdict === "leak").length;
  const unclear = live.tables.filter((t) => t.verdict === "inconclusive");
  return `<section class="part live">
    <h2>The live project</h2>
    <p>With the owner's written consent, the probe sent ${live.requests} read-only requests to <code>${esc(live.project)}</code> with the ${live.keyKind === "publishable" ? "publishable" : "anon"} key every visitor's browser has, once with no account and once as each of two test users the owner created (A and B). ${leaking ? `<strong>${leaking} of the checks below leak on the running project.</strong>` : "Nothing leaked on the running project."}</p>
    <h4>Rows each person can see</h4>
    <p class="probe-what">"Visitor" is everything a visitor without an account can count in the table. "A's rows" is what user A sees of their own rows. "B sees of A's" is how many of those user B gets (for tables owned through a parent row: rows of other users in total). Counts only: no row was downloaded.</p>
    <table class="matrix live-matrix"><thead><tr><th>Table</th><th>In the repo</th><th>Visitor</th><th>A's rows</th><th>B sees of A's</th><th>Result</th></tr></thead><tbody>${live.tables.map(liveRow).join("")}</tbody></table>
    ${unclear.length ? `<p class="probe-what">No answer: ${unclear.map((t) => `<code>${esc(t.table.replace(/^public\./, ""))}</code> (${prose(t.summary)})`).join("; ")}</p>` : ""}
    ${
      live.buckets.length
        ? `<h4>Storage: user A's folder</h4>
    <p class="probe-what">Entries listed under <code>&lt;user A id&gt;/</code>, the folder layout Supabase's storage docs use for per-user files.</p>
    <table class="matrix live-matrix"><thead><tr><th>Bucket</th><th>Access</th><th>Visitor</th><th>User A</th><th>User B</th><th>Result</th></tr></thead><tbody>${live.buckets.map(bucketRow).join("")}</tbody></table>`
        : ""
    }
    ${
      live.drift.length
        ? `<h4>Where the live project and the migrations disagree</h4>
    <table><thead><tr><th>Table</th><th>Drift</th><th>What it means</th></tr></thead><tbody>${live.drift
      .map(
        (d) =>
          `<tr><td><code>${esc(d.table.replace(/^public\./, ""))}</code></td><td>${DRIFT_LABEL[d.kind]}</td><td>${prose(d.detail)}</td></tr>`,
      )
      .join("")}</tbody></table>`
        : ""
    }
    ${
      live.rpcs.length
        ? `<h4>RPC functions (listed, not called)</h4>
    <p class="probe-what">${live.rpcs.map((r) => `<code>${esc(r.name)}</code>${r.securityDefiner ? " (security definer)" : ""}`).join(", ")}. The probe never calls a function on a live project: a function can write. Their grants are covered by the repo checks.</p>`
        : ""
    }
    <h4>How it was run</h4>
    <ul class="caveats">${live.notes.map((n) => `<li>${prose(n)}</li>`).join("")}</ul>
  </section>`;
}

/** Live reads say nothing about a finding that is only about writes (an insert or self-upgrade hole). */
const writeOnly = (f: Finding): boolean =>
  Boolean(f.proof?.leaks.length) && !f.proof?.leaks.some((c) => c.action === "select" && c.actor !== "owner");

/** The live result for the table or bucket a finding is about. */
function liveNote(f: Finding, live: LiveTable | LiveBucket, drift: LiveDrift[]): string {
  const label =
    live.verdict === "leak"
      ? '<b class="pc-leak-text">leaks</b>'
      : live.verdict === "protected"
        ? "<b>protected</b>"
        : `<b>${VERDICT_LABEL[live.verdict]}</b>`;
  const where = live.kind === "live-table" ? live.table : `storage:${live.bucket}`;
  const fixedLive = drift.some((d) => d.table === where && d.kind === "fixed-outside-migrations");
  const extra = writeOnly(f)
    ? " This finding is about writes, which the live probe never tries, so it stands as tested locally."
    : fixedLive
      ? ` The repo still has the hole: the fix lives only in the database, so commit it as a migration${f.patch?.verified ? " (the patch here does that)" : ""}.`
      : "";
  return `<p class="probe-after">Reads on the live project: ${label}. ${prose(live.summary)}${extra}</p>`;
}

/** High findings that have no patch because the fix is a decision, not a code change. */
const NO_PATCH: Record<string, string> = {
  "phi-vendor-egress":
    "No patch: the fix is a decision only you can make (sign a BAA with the vendor, or stop sending these fields), so no diff is offered.",
  "phi-table-unmanaged":
    "No patch: the table's real policies live only in the database. Pull them into a migration first; the scan can then test and patch them.",
  "phi-session-replay": "No patch for this vendor: remove the script from the pages that show health data.",
};

const STATUS_LABEL = { ok: "ok", gap: "gap", confirm: "confirm" } as const;

function phiHtml(phi: PhiResult): string {
  const readCell = (t: PhiResult["tables"][number]): string => {
    if (!t.readBy)
      return `<td class="pc pc-unknown">${t.untested === "no rows to test" ? "no rows to test" : "not tried"}</td>`;
    if (!t.readBy.length) return `<td class="pc pc-ok">nobody</td>`;
    const who = t.readBy.map((a) => (a === "anon" ? "visitor" : "user B")).join(", ");
    return `<td class="pc pc-leak">${esc(who)}</td>`;
  };
  const rows = phi.tables
    .map(
      (t) =>
        `<tr><td><code>${esc(t.table.replace(/^public\./, ""))}</code>${t.relation === "view" ? ' <span class="kind">view</span>' : ""}${t.foundIn.includes("migrations") ? "" : ' <span class="kind">types only</span>'}</td><td>${t.columns
          .map((c) => `<code class="phi-${c.kind}">${esc(c.name)}</code>`)
          .join(
            " ",
          )}</td>${readCell(t)}<td class="pc ${t.relation === "view" ? "pc-na" : t.audited ? "pc-ok" : "pc-leak"}">${t.relation === "view" ? "–" : t.audited ? "yes" : "no"}</td></tr>`,
    )
    .join("");
  const trackers = phi.trackers.length
    ? `<h4>Third-party scripts on pages with health data</h4><ul class="plain">${phi.trackers
        .map(
          (t) =>
            `<li><b>${esc(t.vendor)}</b>${t.replay ? " (can record the screen)" : ""}, loaded in <code>${esc(`${t.file}:${t.line}`)}</code>, runs on ${t.pages.map((p) => `<code>${esc(p)}</code>`).join(", ")}.</li>`,
        )
        .join("")}</ul>`
    : "";
  const controls = phi.controls
    .map(
      (c) =>
        `<tr><td>${esc(c.control)}</td><td>${c.where === "repo" ? "checked in the code" : "dashboard"}</td><td class="st st-${c.status}">${STATUS_LABEL[c.status]}</td><td>${esc(c.detail)}</td></tr>`,
    )
    .join("");
  return `<section class="part phi">
    <h2>Health data</h2>
    <p>This run used the health-data mode. It finds protected health information (PHI) by column name, checks who could read it in the RLS probe, and follows it into scripts, vendor calls, logs and storage. It is a technical scan, not a HIPAA compliance assessment, and nothing in it is legal advice.</p>
    <h4>Where health data lives</h4>
    <p class="probe-what">Columns in <span class="phi-health">dark</span> hold clinical content; the others identify the patient. "Read by others" is what the local probe saw when it gave user A one row and read as a visitor and as user B. Check this map against your schema: a column the names do not give away is not in it.</p>
    <table class="matrix phi-map"><thead><tr><th>Table</th><th>PHI columns</th><th>Read by others</th><th>Audit trigger</th></tr></thead><tbody>${rows}</tbody></table>
    ${trackers}
    <h4>Supabase HIPAA customer controls</h4>
    <p class="probe-what">Supabase lists these as the customer's side of storing health data (<a href="${HIPAA_DOCS_URL}">shared responsibility model</a>, read ${esc(date(`${phi.docsReadOn}T00:00:00Z`))}), plus the two rows at the end that come from this scan. Most are dashboard settings the code cannot show; "confirm" means check it yourself before launch.</p>
    <table class="controls"><thead><tr><th>Control</th><th>Where</th><th>Status</th><th>What the scan saw</th></tr></thead><tbody>${controls}</tbody></table>
  </section>`;
}

function findingHtml(f: Finding, drift: LiveDrift[]): string {
  const patch = f.patch
    ? `<section class="patch">
        <h4>Patch</h4>
        <p>${prose(f.patch.summary)}</p>
        ${f.patch.partial ? `<p class="partial"><b>Partial fix.</b> ${prose(f.patch.partial)}</p>` : ""}
        ${diffHtml(f.patch.diff)}
        <p class="check">${f.patch.verified ? "Applies cleanly to the audited code (<code>git apply --check</code>)." : "Did not pass <code>git apply --check</code>: apply by hand."}</p>
        ${f.patch.caveats.length ? `<ul class="caveats">${f.patch.caveats.map((c) => `<li>${prose(c)}</li>`).join("")}</ul>` : ""}
      </section>`
    : f.severity === "critical" || f.severity === "high"
      ? NO_PATCH[f.rule]
        ? `<p class="partial"><b>No patch.</b> ${prose(NO_PATCH[f.rule]?.replace(/^No patch[^:]*: /, "") ?? "")}</p>`
        : ""
      : "";
  return `<article class="finding" id="${f.id}">
    <aside class="apparatus">
      <p class="fid">${f.id}</p>
      ${tag(f.severity)}
      <dl>
        ${f.cwe ? `<dt>CWE</dt><dd><a href="https://cwe.mitre.org/data/definitions/${f.cwe.id}.html">CWE-${f.cwe.id}</a></dd>` : ""}
        <dt>Effort</dt><dd>${esc(f.effort)}</dd>
        <dt>Source</dt><dd>${esc(f.source)}<br><span class="rule">${esc(f.rule)}</span></dd>
      </dl>
    </aside>
    <div class="body">
      <h3>${esc(f.title)}</h3>
      <p class="where"><code>${esc(where(f))}</code></p>
      ${f.evidence ? `<p class="evidence">${prose(f.evidence)}</p>` : ""}
      ${f.snippet ? `<pre class="snippet"><code>${esc(f.snippet)}</code></pre>` : ""}
      ${f.phi?.length ? `<p class="also">Health data involved: ${f.phi.map((c) => `<code>${esc(c)}</code>`).join(", ")}.</p>` : ""}
      ${f.alsoFlaggedBy.length ? `<p class="also">Also flagged by <code>${f.alsoFlaggedBy.map(esc).join("</code>, <code>")}</code> on the same object.</p>` : ""}
      <h4>Why it matters</h4>
      <p>${prose(f.whyItMatters)}</p>
      <h4>Fix</h4>
      <p>${prose(f.fix)}</p>
      ${f.proof ? proofHtml(f.proof) : ""}
      ${f.live ? liveNote(f, f.live, drift) : ""}
      ${f.cwe ? `<p class="cwe">${esc(`CWE-${f.cwe.id}${f.cwe.name ? `: ${f.cwe.name}` : ""}`)}</p>` : ""}
      ${patch}
    </div>
  </article>`;
}

function tally(result: AuditResult): string {
  const cells = result.findings.map((f) => `<i class="t-${f.severity}" title="${f.id}"></i>`).join("");
  return `<div class="tally" role="img" aria-label="${result.findings.length} findings by severity">${cells}</div>`;
}

const hours = (n: number): string => (Number.isInteger(n) ? String(n) : n.toFixed(1));

async function fontFaces(): Promise<string> {
  const require = createRequire(import.meta.url);
  const faces: [string, string, number, string][] = [
    ["Source Serif 4", "@fontsource/source-serif-4/files/source-serif-4-latin-400-normal.woff2", 400, "normal"],
    ["Source Serif 4", "@fontsource/source-serif-4/files/source-serif-4-latin-400-italic.woff2", 400, "italic"],
    ["Source Serif 4", "@fontsource/source-serif-4/files/source-serif-4-latin-600-normal.woff2", 600, "normal"],
    ["IBM Plex Sans", "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2", 400, "normal"],
    ["IBM Plex Sans", "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-600-normal.woff2", 600, "normal"],
    ["IBM Plex Mono", "@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2", 400, "normal"],
  ];
  const css = await Promise.all(
    faces.map(async ([family, file, weight, style]) => {
      const data = (await readFile(require.resolve(file))).toString("base64");
      return `@font-face{font-family:"${family}";src:url(data:font/woff2;base64,${data}) format("woff2");font-weight:${weight};font-style:${style};font-display:block}`;
    }),
  );
  return css.join("\n");
}

const CSS = String.raw`
:root{
  --ink:#1c2230;--ink-2:#4d5463;--rule:#ddd6c8;--wash:#f4f0e7;--paper:#fffdf9;
  --critical:#a8261b;--high:#a34a06;--medium:#7d6200;--low:#4a5b70;
  --add:#e3f1e2;--add-ink:#1f5a28;--del:#f8e3df;--del-ink:#8c2318;
  --serif:"Source Serif 4",Georgia,serif;--sans:"IBM Plex Sans",system-ui,sans-serif;--mono:"IBM Plex Mono",ui-monospace,monospace;
}
@page{size:A4;margin:18mm 17mm 20mm}
*{box-sizing:border-box}
html{background:var(--wash)}
body{margin:0;color:var(--ink);font:400 10.5pt/1.5 var(--serif);font-variant-numeric:lining-nums;-webkit-print-color-adjust:exact;print-color-adjust:exact}
::selection{background:#f1d9a6}
.sheet{max-width:210mm;margin:0 auto;padding:18mm 17mm;background:var(--paper)}
@media screen{.sheet{margin:24px auto;box-shadow:0 2px 14px rgb(28 34 48 / .12)}}
@media print{html,.sheet{background:#fff}.sheet{padding:0;max-width:none}}
h1,h2,h3,h4{font-weight:600;line-height:1.2;text-wrap:balance;margin:0}
h2{font-size:17pt;margin:0 0 5mm;padding-bottom:2mm;border-bottom:1.5px solid var(--ink)}
h3{font-size:13pt;margin-bottom:1.5mm}
h4{font:600 8pt/1.3 var(--sans);letter-spacing:.06em;text-transform:uppercase;color:var(--ink-2);margin:4mm 0 1mm}
p{margin:0 0 2.2mm;max-width:68ch}
a{color:inherit;text-decoration-color:var(--rule);text-underline-offset:2px}
code,pre{font-family:var(--mono);font-size:8.4pt}
p code,li code,td code,dd code{background:var(--wash);padding:0 .25em;border-radius:2px;overflow-wrap:anywhere}
pre{margin:1.5mm 0 3mm;padding:2.5mm 3mm;background:var(--wash);border-radius:3px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.45}
.sev{display:inline-flex;align-items:center;gap:1.6mm;font:600 8pt/1 var(--sans);letter-spacing:.05em;text-transform:uppercase}
.sev i{width:2.6mm;height:2.6mm;border-radius:.5mm;background:currentColor}
.sev-critical{color:var(--critical)}.sev-high{color:var(--high)}.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}
section.part{break-before:page}

/* Cover */
.cover{display:flex;flex-direction:column;min-height:255mm}
.mast{display:flex;justify-content:space-between;font:600 8pt/1.4 var(--sans);letter-spacing:.08em;text-transform:uppercase;color:var(--ink-2);border-bottom:1px solid var(--ink);padding-bottom:2mm}
.cover h1{font-size:34pt;letter-spacing:-.015em;margin:26mm 0 3mm;max-width:14ch}
.cover .app{font-size:15pt;margin-bottom:8mm}
.cover .app code{font-size:13pt;background:none;padding:0}
.note{font:400 9pt/1.5 var(--sans);color:var(--ink-2);border:1px solid var(--rule);padding:2.5mm 3.5mm;border-radius:3px;max-width:none}
.result{margin:12mm 0 0}
.counts{display:grid;grid-template-columns:repeat(4,1fr);gap:4mm;margin:0 0 4mm}
.counts div{border-top:2px solid currentColor;padding-top:2mm}
.counts b{display:block;font:600 26pt/1 var(--serif);color:var(--ink)}
.tally{display:flex;gap:1mm;flex-wrap:wrap}
.tally i{flex:0 0 5mm;height:5mm;border-radius:.6mm}
.t-critical{background:var(--critical)}.t-high{background:var(--high)}.t-medium{background:var(--medium)}.t-low{background:var(--low)}
.scope{display:grid;grid-template-columns:1fr 1fr;gap:8mm;margin-top:auto;padding-top:10mm;font-size:9.5pt}
.scope ul{margin:0;padding-left:4mm}.scope li{margin-bottom:1.2mm}
.scope h4{margin-top:0}

/* Summary */
.risks{list-style:none;counter-reset:r;padding:0;margin:0 0 6mm}
.risks li{counter-increment:r;display:grid;grid-template-columns:9mm 1fr;padding:3mm 0;border-bottom:1px solid var(--rule)}
.risks li::before{content:counter(r);font:600 18pt/1 var(--serif);color:var(--ink-2)}
.risks strong{display:block;font-size:12pt;margin-bottom:.8mm}
.risks .meta{font:400 8.5pt/1.4 var(--sans);color:var(--ink-2)}
table{width:100%;border-collapse:collapse;font:400 8.6pt/1.4 var(--sans);margin:0 0 5mm}
th{font-weight:600;text-align:left;color:var(--ink-2);border-bottom:1px solid var(--ink);padding:1.5mm 2mm 1.5mm 0}
td{border-bottom:1px solid var(--rule);padding:1.6mm 2mm 1.6mm 0;vertical-align:top}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
tr{break-inside:avoid}
td:first-child{white-space:nowrap}

/* Findings */
.finding{display:grid;grid-template-columns:30mm 1fr;gap:6mm;padding:5mm 0 3mm;border-top:1px solid var(--ink)}
.finding+.finding{break-before:auto}
h2{break-after:avoid}
.body h4,.where{break-after:avoid}
.snippet,.probe,.partial,.caveats li,.evidence{break-inside:avoid}
.apparatus{font:400 8pt/1.4 var(--sans);color:var(--ink-2)}
.apparatus .fid{font:600 15pt/1 var(--serif);color:var(--ink);margin-bottom:2mm}
.apparatus dl{margin:3mm 0 0}.apparatus dt{font-weight:600;letter-spacing:.05em;text-transform:uppercase;font-size:7pt;margin-top:2mm}
.apparatus dd{margin:0}.apparatus .rule{overflow-wrap:anywhere}
.body{min-width:0}
.body h3{break-after:avoid}
.where{font-size:9pt;margin-bottom:2mm}.where code{background:none;padding:0;color:var(--ink-2)}
.also,.cwe,.check{font:400 8.5pt/1.4 var(--sans);color:var(--ink-2)}
.diff{background:#fbfaf6;border:1px solid var(--rule)}
.d-add{display:block;background:var(--add);color:var(--add-ink)}
.d-del{display:block;background:var(--del);color:var(--del-ink)}
.d-hunk,.d-ctx{display:block;color:var(--ink-2)}.d-ctx{color:var(--ink)}
.d-file{display:block;color:var(--ink-2);font-weight:600}
.caveats{margin:0;padding-left:4mm;font-size:9.5pt}.caveats li{margin-bottom:1mm}
.appendix p,.appendix li{font-size:9.5pt}

/* RLS probe */
.probe{margin:3mm 0 1mm}
.probe-what,.probe-after{font:400 8.5pt/1.45 var(--sans);color:var(--ink-2)}
.probe-after b{color:var(--ink)}
.probe-grid{width:auto;margin:1.5mm 0 2mm}
.probe-grid th,.probe-grid td{padding:1.2mm 3mm 1.2mm 0}
.probe-grid thead th{font-weight:600}
.probe-grid tbody th{font-weight:400;color:var(--ink);border-bottom:1px solid var(--rule);text-align:left;padding-right:5mm}
.pc{text-align:center;font-variant-numeric:tabular-nums;white-space:nowrap}
.matrix{table-layout:fixed}.matrix th:first-child{width:30%}
.matrix .pc{text-align:left;white-space:normal}
.pc-leak{color:var(--critical);font-weight:600}
.pc-leak::before{content:"";display:inline-block;width:1.8mm;height:1.8mm;border-radius:.4mm;background:var(--critical);margin-right:1.2mm;vertical-align:.2mm}
.pc-ok{color:var(--ink-2)}
.pc-na{color:var(--rule)}
.pc-unknown{color:var(--medium);font-weight:600}
.pc-leak-text{color:var(--critical)}
.partial{font-size:9.5pt;border-left:2px solid var(--high);padding-left:3mm}
.partial b{color:var(--high)}
.live-matrix th:first-child{width:24%}
.phi-map td:nth-child(2) code{font-size:8pt;color:var(--ink-2);margin-right:1mm}
.phi-map code.phi-health,.phi-health{color:var(--ink);font-weight:600}
.controls{table-layout:fixed;width:100%}
.controls td:first-child{white-space:normal;padding-right:3mm}
.controls th:nth-child(1){width:38%}.controls th:nth-child(2){width:15%}.controls th:nth-child(3){width:11%}
.controls td:nth-child(2){color:var(--ink-2);font-size:8.5pt}
.st{font-weight:600;text-transform:uppercase;font-size:7.5pt;letter-spacing:.05em;white-space:nowrap}
.st-gap{color:var(--critical)}
.st-ok{color:var(--ink-2)}
.st-confirm{color:var(--medium)}
ul.plain{padding-left:4mm}
.kind{font-size:7.5pt;color:var(--ink-2);text-transform:uppercase;letter-spacing:.05em}
`;

function shapeLine(result: AuditResult): string {
  const { shape } = result.app;
  const parts = [shape.label];
  if (shape.migrations) parts.push(`${shape.migrations} Supabase migrations`);
  if (shape.edgeFunctions.length) {
    parts.push(
      `${shape.edgeFunctions.length} edge function${shape.edgeFunctions.length === 1 ? "" : "s"} (${shape.edgeFunctions.map((f) => f.name).join(", ")})`,
    );
  }
  return parts.join(", ");
}

export async function renderHtml(result: AuditResult, options: RenderOptions = {}): Promise<string> {
  const { findings, counts } = result;
  const serious = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const top = findings.slice(0, 3);
  const [lo, hi] = effortRange(serious);
  const patched = findings.filter((f) => f.patch?.verified).length;
  const partial = findings.filter((f) => f.patch?.verified && f.patch.partial).length;

  const cover = `<section class="cover">
    <div class="mast"><span>Automated scan with patches${result.phi ? " · health-data mode" : ""}</span><span>${esc(date(result.generatedAt))}</span></div>
    <h1>Pre-launch security audit</h1>
    <p class="app">${esc(result.app.name)}${result.app.url ? ` · <code>${esc(result.app.url)}</code>` : ""}</p>
    ${options.note ? `<p class="note">${esc(options.note)}</p>` : ""}
    <div class="result">
      <div class="counts">${SEVERITIES.map((s) => `<div class="sev-${s}"><b>${counts[s]}</b>${tag(s)}</div>`).join("")}</div>
      ${tally(result)}
    </div>
    <div class="scope">
      <div><h4>What was checked</h4><ul>
        <li>Project: ${esc(shapeLine(result))}.</li>
        <li>Supabase migrations: RLS, policies, views, SECURITY DEFINER functions, storage buckets.</li>
        ${result.probe ? `<li>Row Level Security by behaviour: ${result.probe.length} tables and views tried as a visitor and as a second user in a local Postgres, before and after the patches.</li>` : ""}
        <li>App code: server keys in browser code, public env prefixes, the Stripe webhook${result.app.shape.edgeFunctions.length ? " (including Deno edge functions and their JWT setting)" : ""}.</li>
        <li>Credentials in the files and in git history.</li>
        ${result.tools.some((t) => t.name === "npm audit" && t.status === "ok") ? "<li>Runtime dependencies against npm's advisory database.</li>" : ""}
        ${result.live ? `<li>The live Supabase project, read-only and with consent: ${result.live.tables.length} tables and views${result.live.buckets.length ? ` and ${result.live.buckets.length} storage bucket${result.live.buckets.length === 1 ? "" : "s"}` : ""} counted as a visitor and two test users.</li>` : ""}
        ${result.phi ? `<li>Health data: ${result.phi.tables.length} tables and views with PHI by column name, scripts on the pages that show it, server calls to AI, email and SMS vendors, function logs, public buckets, audit triggers, and Supabase's HIPAA checklist.</li>` : ""}
        ${result.app.url ? "<li>The live site: HTTPS, security headers, cookies, exposed files, keys in JS bundles.</li>" : ""}
      </ul></div>
      <div><h4>What was not checked</h4><ul>${result.notChecked.map((n) => `<li>${prose(n)}</li>`).join("")}</ul></div>
    </div>
  </section>`;

  const summary = `<section class="part">
    <h2>Summary</h2>
    <p>The scan found <strong>${findings.length} issues</strong>: ${SEVERITIES.map((s) => `${counts[s]} ${LABEL[s].toLowerCase()}`).join(", ")}.
    ${serious.length ? `Fixing the ${serious.length} critical and high ones is about ${hours(lo)} to ${hours(hi)} hours of developer time, and ${patched} of the ${findings.length} come with a patch that applies to the code as it is${partial ? ` (${partial} of them partial: they close the exposure and say what a developer still has to move)` : ""}.` : "Nothing critical or high was found."}</p>
    ${
      top.length
        ? `<h4>The three biggest risks</h4><ol class="risks">${top
            .map(
              (f) =>
                `<li><div><strong>${esc(plainRisk(f))}</strong><span class="meta">${LABEL[f.severity]} · <a href="#${f.id}">${f.id}</a> · ${esc(f.title)}</span></div></li>`,
            )
            .join("")}</ol>`
        : ""
    }
    <h4>All findings</h4>
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Issue</th><th>Where</th><th>Effort</th><th>Patch</th></tr></thead>
      <tbody>${findings
        .map(
          (f) =>
            `<tr><td><a href="#${f.id}">${f.id}</a></td><td>${tag(f.severity)}</td><td>${esc(f.title)}</td><td><code>${esc(where(f))}</code></td><td>${esc(f.effort)}</td><td>${f.patch?.verified ? (f.patch.partial ? "partial" : "yes") : "no"}</td></tr>`,
        )
        .join("")}</tbody>
    </table>
    ${result.probe?.length ? matrixHtml(result.probe) : ""}
  </section>`;

  const liveSection = (result.phi ? phiHtml(result.phi) : "") + (result.live ? liveHtml(result.live) : "");
  const details = `<section class="part"><h2>Findings</h2>${findings.map((f) => findingHtml(f, result.live?.drift ?? [])).join("")}</section>`;

  const appendix = `<section class="part appendix">
    <h2>Appendix</h2>
    <h4>How severity is rated</h4>
    <p>Each rule is placed by the first line that fits. Live-site findings keep the severity apify-launch-audit gives them. When the RLS probe ran, the severity follows what it could really do: a visitor reading user rows is Critical even if the policy only looked suspicious, and an open read on a table with no owner column and no write leak is Low. Dependency advisories are one level below npm's rating, because the scan does not prove your code reaches the affected function.</p>
    <table><tbody>${RUBRIC.map((r) => `<tr><td>${tag(r.severity)}</td><td>${esc(r.rule)}</td></tr>`).join("")}</tbody></table>
    ${result.phi ? `<p>With the health-data mode on, these come first:</p><table><tbody>${PHI_RUBRIC.map((r) => `<tr><td>${tag(r.severity)}</td><td>${esc(r.rule)}</td></tr>`).join("")}</tbody></table>` : ""}
    <h4>Tools</h4>
    <table><thead><tr><th>Tool</th><th>Version</th><th>What ran</th></tr></thead><tbody>${result.tools
      .map(
        (t) =>
          `<tr><td>${esc(t.name)}</td><td>${esc(t.version)}</td><td><code>${esc(t.command)}</code>${t.note ? `<br>${esc(t.note)}` : ""}</td></tr>`,
      )
      .join("")}</tbody></table>
    <h4>Reproduce</h4>
    <pre><code>${esc((options.reproduce ?? [`prelaunch-audit ${result.app.repo}${result.app.url ? ` --url ${result.app.url}` : ""}`]).join("\n"))}</code></pre>
    <h4>Apply the patches</h4>
    <p>Each patch is in <code>patches/&lt;id&gt;.diff</code>. From the root of the repository: <code>git apply --check patches/PA-01.diff</code>, then <code>git apply patches/PA-01.diff</code>. New migrations go through <code>supabase db push</code> as usual. Read every patch first: they are written from the code as it was scanned and cannot know your intent.</p>
    <h4>Repo rules and their CWE</h4>
    <table><thead><tr><th>Rule</th><th>Issue</th><th>CWE</th></tr></thead><tbody>${repoRuleTable()
      .map(
        (r) =>
          `<tr><td><code>${esc(r.rule)}</code></td><td>${esc(r.title)}</td><td>${r.cwe ? `CWE-${r.cwe.id}` : "none"}</td></tr>`,
      )
      .join("")}</tbody></table>
  </section>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(`Pre-launch security audit: ${result.app.name}`)}</title>
<style>${await fontFaces()}${CSS}</style>
</head>
<body><main class="sheet">${cover}${summary}${liveSection}${details}${appendix}</main></body>
</html>
`;
}
