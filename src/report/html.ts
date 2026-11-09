import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { plainRisk, repoRuleTable, RUBRIC } from "../rubric.ts";
import { SEVERITIES, type AuditResult, type Effort, type Finding, type Severity } from "../types.ts";

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

function findingHtml(f: Finding): string {
  const patch = f.patch
    ? `<section class="patch">
        <h4>Patch</h4>
        <p>${prose(f.patch.summary)}</p>
        ${diffHtml(f.patch.diff)}
        <p class="check">${f.patch.verified ? "Applies cleanly to the audited code (<code>git apply --check</code>)." : "Did not pass <code>git apply --check</code>: apply by hand."}</p>
        ${f.patch.caveats.length ? `<ul class="caveats">${f.patch.caveats.map((c) => `<li>${prose(c)}</li>`).join("")}</ul>` : ""}
      </section>`
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
      ${f.alsoFlaggedBy.length ? `<p class="also">Also flagged by <code>${f.alsoFlaggedBy.map(esc).join("</code>, <code>")}</code> on the same object.</p>` : ""}
      <h4>Why it matters</h4>
      <p>${prose(f.whyItMatters)}</p>
      <h4>Fix</h4>
      <p>${prose(f.fix)}</p>
      ${f.cwe ? `<p class="cwe">${esc(`CWE-${f.cwe.id}: ${f.cwe.name}`)}</p>` : ""}
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
.finding{display:grid;grid-template-columns:30mm 1fr;gap:6mm;padding:5mm 0 3mm;border-top:1px solid var(--ink);break-inside:avoid-page}
.finding+.finding{break-before:auto}
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
`;

export async function renderHtml(result: AuditResult, options: RenderOptions = {}): Promise<string> {
  const { findings, counts } = result;
  const serious = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const top = findings.slice(0, 3);
  const [lo, hi] = effortRange(serious);
  const patched = findings.filter((f) => f.patch?.verified).length;
  const repoChecked = result.tools.map((t) => `${t.name} ${t.version}`).join(", ");

  const cover = `<section class="cover">
    <div class="mast"><span>Automated scan with patches</span><span>${esc(date(result.generatedAt))}</span></div>
    <h1>Pre-launch security audit</h1>
    <p class="app">${esc(result.app.name)}${result.app.url ? ` · <code>${esc(result.app.url)}</code>` : ""}</p>
    ${options.note ? `<p class="note">${esc(options.note)}</p>` : ""}
    <div class="result">
      <div class="counts">${SEVERITIES.map((s) => `<div class="sev-${s}"><b>${counts[s]}</b>${tag(s)}</div>`).join("")}</div>
      ${tally(result)}
    </div>
    <div class="scope">
      <div><h4>What was checked</h4><ul>
        <li>Supabase migrations: RLS, policies, views, SECURITY DEFINER functions, storage buckets.</li>
        <li>App code: server keys in browser code, public env prefixes, the Stripe webhook.</li>
        <li>Credentials in the files and in git history.</li>
        ${result.app.url ? "<li>The live site: HTTPS, security headers, cookies, exposed files, keys in JS bundles.</li>" : ""}
        <li>Tools: ${esc(repoChecked)}.</li>
      </ul></div>
      <div><h4>What was not checked</h4><ul>${result.notChecked.map((n) => `<li>${prose(n)}</li>`).join("")}</ul></div>
    </div>
  </section>`;

  const summary = `<section class="part">
    <h2>Summary</h2>
    <p>The scan found <strong>${findings.length} issues</strong>: ${SEVERITIES.map((s) => `${counts[s]} ${LABEL[s].toLowerCase()}`).join(", ")}.
    ${serious.length ? `Fixing the ${serious.length} critical and high ones is about ${hours(lo)} to ${hours(hi)} hours of developer time, and ${patched} of the ${findings.length} come with a patch that applies to the code as it is.` : "Nothing critical or high was found."}</p>
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
            `<tr><td><a href="#${f.id}">${f.id}</a></td><td>${tag(f.severity)}</td><td>${esc(f.title)}</td><td><code>${esc(where(f))}</code></td><td>${esc(f.effort)}</td><td>${f.patch?.verified ? "yes" : "no"}</td></tr>`,
        )
        .join("")}</tbody>
    </table>
  </section>`;

  const details = `<section class="part"><h2>Findings</h2>${findings.map(findingHtml).join("")}</section>`;

  const appendix = `<section class="part appendix">
    <h2>Appendix</h2>
    <h4>How severity is rated</h4>
    <p>Each rule is placed by the first line that fits. Live-site findings keep the severity apify-launch-audit gives them.</p>
    <table><tbody>${RUBRIC.map((r) => `<tr><td>${tag(r.severity)}</td><td>${esc(r.rule)}</td></tr>`).join("")}</tbody></table>
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
<body><main class="sheet">${cover}${summary}${details}${appendix}</main></body>
</html>
`;
}
