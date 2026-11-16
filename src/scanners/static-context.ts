import { createdTables, functionBody, statements, type SqlFile } from "../patches/sql.ts";
import { phiKind } from "../phi/columns.ts";
import type { RawFinding } from "../types.ts";

/** Columns that tie a row to one user. Audit columns (created_by, updated_by) are left out: they name an editor. */
const OWNER_COLUMN = /^(user_id|owner_id|profile_id|patient_id|author_id|account_id|member_id|customer_id|uid)$/i;
/** Columns about a person, beyond the PHI map: contact details and network identifiers. */
const PERSONAL_COLUMN =
  /^(full_name|first_name|last_name|email|e_?mail_address|phone|phone_number|mobile\w*|address|street\w*|ip_address|ip)$/i;

/** Columns of a pricing table: a plan table with none of them is a care or diet plan, not a paid tier. */
const BILLING_COLUMN = /price|amount|cost|stripe|billing|currency|interval|tier|fee|quota/i;
/** Bucket names that say the files are site content meant for everyone: logos, CMS images, marketing. */
const PUBLIC_CONTENT_BUCKET = /(^|[-_])(public|cms|site|static|marketing|brand(ing)?|logos?)([-_]|$)/i;

const CALLER = /\bauth\.(?:uid|jwt)\s*\(/i;

/**
 * True when the RLS probe tried what the static finding claims. The probe tests a column escalation only on
 * paid or role column names (plan, role…), so a finding about `plan_id` keeps its static context.
 */
export function proofTestsClaim(raw: RawFinding): boolean {
  if (!raw.proof) return false;
  if (raw.rule !== "rls-update-privileged-column") return true;
  const column = raw.message.match(/including `(\w+)`/)?.[1];
  return raw.proof.checks.some((c) => c.actor === "owner" && c.column === column);
}

/**
 * Adds what the repo's SQL says to findings the RLS probe could not prove (it did not run, or did not load
 * that table): whether an open read policy sits on a table of public content, and whether a definer function
 * open to visitors works on the caller's own id. The rubric uses it to rate those two cases lower.
 */
export function addStaticContext(raws: RawFinding[], sql: SqlFile[]): void {
  const tables = new Map([...createdTables(sql)].map(([name, columns]) => [name.toLowerCase(), columns]));
  for (const raw of raws) {
    if (proofTestsClaim(raw) || !raw.subject) continue;
    const subject = raw.subject.toLowerCase();
    if (raw.rule === "rls-permissive-policy" && /\(select\)/.test(raw.message)) {
      const columns = tables.get(subject);
      if (!columns) continue;
      const tableOwned = columns.some((c) => c.referencesAuthUsers || OWNER_COLUMN.test(c.name));
      const tablePersonal = columns.some((c) => PERSONAL_COLUMN.test(c.name) || phiKind(subject, c.name));
      raw.context = { tableOwned, tablePersonal };
    } else if (raw.rule === "rls-update-privileged-column") {
      const column = raw.message.match(/including `(\w+)`/)?.[1] ?? "";
      const target = column.match(/^(\w*plan)_id$/)?.[1];
      const plans = target ? (tables.get(`public.${target}s`) ?? tables.get(`public.${target}`)) : undefined;
      if (plans) raw.context = { carePlan: !plans.some((c) => BILLING_COLUMN.test(c.name)) };
    } else if (raw.rule === "storage-public-bucket") {
      const bucket = raw.message.match(/bucket `([^`]+)`/i)?.[1] ?? "";
      raw.context = { publicContentBucket: PUBLIC_CONTENT_BUCKET.test(bucket) };
    } else if (raw.rule === "definer-function-anon" && /default grant/i.test(raw.message)) {
      const body = functionBody(sql, subject);
      if (body !== undefined) raw.context = { checksCaller: CALLER.test(body) };
    }
  }
}

/** Static context that lowers a finding's severity, with the sentence that says why in the report. */
export function contextNote(raw: RawFinding): string | undefined {
  const c = raw.context;
  if (!c || proofTestsClaim(raw) || raw.proof?.leaks.length || raw.live?.verdict === "leak") return undefined;
  if (raw.rule === "rls-permissive-policy" && c.tableOwned === false && c.tablePersonal === false && !raw.phi?.length) {
    return "The table has no owner column and no personal columns, so this looks like public content. Confirm it is meant to be public and that nothing private is added to it later.";
  }
  if (raw.rule === "rls-update-privileged-column" && c.carePlan) {
    return "The plan column points to a table with no price, Stripe or billing column, so it reads as a care or diet plan the row's owner may set, not a paid tier. Confirm that.";
  }
  if (raw.rule === "storage-public-bucket" && c.publicContentBucket) {
    return "The bucket's name says it holds site content (logos, CMS images). Confirm nothing uploaded by users or patients ever lands in it.";
  }
  if (raw.rule === "definer-function-anon" && c.checksCaller) {
    return "The function reads auth.uid() or auth.jwt(), so a visitor runs it with no user id. Check what it does in that case, and revoke anon anyway.";
  }
  return undefined;
}

/**
 * Tables that get `enable row level security` from dynamic SQL: a DO block that loops over a list of names
 * and runs `execute format('alter table public.%I enable row level security', t)`. A scanner that reads
 * statements one by one sees no RLS on them; the list of names in the block says which tables it covers.
 */
export function dynamicRlsTables(sql: SqlFile[]): Set<string> {
  const out = new Set<string>();
  for (const file of sql) {
    for (const stmt of statements(file.text)) {
      if (!/^do\b/i.test(stmt) || !/format\s*\(\s*'[^']*%[Is][^']*enable\s+row\s+level\s+security/i.test(stmt))
        continue;
      const lists = [...stmt.matchAll(/(?:array\s*\[|\bin\s*\()([^\])]*)[\])]/gi)].map((m) => m[1] ?? "");
      for (const list of lists) {
        for (const name of list.matchAll(/'([A-Za-z_][\w]*)'/g)) out.add(`public.${(name[1] ?? "").toLowerCase()}`);
      }
    }
  }
  return out;
}
