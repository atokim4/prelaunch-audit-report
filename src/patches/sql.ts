/** Just enough SQL reading to write fix migrations: statements, tables, policies and function signatures. */

export interface SqlFile {
  path: string;
  text: string;
}

/** Strips comments and splits on top-level semicolons (quotes and $$ bodies respected). */
export function statements(sql: string): string[] {
  const out: string[] = [];
  let current = "";
  let i = 0;
  while (i < sql.length) {
    const rest = sql.slice(i);
    if (rest.startsWith("--")) {
      const end = sql.indexOf("\n", i);
      i = end === -1 ? sql.length : end;
      continue;
    }
    if (rest.startsWith("/*")) {
      const end = sql.indexOf("*/", i + 2);
      i = end === -1 ? sql.length : end + 2;
      continue;
    }
    const dollar = rest.match(/^\$[A-Za-z_]*\$/)?.[0];
    if (dollar) {
      const end = sql.indexOf(dollar, i + dollar.length);
      const stop = end === -1 ? sql.length : end + dollar.length;
      current += sql.slice(i, stop);
      i = stop;
      continue;
    }
    const ch = sql[i] ?? "";
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < sql.length && !(sql[j] === ch && sql[j + 1] !== ch)) j += sql[j] === ch ? 2 : 1;
      current += sql.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === ";") {
      if (current.trim()) out.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
    i += 1;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

/** Content of the parenthesised group that opens at `open` (which must be "("). */
export function balanced(text: string, open: number): string | undefined {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === "(") depth += 1;
    else if (text[i] === ")") {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return undefined;
}

/** Splits on commas that are not inside parentheses. */
export function splitTopLevel(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    if (ch === "," && depth === 0) {
      parts.push(current.trim());
      current = "";
    } else current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

/** `audit_log`, `"public"."audit_log"` and `public.audit_log` all become `public.audit_log`. */
export function qualify(name: string): string {
  const clean = name.replace(/"/g, "").trim().toLowerCase();
  return clean.includes(".") ? clean : `public.${clean}`;
}

const NAME = String.raw`((?:"[^"]+"|[\w]+)(?:\.(?:"[^"]+"|[\w]+))?)`;

export interface Column {
  name: string;
  definition: string;
  referencesAuthUsers: boolean;
  primaryKey: boolean;
}

const CREATE_TABLE = new RegExp(String.raw`^create\s+table\s+(?:if\s+not\s+exists\s+)?${NAME}\s*\(`, "i");

function columnsOf(stmt: string, match: RegExpMatchArray): Column[] | undefined {
  const body = balanced(stmt, match[0].length - 1);
  if (body === undefined) return undefined;
  return splitTopLevel(body)
    .filter((def) => !/^(constraint|primary\s+key|unique|check|foreign\s+key|exclude)\b/i.test(def))
    .map((def) => ({
      name: (def.split(/\s+/)[0] ?? "").replace(/"/g, ""),
      definition: def,
      referencesAuthUsers: /references\s+auth\.users\b/i.test(def),
      primaryKey: /primary\s+key/i.test(def),
    }));
}

export function tableColumns(files: SqlFile[], table: string): Column[] | undefined {
  for (const file of files) {
    for (const stmt of statements(file.text)) {
      const match = stmt.match(CREATE_TABLE);
      if (!match?.[1] || qualify(match[1]) !== table) continue;
      return columnsOf(stmt, match);
    }
  }
  return undefined;
}

/** Every `create table` in the public schema, as `public.<name>` with its columns; later files win. */
export function createdTables(files: SqlFile[]): Map<string, Column[]> {
  const out = new Map<string, Column[]>();
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    for (const stmt of statements(file.text)) {
      const match = stmt.match(CREATE_TABLE);
      if (!match?.[1]) continue;
      const table = qualify(match[1]);
      const columns = columnsOf(stmt, match);
      if (table.startsWith("public.") && columns?.length) out.set(table, columns);
    }
  }
  return out;
}

/** Body of the newest `create function <name>` (the text between its dollar quotes), or undefined. */
export function functionBody(files: SqlFile[], fn: string): string | undefined {
  const head = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?function\s+${NAME}\s*\(`, "i");
  let found: string | undefined;
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    for (const stmt of statements(file.text)) {
      const match = stmt.match(head);
      if (!match?.[1] || qualify(match[1]) !== fn) continue;
      const tag = stmt.slice(match[0].length).match(/\$[A-Za-z_]*\$/)?.[0];
      if (!tag) continue;
      const start = stmt.indexOf(tag, match[0].length) + tag.length;
      const end = stmt.indexOf(tag, start);
      if (end > start) found = stmt.slice(start, end);
    }
  }
  return found;
}

/** The return type of the last definition of `fn` (`boolean`, `setof public.notes`, `table`…), lower case. */
export function functionReturns(files: SqlFile[], fn: string): string | undefined {
  const head = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?function\s+${NAME}\s*\(`, "i");
  let found: string | undefined;
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    for (const stmt of statements(file.text)) {
      const match = stmt.match(head);
      if (!match?.[1] || qualify(match[1]) !== fn) continue;
      const returns = stmt.slice(match[0].length).match(/\)\s*returns\s+((?:setof\s+)?[\w."]+)/i)?.[1];
      if (returns) found = returns.toLowerCase();
    }
  }
  return found;
}

export interface Policy {
  name: string;
  table: string;
  command: string;
  roles: string;
  using?: string;
  withCheck?: string;
}

export function policies(files: SqlFile[], table: string): Policy[] {
  const head = new RegExp(String.raw`^create\s+policy\s+"([^"]+)"\s+on\s+${NAME}`, "i");
  const found: Policy[] = [];
  for (const file of files) {
    for (const stmt of statements(file.text)) {
      const match = stmt.match(head);
      if (!match?.[1] || !match[2] || qualify(match[2]) !== table) continue;
      const tail = stmt.slice(match[0].length);
      const clause = (keyword: string): string | undefined => {
        const at = tail.search(new RegExp(String.raw`\b${keyword}\s*\(`, "i"));
        return at === -1 ? undefined : balanced(tail, tail.indexOf("(", at));
      };
      const beforeExpr = tail.split(/\b(?:using|with\s+check)\s*\(/i)[0] ?? "";
      found.push({
        name: match[1],
        table,
        command: beforeExpr.match(/\bfor\s+(\w+)/i)?.[1]?.toLowerCase() ?? "all",
        roles: beforeExpr.match(/\bto\s+([\w\s,]+?)\s*$/i)?.[1]?.trim() ?? "public",
        using: clause("using"),
        withCheck: clause(String.raw`with\s+check`),
      });
    }
  }
  return found;
}

/** The argument list of `create function <name>(...)`, defaults removed, ready for GRANT/REVOKE. */
export function functionArgs(files: SqlFile[], fn: string): string | undefined {
  const head = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?function\s+${NAME}\s*\(`, "i");
  for (const file of files) {
    for (const stmt of statements(file.text)) {
      const match = stmt.match(head);
      if (!match?.[1] || qualify(match[1]) !== fn) continue;
      const args = balanced(stmt, match[0].length - 1);
      if (args === undefined) return undefined;
      return splitTopLevel(args)
        .map((arg) => arg.replace(/\s+(?:default\b|=).*$/is, "").replace(/\s+/g, " "))
        .join(", ");
    }
  }
  return undefined;
}

/** Quotes an identifier part only when it needs it. */
/** One identifier, quoted only when it has to be. */
export function identPart(part: string): string {
  return /^[a-z_][a-z0-9_]*$/.test(part) ? part : `"${part.replace(/"/g, '""')}"`;
}

/** A dotted name (schema.table) as SQL. For names that may contain dots themselves, use identPart. */
export function ident(name: string): string {
  return name.split(".").map(identPart).join(".");
}

/** `public.<name>` from a probe table name, where <name> may itself contain dots. */
export function publicRel(table: string): string {
  return `public.${identPart(table.replace(/^public\./, ""))}`;
}

export function literal(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}
