import type { RawFinding } from "../types.ts";

/**
 * NestJS keeps the request bytes on `req.rawBody` only through its own body parsers
 * (`NestFactory.create(AppModule, { rawBody: true })`). An app that also registers body-parser itself
 * (`app.use(bodyParser.raw(...))` for the webhook path, `app.use(bodyParser.json(...))` app-wide) replaces
 * them: Nest skips its JSON parser once one is in the stack, and a raw parser that ran first leaves nothing
 * to read. `req.rawBody` is then undefined, and a controller that checks the Stripe signature on it
 * rejects every real event.
 */

export interface UserParser {
  /** Index of `bodyParser.json(` / `express.raw(`. */
  start: number;
  /** Index just after the closing parenthesis. */
  end: number;
  kind: "json" | "raw";
  /** The text between the parentheses. */
  args: string;
}

export interface NestRawBodyGap {
  main: string;
  code: string;
  /** User parsers that do not keep the raw bytes (no `verify` option). */
  parsers: UserParser[];
  /** A source file that reads `req.rawBody` for the signature check. */
  reader: string;
}

const SOURCE = /\.(ts|js|mts|mjs|cjs)$/;
const TEST = /(^|\/)(tests?|__tests__|e2e)\/|\.(test|spec|e2e-spec)\./;

/** Names `body-parser` and `express` are imported under. */
function parserModules(code: string): string[] {
  const names = new Set<string>();
  for (const m of code.matchAll(
    /import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+["'](body-parser|express)["']|(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["'](body-parser|express)["']\s*\)/g,
  )) {
    names.add(m[1] ?? m[3] ?? "");
  }
  names.delete("");
  return [...names];
}

const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Parser calls inside `app.use(...)`, with their argument text. */
export function userParsers(code: string): UserParser[] {
  const names = parserModules(code);
  if (!names.length) return [];
  const call = new RegExp(String.raw`\b(?:${names.map(escape).join("|")})\.(json|raw)\s*\(`, "g");
  const out: UserParser[] = [];
  for (const m of code.matchAll(call)) {
    const start = m.index ?? 0;
    const open = start + m[0].length;
    let depth = 1;
    let i = open;
    for (; i < code.length && depth > 0; i++) {
      if (code[i] === "(") depth++;
      else if (code[i] === ")") depth--;
    }
    if (depth) continue;
    // Only parsers the app registers itself: inside a `.use(` call.
    if (!/\.use\(\s*(?:["'`][^"'`]*["'`]\s*,\s*)?$/.test(code.slice(Math.max(0, start - 200), start))) continue;
    out.push({ start, end: i, kind: m[1] as "json" | "raw", args: code.slice(open, i - 1) });
  }
  return out;
}

export async function nestRawBodyGap(
  files: string[],
  read: (path: string) => Promise<string | undefined>,
): Promise<NestRawBodyGap | undefined> {
  const sources = files.filter((f) => SOURCE.test(f) && !TEST.test(f) && !f.includes("node_modules/"));
  for (const main of sources) {
    const code = await read(main);
    if (!code || !/\bNestFactory\.create\s*(?:<[^>]*>)?\s*\(/.test(code) || !/\brawBody\s*:\s*true\b/.test(code))
      continue;
    const parsers = userParsers(code).filter((p) => !/\bverify\s*[:,(]/.test(p.args));
    if (!parsers.length) continue;
    for (const file of sources) {
      const text = await read(file);
      if (!text || !/\.\s*rawBody\b/.test(text)) continue;
      if (!/constructEvent|stripe-signature/i.test(text)) continue;
      return { main, code, parsers, reader: file };
    }
  }
  return undefined;
}

const lineOf = (code: string, index: number): number => code.slice(0, index).split("\n").length;

export async function nestWebhookFindings(
  files: string[],
  read: (path: string) => Promise<string | undefined>,
): Promise<RawFinding[]> {
  const gap = await nestRawBodyGap(files, read);
  if (!gap) return [];
  const first = gap.parsers[0] as UserParser;
  const calls = gap.parsers.map(
    (p) => `\`${gap.code.slice(p.start, p.start + gap.code.slice(p.start).indexOf("("))}()\``,
  );
  return [
    {
      source: "project-config",
      rule: "stripe-webhook-parsed-body",
      toolSeverity: "warning",
      message: `\`NestFactory.create(…, { rawBody: true })\` in \`${gap.main}\` keeps the raw body only with Nest's own parsers, and this file registers its own (${[...new Set(calls)].join(", ")}) without a \`verify\` option. So \`req.rawBody\`, which \`${gap.reader}\` passes to the Stripe signature check, stays undefined and real events are rejected.`,
      location: { kind: "file", file: gap.main, line: lineOf(gap.code, first.start) },
      subject: `nest-raw-body:${gap.reader}`,
    },
  ];
}
