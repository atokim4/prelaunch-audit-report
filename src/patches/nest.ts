import type { FixContext, PatchDraft } from "./fixers.ts";
import { nestRawBodyGap, type UserParser } from "../scanners/nest.ts";

/**
 * NestJS with its own body parsers registered: each JSON and raw parser gets a `verify` option that keeps
 * the bytes on `req.rawBody`, the property the webhook controller already reads. Nothing else changes, so
 * parsed bodies, limits and paths stay as they were. Bails out when a parser takes its options from a
 * variable (the option object is not visible here).
 */

const HELPER = "keepRawBody";

/** The parser's argument text with `verify: keepRawBody` added, or undefined when it can't be done safely. */
export function withVerify(args: string): string | undefined {
  const trimmed = args.trim();
  if (!trimmed) return `{ verify: ${HELPER} }`;
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return undefined;
  const close = args.lastIndexOf("}");
  const inside = args.slice(0, close);
  if (!args.includes("\n")) {
    const body = inside.replace(/[\s,]*$/, "");
    return `${body}${body.trim() === "{" ? " " : ", "}verify: ${HELPER} ${args.slice(close)}`;
  }
  // Multi-line object: a new property line with the indent of the last one.
  const lines = inside.replace(/\s*$/, "").split("\n");
  const last = lines[lines.length - 1] ?? "";
  const indent = last.match(/^[ \t]*/)?.[0] ?? "  ";
  if (!last.trimEnd().endsWith(",")) lines[lines.length - 1] = `${last.trimEnd()},`;
  const closing = inside.slice(inside.replace(/\s*$/, "").length);
  return `${lines.join("\n")}\n${indent}verify: ${HELPER},${closing}${args.slice(close)}`;
}

function helperLines(ts: boolean): string[] {
  return ts
    ? [
        "// Nest's rawBody option only works with its own body parsers. The parsers registered below replace",
        "// them, so each one keeps the bytes itself: the Stripe signature is checked against those bytes.",
        `function ${HELPER}(req: IncomingMessage, _res: unknown, buf: Buffer): void {`,
        "  (req as IncomingMessage & { rawBody?: Buffer }).rawBody = buf;",
        "}",
      ]
    : [
        "// Nest's rawBody option only works with its own body parsers. The parsers registered below replace",
        "// them, so each one keeps the bytes itself: the Stripe signature is checked against those bytes.",
        `function ${HELPER}(req, _res, buf) {`,
        "  req.rawBody = buf;",
        "}",
      ];
}

/** After the last top-level import (multi-line ones too) or require line, else at the top. */
function afterImports(code: string, lines: string[]): string {
  const last = [
    ...code.matchAll(
      /^(?:import\s[^;]*?\bfrom\s*["'][^"'\n]+["'][ \t]*;?|import\s*["'][^"'\n]+["'][ \t]*;?|(?:const|let|var) [^\n]*=\s*require\([^)]*\)[^;\n]*;?)[ \t]*$/gm,
    ),
  ].pop();
  if (!last) return `${lines.join("\n")}\n\n${code}`;
  const at = (last.index ?? 0) + last[0].length;
  return `${code.slice(0, at)}\n\n${lines.join("\n")}${code.slice(at)}`;
}

export async function nestRawBodyFix(path: string, ctx: FixContext): Promise<PatchDraft | undefined> {
  const gap = await nestRawBodyGap(ctx.files, ctx.read);
  if (gap?.main !== path) return undefined;
  if (new RegExp(String.raw`\b${HELPER}\b`).test(gap.code)) return undefined;
  const ts = /\.(ts|mts)$/.test(path);
  let after = gap.code;
  for (const parser of [...gap.parsers].sort((a: UserParser, b: UserParser) => b.start - a.start)) {
    const open = gap.code.indexOf("(", parser.start) + 1;
    const args = withVerify(parser.args);
    if (args === undefined) return undefined;
    after = after.slice(0, open) + args + after.slice(parser.end - 1);
  }
  const top = helperLines(ts);
  // The file's own quote style for the added import.
  const quote = /^import [^\n]*'[^'\n]+';?\s*$/m.test(gap.code) ? "'" : '"';
  const needsType = ts && !/\bIncomingMessage\b/.test(gap.code);
  after = afterImports(
    after,
    needsType ? [`import type { IncomingMessage } from ${quote}node:http${quote};`, "", ...top] : top,
  );
  return {
    edits: [{ path, before: gap.code, after }],
    summary: `Each body parser this file registers itself (${gap.parsers.length}) gets a \`verify\` option that keeps the request bytes on \`req.rawBody\`, so the signature check in \`${gap.reader}\` gets the exact bytes Stripe signed. Parsed bodies, limits and paths are unchanged.`,
    caveats: [
      "Set STRIPE_WEBHOOK_SECRET to the endpoint's signing secret (whsec_…) in every environment.",
      "Re-send a test event from the Stripe dashboard (or `stripe trigger checkout.session.completed`) and confirm a 200.",
    ],
  };
}
