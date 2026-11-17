import type { Fixer, FixContext, PatchDraft } from "./fixers.ts";
import { nestRawBodyFix } from "./nest.ts";
import {
  JSON_PARSER,
  RAW_PARSER,
  closingBrace,
  globalJsonParsers,
  isExpressFile,
  jsonBeforeMount,
  jsonBeforeRoute,
  stripeRoute,
  type ExternalJsonParser,
  type GlobalJsonParser,
} from "../scanners/express.ts";

/**
 * Fixers for the two Stripe webhook rules, one per way a webhook is usually written:
 * Next.js App Router and Supabase Edge Functions (fetch-style `Request`), Next.js pages/api and
 * Express (Node `req`/`res`). Each one rewrites only the lines it understands and returns undefined
 * otherwise, so an unusual handler keeps the finding and its written fix instead of a wrong patch.
 */

/** `@/lib/stripe` when tsconfig maps @/* to the root, else a relative path. */
function importPath(from: string, to: string, aliasRoot: boolean): string {
  const bare = to.replace(/\.(ts|tsx|js|mjs)$/, "");
  if (aliasRoot) return `@/${bare}`;
  const up = from
    .split("/")
    .slice(0, -1)
    .map(() => "..");
  return [...(up.length ? up : ["."]), bare].join("/");
}

/** A module (other than `self`) that exports a shared `stripe` client. */
async function findStripeModule(ctx: FixContext, self: string): Promise<string | undefined> {
  for (const file of ctx.files) {
    if (!/\.(ts|tsx|js|mjs)$/.test(file) || file === self) continue;
    const text = await ctx.read(file);
    if (text && /export\s+const\s+stripe\s*=\s*new\s+Stripe\(/.test(text)) return file;
  }
  return undefined;
}

/** Adds import lines after the last existing import (or at the top). */
function insertImports(source: string, imports: string[]): string {
  if (!imports.length) return source;
  const last = [...source.matchAll(/^import .*;$/gm)].pop();
  if (!last) return `${imports.join("\n")}\n${source}`;
  const at = (last.index ?? 0) + last[0].length;
  return `${source.slice(0, at)}\n${imports.join("\n")}${source.slice(at)}`;
}

/** Matches `const event = await req.json()` (optionally wrapped in parens and cast to Stripe.Event). */
const PARSED_EVENT =
  /^([ \t]*)(?:const|let)\s+(\w+)\s*=\s*\(?\s*await\s+(\w+)\.json\(\)\s*\)?(?:\s+as\s+Stripe\.Event)?\s*;[ \t]*$/m;

/** Any default import of Stripe, whatever the specifier (npm:, esm.sh, or a bare name from an import map). */
const DENO_STRIPE_IMPORT = /^import\s+Stripe\s*(?:,\s*\{[^}]*\})?\s+from\s+["'][^"']+["'];?$/m;

/**
 * Supabase Edge Function (Deno) version: Deno has no Node crypto, so the signature check needs
 * constructEventAsync with Stripe's SubtleCrypto provider, on the raw text of the request.
 */
async function denoWebhookFix(path: string, before: string): Promise<PatchDraft | undefined> {
  const parse = before.match(PARSED_EVENT);
  if (!parse) return undefined;
  const [line, indent = "  ", eventVar, requestVar] = parse;
  // A type-only import cannot back `new Stripe(...)`: make it a value import of the same module.
  let source = before.replace(/^import\s+type\s+(Stripe\s+from\s+["'][^"']+["'];?)$/m, "import $1");
  const top: string[] = [];
  if (!DENO_STRIPE_IMPORT.test(source)) top.push('import Stripe from "npm:stripe@19.3.1";');
  const client = source.match(/^(?:export\s+)?const\s+(\w+)\s*=\s*new\s+Stripe\(/m)?.[1];
  const stripeRef = client ?? "stripe";
  const setup = [
    ...(client
      ? []
      : [
          'const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY") ?? "", { httpClient: Stripe.createFetchHttpClient() });',
        ]),
    "const cryptoProvider = Stripe.createSubtleCryptoProvider();",
  ];
  const i = indent;
  const verified = [
    `${i}const signature = ${requestVar}.headers.get("stripe-signature");`,
    `${i}if (!signature) {`,
    `${i}  return new Response("Missing stripe-signature header", { status: 400 });`,
    `${i}}`,
    "",
    `${i}let ${eventVar}: Stripe.Event;`,
    `${i}try {`,
    `${i}  ${eventVar} = await ${stripeRef}.webhooks.constructEventAsync(`,
    `${i}    await ${requestVar}.text(),`,
    `${i}    signature,`,
    `${i}    Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? "",`,
    `${i}    undefined,`,
    `${i}    cryptoProvider,`,
    `${i}  );`,
    `${i}} catch {`,
    `${i}  return new Response("Invalid signature", { status: 400 });`,
    `${i}}`,
  ].join("\n");
  source = source.replace(line, verified);
  // New imports and the client go right after the last import, so the file still reads top to bottom.
  const last = [...source.matchAll(/^import .*;$/gm)].pop();
  const at = last ? (last.index ?? 0) + last[0].length : 0;
  const block = [...top, "", ...setup].join("\n");
  const after = last ? `${source.slice(0, at)}\n${block}${source.slice(at)}` : `${block}\n${source}`;
  return {
    edits: [{ path, before, after }],
    summary: `Reads the raw body and checks the stripe-signature header with constructEventAsync and Stripe's SubtleCrypto provider (Deno has no Node crypto) before the function touches the event. Unsigned or tampered requests get a 400.`,
    caveats: [
      `Set the secret: \`supabase secrets set STRIPE_WEBHOOK_SECRET=whsec_...\` (the endpoint's signing secret from the Stripe dashboard).`,
      `Keep \`verify_jwt = false\` for this function in supabase/config.toml: Stripe sends no Supabase token, and the signature is now the gate.`,
      `Test: \`stripe listen --forward-to <project>.supabase.co/functions/v1/${path.split("/")[2] ?? "stripe-webhook"}\`, then \`stripe trigger checkout.session.completed\`.`,
    ],
  };
}

/** Next.js App Router route handler (`export async function POST(request)`). */
async function appRouterUnverified(path: string, before: string, ctx: FixContext): Promise<PatchDraft | undefined> {
  if (!/export\s+async\s+function\s+POST\s*\(/.test(before)) return undefined;
  const parse = before.match(PARSED_EVENT);
  if (!parse) return undefined;
  const [line, indent = "  ", eventVar, requestVar] = parse;

  const stripeModule = await findStripeModule(ctx, path);
  const imports: string[] = [];
  let source = before;
  let stripeRef = "stripe";
  if (stripeModule) {
    const tsconfig = (await ctx.read("tsconfig.json")) ?? "";
    const aliasRoot = /"@\/\*"\s*:\s*\[\s*"\.\/\*"\s*\]/.test(tsconfig);
    imports.push(`import { stripe } from "${importPath(path, stripeModule, aliasRoot)}";`);
    if (!/^import\s+(?:type\s+)?Stripe\s+from\s+"stripe";$/m.test(source))
      imports.push('import type Stripe from "stripe";');
  } else {
    stripeRef = "new Stripe(process.env.STRIPE_SECRET_KEY!)";
    if (/^import\s+type\s+Stripe\s+from\s+"stripe";$/m.test(source)) {
      source = source.replace(/^import\s+type\s+Stripe\s+from\s+"stripe";$/m, 'import Stripe from "stripe";');
    } else if (!/^import\s+Stripe\s+from\s+"stripe";$/m.test(source)) {
      imports.push('import Stripe from "stripe";');
    }
  }
  if (!/import\s*\{[^}]*\bNextResponse\b[^}]*\}\s*from\s*"next\/server"/.test(source)) {
    imports.unshift('import { NextResponse } from "next/server";');
  }
  const i = indent;
  const verified = [
    `${i}const signature = ${requestVar}.headers.get("stripe-signature");`,
    `${i}if (!signature) {`,
    `${i}  return NextResponse.json({ error: "Missing stripe-signature header" }, { status: 400 });`,
    `${i}}`,
    "",
    `${i}let ${eventVar}: Stripe.Event;`,
    `${i}try {`,
    `${i}  ${eventVar} = await ${stripeRef}.webhooks.constructEventAsync(`,
    `${i}    await ${requestVar}.text(),`,
    `${i}    signature,`,
    `${i}    process.env.STRIPE_WEBHOOK_SECRET!,`,
    `${i}  );`,
    `${i}} catch {`,
    `${i}  return NextResponse.json({ error: "Invalid signature" }, { status: 400 });`,
    `${i}}`,
  ].join("\n");
  const after = insertImports(source.replace(line, verified), imports);
  return {
    edits: [{ path, before, after }],
    summary:
      "Reads the raw body and checks the stripe-signature header with constructEventAsync before the handler touches the event. Unsigned or tampered requests get a 400.",
    caveats: [
      "Set STRIPE_WEBHOOK_SECRET to the endpoint's signing secret (whsec_…) in every environment.",
      "Test with `stripe listen --forward-to localhost:3000/api/stripe/webhook` and `stripe trigger checkout.session.completed`.",
    ],
  };
}
const isTypeScript = (path: string): boolean => /\.(ts|tsx|mts|cts)$/.test(path);
const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** `name`, or `fallback` when the code already declares `name`. */
const freeName = (code: string, name: string, fallback: string): string =>
  new RegExp(String.raw`\b(?:const|let|var)\s+${name}\b`).test(code) ? fallback : name;

/** Edits applied from the last index to the first, so earlier indices stay valid. */
interface Splice {
  start: number;
  end: number;
  text: string;
}
function splice(code: string, edits: Splice[]): string {
  let out = code;
  for (const e of [...edits].sort((a, b) => b.start - a.start)) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

/** `const event = req.body;`, `const event = req.body as Stripe.Event;` or `const { type, data } = req.body;`. */
const eventFromBody = (req: string): RegExp =>
  new RegExp(
    String.raw`^([ \t]*)(?:const|let|var)\s+(\w+|\{[^}]*\})\s*=\s*${req}\.body(?:\s+as\s+(?:Stripe\.Event|any))?\s*;?[ \t]*$`,
    "m",
  );

/** The first argument of `constructEvent(` when it is the parsed body: `req.body` or `JSON.stringify(req.body)`. */
const parsedArg = (req: string): RegExp =>
  new RegExp(
    String.raw`(\bconstructEvent(?:Async)?\(\s*)(JSON\.stringify\(\s*${req}\.body\s*\)|${req}\.body\b(?!\s*[.[]))`,
  );

/** What a Node-style handler needs to sign-check the body: the client reference and new top-of-file lines. */
interface NodeStripe {
  ref: string;
  top: string[];
}
function nodeStripeClient(code: string, ts: boolean, commonJs: boolean): NodeStripe {
  const local = code.match(/^(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*new\s+Stripe\(/m)?.[1];
  if (local) return { ref: local, top: [] };
  if (/import\s*\{[^}]*\bstripe\b[^}]*\}\s*from|const\s*\{[^}]*\bstripe\b[^}]*\}\s*=\s*require\(/.test(code)) {
    return { ref: "stripe", top: [] };
  }
  const hasImport =
    /^import\s+(?:type\s+)?Stripe\s+from\s+["']stripe["'];?$|\bStripe\s*=\s*require\(\s*["']stripe["']\s*\)/m.test(
      code,
    );
  const top = hasImport ? [] : [commonJs ? 'const Stripe = require("stripe");' : 'import Stripe from "stripe";'];
  top.push(`const stripe = new Stripe(process.env.STRIPE_SECRET_KEY${ts ? "!" : ""});`);
  return { ref: "stripe", top };
}

/** Puts lines after the last import/require line at the top of the file (or at the very top). */
function afterImports(code: string, lines: string[]): string {
  if (!lines.length) return code;
  const last = [...code.matchAll(/^(?:import .*;|(?:const|let|var) .*=\s*require\([^)]*\)[^;\n]*;?)[ \t]*$/gm)].pop();
  if (!last) return `${lines.join("\n")}\n\n${code}`;
  const at = (last.index ?? 0) + last[0].length;
  return `${code.slice(0, at)}\n\n${lines.join("\n")}${code.slice(at)}`;
}

/** A type-only Stripe import cannot back `new Stripe(...)`. */
const valueImport = (code: string): string =>
  code.replace(/^import\s+type\s+(Stripe\s+from\s+["']stripe["'];?)$/m, "import $1");

/** The lines that read the signature and build the event, for a Node handler (Express or pages/api). */
function nodeVerifyBlock(o: {
  indent: string;
  req: string;
  res: string;
  eventVar: string;
  signatureVar: string;
  ref: string;
  body: string;
  ts: boolean;
  bufferGuard: boolean;
  reply: (status: number, text: string) => string;
}): string[] {
  const i = o.indent;
  return [
    `${i}const ${o.signatureVar} = ${o.req}.headers["stripe-signature"];`,
    ...(o.bufferGuard
      ? [
          `${i}if (!Buffer.isBuffer(${o.req}.body)) {`,
          `${i}  // Stripe signs the exact bytes it sent: a parsed body can never pass the check below.`,
          `${i}  ${o.reply(500, "Webhook body was parsed before the signature check")};`,
          `${i}  return;`,
          `${i}}`,
        ]
      : []),
    `${i}if (typeof ${o.signatureVar} !== "string") {`,
    `${i}  ${o.reply(400, "Missing stripe-signature header")};`,
    `${i}  return;`,
    `${i}}`,
    "",
    `${i}let ${o.eventVar}${o.ts ? ": Stripe.Event" : ""};`,
    `${i}try {`,
    `${i}  ${o.eventVar} = ${o.ref}.webhooks.constructEvent(${o.body}, ${o.signatureVar}, process.env.STRIPE_WEBHOOK_SECRET${o.ts ? "!" : ""});`,
    `${i}} catch {`,
    `${i}  ${o.reply(400, "Invalid signature")};`,
    `${i}  return;`,
    `${i}}`,
  ];
}

/**
 * Replaces the line that trusts the parsed body with a signature check. Returns the new handler body, or
 * undefined when the handler reads the body in some other way or keeps using the parsed object later.
 */
function verifyInBody(
  body: string,
  o: Omit<Parameters<typeof nodeVerifyBlock>[0], "indent" | "eventVar" | "signatureVar">,
): string | undefined {
  const line = body.match(eventFromBody(o.req));
  if (!line) return undefined;
  const [whole, indent = "  ", target = ""] = line;
  const destructure = target.startsWith("{");
  const eventVar = destructure ? freeName(body, "event", "stripeEvent") : target;
  const signatureVar = freeName(body, "signature", "stripeSignature");
  const block = nodeVerifyBlock({ ...o, indent, eventVar, signatureVar });
  if (destructure) block.push(`${indent}const ${target} = ${eventVar};`);
  const next = body.replace(whole, block.join("\n"));
  // Anything else still reading fields of the parsed body would break once the body is raw.
  if (new RegExp(String.raw`\b${escape(o.req)}\.body\s*[.[]`).test(next)) return undefined;
  return next;
}

const expressReply =
  (res: string) =>
  (status: number, text: string): string =>
    `${res}.status(${status}).send(${JSON.stringify(text)})`;

/** The name the file gives the express default export (`import express from "express"`). */
const expressName = (code: string): string | undefined =>
  code.match(/import\s+(\w+)(?:\s*,\s*\{[^}]*\})?\s+from\s+["']express["']/)?.[1] ??
  code.match(/(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["']express["']\s*\)/)?.[1];

/** `app.use(express.json())` rewritten to skip one path, kept on its own lines with the file's indent. */
const skipPath = (parser: GlobalJsonParser, fullPath: string): string =>
  [
    `${parser.indent}// Stripe webhooks need the raw body: JSON parsing skips that route.`,
    `${parser.indent}${parser.object}.use((req, res, next) =>`,
    `${parser.indent}  req.path === ${JSON.stringify(fullPath)} ? next() : ${parser.parser}(req, res, next),`,
    `${parser.indent});`,
  ].join("\n");

/**
 * Express: the webhook route gets `express.raw({ type: "application/json" })` (replacing a route-level
 * `express.json()`), an app-wide JSON parser added earlier in the same file skips the webhook path, and
 * the handler checks the signature on the Buffer. `external` is an app-wide parser in the file that mounts
 * this router (found by following the mount): that file gets the same skip. Without it, bails out when a
 * JSON parser elsewhere in the repo may run first, since the order then depends on code it cannot see.
 */
async function expressFix(
  path: string,
  before: string,
  ctx: FixContext,
  mode: "unverified" | "parsed",
  line: number,
  external?: ExternalJsonParser,
): Promise<PatchDraft | undefined> {
  const route = stripeRoute(before, line);
  const express = expressName(before);
  if (!route || !express) return undefined;
  const ts = isTypeScript(path);
  const commonJs = !/^import\s/m.test(before) && /\brequire\(/.test(before);
  const edits: Splice[] = [];

  // 1. The handler body.
  const body = before.slice(route.bodyOpen, route.bodyClose);
  let top: string[] = [];
  let newBody: string | undefined;
  if (mode === "unverified") {
    const client = nodeStripeClient(before, ts, commonJs);
    top = client.top;
    newBody = verifyInBody(body, {
      req: route.reqVar,
      res: route.resVar,
      ref: client.ref,
      body: `${route.reqVar}.body`,
      ts,
      bufferGuard: true,
      reply: expressReply(route.resVar),
    });
  } else {
    const arg = body.match(parsedArg(route.reqVar));
    if (arg?.index !== undefined) {
      let statementStart = body.lastIndexOf("\n", arg.index) + 1;
      // Inside `try {`: the guard goes before the try, where it reads as a precondition.
      const previous = body.lastIndexOf("\n", statementStart - 2) + 1;
      if (/^[ \t]*try\s*\{[ \t]*$/.test(body.slice(previous, statementStart - 1))) statementStart = previous;
      const indent = body.slice(statementStart).match(/^[ \t]*/)?.[0] ?? "  ";
      const guard = [
        `${indent}if (!Buffer.isBuffer(${route.reqVar}.body)) {`,
        `${indent}  // Stripe signs the exact bytes it sent: a parsed body can never pass the check below.`,
        `${indent}  ${expressReply(route.resVar)(500, "Webhook body was parsed before the signature check")};`,
        `${indent}  return;`,
        `${indent}}`,
        "",
      ].join("\n");
      const replaced = body.replace(parsedArg(route.reqVar), `$1${route.reqVar}.body`);
      newBody = replaced.slice(0, statementStart) + guard + replaced.slice(statementStart);
      if (/Buffer\.isBuffer/.test(body)) newBody = replaced;
    }
  }
  if (!newBody) return undefined;
  if (newBody !== body) edits.push({ start: route.bodyOpen, end: route.bodyClose, text: newBody });

  // 2. The route's own middleware.
  const raw = `${express}.raw({ type: "application/json" })`;
  if (JSON_PARSER.test(route.middleware)) {
    edits.push({
      start: route.middlewareStart,
      end: route.handlerStart,
      text: route.middleware.replace(JSON_PARSER, raw),
    });
  } else if (!RAW_PARSER.test(route.middleware)) {
    edits.push({ start: route.handlerStart, end: route.handlerStart, text: `${raw}, ` });
  }

  // 3. App-wide JSON parsers that run first: in this file they skip the webhook path; elsewhere, give up.
  const first = external
    ? { parser: external.parser, fullPath: external.fullPath as string | undefined }
    : jsonBeforeRoute(before, route);
  if (first && !external) {
    if (!first.fullPath) return undefined;
    const { parser } = first;
    edits.push({ start: parser.index, end: parser.index + parser.line.length, text: skipPath(parser, first.fullPath) });
  } else if (!external) {
    // No parser in this file runs first. One in another file may (an app that mounts this router after
    // `app.use(express.json())`), and the mount order is not visible from here.
    const parsesHere = globalJsonParsers(before).length > 0;
    for (const file of parsesHere ? [] : ctx.files) {
      if (file === path || !/\.(ts|js|mjs|cjs|mts)$/.test(file)) continue;
      const other = await ctx.read(file);
      if (other && isExpressFile(other) && globalJsonParsers(other).length) return undefined;
    }
  }
  if (!edits.length && !external) return undefined;
  const after = edits.length ? valueImport(afterImports(splice(before, edits), top)) : before;
  const fileEdits = after === before ? [] : [{ path, before, after }];
  if (external) {
    const { parser, code } = external;
    const mounted =
      code.slice(0, parser.index) + skipPath(parser, external.fullPath) + code.slice(parser.index + parser.line.length);
    fileEdits.push({ path: external.file, before: code, after: mounted });
  }
  const steps = [
    `the webhook route reads the raw body with \`${raw}\``,
    ...(first
      ? [
          `\`${first.parser.object}.use(${first.parser.parser})\`${external ? ` in \`${external.file}\`` : ""} skips \`${first.fullPath ?? route.path}\``,
        ]
      : []),
    mode === "unverified"
      ? "the handler checks the stripe-signature header with `constructEvent` on that Buffer and answers 400 to unsigned or tampered requests"
      : "`constructEvent` gets the Buffer itself",
  ];
  return {
    edits: fileEdits,
    summary:
      `${steps.join(", ")}.${/Buffer\.isBuffer/.test(newBody) ? " A Buffer.isBuffer guard answers 500 if a parser ever runs first again, so the mistake shows up in Stripe's delivery log instead of as silent signature failures." : ""}`.replace(
        /^./,
        (c) => c.toUpperCase(),
      ),
    caveats: [
      "Set STRIPE_WEBHOOK_SECRET to the endpoint's signing secret (whsec_…) in every environment.",
      `Test with \`stripe listen --forward-to localhost:<port>${first?.fullPath ?? route.path}\` and \`stripe trigger checkout.session.completed\`.`,
    ],
  };
}

/** `export default async function handler(req, res) {`, or `const handler = async (req, res) => {` + `export default handler`. */
function pagesHandler(code: string): { asyncAt?: number; req: string; res: string; open: number } | undefined {
  const TYPE = String.raw`(?:\s*:\s*[\w.<>]+)?`;
  const fn = new RegExp(
    String.raw`export\s+default\s+(async\s+)?function\s*\w*\s*\(\s*(\w+)${TYPE}\s*,\s*(\w+)${TYPE}\s*\)\s*(?::\s*[\w.<>| ]+?\s*)?\{`,
  ).exec(code);
  if (fn) {
    return {
      ...(fn[1] ? {} : { asyncAt: fn.index + "export default ".length }),
      req: fn[2] ?? "req",
      res: fn[3] ?? "res",
      open: fn.index + fn[0].length - 1,
    };
  }
  const name = code.match(/^export\s+default\s+(\w+)\s*;?\s*$/m)?.[1];
  if (!name) return undefined;
  const arrow = new RegExp(
    String.raw`(?:const|let)\s+${name}(?:\s*:\s*[\w.<>]+)?\s*=\s*(async\s+)?\(\s*(\w+)${TYPE}\s*,\s*(\w+)${TYPE}\s*\)\s*(?::\s*[\w.<>| ]+?\s*)?=>\s*\{`,
  ).exec(code);
  if (!arrow) return undefined;
  const paren = arrow.index + arrow[0].indexOf("(");
  return {
    ...(arrow[1] ? {} : { asyncAt: paren }),
    req: arrow[2] ?? "req",
    res: arrow[3] ?? "res",
    open: arrow.index + arrow[0].length - 1,
  };
}

/**
 * Next.js pages/api: turns the body parser off for this route (`export const config`), reads the raw
 * bytes from the request stream and checks the signature on them. The handler becomes async if it was not.
 */
async function pagesFix(path: string, before: string, mode: "unverified" | "parsed"): Promise<PatchDraft | undefined> {
  const handler = pagesHandler(before);
  if (!handler) return undefined;
  const close = closingBrace(before, handler.open);
  if (close < 0) return undefined;
  const ts = isTypeScript(path);
  const reader = freeName(before, "readRawBody", "readStripeBody");
  const readerExists = new RegExp(String.raw`function\s+${reader}\b`).test(before);
  const call = `await ${reader}(${handler.req})`;
  const body = before.slice(handler.open, close);
  let newBody: string | undefined;
  let top: string[] = [];
  if (mode === "unverified") {
    const client = nodeStripeClient(before, ts, false);
    top = client.top;
    newBody = verifyInBody(body, {
      req: handler.req,
      res: handler.res,
      ref: client.ref,
      body: call,
      ts,
      bufferGuard: false,
      reply: (status, text) => `${handler.res}.status(${status}).json({ error: ${JSON.stringify(text)} })`,
    });
  } else {
    newBody = parsedArg(handler.req).test(body) ? body.replace(parsedArg(handler.req), `$1${call}`) : undefined;
    if (newBody && new RegExp(String.raw`\b${escape(handler.req)}\.body\b`).test(newBody)) return undefined;
  }
  if (!newBody) return undefined;

  const edits: Splice[] = [{ start: handler.open, end: close, text: newBody }];
  if (handler.asyncAt !== undefined) edits.push({ start: handler.asyncAt, end: handler.asyncAt, text: "async " });
  const config = /^export\s+const\s+config\s*=\s*\{[\s\S]*?^\};?/m.exec(before);
  if (config) {
    if (/bodyParser\s*:\s*true/.test(config[0])) {
      edits.push({
        start: config.index,
        end: config.index + config[0].length,
        text: config[0].replace(/bodyParser\s*:\s*true/, "bodyParser: false"),
      });
    } else if (!/bodyParser\s*:\s*false/.test(config[0])) {
      return undefined; // a config this patch would have to merge by hand
    }
  } else {
    top.push("", "// Stripe signs the exact bytes it sent, so Next.js must not parse this route's body.");
    top.push("export const config = { api: { bodyParser: false } };");
  }
  if (!readerExists) {
    top.push(
      "",
      ts
        ? `async function ${reader}(req: AsyncIterable<Buffer | string>): Promise<Buffer> {`
        : `async function ${reader}(req) {`,
      ...(ts ? ["  const chunks: Buffer[] = [];"] : ["  const chunks = [];"]),
      '  for await (const chunk of req) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);',
      "  return Buffer.concat(chunks);",
      "}",
    );
  }
  const after = valueImport(afterImports(splice(before, edits), top[0] === "" ? top.slice(1) : top));
  return {
    edits: [{ path, before, after }],
    summary:
      mode === "unverified"
        ? "Turns Next.js body parsing off for this route, reads the raw bytes and checks the stripe-signature header with `constructEvent` before the handler touches the event. Unsigned or tampered requests get a 400."
        : "Turns Next.js body parsing off for this route and passes the raw bytes to `constructEvent`, so real Stripe events pass the signature check.",
    caveats: [
      "Set STRIPE_WEBHOOK_SECRET to the endpoint's signing secret (whsec_…) in every environment.",
      `Test with \`stripe listen --forward-to localhost:3000/${path.replace(/^(?:src\/)?pages\//, "").replace(/(\/index)?\.(ts|js|tsx|jsx)$/, "")}\` and \`stripe trigger checkout.session.completed\`.`,
    ],
  };
}

/**
 * Fetch-style handlers (App Router, Supabase Edge Functions): `await req.json()` becomes `await req.text()`
 * and `constructEvent` gets that text. When the parsed object is still used, it is parsed from the text.
 */
function fetchParsedFix(path: string, before: string): PatchDraft | undefined {
  const read =
    /^([ \t]*)(?:const|let)\s+(\w+)\s*=\s*\(?\s*await\s+(\w+)\.json\(\)\s*\)?((?:\s+as\s+[\w.]+)?)\s*;[ \t]*$/m.exec(
      before,
    );
  if (!read) return undefined;
  const [line, indent = "", name = "", request = ""] = read;
  const cast = read[4] ?? "";
  const arg = new RegExp(
    String.raw`(\bconstructEvent(?:Async)?\(\s*)(JSON\.stringify\(\s*${name}\s*\)|${name}\b(?!\s*[.[]))`,
  );
  if (!arg.test(before)) return undefined;
  const uses = before.match(new RegExp(String.raw`\b${name}\b`, "g"))?.length ?? 0;
  let after: string;
  if (uses <= 2) {
    after = before.replace(arg, `$1${name}`).replace(line, `${indent}const ${name} = await ${request}.text();`);
  } else {
    const raw = freeName(before, "rawBody", "stripeRawBody");
    after = before
      .replace(arg, `$1${raw}`)
      .replace(
        line,
        `${indent}const ${raw} = await ${request}.text();\n${indent}const ${name} = JSON.parse(${raw})${cast};`,
      );
  }
  return {
    edits: [{ path, before, after }],
    summary:
      "Reads the request as text and passes that exact text to the signature check, so real Stripe events stop failing it.",
    caveats: [
      "Re-send a test event from the Stripe dashboard (or `stripe trigger checkout.session.completed`) and confirm a 200.",
    ],
  };
}

const PAGES_API = /(^|\/)pages\/api\//;

export const stripeWebhookUnverified: Fixer = async (finding, ctx) => {
  if (finding.location.kind !== "file") return undefined;
  const path = finding.location.file;
  const before = await ctx.read(path);
  if (!before) return undefined;
  if (path.startsWith("supabase/functions/")) return denoWebhookFix(path, before);
  if (PAGES_API.test(path)) return pagesFix(path, before, "unverified");
  if (isExpressFile(before)) return expressFix(path, before, ctx, "unverified", finding.location.line);
  return appRouterUnverified(path, before, ctx);
};

export const stripeWebhookParsedBody: Fixer = async (finding, ctx) => {
  if (finding.location.kind !== "file") return undefined;
  const path = finding.location.file;
  const before = await ctx.read(path);
  if (!before) return undefined;
  if (PAGES_API.test(path)) return pagesFix(path, before, "parsed");
  if (finding.subject?.startsWith("nest-raw-body:")) return nestRawBodyFix(path, ctx);
  // The parser sits in the file that mounts the webhook router: patch both files.
  const routeFile = finding.subject?.startsWith("express-route:")
    ? finding.subject.slice("express-route:".length)
    : undefined;
  if (routeFile) {
    const routeCode = await ctx.read(routeFile);
    const route = routeCode ? stripeRoute(routeCode) : undefined;
    if (!routeCode || !route) return undefined;
    const external = await jsonBeforeMount(ctx.files, ctx.read, routeFile, route);
    if (external?.file !== path) return undefined;
    const at = routeCode.slice(0, route.start).split("\n").length;
    return expressFix(routeFile, routeCode, ctx, "parsed", at, external);
  }
  if (isExpressFile(before)) return expressFix(path, before, ctx, "parsed", finding.location.line);
  return fetchParsedFix(path, before);
};
