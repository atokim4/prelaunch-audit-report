import type { RawFinding } from "../types.ts";

/**
 * Express webhook routes, read from the source text: which object registers the route, its path, the
 * middleware in front of the handler, the handler's request and response names and its body. Also the
 * app-wide JSON body parsers registered in the same file, because Express runs middleware in the order it
 * was added: a global `express.json()` added before the webhook route eats the raw body the signature
 * check needs, even when the route itself asks for `express.raw()`.
 */

export interface ExpressRoute {
  object: string;
  path: string;
  /** Index of `object.post(`. */
  start: number;
  /** Index where the handler function starts (end of the middleware list). */
  handlerStart: number;
  /** The text between the path's comma and the handler: the route's own middleware. */
  middleware: string;
  middlewareStart: number;
  reqVar: string;
  resVar: string;
  /** Indices of the handler body's opening and closing braces. */
  bodyOpen: number;
  bodyClose: number;
}

export interface GlobalJsonParser {
  /** The whole `app.use(express.json())` line. */
  line: string;
  index: number;
  indent: string;
  object: string;
  /** `express.json({ limit: "1mb" })`, kept as written. */
  parser: string;
}

const ROUTE = /\b(\w+)\.post\(\s*(["'`])([^"'`]+)\2\s*,/g;
const TYPE = String.raw`(?:\s*:\s*[\w.<>]+)?`;
const HANDLER = new RegExp(
  String.raw`(?:async\s+)?(?:function\s*\w*\s*)?\(\s*(\w+)${TYPE}\s*,\s*(\w+)${TYPE}(?:\s*,\s*\w+${TYPE})?\s*\)\s*(?::\s*[\w.<>[\]| ]+?\s*)?(?:=>\s*)?\{`,
  "g",
);
const GLOBAL_JSON =
  /^([ \t]*)(\w+)\.use\(\s*((?:express|bodyParser)\.json\s*\((?:[^()]|\([^()]*\))*\))\s*\)\s*;?[ \t]*$/gm;
export const JSON_PARSER = /\b(?:express|bodyParser)\.json\s*\((?:[^()]|\([^()]*\))*\)/;
export const RAW_PARSER = /\b(?:express|bodyParser)\.raw\s*\(/;
const EVENT_NAME =
  /["'`](checkout\.session\.completed|customer\.subscription\.[a-z_]+|invoice\.(?:paid|payment_succeeded|payment_failed)|payment_intent\.succeeded)["'`]/;
const VERIFIED = /\bconstructEvent(?:Async)?\s*\(/;

export const isExpressFile = (code: string): boolean =>
  /from\s+["']express["']|require\(\s*["']express["']\s*\)/.test(code);

/** Index of the brace that closes the one at `open`, skipping strings, template literals and comments. */
export function closingBrace(code: string, open: number): number {
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    const ch = code[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      for (i++; i < code.length && code[i] !== ch; i++) if (code[i] === "\\") i++;
      continue;
    }
    if (ch === "/" && code[i + 1] === "/") {
      i = code.indexOf("\n", i);
      if (i < 0) return -1;
      continue;
    }
    if (ch === "/" && code[i + 1] === "*") {
      i = code.indexOf("*/", i + 2) + 1;
      if (i <= 0) return -1;
      continue;
    }
    if (ch === "{") depth++;
    else if (ch === "}" && --depth === 0) return i;
  }
  return -1;
}

export function expressRoutes(code: string): ExpressRoute[] {
  const out: ExpressRoute[] = [];
  for (const route of code.matchAll(ROUTE)) {
    const middlewareStart = (route.index ?? 0) + route[0].length;
    HANDLER.lastIndex = middlewareStart;
    const handler = HANDLER.exec(code);
    if (!handler) continue;
    const middleware = code.slice(middlewareStart, handler.index);
    // Anything but a list of expressions in between means the handler belongs to some other call.
    if (/[;{}]/.test(middleware.replace(/\{[^{}]*\}/g, ""))) continue;
    const bodyOpen = handler.index + handler[0].length - 1;
    const bodyClose = closingBrace(code, bodyOpen);
    if (bodyClose < 0) continue;
    out.push({
      object: route[1] ?? "",
      path: route[3] ?? "",
      start: route.index ?? 0,
      handlerStart: handler.index,
      middleware,
      middlewareStart,
      reqVar: handler[1] ?? "req",
      resVar: handler[2] ?? "res",
      bodyOpen,
      bodyClose,
    });
  }
  return out;
}

/** The route that receives Stripe events: a webhook path, or a handler that names Stripe event types. */
export function stripeRoute(code: string, line?: number): ExpressRoute | undefined {
  // The route has to receive Stripe events: Stripe's event names or the signature header in its handler,
  // or a webhook path about Stripe. A bare /webhook route next to Stripe code may belong to Clerk or GitHub,
  // and an authenticated /portal route that only mentions a stripe_customer_id is not a webhook.
  const routes = expressRoutes(code).filter((r) => {
    const body = code.slice(r.bodyOpen, r.bodyClose);
    if (EVENT_NAME.test(body) || /stripe-signature/i.test(body)) return true;
    return /webhook|hook/i.test(r.path) && (/stripe/i.test(r.path) || /stripe/i.test(body));
  });
  if (line === undefined || routes.length < 2) return routes[0];
  const at = (index: number) => code.slice(0, index).split("\n").length;
  return routes.find((r) => at(r.start) <= line && line <= at(r.bodyClose)) ?? routes[0];
}

export function globalJsonParsers(code: string): GlobalJsonParser[] {
  return [...code.matchAll(GLOBAL_JSON)].map((m) => ({
    line: m[0],
    index: m.index ?? 0,
    indent: m[1] ?? "",
    object: m[2] ?? "",
    parser: m[3] ?? "",
  }));
}

/** Where `router` is mounted on `app` in this file: the mount path and the index of the `app.use(...)`. */
export function mountOf(code: string, app: string, router: string): { path: string; index: number } | undefined {
  const m = new RegExp(String.raw`\b${app}\.use\(\s*(["'\`])([^"'\`]+)\1\s*,\s*${router}\s*\)`).exec(code);
  return m ? { path: m[2] ?? "", index: m.index } : undefined;
}

/**
 * The app-wide JSON parser that runs before the route, and the full path the route answers on (mount
 * path + route path), when both live in this file. `undefined` when no parser runs first.
 */
export function jsonBeforeRoute(
  code: string,
  route: ExpressRoute,
): { parser: GlobalJsonParser; fullPath: string | undefined } | undefined {
  for (const parser of globalJsonParsers(code)) {
    if (parser.object === route.object) {
      if (parser.index < route.start) return { parser, fullPath: route.path };
      continue;
    }
    const mount = mountOf(code, parser.object, route.object);
    if (mount && parser.index < mount.index) {
      return { parser, fullPath: `${mount.path.replace(/\/$/, "")}/${route.path.replace(/^\//, "")}` };
    }
  }
  return undefined;
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Where an import or require in `from` points, as a repo path among `files`. */
function resolveImport(from: string, spec: string, files: Set<string>): string | undefined {
  if (!spec.startsWith(".")) return undefined;
  const parts = from.split("/").slice(0, -1);
  for (const part of spec.split("/")) {
    if (part === "..") parts.pop();
    else if (part !== ".") parts.push(part);
  }
  const base = parts.join("/");
  // TypeScript ESM imports name the emitted file: "./routes/webhooks.js" for routes/webhooks.ts.
  const stem = base.replace(/\.[cm]?js$/, "");
  const tries = [
    base,
    ...[".js", ".ts", ".mjs", ".cjs", ".mts"].map((ext) => stem + ext),
    `${base}/index.js`,
    `${base}/index.ts`,
  ];
  return tries.find((t) => files.has(t));
}

export interface ExternalJsonParser {
  /** The file with the app-wide parser and the mount. */
  file: string;
  code: string;
  parser: GlobalJsonParser;
  /** Mount path + route path. */
  fullPath: string;
}

/**
 * The route's router is mounted in another file (`app.use("/webhooks", webhooksRouter)` in server.js) after
 * an app-wide `app.use(express.json())` there: the JSON parser runs first and the route's own
 * `express.raw()` gets nothing. Follows one level of mounting: an import binding or an inline `require()`.
 */
export async function jsonBeforeMount(
  files: string[],
  read: (path: string) => Promise<string | undefined>,
  routeFile: string,
  route: ExpressRoute,
): Promise<ExternalJsonParser | undefined> {
  const known = new Set(files);
  for (const file of files) {
    if (file === routeFile || !/\.(ts|js|mjs|cjs|mts)$/.test(file) || file.includes("node_modules/")) continue;
    const code = await read(file);
    if (!code || !isExpressFile(code)) continue;
    const parsers = globalJsonParsers(code);
    if (!parsers.length) continue;
    const bindings = [
      ...code.matchAll(/import\s+(\w+)(?:\s*,\s*\{[^}]*\})?\s+from\s+["']([^"']+)["']/g),
      ...code.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g),
    ]
      .filter((m) => resolveImport(file, m[2] ?? "", known) === routeFile)
      .map((m) => escapeRegExp(m[1] ?? ""));
    const inline = [...code.matchAll(/require\(\s*["']([^"']+)["']\s*\)/g)]
      .filter((m) => resolveImport(file, m[1] ?? "", known) === routeFile)
      .map((m) => escapeRegExp(m[0]));
    for (const target of [...bindings.map((b) => String.raw`\b${b}\b`), ...inline]) {
      const mount = new RegExp(String.raw`\b(\w+)\.use\(\s*(["'\`])([^"'\`]+)\2\s*,\s*${target}\s*\)`).exec(code);
      if (!mount) continue;
      const parser = parsers.find((p) => p.object === mount[1] && p.index < mount.index);
      if (!parser) continue;
      const fullPath =
        `${(mount[3] ?? "").replace(/\/$/, "")}/${route.path.replace(/^\//, "")}`.replace(/\/$/, "") || "/";
      return { file, code, parser, fullPath };
    }
  }
  return undefined;
}

const lineOf = (code: string, index: number): number => code.slice(0, index).split("\n").length;

/**
 * Express webhook findings vibe-preflight does not make: an unverified route in a file that neither reads
 * the signature header nor sits under a "webhook" path, and a verified route whose raw body is gone
 * because a JSON parser runs first (on the route, or app-wide earlier in the same file). Files the
 * scanner already flagged for the same rule are left alone.
 */
export async function expressWebhookFindings(
  files: string[],
  read: (path: string) => Promise<string | undefined>,
  existing: RawFinding[],
): Promise<RawFinding[]> {
  const flagged = new Set(
    existing.flatMap((f) => (f.location.kind === "file" ? [`${f.rule}|${f.location.file}`] : [])),
  );
  const out: RawFinding[] = [];
  for (const file of files) {
    if (!/\.(ts|js|mjs|cjs|mts)$/.test(file) || /(^|\/)(tests?|__tests__)\/|\.(test|spec)\./.test(file)) continue;
    const code = await read(file);
    if (!code || !isExpressFile(code)) continue;
    const route = stripeRoute(code);
    if (!route) continue;
    const add = (rule: string, toolSeverity: string, message: string, index: number) => {
      if (flagged.has(`${rule}|${file}`)) return;
      out.push({
        source: "project-config",
        rule,
        toolSeverity,
        message,
        location: { kind: "file", file, line: lineOf(code, index) },
      });
    };
    const body = code.slice(route.bodyOpen, route.bodyClose);
    if (!VERIFIED.test(body)) {
      add(
        "stripe-webhook-unverified",
        "error",
        `Express route \`POST ${route.path}\` handles Stripe events without \`constructEvent\`, so any POST is trusted.`,
        route.start,
      );
      continue;
    }
    if (JSON_PARSER.test(route.middleware)) {
      add(
        "stripe-webhook-parsed-body",
        "warning",
        `Express route \`POST ${route.path}\` parses the body with \`express.json()\` before \`constructEvent\`, which needs the raw bytes.`,
        route.start,
      );
      continue;
    }
    const first = jsonBeforeRoute(code, route);
    if (!first && !globalJsonParsers(code).length) {
      const external = await jsonBeforeMount(files, read, file, route);
      if (external && !flagged.has(`stripe-webhook-parsed-body|${external.file}`)) {
        out.push({
          source: "project-config",
          rule: "stripe-webhook-parsed-body",
          toolSeverity: "warning",
          message: `\`${external.parser.object}.use(${external.parser.parser})\` in \`${external.file}\` runs before the router of \`${file}\` is mounted, so \`POST ${external.fullPath}\` gets parsed JSON instead of the raw body${RAW_PARSER.test(route.middleware) ? " (the route's own `express.raw()` then has nothing left to read)" : ""}.`,
          location: { kind: "file", file: external.file, line: lineOf(external.code, external.parser.index) },
          subject: `express-route:${file}`,
        });
      }
      continue;
    }
    if (first) {
      add(
        "stripe-webhook-parsed-body",
        "warning",
        `\`${first.parser.object}.use(${first.parser.parser})\` runs before \`POST ${route.path}\`, so the webhook gets parsed JSON instead of the raw body${RAW_PARSER.test(route.middleware) ? " (the route's own `express.raw()` then has nothing left to read)" : ""}.`,
        first.parser.index,
      );
    }
  }
  return out;
}
