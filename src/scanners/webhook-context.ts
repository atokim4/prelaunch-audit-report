import type { RawFinding } from "../types.ts";

/**
 * Second look at "Stripe webhook that doesn't verify the signature" before it is reported as Critical.
 * vibe-preflight reads one file at a time, so two shapes common in real Express apps come out wrong:
 * - the route reads the stripe-signature header and passes it to a helper in another file
 *   (`billingService.constructWebhookEvent(req.body, sig)`) that calls `constructEvent`;
 * - the file names Stripe events but never reads a request body (a job handler, a client-side test tool),
 *   so it is not a webhook endpoint at all.
 * - the file is another service's webhook (GitHub, Clerk) that only stores a `stripe_customer_id` column:
 *   nothing in it handles a Stripe event.
 * All are dropped and said in the report's "not checked" list, with the file and the helper named.
 */

const VERIFIED = /\bconstructEvent(?:Async)?\s*\(/;
const READS_SIGNATURE = /stripe-signature/i;
/** A request body being read: Express/Next pages (`req.body`), fetch-style (`await req.json()`), Hono, Lambda. */
const READS_BODY =
  /\b(?:req|request|ctx\.request|c\.req|context\.request)\s*\.\s*(?:body\b|rawBody\b|json\s*\(|text\s*\(|arrayBuffer\s*\(|formData\s*\()|\bawait\s+\w+\.(?:json|text|arrayBuffer)\s*\(\s*\)|\bevent\.body\b|\b(?:getRawBody|rawBody|buffer)\s*\(\s*req\b/;
/** Something that handles Stripe: the SDK, its signature header, or a Stripe event type in quotes. */
const HANDLES_STRIPE =
  /stripe-signature|\b(?:from\s+|require\s*\(\s*|import\s*\(\s*)["'](?:npm:|https?:\/\/[^"']*\/)?stripe(?:@[^"'/]*)?(?:\/[^"']*)?["']|\bnew\s+Stripe\s*\(|\bstripe\s*\.\s*webhooks\b|["'`](?:checkout\.session|customer\.subscription|invoice|payment_intent|charge|customer|price|product|account|payout|setup_intent)\.[a-z_.]+["'`]/i;
const SOURCE = /\.(ts|tsx|js|jsx|mjs|cjs|mts)$/;
const TEST = /(^|\/)(tests?|__tests__|e2e)\/|\.(test|spec)\./;

const stripComments = (code: string): string =>
  code.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Names of the functions this file hands the signature to: `verify(req.body, sig)`, `x.parse(body, req.get('stripe-signature'))`. */
function signatureCallees(code: string): string[] {
  const vars = [...code.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*[^;\n]*stripe-signature/gi)].map((m) => m[1] ?? "");
  const mentions = (args: string) =>
    READS_SIGNATURE.test(args) || vars.some((v) => new RegExp(String.raw`\b${escape(v)}\b`).test(args));
  const out = new Set<string>();
  // Every call, nested ones too: the scan goes on right after each opening parenthesis.
  for (const call of code.matchAll(/\b(\w+)\s*\(/g)) {
    const name = call[1] ?? "";
    const open = (call.index ?? 0) + call[0].length;
    let depth = 1;
    let end = open;
    for (; end < code.length && depth > 0; end++) {
      if (code[end] === "(") depth++;
      else if (code[end] === ")") depth--;
    }
    const args = code.slice(open, end - 1);
    // Only the call's own arguments, not a callback body passed to it (a route handler).
    if (/=>\s*\{|function\s*\(/.test(args)) continue;
    if (/^(get|header|headers|if|while|for|switch|require|String|Boolean|log|warn|error)$/.test(name)) continue;
    if (mentions(args)) out.add(name);
  }
  return [...out];
}

/** Another source file that defines `name` and calls constructEvent itself. */
async function verifierFile(
  name: string,
  self: string,
  files: string[],
  read: (path: string) => Promise<string | undefined>,
): Promise<string | undefined> {
  const n = escape(name);
  const defines = new RegExp(
    String.raw`function\s*\*?\s*${n}\s*\(|(?:^|[\s{,])(?:async\s+)?${n}\s*\([^)]*\)\s*(?::[^{]+)?\{|\b${n}\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|\w+\s*=>)`,
    "m",
  );
  for (const file of files) {
    if (file === self || !SOURCE.test(file) || TEST.test(file) || file.includes("node_modules/")) continue;
    const text = await read(file);
    if (!text) continue;
    const code = stripComments(text);
    if (VERIFIED.test(code) && defines.test(code)) return file;
  }
  return undefined;
}

export interface WebhookFilter {
  findings: RawFinding[];
  notes: string[];
}

export async function filterUnverifiedWebhooks(
  raws: RawFinding[],
  files: string[],
  read: (path: string) => Promise<string | undefined>,
): Promise<WebhookFilter> {
  const dropped = new Set<RawFinding>();
  const delegated: string[] = [];
  const notHandlers: string[] = [];
  const notStripe: string[] = [];
  for (const raw of raws) {
    if (raw.rule !== "stripe-webhook-unverified" || raw.location.kind !== "file") continue;
    const file = raw.location.file;
    const text = await read(file);
    if (!text) continue;
    const code = stripComments(text);
    if (!HANDLES_STRIPE.test(code)) {
      dropped.add(raw);
      notStripe.push(`\`${file}\``);
      continue;
    }
    if (!READS_BODY.test(code)) {
      dropped.add(raw);
      notHandlers.push(`\`${file}\``);
      continue;
    }
    if (!READS_SIGNATURE.test(code)) continue;
    for (const name of signatureCallees(code)) {
      const verifier = await verifierFile(name, file, files, read);
      if (!verifier) continue;
      dropped.add(raw);
      delegated.push(
        `\`${file}\` passes the signature to \`${name}()\` in \`${verifier}\`, which calls \`constructEvent\``,
      );
      break;
    }
  }
  const notes: string[] = [];
  if (delegated.length) {
    notes.push(
      `Stripe webhooks that verify through a helper in another file (${delegated.join("; ")}): not reported as unverified. The helper was read, not run, so a person should confirm it gets the raw body.`,
    );
  }
  if (notHandlers.length) {
    notes.push(
      `Files that name Stripe events but never read a request body (${notHandlers.join(", ")}): not webhook endpoints, so not reported as unverified webhooks.`,
    );
  }
  if (notStripe.length) {
    notes.push(
      `Webhooks of other services that only mention a Stripe field (${notStripe.join(", ")}): no Stripe SDK, signature header or event type in them, so not reported as unverified Stripe webhooks. Their own signature checks were not reviewed.`,
    );
  }
  return { findings: raws.filter((r) => !dropped.has(r)), notes };
}
