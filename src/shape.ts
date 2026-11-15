import type { EdgeFunction, ProjectShape, RawFinding } from "./types.ts";

type Read = (path: string) => Promise<string | undefined>;

const LABELS: Record<ProjectShape["framework"], string> = {
  "next-app-router": "Next.js (App Router)",
  "next-pages-router": "Next.js (Pages Router)",
  "vite-react": "Vite + React single-page app",
  react: "React app",
  unknown: "JavaScript app",
};

function dependencies(pkg: string | undefined): Set<string> {
  if (!pkg) return new Set();
  try {
    const json = JSON.parse(pkg) as Record<string, unknown>;
    const names = ["dependencies", "devDependencies"].flatMap((key) => {
      const deps = json[key];
      return deps && typeof deps === "object" ? Object.keys(deps) : [];
    });
    return new Set(names);
  } catch {
    return new Set();
  }
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `[functions.<name>]`, with or without quotes around the name, as supabase/config.toml allows. */
export const functionTable = (name: string): RegExp =>
  new RegExp(String.raw`^\[\s*functions\.("?)${escapeRegExp(name)}\1\s*\]`);

/** `verify_jwt` per function from supabase/config.toml. Only the `[functions.<name>]` tables matter here. */
export function verifyJwtSettings(toml: string): Map<string, boolean> {
  const settings = new Map<string, boolean>();
  let current: string | undefined;
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    const table = line.match(/^\[\s*functions\.("?)([A-Za-z0-9_-]+)\1\s*\]$/);
    if (table) {
      current = table[2];
      continue;
    }
    if (line.startsWith("[")) {
      current = undefined;
      continue;
    }
    const setting = line.match(/^verify_jwt\s*=\s*(true|false)$/);
    if (current && setting) settings.set(current, setting[1] === "true");
  }
  return settings;
}

export async function detectShape(files: string[], read: Read): Promise<ProjectShape> {
  const deps = dependencies(await read("package.json"));
  const has = (pattern: RegExp) => files.some((f) => pattern.test(f));
  let framework: ProjectShape["framework"] = "unknown";
  if (deps.has("next")) {
    framework = has(/^(src\/)?app\/.*(page|route|layout)\.(t|j)sx?$/) ? "next-app-router" : "next-pages-router";
  } else if (deps.has("vite") && (deps.has("react") || deps.has("react-dom"))) {
    framework = "vite-react";
  } else if (deps.has("react")) {
    framework = "react";
  }

  const config = verifyJwtSettings((await read("supabase/config.toml")) ?? "");
  const edgeFunctions: EdgeFunction[] = files
    .map((f) => f.match(/^supabase\/functions\/([^/_][^/]*)\/index\.(ts|js|mts|mjs|tsx)$/))
    .filter((m): m is RegExpMatchArray => m !== null)
    .map((m) => ({ name: m[1] ?? "", path: m[0], verifyJwt: config.get(m[1] ?? "") ?? true }));

  return {
    framework,
    label: LABELS[framework],
    migrations: files.filter((f) => /^supabase\/migrations\/[^/]+\.sql$/.test(f)).length,
    edgeFunctions,
  };
}

/**
 * Stripe cannot send a Supabase JWT, so a webhook edge function left on the default `verify_jwt = true`
 * answers every real event with 401. Flagged only for functions that already check the Stripe signature
 * (otherwise turning the JWT gate off would open the hole that stripe-webhook-unverified reports).
 */
export async function edgeConfigFindings(shape: ProjectShape, read: Read): Promise<RawFinding[]> {
  const out: RawFinding[] = [];
  for (const fn of shape.edgeFunctions) {
    if (!fn.verifyJwt) continue;
    const code = (await read(fn.path)) ?? "";
    if (!/\bconstructEvent(?:Async)?\s*\(/.test(code) || !/stripe-signature/i.test(code)) continue;
    const config = (await read("supabase/config.toml")) ?? "";
    const line = config.split("\n").findIndex((l) => functionTable(fn.name).test(l.trim()));
    out.push({
      source: "project-config",
      rule: "stripe-webhook-jwt-gate",
      toolSeverity: "warning",
      message: `Edge function \`${fn.name}\` verifies the Stripe signature but runs with \`verify_jwt = true\`, so Supabase rejects Stripe's requests with 401 before the code runs.`,
      location:
        line >= 0
          ? { kind: "file", file: "supabase/config.toml", line: line + 1 }
          : { kind: "file", file: fn.path, line: 1 },
      subject: fn.name,
    });
  }
  return out;
}
