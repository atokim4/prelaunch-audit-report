import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { run } from "../src/exec.ts";
import { addedLines, findSecrets, mask, runSecretScan } from "../src/scanners/secrets.ts";

// Built at runtime so this file never contains a credential-shaped literal.
const BODY = "Ab3dE5gH7jK9mN1pQ3sT5vW7yZ";
const stripeLive = ["sk", "live", BODY].join("_");
const stripeTest = ["sk", "test", BODY].join("_");
const jwt = (claims: object): string =>
  [
    Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url"),
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "c2lnbmF0dXJlLW5vdC1yZWFsLWJ1dC1sb25nLWVub3VnaA",
  ].join(".");

describe("findSecrets", () => {
  it("finds a live Stripe key and grades a test key as test", () => {
    const hits = findSecrets(`const a = "${stripeLive}";\nconst b = "${stripeTest}";`);
    expect(hits.map((h) => [h.kind, h.grade, h.line])).toEqual([
      ["stripe-secret-key", "live", 1],
      ["stripe-secret-key", "test", 2],
    ]);
  });

  it("skips placeholders", () => {
    expect(findSecrets(`STRIPE_SECRET_KEY=${["sk", "live", "x".repeat(24)].join("_")}`)).toEqual([]);
    expect(findSecrets(`STRIPE_SECRET_KEY=${["sk", "test", "your_key_here_from_dashboard"].join("_")}`)).toEqual([]);
    expect(findSecrets(`key: ${["sk", "live", "a".repeat(28)].join("_")}`)).toEqual([]);
  });

  it("reports only service_role JWTs, not anon keys or the Supabase CLI demo key", () => {
    const service = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "service_role" });
    const anon = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "anon" });
    const demo = jwt({ iss: "supabase-demo", role: "service_role" });
    expect(findSecrets(`A=${service}\nB=${anon}\nC=${demo}`).map((h) => [h.kind, h.line])).toEqual([
      ["supabase-service-role-jwt", 1],
    ]);
  });

  it("does not take an Anthropic key for an OpenAI key", () => {
    const key = `sk-ant-api03-${BODY}${BODY}`;
    expect(findSecrets(key).map((h) => h.kind)).toEqual(["anthropic-key"]);
  });

  it("masks values", () => {
    expect(mask(stripeLive)).toBe("sk_live_Ab…(34 chars)");
  });
});

describe("addedLines", () => {
  it("tracks commit, file and new-side line numbers", () => {
    const log = [
      "commit 0123456789abcdef0123456789abcdef01234567",
      "diff --git a/x.ts b/x.ts",
      "--- a/x.ts",
      "+++ b/x.ts",
      "@@ -3,0 +4,2 @@",
      "+first",
      "+second",
    ].join("\n");
    expect(addedLines(log)).toEqual([
      { commit: "0123456789ab", file: "x.ts", line: 4, text: "first" },
      { commit: "0123456789ab", file: "x.ts", line: 5, text: "second" },
    ]);
  });
});

describe("runSecretScan", () => {
  let dir = "";
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("reports a key removed from the files as a history finding", async () => {
    dir = await mkdtemp(join(tmpdir(), "secret-scan-"));
    const git = (...args: string[]) =>
      run("git", ["-c", "user.name=test", "-c", "user.email=test@example.invalid", ...args], { cwd: dir });
    await git("init", "-q");
    await writeFile(join(dir, "config.ts"), `export const key = "${stripeLive}";\n`);
    await git("add", ".");
    await git("commit", "-qm", "add key");
    await writeFile(join(dir, "config.ts"), "export const key = process.env.STRIPE_SECRET_KEY;\n");
    await git("commit", "-qam", "remove key");

    const { findings, tool } = await runSecretScan(dir);
    expect(tool.note).toBeUndefined();
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      rule: "secret-in-history",
      toolSeverity: "live",
      location: { kind: "file", file: "config.ts", line: 1 },
    });
    expect(findings[0]!.message).not.toContain(BODY);
  });

  it("reports a key in the current files once, not again from history", async () => {
    dir = await mkdtemp(join(tmpdir(), "secret-scan-"));
    await run("git", ["init", "-q"], { cwd: dir });
    await writeFile(join(dir, "a.ts"), `const k = "${stripeLive}";\n`);
    await run("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "."], { cwd: dir });
    await run("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "x"], { cwd: dir });
    const { findings } = await runSecretScan(dir);
    expect(findings.map((f) => f.rule)).toEqual(["secret-in-tree"]);
  });

  it("scans a plain folder without git and says history was skipped", async () => {
    dir = await mkdtemp(join(tmpdir(), "secret-scan-"));
    await writeFile(join(dir, "a.ts"), `const k = "${stripeTest}";\n`);
    const { findings, tool } = await runSecretScan(dir);
    expect(findings.map((f) => [f.rule, f.toolSeverity])).toEqual([["secret-in-tree", "test"]]);
    expect(tool.note).toMatch(/not a git repository/i);
  });
});
