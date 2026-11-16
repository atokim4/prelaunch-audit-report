import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit.ts";
import { listFiles } from "../src/files.ts";
import { fixContext } from "../src/patches/index.ts";
import { phiColumns } from "../src/phi/columns.ts";
import { runPhiScan } from "../src/scanners/phi.ts";

/**
 * PHI map misses from the run-6 held-out repos (2026-11-16): a lab's patient register with only name and
 * contact fields, report files named by patient, a document vault typed 'prescription' with pages in
 * storage. Each rule has a control of the same shape that must stay out of the map.
 */
const NOW = new Date("2026-11-16T09:00:00Z");
const dirs: string[] = [];

afterAll(async () => {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
});

async function app(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pa-phi-"));
  dirs.push(dir);
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(dir, path)), { recursive: true });
    await writeFile(join(dir, path), text);
  }
  return dir;
}

const pkg = JSON.stringify({ name: "phi-shapes", dependencies: { "@supabase/supabase-js": "2.0.0" } });
const kinds = (columns: { name: string; kind: string }[]) => columns.map((c) => `${c.name}:${c.kind}`);

async function mapOf(sql: string): Promise<Record<string, string[]>> {
  const dir = await app({ "package.json": pkg, "supabase/migrations/1_init.sql": sql });
  const ctx = await fixContext(dir, await listFiles(dir, false), NOW);
  const scan = await runPhiScan(ctx, []);
  return Object.fromEntries(scan.result.tables.map((t) => [t.table, kinds(t.columns)]));
}

describe("PHI map: identifier-only and file-based records", () => {
  it("maps a patient register with only name and contact fields", () => {
    expect(kinds(phiColumns("public.patients", ["id", "external_id", "patient_name", "email", "phone"]))).toEqual([
      "patient_name:identifier",
      "email:identifier",
      "phone:identifier",
    ]);
  });

  it("leaves a plain user table with the same fields out (control)", () => {
    expect(phiColumns("public.users", ["id", "full_name", "email", "phone"])).toEqual([]);
    expect(phiColumns("public.patient_settings", ["id", "user_id", "email"])).toEqual([]);
  });

  it("maps a stored file named by patient as a health record", () => {
    expect(
      kinds(phiColumns("public.reports", ["id", "external_id", "patient_name", "file_path", "file_name", "status"])),
    ).toEqual(["file_path:health", "file_name:health", "patient_name:identifier"]);
  });

  it("leaves an avatar file on a user account out (control)", () => {
    expect(phiColumns("public.avatars", ["id", "user_id", "file_path", "file_name"])).toEqual([]);
  });

  it("maps a document whose type column only allows clinical kinds", () => {
    const columns = ["id", "profile_id", "type", "doc_date", "title", "page_count", "created_at"];
    const clinical = { type: "type text not null check (type in ('prescription', 'report'))" };
    expect(kinds(phiColumns("public.documents", columns, clinical))).toEqual([
      "type:health",
      "doc_date:health",
      "title:health",
      "page_count:health",
    ]);
    // Mutation of the same table: billing documents are not health records.
    const billing = { type: "type text not null check (type in ('invoice', 'receipt'))" };
    expect(phiColumns("public.documents", columns, billing)).toEqual([]);
    // Without the definition the name alone says nothing.
    expect(phiColumns("public.documents", columns)).toEqual([]);
  });

  it("follows the create table definitions and the pages stored under a PHI document", async () => {
    const map = await mapOf(`
      create table public.profiles (id uuid primary key references auth.users (id), full_name text);
      create table public.documents (
        id uuid primary key default gen_random_uuid(),
        profile_id uuid not null references public.profiles (id) on delete cascade,
        type text not null check (type in ('prescription', 'report')),
        title text
      );
      create table public.document_pages (
        id uuid primary key default gen_random_uuid(),
        document_id uuid not null references public.documents (id) on delete cascade,
        page_no int not null,
        storage_path text not null unique
      );
      create table public.invoices (id uuid primary key, profile_id uuid, pdf_url text);
      create table public.invoice_pages (id uuid primary key, invoice_id uuid, storage_path text);`);
    expect(map).toEqual({
      "public.document_pages": ["storage_path:health"],
      "public.documents": ["type:health", "title:health"],
    });
  });

  it("does not let the 'nobody else reads it' verdict pass when the owner is locked out too", async () => {
    const dir = await app({
      "package.json": pkg,
      "supabase/migrations/1_init.sql": `
        create table public.lab_results (
          id uuid primary key default gen_random_uuid(),
          patient_id uuid not null references auth.users (id),
          test_results text
        );
        alter table public.lab_results enable row level security;`,
    });
    const locked = await audit({ repo: dir, now: NOW, npmAudit: false, phi: true });
    expect(locked.phi?.tables.map((t) => [t.table, t.readBy, t.locked])).toEqual([["public.lab_results", [], true]]);

    // Control: the same table with an owner policy is "nobody" and not locked.
    const open = await app({
      "package.json": pkg,
      "supabase/migrations/1_init.sql": `
        create table public.lab_results (
          id uuid primary key default gen_random_uuid(),
          patient_id uuid not null references auth.users (id),
          test_results text
        );
        alter table public.lab_results enable row level security;
        create policy "own" on public.lab_results for select to authenticated using ((select auth.uid()) = patient_id);`,
    });
    const fine = await audit({ repo: open, now: NOW, npmAudit: false, phi: true });
    expect(fine.phi?.tables.map((t) => [t.table, t.readBy, t.locked])).toEqual([["public.lab_results", [], undefined]]);
  });
});
