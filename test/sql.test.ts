import { describe, expect, it } from "vitest";
import { functionArgs, ident, policies, qualify, statements, tableColumns } from "../src/patches/sql.ts";

const sql = `
-- a comment; with a semicolon
create table "public"."Orders" (
  id uuid primary key,
  owner_id uuid references auth.users (id),
  total numeric(10, 2) not null,
  constraint positive check (total > 0)
);
create function public.add(a int, b int default 1) returns int language sql as $$ select a + b; $$;
create policy "Owner reads; nobody else"
  on public."Orders" for select
  to authenticated
  using ((select auth.uid()) = owner_id);
`;
const files = [{ path: "m.sql", text: sql }];

describe("sql helpers", () => {
  it("splits statements around comments, quoted names and dollar bodies", () => {
    expect(statements(sql)).toHaveLength(3);
  });

  it("reads columns and skips table constraints", () => {
    expect(tableColumns(files, "public.orders")?.map((c) => [c.name, c.referencesAuthUsers, c.primaryKey])).toEqual([
      ["id", false, true],
      ["owner_id", true, false],
      ["total", false, false],
    ]);
  });

  it("reads policies with their command, roles and expression", () => {
    expect(policies(files, "public.orders")).toEqual([
      {
        name: "Owner reads; nobody else",
        table: "public.orders",
        command: "select",
        roles: "authenticated",
        using: "(select auth.uid()) = owner_id",
        withCheck: undefined,
      },
    ]);
  });

  it("drops defaults from function arguments", () => {
    expect(functionArgs(files, "public.add")).toBe("a int, b int");
    expect(functionArgs(files, "public.missing")).toBeUndefined();
  });

  it("qualifies and quotes names", () => {
    expect(qualify("audit_log")).toBe("public.audit_log");
    expect(ident("public.audit_log")).toBe("public.audit_log");
    expect(ident('Users can "read"')).toBe('"Users can ""read"""');
  });
});
