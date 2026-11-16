import type { Membership, TenantLink } from "../types.ts";

/**
 * Finds an organization (team, workspace, tenant) model in the loaded schema: a membership table that
 * ties users to rows of an organization table, and the tables whose rows belong to an organization
 * through a foreign key. Read from the catalog (foreign keys, column names, enum and CHECK values), never
 * from table names alone: a table named `teams` with no membership table is not a tenant.
 */

export interface TenancyColumn {
  name: string;
  type: string;
  /** References auth.users(id). */
  user: boolean;
  parent?: { name: string; column: string };
  /** Enum labels, or the values a CHECK (col in (...)) allows. */
  enumLabels?: string[];
}

export interface TenancyTable {
  name: string;
  kind: "table" | "view";
  columns: TenancyColumn[];
  ownerColumns: string[];
}

const TENANT_NAME =
  /^(organi[sz]ations?|orgs?|teams?|workspaces?|tenants?|compan(y|ies)|accounts?|groups?|business_units?|clinics?|practices?|agenc(y|ies)|schools?|stores?|shops?|households?)$/i;
const MEMBER_NAME = /member|seat|staff|(^|_)users?$|^users?_|_roles?$/i;
const ROLE_COLUMN = /^(role|roles|member_role|org_role|team_role|workspace_role|access_level|permission_level)$/i;
/** Role values that manage an organization. */
export const ADMIN_ROLE = /owner|admin|super|manager|editor_admin|root/i;
const DEFAULT_ADMINS = ["owner", "admin"];

export interface Tenancy {
  tenant: string;
  tenantKey: string;
  tenantKeyType: string;
  members: Membership;
  /** Every table whose rows belong to an organization, by bare name (the tenant and membership tables included). */
  links: Map<string, TenantLink>;
}

interface Candidate {
  members: TenancyTable;
  tenant: TenancyTable;
  tenantColumn: TenancyColumn;
  userColumn: string;
}

function candidates(tables: TenancyTable[]): Candidate[] {
  const byName = new Map(tables.map((t) => [t.name, t]));
  const out: Candidate[] = [];
  for (const members of tables) {
    if (members.kind !== "table" || !MEMBER_NAME.test(members.name)) continue;
    for (const column of members.columns) {
      const tenant = column.parent && byName.get(column.parent.name);
      if (!tenant || tenant === members || tenant.kind !== "table") continue;
      const userColumn = members.ownerColumns.find((c) => c !== column.name);
      if (!userColumn) continue;
      out.push({ members, tenant, tenantColumn: column, userColumn });
    }
  }
  return out;
}

/** Plain-member and admin values for the role column, from the enum or CHECK list when there is one. */
function roles(column: TenancyColumn | undefined): Pick<Membership, "adminRoles" | "memberRole"> {
  if (!column) return { adminRoles: [] };
  const labels = column.enumLabels;
  if (!labels?.length) return { adminRoles: DEFAULT_ADMINS, memberRole: "member" };
  const admins = labels.filter((l) => ADMIN_ROLE.test(l));
  const plain = labels.find((l) => !ADMIN_ROLE.test(l) && /member|user|viewer|staff|basic|read/i.test(l));
  return { adminRoles: admins, memberRole: plain ?? labels.find((l) => !ADMIN_ROLE.test(l)) };
}

export function detectTenancy(tables: TenancyTable[]): Tenancy | undefined {
  const found = candidates(tables);
  if (!found.length) return undefined;
  const tenantNames = new Set(found.map((c) => c.tenant.name));
  // The top organization: named like one, not itself owned by another candidate (projects -> organizations),
  // and with the most member-like membership table.
  const score = (c: Candidate): number =>
    (TENANT_NAME.test(c.tenant.name) ? 4 : 0) +
    (c.tenant.columns.some((col) => col.parent && tenantNames.has(col.parent.name) && col.parent.name !== c.tenant.name)
      ? 0
      : 2) +
    (/member/i.test(c.members.name) ? 1 : 0);
  const best = [...found].sort((a, b) => score(b) - score(a) || a.members.name.localeCompare(b.members.name))[0];
  if (!best || !best.tenantColumn.parent) return undefined;
  const { tenant, members } = best;
  const keyColumn = tenant.columns.find((c) => c.name === best.tenantColumn.parent?.column);
  if (!keyColumn) return undefined;
  const roleColumn = members.columns.find((c) => ROLE_COLUMN.test(c.name));
  const membership: Membership = {
    table: `public.${members.name}`,
    tenantColumn: best.tenantColumn.name,
    userColumn: best.userColumn,
    ...(roleColumn ? { roleColumn: roleColumn.name } : {}),
    ...roles(roleColumn),
  };
  const base = { tenant: `public.${tenant.name}`, tenantKey: keyColumn.name, tenantKeyType: keyColumn.type };
  const links = new Map<string, TenantLink>();
  links.set(tenant.name, { ...base, members: membership, via: { kind: "tenant" } });
  links.set(members.name, { ...base, members: membership, via: { kind: "members" } });

  // Direct: a foreign key to the organization table. Then through a parent that is already linked, until
  // nothing changes (a comment -> task -> project -> organization chain).
  for (const table of tables) {
    if (table.kind !== "table" || links.has(table.name)) continue;
    // A foreign key to the organization table; else a column with the membership table's organization column
    // name and the key's type and no foreign key at all (audit logs often skip the constraint).
    const column =
      table.columns.find((c) => c.parent?.name === tenant.name) ??
      table.columns.find((c) => !c.parent && c.name === membership.tenantColumn && c.type === keyColumn.type);
    if (column) links.set(table.name, { ...base, members: membership, via: { kind: "column", column: column.name } });
  }
  // Views have no foreign keys: one that exposes the organization column (same name and type) is read as
  // organization data, so a visitor reading organization A's rows through it counts.
  const orgColumns = new Set([
    membership.tenantColumn,
    ...[...links.values()].flatMap((l) => (l.via.kind === "column" ? [l.via.column] : [])),
  ]);
  for (const view of tables) {
    if (view.kind !== "view") continue;
    const column = view.columns.find((c) => orgColumns.has(c.name) && c.type === keyColumn.type);
    if (column) links.set(view.name, { ...base, members: membership, via: { kind: "column", column: column.name } });
  }
  for (let changed = true; changed;) {
    changed = false;
    for (const table of tables) {
      if (table.kind !== "table" || links.has(table.name)) continue;
      const column = table.columns.find((c) => c.parent && c.parent.name !== table.name && links.has(c.parent.name));
      const parent = column?.parent && links.get(column.parent.name);
      if (!column?.parent || !parent || parent.via.kind === "tenant") continue;
      const parentTenantColumn =
        parent.via.kind === "column"
          ? parent.via.column
          : parent.via.kind === "members"
            ? membership.tenantColumn
            : undefined;
      links.set(table.name, {
        ...base,
        members: membership,
        via: {
          kind: "parent",
          column: column.name,
          parent: `public.${column.parent.name}`,
          parentColumn: column.parent.column,
          ...(parentTenantColumn ? { parentTenantColumn } : {}),
        },
      });
      changed = true;
    }
  }
  return { ...base, members: membership, links };
}
