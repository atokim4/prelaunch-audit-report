-- Usage per organization for the billing page.
create view public.org_usage as
  select o.id as organization_id, o.name, o.plan, count(p.id) as projects
  from public.organizations o
  left join public.projects p on p.organization_id = o.id
  group by o.id;
