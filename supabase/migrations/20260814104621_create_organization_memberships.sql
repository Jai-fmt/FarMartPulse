create type public.org_member_role as enum ('viewer', 'admin', 'owner');

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 1 and 120),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.org_members (
  organization_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role public.org_member_role not null default 'viewer',
  invited_by uuid default auth.uid() references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);

create index org_members_user_id_idx
  on public.org_members (user_id);

create index org_members_organization_role_idx
  on public.org_members (organization_id, role);

create schema if not exists private;

revoke all on schema private from public;

create function private.is_org_member(
  target_organization_id uuid,
  target_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.org_members
    where organization_id = target_organization_id
      and user_id = target_user_id
  );
$$;

create function private.has_org_role(
  target_organization_id uuid,
  target_user_id uuid,
  allowed_roles public.org_member_role[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.org_members
    where organization_id = target_organization_id
      and user_id = target_user_id
      and role = any (allowed_roles)
  );
$$;

create function private.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger organizations_set_updated_at
before update on public.organizations
for each row execute function private.set_updated_at();

create trigger org_members_set_updated_at
before update on public.org_members
for each row execute function private.set_updated_at();

create function private.ensure_org_has_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  target_organization_id uuid := coalesce(new.organization_id, old.organization_id);
begin
  if exists (
    select 1
    from public.organizations
    where id = target_organization_id
  ) and not exists (
    select 1
    from public.org_members
    where organization_id = target_organization_id
      and role = 'owner'
  ) then
    raise exception 'organization % must retain at least one owner', target_organization_id
      using errcode = '23514';
  end if;

  return null;
end;
$$;

create constraint trigger org_members_require_owner
after insert or update or delete on public.org_members
deferrable initially deferred
for each row execute function private.ensure_org_has_owner();

alter table public.organizations enable row level security;
alter table public.org_members enable row level security;

revoke all on public.organizations from anon, authenticated;
revoke all on public.org_members from anon, authenticated;

grant select, delete on public.organizations to authenticated;
grant update (name) on public.organizations to authenticated;
grant select, delete on public.org_members to authenticated;
grant insert (organization_id, user_id, role) on public.org_members to authenticated;
grant update (role) on public.org_members to authenticated;
grant all on public.organizations to service_role;
grant all on public.org_members to service_role;
grant usage on type public.org_member_role to authenticated, service_role;

revoke all on function private.is_org_member(uuid, uuid) from public;
revoke all on function private.has_org_role(uuid, uuid, public.org_member_role[]) from public;
grant execute on function private.is_org_member(uuid, uuid) to authenticated;
grant execute on function private.has_org_role(uuid, uuid, public.org_member_role[]) to authenticated;

create policy "Organization members can view their organizations"
on public.organizations
for select
to authenticated
using (
  (select private.is_org_member(id, (select auth.uid())))
);

create policy "Admins can update their organizations"
on public.organizations
for update
to authenticated
using (
  (select private.has_org_role(
    id,
    (select auth.uid()),
    array['admin', 'owner']::public.org_member_role[]
  ))
)
with check (
  (select private.has_org_role(
    id,
    (select auth.uid()),
    array['admin', 'owner']::public.org_member_role[]
  ))
);

create policy "Owners can delete their organizations"
on public.organizations
for delete
to authenticated
using (
  (select private.has_org_role(
    id,
    (select auth.uid()),
    array['owner']::public.org_member_role[]
  ))
);

create policy "Organization members can view memberships"
on public.org_members
for select
to authenticated
using (
  (select private.is_org_member(organization_id, (select auth.uid())))
);

create policy "Owners and admins can add permitted members"
on public.org_members
for insert
to authenticated
with check (
  (select private.has_org_role(
    organization_id,
    (select auth.uid()),
    array['owner']::public.org_member_role[]
  ))
  or (
    role = 'viewer'
    and (select private.has_org_role(
      organization_id,
      (select auth.uid()),
      array['admin']::public.org_member_role[]
    ))
  )
);

create policy "Owners and admins can update permitted members"
on public.org_members
for update
to authenticated
using (
  (select private.has_org_role(
    organization_id,
    (select auth.uid()),
    array['owner']::public.org_member_role[]
  ))
  or (
    role = 'viewer'
    and (select private.has_org_role(
      organization_id,
      (select auth.uid()),
      array['admin']::public.org_member_role[]
    ))
  )
)
with check (
  (select private.has_org_role(
    organization_id,
    (select auth.uid()),
    array['owner']::public.org_member_role[]
  ))
  or (
    role = 'viewer'
    and (select private.has_org_role(
      organization_id,
      (select auth.uid()),
      array['admin']::public.org_member_role[]
    ))
  )
);

create policy "Owners and admins can delete permitted members"
on public.org_members
for delete
to authenticated
using (
  (select private.has_org_role(
    organization_id,
    (select auth.uid()),
    array['owner']::public.org_member_role[]
  ))
  or (
    role = 'viewer'
    and (select private.has_org_role(
      organization_id,
      (select auth.uid()),
      array['admin']::public.org_member_role[]
    ))
  )
);

create function public.create_organization(organization_name text)
returns public.organizations
language plpgsql
security definer
set search_path = ''
as $$
declare
  actor_id uuid := auth.uid();
  normalized_name text := btrim(organization_name);
  created_organization public.organizations;
begin
  if actor_id is null then
    raise exception 'authentication required'
      using errcode = '42501';
  end if;

  if normalized_name is null or char_length(normalized_name) not between 1 and 120 then
    raise exception 'organization name must contain between 1 and 120 characters'
      using errcode = '22023';
  end if;

  insert into public.organizations (name, created_by)
  values (normalized_name, actor_id)
  returning * into created_organization;

  insert into public.org_members (
    organization_id,
    user_id,
    role,
    invited_by
  )
  values (
    created_organization.id,
    actor_id,
    'owner',
    actor_id
  );

  return created_organization;
end;
$$;

revoke all on function public.create_organization(text) from public;
grant execute on function public.create_organization(text) to authenticated, service_role;

comment on table public.organizations is
  'Tenant organizations whose engagement data is isolated through row-level security.';

comment on table public.org_members is
  'Organization memberships and authorization roles for Supabase Auth users.';

comment on function public.create_organization(text) is
  'Atomically creates an organization and assigns the authenticated creator as its first owner.';
