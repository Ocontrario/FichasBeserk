-- Crônica: campanhas compartilhadas, membros e retratos de personagens
-- Execute este arquivo uma única vez no Supabase > SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.cronica_campaigns (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 70),
  invite_code text not null unique,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.cronica_campaign_members (
  campaign_id uuid not null references public.cronica_campaigns(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('master','player')),
  joined_at timestamptz not null default now(),
  primary key (campaign_id, user_id)
);

create table if not exists public.cronica_campaign_snapshots (
  campaign_id uuid not null references public.cronica_campaigns(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  character_data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (campaign_id, user_id)
);

create index if not exists cronica_campaign_members_user_idx on public.cronica_campaign_members(user_id);
create index if not exists cronica_campaign_snapshots_campaign_idx on public.cronica_campaign_snapshots(campaign_id);

alter table public.cronica_campaigns enable row level security;
alter table public.cronica_campaign_members enable row level security;
alter table public.cronica_campaign_snapshots enable row level security;

create or replace function public.cronica_is_campaign_member(p_campaign_id uuid)
returns boolean language sql stable security definer set search_path = public
as $$
  select exists(select 1 from public.cronica_campaign_members
    where campaign_id = p_campaign_id and user_id = auth.uid());
$$;

create or replace function public.cronica_is_campaign_master(p_campaign_id uuid)
returns boolean language sql stable security definer set search_path = public
as $$
  select exists(select 1 from public.cronica_campaign_members
    where campaign_id = p_campaign_id and user_id = auth.uid() and role = 'master');
$$;

revoke all on function public.cronica_is_campaign_member(uuid) from public;
revoke all on function public.cronica_is_campaign_master(uuid) from public;
grant execute on function public.cronica_is_campaign_member(uuid) to authenticated;
grant execute on function public.cronica_is_campaign_master(uuid) to authenticated;

drop policy if exists "campaigns readable by members" on public.cronica_campaigns;
create policy "campaigns readable by members" on public.cronica_campaigns
for select to authenticated using (
  owner_id = auth.uid() or public.cronica_is_campaign_member(id)
);

drop policy if exists "campaigns insert by owner" on public.cronica_campaigns;
create policy "campaigns insert by owner" on public.cronica_campaigns
for insert to authenticated with check (owner_id = auth.uid());

drop policy if exists "campaigns update by owner" on public.cronica_campaigns;
create policy "campaigns update by owner" on public.cronica_campaigns
for update to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());

drop policy if exists "campaigns delete by owner" on public.cronica_campaigns;
create policy "campaigns delete by owner" on public.cronica_campaigns
for delete to authenticated using (owner_id = auth.uid());

drop policy if exists "members readable by self or master" on public.cronica_campaign_members;
create policy "members readable by self or master" on public.cronica_campaign_members
for select to authenticated using (
  user_id = auth.uid() or public.cronica_is_campaign_master(campaign_id)
);

drop policy if exists "master can add members" on public.cronica_campaign_members;
create policy "master can add members" on public.cronica_campaign_members
for insert to authenticated with check (
  (user_id = auth.uid() and role = 'master' and exists (
    select 1 from public.cronica_campaigns c where c.id = campaign_id and c.owner_id = auth.uid()
  )) or public.cronica_is_campaign_master(campaign_id)
);

drop policy if exists "master can remove members" on public.cronica_campaign_members;
create policy "master can remove members" on public.cronica_campaign_members
for delete to authenticated using (
  user_id = auth.uid() or public.cronica_is_campaign_master(campaign_id)
);

drop policy if exists "snapshots readable by campaign members" on public.cronica_campaign_snapshots;
create policy "snapshots readable by campaign members" on public.cronica_campaign_snapshots
for select to authenticated using (public.cronica_is_campaign_member(campaign_id));

drop policy if exists "players write own snapshot" on public.cronica_campaign_snapshots;
create policy "players write own snapshot" on public.cronica_campaign_snapshots
for insert to authenticated with check (
  user_id = auth.uid() and public.cronica_is_campaign_member(campaign_id)
);

drop policy if exists "players update own snapshot" on public.cronica_campaign_snapshots;
create policy "players update own snapshot" on public.cronica_campaign_snapshots
for update to authenticated using (
  user_id = auth.uid() and public.cronica_is_campaign_member(campaign_id)
) with check (user_id = auth.uid() and public.cronica_is_campaign_member(campaign_id));

create or replace function public.cronica_create_campaign(p_name text)
returns table(id uuid, name text, invite_code text, role text)
language plpgsql
security definer
set search_path = public
as $$
declare
  new_id uuid;
  new_code text;
begin
  if auth.uid() is null then raise exception 'Faça login primeiro.'; end if;
  if char_length(trim(p_name)) < 2 or char_length(trim(p_name)) > 70 then
    raise exception 'O nome precisa ter entre 2 e 70 caracteres.';
  end if;
  new_code := upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));
  insert into public.cronica_campaigns(name, invite_code, owner_id)
  values (trim(p_name), new_code, auth.uid()) returning cronica_campaigns.id into new_id;
  insert into public.cronica_campaign_members(campaign_id, user_id, role)
  values (new_id, auth.uid(), 'master');
  return query select new_id, trim(p_name), new_code, 'master'::text;
end;
$$;

create or replace function public.cronica_join_campaign(p_code text)
returns table(id uuid, name text, invite_code text, role text)
language plpgsql
security definer
set search_path = public
as $$
declare c public.cronica_campaigns%rowtype;
begin
  if auth.uid() is null then raise exception 'Faça login primeiro.'; end if;
  select * into c from public.cronica_campaigns where invite_code = upper(trim(p_code));
  if c.id is null then raise exception 'Código de campanha não encontrado.'; end if;
  insert into public.cronica_campaign_members(campaign_id, user_id, role)
  values (c.id, auth.uid(), 'player')
  on conflict (campaign_id, user_id) do nothing;
  return query select c.id, c.name, c.invite_code, 'player'::text;
end;
$$;

revoke all on function public.cronica_create_campaign(text) from public;
revoke all on function public.cronica_join_campaign(text) from public;
grant execute on function public.cronica_create_campaign(text) to authenticated;
grant execute on function public.cronica_join_campaign(text) to authenticated;
grant select, insert, update, delete on public.cronica_campaigns to authenticated;
grant select, insert, delete on public.cronica_campaign_members to authenticated;
grant select, insert, update on public.cronica_campaign_snapshots to authenticated;
