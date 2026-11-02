-- DNX Digital Tarefas: banco de dados (rodar uma vez no SQL Editor do Supabase)
create table if not exists public.profiles(
  user_id uuid primary key references auth.users on delete cascade,
  email text,
  role text not null default 'gestor' check (role in ('admin','gestor')),
  gestor_id text,
  created_at timestamptz not null default now());

create table if not exists public.items(
  col text not null,
  id text not null,
  gestor_id text,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (col, id));
alter table public.items replica identity full;
create index if not exists items_gestor_idx on public.items(gestor_id);

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.profiles where user_id = auth.uid() and role = 'admin') $$;

create or replace function public.my_gestor() returns text
language sql stable security definer set search_path = public as $$
  select gestor_id from public.profiles where user_id = auth.uid() $$;

create or replace function public.can_write_item(c text, g text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_admin() or (
    public.my_gestor() is not null and (
      c in ('templates','automations','columns','folders')
      or (c <> 'gestores' and g = public.my_gestor()))) $$;

-- o primeiro cadastro vira administrador; os demais entram como gestor sem quadro liberado
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(user_id, email, role)
  values (new.id, new.email,
          case when exists(select 1 from public.profiles where role = 'admin') then 'gestor' else 'admin' end);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.items enable row level security;

drop policy if exists "perfis: ler" on public.profiles;
create policy "perfis: ler" on public.profiles for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
drop policy if exists "perfis: admin altera" on public.profiles;
create policy "perfis: admin altera" on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "itens: ler" on public.items;
create policy "itens: ler" on public.items for select to authenticated
  using (public.is_admin() or (public.my_gestor() is not null and
        (col in ('gestores','templates','automations','columns','folders') or gestor_id = public.my_gestor())));
drop policy if exists "itens: criar" on public.items;
create policy "itens: criar" on public.items for insert to authenticated
  with check (public.can_write_item(col, gestor_id));
drop policy if exists "itens: alterar" on public.items;
create policy "itens: alterar" on public.items for update to authenticated
  using (public.can_write_item(col, gestor_id)) with check (public.can_write_item(col, gestor_id));
drop policy if exists "itens: excluir" on public.items;
create policy "itens: excluir" on public.items for delete to authenticated
  using (public.can_write_item(col, gestor_id));

do $$ begin
  alter publication supabase_realtime add table public.items;
exception when duplicate_object then null; end $$;

-- arquivos anexados (privados, até 10 MB)
insert into storage.buckets(id, name, public, file_size_limit)
values ('anexos', 'anexos', false, 10485760)
on conflict (id) do nothing;
drop policy if exists "anexos: ler" on storage.objects;
create policy "anexos: ler" on storage.objects for select to authenticated
  using (bucket_id = 'anexos' and (public.is_admin() or public.my_gestor() is not null));
drop policy if exists "anexos: enviar" on storage.objects;
create policy "anexos: enviar" on storage.objects for insert to authenticated
  with check (bucket_id = 'anexos' and (public.is_admin() or public.my_gestor() is not null));
drop policy if exists "anexos: excluir" on storage.objects;
create policy "anexos: excluir" on storage.objects for delete to authenticated
  using (bucket_id = 'anexos' and (public.is_admin() or owner = auth.uid()));

-- os 10 gestores
insert into public.items(col, id, data) values
 ('gestores','g-pedro','{"name":"Pedro","createdAt":1761344520000}'),
 ('gestores','g-patrick','{"name":"Patrick","createdAt":1761344520001}'),
 ('gestores','g-joyciele','{"name":"Joyciele","createdAt":1761344520002}'),
 ('gestores','g-alexandre','{"name":"Alexandre","createdAt":1761344520003}'),
 ('gestores','g-edjilson','{"name":"Edjilson","createdAt":1761344520004}'),
 ('gestores','g-luiz','{"name":"Luiz","createdAt":1761344520005}'),
 ('gestores','g-bryan','{"name":"Bryan","createdAt":1761344520006}'),
 ('gestores','g-lucas','{"name":"Lucas","createdAt":1761344520007}'),
 ('gestores','g-alberlan','{"name":"Alberlan","createdAt":1761344520008}'),
 ('gestores','g-adryan','{"name":"Adryan","createdAt":1761344520009}')
on conflict (col, id) do nothing;
