-- GROnote usernames are unique across accounts, regardless of letter case.
create table if not exists public.gronote_usernames (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  username_key text generated always as (lower(btrim(username))) stored,
  created_at timestamptz not null default now(),
  constraint gronote_usernames_username_format check (username ~ '^[A-Za-z0-9._-]{3,24}$'),
  constraint gronote_usernames_username_key_unique unique (username_key)
);

alter table public.gronote_usernames enable row level security;
revoke all on table public.gronote_usernames from anon, authenticated, public;

insert into public.gronote_usernames (user_id, username)
select id, btrim(raw_user_meta_data->>'username')
from auth.users
where nullif(btrim(raw_user_meta_data->>'username'), '') is not null
on conflict (user_id) do update set username = excluded.username;

create or replace function public.gronote_claim_username(p_username text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_username text := btrim(p_username);
begin
  if v_user_id is null then
    raise exception 'You must be signed in to choose a username.';
  end if;
  if v_username !~ '^[A-Za-z0-9._-]{3,24}$' then
    raise exception 'Choose a username between 3 and 24 characters using letters, numbers, dots, underscores or hyphens.';
  end if;

  insert into public.gronote_usernames(user_id, username)
  values (v_user_id, v_username)
  on conflict (user_id) do update set username = excluded.username;

  return jsonb_build_object('success', true);
exception
  when unique_violation then
    raise exception using errcode = '23505',
      message = 'This username is already taken. Please choose another.';
end;
$$;

revoke all on function public.gronote_claim_username(text) from public, anon;
grant execute on function public.gronote_claim_username(text) to authenticated;

create or replace function public.gronote_release_username()
returns void
language sql
security definer
set search_path = ''
as $$
  delete from public.gronote_usernames where user_id = auth.uid();
$$;

revoke all on function public.gronote_release_username() from public, anon;
grant execute on function public.gronote_release_username() to authenticated;
