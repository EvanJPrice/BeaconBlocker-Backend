-- Create the blocking_log table
create table if not exists public.blocking_log (
  id uuid default gen_random_uuid() primary key,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  user_id uuid references auth.users(id) not null,
  url text not null,
  domain text,
  decision text not null,
  reason text,
  page_title text
);

-- Enable Row Level Security (RLS)
alter table public.blocking_log enable row level security;

-- Policy: Users can view their own logs
create policy "Users can view their own logs"
on public.blocking_log
for select
to authenticated
using (auth.uid() = user_id);

-- Policy: Users can insert their own logs (technically backend does this via service role usually, but if client does it directly)
create policy "Users can insert their own logs"
on public.blocking_log
for insert
to authenticated
with check (auth.uid() = user_id);

-- Policy: Users can delete their own logs
create policy "Users can delete their own logs"
on public.blocking_log
for delete
to authenticated
using (auth.uid() = user_id);
