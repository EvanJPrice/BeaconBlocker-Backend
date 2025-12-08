-- Create the bug_reports table
create table public.bug_reports (
  id uuid default gen_random_uuid() primary key,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  user_id uuid references auth.users(id),
  description text not null,
  steps text,
  anonymous boolean default false,
  recipient text
);

-- Enable Row Level Security (RLS)
alter table public.bug_reports enable row level security;

-- Policy: Allow anyone (anon) to insert bug reports
create policy "Allow anonymous inserts"
on public.bug_reports
for insert
to anon, authenticated
with check (true);

-- Policy: Allow service_role (backend) to read/write everything
-- (Service role bypasses RLS by default, but good to know)
