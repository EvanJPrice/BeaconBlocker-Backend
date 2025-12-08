-- Create the settings_presets table
create table public.settings_presets (
  id uuid default gen_random_uuid() primary key,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  user_id uuid references auth.users(id) not null,
  name text not null,
  prompt text,
  blocked_categories jsonb,
  allow_list text[],
  block_list text[]
);

-- Enable Row Level Security (RLS)
alter table public.settings_presets enable row level security;

-- Policy: Users can only see their own presets
create policy "Users can select their own presets"
on public.settings_presets
for select
to authenticated
using (auth.uid() = user_id);

-- Policy: Users can insert their own presets
create policy "Users can insert their own presets"
on public.settings_presets
for insert
to authenticated
with check (auth.uid() = user_id);

-- Policy: Users can update their own presets
create policy "Users can update their own presets"
on public.settings_presets
for update
to authenticated
using (auth.uid() = user_id);

-- Policy: Users can delete their own presets
create policy "Users can delete their own presets"
on public.settings_presets
for delete
to authenticated
using (auth.uid() = user_id);
