-- Enable RLS on the rules table
alter table public.rules enable row level security;

-- Policy: Allow users to view their own rules
create policy "Users can view own rules"
on public.rules
for select
to authenticated
using (auth.uid() = user_id);

-- Policy: Allow users to insert their own rules
create policy "Users can insert own rules"
on public.rules
for insert
to authenticated
with check (auth.uid() = user_id);

-- Policy: Allow users to update their own rules
create policy "Users can update own rules"
on public.rules
for update
to authenticated
using (auth.uid() = user_id);

-- Policy: Allow users to delete their own rules
create policy "Users can delete own rules"
on public.rules
for delete
to authenticated
using (auth.uid() = user_id);
