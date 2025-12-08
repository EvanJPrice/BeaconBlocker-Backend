-- Create the rules table (if it doesn't exist)
create table if not exists public.rules (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users(id) not null,
  prompt text,
  blocked_categories jsonb default '{}'::jsonb,
  allow_list text[] default array[]::text[],
  block_list text[] default array[]::text[],
  last_seen timestamp with time zone default timezone('utc'::text, now()),
  api_key text,
  
  -- CONSTRAINT: Ensure one row per user
  constraint unique_user_id unique (user_id)
);

-- Enable RLS
alter table public.rules enable row level security;

-- FIX: If table already exists but has duplicates, run this MANUALLY:
/*
-- 1. Delete duplicates, keeping the most recent one
DELETE FROM rules a USING rules b
WHERE a.user_id = b.user_id AND a.created_at < b.created_at;

-- 2. Add the unique constraint
ALTER TABLE rules ADD CONSTRAINT unique_user_id UNIQUE (user_id);
*/
