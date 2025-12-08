-- Drop unused columns from the rules table
ALTER TABLE rules DROP COLUMN IF EXISTS api_key;
ALTER TABLE rules DROP COLUMN IF EXISTS last_seen;
