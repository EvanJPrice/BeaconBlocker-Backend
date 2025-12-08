-- Add active_preset_id to rules table to persist the user's active preset
ALTER TABLE public.rules 
ADD COLUMN IF NOT EXISTS active_preset_id uuid REFERENCES public.settings_presets(id) ON DELETE SET NULL;
