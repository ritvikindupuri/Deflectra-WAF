-- Migration: Move Resend API keys from waf_settings to Supabase Vault
-- 
-- IMPORTANT: This is a PROPOSAL migration that does NOT automatically migrate existing keys.
-- The plaintext resend_api_key column is NOT dropped to preserve existing data.
-- 
-- MANUAL MIGRATION STEPS (after this migration runs):
-- 
-- 1. For each user with a resend_api_key in waf_settings:
--    a. Store their key in Vault using the Supabase Vault API or SQL:
--       SELECT vault.create_secret('user-{user_id}-resend-key', 'their_actual_key', 'Resend API key for user');
--    b. Update their record to mark vault migration complete:
--       UPDATE waf_settings SET resend_key_vault_id = 'user-{user_id}-resend-key' WHERE user_id = '{user_id}';
-- 
-- 2. Once ALL users are migrated to Vault, you can safely drop the plaintext column:
--    ALTER TABLE public.waf_settings DROP COLUMN resend_api_key;
-- 
-- BEHAVIOR:
-- - Functions will first check resend_key_vault_id and read from Vault if present
-- - Functions will fall back to resend_api_key (plaintext) if vault_id is NULL
-- - This allows gradual migration without downtime
--

-- Add new column to track Vault secret ID (without dropping the old column)
ALTER TABLE public.waf_settings 
  ADD COLUMN IF NOT EXISTS resend_key_vault_id TEXT DEFAULT NULL;

-- Add helpful comment
COMMENT ON COLUMN public.waf_settings.resend_key_vault_id IS 
  'Vault secret ID for Resend API key. When set, functions read from Vault instead of resend_api_key column.';

COMMENT ON COLUMN public.waf_settings.resend_api_key IS 
  'DEPRECATED: Plaintext Resend API key. Migrate to Vault (resend_key_vault_id) and drop this column.';
