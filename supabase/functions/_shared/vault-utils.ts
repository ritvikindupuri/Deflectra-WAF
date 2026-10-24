/**
 * Vault utilities for secure secret management
 * 
 * Provides helper functions to read secrets from Supabase Vault with fallback
 * to plaintext columns during migration period.
 */

import { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * Retrieves a Resend API key for a user.
 * 
 * Priority:
 * 1. If resend_key_vault_id is set, read from Vault
 * 2. Otherwise, fall back to plaintext resend_api_key column
 * 
 * @param supabase - Supabase client with service role key (required for Vault access)
 * @param userId - User ID
 * @returns API key or null if not configured
 */
export async function getResendApiKey(
  supabase: SupabaseClient,
  userId: string
): Promise<string | null> {
  // Get user's waf_settings
  const { data: settings, error: settingsError } = await supabase
    .from("waf_settings")
    .select("resend_key_vault_id, resend_api_key")
    .eq("user_id", userId)
    .single();

  if (settingsError || !settings) {
    console.error("Failed to fetch waf_settings:", settingsError);
    return null;
  }

  // If Vault ID is set, read from Vault
  if (settings.resend_key_vault_id) {
    try {
      const { data: secret, error: vaultError } = await supabase.rpc(
        "vault_read_secret",
        { secret_id: settings.resend_key_vault_id }
      );

      if (vaultError) {
        console.error("Vault read failed, falling back to plaintext:", vaultError);
        return settings.resend_api_key || null;
      }

      return secret || null;
    } catch (err) {
      console.error("Vault read exception, falling back to plaintext:", err);
      return settings.resend_api_key || null;
    }
  }

  // Fall back to plaintext column
  return settings.resend_api_key || null;
}

/**
 * Migration helper: Store a user's Resend API key in Vault
 * 
 * @param supabase - Supabase client with service role key
 * @param userId - User ID
 * @param apiKey - The API key to store
 * @returns Vault secret ID or null on failure
 */
export async function migrateResendKeyToVault(
  supabase: SupabaseClient,
  userId: string,
  apiKey: string
): Promise<string | null> {
  const vaultId = `user-${userId}-resend-key`;
  
  try {
    // Store in Vault
    const { error: createError } = await supabase.rpc("vault_create_secret", {
      secret_id: vaultId,
      secret_value: apiKey,
      description: `Resend API key for user ${userId}`,
    });

    if (createError) {
      console.error("Failed to create Vault secret:", createError);
      return null;
    }

    // Update waf_settings to reference Vault
    const { error: updateError } = await supabase
      .from("waf_settings")
      .update({ resend_key_vault_id: vaultId })
      .eq("user_id", userId);

    if (updateError) {
      console.error("Failed to update waf_settings with vault_id:", updateError);
      return null;
    }

    return vaultId;
  } catch (err) {
    console.error("Vault migration exception:", err);
    return null;
  }
}
