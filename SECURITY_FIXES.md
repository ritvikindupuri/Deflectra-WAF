# Security Fixes - Deflectra WAF

This document describes the security fixes implemented for three High-severity findings and the manual steps required after merging.

## Summary of Security Fixes

### 1. ✅ Fixed: Open Email Relay (send-notification)

**Issue:** The `send-notification` function accepted `resendApiKey`, `to`, `subject`, and `html` from the request body with `verify_jwt = false` and CORS `'*'`, allowing anyone to send arbitrary emails using any provided API key.

**Fix:**
- Enabled JWT authentication (`verify_jwt = true`)
- Removed API key and recipient from request body
- Fetch `alert_email` and `resend_api_key` from `waf_settings` table based on authenticated user
- Only authenticated users can send emails to their own configured alert email

**Changes:**
- `supabase/config.toml`: Set `verify_jwt = true` for `send-notification`
- `supabase/functions/send-notification/index.ts`: Added authentication check, fetch settings from database
- `supabase/functions/_shared/vault-utils.ts`: Added Vault support for API keys (with plaintext fallback)

---

### 2. ✅ Fixed: SSRF (Server-Side Request Forgery)

**Issue:** Functions `auto-generate-fields` and `auto-setup-waf` fetched caller-supplied `site_url` without authentication or host filtering, allowing attackers to:
- Scan internal networks
- Access cloud metadata endpoints (AWS/GCP/Azure)
- Probe private services

**Fix:**
- Enabled JWT authentication (`verify_jwt = true`) for both functions
- Created shared URL validation utility (`_shared/url-validator.ts`)
- Validates URLs before fetching:
  - ✅ Must be HTTPS only
  - ❌ Blocks private IP ranges (10.x, 172.16-31.x, 192.168.x)
  - ❌ Blocks loopback (127.x, localhost, ::1)
  - ❌ Blocks link-local (169.254.x, fe80:)
  - ❌ Blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal)
  - ❌ Blocks AWS ECS/Fargate metadata range (100.64-127.x)
- Checks final URL after redirects to prevent redirect-based SSRF

**Changes:**
- `supabase/config.toml`: Set `verify_jwt = true` for `auto-generate-fields` and `auto-setup-waf`
- `supabase/functions/_shared/url-validator.ts`: New shared utility with `validateUrl()` and `safeFetch()`
- `supabase/functions/auto-generate-fields/index.ts`: Added auth check, use `safeFetch()` instead of raw `fetch()`
- `supabase/functions/auto-setup-waf/index.ts`: Added `safeFetch()` for URL validation

---

### 3. ✅ Fixed: Plaintext API Keys + Open Cron Endpoint

**Issue:** 
- Resend API keys stored in plaintext in `waf_settings.resend_api_key`
- `weekly-summary` function with `verify_jwt = false` and CORS `'*'` allowed anyone to invoke it and trigger emails

**Fix:**

#### Part A: Secured Cron Endpoint
- Added `x-cron-secret` header requirement to `weekly-summary`
- Function now validates request has correct secret before processing
- Prevents unauthorized invocation

#### Part B: Vault Migration Path (Proposed)
- Created migration file: `supabase/migrations/20261024195130_vault_migration_proposal.sql`
- Adds `resend_key_vault_id` column (does NOT drop plaintext column)
- Created `_shared/vault-utils.ts` with `getResendApiKey()` helper
- Functions now:
  1. First check `resend_key_vault_id` and read from Vault if present
  2. Fall back to `resend_api_key` (plaintext) if Vault ID is NULL
- This allows gradual migration without downtime or data loss

**Changes:**
- `supabase/functions/weekly-summary/index.ts`: Added cron secret validation, use Vault utility
- `supabase/functions/send-notification/index.ts`: Use Vault utility with fallback
- `supabase/functions/_shared/vault-utils.ts`: New Vault helper functions
- `supabase/migrations/20261024195130_vault_migration_proposal.sql`: Schema change for Vault support

---

## 🔧 Manual Steps Required After Merge

### Step 1: Set Environment Variables

Add the following environment variable to your Supabase project:

```bash
# Required for weekly-summary cron protection
CRON_SECRET=<generate-a-strong-random-secret>
```

**How to set:**
1. Go to Supabase Dashboard → Project Settings → Edge Functions → Secrets
2. Add `CRON_SECRET` with a strong random value (e.g., 32+ character random string)

---

### Step 2: Update Cron Job Configuration

If you're using an external cron service (e.g., Vercel Cron, GitHub Actions, Upstash QStash) to trigger `weekly-summary`:

**Update your cron job to include the secret header:**

```bash
curl -X POST https://<project-ref>.supabase.co/functions/v1/weekly-summary \
  -H "x-cron-secret: <your-CRON_SECRET-value>" \
  -H "Content-Type: application/json"
```

Replace `<project-ref>` and `<your-CRON_SECRET-value>` with your actual values.

---

### Step 3: Migrate API Keys to Vault (Recommended)

**Why?** Storing API keys in plaintext is a security risk. Supabase Vault encrypts secrets at rest.

**Current State:** Keys stored in `waf_settings.resend_api_key` (plaintext)  
**Target State:** Keys stored in Supabase Vault, referenced by `waf_settings.resend_key_vault_id`

#### Option A: Manual Migration (Per User)

For each user with a Resend API key:

```sql
-- 1. Store key in Vault
SELECT vault.create_secret(
  'user-<USER_ID>-resend-key',
  '<ACTUAL_API_KEY>',
  'Resend API key for user'
);

-- 2. Update waf_settings to reference Vault
UPDATE waf_settings 
SET resend_key_vault_id = 'user-<USER_ID>-resend-key' 
WHERE user_id = '<USER_ID>';
```

Replace `<USER_ID>` and `<ACTUAL_API_KEY>` with real values.

#### Option B: Bulk Migration Script

Run this from a Supabase SQL editor or admin function:

```sql
DO $$
DECLARE
  rec RECORD;
BEGIN
  FOR rec IN 
    SELECT user_id, resend_api_key 
    FROM waf_settings 
    WHERE resend_api_key IS NOT NULL 
      AND resend_key_vault_id IS NULL
  LOOP
    -- Store in Vault
    PERFORM vault.create_secret(
      'user-' || rec.user_id || '-resend-key',
      rec.resend_api_key,
      'Resend API key for user ' || rec.user_id
    );
    
    -- Update reference
    UPDATE waf_settings 
    SET resend_key_vault_id = 'user-' || rec.user_id || '-resend-key'
    WHERE user_id = rec.user_id;
    
    RAISE NOTICE 'Migrated key for user %', rec.user_id;
  END LOOP;
END $$;
```

#### Option C: Edge Function Migration Helper

You can also use the helper function in `_shared/vault-utils.ts`:

```typescript
import { migrateResendKeyToVault } from "../_shared/vault-utils.ts";

// In an admin-only edge function:
const vaultId = await migrateResendKeyToVault(supabaseService, userId, apiKey);
```

---

### Step 4: Verify Migration

Check that all users are migrated:

```sql
-- Should return 0 rows once migration is complete
SELECT user_id, alert_email 
FROM waf_settings 
WHERE resend_api_key IS NOT NULL 
  AND resend_key_vault_id IS NULL;
```

---

### Step 5: Clean Up (After All Keys Migrated)

Once you've confirmed ALL users are using Vault (Step 4 returns 0 rows):

```sql
-- Drop the plaintext column
ALTER TABLE waf_settings DROP COLUMN resend_api_key;
```

⚠️ **WARNING:** Do NOT drop the column until ALL keys are migrated. The functions have fallback logic that reads from `resend_api_key` if `resend_key_vault_id` is NULL.

---

## Testing Checklist

After deploying these changes, verify:

- [ ] `send-notification` requires authentication (401 without valid JWT)
- [ ] `send-notification` only sends to user's configured `alert_email`
- [ ] `auto-generate-fields` requires authentication (401 without valid JWT)
- [ ] `auto-setup-waf` requires authentication (401 without valid JWT)
- [ ] `auto-generate-fields` rejects private IPs (e.g., `https://192.168.1.1`)
- [ ] `auto-setup-waf` rejects private IPs (e.g., `https://10.0.0.1`)
- [ ] `weekly-summary` requires `x-cron-secret` header (401 without it)
- [ ] Functions still work with plaintext keys (before Vault migration)
- [ ] Functions work with Vault keys (after migration)

---

## Security Considerations

### What This Fixes:
✅ Email relay abuse  
✅ SSRF attacks via URL crawling  
✅ Unauthorized cron invocation  
✅ Plaintext API key storage (after Vault migration)

### What This Doesn't Fix:
⚠️ DNS rebinding attacks (attacker controls DNS that resolves to private IP after validation)  
⚠️ Time-of-check-time-of-use (TOCTOU) race conditions in URL validation  
⚠️ Redirect chains that eventually land on private IPs (partial mitigation: we check final URL)

### Additional Hardening (Optional):
- Implement rate limiting on these functions
- Add IP allowlisting for cron endpoint
- Use dedicated service accounts with minimal privileges
- Enable Supabase audit logs to monitor function invocations

---

## Rollback Plan

If issues occur after deployment:

1. **Revert config.toml changes** (set `verify_jwt = false` temporarily)
2. **Revert function code** to previous commit
3. **Keep migration file** (it's safe and doesn't break existing data)

---

## Questions?

For issues or questions about these security fixes, contact the security team or create an issue.
