-- Rollback MFA fields from users table
DROP INDEX IF EXISTS idx_users_mfa_enabled;

-- SQLite doesn't support DROP COLUMN directly, but we can recreate the table
-- For now, we'll just document that these columns would need manual removal
-- In production, use a proper migration tool or recreate the table

-- Note: These columns will remain but be unused after rollback:
-- totp_secret, mfa_enabled, mfa_enabled_at, mfa_recovery_codes,
-- mfa_last_used_at, mfa_failed_attempts, mfa_locked_until
