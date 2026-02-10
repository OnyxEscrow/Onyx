-- Add MFA/TOTP fields to users table
-- Supports Google Authenticator, Authy, and other TOTP apps

-- TOTP secret (encrypted, base32 encoded internally)
ALTER TABLE users ADD COLUMN totp_secret BLOB;

-- MFA enabled flag
ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;

-- MFA setup timestamp
ALTER TABLE users ADD COLUMN mfa_enabled_at TEXT;

-- Backup/recovery codes (JSON array of hashed codes)
-- Format: ["hash1", "hash2", ...] - 10 codes generated on MFA enable
ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT;

-- Last successful MFA verification (for security audit)
ALTER TABLE users ADD COLUMN mfa_last_used_at TEXT;

-- MFA verification attempts (for rate limiting)
ALTER TABLE users ADD COLUMN mfa_failed_attempts INTEGER NOT NULL DEFAULT 0;

-- Lockout timestamp if too many failed attempts
ALTER TABLE users ADD COLUMN mfa_locked_until TEXT;

-- Index for finding users with MFA enabled (admin queries)
CREATE INDEX idx_users_mfa_enabled ON users(mfa_enabled) WHERE mfa_enabled = 1;
