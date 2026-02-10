-- Mandatory Shield Backup Tracking Table
-- Tracks which users have downloaded their FROST key backup files
-- backup_id is SHA3-256 hash of key_package (allows matching without decryption)

CREATE TABLE shield_backups (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('buyer', 'vendor', 'arbiter')),
    backup_id TEXT NOT NULL,                    -- SHA3-256 hash for matching
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP,                      -- Set when recovery succeeds
    download_count INTEGER NOT NULL DEFAULT 1,  -- Track re-downloads
    last_verified_at TIMESTAMP,                 -- Last successful restore
    FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(escrow_id, user_id)                  -- One shield per user per escrow
);

-- Indexes for efficient lookups
CREATE INDEX idx_shield_backups_escrow ON shield_backups(escrow_id);
CREATE INDEX idx_shield_backups_user ON shield_backups(user_id);
CREATE INDEX idx_shield_backups_backup_id ON shield_backups(backup_id);
