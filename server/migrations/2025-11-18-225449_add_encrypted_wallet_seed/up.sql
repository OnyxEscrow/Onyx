-- Phase 6: Add encrypted wallet seed columns to users table
-- This enables non-custodial wallet derivation from a single master seed

-- Add encrypted master seed (AES-256-GCM encrypted)
ALTER TABLE users ADD COLUMN encrypted_wallet_seed BLOB DEFAULT NULL;

-- Add salt for PBKDF2 password derivation
ALTER TABLE users ADD COLUMN wallet_seed_salt BLOB DEFAULT NULL;

-- Add BIP39 backup seed (12-word mnemonic, encrypted)
ALTER TABLE users ADD COLUMN bip39_backup_seed TEXT DEFAULT NULL;

-- Timestamp when seed was created
ALTER TABLE users ADD COLUMN seed_created_at INTEGER DEFAULT NULL;

-- Track if user acknowledged seed backup
ALTER TABLE users ADD COLUMN seed_backup_acknowledged BOOLEAN DEFAULT FALSE;

-- Index for faster lookups by seed creation time
CREATE INDEX idx_users_seed_created ON users(seed_created_at);
