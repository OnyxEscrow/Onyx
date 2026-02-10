-- Rollback Phase 6: Remove encrypted wallet seed columns

DROP INDEX IF EXISTS idx_users_seed_created;

ALTER TABLE users DROP COLUMN seed_backup_acknowledged;
ALTER TABLE users DROP COLUMN seed_created_at;
ALTER TABLE users DROP COLUMN bip39_backup_seed;
ALTER TABLE users DROP COLUMN wallet_seed_salt;
ALTER TABLE users DROP COLUMN encrypted_wallet_seed;
