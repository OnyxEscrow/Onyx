-- Rollback shield_backups table
DROP INDEX IF EXISTS idx_shield_backups_backup_id;
DROP INDEX IF EXISTS idx_shield_backups_user;
DROP INDEX IF EXISTS idx_shield_backups_escrow;
DROP TABLE IF EXISTS shield_backups;
