-- Rollback wallet RPC configs table and escrow recovery_mode column

DROP TABLE IF EXISTS wallet_rpc_configs;

-- SQLite doesn't support DROP COLUMN directly, need to recreate table
-- For now, this is a destructive rollback (loses escrow data)
-- TODO: Implement proper column removal via table recreation if needed
-- ALTER TABLE escrows DROP COLUMN recovery_mode;
