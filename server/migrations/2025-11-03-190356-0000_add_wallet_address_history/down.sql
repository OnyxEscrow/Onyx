-- Rollback wallet_address_history table
DROP INDEX IF EXISTS idx_wallet_history_changed_at;
DROP INDEX IF EXISTS idx_wallet_history_user_id;
DROP TABLE IF EXISTS wallet_address_history;
