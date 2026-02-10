-- Drop wallets table and indexes
DROP INDEX IF EXISTS idx_wallets_address;
DROP INDEX IF EXISTS idx_wallets_user_id;
DROP TABLE IF EXISTS wallets;
