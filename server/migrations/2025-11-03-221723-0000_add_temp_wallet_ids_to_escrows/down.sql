-- Rollback: Remove temporary wallet ID columns and indexes

DROP INDEX IF EXISTS idx_escrows_arbiter_temp_wallet;
DROP INDEX IF EXISTS idx_escrows_vendor_temp_wallet;
DROP INDEX IF EXISTS idx_escrows_buyer_temp_wallet;

ALTER TABLE escrows DROP COLUMN arbiter_temp_wallet_id;
ALTER TABLE escrows DROP COLUMN vendor_temp_wallet_id;
ALTER TABLE escrows DROP COLUMN buyer_temp_wallet_id;
