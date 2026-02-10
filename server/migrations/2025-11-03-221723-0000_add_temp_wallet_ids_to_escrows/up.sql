-- Add temporary wallet ID columns to escrows table for non-custodial architecture
-- These wallets are EMPTY temporary wallets created by the server for multisig coordination only

ALTER TABLE escrows ADD COLUMN buyer_temp_wallet_id TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN vendor_temp_wallet_id TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN arbiter_temp_wallet_id TEXT DEFAULT NULL;

-- Add indexes for performance (wallet lookups during monitoring)
CREATE INDEX idx_escrows_buyer_temp_wallet ON escrows(buyer_temp_wallet_id);
CREATE INDEX idx_escrows_vendor_temp_wallet ON escrows(vendor_temp_wallet_id);
CREATE INDEX idx_escrows_arbiter_temp_wallet ON escrows(arbiter_temp_wallet_id);
