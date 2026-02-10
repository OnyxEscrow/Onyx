-- Revert MuSig2 nonce fields
ALTER TABLE escrows DROP COLUMN vendor_nonce_commitment;
ALTER TABLE escrows DROP COLUMN buyer_nonce_commitment;
ALTER TABLE escrows DROP COLUMN vendor_nonce_public;
ALTER TABLE escrows DROP COLUMN buyer_nonce_public;
ALTER TABLE escrows DROP COLUMN nonce_aggregated;
