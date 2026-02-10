-- Rollback: Remove signature fields from escrows table

ALTER TABLE escrows DROP COLUMN vendor_signature;
ALTER TABLE escrows DROP COLUMN buyer_signature;
ALTER TABLE escrows DROP COLUMN unsigned_tx_hex;
ALTER TABLE escrows DROP COLUMN vendor_signed_at;
ALTER TABLE escrows DROP COLUMN buyer_signed_at;
