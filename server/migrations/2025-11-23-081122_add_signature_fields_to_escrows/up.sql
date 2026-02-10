-- Add signature fields for vendor-buyer 2-of-3 multisig signing
-- Vendor signs when marking shipped, buyer signs when confirming receipt

ALTER TABLE escrows ADD COLUMN vendor_signature TEXT;
ALTER TABLE escrows ADD COLUMN buyer_signature TEXT;
ALTER TABLE escrows ADD COLUMN unsigned_tx_hex TEXT;
ALTER TABLE escrows ADD COLUMN vendor_signed_at INTEGER;
ALTER TABLE escrows ADD COLUMN buyer_signed_at INTEGER;
