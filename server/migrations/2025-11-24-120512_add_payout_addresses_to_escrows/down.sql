-- Rollback payout address columns
ALTER TABLE escrows DROP COLUMN vendor_payout_address;
ALTER TABLE escrows DROP COLUMN buyer_refund_address;
ALTER TABLE escrows DROP COLUMN vendor_payout_set_at;
ALTER TABLE escrows DROP COLUMN buyer_refund_set_at;
