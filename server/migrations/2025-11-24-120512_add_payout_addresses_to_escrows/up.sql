-- Add payout and refund addresses to escrows table
-- These addresses are where funds will be sent when escrow is released/refunded

ALTER TABLE escrows ADD COLUMN vendor_payout_address TEXT;
ALTER TABLE escrows ADD COLUMN buyer_refund_address TEXT;

-- Track when addresses were set
ALTER TABLE escrows ADD COLUMN vendor_payout_set_at INTEGER;
ALTER TABLE escrows ADD COLUMN buyer_refund_set_at INTEGER;

-- Comments for clarity
-- vendor_payout_address: Monero address where vendor receives funds on successful escrow completion
-- buyer_refund_address: Monero address where buyer receives refund if escrow is cancelled/disputed
-- These addresses should be set BEFORE the multisig is funded
