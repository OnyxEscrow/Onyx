-- Add shipped tracking columns for improved escrow flow
-- Status flow: created -> funded -> shipped -> releasing -> completed

ALTER TABLE escrows ADD COLUMN shipped_at TIMESTAMP;
ALTER TABLE escrows ADD COLUMN auto_release_at TIMESTAMP;
ALTER TABLE escrows ADD COLUMN shipping_tracking TEXT;
