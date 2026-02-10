-- Add underfunded escrow tracking columns (v0.68.0)
-- balance_received: Actual balance received (may be < required amount)
-- grace_period_ends_at: 48h grace period after initial funding timeout
-- refund_requested_at: When buyer requested partial refund
ALTER TABLE escrows ADD COLUMN balance_received BIGINT NOT NULL DEFAULT 0;
ALTER TABLE escrows ADD COLUMN grace_period_ends_at TIMESTAMP;
ALTER TABLE escrows ADD COLUMN refund_requested_at TIMESTAMP;
