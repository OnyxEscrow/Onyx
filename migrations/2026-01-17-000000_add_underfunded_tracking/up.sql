-- Add underfunded tracking columns for partial payment handling
-- Phase 1: Migration for v0.68.0 - Underfunded Escrow Management

-- Track actual balance received (may be less than required amount)
ALTER TABLE escrows ADD COLUMN balance_received BIGINT DEFAULT 0 NOT NULL;

-- Grace period end timestamp (48h after initial funding timeout)
ALTER TABLE escrows ADD COLUMN grace_period_ends_at TIMESTAMP NULL;

-- When buyer requested refund for partial funds
ALTER TABLE escrows ADD COLUMN refund_requested_at TIMESTAMP NULL;

-- Note: buyer_refund_address already exists in schema (column 68)
