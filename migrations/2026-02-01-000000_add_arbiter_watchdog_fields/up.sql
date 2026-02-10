-- Arbiter Watchdog Fields Migration
-- v0.70.0: Add fields for automated arbiter signing service

-- Buyer release request flag (set when buyer calls release)
ALTER TABLE escrows ADD COLUMN buyer_release_requested BOOLEAN DEFAULT FALSE NOT NULL;

-- Vendor refund request flag (set when vendor approves refund)
ALTER TABLE escrows ADD COLUMN vendor_refund_requested BOOLEAN DEFAULT FALSE NOT NULL;

-- Arbiter auto-signed flag (set when watchdog signs automatically)
ALTER TABLE escrows ADD COLUMN arbiter_auto_signed BOOLEAN DEFAULT FALSE NOT NULL;

-- Timestamp when arbiter watchdog auto-signed
ALTER TABLE escrows ADD COLUMN arbiter_auto_signed_at TIMESTAMP NULL;

-- Flag indicating dispute was escalated to human arbiter
ALTER TABLE escrows ADD COLUMN escalated_to_human BOOLEAN DEFAULT FALSE NOT NULL;

-- Arbiter partial signature (stored by watchdog for auto-signing)
-- This is the FROST partial signature from the arbiter's key_package
ALTER TABLE escrows ADD COLUMN arbiter_frost_partial_sig TEXT NULL;
