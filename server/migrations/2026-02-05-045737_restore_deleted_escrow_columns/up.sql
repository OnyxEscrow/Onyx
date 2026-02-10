-- Restore 29 columns that were accidentally deleted by 2026-01-30 migration
-- These columns were added in various migrations but omitted when the table was recreated

-- Columns 61-62: Funding output identification (v0.8.1-0.8.2)
ALTER TABLE escrows ADD COLUMN funding_output_pubkey TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN funding_tx_pubkey TEXT DEFAULT NULL;

-- Columns 63-67: MuSig2 nonce fields (v0.9.0)
ALTER TABLE escrows ADD COLUMN vendor_nonce_commitment TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN buyer_nonce_commitment TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN vendor_nonce_public TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN buyer_nonce_public TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN nonce_aggregated TEXT DEFAULT NULL;

-- Column 68: First signer tracking (v0.9.1)
ALTER TABLE escrows ADD COLUMN first_signer_role TEXT DEFAULT NULL;

-- Columns 69-70: mu_P and mu_C mixing coefficients (v0.37.0)
ALTER TABLE escrows ADD COLUMN mu_p TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN mu_c TEXT DEFAULT NULL;

-- Column 71: First signer R_agg state (v0.41.0)
ALTER TABLE escrows ADD COLUMN first_signer_had_r_agg INTEGER DEFAULT NULL;

-- Columns 72-77: Round-robin signing (v0.43.0)
ALTER TABLE escrows ADD COLUMN multisig_txset TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN signing_round INTEGER DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN current_signer_id TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN partial_signed_txset TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN signing_initiated_at TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN broadcast_tx_hash TEXT DEFAULT NULL;

-- Column 78: Evidence count (v0.66.1)
ALTER TABLE escrows ADD COLUMN evidence_count INTEGER DEFAULT NULL;

-- Columns 79-80: Auto-Resolution/Escalation (v0.66.2)
ALTER TABLE escrows ADD COLUMN auto_escalated_at TIMESTAMP DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN escalation_reason TEXT DEFAULT NULL;

-- Column 81: Dispute signing pair (v0.66.3)
ALTER TABLE escrows ADD COLUMN dispute_signing_pair TEXT DEFAULT NULL;

-- Columns 82-87: Arbiter Watchdog fields (v0.70.0)
ALTER TABLE escrows ADD COLUMN buyer_release_requested BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE escrows ADD COLUMN vendor_refund_requested BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE escrows ADD COLUMN arbiter_auto_signed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE escrows ADD COLUMN arbiter_auto_signed_at TIMESTAMP DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN escalated_to_human BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE escrows ADD COLUMN arbiter_frost_partial_sig TEXT DEFAULT NULL;

-- Columns 88-90: Shipped tracking (v0.75.0)
ALTER TABLE escrows ADD COLUMN shipped_at TIMESTAMP DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN auto_release_at TIMESTAMP DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN shipping_tracking TEXT DEFAULT NULL;
