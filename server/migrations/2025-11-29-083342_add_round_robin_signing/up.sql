-- Add round-robin signing columns to escrows table (v0.8.0)
-- These columns support the correct 2-of-3 multisig CLSAG signing protocol

-- PartialTx JSON from Signer 1 (buyer or vendor)
ALTER TABLE escrows ADD COLUMN partial_tx TEXT;

-- Who initiated the signing (buyer/vendor/arbiter)
ALTER TABLE escrows ADD COLUMN partial_tx_initiator TEXT;

-- CompletedClsag JSON from Signer 2
ALTER TABLE escrows ADD COLUMN completed_clsag TEXT;

-- Timestamp when signing was initiated
ALTER TABLE escrows ADD COLUMN signing_started_at INTEGER;

-- Signing phase: 'awaiting_initiation', 'awaiting_completion', 'completed', 'failed'
ALTER TABLE escrows ADD COLUMN signing_phase TEXT DEFAULT 'awaiting_initiation';
