-- v0.43.0: Add round-robin signing columns for 2-of-3 multisig
-- Uses Monero's native sign_multisig instead of WASM parallel signing
ALTER TABLE escrows ADD COLUMN multisig_txset TEXT;
ALTER TABLE escrows ADD COLUMN signing_round INTEGER;
ALTER TABLE escrows ADD COLUMN current_signer_id TEXT;
ALTER TABLE escrows ADD COLUMN partial_signed_txset TEXT;
ALTER TABLE escrows ADD COLUMN signing_initiated_at TEXT;
ALTER TABLE escrows ADD COLUMN broadcast_tx_hash TEXT;
