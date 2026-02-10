-- Add columns to store real commitment data from funding transaction
-- These are required for CLSAG signing to work properly

-- The commitment mask (blinding factor) for the escrow output
-- This is captured from wallet-rpc when funding is detected
ALTER TABLE escrows ADD COLUMN funding_commitment_mask TEXT;

-- The transaction hash of the funding transaction
ALTER TABLE escrows ADD COLUMN funding_tx_hash TEXT;

-- The output index within the funding transaction (usually 0 or 1)
ALTER TABLE escrows ADD COLUMN funding_output_index INTEGER;

-- The global output index on the blockchain (needed for ring selection)
ALTER TABLE escrows ADD COLUMN funding_global_index INTEGER;
