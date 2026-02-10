-- Add dispute_signing_pair column for WASM arbiter signing selection
-- Set by arbiter after resolution to indicate who co-signs: "arbiter_buyer" or "arbiter_vendor"
ALTER TABLE escrows ADD COLUMN dispute_signing_pair TEXT;
