-- v0.41.0: Add first_signer_had_r_agg column to fix TOCTOU timing bug
-- Stores whether nonces were aggregated when first signer signed
ALTER TABLE escrows ADD COLUMN first_signer_had_r_agg INTEGER;
