-- Rollback: Remove first_signer_had_r_agg column
ALTER TABLE escrows DROP COLUMN first_signer_had_r_agg;
