-- v0.37.0: Add mu_p and mu_c columns for deterministic CLSAG verification
-- These store the mixing coefficients used in CLSAG aggregation
ALTER TABLE escrows ADD COLUMN mu_p TEXT;
ALTER TABLE escrows ADD COLUMN mu_c TEXT;
