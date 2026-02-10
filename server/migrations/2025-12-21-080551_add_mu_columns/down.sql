-- Rollback v0.37.0 mu columns
ALTER TABLE escrows DROP COLUMN mu_p;
ALTER TABLE escrows DROP COLUMN mu_c;
