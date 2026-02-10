-- Drop frost_signing_state table
DROP INDEX IF EXISTS idx_frost_signing_partial_ready;
DROP INDEX IF EXISTS idx_frost_signing_status;
DROP TABLE frost_signing_state;
