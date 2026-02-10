-- Revert adding transaction_hash to escrows table
DROP INDEX idx_escrows_tx_hash;
ALTER TABLE escrows DROP COLUMN transaction_hash;
