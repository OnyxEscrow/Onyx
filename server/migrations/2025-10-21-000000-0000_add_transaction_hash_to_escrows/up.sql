-- Add transaction_hash field to escrows table for tracking release/refund transactions
ALTER TABLE escrows ADD COLUMN transaction_hash VARCHAR(64);

-- Create index for faster transaction lookups
CREATE INDEX idx_escrows_tx_hash ON escrows(transaction_hash);
