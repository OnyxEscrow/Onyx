-- Add blockchain_creation_height to store the blockchain height when escrow was created
-- This ensures we never miss payments by always scanning from the correct height
ALTER TABLE escrows ADD COLUMN blockchain_creation_height INTEGER DEFAULT 0 NOT NULL;
