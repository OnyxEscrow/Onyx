-- Add funding_tx_pubkey column to escrows table
-- This stores the TX public key (R) from the funding transaction
-- Required for computing output secret key derivation: x = H_s(a*R || idx) + b
ALTER TABLE escrows ADD COLUMN funding_tx_pubkey TEXT DEFAULT NULL;
