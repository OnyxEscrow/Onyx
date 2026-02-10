-- Add funding_output_pubkey column to store the output pubkey from funding transaction
-- This is needed by auto-pki.js to compute partial key images
ALTER TABLE escrows ADD COLUMN funding_output_pubkey TEXT DEFAULT NULL;
