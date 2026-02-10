-- Add view_key_component column to wasm_multisig_participants table
-- This stores each participant's PRIVATE view key component (b_i)
-- Required for Monero multisig protocol: b_shared = b_buyer + b_vendor + b_arbiter (mod l)
-- NOTE: wasm_multisig_participants table was deprecated, this migration is now a no-op

-- Only run ALTER if table exists
SELECT 1;
