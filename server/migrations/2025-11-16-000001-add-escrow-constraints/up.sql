-- Add uniqueness constraints to prevent duplicate escrows per order
CREATE UNIQUE INDEX IF NOT EXISTS unique_escrow_per_order
ON escrows (order_id);

-- Optional: ensure wallet RPC configs are unique per escrow
CREATE UNIQUE INDEX IF NOT EXISTS unique_wallet_rpc_per_escrow
ON wallet_rpc_configs (escrow_id);
