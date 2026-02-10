-- Add wallet_rpc_configs table for persisting client wallet RPC connection info
-- This enables automatic recovery of escrows after server restarts

CREATE TABLE wallet_rpc_configs (
    -- Primary key: UUID of the wallet instance
    wallet_id TEXT PRIMARY KEY,

    -- Foreign key to escrows table (CASCADE delete when escrow deleted)
    escrow_id TEXT NOT NULL REFERENCES escrows(id) ON DELETE CASCADE,

    -- Role of this wallet in the escrow
    role TEXT NOT NULL CHECK(role IN ('buyer', 'vendor', 'arbiter')),

    -- RPC connection info (AES-256-GCM encrypted with MULTISIG_ENCRYPTION_KEY)
    -- These fields contain encrypted JSON with connection details
    rpc_url_encrypted BLOB NOT NULL,
    rpc_user_encrypted BLOB,
    rpc_password_encrypted BLOB,

    -- Metadata for monitoring and debugging
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_connected_at INTEGER,
    connection_attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,

    -- Ensure each role appears only once per escrow
    UNIQUE(escrow_id, role)
);

-- Index for fast lookup by escrow_id during recovery
CREATE INDEX idx_wallet_rpc_escrow ON wallet_rpc_configs(escrow_id);

-- Index for role-based queries
CREATE INDEX idx_wallet_rpc_role ON wallet_rpc_configs(role);

-- Add recovery_mode to escrows table
-- - 'manual' (default): Client must re-register RPC after server restart
-- - 'automatic': Server persists RPC config for automatic recovery
ALTER TABLE escrows ADD COLUMN recovery_mode TEXT
    NOT NULL DEFAULT 'manual'
    CHECK(recovery_mode IN ('manual', 'automatic'));
