-- Create wallets table for client-side generated wallet registration
-- Stores wallet metadata and public keys (no private keys ever stored)
CREATE TABLE wallets (
    -- Primary key: UUID for wallet identity
    id TEXT PRIMARY KEY NOT NULL,

    -- Foreign key: Link to user who owns this wallet
    user_id TEXT NOT NULL,

    -- Monero wallet address (58 characters for standard addresses, 95 for integrated)
    address TEXT NOT NULL UNIQUE,

    -- SHA256 hash of address for verification purposes
    address_hash TEXT NOT NULL UNIQUE,

    -- Public spend key (64 hex characters = 32 bytes)
    spend_key_pub TEXT NOT NULL,

    -- Public view key (64 hex characters = 32 bytes)
    view_key_pub TEXT NOT NULL,

    -- Optional signature for proof of ownership
    signature TEXT,

    -- Wallet registration timestamp (UTC)
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Last update timestamp (UTC)
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Add foreign key constraint to users table
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for user_id lookups (users typically query their own wallets)
CREATE INDEX idx_wallets_user_id ON wallets(user_id);

-- Create index for address lookups (verify uniqueness efficiently)
CREATE INDEX idx_wallets_address ON wallets(address);
