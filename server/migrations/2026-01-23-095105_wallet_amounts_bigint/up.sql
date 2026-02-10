-- Migration: Convert wallet amount fields from INTEGER (i32) to BIGINT (i64)
-- Reason: i32 max = 2,147,483,647 piconero = ~0.002 XMR (insufficient for mainnet)
-- i64 max = 9,223,372,036,854,775,807 piconero = ~9.2 million XMR (sufficient)

-- SQLite doesn't support ALTER COLUMN, so we need to recreate the table
-- Step 1: Create new table with correct types
CREATE TABLE wallets_new (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    address TEXT NOT NULL,
    address_hash TEXT NOT NULL,
    spend_key_pub TEXT NOT NULL DEFAULT '',
    view_key_pub TEXT NOT NULL DEFAULT '',
    signature TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    daily_limit_atomic BIGINT,
    monthly_limit_atomic BIGINT,
    last_withdrawal_date DATE,
    withdrawn_today_atomic BIGINT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Step 2: Copy data from old table (existing INTEGER values auto-convert to BIGINT)
INSERT INTO wallets_new (
    id, user_id, address, address_hash, spend_key_pub, view_key_pub,
    signature, created_at, updated_at, daily_limit_atomic, monthly_limit_atomic,
    last_withdrawal_date, withdrawn_today_atomic
)
SELECT
    id, user_id, address, address_hash, spend_key_pub, view_key_pub,
    signature, created_at, updated_at, daily_limit_atomic, monthly_limit_atomic,
    last_withdrawal_date, withdrawn_today_atomic
FROM wallets;

-- Step 3: Drop old table
DROP TABLE wallets;

-- Step 4: Rename new table
ALTER TABLE wallets_new RENAME TO wallets;

-- Step 5: Recreate indexes
CREATE INDEX idx_wallets_user_id ON wallets(user_id);
CREATE UNIQUE INDEX idx_wallets_address ON wallets(address);
