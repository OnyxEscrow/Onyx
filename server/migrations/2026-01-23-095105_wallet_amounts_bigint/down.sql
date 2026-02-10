-- Rollback: Convert wallet amount fields from BIGINT back to INTEGER
-- WARNING: This may cause data truncation if values exceed i32 max

CREATE TABLE wallets_old (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    address TEXT NOT NULL,
    address_hash TEXT NOT NULL,
    spend_key_pub TEXT NOT NULL DEFAULT '',
    view_key_pub TEXT NOT NULL DEFAULT '',
    signature TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    daily_limit_atomic INTEGER,
    monthly_limit_atomic INTEGER,
    last_withdrawal_date DATE,
    withdrawn_today_atomic INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO wallets_old (
    id, user_id, address, address_hash, spend_key_pub, view_key_pub,
    signature, created_at, updated_at, daily_limit_atomic, monthly_limit_atomic,
    last_withdrawal_date, withdrawn_today_atomic
)
SELECT
    id, user_id, address, address_hash, spend_key_pub, view_key_pub,
    signature, created_at, updated_at,
    CAST(daily_limit_atomic AS INTEGER),
    CAST(monthly_limit_atomic AS INTEGER),
    last_withdrawal_date,
    CAST(withdrawn_today_atomic AS INTEGER)
FROM wallets;

DROP TABLE wallets;
ALTER TABLE wallets_old RENAME TO wallets;

CREATE INDEX idx_wallets_user_id ON wallets(user_id);
CREATE UNIQUE INDEX idx_wallets_address ON wallets(address);
