-- Rollback multi-coin support migration

-- Drop indexes
DROP INDEX IF EXISTS idx_supported_coins_enabled;
DROP INDEX IF EXISTS idx_swap_orders_from_currency;

-- Remove from_network column from swap_orders
-- SQLite doesn't support DROP COLUMN, so we recreate the table
CREATE TABLE swap_orders_backup AS SELECT
    id, order_id, provider, provider_order_id, from_currency, to_currency,
    from_amount_sats, to_amount_atomic, rate_btc_per_xmr, rate_locked_at,
    rate_expires_at, btc_deposit_address, status, btc_tx_hash, btc_tx_confirmations,
    xmr_tx_hash, provider_response_json, last_error, retry_count,
    created_at, updated_at, deposit_detected_at, swap_initiated_at, completed_at
FROM swap_orders;

DROP TABLE swap_orders;

CREATE TABLE swap_orders (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_order_id TEXT,
    from_currency TEXT NOT NULL DEFAULT 'BTC',
    to_currency TEXT NOT NULL DEFAULT 'XMR',
    from_amount_sats BIGINT NOT NULL,
    to_amount_atomic BIGINT,
    rate_btc_per_xmr REAL,
    rate_locked_at DATETIME,
    rate_expires_at DATETIME,
    btc_deposit_address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'awaiting_deposit',
    btc_tx_hash TEXT,
    btc_tx_confirmations INTEGER,
    xmr_tx_hash TEXT,
    provider_response_json TEXT,
    last_error TEXT,
    retry_count INTEGER,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deposit_detected_at DATETIME,
    swap_initiated_at DATETIME,
    completed_at DATETIME
);

INSERT INTO swap_orders SELECT * FROM swap_orders_backup;
DROP TABLE swap_orders_backup;

-- Drop supported_coins table
DROP TABLE IF EXISTS supported_coins;
