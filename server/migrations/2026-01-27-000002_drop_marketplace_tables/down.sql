-- Recreate marketplace tables (rollback)
-- WARNING: This does not restore data, only schema

CREATE TABLE IF NOT EXISTS supported_coins (
    ticker TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS listings (
    id TEXT PRIMARY KEY NOT NULL,
    vendor_id TEXT NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price_xmr BIGINT NOT NULL,
    category TEXT NOT NULL,
    stock INTEGER NOT NULL DEFAULT 1,
    images_ipfs_cids TEXT DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER NOT NULL DEFAULT 1,
    shipping_cost_xmr BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY NOT NULL,
    buyer_id TEXT NOT NULL REFERENCES users(id),
    vendor_id TEXT NOT NULL REFERENCES users(id),
    listing_id TEXT NOT NULL REFERENCES listings(id),
    escrow_id TEXT REFERENCES escrows(id),
    status TEXT NOT NULL DEFAULT 'pending',
    total_xmr BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    shipping_address TEXT,
    shipping_notes TEXT,
    payment_method TEXT,
    swap_order_id TEXT
);

CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL REFERENCES orders(id),
    reviewer_id TEXT NOT NULL REFERENCES users(id),
    reviewed_id TEXT NOT NULL REFERENCES users(id),
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    signature TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS swap_orders (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL REFERENCES orders(id),
    provider TEXT NOT NULL,
    provider_order_id TEXT,
    from_currency TEXT NOT NULL,
    to_currency TEXT NOT NULL,
    from_amount_sats BIGINT NOT NULL,
    to_amount_atomic BIGINT,
    rate_btc_per_xmr REAL,
    rate_locked_at TIMESTAMP,
    rate_expires_at TIMESTAMP,
    btc_deposit_address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'created',
    btc_tx_hash TEXT,
    btc_tx_confirmations INTEGER,
    xmr_tx_hash TEXT,
    provider_response_json TEXT,
    last_error TEXT,
    retry_count INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_messages (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL REFERENCES orders(id),
    sender_id TEXT NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
