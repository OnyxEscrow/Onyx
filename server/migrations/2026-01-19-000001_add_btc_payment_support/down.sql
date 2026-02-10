-- Rollback: Remove BTC Payment Support

-- Drop indexes first
DROP INDEX IF EXISTS idx_orders_payment_method;
DROP INDEX IF EXISTS idx_swap_orders_btc_address;
DROP INDEX IF EXISTS idx_swap_orders_provider;
DROP INDEX IF EXISTS idx_swap_orders_status;
DROP INDEX IF EXISTS idx_swap_orders_order_id;

-- SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
-- First, create a temp table with the original schema
CREATE TABLE orders_backup AS SELECT
    id, buyer_id, vendor_id, listing_id, escrow_id, status,
    total_xmr, created_at, updated_at, shipping_address, shipping_notes
FROM orders;

-- Drop original table
DROP TABLE orders;

-- Recreate original table
CREATE TABLE orders (
    id TEXT PRIMARY KEY NOT NULL,
    buyer_id TEXT NOT NULL REFERENCES users(id),
    vendor_id TEXT NOT NULL REFERENCES users(id),
    listing_id TEXT NOT NULL REFERENCES listings(id),
    escrow_id TEXT REFERENCES escrows(id),
    status TEXT NOT NULL DEFAULT 'pending',
    total_xmr BIGINT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    shipping_address TEXT,
    shipping_notes TEXT
);

-- Restore data
INSERT INTO orders SELECT * FROM orders_backup;

-- Drop backup
DROP TABLE orders_backup;

-- Drop swap_orders table
DROP TABLE IF EXISTS swap_orders;
