-- Rollback: Remove shipping information from orders table

-- SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
-- This is the safe way to remove columns in SQLite

-- Create new table without shipping columns
CREATE TABLE orders_new (
    id TEXT PRIMARY KEY NOT NULL,
    buyer_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    listing_id TEXT NOT NULL,
    escrow_id TEXT,
    status TEXT NOT NULL,
    total_xmr BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Copy data from old table (excluding shipping columns)
INSERT INTO orders_new (id, buyer_id, vendor_id, listing_id, escrow_id, status, total_xmr, created_at, updated_at)
SELECT id, buyer_id, vendor_id, listing_id, escrow_id, status, total_xmr, created_at, updated_at
FROM orders;

-- Drop old table
DROP TABLE orders;

-- Rename new table to orders
ALTER TABLE orders_new RENAME TO orders;
