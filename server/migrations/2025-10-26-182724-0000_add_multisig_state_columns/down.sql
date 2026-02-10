-- Rollback multisig state persistence

-- Drop trigger first
DROP TRIGGER IF EXISTS update_multisig_timestamp;

-- Drop indexes
DROP INDEX IF EXISTS idx_escrows_active_multisig;
DROP INDEX IF EXISTS idx_escrows_multisig_updated;
DROP INDEX IF EXISTS idx_escrows_multisig_phase;

-- Remove columns (SQLite requires recreation of table for column removal in older versions)
-- For SQLite 3.35+, we can use DROP COLUMN directly
-- ALTER TABLE escrows DROP COLUMN multisig_updated_at;
-- ALTER TABLE escrows DROP COLUMN multisig_state_json;
-- ALTER TABLE escrows DROP COLUMN multisig_phase;

-- For compatibility with older SQLite, use table recreation:
CREATE TABLE escrows_backup AS SELECT
    id, order_id, buyer_id, vendor_id, arbiter_id, amount,
    multisig_address, status, created_at, updated_at,
    buyer_wallet_info, vendor_wallet_info, arbiter_wallet_info,
    transaction_hash, expires_at, last_activity_at
FROM escrows;

DROP TABLE escrows;

CREATE TABLE escrows (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL,
    buyer_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    arbiter_id TEXT NOT NULL,
    amount BIGINT NOT NULL CHECK (amount > 0),
    multisig_address TEXT,
    status TEXT NOT NULL DEFAULT 'init',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    buyer_wallet_info BLOB,
    vendor_wallet_info BLOB,
    arbiter_wallet_info BLOB,
    transaction_hash TEXT,
    expires_at TIMESTAMP,
    last_activity_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);

INSERT INTO escrows SELECT * FROM escrows_backup;
DROP TABLE escrows_backup;

-- Recreate original indexes
CREATE INDEX idx_escrows_order ON escrows(order_id);
CREATE INDEX idx_escrows_buyer ON escrows(buyer_id);
CREATE INDEX idx_escrows_vendor ON escrows(vendor_id);
CREATE INDEX idx_escrows_arbiter ON escrows(arbiter_id);
