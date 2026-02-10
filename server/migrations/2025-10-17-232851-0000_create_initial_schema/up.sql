-- Schéma SQL corrigé pour la compatibilité avec SQLite

CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('buyer', 'vendor', 'arbiter', 'admin')),
    wallet_address TEXT,
    wallet_id TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE listings (
    id TEXT PRIMARY KEY NOT NULL,
    vendor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    price_xmr BIGINT NOT NULL CHECK (price_xmr > 0),
    stock INT NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    images_ipfs_cids TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id TEXT PRIMARY KEY NOT NULL,
    buyer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vendor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    listing_id TEXT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
    escrow_id TEXT UNIQUE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_xmr BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE escrows (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    buyer_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    vendor_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    arbiter_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    amount BIGINT NOT NULL CHECK (amount > 0),
    multisig_address VARCHAR(95),
    status VARCHAR(50) NOT NULL DEFAULT 'init',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    buyer_wallet_info BLOB, -- ENCRYPTED multisig info
    vendor_wallet_info BLOB, -- ENCRYPTED multisig info
    arbiter_wallet_info BLOB -- ENCRYPTED multisig info
);

CREATE TABLE transactions (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL REFERENCES escrows(id) ON DELETE CASCADE,
    tx_hash VARCHAR(64) UNIQUE,
    amount_xmr BIGINT NOT NULL,
    confirmations INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_listings_vendor ON listings(vendor_id);
CREATE INDEX idx_orders_buyer ON orders(buyer_id);
CREATE INDEX idx_orders_vendor ON orders(vendor_id);
CREATE INDEX idx_escrows_order ON escrows(order_id);
CREATE INDEX idx_escrows_buyer ON escrows(buyer_id);
CREATE INDEX idx_escrows_vendor ON escrows(vendor_id);
CREATE INDEX idx_escrows_arbiter ON escrows(arbiter_id);
CREATE INDEX idx_transactions_escrow ON transactions(escrow_id);
