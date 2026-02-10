CREATE TABLE marketplace_clients (
    id TEXT PRIMARY KEY NOT NULL,
    api_key_user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT,
    fee_bps INTEGER NOT NULL DEFAULT 150,
    webhook_url TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (api_key_user_id) REFERENCES users(id)
);

CREATE INDEX idx_marketplace_clients_api_key_user_id ON marketplace_clients(api_key_user_id);

CREATE TABLE fee_ledger (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    client_id TEXT,
    fee_type TEXT NOT NULL,
    amount_atomic BIGINT NOT NULL,
    tx_hash TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (escrow_id) REFERENCES escrows(id)
);

CREATE INDEX idx_fee_ledger_escrow_id ON fee_ledger(escrow_id);
CREATE INDEX idx_fee_ledger_client_id ON fee_ledger(client_id);
