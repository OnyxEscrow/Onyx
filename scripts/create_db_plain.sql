-- NEXUS Database Schema - Plain Text Creation
-- Generated from schema.rs for SQLCipher encryption

PRAGMA foreign_keys = ON;

-- 1. api_keys
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    tier TEXT NOT NULL,
    rate_limit_override INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    total_requests INTEGER NOT NULL DEFAULT 0,
    metadata TEXT
);

-- 2. dispute_evidence
CREATE TABLE IF NOT EXISTS dispute_evidence (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    uploader_id TEXT NOT NULL,
    uploader_role TEXT NOT NULL,
    ipfs_cid TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 3. encrypted_relay
CREATE TABLE IF NOT EXISTS encrypted_relay (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    encrypted_blob TEXT NOT NULL,
    first_signer_role TEXT NOT NULL,
    first_signer_pubkey TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
);

-- 4. escrows (86 columns matching schema.rs)
CREATE TABLE IF NOT EXISTS escrows (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL DEFAULT '',
    buyer_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    arbiter_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    multisig_address TEXT,
    status TEXT NOT NULL DEFAULT 'awaiting_wallet_info',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    buyer_wallet_info BLOB,
    vendor_wallet_info BLOB,
    arbiter_wallet_info BLOB,
    transaction_hash TEXT,
    expires_at TEXT,
    last_activity_at TEXT NOT NULL DEFAULT (datetime('now')),
    multisig_phase TEXT NOT NULL DEFAULT 'not_started',
    multisig_state_json TEXT,
    multisig_updated_at INTEGER NOT NULL DEFAULT 0,
    recovery_mode TEXT NOT NULL DEFAULT 'none',
    buyer_temp_wallet_id TEXT,
    vendor_temp_wallet_id TEXT,
    arbiter_temp_wallet_id TEXT,
    dispute_reason TEXT,
    dispute_created_at TEXT,
    dispute_resolved_at TEXT,
    resolution_decision TEXT,
    vendor_signature TEXT,
    buyer_signature TEXT,
    unsigned_tx_hex TEXT,
    vendor_signed_at INTEGER,
    buyer_signed_at INTEGER,
    vendor_payout_address TEXT,
    buyer_refund_address TEXT,
    vendor_payout_set_at INTEGER,
    buyer_refund_set_at INTEGER,
    multisig_view_key TEXT,
    funding_commitment_mask TEXT,
    funding_tx_hash TEXT,
    funding_output_index INTEGER,
    funding_global_index INTEGER,
    ring_data_json TEXT,
    buyer_partial_key_image TEXT,
    vendor_partial_key_image TEXT,
    arbiter_partial_key_image TEXT,
    aggregated_key_image TEXT,
    partial_tx TEXT,
    partial_tx_initiator TEXT,
    completed_clsag TEXT,
    signing_started_at INTEGER,
    signing_phase TEXT,
    funding_output_pubkey TEXT,
    funding_tx_pubkey TEXT,
    vendor_nonce_commitment TEXT,
    buyer_nonce_commitment TEXT,
    vendor_nonce_public TEXT,
    buyer_nonce_public TEXT,
    nonce_aggregated TEXT,
    first_signer_role TEXT,
    mu_p TEXT,
    mu_c TEXT,
    first_signer_had_r_agg INTEGER,
    multisig_txset TEXT,
    signing_round INTEGER,
    current_signer_id TEXT,
    partial_signed_txset TEXT,
    signing_initiated_at TEXT,
    broadcast_tx_hash TEXT,
    frost_enabled INTEGER NOT NULL DEFAULT 0,
    frost_group_pubkey TEXT,
    frost_dkg_complete INTEGER NOT NULL DEFAULT 0,
    evidence_count INTEGER,
    auto_escalated_at TEXT,
    escalation_reason TEXT,
    dispute_signing_pair TEXT,
    balance_received INTEGER NOT NULL DEFAULT 0,
    grace_period_ends_at TEXT,
    refund_requested_at TEXT,
    external_reference TEXT,
    description TEXT,
    buyer_release_requested INTEGER NOT NULL DEFAULT 0,
    vendor_refund_requested INTEGER NOT NULL DEFAULT 0,
    arbiter_auto_signed INTEGER NOT NULL DEFAULT 0,
    arbiter_auto_signed_at TEXT,
    escalated_to_human INTEGER NOT NULL DEFAULT 0,
    arbiter_frost_partial_sig TEXT
);

-- 5. frost_dkg_state
CREATE TABLE IF NOT EXISTS frost_dkg_state (
    escrow_id TEXT PRIMARY KEY NOT NULL,
    buyer_round1_package TEXT,
    vendor_round1_package TEXT,
    arbiter_round1_package TEXT,
    round1_complete INTEGER NOT NULL DEFAULT 0,
    buyer_to_vendor_round2 TEXT,
    buyer_to_arbiter_round2 TEXT,
    vendor_to_buyer_round2 TEXT,
    vendor_to_arbiter_round2 TEXT,
    arbiter_to_buyer_round2 TEXT,
    arbiter_to_vendor_round2 TEXT,
    round2_complete INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 6. login_attempts
CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT,
    attempt_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 7. multisig_challenges
CREATE TABLE IF NOT EXISTS multisig_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    escrow_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- 8. message_keypairs
CREATE TABLE IF NOT EXISTS message_keypairs (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    key_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

-- 9. message_read_receipts
CREATE TABLE IF NOT EXISTS message_read_receipts (
    message_id TEXT PRIMARY KEY NOT NULL,
    read_at TEXT NOT NULL
);

-- 10. messages
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    is_read INTEGER NOT NULL DEFAULT 0
);

-- 11. multisig_participants
CREATE TABLE IF NOT EXISTS multisig_participants (
    id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    participant_type TEXT NOT NULL,
    wallet_id TEXT,
    user_id TEXT,
    has_submitted_round1 INTEGER NOT NULL DEFAULT 0,
    has_submitted_round2 INTEGER NOT NULL DEFAULT 0,
    public_spend_key TEXT,
    multisig_info_round1 TEXT,
    multisig_info_round2 TEXT,
    submitted_at_round1 INTEGER,
    submitted_at_round2 INTEGER
);

-- 12. multisig_sessions
CREATE TABLE IF NOT EXISTS multisig_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    timeout_at INTEGER,
    multisig_address TEXT
);

-- 13. notifications
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    data TEXT,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 14. recovery_codes
CREATE TABLE IF NOT EXISTS recovery_codes (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 15. secure_messages
CREATE TABLE IF NOT EXISTS secure_messages (
    id TEXT PRIMARY KEY NOT NULL,
    conversation_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    nonce TEXT NOT NULL,
    sender_ephemeral_pubkey TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    is_deleted_by_sender INTEGER NOT NULL DEFAULT 0,
    is_deleted_by_recipient INTEGER NOT NULL DEFAULT 0
);

-- 16. signing_sessions
CREATE TABLE IF NOT EXISTS signing_sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    tx_secret_key_encrypted TEXT NOT NULL,
    tx_pubkey TEXT NOT NULL,
    derivation TEXT NOT NULL,
    output_mask TEXT NOT NULL,
    pseudo_out_mask TEXT NOT NULL,
    mask_delta TEXT NOT NULL,
    ring_data_json TEXT NOT NULL,
    real_ring_index INTEGER NOT NULL,
    expected_one_time_pubkey TEXT NOT NULL,
    expected_key_image TEXT NOT NULL,
    tx_prefix_hash TEXT NOT NULL,
    clsag_message TEXT NOT NULL,
    bulletproof_plus_json TEXT NOT NULL,
    dest_spend_pubkey TEXT NOT NULL,
    dest_view_pubkey TEXT NOT NULL,
    funding_tx_hash TEXT NOT NULL,
    funding_output_index INTEGER NOT NULL,
    funding_amount INTEGER NOT NULL,
    output_commitment TEXT NOT NULL,
    pseudo_out TEXT NOT NULL,
    buyer_partial_sig TEXT,
    vendor_partial_sig TEXT,
    buyer_partial_ki TEXT,
    vendor_partial_ki TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    initiator_role TEXT NOT NULL
);

-- 17. transactions
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    tx_hash TEXT,
    amount_xmr INTEGER NOT NULL,
    confirmations INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 18. user_escrow_roles
CREATE TABLE IF NOT EXISTS user_escrow_roles (
    id TEXT,
    user_id TEXT NOT NULL,
    escrow_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- 19. users
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    wallet_address TEXT,
    wallet_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    encrypted_wallet_seed BLOB,
    wallet_seed_salt BLOB,
    bip39_backup_seed TEXT,
    seed_created_at INTEGER,
    seed_backup_acknowledged INTEGER
);

-- 20. wallet_address_history
CREATE TABLE IF NOT EXISTS wallet_address_history (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    old_address TEXT,
    new_address TEXT NOT NULL,
    changed_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);

-- 21. wallet_rpc_configs
CREATE TABLE IF NOT EXISTS wallet_rpc_configs (
    wallet_id TEXT,
    escrow_id TEXT NOT NULL,
    role TEXT NOT NULL,
    rpc_url_encrypted BLOB NOT NULL,
    rpc_user_encrypted BLOB,
    rpc_password_encrypted BLOB,
    created_at INTEGER NOT NULL,
    last_connected_at INTEGER,
    connection_attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

-- 22. wallets
CREATE TABLE IF NOT EXISTS wallets (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    address TEXT NOT NULL,
    address_hash TEXT NOT NULL,
    spend_key_pub TEXT NOT NULL,
    view_key_pub TEXT NOT NULL,
    signature TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    daily_limit_atomic INTEGER,
    monthly_limit_atomic INTEGER,
    last_withdrawal_date TEXT,
    withdrawn_today_atomic INTEGER
);

-- 23. wasm_multisig_infos
CREATE TABLE IF NOT EXISTS wasm_multisig_infos (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    role TEXT NOT NULL,
    multisig_info TEXT NOT NULL,
    view_key_component TEXT,
    created_at INTEGER NOT NULL
);

-- 24. webhook_deliveries
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY NOT NULL,
    webhook_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    http_status_code INTEGER,
    response_body TEXT,
    error_message TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT,
    created_at TEXT NOT NULL,
    delivered_at TEXT
);

-- 25. webhooks
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY NOT NULL,
    api_key_id TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_failure_reason TEXT,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Diesel migrations tracking table
CREATE TABLE IF NOT EXISTS __diesel_schema_migrations (
    version TEXT PRIMARY KEY NOT NULL,
    run_on TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Mark all migrations as applied
INSERT INTO __diesel_schema_migrations (version, run_on) VALUES
('2025-10-17-232851-0000', datetime('now')),
('2025-10-21-000000-0000', datetime('now')),
('2025-10-22-000000-0000', datetime('now')),
('2025-10-26-175351-0000', datetime('now')),
('2025-10-26-182724-0000', datetime('now')),
('2025-10-26-202554-0000', datetime('now')),
('2025-10-27-000000-0000', datetime('now')),
('2025-10-28-183959-0000', datetime('now')),
('2025-11-03-190356-0000', datetime('now')),
('2025-11-03-221723-0000', datetime('now')),
('2025-11-07-000000-0000', datetime('now')),
('2025-11-16-000001', datetime('now')),
('2025-11-18-225449', datetime('now')),
('2025-11-18-225521', datetime('now')),
('2025-11-20-073322', datetime('now')),
('2025-11-21-201741', datetime('now')),
('2025-11-21-214500', datetime('now')),
('2025-11-22-203351', datetime('now')),
('2025-11-23-081122', datetime('now')),
('2025-11-24-120512', datetime('now')),
('2025-11-24-193131', datetime('now')),
('2025-11-25-004800', datetime('now')),
('2025-11-26-172917', datetime('now')),
('2025-11-27-102301', datetime('now')),
('2025-11-27-223201', datetime('now')),
('2025-11-29-083342', datetime('now')),
('2025-12-05-165428', datetime('now')),
('2025-12-05-232351', datetime('now')),
('2025-12-09-191427', datetime('now')),
('2025-12-11-160745', datetime('now')),
('2025-12-21-080551', datetime('now')),
('2025-12-24-113425', datetime('now')),
('2025-12-24-201537', datetime('now')),
('2025-12-24-235228', datetime('now')),
('2025-12-30-202216', datetime('now')),
('2025-12-31-115338', datetime('now')),
('2026-01-05-064244', datetime('now')),
('2026-01-05-075026', datetime('now')),
('2026-01-05-092631', datetime('now')),
('2026-01-08-184325', datetime('now')),
('2026-01-13-110527', datetime('now')),
('2026-01-17-181205', datetime('now')),
('2026-01-18-070904', datetime('now')),
('2026-01-19-000001', datetime('now')),
('2026-01-20-210728', datetime('now')),
('2026-01-21-112110', datetime('now')),
('2026-01-21-134453', datetime('now')),
('2026-01-23-095105', datetime('now')),
('2026-01-27-000001', datetime('now')),
('2026-01-27-000002', datetime('now')),
('2026-01-28-100256', datetime('now')),
('2026-01-28-110000', datetime('now')),
('2026-01-29-234305', datetime('now')),
('2026-01-30-070000', datetime('now'));

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_escrows_status ON escrows(status);
CREATE INDEX IF NOT EXISTS idx_escrows_buyer_id ON escrows(buyer_id);
CREATE INDEX IF NOT EXISTS idx_escrows_vendor_id ON escrows(vendor_id);
CREATE INDEX IF NOT EXISTS idx_escrows_arbiter_id ON escrows(arbiter_id);
CREATE INDEX IF NOT EXISTS idx_escrows_expires_at ON escrows(expires_at);
CREATE INDEX IF NOT EXISTS idx_escrows_frost_enabled ON escrows(frost_enabled);
CREATE INDEX IF NOT EXISTS idx_messages_escrow_id ON messages(escrow_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_user_escrow_roles_user_id ON user_escrow_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_escrow_roles_escrow_id ON user_escrow_roles(escrow_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_api_key_id ON webhooks(api_key_id);

-- Done
SELECT 'Database schema created successfully with ' ||
       (SELECT COUNT(*) FROM sqlite_master WHERE type='table') || ' tables';
