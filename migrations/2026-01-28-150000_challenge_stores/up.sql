-- BE-001: ChallengeStore migration - multisig_challenges table
-- BE-002: WasmMultisigStore migration - wasm_multisig_infos table

-- Table for storing multisig challenge-response authentication
CREATE TABLE multisig_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    escrow_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    UNIQUE(user_id, escrow_id)
);

-- Index for efficient expired challenge cleanup
CREATE INDEX idx_multisig_challenges_expires ON multisig_challenges(expires_at);

-- Table for WASM multisig info exchange during setup
CREATE TABLE wasm_multisig_infos (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('buyer', 'vendor', 'arbiter')),
    multisig_info TEXT NOT NULL,
    view_key_component TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE(escrow_id, role)
);

-- Index for efficient escrow lookups
CREATE INDEX idx_wasm_multisig_infos_escrow ON wasm_multisig_infos(escrow_id);
