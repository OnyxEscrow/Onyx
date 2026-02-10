-- Phase 6: Track which user has which role in each escrow
-- Enables deterministic wallet derivation per (user, escrow, role)

CREATE TABLE user_escrow_roles (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    escrow_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('buyer', 'seller', 'arbiter')),
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE,

    -- Ensure one user can only have one role per escrow
    UNIQUE(user_id, escrow_id, role)
);

-- Indexes for fast lookups
CREATE INDEX idx_user_escrow_roles_user ON user_escrow_roles(user_id);
CREATE INDEX idx_user_escrow_roles_escrow ON user_escrow_roles(escrow_id);
CREATE INDEX idx_user_escrow_roles_role ON user_escrow_roles(role);
