-- Migration: Add dispute_evidence table for IPFS-based evidence storage
-- Table and columns already exist - making migration idempotent
CREATE TABLE IF NOT EXISTS dispute_evidence (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL REFERENCES escrows(id) ON DELETE CASCADE,
    uploader_id TEXT NOT NULL,
    uploader_role TEXT NOT NULL CHECK(uploader_role IN ('buyer', 'vendor', 'arbiter')),
    ipfs_cid TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL CHECK(file_size > 0 AND file_size <= 5242880),
    mime_type TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_evidence_escrow_id ON dispute_evidence(escrow_id);
CREATE INDEX IF NOT EXISTS idx_evidence_uploader_id ON dispute_evidence(uploader_id);
