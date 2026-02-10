-- Rollback: Remove dispute_evidence table

-- Remove evidence_count from escrows (SQLite 3.35+)
ALTER TABLE escrows DROP COLUMN evidence_count;

-- Drop indexes
DROP INDEX IF EXISTS idx_evidence_uploader_id;
DROP INDEX IF EXISTS idx_evidence_escrow_id;

-- Drop the evidence table
DROP TABLE IF EXISTS dispute_evidence;
