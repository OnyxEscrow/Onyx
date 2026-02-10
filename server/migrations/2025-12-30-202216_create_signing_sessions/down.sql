-- Rollback: Drop signing_sessions table and all indexes
DROP INDEX IF EXISTS idx_signing_sessions_active_escrow;
DROP INDEX IF EXISTS idx_signing_sessions_status;
DROP INDEX IF EXISTS idx_signing_sessions_expires_at;
DROP INDEX IF EXISTS idx_signing_sessions_escrow_id;
DROP TABLE IF EXISTS signing_sessions;
