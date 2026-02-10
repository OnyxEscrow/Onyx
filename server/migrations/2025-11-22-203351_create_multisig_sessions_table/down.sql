-- Rollback multisig coordination tables
DROP INDEX IF EXISTS idx_multisig_participants_user;
DROP INDEX IF EXISTS idx_multisig_participants_session;
DROP INDEX IF EXISTS idx_multisig_sessions_timeout;
DROP INDEX IF EXISTS idx_multisig_sessions_stage;
DROP INDEX IF EXISTS idx_multisig_sessions_escrow;

DROP TABLE IF EXISTS multisig_participants;
DROP TABLE IF EXISTS multisig_sessions;
