-- Rollback BE-001 and BE-002 migrations

DROP INDEX IF EXISTS idx_wasm_multisig_infos_escrow;
DROP TABLE IF EXISTS wasm_multisig_infos;

DROP INDEX IF EXISTS idx_multisig_challenges_expires;
DROP TABLE IF EXISTS multisig_challenges;
