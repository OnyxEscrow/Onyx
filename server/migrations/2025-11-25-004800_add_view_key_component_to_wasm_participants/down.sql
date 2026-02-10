-- Rollback: Remove view_key_component column from wasm_multisig_participants

ALTER TABLE wasm_multisig_participants
DROP COLUMN view_key_component;
