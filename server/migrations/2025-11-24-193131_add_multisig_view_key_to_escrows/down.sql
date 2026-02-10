-- Revert multisig_view_key column
-- SQLite doesn't support DROP COLUMN directly, need to recreate table
-- For simplicity in development, we create a new table without the column

-- Create temporary table without the column
CREATE TABLE escrows_backup AS SELECT
    id, order_id, buyer_id, vendor_id, arbiter_id,
    multisig_address, status, amount, currency,
    created_at, updated_at, transaction_hash,
    timeout_at, timeout_extension_count, dispute_reason,
    buyer_multisig_info, vendor_multisig_info, arbiter_multisig_info,
    buyer_ready, vendor_ready, arbiter_ready,
    buyer_temp_wallet_id, vendor_temp_wallet_id, arbiter_temp_wallet_id,
    buyer_wallet_info, vendor_wallet_info, arbiter_wallet_info,
    buyer_payout_address, vendor_payout_address
FROM escrows;

DROP TABLE escrows;

ALTER TABLE escrows_backup RENAME TO escrows;
