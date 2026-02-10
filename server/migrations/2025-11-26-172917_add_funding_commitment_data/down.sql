-- Revert the funding commitment data columns
-- Note: SQLite doesn't support DROP COLUMN directly in older versions
-- For SQLite 3.35.0+, we can use ALTER TABLE ... DROP COLUMN

-- Create a new table without the columns
CREATE TABLE escrows_backup AS SELECT
    id,
    order_id,
    buyer_user_id,
    seller_user_id,
    arbiter_user_id,
    amount_xmr,
    status,
    escrow_address,
    buyer_multisig_info,
    seller_multisig_info,
    arbiter_multisig_info,
    multisig_wallet_data,
    created_at,
    updated_at,
    buyer_view_key,
    seller_view_key,
    arbiter_view_key,
    buyer_spend_key,
    seller_spend_key,
    arbiter_spend_key,
    buyer_signed,
    seller_signed,
    arbiter_signed,
    release_tx_hex,
    release_tx_hash,
    buyer_payout_address,
    seller_payout_address
FROM escrows;

-- Drop the original table
DROP TABLE escrows;

-- Rename backup to original name
ALTER TABLE escrows_backup RENAME TO escrows;
