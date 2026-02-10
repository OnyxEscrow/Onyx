-- Rollback dashboard indexes
DROP INDEX IF EXISTS idx_escrows_external_ref;
DROP INDEX IF EXISTS idx_escrows_status_updated;
DROP INDEX IF EXISTS idx_escrows_created_at;
DROP INDEX IF EXISTS idx_escrows_arbiter_status;
DROP INDEX IF EXISTS idx_escrows_vendor_status;
DROP INDEX IF EXISTS idx_escrows_buyer_status;
