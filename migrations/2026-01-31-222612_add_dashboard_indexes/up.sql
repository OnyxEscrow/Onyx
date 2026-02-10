-- Dashboard optimization indexes for escrow queries
-- Enables efficient filtering by user role + status

-- Index for buyer dashboard queries
CREATE INDEX IF NOT EXISTS idx_escrows_buyer_status
    ON escrows(buyer_id, status);

-- Index for vendor dashboard queries
CREATE INDEX IF NOT EXISTS idx_escrows_vendor_status
    ON escrows(vendor_id, status);

-- Index for arbiter dashboard queries
CREATE INDEX IF NOT EXISTS idx_escrows_arbiter_status
    ON escrows(arbiter_id, status);

-- Index for sorting by creation date (DESC for newest first)
CREATE INDEX IF NOT EXISTS idx_escrows_created_at
    ON escrows(created_at DESC);

-- Index for status + updated_at (for activity sorting)
CREATE INDEX IF NOT EXISTS idx_escrows_status_updated
    ON escrows(status, updated_at DESC);

-- Index for external reference lookups (EaaS B2B)
CREATE INDEX IF NOT EXISTS idx_escrows_external_ref
    ON escrows(external_reference) WHERE external_reference IS NOT NULL;
