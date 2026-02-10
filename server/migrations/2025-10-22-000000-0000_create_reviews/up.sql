-- Reviews table for cryptographically-signed vendor reputation system
-- Each review is a verifiable proof signed with buyer's ed25519 key

CREATE TABLE reviews (
    id TEXT PRIMARY KEY NOT NULL,
    txid TEXT NOT NULL,
    reviewer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vendor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    buyer_pubkey TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure one review per transaction
    UNIQUE(txid, reviewer_id)
);

-- Performance indexes for common queries
CREATE INDEX idx_reviews_vendor ON reviews(vendor_id);
CREATE INDEX idx_reviews_txid ON reviews(txid);
CREATE INDEX idx_reviews_verified ON reviews(verified);
CREATE INDEX idx_reviews_timestamp ON reviews(timestamp DESC);
CREATE INDEX idx_reviews_rating ON reviews(rating);

-- Composite index for most common query: "get verified reviews for vendor"
CREATE INDEX idx_reviews_vendor_verified ON reviews(vendor_id, verified) WHERE verified = 1;

-- Index for detecting duplicate reviews
CREATE INDEX idx_reviews_reviewer_txid ON reviews(reviewer_id, txid);
