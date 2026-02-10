-- Rollback: Drop reviews table and all indexes

DROP INDEX IF EXISTS idx_reviews_reviewer_txid;
DROP INDEX IF EXISTS idx_reviews_vendor_verified;
DROP INDEX IF EXISTS idx_reviews_rating;
DROP INDEX IF EXISTS idx_reviews_timestamp;
DROP INDEX IF EXISTS idx_reviews_verified;
DROP INDEX IF EXISTS idx_reviews_txid;
DROP INDEX IF EXISTS idx_reviews_vendor;
DROP TABLE IF EXISTS reviews;
