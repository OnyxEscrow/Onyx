-- Add MuSig2 nonce aggregation fields for v0.9.0
ALTER TABLE escrows ADD COLUMN vendor_nonce_commitment TEXT;
ALTER TABLE escrows ADD COLUMN buyer_nonce_commitment TEXT;
ALTER TABLE escrows ADD COLUMN vendor_nonce_public TEXT;  -- JSON: {r_public: "...", r_prime_public: "..."}
ALTER TABLE escrows ADD COLUMN buyer_nonce_public TEXT;   -- JSON: {r_public: "...", r_prime_public: "..."}
ALTER TABLE escrows ADD COLUMN nonce_aggregated TEXT;     -- JSON: {r_agg: "...", r_prime_agg: "..."}
