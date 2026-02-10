-- Add shipping information to orders table
-- shipping_address: Encrypted address where the product should be shipped
-- shipping_notes: Optional encrypted notes from buyer (e.g., "Ring doorbell", "Leave with neighbor")

ALTER TABLE orders ADD COLUMN shipping_address TEXT;
ALTER TABLE orders ADD COLUMN shipping_notes TEXT;
