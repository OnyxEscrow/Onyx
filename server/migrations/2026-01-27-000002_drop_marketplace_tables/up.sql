-- Drop marketplace tables (EaaS transformation)
-- These tables are no longer needed for pure escrow-as-a-service

-- Drop order_messages first (references orders)
DROP TABLE IF EXISTS order_messages;

-- Drop swap_orders (references orders)
DROP TABLE IF EXISTS swap_orders;

-- Drop reviews (references orders and listings)
DROP TABLE IF EXISTS reviews;

-- Drop orders (references listings)
DROP TABLE IF EXISTS orders;

-- Drop listings (standalone)
DROP TABLE IF EXISTS listings;

-- Drop supported_coins (swap feature)
DROP TABLE IF EXISTS supported_coins;
