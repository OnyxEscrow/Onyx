-- Rollback: remove shipping_cost_xmr from listings
ALTER TABLE listings DROP COLUMN shipping_cost_xmr;
