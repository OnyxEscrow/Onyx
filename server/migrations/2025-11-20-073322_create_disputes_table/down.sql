-- Drop messages table
DROP TABLE IF EXISTS messages;

-- Remove dispute fields from escrows
ALTER TABLE escrows DROP COLUMN dispute_reason;
ALTER TABLE escrows DROP COLUMN dispute_created_at;
ALTER TABLE escrows DROP COLUMN dispute_resolved_at;
ALTER TABLE escrows DROP COLUMN resolution_decision;
