-- Rollback auto-resolution fields
-- SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
-- For simplicity, we'll just document this; in production, use a full table recreation

-- Note: This is a one-way migration for SQLite.
-- The columns will remain but can be ignored if rolled back.
-- In a production environment with PostgreSQL, use:
-- ALTER TABLE escrows DROP COLUMN auto_escalated_at;
-- ALTER TABLE escrows DROP COLUMN escalation_reason;
