-- Add timeout tracking fields to escrows table
--
-- These fields enable the TimeoutMonitor service to detect and handle
-- stuck escrows that exceed configured time limits for their status.

-- expires_at: Deadline for current escrow status
-- Calculated as: last_activity_at + timeout_for_status(status)
-- NULL for terminal states (completed, refunded, cancelled, expired)
ALTER TABLE escrows ADD COLUMN expires_at TIMESTAMP;

-- last_activity_at: Timestamp of last state transition or significant action
-- Updated on: status changes, multisig setup steps, fund deposits, disputes
-- Initialized to created_at for existing rows
ALTER TABLE escrows ADD COLUMN last_activity_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Create index for efficient timeout queries
-- TimeoutMonitor polls: SELECT * FROM escrows WHERE status IN (...) AND expires_at < NOW()
CREATE INDEX idx_escrows_timeout ON escrows(status, expires_at) WHERE expires_at IS NOT NULL;

-- Initialize last_activity_at for existing escrows to their created_at timestamp
UPDATE escrows SET last_activity_at = created_at WHERE last_activity_at IS NULL;

-- Set initial expires_at based on current status (using default timeouts)
-- created: 1 hour from last_activity
-- funded: 24 hours from last_activity
-- releasing/refunding: 6 hours from last_activity
-- disputed: 7 days from last_activity
-- completed/refunded/cancelled/expired: NULL (no expiration)
UPDATE escrows
SET expires_at = CASE
    WHEN status = 'created' THEN datetime(last_activity_at, '+1 hour')
    WHEN status = 'funded' THEN datetime(last_activity_at, '+24 hours')
    WHEN status IN ('releasing', 'refunding') THEN datetime(last_activity_at, '+6 hours')
    WHEN status = 'disputed' THEN datetime(last_activity_at, '+7 days')
    WHEN status IN ('completed', 'refunded', 'cancelled', 'expired') THEN NULL
    ELSE datetime(last_activity_at, '+1 hour')  -- Fallback for unknown states
END
WHERE expires_at IS NULL;
