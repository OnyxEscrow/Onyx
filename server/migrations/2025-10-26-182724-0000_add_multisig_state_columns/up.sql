-- Add multisig state persistence columns to escrows table
-- Enables crash recovery and state reconstruction

-- Phase column: Current state of multisig setup
-- Values: 'not_started', 'preparing', 'exchanging', 'ready', 'failed'
ALTER TABLE escrows ADD COLUMN multisig_phase TEXT NOT NULL DEFAULT 'not_started';

-- State JSON: Full snapshot for recovery (encrypted participant info, round data, etc.)
-- Format: JSON with {phase: {...}, wallet_ids: {...}, rpc_urls: {...}}
ALTER TABLE escrows ADD COLUMN multisig_state_json TEXT;

-- Timestamp of last state update (for stuck escrow detection)
ALTER TABLE escrows ADD COLUMN multisig_updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'));

-- Performance indexes
CREATE INDEX idx_escrows_multisig_phase ON escrows(multisig_phase) WHERE multisig_phase != 'ready';
CREATE INDEX idx_escrows_multisig_updated ON escrows(multisig_updated_at);

-- Composite index for recovery queries (find active escrows needing recovery)
CREATE INDEX idx_escrows_active_multisig ON escrows(status, multisig_phase)
WHERE status IN ('created', 'funded', 'releasing', 'refunding')
AND multisig_phase NOT IN ('ready', 'failed');

-- Trigger to auto-update multisig_updated_at on phase change
CREATE TRIGGER update_multisig_timestamp
AFTER UPDATE OF multisig_phase, multisig_state_json ON escrows
FOR EACH ROW
BEGIN
    UPDATE escrows SET multisig_updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;
