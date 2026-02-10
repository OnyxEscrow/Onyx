-- Create messages table
CREATE TABLE messages (
    id TEXT PRIMARY KEY NOT NULL,
    escrow_id TEXT NOT NULL REFERENCES escrows(id) ON DELETE CASCADE,
    sender_id TEXT NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN NOT NULL DEFAULT 0
);

CREATE INDEX idx_messages_escrow_id ON messages(escrow_id);
CREATE INDEX idx_messages_created_at ON messages(created_at);

-- Add dispute fields to escrows table
ALTER TABLE escrows ADD COLUMN dispute_reason TEXT;
ALTER TABLE escrows ADD COLUMN dispute_created_at TIMESTAMP;
ALTER TABLE escrows ADD COLUMN dispute_resolved_at TIMESTAMP;
ALTER TABLE escrows ADD COLUMN resolution_decision TEXT;
