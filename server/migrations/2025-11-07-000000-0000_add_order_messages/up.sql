-- Add order_messages table for vendor-buyer communication
CREATE TABLE order_messages (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for fast order message lookups
CREATE INDEX idx_order_messages_order_id ON order_messages(order_id);
CREATE INDEX idx_order_messages_created_at ON order_messages(created_at ASC);
CREATE INDEX idx_order_messages_sender_id ON order_messages(sender_id);
