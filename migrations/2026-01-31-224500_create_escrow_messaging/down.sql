-- Rollback escrow messaging tables

-- Drop escrow message read receipts
DROP INDEX IF EXISTS idx_escrow_read_receipts_user;
DROP INDEX IF EXISTS idx_escrow_read_receipts_message;
DROP TABLE IF EXISTS escrow_message_read_receipts;

-- Drop escrow message keypairs
DROP INDEX IF EXISTS idx_escrow_message_keypairs_user;
DROP INDEX IF EXISTS idx_escrow_message_keypairs_escrow;
DROP TABLE IF EXISTS escrow_message_keypairs;

-- Drop escrow messages
DROP INDEX IF EXISTS idx_escrow_messages_created;
DROP INDEX IF EXISTS idx_escrow_messages_sender;
DROP INDEX IF EXISTS idx_escrow_messages_escrow;
DROP TABLE IF EXISTS escrow_messages;

-- Drop message read receipts
DROP TABLE IF EXISTS message_read_receipts;

-- Drop secure messages
DROP INDEX IF EXISTS idx_secure_messages_expires;
DROP INDEX IF EXISTS idx_secure_messages_created;
DROP INDEX IF EXISTS idx_secure_messages_recipient;
DROP INDEX IF EXISTS idx_secure_messages_sender;
DROP INDEX IF EXISTS idx_secure_messages_conversation;
DROP TABLE IF EXISTS secure_messages;

-- Drop message keypairs
DROP INDEX IF EXISTS idx_message_keypairs_user_active;
DROP INDEX IF EXISTS idx_message_keypairs_user;
DROP TABLE IF EXISTS message_keypairs;
