use crate::crypto::encryption::{decrypt_field, encrypt_field};
use crate::models::escrow_message::{EscrowMessage, NewEscrowMessage};
use anyhow::{bail, Context, Result};
use diesel::SqliteConnection;
use std::env;
use uuid::Uuid;

/// Messaging service with server-side encryption
/// Uses DB_ENCRYPTION_KEY for message encryption
pub struct MessagingService {
    encryption_key: Vec<u8>,
}

impl MessagingService {
    /// Create new messaging service with encryption
    pub fn new() -> Result<Self> {
        let key_hex = env::var("DB_ENCRYPTION_KEY")
            .context("DB_ENCRYPTION_KEY not set - required for message encryption")?;

        let encryption_key =
            hex::decode(&key_hex).context("Failed to decode DB_ENCRYPTION_KEY from hex")?;

        if encryption_key.len() != 32 {
            bail!(
                "DB_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got {} bytes",
                encryption_key.len()
            );
        }

        Ok(Self { encryption_key })
    }

    /// Send encrypted message to escrow chat
    pub fn send_message(
        &self,
        conn: &mut SqliteConnection,
        escrow_id: &str,
        sender_id: &str,
        plaintext_content: &str,
    ) -> Result<EscrowMessage> {
        // Encrypt message content
        let encrypted_bytes = encrypt_field(plaintext_content, &self.encryption_key)
            .context("Failed to encrypt message content")?;

        // Convert to base64 for storage
        let encrypted_content = base64::encode(&encrypted_bytes);

        let new_message = NewEscrowMessage {
            id: Uuid::new_v4().to_string(),
            escrow_id: escrow_id.to_string(),
            sender_id: sender_id.to_string(),
            content: encrypted_content,
            is_read: false,
        };

        EscrowMessage::create(conn, new_message).context("Failed to insert message into database")
    }

    /// Get all messages for an escrow (decrypted)
    pub fn get_messages(
        &self,
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<Vec<DecryptedMessage>> {
        let encrypted_messages = EscrowMessage::find_by_escrow(conn, escrow_id)
            .context("Failed to fetch messages from database")?;

        let mut decrypted_messages = Vec::new();

        for msg in encrypted_messages {
            // Decode from base64
            let encrypted_bytes =
                base64::decode(&msg.content).context("Failed to decode message from base64")?;

            // Decrypt
            let plaintext = decrypt_field(&encrypted_bytes, &self.encryption_key)
                .context("Failed to decrypt message content")?;

            decrypted_messages.push(DecryptedMessage {
                id: msg.id,
                escrow_id: msg.escrow_id,
                sender_id: msg.sender_id,
                content: plaintext,
                created_at: msg.created_at,
                is_read: msg.is_read,
            });
        }

        Ok(decrypted_messages)
    }

    /// Get unread message count
    pub fn count_unread(&self, conn: &mut SqliteConnection, escrow_id: &str) -> Result<i64> {
        EscrowMessage::count_unread(conn, escrow_id).context("Failed to count unread messages")
    }

    /// Mark message as read
    pub fn mark_as_read(&self, conn: &mut SqliteConnection, message_id: &str) -> Result<()> {
        EscrowMessage::mark_as_read(conn, message_id).context("Failed to mark message as read")?;
        Ok(())
    }

    /// Mark all messages as read except sender's own
    pub fn mark_all_as_read_except_sender(
        &self,
        conn: &mut SqliteConnection,
        escrow_id: &str,
        sender_id: &str,
    ) -> Result<()> {
        EscrowMessage::mark_all_as_read_except_sender(conn, escrow_id, sender_id)
            .context("Failed to mark messages as read")?;
        Ok(())
    }
}

/// Decrypted message for API responses
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecryptedMessage {
    pub id: String,
    pub escrow_id: String,
    pub sender_id: String,
    pub content: String,
    pub created_at: chrono::NaiveDateTime,
    pub is_read: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Fix database connection for tests
    // #[test]
    /*
    fn test_encrypt_decrypt_message() {
        let service = MessagingService::new().unwrap();
        let mut conn = establish_connection();
        let escrow_id = format!("test_escrow_{}", Uuid::new_v4());
        let plaintext = "This is a secret message";

        // Send message
        let msg = service
            .send_message(&mut conn, &escrow_id, "sender123", plaintext)
            .unwrap();

        // Verify content is encrypted in DB
        assert_ne!(msg.content, plaintext);
        assert!(msg.content.len() > plaintext.len()); // Encrypted is longer

        // Retrieve and decrypt
        let messages = service.get_messages(&mut conn, &escrow_id).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, plaintext);
    }

    // #[test]
    fn test_unread_count() {
        let service = MessagingService::new().unwrap();
        // let mut conn = establish_connection();
        let escrow_id = format!("escrow_{}", Uuid::new_v4());

        // service
        //     .send_message(&mut conn, &escrow_id, "sender1", "msg1")
        //     .unwrap();
        // service
        //     .send_message(&mut conn, &escrow_id, "sender2", "msg2")
        //     .unwrap();

        // let unread = service.count_unread(&mut conn, &escrow_id).unwrap();
        // assert_eq!(unread, 2);
    }
    */
}
