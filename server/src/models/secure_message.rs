//! Secure E2E Encrypted Messaging Models
//!
//! Provides database models for end-to-end encrypted messaging between users.
//! All message content is encrypted client-side using X25519 ECDH + ChaCha20Poly1305.
//! The server only stores encrypted blobs and cannot decrypt message content.

use anyhow::{Context, Result};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::{message_keypairs, message_read_receipts, secure_messages};

// ============================================================================
// Message Keypair Models
// ============================================================================

/// User's messaging keypair for E2E encryption
/// Private key is encrypted client-side before storage
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = message_keypairs)]
pub struct MessageKeypair {
    pub id: String,
    pub user_id: String,
    pub public_key: String,            // X25519 public key (base64)
    pub encrypted_private_key: String, // Encrypted with password-derived key
    pub key_salt: String,              // Salt for key derivation (base64)
    pub created_at: String,
    pub is_active: i32,
}

/// New keypair for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = message_keypairs)]
pub struct NewMessageKeypair {
    pub id: String,
    pub user_id: String,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub key_salt: String,
    pub is_active: i32,
}

impl NewMessageKeypair {
    /// Create a new messaging keypair
    pub fn new(
        user_id: String,
        public_key: String,
        encrypted_private_key: String,
        key_salt: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            public_key,
            encrypted_private_key,
            key_salt,
            is_active: 1,
        }
    }
}

impl MessageKeypair {
    /// Get active keypair for a user
    pub fn get_active_for_user(
        user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Option<MessageKeypair>> {
        use crate::schema::message_keypairs::dsl;

        let keypair = dsl::message_keypairs
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::is_active.eq(1))
            .first::<MessageKeypair>(conn)
            .optional()
            .context("Failed to query keypair")?;

        Ok(keypair)
    }

    /// Get public key for a user (for encryption)
    pub fn get_public_key_for_user(
        user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Option<String>> {
        use crate::schema::message_keypairs::dsl;

        let pubkey = dsl::message_keypairs
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::is_active.eq(1))
            .select(dsl::public_key)
            .first::<String>(conn)
            .optional()
            .context("Failed to query public key")?;

        Ok(pubkey)
    }

    /// Create or replace keypair for user
    /// Deactivates any existing active keypair
    pub fn create_or_replace(
        new_keypair: NewMessageKeypair,
        conn: &mut SqliteConnection,
    ) -> Result<MessageKeypair> {
        use crate::schema::message_keypairs::dsl;

        // Deactivate existing active keypairs
        diesel::update(
            dsl::message_keypairs
                .filter(dsl::user_id.eq(&new_keypair.user_id))
                .filter(dsl::is_active.eq(1)),
        )
        .set(dsl::is_active.eq(0))
        .execute(conn)
        .context("Failed to deactivate old keypair")?;

        // Insert new keypair
        diesel::insert_into(dsl::message_keypairs)
            .values(&new_keypair)
            .execute(conn)
            .context("Failed to insert keypair")?;

        let keypair = dsl::message_keypairs
            .find(&new_keypair.id)
            .first::<MessageKeypair>(conn)
            .context("Failed to retrieve created keypair")?;

        Ok(keypair)
    }
}

// ============================================================================
// Secure Message Models
// ============================================================================

/// E2E encrypted message
/// Content is encrypted client-side - server cannot decrypt
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = secure_messages)]
pub struct SecureMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub encrypted_content: String, // ChaCha20Poly1305 ciphertext (base64)
    pub nonce: String,             // 12-byte nonce (base64)
    pub sender_ephemeral_pubkey: String, // X25519 ephemeral key for PFS
    pub created_at: String,
    pub expires_at: Option<String>,
    pub is_deleted_by_sender: i32,
    pub is_deleted_by_recipient: i32,
}

/// New message for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = secure_messages)]
pub struct NewSecureMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub encrypted_content: String,
    pub nonce: String,
    pub sender_ephemeral_pubkey: String,
    pub expires_at: Option<String>,
}

impl NewSecureMessage {
    /// Create a new encrypted message
    pub fn new(
        sender_id: String,
        recipient_id: String,
        encrypted_content: String,
        nonce: String,
        sender_ephemeral_pubkey: String,
        expires_at: Option<String>,
    ) -> Self {
        let conversation_id = Self::compute_conversation_id(&sender_id, &recipient_id);

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            conversation_id,
            sender_id,
            recipient_id,
            encrypted_content,
            nonce,
            sender_ephemeral_pubkey,
            expires_at,
        }
    }

    /// Compute deterministic conversation ID from two user IDs
    /// Uses SHA256(sorted(user1, user2)) for consistency
    pub fn compute_conversation_id(user1: &str, user2: &str) -> String {
        let mut ids = [user1, user2];
        ids.sort();

        let mut hasher = Sha256::new();
        hasher.update(ids[0].as_bytes());
        hasher.update(b":");
        hasher.update(ids[1].as_bytes());

        hex::encode(hasher.finalize())
    }
}

/// Message with read status for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessageDto {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub encrypted_content: String,
    pub nonce: String,
    pub sender_ephemeral_pubkey: String,
    pub created_at: String,
    pub is_read: bool,
    pub is_own_message: bool,
}

/// Conversation summary for inbox listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub conversation_id: String,
    pub other_user_id: String,
    pub other_username: String,
    pub last_message_at: String,
    pub unread_count: i64,
    pub has_keypair: bool,
}

impl SecureMessage {
    /// Create a new message
    pub fn create(
        new_message: NewSecureMessage,
        conn: &mut SqliteConnection,
    ) -> Result<SecureMessage> {
        use crate::schema::secure_messages::dsl;

        diesel::insert_into(dsl::secure_messages)
            .values(&new_message)
            .execute(conn)
            .context("Failed to insert message")?;

        let message = dsl::secure_messages
            .find(&new_message.id)
            .first::<SecureMessage>(conn)
            .context("Failed to retrieve created message")?;

        Ok(message)
    }

    /// Get messages for a conversation
    pub fn get_conversation(
        user_id: &str,
        other_user_id: &str,
        limit: i64,
        offset: i64,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<SecureMessage>> {
        use crate::schema::secure_messages::dsl;

        let conversation_id = NewSecureMessage::compute_conversation_id(user_id, other_user_id);

        let messages = dsl::secure_messages
            .filter(dsl::conversation_id.eq(&conversation_id))
            .filter(
                // Not deleted by current user
                diesel::dsl::not(
                    dsl::sender_id
                        .eq(user_id)
                        .and(dsl::is_deleted_by_sender.eq(1)),
                )
                .and(diesel::dsl::not(
                    dsl::recipient_id
                        .eq(user_id)
                        .and(dsl::is_deleted_by_recipient.eq(1)),
                )),
            )
            .order(dsl::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<SecureMessage>(conn)
            .context("Failed to load conversation")?;

        Ok(messages)
    }

    /// Get unread message count for a user
    pub fn count_unread_for_user(user_id: &str, conn: &mut SqliteConnection) -> Result<i64> {
        use crate::schema::message_read_receipts::dsl as read_dsl;
        use crate::schema::secure_messages::dsl;

        let count = dsl::secure_messages
            .filter(dsl::recipient_id.eq(user_id))
            .filter(dsl::is_deleted_by_recipient.eq(0))
            .left_join(read_dsl::message_read_receipts.on(read_dsl::message_id.eq(dsl::id)))
            .filter(read_dsl::message_id.is_null())
            .count()
            .get_result(conn)
            .context("Failed to count unread messages")?;

        Ok(count)
    }

    /// Get all conversations for a user with summary info
    pub fn get_conversations_for_user(
        user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<(String, String, String, i64)>> {
        use crate::schema::message_read_receipts::dsl as read_dsl;
        use crate::schema::secure_messages::dsl;
        use crate::schema::users::dsl as users_dsl;

        // Get all messages involving this user
        let messages: Vec<SecureMessage> = dsl::secure_messages
            .filter(dsl::sender_id.eq(user_id).or(dsl::recipient_id.eq(user_id)))
            .filter(
                // Not deleted by current user
                diesel::dsl::not(
                    dsl::sender_id
                        .eq(user_id)
                        .and(dsl::is_deleted_by_sender.eq(1)),
                )
                .and(diesel::dsl::not(
                    dsl::recipient_id
                        .eq(user_id)
                        .and(dsl::is_deleted_by_recipient.eq(1)),
                )),
            )
            .order(dsl::created_at.desc())
            .load::<SecureMessage>(conn)
            .context("Failed to load messages")?;

        // Build unique conversations map
        let mut conversations: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for msg in &messages {
            let other_id = if msg.sender_id == user_id {
                &msg.recipient_id
            } else {
                &msg.sender_id
            };
            conversations
                .entry(msg.conversation_id.clone())
                .or_insert_with(|| other_id.clone());
        }

        // Build result with user info and unread count
        let mut result = Vec::new();
        for (conv_id, other_id) in conversations {
            // Get other user's username
            let other_username = users_dsl::users
                .find(&other_id)
                .select(users_dsl::username)
                .first::<String>(conn)
                .unwrap_or_else(|_| "Unknown".to_string());

            // Count unread messages in this conversation
            let unread: i64 = dsl::secure_messages
                .filter(dsl::conversation_id.eq(&conv_id))
                .filter(dsl::recipient_id.eq(user_id))
                .filter(dsl::is_deleted_by_recipient.eq(0))
                .left_join(read_dsl::message_read_receipts.on(read_dsl::message_id.eq(dsl::id)))
                .filter(read_dsl::message_id.is_null())
                .count()
                .get_result(conn)
                .unwrap_or(0);

            result.push((conv_id, other_id, other_username, unread));
        }

        Ok(result)
    }

    /// Soft-delete message for a user
    pub fn soft_delete(
        message_id: &str,
        user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<bool> {
        use crate::schema::secure_messages::dsl;

        // Check if user is sender or recipient
        let message = dsl::secure_messages
            .find(message_id)
            .first::<SecureMessage>(conn)
            .optional()
            .context("Failed to find message")?;

        let Some(msg) = message else {
            return Ok(false);
        };

        if msg.sender_id == user_id {
            diesel::update(dsl::secure_messages.find(message_id))
                .set(dsl::is_deleted_by_sender.eq(1))
                .execute(conn)
                .context("Failed to delete message")?;
            Ok(true)
        } else if msg.recipient_id == user_id {
            diesel::update(dsl::secure_messages.find(message_id))
                .set(dsl::is_deleted_by_recipient.eq(1))
                .execute(conn)
                .context("Failed to delete message")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete expired messages (cleanup job)
    pub fn delete_expired(conn: &mut SqliteConnection) -> Result<usize> {
        use crate::schema::secure_messages::dsl;

        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let count = diesel::delete(
            dsl::secure_messages
                .filter(dsl::expires_at.is_not_null())
                .filter(dsl::expires_at.lt(&now)),
        )
        .execute(conn)
        .context("Failed to delete expired messages")?;

        Ok(count)
    }
}

// ============================================================================
// Read Receipt Models
// ============================================================================

/// Message read receipt
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = message_read_receipts)]
#[diesel(primary_key(message_id))]
pub struct MessageReadReceipt {
    pub message_id: String,
    pub read_at: String,
}

/// New read receipt for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = message_read_receipts)]
pub struct NewMessageReadReceipt {
    pub message_id: String,
}

impl MessageReadReceipt {
    /// Mark a message as read
    pub fn mark_read(message_id: &str, conn: &mut SqliteConnection) -> Result<()> {
        use crate::schema::message_read_receipts::dsl;

        diesel::insert_into(dsl::message_read_receipts)
            .values(NewMessageReadReceipt {
                message_id: message_id.to_string(),
            })
            .on_conflict_do_nothing()
            .execute(conn)
            .context("Failed to mark message as read")?;

        Ok(())
    }

    /// Mark all messages in a conversation as read
    pub fn mark_conversation_read(
        user_id: &str,
        other_user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<usize> {
        use crate::schema::message_read_receipts::dsl as read_dsl;
        use crate::schema::secure_messages::dsl;

        let conversation_id = NewSecureMessage::compute_conversation_id(user_id, other_user_id);

        // Get unread message IDs for this user in this conversation
        let unread_ids: Vec<String> = dsl::secure_messages
            .filter(dsl::conversation_id.eq(&conversation_id))
            .filter(dsl::recipient_id.eq(user_id))
            .left_join(read_dsl::message_read_receipts.on(read_dsl::message_id.eq(dsl::id)))
            .filter(read_dsl::message_id.is_null())
            .select(dsl::id)
            .load(conn)
            .context("Failed to get unread messages")?;

        let count = unread_ids.len();

        // Insert read receipts for all
        for msg_id in unread_ids {
            diesel::insert_into(read_dsl::message_read_receipts)
                .values(NewMessageReadReceipt { message_id: msg_id })
                .on_conflict_do_nothing()
                .execute(conn)
                .ok();
        }

        Ok(count)
    }

    /// Check if a message is read
    pub fn is_read(message_id: &str, conn: &mut SqliteConnection) -> Result<bool> {
        use crate::schema::message_read_receipts::dsl;

        let exists = dsl::message_read_receipts
            .find(message_id)
            .first::<MessageReadReceipt>(conn)
            .optional()
            .context("Failed to check read status")?;

        Ok(exists.is_some())
    }
}
