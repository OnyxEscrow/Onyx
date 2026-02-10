//! Diesel models for encrypted relay table
//!
//! Stores encrypted messages for FROST signing relay.
//! The server NEVER sees the decrypted content - only encrypted ciphertext.

use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::encrypted_relay;

/// Queryable model for encrypted_relay table
/// IMPORTANT: Column order MUST match schema.rs exactly!
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = encrypted_relay)]
pub struct EncryptedRelay {
    pub id: String,                  // 1
    pub escrow_id: String,           // 2
    pub encrypted_blob: String,      // 3
    pub first_signer_role: String,   // 4
    pub first_signer_pubkey: String, // 5
    pub nonce: String,               // 6
    pub created_at: String,          // 7
    pub expires_at: String,          // 8 - NOT NULL
    pub consumed_at: Option<String>, // 9
    pub status: String,              // 10
}

/// Insertable model for creating new relay entries
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = encrypted_relay)]
pub struct NewEncryptedRelay {
    pub id: String,
    pub escrow_id: String,
    pub encrypted_blob: String,
    pub first_signer_role: String,
    pub first_signer_pubkey: String,
    pub nonce: String,
    pub created_at: String,
    pub expires_at: String,
    pub status: String,
}

/// Constants for relay configuration
pub const RELAY_TTL_SECONDS: i64 = 600; // 10 minutes
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024; // 10KB max

impl EncryptedRelay {
    /// Find pending relay for an escrow
    pub fn find_pending_by_escrow(
        conn: &mut SqliteConnection,
        escrow_id_val: &str,
    ) -> QueryResult<Vec<Self>> {
        encrypted_relay::table
            .filter(encrypted_relay::escrow_id.eq(escrow_id_val))
            .filter(encrypted_relay::status.eq("pending"))
            .filter(encrypted_relay::consumed_at.is_null())
            .order(encrypted_relay::created_at.asc())
            .load(conn)
    }

    /// Find relay by ID
    pub fn find_by_id(conn: &mut SqliteConnection, relay_id: &str) -> QueryResult<Option<Self>> {
        encrypted_relay::table
            .filter(encrypted_relay::id.eq(relay_id))
            .first(conn)
            .optional()
    }

    /// Mark relay as consumed
    pub fn mark_consumed(conn: &mut SqliteConnection, relay_id: &str) -> QueryResult<usize> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        diesel::update(encrypted_relay::table.filter(encrypted_relay::id.eq(relay_id)))
            .set((
                encrypted_relay::consumed_at.eq(Some(now)),
                encrypted_relay::status.eq("consumed"),
            ))
            .execute(conn)
    }

    /// Mark relay as expired
    pub fn mark_expired(conn: &mut SqliteConnection, relay_id: &str) -> QueryResult<usize> {
        diesel::update(encrypted_relay::table.filter(encrypted_relay::id.eq(relay_id)))
            .set(encrypted_relay::status.eq("expired"))
            .execute(conn)
    }

    /// Delete expired relays (cleanup)
    pub fn cleanup_expired(conn: &mut SqliteConnection) -> QueryResult<usize> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        diesel::delete(
            encrypted_relay::table
                .filter(encrypted_relay::status.eq("pending"))
                .filter(encrypted_relay::expires_at.lt(&now)),
        )
        .execute(conn)
    }

    /// Check if relay is expired
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.expires_at < now || self.status == "expired"
    }

    /// Check if relay was consumed
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some() || self.status == "consumed"
    }

    /// Alias for backwards compatibility
    pub fn is_retrieved(&self) -> bool {
        self.is_consumed()
    }

    /// Alias for backwards compatibility
    pub fn mark_retrieved(conn: &mut SqliteConnection, relay_id: &str) -> QueryResult<usize> {
        Self::mark_consumed(conn, relay_id)
    }
}

impl NewEncryptedRelay {
    /// Create a new relay entry
    pub fn new(
        escrow_id: String,
        encrypted_blob: String,
        first_signer_role: String,
        first_signer_pubkey: String,
        nonce: String,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let created_at = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let expires_at = (now + chrono::Duration::seconds(RELAY_TTL_SECONDS))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        Self {
            id,
            escrow_id,
            encrypted_blob,
            first_signer_role,
            first_signer_pubkey,
            nonce,
            created_at,
            expires_at,
            status: "pending".to_string(),
        }
    }

    /// Insert into database
    pub fn insert(&self, conn: &mut SqliteConnection) -> QueryResult<EncryptedRelay> {
        diesel::insert_into(encrypted_relay::table)
            .values(self)
            .execute(conn)?;

        encrypted_relay::table
            .filter(encrypted_relay::id.eq(&self.id))
            .first(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_encrypted_relay() {
        let relay = NewEncryptedRelay::new(
            "escrow_123".to_string(),
            "encrypted_data".to_string(),
            "buyer".to_string(),
            "pubkey_hex".to_string(),
            "nonce_hex".to_string(),
        );

        assert!(!relay.id.is_empty());
        assert_eq!(relay.escrow_id, "escrow_123");
        assert_eq!(relay.first_signer_role, "buyer");
        assert_eq!(relay.first_signer_pubkey, "pubkey_hex");
        assert_eq!(relay.nonce, "nonce_hex");
        assert_eq!(relay.status, "pending");
    }
}
