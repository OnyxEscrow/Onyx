use crate::schema::{escrow_chat_keypairs, escrow_chat_read_receipts, messages, secure_escrow_messages};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Legacy simple messages (messages table)
// ============================================================================

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = messages)]
pub struct EscrowMessage {
    pub id: String,
    pub escrow_id: String,
    pub sender_id: String,
    pub content: String,
    pub created_at: chrono::NaiveDateTime,
    pub is_read: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = messages)]
pub struct NewEscrowMessage {
    pub id: String,
    pub escrow_id: String,
    pub sender_id: String,
    pub content: String,
    pub is_read: bool,
}

impl EscrowMessage {
    pub fn create(conn: &mut SqliteConnection, new_message: NewEscrowMessage) -> QueryResult<Self> {
        diesel::insert_into(messages::table)
            .values(&new_message)
            .execute(conn)?;
        messages::table
            .filter(messages::id.eq(&new_message.id))
            .first(conn)
    }

    pub fn find_by_escrow(conn: &mut SqliteConnection, escrow_id_param: &str) -> QueryResult<Vec<Self>> {
        messages::table
            .filter(messages::escrow_id.eq(escrow_id_param))
            .order(messages::created_at.asc())
            .load(conn)
    }

    pub fn count_unread(conn: &mut SqliteConnection, escrow_id_param: &str) -> QueryResult<i64> {
        messages::table
            .filter(messages::escrow_id.eq(escrow_id_param))
            .filter(messages::is_read.eq(false))
            .count()
            .get_result(conn)
    }

    pub fn mark_as_read(conn: &mut SqliteConnection, message_id: &str) -> QueryResult<usize> {
        diesel::update(messages::table.filter(messages::id.eq(message_id)))
            .set(messages::is_read.eq(true))
            .execute(conn)
    }

    pub fn mark_all_as_read_except_sender(
        conn: &mut SqliteConnection,
        escrow_id_param: &str,
        sender_id_param: &str,
    ) -> QueryResult<usize> {
        diesel::update(
            messages::table
                .filter(messages::escrow_id.eq(escrow_id_param))
                .filter(messages::sender_id.ne(sender_id_param))
                .filter(messages::is_read.eq(false)),
        )
        .set(messages::is_read.eq(true))
        .execute(conn)
    }
}

// ============================================================================
// E2EE Chat Keypairs (escrow_chat_keypairs table)
// ============================================================================

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = escrow_chat_keypairs)]
pub struct EscrowMessageKeypair {
    pub id: String,
    pub escrow_id: String,
    pub user_id: String,
    pub role: String,
    pub public_key: String,
    pub created_at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = escrow_chat_keypairs)]
pub struct NewEscrowMessageKeypair {
    pub id: String,
    pub escrow_id: String,
    pub user_id: String,
    pub role: String,
    pub public_key: String,
}

impl NewEscrowMessageKeypair {
    pub fn new(escrow_id: String, user_id: String, role: String, public_key: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            escrow_id,
            user_id,
            role,
            public_key,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EscrowKeypairsDto {
    pub buyer_pubkey: Option<String>,
    pub buyer_id: Option<String>,
    pub buyer_username: Option<String>,
    pub vendor_pubkey: Option<String>,
    pub vendor_id: Option<String>,
    pub vendor_username: Option<String>,
    pub arbiter_pubkey: Option<String>,
    pub arbiter_id: Option<String>,
    pub arbiter_username: Option<String>,
    pub all_registered: bool,
    /// True when buyer + vendor both have keys (sufficient for chat — arbiter is automated)
    pub buyer_vendor_registered: bool,
}

impl EscrowMessageKeypair {
    /// Upsert a keypair (replace if already exists for this escrow+user)
    pub fn register(conn: &mut SqliteConnection, new: NewEscrowMessageKeypair) -> QueryResult<Self> {
        // Try to find existing
        let existing = escrow_chat_keypairs::table
            .filter(escrow_chat_keypairs::escrow_id.eq(&new.escrow_id))
            .filter(escrow_chat_keypairs::user_id.eq(&new.user_id))
            .first::<Self>(conn)
            .optional()?;

        if let Some(existing) = existing {
            // Update public key
            diesel::update(escrow_chat_keypairs::table.filter(escrow_chat_keypairs::id.eq(&existing.id)))
                .set(escrow_chat_keypairs::public_key.eq(&new.public_key))
                .execute(conn)?;
            escrow_chat_keypairs::table
                .filter(escrow_chat_keypairs::id.eq(&existing.id))
                .first(conn)
        } else {
            diesel::insert_into(escrow_chat_keypairs::table)
                .values(&new)
                .execute(conn)?;
            escrow_chat_keypairs::table
                .filter(escrow_chat_keypairs::id.eq(&new.id))
                .first(conn)
        }
    }

    /// Get all keypairs for an escrow as a DTO with usernames
    pub fn get_keypairs_dto(conn: &mut SqliteConnection, escrow_id: &str) -> QueryResult<EscrowKeypairsDto> {
        let keypairs: Vec<Self> = escrow_chat_keypairs::table
            .filter(escrow_chat_keypairs::escrow_id.eq(escrow_id))
            .load(conn)?;

        // Fetch usernames from users table
        use crate::schema::users;

        let mut dto = EscrowKeypairsDto {
            buyer_pubkey: None,
            buyer_id: None,
            buyer_username: None,
            vendor_pubkey: None,
            vendor_id: None,
            vendor_username: None,
            arbiter_pubkey: None,
            arbiter_id: None,
            arbiter_username: None,
            all_registered: false,
            buyer_vendor_registered: false,
        };

        let mut count = 0;
        for kp in &keypairs {
            let username: Option<String> = users::table
                .filter(users::id.eq(&kp.user_id))
                .select(users::username)
                .first::<String>(conn)
                .optional()?;

            match kp.role.as_str() {
                "buyer" => {
                    dto.buyer_pubkey = Some(kp.public_key.clone());
                    dto.buyer_id = Some(kp.user_id.clone());
                    dto.buyer_username = username;
                    count += 1;
                }
                "vendor" => {
                    dto.vendor_pubkey = Some(kp.public_key.clone());
                    dto.vendor_id = Some(kp.user_id.clone());
                    dto.vendor_username = username;
                    count += 1;
                }
                "arbiter" => {
                    dto.arbiter_pubkey = Some(kp.public_key.clone());
                    dto.arbiter_id = Some(kp.user_id.clone());
                    dto.arbiter_username = username;
                    count += 1;
                }
                _ => {}
            }
        }

        dto.all_registered = count >= 3;
        dto.buyer_vendor_registered = dto.buyer_pubkey.is_some() && dto.vendor_pubkey.is_some();
        Ok(dto)
    }
}

// ============================================================================
// Secure E2EE Messages (secure_escrow_messages table)
// ============================================================================

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = secure_escrow_messages)]
pub struct SecureEscrowMessage {
    pub id: String,
    pub escrow_id: String,
    pub sender_id: String,
    pub sender_role: String,
    pub encrypted_content_buyer: String,
    pub encrypted_content_vendor: String,
    pub encrypted_content_arbiter: String,
    pub sender_ephemeral_pubkey: String,
    pub nonce: String,
    pub frost_signature: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = secure_escrow_messages)]
pub struct NewSecureEscrowMessage {
    pub id: String,
    pub escrow_id: String,
    pub sender_id: String,
    pub sender_role: String,
    pub encrypted_content_buyer: String,
    pub encrypted_content_vendor: String,
    pub encrypted_content_arbiter: String,
    pub sender_ephemeral_pubkey: String,
    pub nonce: String,
    pub frost_signature: Option<String>,
}

impl NewSecureEscrowMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        escrow_id: String,
        sender_id: String,
        sender_role: String,
        encrypted_content_buyer: String,
        encrypted_content_vendor: String,
        encrypted_content_arbiter: String,
        sender_ephemeral_pubkey: String,
        nonce: String,
        frost_signature: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            escrow_id,
            sender_id,
            sender_role,
            encrypted_content_buyer,
            encrypted_content_vendor,
            encrypted_content_arbiter,
            sender_ephemeral_pubkey,
            nonce,
            frost_signature,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SecureEscrowMessageDto {
    pub id: String,
    pub sender_id: String,
    pub sender_role: String,
    pub sender_username: String,
    pub encrypted_content: String,
    pub sender_ephemeral_pubkey: String,
    pub nonce: String,
    pub frost_signature: Option<String>,
    pub created_at: String,
    pub is_read: bool,
    pub is_own_message: bool,
}

impl SecureEscrowMessage {
    pub fn create(conn: &mut SqliteConnection, new: NewSecureEscrowMessage) -> QueryResult<Self> {
        diesel::insert_into(secure_escrow_messages::table)
            .values(&new)
            .execute(conn)?;
        secure_escrow_messages::table
            .filter(secure_escrow_messages::id.eq(&new.id))
            .first(conn)
    }

    /// Get messages for a specific escrow, ordered by most recent first, with pagination
    pub fn find_by_escrow_for_role(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        _role: &str,
        limit: i64,
        offset: i64,
    ) -> QueryResult<Vec<Self>> {
        secure_escrow_messages::table
            .filter(secure_escrow_messages::escrow_id.eq(escrow_id))
            .order(secure_escrow_messages::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load(conn)
    }

    pub fn count_for_escrow(conn: &mut SqliteConnection, escrow_id: &str) -> QueryResult<i64> {
        secure_escrow_messages::table
            .filter(secure_escrow_messages::escrow_id.eq(escrow_id))
            .count()
            .get_result(conn)
    }

    /// Export all messages for dispute evidence (returns raw encrypted data)
    pub fn export_for_dispute(conn: &mut SqliteConnection, escrow_id: &str) -> QueryResult<Vec<Self>> {
        secure_escrow_messages::table
            .filter(secure_escrow_messages::escrow_id.eq(escrow_id))
            .order(secure_escrow_messages::created_at.asc())
            .load(conn)
    }

    /// Convert to DTO with role-specific encrypted content
    pub fn to_dto_for_role(&self, role: &str, current_user_id: &str, is_read: bool) -> SecureEscrowMessageDto {
        let encrypted_content = match role {
            "buyer" => self.encrypted_content_buyer.clone(),
            "vendor" => self.encrypted_content_vendor.clone(),
            "arbiter" => self.encrypted_content_arbiter.clone(),
            _ => String::new(),
        };

        // Get sender username from role as fallback
        let sender_username = self.sender_role.clone();

        SecureEscrowMessageDto {
            id: self.id.clone(),
            sender_id: self.sender_id.clone(),
            sender_role: self.sender_role.clone(),
            sender_username,
            encrypted_content,
            sender_ephemeral_pubkey: self.sender_ephemeral_pubkey.clone(),
            nonce: self.nonce.clone(),
            frost_signature: self.frost_signature.clone(),
            created_at: self.created_at.clone(),
            is_read,
            is_own_message: self.sender_id == current_user_id,
        }
    }
}

// ============================================================================
// Read Receipts (escrow_chat_read_receipts table)
// ============================================================================

#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = escrow_chat_read_receipts)]
pub struct EscrowMessageReadReceipt {
    pub id: String,
    pub message_id: String,
    pub user_id: String,
    pub read_at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = escrow_chat_read_receipts)]
pub struct NewEscrowMessageReadReceipt {
    pub id: String,
    pub message_id: String,
    pub user_id: String,
}

impl EscrowMessageReadReceipt {
    pub fn is_read_by_user(conn: &mut SqliteConnection, message_id: &str, user_id: &str) -> QueryResult<bool> {
        let count: i64 = escrow_chat_read_receipts::table
            .filter(escrow_chat_read_receipts::message_id.eq(message_id))
            .filter(escrow_chat_read_receipts::user_id.eq(user_id))
            .count()
            .get_result(conn)?;
        Ok(count > 0)
    }

    pub fn mark_read(conn: &mut SqliteConnection, message_id: &str, user_id: &str) -> QueryResult<()> {
        // Check if already read
        let already_read = Self::is_read_by_user(conn, message_id, user_id)?;
        if already_read {
            return Ok(());
        }

        let new_receipt = NewEscrowMessageReadReceipt {
            id: Uuid::new_v4().to_string(),
            message_id: message_id.to_string(),
            user_id: user_id.to_string(),
        };

        diesel::insert_into(escrow_chat_read_receipts::table)
            .values(&new_receipt)
            .execute(conn)?;
        Ok(())
    }
}
