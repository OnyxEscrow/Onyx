//! Wallet RPC configuration persistence for escrow recovery
//!
//! This module handles storage and retrieval of client wallet RPC connection information.
//! RPC credentials are encrypted at rest using AES-256-GCM with the MULTISIG_ENCRYPTION_KEY.
//!
//! ## Security Considerations
//!
//! - All RPC URLs, usernames, and passwords are encrypted before storage
//! - Uses same encryption key as MultisigStateRepository
//! - Connection attempts and errors logged for monitoring
//! - Supports both manual and automatic recovery modes

use anyhow::{Context, Result};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::wallet_rpc_configs;

/// Wallet RPC configuration stored in database
///
/// Contains encrypted connection information for client-controlled wallets.
/// Used during server restart to automatically reconnect to wallet RPCs
/// if recovery_mode is 'automatic'.
#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(table_name = wallet_rpc_configs)]
#[diesel(primary_key(wallet_id))]
#[diesel(belongs_to(crate::models::escrow::Escrow, foreign_key = escrow_id))]
pub struct WalletRpcConfig {
    pub wallet_id: Option<String>,
    pub escrow_id: String,
    pub role: String,
    pub rpc_url_encrypted: Vec<u8>,
    pub rpc_user_encrypted: Option<Vec<u8>>,
    pub rpc_password_encrypted: Option<Vec<u8>>,
    pub created_at: i32,
    pub last_connected_at: Option<i32>,
    pub connection_attempts: i32,
    pub last_error: Option<String>,
}

/// Insertable wallet RPC config (for new records)
#[derive(Insertable)]
#[diesel(table_name = wallet_rpc_configs)]
pub struct NewWalletRpcConfig {
    pub wallet_id: String,
    pub escrow_id: String,
    pub role: String,
    pub rpc_url_encrypted: Vec<u8>,
    pub rpc_user_encrypted: Option<Vec<u8>>,
    pub rpc_password_encrypted: Option<Vec<u8>>,
}

impl WalletRpcConfig {
    /// Save a new wallet RPC configuration to database
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `wallet_id` - UUID of the wallet instance
    /// * `escrow_id` - Associated escrow ID
    /// * `role` - Wallet role ("buyer", "vendor", or "arbiter")
    /// * `rpc_url` - Plaintext RPC URL (will be encrypted)
    /// * `rpc_user` - Optional RPC username (will be encrypted)
    /// * `rpc_password` - Optional RPC password (will be encrypted)
    /// * `encryption_key` - 32-byte AES-256-GCM key
    ///
    /// # Returns
    /// The created WalletRpcConfig record
    ///
    /// # Errors
    /// - Database insert fails
    /// - Encryption fails
    /// - Unique constraint violation (wallet_id or escrow_id+role already exists)
    pub fn save(
        conn: &mut SqliteConnection,
        wallet_id: &str,
        escrow_id: &str,
        role: &str,
        rpc_url: &str,
        rpc_user: Option<&str>,
        rpc_password: Option<&str>,
        encryption_key: &[u8],
    ) -> Result<Self> {
        use crate::crypto::encryption::encrypt_field;

        // Encrypt all sensitive fields
        let rpc_url_encrypted =
            encrypt_field(rpc_url, encryption_key).context("Failed to encrypt RPC URL")?;

        let rpc_user_encrypted = rpc_user
            .map(|u| encrypt_field(u, encryption_key))
            .transpose()
            .context("Failed to encrypt RPC user")?;

        let rpc_password_encrypted = rpc_password
            .map(|p| encrypt_field(p, encryption_key))
            .transpose()
            .context("Failed to encrypt RPC password")?;

        let new_config = NewWalletRpcConfig {
            wallet_id: wallet_id.to_string(),
            escrow_id: escrow_id.to_string(),
            role: role.to_string(),
            rpc_url_encrypted,
            rpc_user_encrypted,
            rpc_password_encrypted,
        };

        diesel::insert_into(wallet_rpc_configs::table)
            .values(&new_config)
            .execute(conn)
            .context("Failed to insert wallet RPC config")?;

        // Retrieve the created record
        wallet_rpc_configs::table
            .filter(wallet_rpc_configs::wallet_id.eq(wallet_id))
            .first(conn)
            .context("Failed to retrieve created wallet RPC config")
    }

    /// Find all wallet RPC configs for a specific escrow
    ///
    /// Used during recovery to reconnect all wallets associated with an escrow.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `escrow_id` - Escrow identifier
    ///
    /// # Returns
    /// Vector of WalletRpcConfig records (may be empty if none found)
    ///
    /// # Errors
    /// Database query fails
    pub fn find_by_escrow(conn: &mut SqliteConnection, escrow_id: &str) -> Result<Vec<Self>> {
        wallet_rpc_configs::table
            .filter(wallet_rpc_configs::escrow_id.eq(escrow_id))
            .load(conn)
            .context(format!(
                "Failed to load RPC configs for escrow {}",
                escrow_id
            ))
    }

    /// Find wallet RPC config by wallet ID
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `wallet_id` - Wallet UUID
    ///
    /// # Returns
    /// The wallet RPC config if found
    ///
    /// # Errors
    /// - Not found
    /// - Database query fails
    pub fn find_by_wallet_id(conn: &mut SqliteConnection, wallet_id: &str) -> Result<Self> {
        wallet_rpc_configs::table
            .filter(wallet_rpc_configs::wallet_id.eq(wallet_id))
            .first(conn)
            .context(format!("Wallet RPC config not found: {}", wallet_id))
    }

    /// Decrypt the RPC URL
    ///
    /// # Arguments
    /// * `encryption_key` - 32-byte AES-256-GCM key
    ///
    /// # Returns
    /// Decrypted RPC URL as String
    ///
    /// # Errors
    /// - Decryption fails
    /// - Invalid UTF-8 in decrypted data
    pub fn decrypt_url(&self, encryption_key: &[u8]) -> Result<String> {
        use crate::crypto::encryption::decrypt_field;

        decrypt_field(&self.rpc_url_encrypted, encryption_key).context("Failed to decrypt RPC URL")
    }

    /// Decrypt the RPC username (if present)
    ///
    /// # Arguments
    /// * `encryption_key` - 32-byte AES-256-GCM key
    ///
    /// # Returns
    /// Some(username) if set, None if not set
    ///
    /// # Errors
    /// Decryption fails or invalid UTF-8
    pub fn decrypt_user(&self, encryption_key: &[u8]) -> Result<Option<String>> {
        use crate::crypto::encryption::decrypt_field;

        match &self.rpc_user_encrypted {
            Some(encrypted) => {
                let user = decrypt_field(encrypted, encryption_key)
                    .context("Failed to decrypt RPC user")?;
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    /// Decrypt the RPC password (if present)
    ///
    /// # Arguments
    /// * `encryption_key` - 32-byte AES-256-GCM key
    ///
    /// # Returns
    /// Some(password) if set, None if not set
    ///
    /// # Errors
    /// Decryption fails or invalid UTF-8
    pub fn decrypt_password(&self, encryption_key: &[u8]) -> Result<Option<String>> {
        use crate::crypto::encryption::decrypt_field;

        match &self.rpc_password_encrypted {
            Some(encrypted) => {
                let password = decrypt_field(encrypted, encryption_key)
                    .context("Failed to decrypt RPC password")?;
                Ok(Some(password))
            }
            None => Ok(None),
        }
    }

    /// Update last_connected_at timestamp to now
    ///
    /// Called after successful reconnection to wallet RPC during recovery.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `wallet_id` - Wallet UUID
    ///
    /// # Returns
    /// Ok(()) on success
    ///
    /// # Errors
    /// Database update fails
    pub fn update_last_connected(conn: &mut SqliteConnection, wallet_id: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        diesel::update(
            wallet_rpc_configs::table.filter(wallet_rpc_configs::wallet_id.eq(wallet_id)),
        )
        .set(wallet_rpc_configs::last_connected_at.eq(Some(now as i32)))
        .execute(conn)
        .context(format!(
            "Failed to update last_connected_at for wallet {}",
            wallet_id
        ))?;

        Ok(())
    }

    /// Increment connection_attempts counter
    ///
    /// Called when recovery attempt fails. Used for monitoring and alerting.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `wallet_id` - Wallet UUID
    /// * `error_message` - Optional error message to store
    ///
    /// # Returns
    /// Ok(()) on success
    ///
    /// # Errors
    /// Database update fails
    pub fn increment_connection_attempts(
        conn: &mut SqliteConnection,
        wallet_id: &str,
        error_message: Option<&str>,
    ) -> Result<()> {
        diesel::update(
            wallet_rpc_configs::table.filter(wallet_rpc_configs::wallet_id.eq(wallet_id)),
        )
        .set((
            wallet_rpc_configs::connection_attempts.eq(wallet_rpc_configs::connection_attempts + 1),
            wallet_rpc_configs::last_error.eq(error_message),
        ))
        .execute(conn)
        .context(format!(
            "Failed to increment connection_attempts for wallet {}",
            wallet_id
        ))?;

        Ok(())
    }

    /// Delete wallet RPC config
    ///
    /// Called when wallet is no longer needed (escrow completed, refunded, etc.)
    /// Note: CASCADE delete handles this automatically when escrow is deleted.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `wallet_id` - Wallet UUID to delete
    ///
    /// # Returns
    /// Ok(()) on success
    ///
    /// # Errors
    /// Database delete fails
    pub fn delete(conn: &mut SqliteConnection, wallet_id: &str) -> Result<()> {
        diesel::delete(
            wallet_rpc_configs::table.filter(wallet_rpc_configs::wallet_id.eq(wallet_id)),
        )
        .execute(conn)
        .context(format!("Failed to delete wallet RPC config {}", wallet_id))?;

        Ok(())
    }
}
