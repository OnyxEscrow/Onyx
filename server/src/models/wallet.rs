//! Wallet model for client-side generated wallets
//! Stores wallet metadata and public keys (no private keys ever stored)

use anyhow::{Context, Result};
use chrono::{NaiveDate, NaiveDateTime};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::wallets;

#[derive(Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = wallets)]
pub struct Wallet {
    /// UUID for wallet identity
    pub id: String,

    /// Link to user who owns this wallet
    pub user_id: String,

    /// Monero wallet address (58 chars for standard, 95 for integrated)
    pub address: String,

    /// SHA256 hash of address for verification
    pub address_hash: String,

    /// Public spend key (64 hex characters = 32 bytes)
    pub spend_key_pub: String,

    /// Public view key (64 hex characters = 32 bytes)
    pub view_key_pub: String,

    /// Optional signature for proof of ownership
    pub signature: Option<String>,

    /// Wallet registration timestamp
    pub created_at: NaiveDateTime,

    /// Last update timestamp
    pub updated_at: NaiveDateTime,

    /// Daily withdrawal limit in atomic units (0 = unlimited)
    /// v0.47.0: Changed from i32 to i64 to support mainnet amounts (i32 max = 0.002 XMR)
    pub daily_limit_atomic: Option<i64>,

    /// Monthly withdrawal limit in atomic units (0 = unlimited)
    /// v0.47.0: Changed from i32 to i64 to support mainnet amounts
    pub monthly_limit_atomic: Option<i64>,

    /// Last withdrawal date for daily limit tracking
    /// v0.46.0: Fixed type to NaiveDate to match schema.rs (was incorrectly String)
    pub last_withdrawal_date: Option<NaiveDate>,

    /// Amount withdrawn today in atomic units
    /// v0.47.0: Changed from i32 to i64 to support mainnet amounts
    pub withdrawn_today_atomic: Option<i64>,
}

/// Debug impl that redacts sensitive fields
impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("address", &"<redacted>")
            .field("address_hash", &"<redacted>")
            .field("spend_key_pub", &"<redacted>")
            .field("view_key_pub", &"<redacted>")
            .field("signature", &self.signature.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Insertable)]
#[diesel(table_name = wallets)]
pub struct NewWallet {
    pub id: String,
    pub user_id: String,
    pub address: String,
    pub address_hash: String,
    pub spend_key_pub: Option<String>,
    pub view_key_pub: Option<String>,
    pub signature: Option<String>,
    #[diesel(column_name = daily_limit_atomic)]
    pub daily_limit_atomic: Option<i64>,
    #[diesel(column_name = monthly_limit_atomic)]
    pub monthly_limit_atomic: Option<i64>,
    #[diesel(column_name = last_withdrawal_date)]
    pub last_withdrawal_date: Option<NaiveDate>,
    #[diesel(column_name = withdrawn_today_atomic)]
    pub withdrawn_today_atomic: Option<i64>,
}

impl Wallet {
    /// Create a new wallet in the database
    pub fn create(conn: &mut SqliteConnection, new_wallet: NewWallet) -> Result<Wallet> {
        diesel::insert_into(wallets::table)
            .values(&new_wallet)
            .execute(conn)
            .context("Failed to insert wallet")?;

        wallets::table
            .filter(wallets::id.eq(new_wallet.id))
            .first(conn)
            .context("Failed to retrieve created wallet")
    }

    /// Find wallet by ID
    pub fn find_by_id(conn: &mut SqliteConnection, wallet_id: String) -> Result<Wallet> {
        wallets::table
            .filter(wallets::id.eq(wallet_id.clone()))
            .first(conn)
            .context(format!("Wallet with ID {} not found", wallet_id))
    }

    /// Find wallet by address
    pub fn find_by_address(conn: &mut SqliteConnection, address: &str) -> Result<Wallet> {
        wallets::table
            .filter(wallets::address.eq(address))
            .first(conn)
            .context(format!("Wallet with address {} not found", address))
    }

    /// Find all wallets for a user
    pub fn find_by_user_id(conn: &mut SqliteConnection, user_id: String) -> Result<Vec<Wallet>> {
        wallets::table
            .filter(wallets::user_id.eq(user_id.clone()))
            .load(conn)
            .context(format!("Failed to load wallets for user {}", user_id))
    }

    /// Check if address already exists
    pub fn address_exists(conn: &mut SqliteConnection, address: &str) -> Result<bool> {
        let count: i64 = wallets::table
            .filter(wallets::address.eq(address))
            .count()
            .get_result(conn)
            .context("Failed to check address existence")?;
        Ok(count > 0)
    }

    /// Delete wallet by ID
    pub fn delete(conn: &mut SqliteConnection, wallet_id: String) -> Result<()> {
        diesel::delete(wallets::table.filter(wallets::id.eq(wallet_id.clone())))
            .execute(conn)
            .context(format!("Failed to delete wallet {}", wallet_id))?;
        Ok(())
    }

    /// Get count of wallets for a user
    pub fn count_for_user(conn: &mut SqliteConnection, user_id: &str) -> Result<i64> {
        wallets::table
            .filter(wallets::user_id.eq(user_id))
            .count()
            .get_result(conn)
            .context("Failed to count wallets for user")
    }

    /// Check if a withdrawal amount exceeds daily limit
    /// v0.47.0: Changed parameter to i64 to support mainnet amounts
    pub fn check_daily_limit(&self, amount_atomic: i64) -> Result<bool> {
        match self.daily_limit_atomic {
            None | Some(0) => Ok(true),
            Some(limit) => {
                let withdrawn = self.withdrawn_today_atomic.unwrap_or(0);
                Ok(withdrawn + amount_atomic <= limit)
            }
        }
    }

    /// Check if a withdrawal amount exceeds monthly limit
    /// v0.47.0: Changed parameter to i64 to support mainnet amounts
    pub fn check_monthly_limit(&self, amount_atomic: i64) -> Result<bool> {
        match self.monthly_limit_atomic {
            None | Some(0) => Ok(true),
            Some(limit) => Ok(amount_atomic <= limit),
        }
    }

    /// Set daily withdrawal limit
    /// v0.47.0: Changed parameter to i64 to support mainnet amounts
    pub fn set_daily_limit(
        conn: &mut SqliteConnection,
        wallet_id: &str,
        limit_atomic: i64,
    ) -> Result<()> {
        diesel::update(wallets::table.filter(wallets::id.eq(wallet_id)))
            .set(wallets::daily_limit_atomic.eq(limit_atomic))
            .execute(conn)
            .context("Failed to set daily limit")?;
        Ok(())
    }

    /// Set monthly withdrawal limit
    /// v0.47.0: Changed parameter to i64 to support mainnet amounts
    pub fn set_monthly_limit(
        conn: &mut SqliteConnection,
        wallet_id: &str,
        limit_atomic: i64,
    ) -> Result<()> {
        diesel::update(wallets::table.filter(wallets::id.eq(wallet_id)))
            .set(wallets::monthly_limit_atomic.eq(limit_atomic))
            .execute(conn)
            .context("Failed to set monthly limit")?;
        Ok(())
    }
}
