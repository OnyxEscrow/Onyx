//! Transaction model and related database operations
//!
//! Represents blockchain transactions associated with escrows in the marketplace.
//! Each transaction tracks the funding, release, or refund of escrow funds.

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::transactions;

/// Transaction database model
///
/// Tracks Monero blockchain transactions related to escrow operations.
/// Each transaction is linked to an escrow and contains the transaction hash,
/// amount, and confirmation count.
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = transactions)]
pub struct Transaction {
    /// Unique transaction ID (UUID)
    pub id: String,
    /// Associated escrow ID
    pub escrow_id: String,
    /// Monero transaction hash (64 hex characters)
    pub tx_hash: Option<String>,
    /// Transaction amount in atomic units (piconeros)
    /// 1 XMR = 1,000,000,000,000 piconeros
    pub amount_xmr: i64,
    /// Number of blockchain confirmations
    /// Monero requires 10 confirmations for finality
    pub confirmations: i32,
    /// Transaction creation timestamp
    pub created_at: NaiveDateTime,
}

/// New transaction for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = transactions)]
pub struct NewTransaction {
    pub id: String,
    pub escrow_id: String,
    pub tx_hash: Option<String>,
    pub amount_xmr: i64,
    pub confirmations: i32,
}

impl Transaction {
    /// Create a new transaction record in the database
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `new_transaction` - New transaction data
    ///
    /// # Returns
    ///
    /// The created transaction with timestamp populated by the database
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Database insertion fails
    /// - Transaction retrieval fails after insertion
    /// - Escrow ID does not exist (foreign key constraint)
    pub fn create(
        conn: &mut SqliteConnection,
        new_transaction: NewTransaction,
    ) -> Result<Transaction> {
        diesel::insert_into(transactions::table)
            .values(&new_transaction)
            .execute(conn)
            .context("Failed to insert transaction")?;

        transactions::table
            .filter(transactions::id.eq(&new_transaction.id))
            .first(conn)
            .context(format!(
                "Failed to retrieve created transaction with ID {}",
                new_transaction.id
            ))
    }

    /// Find transaction by ID
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `transaction_id` - Transaction UUID
    ///
    /// # Errors
    ///
    /// Returns error if transaction with the given ID does not exist
    pub fn find_by_id(conn: &mut SqliteConnection, transaction_id: String) -> Result<Transaction> {
        transactions::table
            .filter(transactions::id.eq(transaction_id.clone()))
            .first(conn)
            .context(format!("Transaction with ID {} not found", transaction_id))
    }

    /// Find transaction by Monero transaction hash
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `tx_hash` - Monero transaction hash (64 hex characters)
    ///
    /// # Errors
    ///
    /// Returns error if transaction with the given hash does not exist
    pub fn find_by_tx_hash(conn: &mut SqliteConnection, tx_hash: &str) -> Result<Transaction> {
        transactions::table
            .filter(transactions::tx_hash.eq(tx_hash))
            .first(conn)
            .context(format!("Transaction with hash {} not found", tx_hash))
    }

    /// Find all transactions for a specific escrow
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `escrow_id` - Escrow UUID
    ///
    /// # Returns
    ///
    /// Vector of transactions ordered by creation time (oldest first)
    ///
    /// # Errors
    ///
    /// Returns error if database query fails
    pub fn find_by_escrow(
        conn: &mut SqliteConnection,
        escrow_id: String,
    ) -> Result<Vec<Transaction>> {
        transactions::table
            .filter(transactions::escrow_id.eq(escrow_id))
            .order(transactions::created_at.asc())
            .load(conn)
            .context("Failed to load transactions for escrow")
    }

    /// Update transaction confirmation count
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `transaction_id` - Transaction UUID
    /// * `confirmations` - New confirmation count
    ///
    /// # Returns
    ///
    /// Updated transaction
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Transaction does not exist
    /// - Database update fails
    pub fn update_confirmations(
        conn: &mut SqliteConnection,
        transaction_id: String,
        confirmations: i32,
    ) -> Result<Transaction> {
        diesel::update(transactions::table.filter(transactions::id.eq(transaction_id.clone())))
            .set(transactions::confirmations.eq(confirmations))
            .execute(conn)
            .context(format!(
                "Failed to update confirmations for transaction {}",
                transaction_id
            ))?;

        Self::find_by_id(conn, transaction_id)
    }

    /// Set transaction hash (for transactions created before broadcast)
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `transaction_id` - Transaction UUID
    /// * `tx_hash` - Monero transaction hash
    ///
    /// # Returns
    ///
    /// Updated transaction
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Transaction does not exist
    /// - Database update fails
    /// - Transaction already has a hash set
    pub fn set_tx_hash(
        conn: &mut SqliteConnection,
        transaction_id: String,
        tx_hash: String,
    ) -> Result<Transaction> {
        // Verify transaction exists and doesn't already have a hash
        let existing = Self::find_by_id(conn, transaction_id.clone())?;
        if let Some(ref existing_hash) = existing.tx_hash {
            anyhow::bail!(
                "Transaction {} already has tx_hash set: {}",
                transaction_id,
                existing_hash
            );
        }

        diesel::update(transactions::table.filter(transactions::id.eq(transaction_id.clone())))
            .set(transactions::tx_hash.eq(tx_hash))
            .execute(conn)
            .context(format!(
                "Failed to set tx_hash for transaction {}",
                transaction_id
            ))?;

        Self::find_by_id(conn, transaction_id)
    }

    /// Find all unconfirmed transactions (confirmations < 10)
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    ///
    /// # Returns
    ///
    /// Vector of transactions with less than 10 confirmations
    ///
    /// # Errors
    ///
    /// Returns error if database query fails
    pub fn find_unconfirmed(conn: &mut SqliteConnection) -> Result<Vec<Transaction>> {
        transactions::table
            .filter(transactions::confirmations.lt(10))
            .order(transactions::created_at.asc())
            .load(conn)
            .context("Failed to load unconfirmed transactions")
    }

    /// Find all confirmed transactions (confirmations >= 10)
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    ///
    /// # Returns
    ///
    /// Vector of confirmed transactions
    ///
    /// # Errors
    ///
    /// Returns error if database query fails
    pub fn find_confirmed(conn: &mut SqliteConnection) -> Result<Vec<Transaction>> {
        transactions::table
            .filter(transactions::confirmations.ge(10))
            .order(transactions::created_at.desc())
            .load(conn)
            .context("Failed to load confirmed transactions")
    }

    /// Calculate total amount for all transactions in an escrow
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `escrow_id` - Escrow UUID
    ///
    /// # Returns
    ///
    /// Total amount in atomic units (piconeros)
    ///
    /// # Errors
    ///
    /// Returns error if database query fails
    pub fn total_amount_for_escrow(conn: &mut SqliteConnection, escrow_id: String) -> Result<i64> {
        let txs = Self::find_by_escrow(conn, escrow_id)?;
        let total = txs.iter().map(|tx| tx.amount_xmr).sum();
        Ok(total)
    }

    /// Check if transaction is fully confirmed (10+ confirmations)
    pub fn is_confirmed(&self) -> bool {
        self.confirmations >= 10
    }

    /// Convert amount from atomic units to XMR
    pub fn amount_as_xmr(&self) -> f64 {
        self.amount_xmr as f64 / 1_000_000_000_000.0
    }

    /// Validate transaction data
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Amount is negative or zero
    /// - Confirmations is negative
    /// - tx_hash is invalid format (if present)
    pub fn validate(&self) -> Result<()> {
        if self.amount_xmr <= 0 {
            anyhow::bail!(
                "Transaction amount must be positive, got {}",
                self.amount_xmr
            );
        }

        if self.confirmations < 0 {
            anyhow::bail!(
                "Transaction confirmations cannot be negative, got {}",
                self.confirmations
            );
        }

        if let Some(ref hash) = self.tx_hash {
            if hash.len() != 64 {
                anyhow::bail!(
                    "Invalid transaction hash length: expected 64 hex characters, got {}",
                    hash.len()
                );
            }

            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!("Transaction hash must contain only hexadecimal characters");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_conversion() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: Some("a".repeat(64)),
            amount_xmr: 2_500_000_000_000, // 2.5 XMR
            confirmations: 10,
            created_at: chrono::Utc::now().naive_utc(),
        };

        assert_eq!(transaction.amount_as_xmr(), 2.5);
    }

    #[test]
    fn test_is_confirmed() {
        let mut transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: Some("a".repeat(64)),
            amount_xmr: 1_000_000_000_000,
            confirmations: 5,
            created_at: chrono::Utc::now().naive_utc(),
        };

        assert!(!transaction.is_confirmed());

        transaction.confirmations = 10;
        assert!(transaction.is_confirmed());

        transaction.confirmations = 15;
        assert!(transaction.is_confirmed());
    }

    #[test]
    fn test_validation_positive_amount() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: None,
            amount_xmr: 1_000_000_000_000,
            confirmations: 0,
            created_at: chrono::Utc::now().naive_utc(),
        };

        assert!(transaction.validate().is_ok());
    }

    #[test]
    fn test_validation_negative_amount() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: None,
            amount_xmr: -1_000_000_000_000,
            confirmations: 0,
            created_at: chrono::Utc::now().naive_utc(),
        };

        let result = transaction.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be positive"));
    }

    #[test]
    fn test_validation_zero_amount() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: None,
            amount_xmr: 0,
            confirmations: 0,
            created_at: chrono::Utc::now().naive_utc(),
        };

        let result = transaction.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be positive"));
    }

    #[test]
    fn test_validation_negative_confirmations() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: None,
            amount_xmr: 1_000_000_000_000,
            confirmations: -5,
            created_at: chrono::Utc::now().naive_utc(),
        };

        let result = transaction.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot be negative"));
    }

    #[test]
    fn test_validation_valid_tx_hash() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: Some("1234567890abcdef".repeat(4)), // 64 hex chars
            amount_xmr: 1_000_000_000_000,
            confirmations: 10,
            created_at: chrono::Utc::now().naive_utc(),
        };

        assert!(transaction.validate().is_ok());
    }

    #[test]
    fn test_validation_invalid_tx_hash_length() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: Some("1234abcd".to_string()), // Too short
            amount_xmr: 1_000_000_000_000,
            confirmations: 10,
            created_at: chrono::Utc::now().naive_utc(),
        };

        let result = transaction.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid transaction hash length"));
    }

    #[test]
    fn test_validation_invalid_tx_hash_characters() {
        let transaction = Transaction {
            id: "test-id".to_string(),
            escrow_id: "escrow-id".to_string(),
            tx_hash: Some("z".repeat(64)), // Invalid hex character
            amount_xmr: 1_000_000_000_000,
            confirmations: 10,
            created_at: chrono::Utc::now().naive_utc(),
        };

        let result = transaction.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("hexadecimal characters"));
    }
}
