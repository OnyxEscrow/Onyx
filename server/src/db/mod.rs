use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, CustomizeConnection};
use diesel::sql_query;
use uuid::Uuid;

use crate::models::escrow::{Escrow, NewEscrow};
use crate::models::transaction::{NewTransaction, Transaction};
use crate::schema::escrows;
use monero_marketplace_common::types::MultisigInfo;

pub mod manager;
pub use manager::{DatabaseConfig, DatabaseManager};

pub type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

/// Custom connection customizer that sets the SQLCipher encryption key
#[derive(Debug, Clone)]
struct SqlCipherConnectionCustomizer {
    encryption_key: String,
}

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for SqlCipherConnectionCustomizer {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        // NOTE: SQLCipher encryption enabled for v0.4.0-mainnet
        // Uses soft encryption (non-breaking): encrypts new writes, reads existing unencrypted data
        // See: docs/SQLCIPHER-MONITORING.md for encryption progress tracking
        // See: docs/BACKUP-SYSTEM.md Phase 3 for encryption monitoring strategy

        // Set SQLCipher key using raw SQL for database encryption
        // This must be the first PRAGMA executed on each connection
        // IMPORTANT: Backup system ensures data recovery if encryption fails
        // SKIP encryption if key is empty (allows unencrypted databases for dev/testing)
        if !self.encryption_key.is_empty() {
            sql_query(format!("PRAGMA key = '{}';", self.encryption_key))
                .execute(conn)
                .map_err(diesel::r2d2::Error::QueryError)?;
        }

        // Disable foreign key enforcement for EaaS (standalone escrows without orders)
        // The orders table FK is legacy from marketplace era
        sql_query("PRAGMA foreign_keys = OFF;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        // Use DELETE journal mode for SQLCipher compatibility
        // WAL mode has issues with encrypted databases - writes may not persist
        // DELETE mode is slower but reliable with SQLCipher
        sql_query("PRAGMA journal_mode = DELETE;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        // Wait up to 5 seconds for locks instead of failing immediately
        sql_query("PRAGMA busy_timeout = 5000;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        // Balance between safety and performance with WAL mode
        // For now keep NORMAL mode to ensure backup system stability
        // Will upgrade to FULL when encryption is enabled
        sql_query("PRAGMA synchronous = NORMAL;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        // 64MB cache to reduce disk I/O and lock contention
        sql_query("PRAGMA cache_size = -64000;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        // Use RAM for temporary tables/indexes
        sql_query("PRAGMA temp_store = MEMORY;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        // Verify encryption is working by checking we can read from sqlite_master
        // This will fail if the encryption key is wrong or database is corrupted
        sql_query("SELECT count(*) FROM sqlite_master;")
            .execute(conn)
            .map_err(diesel::r2d2::Error::QueryError)?;

        Ok(())
    }
}

/// Create a database connection pool with SQLCipher encryption
///
/// # Arguments
/// * `database_url` - Path to the SQLite database file
/// * `encryption_key` - Encryption key for SQLCipher (must be non-empty for production)
///
/// # Security
/// - Uses SQLCipher for at-rest encryption
/// - Key is applied to every connection in the pool
/// - Empty keys are rejected in production builds
pub fn create_pool(database_url: &str, encryption_key: &str) -> Result<DbPool> {
    // In production, require non-empty encryption key
    // UNLESS ALLOW_UNENCRYPTED_DB=1 is set (for development/testing with existing unencrypted DBs)
    #[cfg(not(debug_assertions))]
    {
        let allow_unencrypted = std::env::var("ALLOW_UNENCRYPTED_DB")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

        if encryption_key.is_empty() && !allow_unencrypted {
            anyhow::bail!("Encryption key cannot be empty in production mode");
        }
    }

    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let customizer = SqlCipherConnectionCustomizer {
        encryption_key: encryption_key.to_string(),
    };

    let pool = r2d2::Pool::builder()
        .max_size(30) // Increased from 10 to support parallel escrow monitoring
        .connection_timeout(std::time::Duration::from_secs(30))
        .connection_customizer(Box::new(customizer))
        .build(manager)
        .context("Failed to create database connection pool")?;

    Ok(pool)
}

pub async fn db_insert_escrow(pool: &DbPool, new_escrow: NewEscrow) -> Result<Escrow> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    let escrow_id = new_escrow.id.to_string();
    tokio::task::spawn_blocking(move || {
        diesel::insert_into(escrows::table)
            .values(&new_escrow)
            .execute(&mut conn)
            .map_err(|e| {
                tracing::error!("Database insert error for escrow {}: {:?}", escrow_id, e);
                anyhow::anyhow!("Failed to insert escrow: {}", e)
            })?;

        escrows::table
            .filter(escrows::id.eq(escrow_id.clone()))
            .first(&mut conn)
            .map_err(|e| {
                tracing::error!("Failed to retrieve escrow {} after insert: {:?}", escrow_id, e);
                anyhow::anyhow!("Failed to retrieve created escrow: {}", e)
            })
    })
    .await?
}

pub async fn db_load_escrow(pool: &DbPool, escrow_id: Uuid) -> Result<Escrow> {
    db_load_escrow_by_str(pool, &escrow_id.to_string()).await
}

pub async fn db_load_escrow_by_str(pool: &DbPool, escrow_id: &str) -> Result<Escrow> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    let id = escrow_id.to_string();
    tokio::task::spawn_blocking(move || {
        escrows::table
            .filter(escrows::id.eq(&id))
            .first(&mut conn)
            .context(format!("Escrow with ID {} not found", id))
    })
    .await?
}

pub async fn db_update_escrow_address(pool: &DbPool, escrow_id: Uuid, address: &str) -> Result<()> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    let address_clone = address.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.to_string())))
            .set(escrows::multisig_address.eq(address_clone))
            .execute(&mut conn)
            .context(format!("Failed to update escrow {} address", escrow_id))
    })
    .await?;
    Ok(())
}

pub async fn db_update_escrow_status(pool: &DbPool, escrow_id: Uuid, status: &str) -> Result<()> {
    db_update_escrow_status_by_str(pool, &escrow_id.to_string(), status).await
}

pub async fn db_update_escrow_status_by_str(pool: &DbPool, escrow_id: &str, status: &str) -> Result<()> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    let status_clone = status.to_string();
    let id = escrow_id.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        diesel::update(escrows::table.filter(escrows::id.eq(&id)))
            .set(escrows::status.eq(status_clone))
            .execute(&mut conn)
            .context(format!("Failed to update escrow {} status", id))
    })
    .await?;
    Ok(())
}

pub async fn db_update_escrow_transaction_hash(
    pool: &DbPool,
    escrow_id: Uuid,
    tx_hash: &str,
) -> Result<()> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    let tx_hash_clone = tx_hash.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.to_string())))
            .set(escrows::transaction_hash.eq(tx_hash_clone))
            .execute(&mut conn)
            .context(format!(
                "Failed to update escrow {} transaction_hash",
                escrow_id
            ))
    })
    .await?;
    Ok(())
}

pub async fn db_update_ring_data_json(
    pool: &DbPool,
    escrow_id: Uuid,
    ring_data_json: &str,
) -> Result<()> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    let json_clone = ring_data_json.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.to_string())))
            .set(escrows::ring_data_json.eq(json_clone))
            .execute(&mut conn)
            .context(format!(
                "Failed to update escrow {} ring_data_json",
                escrow_id
            ))
    })
    .await?;
    Ok(())
}

pub async fn db_store_multisig_info(
    pool: &DbPool,
    escrow_id: Uuid,
    party: &str,
    info: Vec<u8>,
) -> Result<()> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    let info_clone = info.clone();
    let party_clone = party.to_string();
    tokio::task::spawn_blocking(move || {
        match party_clone.as_str() {
            "buyer" => diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.to_string())))
                .set(escrows::buyer_wallet_info.eq(info_clone))
                .execute(&mut conn),
            "vendor" => {
                diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.to_string())))
                    .set(escrows::vendor_wallet_info.eq(info_clone))
                    .execute(&mut conn)
            }
            "arbiter" => {
                diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.to_string())))
                    .set(escrows::arbiter_wallet_info.eq(info_clone))
                    .execute(&mut conn)
            }
            _ => return Err(anyhow::anyhow!("Invalid party for multisig info")),
        }
        .context(format!(
            "Failed to store multisig info for escrow {} party {}",
            escrow_id, party_clone
        ))
    })
    .await??;
    Ok(())
}

pub async fn db_count_multisig_infos(pool: &DbPool, escrow_id: Uuid) -> Result<i64> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || {
        let escrow = escrows::table
            .filter(escrows::id.eq(escrow_id.to_string()))
            .first::<Escrow>(&mut conn)
            .context(format!("Escrow with ID {} not found", escrow_id))?;

        let mut count = 0;
        if escrow.buyer_wallet_info.is_some() {
            count += 1;
        }
        if escrow.vendor_wallet_info.is_some() {
            count += 1;
        }
        if escrow.arbiter_wallet_info.is_some() {
            count += 1;
        }
        Ok(count)
    })
    .await?
}

pub async fn db_load_multisig_infos(pool: &DbPool, escrow_id: Uuid) -> Result<Vec<MultisigInfo>> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || {
        let escrow = escrows::table
            .filter(escrows::id.eq(escrow_id.to_string()))
            .first::<Escrow>(&mut conn)
            .context(format!("Escrow with ID {} not found", escrow_id))?;

        let mut infos = Vec::new();
        if let Some(info) = escrow.buyer_wallet_info {
            infos.push(MultisigInfo {
                multisig_info: String::from_utf8(info)?,
            });
        }
        if let Some(info) = escrow.vendor_wallet_info {
            infos.push(MultisigInfo {
                multisig_info: String::from_utf8(info)?,
            });
        }
        if let Some(info) = escrow.arbiter_wallet_info {
            infos.push(MultisigInfo {
                multisig_info: String::from_utf8(info)?,
            });
        }
        Ok(infos)
    })
    .await?
}

// ============================================================================
// Transaction Database Operations
// ============================================================================

/// Create a new transaction record in the database
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `new_transaction` - New transaction data
///
/// # Returns
///
/// The created transaction with timestamp populated
///
/// # Errors
///
/// Returns error if database insertion or retrieval fails
pub async fn db_create_transaction(
    pool: &DbPool,
    new_transaction: NewTransaction,
) -> Result<Transaction> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || Transaction::create(&mut conn, new_transaction)).await?
}

/// Find transaction by ID
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `transaction_id` - Transaction UUID string
///
/// # Errors
///
/// Returns error if transaction not found or database query fails
pub async fn db_find_transaction(pool: &DbPool, transaction_id: String) -> Result<Transaction> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || Transaction::find_by_id(&mut conn, transaction_id)).await?
}

/// Find transaction by Monero transaction hash
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `tx_hash` - Monero transaction hash (64 hex characters)
///
/// # Errors
///
/// Returns error if transaction not found or database query fails
pub async fn db_find_transaction_by_hash(pool: &DbPool, tx_hash: String) -> Result<Transaction> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || Transaction::find_by_tx_hash(&mut conn, &tx_hash)).await?
}

/// Find all transactions for a specific escrow
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `escrow_id` - Escrow UUID string
///
/// # Returns
///
/// Vector of transactions ordered by creation time (oldest first)
///
/// # Errors
///
/// Returns error if database query fails
pub async fn db_find_transactions_by_escrow(
    pool: &DbPool,
    escrow_id: String,
) -> Result<Vec<Transaction>> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || Transaction::find_by_escrow(&mut conn, escrow_id)).await?
}

/// Update transaction confirmation count
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `transaction_id` - Transaction UUID string
/// * `confirmations` - New confirmation count
///
/// # Returns
///
/// Updated transaction
///
/// # Errors
///
/// Returns error if transaction not found or database update fails
pub async fn db_update_transaction_confirmations(
    pool: &DbPool,
    transaction_id: String,
    confirmations: i32,
) -> Result<Transaction> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || {
        Transaction::update_confirmations(&mut conn, transaction_id, confirmations)
    })
    .await?
}

/// Set transaction hash for a transaction
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `transaction_id` - Transaction UUID string
/// * `tx_hash` - Monero transaction hash
///
/// # Returns
///
/// Updated transaction
///
/// # Errors
///
/// Returns error if:
/// - Transaction not found
/// - Transaction already has a hash set
/// - Database update fails
pub async fn db_set_transaction_hash(
    pool: &DbPool,
    transaction_id: String,
    tx_hash: String,
) -> Result<Transaction> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || {
        Transaction::set_tx_hash(&mut conn, transaction_id, tx_hash)
    })
    .await?
}

/// Find all unconfirmed transactions (confirmations < 10)
///
/// # Arguments
///
/// * `pool` - Database connection pool
///
/// # Returns
///
/// Vector of unconfirmed transactions
///
/// # Errors
///
/// Returns error if database query fails
pub async fn db_find_unconfirmed_transactions(pool: &DbPool) -> Result<Vec<Transaction>> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || Transaction::find_unconfirmed(&mut conn)).await?
}

/// Find all confirmed transactions (confirmations >= 10)
///
/// # Arguments
///
/// * `pool` - Database connection pool
///
/// # Returns
///
/// Vector of confirmed transactions
///
/// # Errors
///
/// Returns error if database query fails
pub async fn db_find_confirmed_transactions(pool: &DbPool) -> Result<Vec<Transaction>> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || Transaction::find_confirmed(&mut conn)).await?
}

/// Calculate total transaction amount for an escrow
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `escrow_id` - Escrow UUID string
///
/// # Returns
///
/// Total amount in atomic units (piconeros)
///
/// # Errors
///
/// Returns error if database query fails
pub async fn db_transaction_total_for_escrow(pool: &DbPool, escrow_id: String) -> Result<i64> {
    let mut conn = pool.get().context("Failed to get DB connection")?;
    tokio::task::spawn_blocking(move || Transaction::total_amount_for_escrow(&mut conn, escrow_id))
        .await?
}

// Note: Reputation module removed during EaaS transformation (marketplace feature)
