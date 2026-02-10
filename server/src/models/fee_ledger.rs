//! Fee Ledger model for tracking escrow fee distributions
//!
//! Records every fee event: platform fees, client splits, refunds.

use anyhow::{Context, Result};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::fee_ledger;

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = fee_ledger)]
pub struct FeeLedgerEntry {
    pub id: String,
    pub escrow_id: String,
    pub client_id: Option<String>,
    pub fee_type: String,
    pub amount_atomic: i64,
    pub tx_hash: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = fee_ledger)]
pub struct NewFeeLedgerEntry {
    pub id: String,
    pub escrow_id: String,
    pub client_id: Option<String>,
    pub fee_type: String,
    pub amount_atomic: i64,
    pub tx_hash: Option<String>,
    pub created_at: String,
}

impl FeeLedgerEntry {
    pub fn create(conn: &mut SqliteConnection, new: NewFeeLedgerEntry) -> Result<Self> {
        let entry_id = new.id.clone();
        diesel::insert_into(fee_ledger::table)
            .values(&new)
            .execute(conn)
            .context("Failed to insert fee ledger entry")?;
        fee_ledger::table
            .find(entry_id)
            .first(conn)
            .context("Failed to retrieve created fee ledger entry")
    }

    pub fn find_by_escrow(conn: &mut SqliteConnection, escrow_id: &str) -> Result<Vec<Self>> {
        fee_ledger::table
            .filter(fee_ledger::escrow_id.eq(escrow_id))
            .order(fee_ledger::created_at.desc())
            .load(conn)
            .context("Failed to query fee ledger by escrow")
    }

    pub fn find_by_client(conn: &mut SqliteConnection, client_id: &str) -> Result<Vec<Self>> {
        fee_ledger::table
            .filter(fee_ledger::client_id.eq(client_id))
            .order(fee_ledger::created_at.desc())
            .load(conn)
            .context("Failed to query fee ledger by client")
    }

    pub fn sum_by_client(conn: &mut SqliteConnection, client_id: &str) -> Result<i64> {
        let results: Vec<i64> = fee_ledger::table
            .filter(fee_ledger::client_id.eq(client_id))
            .select(fee_ledger::amount_atomic)
            .load::<i64>(conn)
            .context("Failed to query fees for client")?;
        Ok(results.iter().sum())
    }

    pub fn new_platform_fee(
        escrow_id: &str,
        amount_atomic: i64,
        tx_hash: Option<&str>,
    ) -> NewFeeLedgerEntry {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        NewFeeLedgerEntry {
            id: Uuid::new_v4().to_string(),
            escrow_id: escrow_id.to_string(),
            client_id: None,
            fee_type: "platform".to_string(),
            amount_atomic,
            tx_hash: tx_hash.map(|s| s.to_string()),
            created_at: now,
        }
    }

    pub fn new_client_fee(
        escrow_id: &str,
        client_id: &str,
        amount_atomic: i64,
        tx_hash: Option<&str>,
    ) -> NewFeeLedgerEntry {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        NewFeeLedgerEntry {
            id: Uuid::new_v4().to_string(),
            escrow_id: escrow_id.to_string(),
            client_id: Some(client_id.to_string()),
            fee_type: "client".to_string(),
            amount_atomic,
            tx_hash: tx_hash.map(|s| s.to_string()),
            created_at: now,
        }
    }
}
