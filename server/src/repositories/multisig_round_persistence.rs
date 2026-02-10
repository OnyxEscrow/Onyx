//! Phase 1.6: Atomic Multisig Round State Persistence
//!
//! # Critical Purpose
//! Prevents loss of multisig progress on crashes by persisting state after EACH round.
//!
//! # The Problem This Solves
//! - Crash after Round 1 complete → Without persistence, restart from Round 0
//! - Creates infinite loop: crash → restart → Round 1 → crash
//! - Loss of cryptographic material generated during prepare_multisig()
//!
//! # Solution: Atomic Persistence + Recovery
//! 1. Mark round as "in_progress" BEFORE RPC call
//! 2. Execute multisig RPC operation
//! 3. Mark round as "completed" AFTER successful RPC
//! 4. On restart: Check DB → Skip completed rounds → Resume at next round

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::db::DbPool;
use crate::schema::multisig_round_state;

/// Status of a multisig round
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RoundStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl RoundStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            _ => Self::Pending,
        }
    }
}

/// Diesel model for multisig_round_state table
#[derive(Debug, Clone, Queryable, Identifiable, Selectable)]
#[diesel(table_name = multisig_round_state)]
pub struct MultisigRoundState {
    pub id: i32,
    pub escrow_id: String,
    pub round_number: i32,
    pub status: String,
    pub rpc_url: String,
    pub wallet_filename: String,
    pub role: String,
    pub multisig_info: Option<String>,
    pub started_at: NaiveDateTime,
    pub completed_at: Option<NaiveDateTime>,
    pub last_error: Option<String>,
}

/// Insertable model
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = multisig_round_state)]
pub struct NewMultisigRoundState {
    pub escrow_id: String,
    pub round_number: i32,
    pub status: String,
    pub rpc_url: String,
    pub wallet_filename: String,
    pub role: String,
    pub multisig_info: Option<String>,
    pub last_error: Option<String>,
}

/// Repository for atomic multisig state persistence
pub struct MultisigRoundPersistence {
    pool: Arc<DbPool>,
}

impl MultisigRoundPersistence {
    pub fn new(pool: Arc<DbPool>) -> Self {
        info!("🗄️  MultisigRoundPersistence initialized (Phase 1.6)");
        Self { pool }
    }

    /// Mark round as IN_PROGRESS before RPC call
    pub fn mark_round_started(
        &self,
        escrow_id: Uuid,
        round: i32,
        rpc_url: &str,
        wallet_filename: &str,
        role: &str,
    ) -> Result<()> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;

        let new_state = NewMultisigRoundState {
            escrow_id: escrow_id.to_string(),
            round_number: round,
            status: RoundStatus::InProgress.as_str().to_string(),
            rpc_url: rpc_url.to_string(),
            wallet_filename: wallet_filename.to_string(),
            role: role.to_string(),
            multisig_info: None,
            last_error: None,
        };

        diesel::insert_into(multisig_round_state::table)
            .values(&new_state)
            .on_conflict((
                multisig_round_state::escrow_id,
                multisig_round_state::round_number,
                multisig_round_state::role,
            ))
            .do_update()
            .set(multisig_round_state::status.eq(RoundStatus::InProgress.as_str()))
            .execute(&mut conn)
            .context("Failed to mark round started")?;

        debug!(escrow_id = %escrow_id, round, role, "📝 Round IN_PROGRESS");
        Ok(())
    }

    /// Mark round as COMPLETED after successful RPC
    pub fn mark_round_completed(
        &self,
        escrow_id: Uuid,
        round: i32,
        role: &str,
        multisig_info_json: Option<String>,
    ) -> Result<()> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        let now = chrono::Utc::now().naive_utc();

        diesel::update(
            multisig_round_state::table
                .filter(multisig_round_state::escrow_id.eq(escrow_id.to_string()))
                .filter(multisig_round_state::round_number.eq(round))
                .filter(multisig_round_state::role.eq(role)),
        )
        .set((
            multisig_round_state::status.eq(RoundStatus::Completed.as_str()),
            multisig_round_state::completed_at.eq(Some(now)),
            multisig_round_state::multisig_info.eq(multisig_info_json),
        ))
        .execute(&mut conn)
        .context("Failed to mark round completed")?;

        info!(escrow_id = %escrow_id, round, role, "✅ Round COMPLETED");
        Ok(())
    }

    /// Mark round as FAILED
    pub fn mark_round_failed(&self, escrow_id: Uuid, round: i32, role: &str, error: &str) -> Result<()> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;

        diesel::update(
            multisig_round_state::table
                .filter(multisig_round_state::escrow_id.eq(escrow_id.to_string()))
                .filter(multisig_round_state::round_number.eq(round))
                .filter(multisig_round_state::role.eq(role)),
        )
        .set((
            multisig_round_state::status.eq(RoundStatus::Failed.as_str()),
            multisig_round_state::last_error.eq(Some(error.to_string())),
        ))
        .execute(&mut conn)
        .context("Failed to mark round failed")?;

        warn!(escrow_id = %escrow_id, round, role, error, "❌ Round FAILED");
        Ok(())
    }

    /// Check if round already completed (recovery logic)
    pub fn is_round_complete(&self, escrow_id: Uuid, round: i32, role: &str) -> Result<bool> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;

        let result: Option<MultisigRoundState> = multisig_round_state::table
            .filter(multisig_round_state::escrow_id.eq(escrow_id.to_string()))
            .filter(multisig_round_state::round_number.eq(round))
            .filter(multisig_round_state::role.eq(role))
            .first(&mut conn)
            .optional()
            .context("Failed to check round completion")?;

        Ok(result.map(|s| s.status == RoundStatus::Completed.as_str()).unwrap_or(false))
    }

    /// Get last completed round for recovery
    pub fn get_last_completed_round(&self, escrow_id: Uuid, role: &str) -> Result<Option<i32>> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;

        let result: Option<i32> = multisig_round_state::table
            .select(multisig_round_state::round_number)
            .filter(multisig_round_state::escrow_id.eq(escrow_id.to_string()))
            .filter(multisig_round_state::role.eq(role))
            .filter(multisig_round_state::status.eq(RoundStatus::Completed.as_str()))
            .order(multisig_round_state::round_number.desc())
            .first(&mut conn)
            .optional()
            .context("Failed to get last completed round")?;

        Ok(result)
    }

    /// Cleanup completed escrows
    pub fn cleanup_completed_escrows(&self, escrow_ids: &[Uuid]) -> Result<usize> {
        let mut conn = self.pool.get().context("Failed to get DB connection")?;
        let escrow_ids_str: Vec<String> = escrow_ids.iter().map(|id| id.to_string()).collect();

        let deleted = diesel::delete(
            multisig_round_state::table.filter(multisig_round_state::escrow_id.eq_any(escrow_ids_str)),
        )
        .execute(&mut conn)
        .context("Failed to cleanup")?;

        info!("🧹 Cleaned up {} round states", deleted);
        Ok(deleted)
    }
}
