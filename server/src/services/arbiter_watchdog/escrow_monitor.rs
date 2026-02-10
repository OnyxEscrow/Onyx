//! Escrow Monitor - Polls for escrows awaiting arbiter action
//!
//! Queries the database for escrows that:
//! - Have status 'active' or 'funded' (signing in progress)
//! - Have at least one party signature but not arbiter
//! - Are NOT in disputed state (those go to human arbiter)

use anyhow::{Context, Result};
use diesel::prelude::*;
use std::time::Duration;
use tracing::{debug, info};

use crate::db::DbPool;
use crate::models::escrow::Escrow;
use crate::schema::escrows;

/// EscrowMonitor polls the database for escrows awaiting arbiter action
pub struct EscrowMonitor {
    db_pool: DbPool,
    poll_interval: Duration,
}

impl EscrowMonitor {
    /// Create a new EscrowMonitor
    ///
    /// # Arguments
    /// * `db_pool` - Database connection pool
    /// * `poll_interval` - How often to poll for pending escrows
    pub fn new(db_pool: DbPool, poll_interval: Duration) -> Self {
        Self {
            db_pool,
            poll_interval,
        }
    }

    /// Poll for escrows awaiting arbiter action
    ///
    /// Returns escrows where:
    /// - frost_enabled = true (using FROST threshold signing)
    /// - frost_dkg_complete = true (DKG finished, ready for signing)
    /// - signing_round >= 1 (at least one party has signed)
    /// - arbiter_frost_partial_sig IS NULL (arbiter hasn't signed yet)
    /// - status NOT IN ('completed', 'refunded', 'cancelled', 'expired')
    /// - OR status = 'disputed' with dispute_signing_pair set (arbiter resolved, needs auto-sign)
    pub async fn poll_pending_escrows(&self) -> Result<Vec<Escrow>> {
        let db_pool = self.db_pool.clone();

        let escrows = tokio::task::spawn_blocking(move || {
            let mut conn = db_pool.get().context("Failed to get DB connection")?;

            // Query for escrows awaiting arbiter signature
            // These are escrows where:
            // 1. FROST is enabled and DKG is complete
            // 2. At least one party has initiated signing (signing_round >= 1)
            // 3. Arbiter hasn't signed yet
            // 4. Not in terminal state
            // 5. If disputed, only include if dispute_signing_pair is set (arbiter already decided)
            let pending_escrows: Vec<Escrow> = escrows::table
                .filter(escrows::frost_enabled.eq(true))
                .filter(escrows::frost_dkg_complete.eq(true))
                .filter(escrows::arbiter_frost_partial_sig.is_null())
                .filter(escrows::status.ne("completed"))
                .filter(escrows::status.ne("refunded"))
                .filter(escrows::status.ne("cancelled"))
                .filter(escrows::status.ne("expired"))
                .filter(
                    // Normal flow: signing_round >= 1 (at least one party signed)
                    // Dispute flow: dispute_signing_pair set (arbiter decided, skip signing_round check)
                    escrows::signing_round
                        .ge(1)
                        .or(escrows::dispute_signing_pair.is_not_null()),
                )
                .filter(
                    // Non-disputed escrows OR disputed with arbiter decision recorded
                    escrows::status
                        .ne("disputed")
                        .or(escrows::dispute_signing_pair.is_not_null()),
                )
                .load(&mut conn)
                .context("Failed to query pending escrows")?;

            Ok::<Vec<Escrow>, anyhow::Error>(pending_escrows)
        })
        .await
        .context("Task join error")??;

        if !escrows.is_empty() {
            debug!(
                count = escrows.len(),
                "Found escrows awaiting arbiter action"
            );
        }

        Ok(escrows)
    }

    /// Poll for escrows that have both party signatures and are ready for arbiter auto-sign
    ///
    /// More specific query for auto-signing scenarios:
    /// - buyer_release_requested = true AND vendor has signed (release flow)
    /// - vendor_refund_requested = true AND buyer has signed (refund flow)
    pub async fn poll_auto_signable_escrows(&self) -> Result<Vec<Escrow>> {
        let db_pool = self.db_pool.clone();

        let escrows = tokio::task::spawn_blocking(move || {
            let mut conn = db_pool.get().context("Failed to get DB connection")?;

            // Query for escrows eligible for auto-signing
            // Either: buyer requested release AND vendor signed
            // Or: vendor requested refund AND buyer signed
            let signable_escrows: Vec<Escrow> = escrows::table
                .filter(escrows::frost_enabled.eq(true))
                .filter(escrows::frost_dkg_complete.eq(true))
                .filter(escrows::arbiter_frost_partial_sig.is_null())
                .filter(escrows::status.ne("completed"))
                .filter(escrows::status.ne("refunded"))
                .filter(escrows::status.ne("cancelled"))
                .filter(escrows::status.ne("disputed"))
                .filter(
                    // Release case: buyer approved release AND vendor has signed
                    escrows::buyer_release_requested
                        .eq(true)
                        .and(escrows::vendor_signature.is_not_null())
                        // Refund case: vendor approved refund AND buyer has signed
                        .or(escrows::vendor_refund_requested
                            .eq(true)
                            .and(escrows::buyer_signature.is_not_null())),
                )
                .load(&mut conn)
                .context("Failed to query auto-signable escrows")?;

            Ok::<Vec<Escrow>, anyhow::Error>(signable_escrows)
        })
        .await
        .context("Task join error")??;

        if !escrows.is_empty() {
            info!(
                count = escrows.len(),
                "Found escrows eligible for auto-signing"
            );
        }

        Ok(escrows)
    }

    /// Poll for disputed escrows that need human arbiter attention
    ///
    /// Returns escrows where:
    /// - status = 'disputed'
    /// - escalated_to_human = false (not yet escalated)
    pub async fn poll_disputed_escrows(&self) -> Result<Vec<Escrow>> {
        let db_pool = self.db_pool.clone();

        let escrows = tokio::task::spawn_blocking(move || {
            let mut conn = db_pool.get().context("Failed to get DB connection")?;

            let disputed_escrows: Vec<Escrow> = escrows::table
                .filter(escrows::status.eq("disputed"))
                .filter(escrows::escalated_to_human.eq(false))
                .load(&mut conn)
                .context("Failed to query disputed escrows")?;

            Ok::<Vec<Escrow>, anyhow::Error>(disputed_escrows)
        })
        .await
        .context("Task join error")??;

        if !escrows.is_empty() {
            info!(
                count = escrows.len(),
                "Found disputed escrows needing human arbiter"
            );
        }

        Ok(escrows)
    }

    /// Get poll interval
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_creation() {
        // Just verify struct can be created (actual testing requires DB)
        let _duration = Duration::from_secs(30);
        // Cannot test without actual DB pool
    }
}
