//! Round-Robin Multisig Signing Coordinator (v0.43.0) - 100% NON-CUSTODIAL
//!
//! This module coordinates round-robin signing for 2-of-3 multisig WITHOUT
//! ever touching client wallets. The server is a PURE DATA RELAY.
//!
//! ## Non-Custodial Architecture
//!
//! The server NEVER calls wallet RPC methods. All wallet operations are
//! performed by clients on their LOCAL wallets:
//!
//! ```text
//! Client A (local wallet) → creates multisig_txset → Server (stores) → Client B
//! Client B (local wallet) → signs → partial_signed_txset → Server → Client A
//! Client A (local wallet) → signs → broadcasts to daemon
//! Client A → confirms tx_hash → Server (marks complete)
//! ```
//!
//! ## Problem Solved
//!
//! In 2-of-3 multisig, each participant holds 2 of 3 sub-keys:
//! - Vendor: k1 + k2
//! - Buyer:  k2 + k3
//! - Arbiter: k1 + k3
//!
//! When Vendor + Buyer sign in parallel: (k1+k2) + (k2+k3) = k1 + 2*k2 + k3
//! The k2 sub-key is DOUBLE-COUNTED, causing CLSAG verification to fail.
//!
//! Monero's native `sign_multisig` handles this correctly when used in
//! round-robin (sequential) fashion - each client calls it on their LOCAL wallet.

use anyhow::{Context, Result};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::models::escrow::Escrow;
use crate::schema::escrows;

/// Signing round states
pub const SIGNING_NOT_STARTED: i32 = 0;
pub const SIGNING_TXSET_SUBMITTED: i32 = 1;
pub const SIGNING_FIRST_SIGNED: i32 = 2;
pub const SIGNING_COMPLETE: i32 = 3;

/// Signing status for UI display and client coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningStatus {
    pub phase: String,
    pub current_signer: Option<String>,
    pub round: i32,
    pub is_complete: bool,
    pub tx_hash: Option<String>,
    /// Data for current signer to sign (multisig_txset or partial_signed_txset)
    pub data_to_sign: Option<String>,
    pub destination_address: Option<String>,
    pub amount: Option<i64>,
}

/// Round-robin signing coordinator (100% NON-CUSTODIAL)
///
/// This coordinator ONLY stores and relays data between clients.
/// It NEVER calls wallet RPC methods or touches private keys.
pub struct RoundRobinCoordinator;

impl RoundRobinCoordinator {
    /// Initialize round-robin signing
    pub fn initialize(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
        destination_address: &str,
        first_signer_id: &str,
        first_signer_role: &str,
    ) -> Result<()> {
        let escrow: Escrow = escrows::table
            .filter(escrows::id.eq(escrow_id))
            .first(conn)
            .context("Escrow not found")?;

        // Allow: funded (normal), ready_to_release, disputed (arbiter resolution)
        if escrow.status != "funded" && escrow.status != "ready_to_release" && escrow.status != "disputed" {
            anyhow::bail!("Escrow must be funded or disputed. Current: {}", escrow.status);
        }

        if escrow.signing_round.unwrap_or(0) > 0 {
            anyhow::bail!("Signing already in progress");
        }

        let now = chrono::Utc::now().to_rfc3339();

        // Store destination based on role
        if first_signer_role == "vendor" {
            diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
                .set((
                    escrows::signing_round.eq(SIGNING_NOT_STARTED),
                    escrows::current_signer_id.eq(first_signer_id),
                    escrows::first_signer_role.eq(Some(first_signer_role)),
                    escrows::signing_initiated_at.eq(&now),
                    escrows::status.eq("round_robin_signing"),
                    escrows::vendor_payout_address.eq(Some(destination_address)),
                ))
                .execute(conn)?;
        } else {
            diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
                .set((
                    escrows::signing_round.eq(SIGNING_NOT_STARTED),
                    escrows::current_signer_id.eq(first_signer_id),
                    escrows::first_signer_role.eq(Some(first_signer_role)),
                    escrows::signing_initiated_at.eq(&now),
                    escrows::status.eq("round_robin_signing"),
                    escrows::buyer_refund_address.eq(Some(destination_address)),
                ))
                .execute(conn)?;
        }

        info!(
            escrow_id = %escrow_id,
            first_signer = %first_signer_id,
            "[ROUND-ROBIN-NC] Initialized - client must create TX locally"
        );

        Ok(())
    }

    /// Submit unsigned multisig_txset from first signer
    pub fn submit_multisig_txset(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
        signer_id: &str,
        multisig_txset: &str,
    ) -> Result<String> {
        let escrow: Escrow = escrows::table
            .filter(escrows::id.eq(escrow_id))
            .first(conn)
            .context("Escrow not found")?;

        if escrow.current_signer_id.as_ref() != Some(&signer_id.to_string()) {
            anyhow::bail!("Not your turn");
        }

        if escrow.signing_round.unwrap_or(-1) != SIGNING_NOT_STARTED {
            anyhow::bail!("Wrong signing phase");
        }

        // Determine second signer based on dispute_signing_pair or happy path
        let second_signer_id = if let Some(ref pair) = escrow.dispute_signing_pair {
            // Dispute resolution: arbiter is always the second signer
            match pair.as_str() {
                "arbiter_buyer" | "arbiter_vendor" => escrow.arbiter_id.clone(),
                _ => {
                    // Fallback to happy path logic
                    let first_role = escrow.first_signer_role.as_deref().unwrap_or("vendor");
                    if first_role == "vendor" {
                        escrow.buyer_id.clone()
                    } else {
                        escrow.vendor_id.clone()
                    }
                }
            }
        } else {
            // Happy path: vendor/buyer pair
            let first_role = escrow.first_signer_role.as_deref().unwrap_or("vendor");
            if first_role == "vendor" {
                escrow.buyer_id.clone()
            } else {
                escrow.vendor_id.clone()
            }
        };

        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set((
                escrows::multisig_txset.eq(multisig_txset),
                escrows::signing_round.eq(SIGNING_TXSET_SUBMITTED),
                escrows::current_signer_id.eq(&second_signer_id),
            ))
            .execute(conn)?;

        info!(
            escrow_id = %escrow_id,
            next = %second_signer_id,
            "[ROUND-ROBIN-NC] Txset received - waiting for second signer"
        );

        Ok(second_signer_id)
    }

    /// Submit partial signature from second signer
    pub fn submit_partial_signature(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
        signer_id: &str,
        partial_signed_txset: &str,
    ) -> Result<String> {
        let escrow: Escrow = escrows::table
            .filter(escrows::id.eq(escrow_id))
            .first(conn)
            .context("Escrow not found")?;

        if escrow.current_signer_id.as_ref() != Some(&signer_id.to_string()) {
            anyhow::bail!("Not your turn");
        }

        if escrow.signing_round.unwrap_or(-1) != SIGNING_TXSET_SUBMITTED {
            anyhow::bail!("Wrong signing phase");
        }

        let first_role = escrow.first_signer_role.as_deref().unwrap_or("vendor");
        let first_signer_id = if first_role == "vendor" {
            escrow.vendor_id.clone()
        } else {
            escrow.buyer_id.clone()
        };

        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set((
                escrows::partial_signed_txset.eq(partial_signed_txset),
                escrows::signing_round.eq(SIGNING_FIRST_SIGNED),
                escrows::current_signer_id.eq(&first_signer_id),
            ))
            .execute(conn)?;

        info!(
            escrow_id = %escrow_id,
            next = %first_signer_id,
            "[ROUND-ROBIN-NC] Partial sig received - waiting for completion"
        );

        Ok(first_signer_id)
    }

    /// Confirm broadcast with tx_hash
    pub fn confirm_broadcast(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
        signer_id: &str,
        tx_hash: &str,
    ) -> Result<()> {
        let escrow: Escrow = escrows::table
            .filter(escrows::id.eq(escrow_id))
            .first(conn)
            .context("Escrow not found")?;

        if signer_id != escrow.buyer_id
            && signer_id != escrow.vendor_id
            && signer_id != escrow.arbiter_id
        {
            anyhow::bail!("Not authorized");
        }

        if escrow.signing_round.unwrap_or(-1) != SIGNING_FIRST_SIGNED {
            anyhow::bail!("Wrong signing phase");
        }

        if tx_hash.len() != 64 {
            anyhow::bail!("Invalid tx_hash format");
        }

        let final_status = if escrow.vendor_payout_address.is_some() {
            "completed"
        } else {
            "refunded"
        };

        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set((
                escrows::broadcast_tx_hash.eq(tx_hash),
                escrows::transaction_hash.eq(tx_hash),
                escrows::signing_round.eq(SIGNING_COMPLETE),
                escrows::current_signer_id.eq(None::<String>),
                escrows::status.eq(final_status),
            ))
            .execute(conn)?;

        info!(
            escrow_id = %escrow_id,
            tx_hash = %tx_hash,
            "[ROUND-ROBIN-NC] ✅ Broadcast confirmed!"
        );

        Ok(())
    }

    /// Get signing status (includes data_to_sign for client)
    pub fn get_status(escrow: &Escrow) -> SigningStatus {
        let round = escrow.signing_round.unwrap_or(-1);

        let (phase, data_to_sign) = match round {
            SIGNING_NOT_STARTED => ("waiting_for_txset".to_string(), None),
            SIGNING_TXSET_SUBMITTED => (
                "waiting_for_second_signature".to_string(),
                escrow.multisig_txset.clone(),
            ),
            SIGNING_FIRST_SIGNED => (
                "waiting_for_completion".to_string(),
                escrow.partial_signed_txset.clone(),
            ),
            SIGNING_COMPLETE => ("completed".to_string(), None),
            _ => ("not_started".to_string(), None),
        };

        SigningStatus {
            phase,
            current_signer: escrow.current_signer_id.clone(),
            round,
            is_complete: round == SIGNING_COMPLETE,
            tx_hash: escrow.broadcast_tx_hash.clone(),
            data_to_sign,
            destination_address: escrow.vendor_payout_address.clone()
                .or_else(|| escrow.buyer_refund_address.clone()),
            amount: Some(escrow.amount),
        }
    }
}
