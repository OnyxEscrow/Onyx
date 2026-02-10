//! Arbiter Watchdog Service (v0.70.0)
//!
//! Daemon that automatically signs escrow transactions on behalf of the arbiter
//! when both parties have agreed (release or refund). This enables non-custodial
//! escrow to complete without manual arbiter intervention for non-disputed cases.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ARBITER WATCHDOG SERVICE                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │   ┌──────────────────┐    ┌──────────────────┐                 │
//! │   │ EscrowMonitor    │    │ AutoSigningRules │                 │
//! │   │ (Poll DB/Redis)  │───▶│ (Decision Engine)│                 │
//! │   └──────────────────┘    └────────┬─────────┘                 │
//! │                                    │                            │
//! │   ┌────────────────────────────────▼───────────────────┐       │
//! │   │               SigningDecision                       │       │
//! │   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │       │
//! │   │  │ AUTO_RELEASE│  │ AUTO_REFUND │  │ESCALATE_HMN │ │       │
//! │   │  │ (buyer OK)  │  │ (vendor OK) │  │ (dispute)   │ │       │
//! │   │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │       │
//! │   └─────────┼────────────────┼────────────────┼────────┘       │
//! │             │                │                │                 │
//! │   ┌─────────▼────────────────▼────────┐  ┌────▼──────────────┐ │
//! │   │      ArbiterKeyVault              │  │ NotificationSvc   │ │
//! │   │  (Encrypted key_package storage)  │  │ (Telegram/Email)  │ │
//! │   └─────────┬─────────────────────────┘  └───────────────────┘ │
//! │             │                                                   │
//! │   ┌─────────▼─────────────────────────────────────────────────┐│
//! │   │              FrostAutoSigner                               ││
//! │   │  - Compute partial signature (native FROST)                ││
//! │   │  - Store in escrow.arbiter_frost_partial_sig               ││
//! │   │  - Log audit trail                                         ││
//! │   └────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Auto-Signing Rules
//!
//! ### Case: AUTO_RELEASE (Arbiter signs automatically for vendor payout)
//! - escrow.status == "active" OR "funded"
//! - escrow.buyer_release_requested == true
//! - escrow.vendor_signature.is_some() (Vendor already signed)
//! - escrow.status != "disputed"
//!
//! ### Case: AUTO_REFUND (Arbiter signs automatically for buyer refund)
//! - escrow.status == "active" OR "funded"
//! - escrow.vendor_refund_requested == true
//! - escrow.buyer_signature.is_some() (Buyer already signed)
//! - escrow.status != "disputed"
//!
//! ### Case: ESCALATE_HUMAN (Notify human arbiter required)
//! - escrow.status == "disputed"
//! - OR parties disagree (buyer wants release, vendor wants refund)
//! - OR timeout imminent (< 24h before 7-day limit)
//!
//! ## Security Model
//!
//! 1. **Key Storage**: Arbiter FROST key_package is stored in Redis with:
//!    - Argon2id key derivation from master password
//!    - ChaCha20Poly1305 authenticated encryption
//!    - 30-day TTL (escrow lifetime)
//!
//! 2. **Signing Guard**: Watchdog ONLY signs when BOTH parties agree:
//!    - For release: buyer_release_requested AND vendor has signed
//!    - For refund: vendor_refund_requested AND buyer has signed
//!
//! 3. **Dispute Protection**: If status == "disputed", always ESCALATE_HUMAN

pub mod auto_signing_rules;
pub mod config;
pub mod escrow_monitor;
pub mod frost_auto_signer;
pub mod key_vault;
pub mod notification;

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::db::DbPool;
use crate::redis_pool::RedisPool;

pub use auto_signing_rules::{AutoSigningRules, SigningDecision};
pub use config::WatchdogConfig;
pub use escrow_monitor::EscrowMonitor;
pub use frost_auto_signer::FrostAutoSigner;
pub use key_vault::ArbiterKeyVault;
pub use notification::{NotificationChannel, NotificationService};

/// Arbiter Watchdog - Main service coordinator
///
/// Orchestrates the escrow monitoring, decision making, and auto-signing
/// workflow for non-disputed escrow transactions.
pub struct ArbiterWatchdog {
    config: WatchdogConfig,
    pool: DbPool,
    monitor: EscrowMonitor,
    key_vault: ArbiterKeyVault,
    auto_signer: FrostAutoSigner,
    notification_service: NotificationService,
}

impl ArbiterWatchdog {
    /// Create a new ArbiterWatchdog instance
    ///
    /// # Arguments
    /// * `db_pool` - Database connection pool for escrow queries
    /// * `redis_pool` - Redis pool for key storage
    /// * `config` - Watchdog configuration
    pub async fn new(
        db_pool: DbPool,
        redis_pool: RedisPool,
        config: WatchdogConfig,
    ) -> Result<Self> {
        let key_vault = ArbiterKeyVault::new(
            redis_pool.clone(),
            config.vault_master_password.clone(),
        )
        .context("Failed to initialize ArbiterKeyVault")?;

        let auto_signer = FrostAutoSigner::new(key_vault.clone(), db_pool.clone());
        let monitor = EscrowMonitor::new(db_pool.clone(), config.poll_interval);
        let notification_service = NotificationService::from_config(&config)?;

        info!(
            poll_interval_secs = config.poll_interval.as_secs(),
            auto_sign_enabled = config.auto_sign_enabled,
            "ArbiterWatchdog initialized"
        );

        Ok(Self {
            config,
            pool: db_pool,
            monitor,
            key_vault,
            auto_signer,
            notification_service,
        })
    }

    /// Start the watchdog monitoring loop
    ///
    /// This runs indefinitely, polling the database at the configured interval
    /// and processing escrows that require arbiter action.
    pub async fn run(self: Arc<Self>) {
        let mut poll_timer = interval(self.config.poll_interval);

        info!("ArbiterWatchdog starting monitoring loop");

        loop {
            poll_timer.tick().await;

            if let Err(e) = self.process_pending_escrows().await {
                error!(error = %e, "Error processing pending escrows");
            }
        }
    }

    /// Process all escrows awaiting arbiter action
    async fn process_pending_escrows(&self) -> Result<()> {
        // Get escrows that need arbiter signature
        let pending_escrows = self.monitor.poll_pending_escrows().await?;

        if pending_escrows.is_empty() {
            return Ok(());
        }

        info!(count = pending_escrows.len(), "Found escrows awaiting arbiter action");

        for escrow in pending_escrows {
            if let Err(e) = self.process_single_escrow(&escrow).await {
                error!(
                    escrow_id = %escrow.id,
                    error = %e,
                    "Failed to process escrow"
                );
            }
        }

        Ok(())
    }

    /// Process a single escrow and take appropriate action
    async fn process_single_escrow(&self, escrow: &crate::models::escrow::Escrow) -> Result<()> {
        // === FROST SIGNING DETECTION ===
        // Check if FROST-enabled escrow has buyer + vendor signatures ready
        if escrow.frost_enabled {
            if let Ok(mut conn) = self.pool.get() {
                use crate::services::frost_signing_coordinator::FrostSigningCoordinator;

                // Check if signing state exists and both parties submitted
                if let Ok(status) = FrostSigningCoordinator::get_status(&mut conn, &escrow.id) {
                    if status.buyer_partial_submitted
                        && status.vendor_partial_submitted
                        && !status.arbiter_partial_submitted
                        && status.status == "ready_for_aggregation"
                    {
                        info!(
                            escrow_id = %escrow.id,
                            "FROST: Both buyer + vendor signed, arbiter auto-signing..."
                        );

                        // Let the normal decision flow handle arbiter signing
                        let decision = AutoSigningRules::evaluate(escrow);
                        if matches!(decision, SigningDecision::AutoRelease { .. }) {
                            // Arbiter signs (already handled below)
                            // After arbiter signs, trigger aggregation
                            // This will happen in the AutoRelease branch
                        }
                    } else if status.buyer_partial_submitted
                        && status.vendor_partial_submitted
                        && status.arbiter_partial_submitted
                        && status.status == "ready_for_aggregation"
                    {
                        info!(
                            escrow_id = %escrow.id,
                            "FROST: All signatures ready, triggering aggregation..."
                        );

                        // Aggregate and broadcast
                        match FrostSigningCoordinator::aggregate_and_broadcast(&mut conn, &escrow.id)
                            .await
                        {
                            Ok(tx_hash) => {
                                info!(
                                    escrow_id = %escrow.id,
                                    tx_hash = %tx_hash,
                                    "FROST: TX aggregated and broadcasted"
                                );
                                return Ok(());
                            }
                            Err(e) => {
                                error!(
                                    escrow_id = %escrow.id,
                                    error = %e,
                                    "FROST: Aggregation failed"
                                );
                            }
                        }
                    }
                }
            }
        }

        let decision = AutoSigningRules::evaluate(escrow);

        match decision {
            SigningDecision::AutoRelease { escrow_id, vendor_address } => {
                if !self.config.auto_sign_enabled {
                    info!(
                        escrow_id = %escrow_id,
                        "Auto-sign disabled, skipping release"
                    );
                    return Ok(());
                }

                // Dispute resolution uses CLI binary path, not interactive FROST
                if escrow.status == "disputed" && escrow.dispute_signing_pair.is_some() {
                    info!(
                        escrow_id = %escrow_id,
                        "AUTO_RELEASE (dispute): Using CLI broadcast path"
                    );
                    return self.handle_dispute_broadcast(escrow).await;
                }

                info!(
                    escrow_id = %escrow_id,
                    vendor_address_prefix = &vendor_address[..12],
                    "AUTO_RELEASE: Signing for vendor payout"
                );

                self.auto_signer
                    .sign_release(&escrow_id, &vendor_address)
                    .await
                    .context("Failed to auto-sign release")?;

                info!(
                    escrow_id = %escrow_id,
                    "AUTO_RELEASE complete: arbiter partial signature stored"
                );

                // === FROST AGGREGATION TRIGGER ===
                // After arbiter signs, check if we should aggregate
                if escrow.frost_enabled {
                    if let Ok(mut conn) = self.pool.get() {
                        use crate::services::frost_signing_coordinator::FrostSigningCoordinator;

                        match FrostSigningCoordinator::aggregate_and_broadcast(&mut conn, &escrow_id)
                            .await
                        {
                            Ok(tx_hash) => {
                                info!(
                                    escrow_id = %escrow_id,
                                    tx_hash = %tx_hash,
                                    "FROST: TX aggregated and broadcasted after arbiter sign"
                                );
                            }
                            Err(e) => {
                                error!(
                                    escrow_id = %escrow_id,
                                    error = %e,
                                    "FROST: Aggregation failed after arbiter sign"
                                );
                            }
                        }
                    }
                }
            }

            SigningDecision::AutoRefund { escrow_id, buyer_address } => {
                if !self.config.auto_sign_enabled {
                    info!(
                        escrow_id = %escrow_id,
                        "Auto-sign disabled, skipping refund"
                    );
                    return Ok(());
                }

                // Dispute resolution uses CLI binary path, not interactive FROST
                if escrow.status == "disputed" && escrow.dispute_signing_pair.is_some() {
                    info!(
                        escrow_id = %escrow_id,
                        "AUTO_REFUND (dispute): Using CLI broadcast path"
                    );
                    return self.handle_dispute_broadcast(escrow).await;
                }

                info!(
                    escrow_id = %escrow_id,
                    buyer_address_prefix = &buyer_address[..12],
                    "AUTO_REFUND: Signing for buyer refund"
                );

                self.auto_signer
                    .sign_refund(&escrow_id, &buyer_address)
                    .await
                    .context("Failed to auto-sign refund")?;

                info!(
                    escrow_id = %escrow_id,
                    "AUTO_REFUND complete: arbiter partial signature stored"
                );
            }

            SigningDecision::EscalateHuman { escrow_id, reason } => {
                warn!(
                    escrow_id = %escrow_id,
                    reason = %reason,
                    "ESCALATE_HUMAN: Notifying human arbiter"
                );

                self.notification_service
                    .alert_dispute(escrow, &reason)
                    .await
                    .context("Failed to send escalation notification")?;

                info!(
                    escrow_id = %escrow_id,
                    "ESCALATE_HUMAN: Notification sent to human arbiter"
                );
            }

            SigningDecision::NoAction => {
                // Nothing to do
            }
        }

        Ok(())
    }

    /// Handle dispute resolution via CLI binary broadcast
    ///
    /// Unlike the interactive FROST signing flow (used for normal release/refund),
    /// disputes use the `full_offline_broadcast_dispute` CLI binary which:
    /// 1. Takes raw FROST signing shares (arbiter + winner)
    /// 2. Reconstructs the private key via Lagrange interpolation
    /// 3. Signs the CLSAG and broadcasts atomically
    ///
    /// The watchdog's role:
    /// - Extract arbiter's signing share from vault → store in ring_data_json
    /// - If winner's share is also present → call CLI binary → update status
    /// - If winner's share missing → wait (winner must submit via frontend)
    async fn handle_dispute_broadcast(
        &self,
        escrow: &crate::models::escrow::Escrow,
    ) -> Result<()> {
        let escrow_id = &escrow.id;
        let dispute_pair = escrow
            .dispute_signing_pair
            .as_deref()
            .context("dispute_signing_pair not set")?;

        // Step 1: Load ring_data_json and check for arbiter share
        let mut ring_data: serde_json::Value = escrow
            .ring_data_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| serde_json::json!({}));

        let has_arbiter_share = ring_data
            .get("arbiter_frost_share")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some();

        // Step 2: Extract arbiter share from vault if not already stored
        if !has_arbiter_share {
            match self.auto_signer.extract_arbiter_share_hex(escrow_id).await {
                Ok(share_hex) => {
                    ring_data["arbiter_frost_share"] = serde_json::json!(share_hex);

                    // Persist to DB
                    self.update_ring_data_json(escrow_id, &ring_data).await?;

                    info!(
                        escrow_id = %escrow_id,
                        share_prefix = &share_hex[..16],
                        "Arbiter FROST share extracted from vault and stored in ring_data_json"
                    );
                }
                Err(e) => {
                    error!(
                        escrow_id = %escrow_id,
                        error = %e,
                        "Failed to extract arbiter share from vault (key expired or Redis down?)"
                    );
                    return Err(e);
                }
            }
        }

        // Step 3: Check if winner's share is present
        let winner_key = if dispute_pair == "arbiter_buyer" {
            "buyer_frost_share"
        } else {
            "vendor_frost_share"
        };
        let winner_share = ring_data
            .get(winner_key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());

        let arbiter_share = ring_data
            .get("arbiter_frost_share")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .context("Arbiter share should be present after extraction")?;

        let winner_share = match winner_share {
            Some(s) => s,
            None => {
                let winner_role = if dispute_pair == "arbiter_buyer" {
                    "buyer"
                } else {
                    "vendor"
                };
                info!(
                    escrow_id = %escrow_id,
                    winner_role = %winner_role,
                    "Arbiter share ready. Waiting for {} to submit their FROST share via frontend.",
                    winner_role
                );
                return Ok(()); // Will retry on next poll cycle
            }
        };

        // Step 4: Both shares present — call CLI binary
        let payout_address = if dispute_pair == "arbiter_buyer" {
            escrow
                .buyer_refund_address
                .as_deref()
                .context("Buyer refund address not set")?
        } else {
            escrow
                .vendor_payout_address
                .as_deref()
                .context("Vendor payout address not set")?
        };

        info!(
            escrow_id = %escrow_id,
            dispute_pair = %dispute_pair,
            "Both FROST shares present. Calling full_offline_broadcast_dispute CLI."
        );

        let cli_path = std::env::current_dir()
            .map(|p| p.join("target/release/full_offline_broadcast_dispute"))
            .unwrap_or_else(|_| {
                std::path::PathBuf::from("./target/release/full_offline_broadcast_dispute")
            });

        let output = tokio::process::Command::new(&cli_path)
            .args([
                escrow_id,
                arbiter_share,
                winner_share,
                payout_address,
                dispute_pair,
                "--broadcast",
            ])
            .output()
            .await
            .context("Failed to execute dispute broadcast CLI")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            let tx_hash = stdout
                .lines()
                .find(|line| line.contains("TX hash:"))
                .and_then(|line| line.split("TX hash:").nth(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let final_status = if dispute_pair == "arbiter_buyer" {
                "refunded"
            } else {
                "completed"
            };

            self.update_escrow_final_status(escrow_id, final_status, &tx_hash)
                .await?;

            info!(
                escrow_id = %escrow_id,
                tx_hash = %tx_hash,
                final_status = %final_status,
                "Dispute resolution broadcast successful via watchdog"
            );
        } else {
            error!(
                escrow_id = %escrow_id,
                exit_code = ?output.status.code(),
                stdout = %stdout,
                stderr = %stderr,
                "Dispute broadcast CLI failed"
            );
            return Err(anyhow::anyhow!(
                "CLI dispute broadcast failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr
            ));
        }

        Ok(())
    }

    /// Update ring_data_json in the escrow record
    async fn update_ring_data_json(
        &self,
        escrow_id: &str,
        ring_data: &serde_json::Value,
    ) -> Result<()> {
        use crate::schema::escrows;
        use diesel::prelude::*;

        let db_pool = self.pool.clone();
        let escrow_id = escrow_id.to_string();
        let ring_json =
            serde_json::to_string(ring_data).context("Failed to serialize ring_data")?;

        tokio::task::spawn_blocking(move || {
            let mut conn = db_pool.get().context("Failed to get DB connection")?;
            diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
                .set((
                    escrows::ring_data_json.eq(Some(&ring_json)),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(&mut conn)
                .context("Failed to update ring_data_json")?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Task join error")?
    }

    /// Update escrow to final status after successful broadcast
    async fn update_escrow_final_status(
        &self,
        escrow_id: &str,
        final_status: &str,
        tx_hash: &str,
    ) -> Result<()> {
        use crate::schema::escrows;
        use diesel::prelude::*;

        let db_pool = self.pool.clone();
        let escrow_id = escrow_id.to_string();
        let status = final_status.to_string();
        let tx_hash = tx_hash.to_string();

        tokio::task::spawn_blocking(move || {
            let mut conn = db_pool.get().context("Failed to get DB connection")?;
            diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
                .set((
                    escrows::status.eq(&status),
                    escrows::broadcast_tx_hash.eq(Some(&tx_hash)),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(&mut conn)
                .context("Failed to update escrow final status")?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Task join error")?
    }

    /// Register an arbiter's key_package for an escrow
    ///
    /// Called after DKG Part 3 when the arbiter's key_package is generated.
    /// Stores the encrypted key_package in Redis for later auto-signing.
    pub async fn register_arbiter_key(
        &self,
        escrow_id: &str,
        key_package_hex: &str,
    ) -> Result<()> {
        self.key_vault
            .store_key_package(escrow_id, key_package_hex)
            .await
            .context("Failed to store arbiter key_package")?;

        info!(
            escrow_id = %escrow_id,
            "Arbiter key_package registered for auto-signing"
        );

        Ok(())
    }

    /// Check if arbiter key is registered for an escrow
    pub async fn has_arbiter_key(&self, escrow_id: &str) -> bool {
        self.key_vault.has_key_package(escrow_id).await.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_watchdog_config_default() {
        let config = WatchdogConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        assert!(config.auto_sign_enabled);
        assert!(config.require_both_signatures);
    }
}
