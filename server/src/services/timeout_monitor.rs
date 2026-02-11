//! Timeout monitoring service for detecting and handling stuck escrows
//!
//! This service runs in the background and periodically checks for escrows
//! that have exceeded their timeout deadlines. It takes automatic actions
//! based on the escrow status and sends notifications via WebSocket.

use actix::Addr;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::time::interval;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::TimeoutConfig;
use crate::db::DbPool;
use crate::models::escrow::Escrow;
use crate::models::webhook::WebhookEventType;
use crate::repositories::MultisigStateRepository;
use crate::services::webhook_dispatcher::{
    build_escrow_payload, emit_webhook_nonblocking, WebhookDispatcher,
};
use crate::websocket::{NotifyUser, WebSocketServer, WsEvent};

/// Timeout monitoring service
///
/// Runs in the background and polls the database for escrows that have
/// exceeded their configured timeouts. Takes automatic actions and sends
/// notifications to affected parties.
pub struct TimeoutMonitor {
    db: DbPool,
    websocket: Addr<WebSocketServer>,
    config: TimeoutConfig,
    multisig_repo: Option<Arc<MultisigStateRepository>>,
    webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
}

impl TimeoutMonitor {
    /// Create a new TimeoutMonitor
    ///
    /// # Arguments
    /// * `db` - Database connection pool
    /// * `websocket` - WebSocket server for sending notifications
    /// * `config` - Timeout configuration (deadlines and polling intervals)
    pub fn new(db: DbPool, websocket: Addr<WebSocketServer>, config: TimeoutConfig) -> Self {
        info!(
            "TimeoutMonitor initialized with poll_interval={}s",
            config.poll_interval_secs
        );
        Self {
            db,
            websocket,
            config,
            multisig_repo: None,
            webhook_dispatcher: None,
        }
    }

    /// Set the webhook dispatcher for B2B event emission
    pub fn with_webhook_dispatcher(mut self, dispatcher: Arc<WebhookDispatcher>) -> Self {
        self.webhook_dispatcher = Some(dispatcher);
        self
    }

    /// Create a new TimeoutMonitor with multisig state persistence
    ///
    /// # Arguments
    /// * `db` - Database connection pool
    /// * `websocket` - WebSocket server for sending notifications
    /// * `config` - Timeout configuration (deadlines and polling intervals)
    /// * `encryption_key` - Encryption key for multisig state data
    pub fn new_with_persistence(
        db: DbPool,
        websocket: Addr<WebSocketServer>,
        config: TimeoutConfig,
        encryption_key: Vec<u8>,
    ) -> Self {
        let multisig_repo = MultisigStateRepository::new(db.clone(), encryption_key);
        info!(
            "TimeoutMonitor initialized with persistence and poll_interval={}s",
            config.poll_interval_secs
        );
        Self {
            db,
            websocket,
            config,
            multisig_repo: Some(Arc::new(multisig_repo)),
            webhook_dispatcher: None,
        }
    }

    /// Start monitoring in background
    ///
    /// This spawns a background task that periodically checks for:
    /// - Expired escrows (past deadline)
    /// - Escrows approaching expiration (warning notifications)
    /// - Stuck multisig setups (if persistence enabled)
    ///
    /// The task runs indefinitely until the server shuts down.
    pub async fn start_monitoring(self: Arc<Self>) {
        let mut poll_timer = interval(self.config.poll_interval());

        info!("Starting timeout monitoring loop");

        loop {
            poll_timer.tick().await;

            // Check for expired escrows first (highest priority)
            if let Err(e) = self.check_expired_escrows().await {
                error!("Error checking expired escrows: {}", e);
            }

            // Check for escrows approaching expiration (send warnings)
            if let Err(e) = self.check_expiring_escrows().await {
                error!("Error checking expiring escrows: {}", e);
            }

            // v0.75.0: Check for shipped escrows pending auto-release
            if let Err(e) = self.check_auto_release_escrows().await {
                error!("Error checking auto-release escrows: {}", e);
            }

            // Check for stuck multisig setups (if persistence enabled)
            if self.multisig_repo.is_some() {
                if let Err(e) = self.check_stuck_multisig_setups().await {
                    error!("Error checking stuck multisig setups: {}", e);
                }
            }
        }
    }

    /// Check for and handle expired escrows
    ///
    /// Finds all escrows past their deadline and takes appropriate action:
    /// - "created" → Cancel (multisig setup incomplete)
    /// - "funded" → Cancel (buyer never deposited funds)
    /// - "releasing"/"refunding" → Alert admin (transaction stuck)
    /// - "disputed" → Escalate (arbiter timeout)
    async fn check_expired_escrows(&self) -> Result<()> {
        let mut conn = self.db.get().context("Failed to get DB connection")?;

        let expired_escrows = tokio::task::spawn_blocking(move || Escrow::find_expired(&mut conn))
            .await
            .context("Task join error")??;

        if expired_escrows.is_empty() {
            return Ok(());
        }

        info!("Found {} expired escrows", expired_escrows.len());

        for escrow in expired_escrows {
            let escrow_id = escrow
                .id
                .parse::<Uuid>()
                .context("Failed to parse escrow_id")?;

            info!(
                "Processing expired escrow: id={}, status={}, created={}",
                escrow_id, escrow.status, escrow.created_at
            );

            // Handle based on current status
            match escrow.status.as_str() {
                "created" => {
                    self.handle_multisig_setup_timeout(escrow_id, escrow)
                        .await?;
                }
                "funded" => {
                    self.handle_funded_timeout(escrow_id, escrow).await?;
                }
                // v0.68.0: Handle underfunded escrows with grace period
                "underfunded" => {
                    self.handle_underfunded_timeout(escrow_id, escrow).await?;
                }
                // v0.75.0: Shipped escrows handled via check_auto_release_escrows
                // But if they have an expires_at set, handle it here
                "shipped" => {
                    // Shipped escrows use auto_release_at, not expires_at
                    // This case should not occur, but handle gracefully
                    warn!(
                        escrow_id = %escrow_id,
                        "Shipped escrow found in expired check - should use auto_release_at instead"
                    );
                }
                "releasing" | "refunding" => {
                    self.handle_transaction_timeout(escrow_id, escrow).await?;
                }
                "disputed" => {
                    self.handle_dispute_timeout(escrow_id, escrow).await?;
                }
                _ => {
                    warn!(
                        "Unexpected expired escrow status: {} for escrow {}",
                        escrow.status, escrow_id
                    );
                }
            }
        }

        Ok(())
    }

    /// Check for escrows approaching expiration and send warnings
    async fn check_expiring_escrows(&self) -> Result<()> {
        let warning_threshold = self.config.warning_threshold_secs;
        let mut conn = self.db.get().context("Failed to get DB connection")?;

        let expiring_escrows = tokio::task::spawn_blocking(move || {
            Escrow::find_expiring_soon(&mut conn, warning_threshold as i64)
        })
        .await
        .context("Task join error")??;

        if expiring_escrows.is_empty() {
            return Ok(());
        }

        info!(
            "Found {} escrows approaching expiration",
            expiring_escrows.len()
        );

        for escrow in expiring_escrows {
            let escrow_id = escrow
                .id
                .parse::<Uuid>()
                .context("Failed to parse escrow_id")?;

            let expires_in_secs = escrow.seconds_until_expiration().unwrap_or(0);

            info!(
                "Sending expiration warning for escrow {}: {}s remaining",
                escrow_id, expires_in_secs
            );

            // Send warning to all parties (buyer, vendor, arbiter)
            self.send_expiring_warning(escrow_id, &escrow, expires_in_secs as u64)
                .await?;
        }

        Ok(())
    }

    /// Handle timeout for multisig setup (status: "created")
    ///
    /// Action: Cancel the escrow (no funds at risk, setup incomplete)
    async fn handle_multisig_setup_timeout(&self, escrow_id: Uuid, escrow: Escrow) -> Result<()> {
        info!(
            "Multisig setup timeout for escrow {}: cancelling",
            escrow_id
        );

        // Update status to cancelled
        let mut conn = self.db.get().context("Failed to get DB connection")?;
        let escrow_id_clone = escrow_id.to_string();
        tokio::task::spawn_blocking(move || {
            Escrow::update_status(&mut conn, escrow_id_clone, "cancelled")
        })
        .await
        .context("Task join error")??;

        // Notify all parties
        self.websocket.do_send(WsEvent::EscrowAutoCancelled {
            escrow_id,
            reason: "Multisig setup not completed within 1 hour".to_string(),
            cancelled_at_status: "created".to_string(),
        });

        // B2B Webhook: EscrowCancelled
        if let Some(ref dispatcher) = self.webhook_dispatcher {
            emit_webhook_nonblocking(
                Arc::clone(dispatcher),
                WebhookEventType::EscrowCancelled,
                build_escrow_payload(
                    &escrow_id.to_string(),
                    "escrow.cancelled",
                    serde_json::json!({
                        "reason": "Multisig setup not completed within 1 hour",
                        "cancelled_at_status": "created",
                    }),
                ),
            );
        }

        info!("Escrow {} auto-cancelled due to setup timeout", escrow_id);
        Ok(())
    }

    /// Handle timeout for funded escrow (status: "funded")
    ///
    /// v0.75.0: "funded" now means payment received, vendor hasn't shipped yet
    /// Action: Notify vendor to ship, or refund buyer if vendor unresponsive
    async fn handle_funded_timeout(&self, escrow_id: Uuid, escrow: Escrow) -> Result<()> {
        use crate::models::notification::{NewNotification, Notification, NotificationType};

        info!(
            escrow_id = %escrow_id,
            "Funded escrow timeout: vendor hasn't shipped within deadline"
        );

        // Option 1: Warn vendor first, cancel if repeated
        // For now, send warning to vendor and buyer
        let vendor_id = escrow
            .vendor_id
            .parse::<Uuid>()
            .context("Failed to parse vendor_id")?;
        let buyer_id = escrow
            .buyer_id
            .parse::<Uuid>()
            .context("Failed to parse buyer_id")?;

        // Create warning notification for vendor
        let db_pool = self.db.clone();
        let vendor_id_str = escrow.vendor_id.clone();
        let escrow_id_str = escrow_id.to_string();
        let escrow_link = format!("/escrow/{escrow_id}");

        let _ = tokio::task::spawn_blocking(move || {
            let mut conn = match db_pool.get() {
                Ok(c) => c,
                Err(_) => return,
            };

            let notification = NewNotification::new(
                vendor_id_str,
                NotificationType::EscrowUpdate,
                "Shipping Deadline Approaching".to_string(),
                "Please ship the order soon or buyer may request a refund.".to_string(),
                Some(escrow_link),
                Some(
                    serde_json::json!({
                        "escrow_id": escrow_id_str,
                        "event": "shipping_deadline_warning"
                    })
                    .to_string(),
                ),
            );

            let _ = Notification::create(notification, &mut conn);
        });

        // Send WebSocket warning
        self.websocket.do_send(NotifyUser {
            user_id: vendor_id,
            event: WsEvent::EscrowExpiring {
                escrow_id,
                status: "funded".to_string(),
                expires_in_secs: 0, // Already expired
                action_required: "Ship the order immediately or buyer can request refund"
                    .to_string(),
            },
        });

        // Notify buyer they can request refund
        self.websocket.do_send(NotifyUser {
            user_id: buyer_id,
            event: WsEvent::RefundAvailable {
                escrow_id,
                user_id: buyer_id,
                amount_atomic: escrow.amount as u64,
                reason: "Vendor did not ship within deadline".to_string(),
            },
        });

        info!(
            escrow_id = %escrow_id,
            "Funded escrow timeout warning sent to vendor and buyer"
        );

        Ok(())
    }

    /// Handle timeout for underfunded escrow (status: "underfunded")
    ///
    /// v0.68.0: Underfunded escrows get a 48h grace period after initial timeout.
    /// During grace period: buyer can complete funding or request refund.
    /// After grace period: escrow transitions to "cancelled_recoverable".
    async fn handle_underfunded_timeout(&self, escrow_id: Uuid, escrow: Escrow) -> Result<()> {
        use crate::models::notification::{NewNotification, Notification, NotificationType};

        // Check if grace period already started
        if escrow.grace_period_ends_at.is_none() {
            // First timeout - start grace period
            let grace_period_secs = self.config.grace_period_secs as i64;

            info!(
                escrow_id = %escrow_id,
                balance_received = escrow.balance_received,
                amount_required = escrow.amount,
                grace_period_hours = grace_period_secs / 3600,
                "Underfunded escrow timeout: starting 48h grace period"
            );

            // Start grace period in database
            let mut conn = self.db.get().context("Failed to get DB connection")?;
            let escrow_id_str = escrow_id.to_string();

            tokio::task::spawn_blocking(move || {
                Escrow::start_grace_period(&mut conn, escrow_id_str, grace_period_secs)
            })
            .await
            .context("Task join error")??;

            // Send notification to buyer about grace period
            let shortfall_xmr =
                (escrow.amount - escrow.balance_received) as f64 / 1_000_000_000_000.0;
            let received_xmr = escrow.balance_received as f64 / 1_000_000_000_000.0;

            let db_pool = self.db.clone();
            let buyer_id = escrow.buyer_id.clone();
            let escrow_id_for_notif = escrow_id.to_string();

            let _ = tokio::task::spawn_blocking(move || {
                let mut conn = match db_pool.get() {
                    Ok(c) => c,
                    Err(_) => return,
                };

                let notification = NewNotification::new(
                    buyer_id,
                    NotificationType::EscrowUpdate,
                    "Grace Period Started".to_string(),
                    format!(
                        "Funding timeout reached. You have 48 hours to send the remaining {shortfall_xmr:.6} XMR or request a refund of {received_xmr:.6} XMR."
                    ),
                    Some(format!("/escrow/{escrow_id_for_notif}")),
                    Some(serde_json::json!({
                        "escrow_id": escrow_id_for_notif,
                        "event": "grace_period_started",
                        "grace_period_hours": 48
                    }).to_string()),
                );

                let _ = Notification::create(notification, &mut conn);
            });

            // WebSocket notification
            self.websocket.do_send(WsEvent::GracePeriodStarted {
                escrow_id,
                balance_received: escrow.balance_received as u64,
                amount_required: escrow.amount as u64,
                grace_period_ends_at: chrono::Utc::now().naive_utc()
                    + chrono::Duration::seconds(grace_period_secs),
            });

            info!(
                escrow_id = %escrow_id,
                "Grace period started for underfunded escrow (48 hours remaining)"
            );
        } else if escrow.is_grace_period_expired() {
            // Grace period expired - transition to cancelled_recoverable
            info!(
                escrow_id = %escrow_id,
                balance_received = escrow.balance_received,
                "Grace period expired for underfunded escrow: transitioning to cancelled_recoverable"
            );

            let mut conn = self.db.get().context("Failed to get DB connection")?;
            let escrow_id_str = escrow_id.to_string();

            tokio::task::spawn_blocking(move || {
                Escrow::update_status(&mut conn, escrow_id_str, "cancelled_recoverable")
            })
            .await
            .context("Task join error")??;

            // Send notification to buyer about refund availability
            let received_xmr = escrow.balance_received as f64 / 1_000_000_000_000.0;

            let db_pool = self.db.clone();
            let buyer_id = escrow.buyer_id.clone();
            let escrow_id_for_notif = escrow_id.to_string();

            let balance_recoverable = escrow.balance_received;
            let _ = tokio::task::spawn_blocking(move || {
                let mut conn = match db_pool.get() {
                    Ok(c) => c,
                    Err(_) => return,
                };

                let notification = NewNotification::new(
                    buyer_id,
                    NotificationType::EscrowUpdate,
                    "Refund Available".to_string(),
                    format!(
                        "Your escrow has been cancelled. Click to request refund of {received_xmr:.6} XMR."
                    ),
                    Some(format!("/escrow/{escrow_id_for_notif}")),
                    Some(
                        serde_json::json!({
                            "escrow_id": escrow_id_for_notif,
                            "event": "refund_available",
                            "balance_recoverable": balance_recoverable
                        })
                        .to_string(),
                    ),
                );

                let _ = Notification::create(notification, &mut conn);
            });

            // WebSocket notification
            self.websocket.do_send(WsEvent::EscrowCancelledRecoverable {
                escrow_id,
                balance_recoverable: escrow.balance_received as u64,
                reason: "Grace period expired - buyer can request refund".to_string(),
            });

            // B2B Webhook: EscrowCancelled (grace period expired)
            if let Some(ref dispatcher) = self.webhook_dispatcher {
                emit_webhook_nonblocking(
                    Arc::clone(dispatcher),
                    WebhookEventType::EscrowCancelled,
                    build_escrow_payload(
                        &escrow_id.to_string(),
                        "escrow.cancelled",
                        serde_json::json!({
                            "reason": "Grace period expired - underfunded",
                            "balance_recoverable": escrow.balance_received,
                            "status": "cancelled_recoverable",
                        }),
                    ),
                );
            }

            info!(
                escrow_id = %escrow_id,
                balance_recoverable = escrow.balance_received,
                "Escrow cancelled_recoverable: buyer can request refund"
            );
        }

        Ok(())
    }

    /// Handle timeout for transaction confirmation (status: "releasing"/"refunding")
    ///
    /// Action: Alert admin (transaction may be stuck in mempool)
    /// No auto-action taken as funds are already on blockchain
    async fn handle_transaction_timeout(&self, escrow_id: Uuid, escrow: Escrow) -> Result<()> {
        let tx_hash = escrow.transaction_hash.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Escrow {} in {} status but no tx_hash",
                escrow_id,
                escrow.status
            )
        })?;

        warn!(
            "Transaction timeout for escrow {}: tx {} stuck for >6h",
            escrow_id,
            &tx_hash[..10]
        );

        // Calculate hours pending
        let secs_since_activity =
            (chrono::Utc::now().naive_utc() - escrow.last_activity_at).num_seconds();
        let hours_pending = (secs_since_activity / 3600) as u64;

        // Send stuck transaction alert
        self.websocket.do_send(WsEvent::TransactionStuck {
            escrow_id,
            tx_hash: tx_hash.clone(),
            hours_pending,
            suggested_action: "Check blockchain explorer for transaction status. \
                              May need to increase fee or wait for mempool clearance."
                .to_string(),
        });

        info!(
            "Sent stuck transaction alert for escrow {} (tx: {})",
            escrow_id,
            &tx_hash[..10]
        );

        Ok(())
    }

    /// v0.75.0: Check for shipped escrows that need auto-release
    ///
    /// Finds escrows in "shipped" status where auto_release_at has passed.
    /// These are escrows where the buyer didn't confirm receipt within the deadline.
    /// Action: Set buyer_release_requested to trigger Arbiter Watchdog auto-signing.
    async fn check_auto_release_escrows(&self) -> Result<()> {
        use crate::models::notification::{NewNotification, Notification, NotificationType};

        let mut conn = self.db.get().context("Failed to get DB connection")?;

        let pending_releases =
            tokio::task::spawn_blocking(move || Escrow::find_pending_auto_release(&mut conn))
                .await
                .context("Task join error")??;

        if pending_releases.is_empty() {
            return Ok(());
        }

        info!(
            "Found {} shipped escrows pending auto-release",
            pending_releases.len()
        );

        for escrow in pending_releases {
            let escrow_id = escrow
                .id
                .parse::<Uuid>()
                .context("Failed to parse escrow_id")?;

            info!(
                escrow_id = %escrow_id,
                shipped_at = ?escrow.shipped_at,
                auto_release_at = ?escrow.auto_release_at,
                "Auto-releasing escrow - buyer timeout reached"
            );

            // Set buyer_release_requested to trigger Arbiter Watchdog
            let mut conn = self.db.get().context("Failed to get DB connection")?;
            let escrow_id_clone = escrow_id.to_string();

            tokio::task::spawn_blocking(move || {
                use crate::schema::escrows;
                use diesel::prelude::*;

                diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id_clone)))
                    .set((
                        escrows::buyer_release_requested.eq(true),
                        escrows::status.eq("releasing"),
                        escrows::updated_at.eq(diesel::dsl::now),
                    ))
                    .execute(&mut conn)
            })
            .await
            .context("Task join error")??;

            // Create notifications
            let buyer_id = escrow
                .buyer_id
                .parse::<Uuid>()
                .context("Failed to parse buyer_id")?;
            let vendor_id = escrow
                .vendor_id
                .parse::<Uuid>()
                .context("Failed to parse vendor_id")?;

            // Notify buyer about auto-release
            let mut conn2 = self.db.get().context("Failed to get DB connection")?;
            let escrow_id_for_notif = escrow_id.to_string();
            let escrow_link = format!("/escrow/{escrow_id}");
            let buyer_id_str = escrow.buyer_id.clone();

            tokio::task::spawn_blocking(move || {
                let notification = NewNotification::new(
                    buyer_id_str,
                    NotificationType::EscrowUpdate,
                    "Auto-Release Triggered".to_string(),
                    "You didn't confirm receipt. Funds are being released to vendor.".to_string(),
                    Some(escrow_link),
                    Some(
                        serde_json::json!({
                            "escrow_id": escrow_id_for_notif,
                            "event": "auto_release_triggered"
                        })
                        .to_string(),
                    ),
                );

                let _ = Notification::create(notification, &mut conn2);
            });

            // WebSocket notification
            self.websocket.do_send(WsEvent::EscrowStatusChanged {
                escrow_id,
                new_status: "releasing".to_string(),
            });

            // Notify vendor
            self.websocket.do_send(NotifyUser {
                user_id: vendor_id,
                event: WsEvent::EscrowStatusChanged {
                    escrow_id,
                    new_status: "releasing".to_string(),
                },
            });

            // B2B Webhook: EscrowReleased (auto-release due to buyer timeout)
            if let Some(ref dispatcher) = self.webhook_dispatcher {
                emit_webhook_nonblocking(
                    Arc::clone(dispatcher),
                    WebhookEventType::EscrowReleased,
                    build_escrow_payload(
                        &escrow_id.to_string(),
                        "escrow.released",
                        serde_json::json!({
                            "reason": "auto_release_buyer_timeout",
                            "status": "releasing",
                        }),
                    ),
                );
            }

            info!(
                escrow_id = %escrow_id,
                "Auto-release initiated for shipped escrow (buyer timeout)"
            );
        }

        Ok(())
    }

    /// Handle timeout for dispute resolution (status: "disputed")
    ///
    /// Action: Escalate and notify buyer they can claim refund
    /// v0.67: Auto-sets signing pair to arbiter_buyer to enable refund
    async fn handle_dispute_timeout(&self, escrow_id: Uuid, escrow: Escrow) -> Result<()> {
        let arbiter_id = escrow
            .arbiter_id
            .parse::<Uuid>()
            .context("Failed to parse arbiter_id")?;
        let buyer_id = escrow
            .buyer_id
            .parse::<Uuid>()
            .context("Failed to parse buyer_id")?;

        // Calculate days in dispute
        let dispute_started = escrow.dispute_created_at.unwrap_or(escrow.last_activity_at);
        let secs_in_dispute = (chrono::Utc::now().naive_utc() - dispute_started).num_seconds();
        let days_in_dispute = (secs_in_dispute / 86400) as u64;

        warn!(
            escrow_id = %escrow_id,
            arbiter_id = %arbiter_id,
            days_in_dispute = days_in_dispute,
            "Dispute timeout: auto-escalating and enabling buyer refund"
        );

        // v0.67: Enhanced escalation with buyer refund option
        let escalation_reason = format!(
            "7-day dispute timeout reached. Dispute initiated on {:?}, auto-escalated after {} days. \
             Buyer refund enabled - arbiter_buyer signing pair set.",
            dispute_started.format("%Y-%m-%d %H:%M UTC"),
            days_in_dispute
        );

        // Get database connection and record escalation
        let mut conn = self.db.get().context("Failed to get database connection")?;
        use crate::schema::escrows;
        use diesel::prelude::*;

        // v0.67: Set signing pair to arbiter_buyer to enable refund without arbiter action
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.to_string())))
            .set((
                escrows::auto_escalated_at.eq(Some(chrono::Utc::now().naive_utc())),
                escrows::escalation_reason.eq(Some(&escalation_reason)),
                escrows::dispute_signing_pair.eq(Some("arbiter_buyer".to_string())),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(&mut conn)
            .context("Failed to record dispute escalation")?;

        // Send escalation notification to all parties
        self.websocket.do_send(WsEvent::DisputeEscalated {
            escrow_id,
            arbiter_id,
            days_in_dispute,
            action_taken:
                "Dispute auto-escalated. Buyer refund enabled. Visit /orders to claim refund."
                    .to_string(),
        });

        // Send specific notification to buyer about refund availability
        self.websocket.do_send(WsEvent::RefundAvailable {
            escrow_id,
            user_id: buyer_id,
            amount_atomic: escrow.amount as u64,
            reason: "Dispute timeout - arbiter did not resolve within 7 days".to_string(),
        });

        info!(
            escrow_id = %escrow_id,
            "Dispute auto-escalated: buyer refund enabled (arbiter_buyer signing pair set)"
        );

        Ok(())
    }

    /// Send expiration warning to all parties
    async fn send_expiring_warning(
        &self,
        escrow_id: Uuid,
        escrow: &Escrow,
        expires_in_secs: u64,
    ) -> Result<()> {
        let action_required = match escrow.status.as_str() {
            "created" => "Complete multisig setup".to_string(),
            "funded" => "Vendor: ship the order".to_string(),
            "shipped" => "Buyer: confirm receipt or open dispute".to_string(),
            "releasing" | "refunding" => "Wait for blockchain confirmation".to_string(),
            "disputed" => "Arbiter: resolve dispute".to_string(),
            _ => "No action required".to_string(),
        };

        // Parse party IDs
        let buyer_id = escrow
            .buyer_id
            .parse::<Uuid>()
            .context("Failed to parse buyer_id")?;
        let vendor_id = escrow
            .vendor_id
            .parse::<Uuid>()
            .context("Failed to parse vendor_id")?;
        let arbiter_id = escrow
            .arbiter_id
            .parse::<Uuid>()
            .context("Failed to parse arbiter_id")?;

        // Send to all parties
        for user_id in [buyer_id, vendor_id, arbiter_id] {
            self.websocket.do_send(NotifyUser {
                user_id,
                event: WsEvent::EscrowExpiring {
                    escrow_id,
                    status: escrow.status.clone(),
                    expires_in_secs,
                    action_required: action_required.clone(),
                },
            });
        }

        info!(
            "Sent expiration warning for escrow {}: {}s remaining",
            escrow_id, expires_in_secs
        );

        Ok(())
    }

    /// Check for stuck multisig setups using persisted state
    ///
    /// Identifies escrows where multisig setup has stalled:
    /// - Last state update > 15 minutes ago
    /// - Status is "created" (setup not completed)
    /// - Multisig state exists but setup incomplete
    ///
    /// Action: Send stuck setup notification to all parties
    async fn check_stuck_multisig_setups(&self) -> Result<()> {
        let repo = self
            .multisig_repo
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MultisigStateRepository not initialized"))?;

        // Use repository's built-in method to find stuck escrows (15 minutes = 900 seconds)
        let stuck_escrow_ids = repo.find_stuck_escrows(900)?;

        if stuck_escrow_ids.is_empty() {
            return Ok(());
        }

        info!("Found {} stuck multisig setup(s)", stuck_escrow_ids.len());

        for escrow_id_str in stuck_escrow_ids {
            let escrow_id = escrow_id_str
                .parse::<Uuid>()
                .context("Failed to parse escrow_id")?;

            // Load both escrow and snapshot to get phase and timestamp
            let mut conn = self.db.get().context("Failed to get DB connection")?;
            let escrow_id_clone = escrow_id_str.clone();

            let escrow_result = tokio::task::spawn_blocking(move || {
                use crate::schema::escrows::dsl::*;
                use diesel::prelude::*;
                escrows
                    .find(escrow_id_clone)
                    .first::<Escrow>(&mut conn)
                    .optional()
            })
            .await
            .context("Task join error")??;

            if let Some(escrow) = escrow_result {
                match repo.load_snapshot(&escrow_id_str) {
                    Ok(Some(snapshot)) => {
                        let minutes_stuck = (chrono::Utc::now().naive_utc().timestamp()
                            - escrow.multisig_updated_at as i64)
                            / 60;

                        warn!(
                            "Stuck multisig setup detected for escrow {}: {} minutes with no progress",
                            escrow_id, minutes_stuck
                        );

                        // Send stuck setup notification
                        self.websocket.do_send(WsEvent::MultisigSetupStuck {
                            escrow_id: escrow_id.to_string(),
                            minutes_stuck: minutes_stuck as u64,
                            last_step: snapshot.phase.status_description(),
                            suggested_action: "Check wallet RPC connectivity and retry multisig setup"
                                .to_string(),
                        });

                        info!(
                            "Sent stuck multisig setup notification for escrow {}",
                            escrow_id
                        );
                    }
                    Ok(None) => {
                        warn!(
                            "Stuck escrow {} has no snapshot (should not happen)",
                            escrow_id
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to load multisig snapshot for escrow {}: {}",
                            escrow_id, e
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_config_creation() {
        let config = TimeoutConfig::default();
        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| ":memory:".to_string());

        // Just verify we can create the struct (actual testing requires DB setup)
        assert_eq!(config.poll_interval_secs, 60);
        assert_eq!(config.multisig_setup_timeout_secs, 3600);
    }
}
