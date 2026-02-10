//! Automatic Multisig Coordination Service
//!
//! This service monitors escrows in "all_registered" state and automatically
//! triggers the multisig setup process when all 3 wallets are ready.

use actix::Addr;
use anyhow::{Context, Result};
use diesel::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::db::DbPool;
use crate::models::escrow::Escrow;
use crate::schema::escrows;
use crate::websocket::WebSocketServer;

/// Auto-coordination service for multisig setup
///
/// Polls the database for escrows where all 3 wallets are registered
/// and automatically triggers the multisig coordination process.
pub struct MultisigAutoCoordinator {
    db: DbPool,
    websocket: Addr<WebSocketServer>,
    poll_interval_secs: u64,
}

impl MultisigAutoCoordinator {
    /// Create a new MultisigAutoCoordinator
    ///
    /// # Arguments
    /// * `db` - Database connection pool
    /// * `websocket` - WebSocket server for sending notifications
    /// * `poll_interval_secs` - Polling interval in seconds (default: 5)
    pub fn new(
        db: DbPool,
        websocket: Addr<WebSocketServer>,
        poll_interval_secs: Option<u64>,
    ) -> Self {
        let poll_interval = poll_interval_secs.unwrap_or(5);
        info!(
            "MultisigAutoCoordinator initialized with poll_interval={}s",
            poll_interval
        );
        Self {
            db,
            websocket,
            poll_interval_secs: poll_interval,
        }
    }

    /// Start monitoring in background
    ///
    /// This spawns a background task that periodically checks for escrows
    /// in "all_registered" state and triggers multisig coordination.
    pub async fn start_monitoring(self: Arc<Self>) {
        let mut poll_timer = interval(Duration::from_secs(self.poll_interval_secs));

        info!("🚀 Starting MultisigAutoCoordinator monitoring loop");

        loop {
            poll_timer.tick().await;

            if let Err(e) = self.check_and_coordinate().await {
                error!("❌ Error in auto-coordination: {}", e);
            }
        }
    }

    /// Check for escrows ready for coordination and trigger setup
    async fn check_and_coordinate(&self) -> Result<()> {
        let mut conn = self.db.get().context("Failed to get database connection")?;

        // Find escrows in "all_registered" state
        let ready_escrows: Vec<Escrow> = escrows::table
            .filter(escrows::multisig_phase.eq("all_registered"))
            .load::<Escrow>(&mut conn)
            .context("Failed to query escrows")?;

        if !ready_escrows.is_empty() {
            info!(
                "🔍 Found {} escrows ready for multisig coordination",
                ready_escrows.len()
            );
        }

        for escrow in ready_escrows {
            info!(
                "🎯 Triggering auto-coordination for escrow {} (order: {:?})",
                escrow.id, escrow.order_id
            );

            // Update phase to "coordinating" to prevent duplicate processing
            diesel::update(escrows::table.filter(escrows::id.eq(&escrow.id)))
                .set((
                    escrows::multisig_phase.eq("coordinating"),
                    escrows::multisig_updated_at.eq(chrono::Utc::now().timestamp() as i32),
                ))
                .execute(&mut conn)
                .context("Failed to update multisig_phase")?;

            // In WASM mode, coordination happens client-side
            // Send WebSocket notification to advance UI to coordination step
            use crate::websocket::WsEvent;
            self.websocket.do_send(WsEvent::EscrowProgress {
                escrow_id: escrow.id.clone(),
                step: 3, // Step 3: Multisig coordination in progress
            });

            info!(
                "✅ Auto-coordination triggered for escrow {} - WebSocket Step 3 sent",
                escrow.id
            );

            // For WASM v0.5.0: The coordination happens in the browser
            // Each wallet executes prepare_multisig locally
            // The server only coordinates the exchange of multisig info

            // Update phase to "awaiting_multisig_info" after triggering
            diesel::update(escrows::table.filter(escrows::id.eq(&escrow.id)))
                .set((
                    escrows::multisig_phase.eq("awaiting_multisig_info"),
                    escrows::multisig_updated_at.eq(chrono::Utc::now().timestamp() as i32),
                ))
                .execute(&mut conn)
                .context("Failed to update to awaiting_multisig_info")?;

            info!(
                "📊 Escrow {} phase updated: all_registered → awaiting_multisig_info",
                escrow.id
            );
        }

        Ok(())
    }
}
