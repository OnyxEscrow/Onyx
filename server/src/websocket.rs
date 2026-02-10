//! WebSocket server for real-time notifications

use actix::{Actor, ActorContext, Addr, AsyncContext, Context, Handler, Message, StreamHandler};
use actix_web_actors::ws;
use anyhow::Result;
use serde;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

// --- WebSocket Session Actor ---

pub struct WebSocketSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub hb: Instant,
    pub server: Addr<WebSocketServer>,
    pub conn_mgr: actix_web::web::Data<crate::middleware::ConnectionManager>,
    pub user_id_str: String,
}

impl Actor for WebSocketSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
        self.server.do_send(Connect {
            id: self.id,
            user_id: self.user_id,
            addr: ctx.address(),
        });
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        self.server.do_send(Disconnect { id: self.id });
        // Release connection slot when WebSocket closes
        self.conn_mgr.release(&self.user_id_str);
        info!("WebSocket disconnected for user {} (released connection slot)", self.user_id);
    }
}

impl WebSocketSession {
    fn hb(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                warn!("Heartbeat timeout, disconnecting session {}", act.id);
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WebSocketSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => {}
        }
    }
}

impl Handler<WsMessage> for WebSocketSession {
    type Result = ();

    fn handle(&mut self, msg: WsMessage, ctx: &mut <Self as Actor>::Context) {
        ctx.text(msg.0);
    }
}

// --- WebSocket Server Actor ---

#[derive(Default)]
pub struct WebSocketServer {
    sessions: HashMap<Uuid, Addr<WebSocketSession>>,
    user_sessions: HashMap<Uuid, HashSet<Uuid>>,
}

impl Actor for WebSocketServer {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Context<Self>) {
        info!("WebSocketServer actor started");
    }
}

// --- Messages ---

#[derive(Message)]
#[rtype(result = "()")]
pub struct Connect {
    pub id: Uuid,
    pub user_id: Uuid,
    pub addr: Addr<WebSocketSession>,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Disconnect {
    pub id: Uuid,
}

#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct WsMessage(pub String);

#[derive(Message, Debug, Clone, serde::Serialize)]
#[rtype(result = "()")]
pub enum WsEvent {
    EscrowInit {
        escrow_id: Uuid,
    },
    EscrowAssigned {
        escrow_id: Uuid,
    },
    EscrowStatusChanged {
        escrow_id: Uuid,
        new_status: String,
    },
    TransactionConfirmed {
        tx_hash: String,
        confirmations: u32,
    },
    NewMessage {
        escrow_id: Uuid,
        sender_id: Uuid,
        message_id: String,
    },
    OrderStatusChanged {
        order_id: Uuid,
        new_status: String,
    },
    DisputeResolved {
        escrow_id: Uuid,
        resolution: String,
        decided_by: Uuid,
    },
    /// Invitation to submit a review after escrow transaction completion
    ///
    /// Triggered automatically when a transaction is confirmed on the blockchain.
    /// The buyer receives this notification to invite them to rate the vendor.
    ReviewInvitation {
        escrow_id: String,
        tx_hash: String,
        buyer_id: String,
        vendor_id: String,
    },
    /// Warning that an escrow is approaching expiration
    ///
    /// Triggered when an escrow is within the warning threshold (default 1h) of its deadline.
    /// Parties should complete required actions or the escrow will be auto-cancelled/refunded.
    EscrowExpiring {
        escrow_id: Uuid,
        status: String,
        expires_in_secs: u64,
        action_required: String,
    },
    /// Notification that an escrow has expired
    ///
    /// Triggered when an escrow exceeds its timeout for the current status.
    /// The escrow status has been updated to "expired" or "cancelled".
    EscrowExpired {
        escrow_id: Uuid,
        previous_status: String,
        reason: String,
    },
    /// Notification that an escrow was automatically cancelled due to timeout
    ///
    /// Occurs when setup/funding takes too long. No funds were lost as
    /// multisig was not funded or transaction did not complete.
    EscrowAutoCancelled {
        escrow_id: Uuid,
        reason: String,
        cancelled_at_status: String,
    },
    /// Notification that a dispute has been escalated due to timeout
    ///
    /// Occurs when an arbiter does not resolve a dispute within the timeout period.
    /// Admin intervention is now required, or automatic refund has been triggered.
    DisputeEscalated {
        escrow_id: Uuid,
        arbiter_id: Uuid,
        days_in_dispute: u64,
        action_taken: String,
    },
    /// Notification that a refund is available for the buyer
    ///
    /// Triggered when:
    /// - Dispute timeout occurred and arbiter didn't resolve (auto-refund)
    /// - Vendor didn't ship within shipping timeout (14 days)
    /// The buyer can claim the refund by initiating the signing process.
    RefundAvailable {
        escrow_id: Uuid,
        /// User ID of the buyer who can claim the refund
        user_id: Uuid,
        /// Amount available for refund in atomic units
        amount_atomic: u64,
        /// Reason for the refund availability
        reason: String,
    },
    /// Notification to vendor that a new order has been placed
    ///
    /// Triggered when a buyer creates a new order for a vendor's listing.
    /// The vendor receives this notification to take action (initiate escrow).
    NewOrder {
        order_id: Uuid,
        /// Vendor's user ID (recipient of the notification)
        vendor_id: Uuid,
        /// Buyer's username (anonymized if needed)
        buyer_username: String,
        /// Listing title
        listing_title: String,
        /// Total amount in piconeros
        amount_atomic: u64,
        /// Quantity ordered
        quantity: u32,
    },
    /// Alert that a transaction appears stuck (high confirmation timeout)
    ///
    /// Triggered when a "releasing" or "refunding" transaction has not confirmed
    /// within the expected timeframe. May indicate blockchain congestion or other issues.
    TransactionStuck {
        escrow_id: Uuid,
        tx_hash: String,
        hours_pending: u64,
        suggested_action: String,
    },
    /// Alert that multisig setup has stalled
    ///
    /// Triggered when an escrow in "created" status has had no progress for >15 minutes.
    /// May indicate wallet RPC connectivity issues or client disconnection.
    MultisigSetupStuck {
        escrow_id: String,
        minutes_stuck: u64,
        last_step: String,
        suggested_action: String,
    },
    /// Alert that multisig setup has failed permanently
    ///
    /// Triggered when MultisigStateRepository marks an escrow as failed.
    /// Indicates unrecoverable error requiring manual intervention or escrow cancellation.
    MultisigSetupFailed {
        escrow_id: Uuid,
        reason: String,
        failed_at_step: String,
        can_retry: bool,
    },
    /// Notification that wallet recovery was successful
    ///
    /// Triggered after server restart when WalletManager successfully recovers
    /// an escrow's wallet state from persisted RPC configs and multisig snapshots.
    MultisigRecovered {
        escrow_id: Uuid,
        recovered_wallets: Vec<String>, // ["buyer", "vendor", "arbiter"]
        phase: String,
        recovered_at: i64, // Unix timestamp
    },
    /// Progress notification for non-custodial escrow setup
    ///
    /// Triggered during the 4-step multisig coordination process:
    /// - Step 1: User downloaded local wallet assistant
    /// - Step 2: All wallets registered
    /// - Step 3: Multisig exchange in progress
    /// - Step 4: Multisig address ready
    EscrowProgress {
        escrow_id: String,
        step: u8,
    },

    // ========== FROST DKG Notifications ==========

    /// Notification that FROST DKG Round 1 requires user action
    ///
    /// Triggered when a party needs to submit their Round 1 commitment.
    /// Each of the 3 parties (buyer, vendor, arbiter) must submit before Round 2.
    FrostDkgRound1Required {
        escrow_id: Uuid,
        /// Role of the party receiving this notification ("buyer", "vendor", "arbiter")
        party_role: String,
        /// Parties who have already submitted their Round 1 data
        parties_submitted: Vec<String>,
        /// Parties who still need to submit
        parties_pending: Vec<String>,
    },

    /// Notification that FROST DKG Round 1 is complete
    ///
    /// Triggered when all 3 parties have submitted their Round 1 commitments.
    /// The system will automatically proceed to Round 2.
    FrostDkgRound1Complete {
        escrow_id: Uuid,
    },

    /// Notification that FROST DKG Round 2 requires user action
    ///
    /// Triggered when a party needs to submit their Round 2 secret share packages.
    /// Each party submits 2 packages (one for each other participant) = 6 total.
    FrostDkgRound2Required {
        escrow_id: Uuid,
        /// Role of the party receiving this notification
        party_role: String,
        /// Number of Round 2 packages received so far (0-6)
        packages_submitted: u8,
        /// Total packages required (always 6)
        packages_total: u8,
    },

    /// Notification that FROST DKG Round 2 is complete
    ///
    /// Triggered when all 6 Round 2 packages have been submitted.
    /// Each party can now finalize their key share locally (Round 3).
    FrostDkgRound2Complete {
        escrow_id: Uuid,
    },

    /// Notification that FROST DKG is fully complete
    ///
    /// Triggered after all parties have finalized Round 3 locally.
    /// The 2-of-3 multisig wallet is now ready for funding and signing.
    FrostDkgComplete {
        escrow_id: Uuid,
        /// The generated multisig address (for display purposes)
        multisig_address: String,
    },

    // ========== FROST Signing Notifications ==========

    /// Notification that a signature is required from a specific party
    ///
    /// Triggered during round-robin signing:
    /// - Signer 1 (Vendor): "Mark as Shipped" action
    /// - Signer 2 (Buyer): "Complete Signature" action
    SignatureRequired {
        escrow_id: Uuid,
        /// Role of the party who needs to sign ("vendor" or "buyer")
        signer_role: String,
        /// Which signer in the sequence (1 or 2)
        signer_number: u8,
        /// User-friendly label for the action ("Mark as Shipped", "Complete Signature")
        action_label: String,
    },

    /// Notification that a signature has been submitted
    ///
    /// Triggered after each party signs, updating all participants on progress.
    SignatureSubmitted {
        escrow_id: Uuid,
        /// Role of the party who just signed
        signer_role: String,
        /// Number of signatures collected so far (1 or 2)
        signatures_collected: u8,
        /// Total signatures required (always 2 for 2-of-3)
        signatures_required: u8,
    },

    /// Notification that the transaction is ready to broadcast
    ///
    /// Triggered after both required signatures are collected.
    /// The buyer can now broadcast the transaction to the Monero network.
    ReadyToBroadcast {
        escrow_id: Uuid,
        /// Amount being transferred (e.g., "0.5")
        tx_amount_xmr: String,
        /// Who receives the funds ("vendor" or "buyer" for refund)
        recipient: String,
    },

    /// Notification that broadcast was successful
    ///
    /// Triggered after transaction is submitted to the network.
    /// Includes confirmation tracking for UI progress display.
    BroadcastSuccess {
        escrow_id: Uuid,
        /// Transaction hash for reference
        tx_hash: String,
        /// Current confirmation count (0-10)
        confirmations: u8,
    },

    /// Notification that broadcast failed
    ///
    /// Triggered if the transaction broadcast encounters an error.
    /// Provides actionable information for retry or escalation.
    BroadcastFailed {
        escrow_id: Uuid,
        /// Error message describing the failure
        error: String,
        /// Whether the user can retry the broadcast
        can_retry: bool,
    },

    // ========== Secure E2E Messaging Notifications ==========

    /// Notification that a new secure message was received
    ///
    /// Triggered when another user sends an encrypted message.
    /// The message content is encrypted - only the recipient can decrypt it.
    SecureMessageReceived {
        /// Unique message ID
        message_id: String,
        /// Sender's user ID
        sender_id: String,
        /// Sender's username (for display)
        sender_username: String,
        /// Conversation ID (hash of both user IDs)
        conversation_id: String,
        /// Timestamp of the message
        created_at: String,
    },

    /// Notification that a message was read by recipient
    ///
    /// Triggered when the recipient marks a message as read.
    /// Used to update read receipts in the sender's UI.
    SecureMessageRead {
        /// Message ID that was read
        message_id: String,
        /// Conversation ID
        conversation_id: String,
        /// Timestamp when read
        read_at: String,
    },

    // ========== Shipped Tracking Notifications (v0.75.0) ==========

    /// Early payment detection - TX visible on chain but not yet fully confirmed
    ///
    /// Triggered when blockchain monitor sees total_balance > 0 but unlocked_balance < amount.
    /// This means the TX has 1-9 confirmations (visible but locked).
    /// Reassures buyer funds are arriving; alerts vendor that payment is incoming.
    PaymentDetected {
        escrow_id: String,
        /// Amount detected in piconeros (total balance including unconfirmed)
        amount_detected: u64,
        /// Amount required for full funding
        amount_required: u64,
        /// Buyer's user ID
        buyer_id: String,
        /// Vendor's user ID
        vendor_id: String,
    },

    /// Notification that escrow is now funded and awaiting shipment
    ///
    /// Triggered when blockchain monitor detects sufficient funds in escrow address.
    /// Vendor should now ship the goods/services.
    EscrowFunded {
        escrow_id: String,
        /// Amount funded in piconeros
        amount_funded: u64,
        /// Buyer's user ID
        buyer_id: String,
        /// Vendor's user ID (who should now ship)
        vendor_id: String,
    },

    /// Notification that vendor has marked order as shipped
    ///
    /// Triggered when vendor calls confirm_shipped endpoint.
    /// Buyer should confirm receipt when goods arrive.
    EscrowShipped {
        escrow_id: String,
        /// Vendor's user ID (who shipped)
        vendor_id: String,
        /// Buyer's user ID (who should confirm receipt)
        buyer_id: String,
        /// Optional tracking information
        tracking_info: Option<String>,
        /// When auto-release will trigger if buyer doesn't confirm
        auto_release_at: chrono::NaiveDateTime,
    },

    /// Notification that buyer has confirmed receipt
    ///
    /// Triggered when buyer calls confirm_receipt endpoint.
    /// Arbiter Watchdog will now auto-sign to release funds.
    BuyerConfirmedReceipt {
        escrow_id: String,
        /// Buyer's user ID (who confirmed)
        buyer_id: String,
        /// Vendor's user ID (who will receive funds)
        vendor_id: String,
    },

    /// Notification that auto-release is approaching
    ///
    /// Triggered when shipped escrow is within 24h of auto-release.
    /// Warning to buyer to confirm receipt or open dispute.
    AutoReleaseWarning {
        escrow_id: Uuid,
        /// Hours remaining until auto-release
        hours_remaining: u64,
        /// Buyer's user ID
        buyer_id: Uuid,
    },

    // ========== Underfunded Escrow Notifications (v0.68.0) ==========

    /// Notification that grace period has started for underfunded escrow
    ///
    /// Triggered when funding timeout is reached but partial funds exist.
    /// Buyer has 48 hours to complete funding or request refund.
    GracePeriodStarted {
        escrow_id: Uuid,
        /// Amount already received in piconeros
        balance_received: u64,
        /// Total amount required in piconeros
        amount_required: u64,
        /// When the grace period ends
        grace_period_ends_at: chrono::NaiveDateTime,
    },

    /// Notification that escrow is cancelled but funds are recoverable
    ///
    /// Triggered when grace period expires for underfunded escrow.
    /// Buyer can request refund of partial funds via "Request Refund" button.
    EscrowCancelledRecoverable {
        escrow_id: Uuid,
        /// Amount that can be recovered in piconeros
        balance_recoverable: u64,
        /// Reason for cancellation
        reason: String,
    },

    /// Notification of partial payment received
    ///
    /// Triggered when blockchain monitor detects partial funding.
    /// Includes shortfall information for buyer action.
    PartialPaymentReceived {
        escrow_id: Uuid,
        /// Amount received in piconeros
        balance_received: u64,
        /// Amount required in piconeros
        amount_required: u64,
        /// Amount still needed in piconeros
        shortfall: u64,
    },

    // ========== BTC → XMR Swap Notifications (Multi-Currency Track 1) ==========

    /// Notification that a BTC swap quote was created
    ///
    /// Triggered when a user requests a BTC→XMR swap quote.
    /// Contains the BTC deposit address for payment.
    SwapQuoteCreated {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID (for tracking)
        provider_order_id: String,
        /// BTC address to deposit to
        btc_deposit_address: String,
        /// Amount of BTC to send (in satoshis)
        btc_amount_sats: u64,
        /// Estimated XMR to receive (in piconeros)
        xmr_amount_atomic: u64,
        /// Exchange rate (BTC per XMR)
        rate_btc_per_xmr: f64,
        /// When the quote expires
        expires_at: String,
    },

    /// Notification that BTC deposit was detected
    ///
    /// Triggered when the swap provider detects an incoming BTC transaction.
    /// Waiting for confirmations before proceeding.
    SwapDepositDetected {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID
        provider_order_id: String,
        /// BTC transaction hash
        btc_tx_hash: String,
        /// Current confirmation count
        btc_confirmations: u32,
    },

    /// Notification that BTC deposit is confirmed
    ///
    /// Triggered when the BTC transaction has sufficient confirmations.
    /// The swap will now proceed.
    SwapDepositConfirmed {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID
        provider_order_id: String,
        /// BTC transaction hash
        btc_tx_hash: String,
        /// Final confirmation count
        btc_confirmations: u32,
    },

    /// Notification that swap is in progress
    ///
    /// Triggered when the provider is actively exchanging BTC for XMR.
    /// This may take a few minutes depending on network conditions.
    SwapInProgress {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID
        provider_order_id: String,
    },

    /// Notification that swap completed successfully
    ///
    /// Triggered when XMR has been sent to the escrow address.
    /// The order payment is now funded.
    SwapComplete {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID
        provider_order_id: String,
        /// XMR transaction hash
        xmr_tx_hash: String,
        /// Actual XMR amount received (in piconeros)
        xmr_received_atomic: u64,
    },

    /// Notification that swap failed
    ///
    /// Triggered when the swap could not be completed.
    /// The user may need to take action (contact support, retry).
    SwapFailed {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID
        provider_order_id: String,
        /// Error message describing the failure
        error_message: String,
        /// Whether a refund may be available
        refund_possible: bool,
    },

    /// Notification that swap expired
    ///
    /// Triggered when the quote expired before payment was detected.
    /// The user needs to create a new quote if they still want to pay.
    SwapExpired {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID
        provider_order_id: String,
        /// Message explaining expiration
        message: String,
    },

    /// Notification that BTC was refunded
    ///
    /// Triggered when the swap failed and BTC was returned.
    /// Contains the refund transaction details.
    SwapRefunded {
        /// Associated order ID
        order_id: Uuid,
        /// Provider's order ID
        provider_order_id: String,
        /// BTC refund transaction hash
        btc_refund_tx_hash: String,
        /// Refund address
        refund_address: Option<String>,
    },

    // ========== Escrow E2EE Chat Notifications ==========

    /// Notification that a new encrypted chat message was sent in an escrow
    ///
    /// Triggered when a participant sends a message in the escrow chat.
    /// Only participants of the escrow can decrypt the message.
    EscrowChatMessage {
        escrow_id: String,
        message_id: String,
        sender_id: String,
        sender_role: String,
        sender_username: String,
    },
}

// --- Handlers ---

impl Handler<Connect> for WebSocketServer {
    type Result = ();

    fn handle(&mut self, msg: Connect, _: &mut Context<Self>) {
        info!(
            "WebSocket session {} connected for user {}",
            msg.id, msg.user_id
        );
        self.sessions.insert(msg.id, msg.addr);
        self.user_sessions
            .entry(msg.user_id)
            .or_default()
            .insert(msg.id);
    }
}

impl Handler<Disconnect> for WebSocketServer {
    type Result = ();

    fn handle(&mut self, msg: Disconnect, _: &mut Context<Self>) {
        info!("WebSocket session {} disconnected", msg.id);
        if self.sessions.remove(&msg.id).is_some() {
            // This is inefficient, but acceptable for now.
            // A better implementation would use a reverse map.
            for sessions in self.user_sessions.values_mut() {
                sessions.remove(&msg.id);
            }
        }
    }
}

impl Handler<WsEvent> for WebSocketServer {
    type Result = ();

    fn handle(&mut self, msg: WsEvent, _ctx: &mut Context<Self>) {
        // Serialize event to JSON
        let json_msg = match serde_json::to_string(&msg) {
            Ok(json) => json,
            Err(e) => {
                warn!("Failed to serialize WebSocket event: {}", e);
                return;
            }
        };

        // Broadcast to all connected sessions
        // In a production system, we would filter by user_id based on the event type
        for addr in self.sessions.values() {
            addr.do_send(WsMessage(json_msg.clone()));
        }

        info!("Broadcast WebSocket event: {:?}", msg);
    }
}

/// Message to notify a specific user
#[derive(Message)]
#[rtype(result = "()")]
pub struct NotifyUser {
    pub user_id: Uuid,
    pub event: WsEvent,
}

impl Handler<NotifyUser> for WebSocketServer {
    type Result = ();

    fn handle(&mut self, msg: NotifyUser, _ctx: &mut Context<Self>) {
        // Find all sessions for this user
        let session_ids = match self.user_sessions.get(&msg.user_id) {
            Some(ids) => ids,
            None => {
                info!(
                    "User {} has no active WebSocket sessions, cannot notify",
                    msg.user_id
                );
                return;
            }
        };

        // Serialize event to JSON
        let json_msg = match serde_json::to_string(&msg.event) {
            Ok(json) => json,
            Err(e) => {
                warn!("Failed to serialize WebSocket event: {}", e);
                return;
            }
        };

        // Send to all sessions for this user
        let mut notified_count = 0;
        for session_id in session_ids {
            if let Some(addr) = self.sessions.get(session_id) {
                addr.do_send(WsMessage(json_msg.clone()));
                notified_count += 1;
            }
        }

        info!(
            "Notified user {} via {} WebSocket session(s): {:?}",
            msg.user_id, notified_count, msg.event
        );
    }
}
