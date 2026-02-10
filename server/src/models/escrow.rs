//! Escrow model and related database operations

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::escrows;

/// Escrow model - IMPORTANT: Column order MUST match schema.rs exactly!
/// Diesel's Queryable trait requires fields in the same order as the table columns.
#[derive(Debug, Clone, Serialize, Deserialize, Queryable)]
#[diesel(table_name = escrows)]
pub struct Escrow {
    // Columns 1-10
    pub id: String,
    pub order_id: Option<String>,  // Nullable for EaaS (standalone escrows)
    pub buyer_id: String,
    pub vendor_id: String,
    pub arbiter_id: String,
    pub amount: i64,
    pub multisig_address: Option<String>,
    pub status: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    // Columns 11-20
    pub buyer_wallet_info: Option<Vec<u8>>,
    pub vendor_wallet_info: Option<Vec<u8>>,
    pub arbiter_wallet_info: Option<Vec<u8>>,
    pub transaction_hash: Option<String>,
    pub expires_at: Option<NaiveDateTime>,
    pub last_activity_at: NaiveDateTime,
    pub multisig_phase: String,
    pub multisig_state_json: Option<String>,
    pub multisig_updated_at: i32,
    pub recovery_mode: String,
    // Columns 21-27: Non-custodial + Dispute
    pub buyer_temp_wallet_id: Option<String>,
    pub vendor_temp_wallet_id: Option<String>,
    pub arbiter_temp_wallet_id: Option<String>,
    pub dispute_reason: Option<String>,
    pub dispute_created_at: Option<NaiveDateTime>,
    pub dispute_resolved_at: Option<NaiveDateTime>,
    pub resolution_decision: Option<String>,
    // Columns 28-31: Signatures (MUST match schema.rs order!)
    pub vendor_signature: Option<String>,
    pub buyer_signature: Option<String>,
    pub unsigned_tx_hex: Option<String>,
    pub vendor_signed_at: Option<i32>,
    pub buyer_signed_at: Option<i32>,
    // Columns 32-35: Payout addresses
    pub vendor_payout_address: Option<String>,
    pub buyer_refund_address: Option<String>,
    pub vendor_payout_set_at: Option<i32>,
    pub buyer_refund_set_at: Option<i32>,
    // Columns 36-41: Funding data
    pub multisig_view_key: Option<String>,
    pub funding_commitment_mask: Option<String>,
    pub funding_tx_hash: Option<String>,
    pub funding_output_index: Option<i32>,
    pub funding_global_index: Option<i32>,
    pub ring_data_json: Option<String>,
    // Columns 42-45: CLSAG partial key images (v0.7.0)
    pub buyer_partial_key_image: Option<String>,
    pub vendor_partial_key_image: Option<String>,
    pub arbiter_partial_key_image: Option<String>,
    pub aggregated_key_image: Option<String>,
    // Columns 46-50: Round-robin signing (v0.8.0)
    pub partial_tx: Option<String>,
    pub partial_tx_initiator: Option<String>,
    pub completed_clsag: Option<String>,
    pub signing_started_at: Option<i32>,
    pub signing_phase: Option<String>,
    // Columns 51-53: Underfunded escrow tracking (v0.68.0)
    pub balance_received: i64,                    // Actual balance received (may be < amount)
    pub grace_period_ends_at: Option<NaiveDateTime>, // 48h grace period after initial timeout
    pub refund_requested_at: Option<NaiveDateTime>,  // When buyer requested partial refund
    // Columns 54-55: EaaS fields (v1.0.0 - EaaS transformation)
    pub external_reference: Option<String>,       // External tracking ID (replaces order_id for EaaS)
    pub description: Option<String>,              // Escrow purpose/description for EaaS clients
    // Columns 56-59: FROST DKG (v0.45.0 - RFC 9591 threshold CLSAG)
    pub frost_enabled: bool,                      // True if using FROST instead of Monero native
    pub frost_group_pubkey: Option<String>,       // FROST group public key (shared by all 3 parties)
    pub frost_dkg_complete: bool,                 // True when DKG round 3 is complete
    pub frost_dkg_state: Option<String>,          // DKG state: 'pending', 'round1', 'round2', 'complete'
    // Column 60: Funding output pubkey for auto-PKI (v0.8.1)
    pub funding_output_pubkey: Option<String>,
    // Column 61: TX public key from funding transaction for derivation (v0.8.2)
    pub funding_tx_pubkey: Option<String>,
    // Columns 62-66: MuSig2 nonce fields (v0.9.0)
    pub vendor_nonce_commitment: Option<String>,
    pub buyer_nonce_commitment: Option<String>,
    pub vendor_nonce_public: Option<String>,
    pub buyer_nonce_public: Option<String>,
    pub nonce_aggregated: Option<String>,
    // Column 67: First signer tracking to prevent timestamp race (v0.9.1)
    pub first_signer_role: Option<String>,
    // Columns 68-69: mu_P and mu_C mixing coefficients (v0.37.0)
    pub mu_p: Option<String>,
    pub mu_c: Option<String>,
    // Column 70: First signer R_agg state at signing time (v0.41.0)
    pub first_signer_had_r_agg: Option<i32>,
    // Columns 71-76: Round-robin signing (v0.43.0)
    pub multisig_txset: Option<String>,
    pub signing_round: Option<i32>,
    pub current_signer_id: Option<String>,
    pub partial_signed_txset: Option<String>,
    pub signing_initiated_at: Option<String>,
    pub broadcast_tx_hash: Option<String>,
    // Column 84: Evidence count for dispute management (v0.66.1)
    pub evidence_count: Option<i32>,
    // Columns 85-86: Auto-Resolution / Escalation (v0.66.2)
    pub auto_escalated_at: Option<NaiveDateTime>,
    pub escalation_reason: Option<String>,
    // Column 87: Dispute Signing Pair for WASM arbiter signing (v0.66.3)
    pub dispute_signing_pair: Option<String>,
    // Columns 88-93: Arbiter Watchdog fields (v0.70.0)
    pub buyer_release_requested: bool,
    pub vendor_refund_requested: bool,
    pub arbiter_auto_signed: bool,
    pub arbiter_auto_signed_at: Option<NaiveDateTime>,
    pub escalated_to_human: bool,
    pub arbiter_frost_partial_sig: Option<String>,
    // Columns 94-96: Shipped tracking (v0.75.0)
    pub shipped_at: Option<NaiveDateTime>,
    pub auto_release_at: Option<NaiveDateTime>,
    pub shipping_tracking: Option<String>,
    // Columns 97-98: B2B multi-tenancy (v1.1.0)
    pub client_id: Option<String>,
    pub metadata_json: Option<String>,
}

#[derive(Insertable)]
#[diesel(table_name = escrows)]
pub struct NewEscrow {
    pub id: String,
    pub order_id: Option<String>,  // Nullable for EaaS
    pub buyer_id: String,
    pub vendor_id: String,
    pub arbiter_id: String,
    pub amount: i64,
    pub status: String,
    // Required NOT NULL timestamp fields (Diesel requires explicit values)
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_activity_at: NaiveDateTime,
    // Required NOT NULL fields with defaults
    pub multisig_phase: String,
    pub multisig_updated_at: i32,
    pub recovery_mode: String,
    pub balance_received: i64,
    pub frost_enabled: bool,
    pub frost_dkg_complete: bool,
    // EaaS fields (v1.0.0)
    pub external_reference: Option<String>,
    pub description: Option<String>,
    // Arbiter Watchdog fields (v0.70.0)
    pub buyer_release_requested: bool,
    pub vendor_refund_requested: bool,
    pub arbiter_auto_signed: bool,
    pub escalated_to_human: bool,
    // B2B multi-tenancy (v1.1.0)
    pub client_id: Option<String>,
    pub metadata_json: Option<String>,
}

impl Default for NewEscrow {
    fn default() -> Self {
        let now = chrono::Utc::now().naive_utc();
        Self {
            id: String::new(),
            order_id: None,
            buyer_id: String::new(),
            vendor_id: String::new(),
            arbiter_id: String::new(),
            amount: 0,
            status: "pending_counterparty".to_string(),
            created_at: now,
            updated_at: now,
            last_activity_at: now,
            multisig_phase: "not_started".to_string(),
            multisig_updated_at: 0,
            recovery_mode: "manual".to_string(),
            balance_received: 0,
            frost_enabled: true,
            frost_dkg_complete: false,
            external_reference: None,
            description: None,
            // Arbiter Watchdog fields (v0.70.0)
            buyer_release_requested: false,
            vendor_refund_requested: false,
            arbiter_auto_signed: false,
            escalated_to_human: false,
            // B2B multi-tenancy (v1.1.0)
            client_id: None,
            metadata_json: None,
        }
    }
}

impl Escrow {
    /// Create a new escrow in the database
    pub fn create(conn: &mut SqliteConnection, new_escrow: NewEscrow) -> Result<Escrow> {
        let escrow_id = new_escrow.id.clone();

        diesel::insert_into(escrows::table)
            .values(&new_escrow)
            .execute(conn)
            .map_err(|e| {
                tracing::error!("Diesel insert error: {:?}", e);
                tracing::error!("NewEscrow values - id: {}, order_id: {:?}, buyer: {}, vendor: {}, arbiter: {}, amount: {}, status: {}, multisig_phase: {}, recovery_mode: {}",
                    escrow_id, new_escrow.order_id, new_escrow.buyer_id, new_escrow.vendor_id,
                    new_escrow.arbiter_id, new_escrow.amount, new_escrow.status,
                    new_escrow.multisig_phase, new_escrow.recovery_mode);
                anyhow::anyhow!("Failed to insert escrow: {}", e)
            })?;

        escrows::table
            .filter(escrows::id.eq(escrow_id))
            .first(conn)
            .context("Failed to retrieve created escrow")
    }

    /// Find escrow by ID
    pub fn find_by_id(conn: &mut SqliteConnection, escrow_id: String) -> Result<Escrow> {
        escrows::table
            .filter(escrows::id.eq(escrow_id.clone()))
            .first(conn)
            .context(format!("Escrow with ID {} not found", escrow_id))
    }

    /// Find escrows by buyer ID
    pub fn find_by_buyer(conn: &mut SqliteConnection, buyer_id: String) -> Result<Vec<Escrow>> {
        escrows::table
            .filter(escrows::buyer_id.eq(buyer_id.clone()))
            .load(conn)
            .context(format!("Failed to load escrows for buyer {}", buyer_id))
    }

    /// Find escrows by vendor ID
    pub fn find_by_vendor(conn: &mut SqliteConnection, vendor_id: String) -> Result<Vec<Escrow>> {
        escrows::table
            .filter(escrows::vendor_id.eq(vendor_id.clone()))
            .load(conn)
            .context(format!("Failed to load escrows for vendor {}", vendor_id))
    }

    /// Find escrows by arbiter ID
    pub fn find_by_arbiter(conn: &mut SqliteConnection, arbiter_id: String) -> Result<Vec<Escrow>> {
        escrows::table
            .filter(escrows::arbiter_id.eq(arbiter_id.clone()))
            .load(conn)
            .context(format!("Failed to load escrows for arbiter {}", arbiter_id))
    }

    /// Find escrow by order ID (legacy - use find_by_external_reference for EaaS)
    pub fn find_by_order(conn: &mut SqliteConnection, order_id: String) -> Result<Escrow> {
        escrows::table
            .filter(escrows::order_id.eq(order_id.clone()))
            .first(conn)
            .context(format!("Escrow for order {} not found", order_id))
    }

    /// Find escrow by external reference (EaaS API)
    ///
    /// External references allow EaaS clients to link escrows to their
    /// own tracking systems without using internal order IDs.
    pub fn find_by_external_reference(conn: &mut SqliteConnection, external_ref: &str) -> Result<Escrow> {
        escrows::table
            .filter(escrows::external_reference.eq(external_ref))
            .first(conn)
            .context(format!("Escrow with external_reference {} not found", external_ref))
    }

    /// Update escrow status
    pub fn update_status(
        conn: &mut SqliteConnection,
        escrow_id: String,
        new_status: &str,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::status.eq(new_status),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!("Failed to update status for escrow {}", escrow_id))?;
        Ok(())
    }

    /// Update multisig address
    pub fn update_multisig_address(
        conn: &mut SqliteConnection,
        escrow_id: String,
        address: &str,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::multisig_address.eq(address),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update multisig address for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Update shared multisig view key for server-side balance monitoring
    ///
    /// The view key allows the server to check the escrow balance without
    /// being able to spend the funds. This is deterministic - all 3 parties
    /// generate the same view key, so we only need to store it once.
    pub fn update_multisig_view_key(
        conn: &mut SqliteConnection,
        escrow_id: String,
        view_key: &str,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::multisig_view_key.eq(view_key),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update multisig view key for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Store encrypted wallet info for a party
    pub fn store_wallet_info(
        conn: &mut SqliteConnection,
        escrow_id: String,
        party: &str,
        encrypted_info: Vec<u8>,
    ) -> Result<()> {
        let update_result = match party {
            "buyer" => diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set(escrows::buyer_wallet_info.eq(Some(encrypted_info)))
                .execute(conn),
            "vendor" => diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set(escrows::vendor_wallet_info.eq(Some(encrypted_info)))
                .execute(conn),
            "arbiter" => diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set(escrows::arbiter_wallet_info.eq(Some(encrypted_info)))
                .execute(conn),
            _ => return Err(anyhow::anyhow!("Invalid party: {}", party)),
        };

        update_result.context(format!(
            "Failed to store wallet info for {} in escrow {}",
            party, escrow_id
        ))?;
        Ok(())
    }

    /// Count how many parties have submitted wallet info
    pub fn count_wallet_infos(conn: &mut SqliteConnection, escrow_id: String) -> Result<usize> {
        let escrow = Self::find_by_id(conn, escrow_id)?;
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
    }

    /// Get all wallet infos (returns vec of encrypted data)
    pub fn get_all_wallet_infos(
        conn: &mut SqliteConnection,
        escrow_id: String,
    ) -> Result<Vec<Vec<u8>>> {
        let escrow = Self::find_by_id(conn, escrow_id)?;
        let mut infos = Vec::new();
        if let Some(buyer_info) = escrow.buyer_wallet_info {
            infos.push(buyer_info);
        }
        if let Some(vendor_info) = escrow.vendor_wallet_info {
            infos.push(vendor_info);
        }
        if let Some(arbiter_info) = escrow.arbiter_wallet_info {
            infos.push(arbiter_info);
        }
        Ok(infos)
    }

    /// Update transaction hash for release/refund transaction
    ///
    /// This is called when funds are released to vendor or refunded to buyer.
    /// The transaction_hash is used by the blockchain monitor to track confirmations.
    pub fn update_transaction_hash(
        conn: &mut SqliteConnection,
        escrow_id: String,
        tx_hash: &str,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::transaction_hash.eq(tx_hash),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update transaction_hash for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Update last_activity_at timestamp to current time
    ///
    /// Should be called whenever there's a significant action on an escrow:
    /// - Status change
    /// - Multisig setup step completed
    /// - Funds deposited
    /// - Dispute initiated/resolved
    ///
    /// This resets the timeout clock for the current status.
    pub fn update_activity(
        conn: &mut SqliteConnection,
        escrow_id: String,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::last_activity_at.eq(diesel::dsl::now),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update last_activity_at for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Update expires_at deadline for the current escrow status
    ///
    /// Called after status changes or activity updates to set the new deadline.
    /// Pass None to clear expiration (for terminal states like completed/refunded).
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `escrow_id` - Escrow ID to update
    /// * `new_expires_at` - New expiration timestamp, or None for no expiration
    pub fn update_expiration(
        conn: &mut SqliteConnection,
        escrow_id: String,
        new_expires_at: Option<NaiveDateTime>,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::expires_at.eq(new_expires_at),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update expires_at for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Check if escrow has expired (deadline passed)
    ///
    /// Returns true if expires_at is set and is in the past.
    /// Returns false if expires_at is None (terminal states) or in the future.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < chrono::Utc::now().naive_utc()
        } else {
            false
        }
    }

    /// Get seconds remaining until expiration
    ///
    /// Returns None if expires_at is not set (terminal states).
    /// Returns Some(0) if already expired.
    /// Returns Some(n) with seconds remaining otherwise.
    pub fn seconds_until_expiration(&self) -> Option<i64> {
        self.expires_at.map(|expires_at| {
            let now = chrono::Utc::now().naive_utc();
            let duration = expires_at.signed_duration_since(now);
            duration.num_seconds().max(0)
        })
    }

    /// Check if escrow is approaching expiration (within warning threshold)
    ///
    /// # Arguments
    /// * `warning_threshold_secs` - How many seconds before expiration to warn (default 3600 = 1h)
    ///
    /// Returns true if expiration is within the threshold but not yet expired.
    pub fn is_expiring_soon(&self, warning_threshold_secs: i64) -> bool {
        if let Some(secs_remaining) = self.seconds_until_expiration() {
            secs_remaining > 0 && secs_remaining <= warning_threshold_secs
        } else {
            false
        }
    }

    /// Get all escrows that have expired (past their deadline)
    ///
    /// Returns escrows where:
    /// - expires_at IS NOT NULL
    /// - expires_at < NOW()
    /// - status is not a terminal state
    ///
    /// Used by TimeoutMonitor to find escrows needing timeout handling.
    pub fn find_expired(conn: &mut SqliteConnection) -> Result<Vec<Escrow>> {
        let now = chrono::Utc::now().naive_utc();

        escrows::table
            .filter(escrows::expires_at.is_not_null())
            .filter(escrows::expires_at.lt(now))
            .filter(escrows::status.ne("completed"))
            .filter(escrows::status.ne("refunded"))
            .filter(escrows::status.ne("cancelled"))
            .filter(escrows::status.ne("expired"))
            .load(conn)
            .map_err(|e| {
                tracing::error!("Diesel error in find_expired: {:?}", e);
                e
            })
            .context("Failed to load expired escrows")
    }

    /// Get all escrows approaching expiration (within warning threshold)
    ///
    /// Returns escrows where:
    /// - expires_at IS NOT NULL
    /// - expires_at is between NOW() and NOW() + warning_threshold
    /// - status is not a terminal state
    ///
    /// Used by TimeoutMonitor to send warning notifications.
    pub fn find_expiring_soon(
        conn: &mut SqliteConnection,
        warning_threshold_secs: i64,
    ) -> Result<Vec<Escrow>> {
        let now = chrono::Utc::now().naive_utc();
        let warning_time = now + chrono::Duration::seconds(warning_threshold_secs);

        escrows::table
            .filter(escrows::expires_at.is_not_null())
            .filter(escrows::expires_at.gt(now))
            .filter(escrows::expires_at.le(warning_time))
            .filter(escrows::status.ne("completed"))
            .filter(escrows::status.ne("refunded"))
            .filter(escrows::status.ne("cancelled"))
            .filter(escrows::status.ne("expired"))
            .load(conn)
            .context("Failed to load expiring escrows")
    }

    /// Update funding commitment data when funding is detected
    ///
    /// This stores the real commitment mask (blinding factor) from the funding
    /// transaction. The commitment mask is required for CLSAG ring signatures
    /// when releasing funds from the escrow.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `escrow_id` - Escrow ID to update
    /// * `commitment_mask` - The blinding factor (hex string)
    /// * `tx_hash` - Transaction hash of the funding transaction
    /// * `output_index` - Output index within the transaction
    /// * `global_index` - Global output index on the blockchain
    /// * `output_pubkey` - Output public key (optional, for auto-PKI)
    /// * `tx_pubkey` - Transaction public key R (optional, v0.8.2 for PKI derivation)
    pub fn update_funding_commitment_data(
        conn: &mut SqliteConnection,
        escrow_id: String,
        commitment_mask: &str,
        tx_hash: &str,
        output_index: i32,
        global_index: i32,
        output_pubkey: Option<&str>,
        tx_pubkey: Option<&str>,  // v0.8.2: For PKI derivation H_s(a*R || idx)
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::funding_commitment_mask.eq(commitment_mask),
                escrows::funding_tx_hash.eq(tx_hash),
                escrows::funding_output_index.eq(output_index),
                escrows::funding_global_index.eq(global_index),
                escrows::funding_output_pubkey.eq(output_pubkey),
                escrows::funding_tx_pubkey.eq(tx_pubkey),  // v0.8.2: Store tx_pub_key R
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update funding commitment data for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Store ring data JSON for transaction reconstruction at broadcast time
    ///
    /// The ring data contains all information needed to reconstruct the exact
    /// ring used during prepare_sign. This ensures deterministic transaction
    /// building when broadcasting.
    ///
    /// # JSON Format
    /// ```json
    /// {
    ///   "ring_member_indices": [u64, ...],     // 16 global output indices
    ///   "signer_index": u8,                     // Position of real output (0-15)
    ///   "real_global_index": u64,               // Real output's global index
    ///   "ring_public_keys": ["hex", ...],       // 16 public keys (32 bytes each)
    ///   "ring_commitments": ["hex", ...]        // 16 commitments (32 bytes each)
    /// }
    /// ```
    pub fn update_ring_data_json(
        conn: &mut SqliteConnection,
        escrow_id: String,
        ring_data_json: &str,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::ring_data_json.eq(ring_data_json),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update ring_data_json for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    // =========================================================================
    // Phase 13 (v0.7.0): CLSAG Partial Key Image Methods
    // =========================================================================

    /// Store a partial key image for a participant
    ///
    /// Each participant computes their partial key image locally:
    ///   pKI_i = x_i * Hp(P_multisig)
    /// where x_i is their private spend key share and Hp is hash-to-point.
    ///
    /// This is stored as a 32-byte compressed Edwards point in hex format.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `escrow_id` - Escrow ID
    /// * `role` - "buyer", "vendor", or "arbiter"
    /// * `partial_key_image` - Hex-encoded 32-byte compressed Edwards point
    pub fn update_partial_key_image(
        conn: &mut SqliteConnection,
        escrow_id: String,
        role: &str,
        partial_key_image: &str,
    ) -> Result<()> {
        let update_result = match role {
            "buyer" => diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set((
                    escrows::buyer_partial_key_image.eq(Some(partial_key_image)),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn),
            "vendor" => diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set((
                    escrows::vendor_partial_key_image.eq(Some(partial_key_image)),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn),
            "arbiter" => diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set((
                    escrows::arbiter_partial_key_image.eq(Some(partial_key_image)),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn),
            _ => return Err(anyhow::anyhow!("Invalid role for partial key image: {}", role)),
        };

        update_result.context(format!(
            "Failed to store partial key image for {} in escrow {}",
            role, escrow_id
        ))?;
        Ok(())
    }

    /// Get partial key images for the two signing participants
    ///
    /// In a 2-of-3 multisig, two participants sign. This returns their partial
    /// key images if both are present.
    ///
    /// # Returns
    /// * `Ok(Some((role1, pki1), (role2, pki2)))` - Both PKIs available
    /// * `Ok(None)` - Less than 2 PKIs submitted
    pub fn get_partial_key_images_for_signing(
        conn: &mut SqliteConnection,
        escrow_id: String,
    ) -> Result<Option<((&'static str, String), (&'static str, String))>> {
        let escrow = Self::find_by_id(conn, escrow_id)?;

        let mut pkis: Vec<(&'static str, String)> = Vec::new();

        if let Some(pki) = escrow.buyer_partial_key_image {
            pkis.push(("buyer", pki));
        }
        if let Some(pki) = escrow.vendor_partial_key_image {
            pkis.push(("vendor", pki));
        }
        if let Some(pki) = escrow.arbiter_partial_key_image {
            pkis.push(("arbiter", pki));
        }

        if pkis.len() >= 2 {
            Ok(Some((pkis[0].clone(), pkis[1].clone())))
        } else {
            Ok(None)
        }
    }

    /// Count how many partial key images have been submitted
    pub fn count_partial_key_images(conn: &mut SqliteConnection, escrow_id: String) -> Result<usize> {
        let escrow = Self::find_by_id(conn, escrow_id)?;
        let mut count = 0;
        if escrow.buyer_partial_key_image.is_some() {
            count += 1;
        }
        if escrow.vendor_partial_key_image.is_some() {
            count += 1;
        }
        if escrow.arbiter_partial_key_image.is_some() {
            count += 1;
        }
        Ok(count)
    }

    /// v0.29.0: Get ALL THREE partial key images for correct key_image aggregation.
    ///
    /// For 2-of-3 multisig with additive secret sharing:
    ///   x_total = x_buyer + x_vendor + x_arbiter
    ///   KI = x_total * Hp(P) = pKI_buyer + pKI_vendor + pKI_arbiter
    ///
    /// Even if only 2 parties SIGN, the key_image must be computed from ALL 3 PKIs.
    ///
    /// # Returns
    /// * `Ok(Some((buyer_pki, vendor_pki, arbiter_pki)))` - All 3 PKIs available
    /// * `Ok(None)` - Less than 3 PKIs submitted
    pub fn get_all_three_partial_key_images(
        conn: &mut SqliteConnection,
        escrow_id: String,
    ) -> Result<Option<(String, String, String)>> {
        let escrow = Self::find_by_id(conn, escrow_id)?;

        match (
            escrow.buyer_partial_key_image,
            escrow.vendor_partial_key_image,
            escrow.arbiter_partial_key_image,
        ) {
            (Some(buyer), Some(vendor), Some(arbiter)) => {
                Ok(Some((buyer, vendor, arbiter)))
            }
            _ => Ok(None),
        }
    }

    /// Store the aggregated key image after combining partial key images
    ///
    /// The aggregated key image is computed via Edwards point addition:
    ///   KI_total = pKI_1 + pKI_2
    /// where pKI_1 and pKI_2 are the partial key images from 2 signers.
    ///
    /// This is stored as a 32-byte compressed Edwards point in hex format.
    ///
    /// v0.23.0 FIX: Also updates ring_data_json.key_image if ring_data_json exists.
    /// This ensures consistency between aggregated_key_image and the key_image
    /// used for tx_prefix_hash computation during signing.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `escrow_id` - Escrow ID
    /// * `aggregated_key_image` - Hex-encoded 32-byte compressed Edwards point
    pub fn update_aggregated_key_image(
        conn: &mut SqliteConnection,
        escrow_id: String,
        aggregated_key_image: &str,
    ) -> Result<()> {
        use tracing::{info, warn};

        // v0.42.0 FIX: Check if ring_data_json exists FIRST
        // If it does, the tx_prefix_hash is FROZEN and we MUST NOT update key_image
        // Updating would cause CLSAG verification to fail because the signature
        // was computed with the original key_image stored in ring_data_json
        let existing: Option<Self> = escrows::table
            .filter(escrows::id.eq(&escrow_id))
            .first(conn)
            .optional()
            .context("Failed to fetch escrow for key image update")?;

        // v0.42.0 GUARD: If ring_data_json exists, the key_image is frozen
        if let Some(ref escrow) = existing {
            if escrow.ring_data_json.is_some() {
                let current_ki = escrow.aggregated_key_image.as_deref().unwrap_or("(none)");
                if current_ki != aggregated_key_image {
                    warn!(
                        escrow_id = %escrow_id,
                        current_ki_prefix = %&current_ki[..16.min(current_ki.len())],
                        new_ki_prefix = %&aggregated_key_image[..16.min(aggregated_key_image.len())],
                        "[v0.42.0] BLOCKED: Cannot update aggregated_key_image - ring_data_json already exists (tx_prefix_hash frozen)"
                    );
                } else {
                    info!(
                        escrow_id = %escrow_id,
                        "[v0.42.0] Key image unchanged - ring_data_json exists, values already match"
                    );
                }
                return Ok(()); // Do NOT update anything
            }
        }

        // ring_data_json doesn't exist yet - safe to update aggregated_key_image
        // No need to update ring_data_json since it doesn't exist
        let updated_ring_data_json: Option<String> = None;

        // Update both aggregated_key_image and optionally ring_data_json
        if let Some(new_ring_data) = updated_ring_data_json {
            diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set((
                    escrows::aggregated_key_image.eq(aggregated_key_image),
                    escrows::ring_data_json.eq(Some(new_ring_data)),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn)
                .context(format!(
                    "Failed to update aggregated key image and ring_data for escrow {}",
                    escrow_id
                ))?;
        } else {
            diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
                .set((
                    escrows::aggregated_key_image.eq(aggregated_key_image),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn)
                .context(format!(
                    "Failed to update aggregated key image for escrow {}",
                    escrow_id
                ))?;
        }
        Ok(())
    }

    /// Check if the escrow has a valid aggregated key image ready for broadcast
    pub fn has_aggregated_key_image(&self) -> bool {
        self.aggregated_key_image.is_some()
    }

    /// Get the aggregated key image if available
    pub fn get_aggregated_key_image(&self) -> Option<&str> {
        self.aggregated_key_image.as_deref()
    }

    // =========================================================================
    // v0.68.0: Underfunded Escrow Tracking Methods
    // =========================================================================

    /// Update the balance received for an escrow
    ///
    /// Called by blockchain_monitor when partial payment is detected.
    /// Stores the actual balance on the multisig address.
    pub fn update_balance_received(
        conn: &mut SqliteConnection,
        escrow_id: String,
        balance: i64,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::balance_received.eq(balance),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update balance_received for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Start grace period for underfunded escrow
    ///
    /// Called when funding timeout is reached but partial funds exist.
    /// Sets grace_period_ends_at to now + duration.
    pub fn start_grace_period(
        conn: &mut SqliteConnection,
        escrow_id: String,
        grace_period_secs: i64,
    ) -> Result<()> {
        let grace_end = chrono::Utc::now().naive_utc() + chrono::Duration::seconds(grace_period_secs);

        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::grace_period_ends_at.eq(Some(grace_end)),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to start grace period for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Record refund request for underfunded/cancelled escrow
    ///
    /// Called when buyer clicks "Request Refund" button.
    /// Stores timestamp and validates buyer_refund_address is set.
    pub fn request_refund(
        conn: &mut SqliteConnection,
        escrow_id: String,
        refund_address: &str,
    ) -> Result<()> {
        let now = chrono::Utc::now().naive_utc();
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id.clone())))
            .set((
                escrows::refund_requested_at.eq(Some(now)),
                escrows::buyer_refund_address.eq(Some(refund_address)),
                escrows::updated_at.eq(now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to record refund request for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Check if escrow is underfunded (has partial balance but less than required)
    pub fn is_underfunded(&self) -> bool {
        self.balance_received > 0 && self.balance_received < self.amount
    }

    /// Check if escrow is in grace period
    pub fn is_in_grace_period(&self) -> bool {
        if let Some(grace_end) = self.grace_period_ends_at {
            chrono::Utc::now().naive_utc() < grace_end
        } else {
            false
        }
    }

    /// Check if grace period has expired
    pub fn is_grace_period_expired(&self) -> bool {
        if let Some(grace_end) = self.grace_period_ends_at {
            chrono::Utc::now().naive_utc() >= grace_end
        } else {
            false
        }
    }

    // =========================================================================
    // v0.75.0: Shipped Tracking Methods
    // =========================================================================

    /// Update escrow status to "shipped" with tracking info
    ///
    /// Called by vendor when they ship the goods/services.
    /// Sets auto_release_at to now + delivery_days for buyer timeout.
    pub fn update_shipped_status(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        tracking_info: Option<String>,
        auto_release_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set((
                escrows::status.eq("shipped"),
                escrows::shipped_at.eq(chrono::Utc::now().naive_utc()),
                escrows::auto_release_at.eq(auto_release_at.naive_utc()),
                escrows::shipping_tracking.eq(tracking_info),
                escrows::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .context(format!(
                "Failed to update shipped status for escrow {}",
                escrow_id
            ))?;
        Ok(())
    }

    /// Find escrows in "shipped" status that have passed their auto_release_at deadline
    ///
    /// Used by TimeoutMonitor to trigger auto-release when buyer doesn't confirm receipt.
    pub fn find_pending_auto_release(conn: &mut SqliteConnection) -> Result<Vec<Escrow>> {
        let now = chrono::Utc::now().naive_utc();

        escrows::table
            .filter(escrows::status.eq("shipped"))
            .filter(escrows::auto_release_at.is_not_null())
            .filter(escrows::auto_release_at.lt(now))
            .load(conn)
            .context("Failed to find pending auto-release escrows")
    }

    /// Check if escrow is past its auto-release deadline
    pub fn is_auto_release_due(&self) -> bool {
        if let Some(auto_release) = self.auto_release_at {
            chrono::Utc::now().naive_utc() >= auto_release
        } else {
            false
        }
    }

    /// Get seconds remaining until auto-release (returns 0 if already due or not set)
    pub fn seconds_until_auto_release(&self) -> i64 {
        if let Some(auto_release) = self.auto_release_at {
            let now = chrono::Utc::now().naive_utc();
            let duration = auto_release.signed_duration_since(now);
            duration.num_seconds().max(0)
        } else {
            0
        }
    }

    /// Get amount still needed to fully fund escrow
    pub fn funding_shortfall(&self) -> i64 {
        (self.amount - self.balance_received).max(0)
    }

    /// Get funding progress as percentage (0-100)
    pub fn funding_progress_percent(&self) -> u8 {
        if self.amount == 0 {
            return 0;
        }
        ((self.balance_received as f64 / self.amount as f64) * 100.0).min(100.0) as u8
    }

    /// Find all underfunded escrows (partial payment received)
    pub fn find_underfunded(conn: &mut SqliteConnection) -> Result<Vec<Escrow>> {
        escrows::table
            .filter(escrows::status.eq("underfunded"))
            .load(conn)
            .context("Failed to load underfunded escrows")
    }

    /// Find escrows with expired grace period
    pub fn find_grace_period_expired(conn: &mut SqliteConnection) -> Result<Vec<Escrow>> {
        let now = chrono::Utc::now().naive_utc();

        escrows::table
            .filter(escrows::grace_period_ends_at.is_not_null())
            .filter(escrows::grace_period_ends_at.lt(now))
            .filter(escrows::status.ne("completed"))
            .filter(escrows::status.ne("cancelled"))
            .filter(escrows::status.ne("cancelled_recoverable"))
            .load(conn)
            .context("Failed to load escrows with expired grace period")
    }

    // =========================================================================
    // v1.1.0: B2B Multi-Tenancy Methods
    // =========================================================================

    /// Find all escrows belonging to a B2B client
    pub fn find_by_client_id(conn: &mut SqliteConnection, client_id: &str) -> Result<Vec<Escrow>> {
        escrows::table
            .filter(escrows::client_id.eq(client_id))
            .order(escrows::created_at.desc())
            .load(conn)
            .context("Failed to load escrows for client")
    }

    /// Find escrow by ID scoped to a specific client (prevents cross-tenant access)
    pub fn find_by_id_scoped(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        client_id: &str,
    ) -> Result<Option<Escrow>> {
        escrows::table
            .filter(escrows::id.eq(escrow_id))
            .filter(escrows::client_id.eq(client_id))
            .first(conn)
            .optional()
            .context("Failed to query scoped escrow")
    }
}
