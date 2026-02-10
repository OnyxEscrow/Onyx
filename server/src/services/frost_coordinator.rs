//! FROST DKG Coordinator Service (RFC 9591)
//!
//! Coordinates the 3-round DKG protocol between buyer, vendor, and arbiter.
//! Each party can contribute asynchronously.
//!
//! ## Flow:
//! ```text
//! Round 1: Each party submits round1_package (public commitment)
//!          -> When all 3 submitted, round1_complete = true
//!
//! Round 2: Each party receives Round 1 packages, submits Round 2 packages
//!          -> Each party sends 2 packages (one to each other party)
//!          -> When all 6 packages submitted, round2_complete = true
//!
//! Round 3: Each party finalizes locally (KeyPackage, group_pubkey)
//!          -> Server stores group_pubkey in escrow
//!          -> DKG complete!
//! ```

use anyhow::{Context, Result};
use diesel::prelude::*;
use frost_ed25519::keys::dkg;
use frost_ed25519::Identifier;
use rand_core::OsRng;
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::models::frost_dkg::{
    compute_lagrange_coefficients, DkgStatus, FrostDkgState, FrostRole, NewFrostDkgState,
};
use crate::schema::{escrows, frost_dkg_state};

/// FROST DKG Coordinator
pub struct FrostCoordinator;

impl FrostCoordinator {
    /// Initialize FROST DKG for an escrow
    ///
    /// Creates the frost_dkg_state record and sets frost_enabled=true on escrow.
    /// **Idempotent**: Uses INSERT OR IGNORE to handle race conditions.
    /// **Protected**: Blocks re-initialization if DKG is already complete.
    pub fn init_dkg(conn: &mut SqliteConnection, escrow_id: &str) -> Result<FrostDkgState> {
        // v0.55.0 SECURITY: Prevent DKG re-initialization if already complete
        // This protects against race conditions where a second browser tab/user
        // could restart DKG and overwrite keys from a completed session
        if Self::is_dkg_complete(conn, escrow_id).unwrap_or(false) {
            warn!(
                escrow_id = %escrow_id,
                "Blocked DKG re-initialization: DKG already complete for this escrow"
            );
            // Return existing state instead of error to maintain idempotency for UI
            return Self::get_state(conn, escrow_id);
        }

        // Create DKG state record with INSERT OR IGNORE (race-safe)
        // If another participant already created it, this silently succeeds
        let new_state = NewFrostDkgState::new(escrow_id);
        diesel::insert_or_ignore_into(frost_dkg_state::table)
            .values(&new_state)
            .execute(conn)
            .context("Failed to create FROST DKG state")?;

        // Enable FROST on escrow (idempotent - can run multiple times)
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set(escrows::frost_enabled.eq(true))
            .execute(conn)
            .context("Failed to enable FROST on escrow")?;

        info!(escrow_id = %escrow_id, "FROST DKG initialized (or already existed)");

        // Return the state (either newly created or existing)
        Self::get_state(conn, escrow_id)
    }

    /// Get current DKG state
    pub fn get_state(conn: &mut SqliteConnection, escrow_id: &str) -> Result<FrostDkgState> {
        frost_dkg_state::table
            .find(escrow_id)
            .first(conn)
            .context("FROST DKG state not found")
    }

    /// Get DKG status (for API responses)
    ///
    /// Queries both frost_dkg_state and escrows.frost_dkg_complete for accurate status.
    pub fn get_status(conn: &mut SqliteConnection, escrow_id: &str) -> Result<DkgStatus> {
        let state = Self::get_state(conn, escrow_id)?;
        let dkg_complete = Self::is_dkg_complete(conn, escrow_id).unwrap_or(false);
        Ok(DkgStatus::from(&state).with_dkg_complete(dkg_complete))
    }

    /// Submit Round 1 package from a participant
    ///
    /// Returns true if all 3 participants have now submitted.
    /// **Protected**: Blocks submission if DKG is already complete.
    pub fn submit_round1(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        role: FrostRole,
        round1_package: &str,
    ) -> Result<bool> {
        // v0.55.0 SECURITY: Prevent DKG modification after completion
        if Self::is_dkg_complete(conn, escrow_id).unwrap_or(false) {
            anyhow::bail!("DKG already complete - cannot submit new Round 1 package");
        }

        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // Update the appropriate column based on role
        match role {
            FrostRole::Buyer => {
                diesel::update(frost_dkg_state::table.find(escrow_id))
                    .set((
                        frost_dkg_state::buyer_round1_package.eq(round1_package),
                        frost_dkg_state::updated_at.eq(&now),
                    ))
                    .execute(conn)
                    .context("Failed to store buyer Round 1 package")?;
            }
            FrostRole::Vendor => {
                diesel::update(frost_dkg_state::table.find(escrow_id))
                    .set((
                        frost_dkg_state::vendor_round1_package.eq(round1_package),
                        frost_dkg_state::updated_at.eq(&now),
                    ))
                    .execute(conn)
                    .context("Failed to store vendor Round 1 package")?;
            }
            FrostRole::Arbiter => {
                diesel::update(frost_dkg_state::table.find(escrow_id))
                    .set((
                        frost_dkg_state::arbiter_round1_package.eq(round1_package),
                        frost_dkg_state::updated_at.eq(&now),
                    ))
                    .execute(conn)
                    .context("Failed to store arbiter Round 1 package")?;
            }
        }

        info!(escrow_id = %escrow_id, role = ?role, "Round 1 package submitted");

        // Check if all 3 have submitted
        let state = Self::get_state(conn, escrow_id)?;
        let all_submitted = state.buyer_round1_package.is_some()
            && state.vendor_round1_package.is_some()
            && state.arbiter_round1_package.is_some();

        if all_submitted && !state.round1_complete {
            // Mark Round 1 as complete
            diesel::update(frost_dkg_state::table.find(escrow_id))
                .set((
                    frost_dkg_state::round1_complete.eq(true),
                    frost_dkg_state::updated_at.eq(&now),
                ))
                .execute(conn)
                .context("Failed to mark Round 1 complete")?;

            info!(escrow_id = %escrow_id, "Round 1 COMPLETE - all 3 parties submitted");
        }

        Ok(all_submitted)
    }

    /// Get all Round 1 packages (for Round 2 processing)
    ///
    /// Returns JSON: {"1": "hex...", "2": "hex...", "3": "hex..."}
    pub fn get_all_round1_packages(conn: &mut SqliteConnection, escrow_id: &str) -> Result<String> {
        let state = Self::get_state(conn, escrow_id)?;

        if !state.round1_complete {
            anyhow::bail!("Round 1 not complete yet");
        }

        let packages = serde_json::json!({
            "1": state.buyer_round1_package.as_ref().unwrap_or(&String::new()),
            "2": state.vendor_round1_package.as_ref().unwrap_or(&String::new()),
            "3": state.arbiter_round1_package.as_ref().unwrap_or(&String::new()),
        });

        Ok(packages.to_string())
    }

    /// Submit Round 2 packages from a participant
    ///
    /// Each participant sends 2 packages (one to each other party).
    /// **Protected**: Blocks submission if DKG is already complete.
    pub fn submit_round2(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        from_role: FrostRole,
        packages: &std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        // v0.55.0 SECURITY: Prevent DKG modification after completion
        if Self::is_dkg_complete(conn, escrow_id).unwrap_or(false) {
            anyhow::bail!("DKG already complete - cannot submit new Round 2 packages");
        }

        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // Debug: Log received package keys
        let keys: Vec<&String> = packages.keys().collect();
        info!(
            escrow_id = %escrow_id,
            from = ?from_role,
            keys = ?keys,
            "Round 2 packages received with keys"
        );

        // Store packages based on sender role
        match from_role {
            FrostRole::Buyer => {
                let to_vendor = packages.get("2").cloned();
                let to_arbiter = packages.get("3").cloned();
                diesel::update(frost_dkg_state::table.find(escrow_id))
                    .set((
                        frost_dkg_state::buyer_to_vendor_round2.eq(to_vendor),
                        frost_dkg_state::buyer_to_arbiter_round2.eq(to_arbiter),
                        frost_dkg_state::updated_at.eq(&now),
                    ))
                    .execute(conn)
                    .context("Failed to store buyer Round 2 packages")?;
            }
            FrostRole::Vendor => {
                let to_buyer = packages.get("1").cloned();
                let to_arbiter = packages.get("3").cloned();
                diesel::update(frost_dkg_state::table.find(escrow_id))
                    .set((
                        frost_dkg_state::vendor_to_buyer_round2.eq(to_buyer),
                        frost_dkg_state::vendor_to_arbiter_round2.eq(to_arbiter),
                        frost_dkg_state::updated_at.eq(&now),
                    ))
                    .execute(conn)
                    .context("Failed to store vendor Round 2 packages")?;
            }
            FrostRole::Arbiter => {
                let to_buyer = packages.get("1").cloned();
                let to_vendor = packages.get("2").cloned();
                diesel::update(frost_dkg_state::table.find(escrow_id))
                    .set((
                        frost_dkg_state::arbiter_to_buyer_round2.eq(to_buyer),
                        frost_dkg_state::arbiter_to_vendor_round2.eq(to_vendor),
                        frost_dkg_state::updated_at.eq(&now),
                    ))
                    .execute(conn)
                    .context("Failed to store arbiter Round 2 packages")?;
            }
        }

        info!(escrow_id = %escrow_id, from = ?from_role, "Round 2 packages submitted");

        // Check if all packages submitted
        let state = Self::get_state(conn, escrow_id)?;
        let buyer_done =
            state.buyer_to_vendor_round2.is_some() && state.buyer_to_arbiter_round2.is_some();
        let vendor_done =
            state.vendor_to_buyer_round2.is_some() && state.vendor_to_arbiter_round2.is_some();
        let arbiter_done =
            state.arbiter_to_buyer_round2.is_some() && state.arbiter_to_vendor_round2.is_some();

        let all_complete = buyer_done && vendor_done && arbiter_done;

        // Debug: Log completion status
        info!(
            escrow_id = %escrow_id,
            buyer_done = %buyer_done,
            vendor_done = %vendor_done,
            arbiter_done = %arbiter_done,
            all_complete = %all_complete,
            "Round 2 completion check"
        );

        if all_complete && !state.round2_complete {
            diesel::update(frost_dkg_state::table.find(escrow_id))
                .set((
                    frost_dkg_state::round2_complete.eq(true),
                    frost_dkg_state::updated_at.eq(&now),
                ))
                .execute(conn)
                .context("Failed to mark Round 2 complete")?;

            info!(escrow_id = %escrow_id, "Round 2 COMPLETE - all 6 packages submitted");
        }

        Ok(all_complete)
    }

    /// Get Round 2 packages destined for a specific participant
    ///
    /// Returns JSON: {"from_index": "hex_package", ...}
    pub fn get_round2_packages_for(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        role: FrostRole,
    ) -> Result<String> {
        let state = Self::get_state(conn, escrow_id)?;

        if !state.round1_complete {
            anyhow::bail!("Round 1 not complete yet");
        }

        let packages = match role {
            FrostRole::Buyer => {
                // Buyer receives from vendor (2) and arbiter (3)
                serde_json::json!({
                    "2": state.vendor_to_buyer_round2.unwrap_or_default(),
                    "3": state.arbiter_to_buyer_round2.unwrap_or_default(),
                })
            }
            FrostRole::Vendor => {
                // Vendor receives from buyer (1) and arbiter (3)
                serde_json::json!({
                    "1": state.buyer_to_vendor_round2.unwrap_or_default(),
                    "3": state.arbiter_to_vendor_round2.unwrap_or_default(),
                })
            }
            FrostRole::Arbiter => {
                // Arbiter receives from buyer (1) and vendor (2)
                serde_json::json!({
                    "1": state.buyer_to_arbiter_round2.unwrap_or_default(),
                    "2": state.vendor_to_arbiter_round2.unwrap_or_default(),
                })
            }
        };

        Ok(packages.to_string())
    }

    /// Complete DKG by storing the group public key and derived address
    ///
    /// Called after a participant completes Round 3 locally.
    /// Stores the address and view key so the blockchain monitor can track funding.
    /// **Protected**: Validates consistency if DKG already complete.
    pub fn complete_dkg(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        group_pubkey: &str,
        multisig_address: &str,
        multisig_view_key: &str,
    ) -> Result<()> {
        // v0.55.0 SECURITY: Check if DKG is already complete
        // If so, verify the incoming data matches existing data
        if Self::is_dkg_complete(conn, escrow_id).unwrap_or(false) {
            // Get existing group pubkey to validate consistency
            let existing_pubkey: Option<String> = escrows::table
                .filter(escrows::id.eq(escrow_id))
                .select(escrows::frost_group_pubkey)
                .first(conn)
                .context("Failed to get existing group pubkey")?;

            if let Some(existing) = existing_pubkey {
                if existing != group_pubkey {
                    // CRITICAL: Different group pubkey = different DKG = key mixup!
                    anyhow::bail!(
                        "DKG already complete with different group_pubkey! \
                         Existing: {}..., Incoming: {}... - possible key mixup detected",
                        &existing[..16.min(existing.len())],
                        &group_pubkey[..16.min(group_pubkey.len())]
                    );
                }
            }
            // Same group_pubkey = idempotent call, just return success
            info!(escrow_id = %escrow_id, "DKG complete_dkg called again (idempotent)");
            return Ok(());
        }

        // Store group pubkey, address, view key and mark DKG complete on escrow
        diesel::update(escrows::table.filter(escrows::id.eq(escrow_id)))
            .set((
                escrows::frost_group_pubkey.eq(group_pubkey),
                escrows::frost_dkg_complete.eq(true),
                escrows::multisig_address.eq(multisig_address),
                escrows::multisig_view_key.eq(multisig_view_key),
                // Also set status to "created" so monitor starts watching
                escrows::status.eq("created"),
            ))
            .execute(conn)
            .context("Failed to complete FROST DKG")?;

        info!(
            escrow_id = %escrow_id,
            address_prefix = &multisig_address[..10],
            "FROST DKG COMPLETE - address stored, monitor can now watch for funding"
        );

        Ok(())
    }

    /// Get Lagrange coefficients for a signing pair
    ///
    /// Returns (λ_signer1, λ_signer2) as hex scalars.
    pub fn get_lagrange_coefficients(
        signer1_role: &str,
        signer2_role: &str,
    ) -> Result<(String, String)> {
        let role1 = FrostRole::from_str(signer1_role)
            .ok_or_else(|| anyhow::anyhow!("Invalid role: {}", signer1_role))?;
        let role2 = FrostRole::from_str(signer2_role)
            .ok_or_else(|| anyhow::anyhow!("Invalid role: {}", signer2_role))?;

        Ok(compute_lagrange_coefficients(role1, role2))
    }

    /// Check if escrow has FROST enabled
    pub fn is_frost_enabled(conn: &mut SqliteConnection, escrow_id: &str) -> Result<bool> {
        let enabled: bool = escrows::table
            .filter(escrows::id.eq(escrow_id))
            .select(escrows::frost_enabled)
            .first(conn)
            .context("Escrow not found")?;

        Ok(enabled)
    }

    /// Check if FROST DKG is complete for an escrow
    pub fn is_dkg_complete(conn: &mut SqliteConnection, escrow_id: &str) -> Result<bool> {
        let complete: bool = escrows::table
            .filter(escrows::id.eq(escrow_id))
            .select(escrows::frost_dkg_complete)
            .first(conn)
            .context("Escrow not found")?;

        Ok(complete)
    }

    // =========================================================================
    // ARBITER AUTO-DKG FUNCTIONS
    // =========================================================================

    /// Check if arbiter Round 1 should be auto-generated
    ///
    /// Returns true if:
    /// - Buyer Round 1 package is present
    /// - Vendor Round 1 package is present
    /// - Arbiter Round 1 package is NOT present
    pub fn should_auto_generate_arbiter_round1(
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<bool> {
        let state = Self::get_state(conn, escrow_id)?;

        let should_gen = state.buyer_round1_package.is_some()
            && state.vendor_round1_package.is_some()
            && state.arbiter_round1_package.is_none();

        debug!(
            escrow_id = %escrow_id,
            buyer_r1 = state.buyer_round1_package.is_some(),
            vendor_r1 = state.vendor_round1_package.is_some(),
            arbiter_r1 = state.arbiter_round1_package.is_some(),
            should_gen = should_gen,
            "Checking arbiter R1 auto-gen condition"
        );

        Ok(should_gen)
    }

    /// Generate arbiter's Round 1 package
    ///
    /// Returns (round1_package_hex, secret_package_hex)
    /// The secret must be stored securely (Redis via ArbiterKeyVault)
    pub fn generate_arbiter_round1() -> Result<(String, String)> {
        let id_arbiter = Identifier::try_from(3u16)
            .map_err(|e| anyhow::anyhow!("Failed to create arbiter identifier: {:?}", e))?;

        let threshold = 2u16;
        let max_signers = 3u16;

        let (r1_secret, r1_package) = dkg::part1(id_arbiter, max_signers, threshold, &mut OsRng)
            .map_err(|e| anyhow::anyhow!("FROST DKG part1 failed: {:?}", e))?;

        // Serialize to hex
        let package_hex = hex::encode(
            r1_package
                .serialize()
                .map_err(|e| anyhow::anyhow!("Failed to serialize R1 package: {:?}", e))?,
        );
        let secret_hex = hex::encode(
            r1_secret
                .serialize()
                .map_err(|e| anyhow::anyhow!("Failed to serialize R1 secret: {:?}", e))?,
        );

        info!("Generated arbiter Round 1 package");

        Ok((package_hex, secret_hex))
    }

    /// Check if arbiter Round 2 should be auto-generated
    ///
    /// Returns true if:
    /// - Round 1 is complete
    /// - Buyer Round 2 packages are present
    /// - Vendor Round 2 packages are present
    /// - Arbiter Round 2 packages are NOT present
    pub fn should_auto_generate_arbiter_round2(
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<bool> {
        let state = Self::get_state(conn, escrow_id)?;

        if !state.round1_complete {
            return Ok(false);
        }

        let buyer_r2_done =
            state.buyer_to_vendor_round2.is_some() && state.buyer_to_arbiter_round2.is_some();
        let vendor_r2_done =
            state.vendor_to_buyer_round2.is_some() && state.vendor_to_arbiter_round2.is_some();
        let arbiter_r2_done =
            state.arbiter_to_buyer_round2.is_some() && state.arbiter_to_vendor_round2.is_some();

        let should_gen = buyer_r2_done && vendor_r2_done && !arbiter_r2_done;

        debug!(
            escrow_id = %escrow_id,
            buyer_r2 = buyer_r2_done,
            vendor_r2 = vendor_r2_done,
            arbiter_r2 = arbiter_r2_done,
            should_gen = should_gen,
            "Checking arbiter R2 auto-gen condition"
        );

        Ok(should_gen)
    }

    /// Generate arbiter's Round 2 packages
    ///
    /// Takes the arbiter's R1 secret (from vault) and generates R2 packages
    /// Returns (packages_map, r2_secret_hex)
    pub fn generate_arbiter_round2(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        arbiter_r1_secret_hex: &str,
    ) -> Result<(std::collections::HashMap<String, String>, String)> {
        let state = Self::get_state(conn, escrow_id)?;

        // Deserialize arbiter's R1 secret
        let r1_secret_bytes =
            hex::decode(arbiter_r1_secret_hex).context("Failed to decode arbiter R1 secret hex")?;
        let r1_secret = dkg::round1::SecretPackage::deserialize(&r1_secret_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize R1 secret: {:?}", e))?;

        // Get other parties' R1 packages
        let id_buyer = Identifier::try_from(1u16).unwrap();
        let id_vendor = Identifier::try_from(2u16).unwrap();

        let buyer_r1_bytes = hex::decode(
            state
                .buyer_round1_package
                .as_ref()
                .context("Buyer R1 package missing")?,
        )
        .context("Failed to decode buyer R1 package")?;
        let vendor_r1_bytes = hex::decode(
            state
                .vendor_round1_package
                .as_ref()
                .context("Vendor R1 package missing")?,
        )
        .context("Failed to decode vendor R1 package")?;

        let buyer_r1 = dkg::round1::Package::deserialize(&buyer_r1_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize buyer R1: {:?}", e))?;
        let vendor_r1 = dkg::round1::Package::deserialize(&vendor_r1_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize vendor R1: {:?}", e))?;

        // Build map of other R1 packages
        let mut other_r1 = BTreeMap::new();
        other_r1.insert(id_buyer, buyer_r1);
        other_r1.insert(id_vendor, vendor_r1);

        // Generate Round 2
        let (r2_secret, r2_packages) = dkg::part2(r1_secret, &other_r1)
            .map_err(|e| anyhow::anyhow!("FROST DKG part2 failed: {:?}", e))?;

        // Convert to HashMap<String, String> (recipient_index -> package_hex)
        let mut packages = std::collections::HashMap::new();
        for (id, pkg) in r2_packages {
            // Convert Identifier to index string (1=buyer, 2=vendor, 3=arbiter)
            let index = if id == id_buyer {
                "1".to_string()
            } else if id == id_vendor {
                "2".to_string()
            } else {
                // This shouldn't happen for arbiter's packages (only to buyer/vendor)
                continue;
            };
            let pkg_hex = hex::encode(
                pkg.serialize()
                    .map_err(|e| anyhow::anyhow!("Failed to serialize R2 package: {:?}", e))?,
            );
            packages.insert(index, pkg_hex);
        }

        let secret_hex = hex::encode(
            r2_secret
                .serialize()
                .map_err(|e| anyhow::anyhow!("Failed to serialize R2 secret: {:?}", e))?,
        );

        info!(
            escrow_id = %escrow_id,
            packages_count = packages.len(),
            "Generated arbiter Round 2 packages"
        );

        Ok((packages, secret_hex))
    }

    /// Check if arbiter Round 3 (finalization) should be auto-generated
    ///
    /// Returns true if:
    /// - Round 2 is complete
    /// - Arbiter has received all R2 packages destined for them
    pub fn should_auto_generate_arbiter_round3(
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<bool> {
        let state = Self::get_state(conn, escrow_id)?;

        if !state.round2_complete {
            return Ok(false);
        }

        // Arbiter receives R2 packages from buyer and vendor
        let has_r2_from_buyer = state.buyer_to_arbiter_round2.is_some();
        let has_r2_from_vendor = state.vendor_to_arbiter_round2.is_some();

        let should_gen = has_r2_from_buyer && has_r2_from_vendor;

        debug!(
            escrow_id = %escrow_id,
            r2_from_buyer = has_r2_from_buyer,
            r2_from_vendor = has_r2_from_vendor,
            should_gen = should_gen,
            "Checking arbiter R3 auto-gen condition"
        );

        Ok(should_gen)
    }

    /// Generate arbiter's Round 3 (finalization) - KeyPackage
    ///
    /// Takes the arbiter's R2 secret and generates the final key_package
    /// Returns (key_package_hex, group_pubkey_hex)
    pub fn generate_arbiter_round3(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        arbiter_r2_secret_hex: &str,
    ) -> Result<(String, String)> {
        let state = Self::get_state(conn, escrow_id)?;

        // Deserialize arbiter's R2 secret
        let r2_secret_bytes =
            hex::decode(arbiter_r2_secret_hex).context("Failed to decode arbiter R2 secret hex")?;
        let r2_secret = dkg::round2::SecretPackage::deserialize(&r2_secret_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize R2 secret: {:?}", e))?;

        // Get other parties' R1 packages (needed for part3)
        let id_buyer = Identifier::try_from(1u16).unwrap();
        let id_vendor = Identifier::try_from(2u16).unwrap();

        let buyer_r1_bytes = hex::decode(
            state
                .buyer_round1_package
                .as_ref()
                .context("Buyer R1 package missing")?,
        )?;
        let vendor_r1_bytes = hex::decode(
            state
                .vendor_round1_package
                .as_ref()
                .context("Vendor R1 package missing")?,
        )?;

        let buyer_r1 = dkg::round1::Package::deserialize(&buyer_r1_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize buyer R1: {:?}", e))?;
        let vendor_r1 = dkg::round1::Package::deserialize(&vendor_r1_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize vendor R1: {:?}", e))?;

        let mut other_r1 = BTreeMap::new();
        other_r1.insert(id_buyer, buyer_r1);
        other_r1.insert(id_vendor, vendor_r1);

        // Get R2 packages destined for arbiter
        let r2_from_buyer_bytes = hex::decode(
            state
                .buyer_to_arbiter_round2
                .as_ref()
                .context("R2 from buyer missing")?,
        )?;
        let r2_from_vendor_bytes = hex::decode(
            state
                .vendor_to_arbiter_round2
                .as_ref()
                .context("R2 from vendor missing")?,
        )?;

        let r2_from_buyer = dkg::round2::Package::deserialize(&r2_from_buyer_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize R2 from buyer: {:?}", e))?;
        let r2_from_vendor = dkg::round2::Package::deserialize(&r2_from_vendor_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize R2 from vendor: {:?}", e))?;

        let mut r2_for_arbiter = BTreeMap::new();
        r2_for_arbiter.insert(id_buyer, r2_from_buyer);
        r2_for_arbiter.insert(id_vendor, r2_from_vendor);

        // Finalize Round 3
        let (key_package, pub_package) = dkg::part3(&r2_secret, &other_r1, &r2_for_arbiter)
            .map_err(|e| anyhow::anyhow!("FROST DKG part3 failed: {:?}", e))?;

        // Serialize
        let key_package_hex = hex::encode(
            key_package
                .serialize()
                .map_err(|e| anyhow::anyhow!("Failed to serialize key_package: {:?}", e))?,
        );
        let group_pubkey_hex = hex::encode(
            pub_package
                .verifying_key()
                .serialize()
                .map_err(|e| anyhow::anyhow!("Failed to serialize group pubkey: {:?}", e))?,
        );

        info!(
            escrow_id = %escrow_id,
            group_pubkey_prefix = &group_pubkey_hex[..16],
            "Generated arbiter key_package (DKG Round 3 complete)"
        );

        Ok((key_package_hex, group_pubkey_hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lagrange_coefficients() {
        let (l1, l2) = FrostCoordinator::get_lagrange_coefficients("buyer", "vendor").unwrap();
        assert!(!l1.is_empty());
        assert!(!l2.is_empty());
        assert_eq!(l1.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(l2.len(), 64);
    }

    #[test]
    fn test_lagrange_all_pairs() {
        // Test all valid signing pairs
        let pairs = [
            ("buyer", "vendor"),
            ("buyer", "arbiter"),
            ("vendor", "arbiter"),
        ];

        for (r1, r2) in pairs {
            let (l1, l2) = FrostCoordinator::get_lagrange_coefficients(r1, r2).unwrap();
            assert_eq!(l1.len(), 64);
            assert_eq!(l2.len(), 64);
        }
    }
}
