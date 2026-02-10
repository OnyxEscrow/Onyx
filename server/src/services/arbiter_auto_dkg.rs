//! Arbiter Auto-DKG Service
//!
//! Orchestrates automatic generation of Arbiter's DKG rounds when both
//! Buyer and Vendor have submitted their packages.
//!
//! ## Flow
//! ```text
//! 1. Buyer submits Round 1 → check if we should auto-generate
//! 2. Vendor submits Round 1 → trigger Arbiter Round 1 auto-gen
//! 3. Round 1 complete → trigger Arbiter Round 2 auto-gen
//! 4. Round 2 complete → trigger Arbiter Round 3 auto-gen (finalization)
//! ```
//!
//! ## Security
//! - All Arbiter secrets stored encrypted via ArbiterKeyVault
//! - Uses same Argon2id + ChaCha20Poly1305 as final key_package storage
//! - Secrets cleaned up after Round 3 finalization

use anyhow::{Context, Result};
use diesel::prelude::*;
use tracing::{debug, error, info, warn};

use crate::db::DbPool;
use crate::models::frost_dkg::FrostRole;
use crate::services::arbiter_watchdog::ArbiterKeyVault;
use crate::services::frost_coordinator::FrostCoordinator;

/// Arbiter Auto-DKG Service
///
/// Bridges the sync FrostCoordinator with the async ArbiterKeyVault.
pub struct ArbiterAutoDkg {
    db_pool: DbPool,
    key_vault: ArbiterKeyVault,
}

impl ArbiterAutoDkg {
    /// Create a new ArbiterAutoDkg service
    pub fn new(db_pool: DbPool, key_vault: ArbiterKeyVault) -> Self {
        Self { db_pool, key_vault }
    }

    /// Check and trigger Arbiter Round 1 auto-generation
    ///
    /// Should be called after a Buyer or Vendor submits Round 1.
    /// Generates Arbiter's Round 1 if both parties have submitted.
    pub async fn maybe_generate_round1(&self, escrow_id: &str) -> Result<bool> {
        debug!(escrow_id = %escrow_id, "Checking if Arbiter Round 1 auto-generation needed");

        let mut conn = self
            .db_pool
            .get()
            .context("Failed to get DB connection for Arbiter auto-DKG")?;

        // Check if we should generate
        let should_gen =
            FrostCoordinator::should_auto_generate_arbiter_round1(&mut conn, escrow_id)
                .context("Failed to check if Arbiter R1 should be generated")?;

        if !should_gen {
            debug!(escrow_id = %escrow_id, "Arbiter Round 1 auto-gen not needed (waiting for both parties)");
            return Ok(false);
        }

        info!(escrow_id = %escrow_id, "🤖 Auto-generating Arbiter Round 1 (both parties submitted)");

        // Generate Round 1 (sync crypto operation)
        let (round1_package, secret_package) = FrostCoordinator::generate_arbiter_round1()
            .context("Crypto error generating Arbiter Round 1")?;

        debug!(
            escrow_id = %escrow_id,
            package_len = round1_package.len(),
            "Arbiter Round 1 package generated, storing secret in vault"
        );

        // Store secret in vault (async Redis)
        self.key_vault
            .store_dkg_round1_secret(escrow_id, &secret_package)
            .await
            .context("Failed to store Arbiter R1 secret in Redis vault")?;

        debug!(escrow_id = %escrow_id, "Arbiter R1 secret stored, submitting package to DB");

        // Submit Round 1 package to DB (sync)
        let all_submitted = FrostCoordinator::submit_round1(
            &mut conn,
            escrow_id,
            FrostRole::Arbiter,
            &round1_package,
        )
        .context("Failed to submit Arbiter R1 package to database")?;

        info!(
            escrow_id = %escrow_id,
            all_submitted = all_submitted,
            "✅ Arbiter Round 1 auto-generated and submitted"
        );

        // If all 3 submitted, also trigger Round 2
        if all_submitted {
            debug!(escrow_id = %escrow_id, "All 3 Round 1 packages complete, triggering Round 2 auto-gen");
            self.maybe_generate_round2(escrow_id).await?;
        }

        Ok(true)
    }

    /// Check and trigger Arbiter Round 2 auto-generation
    ///
    /// Should be called after Round 1 is complete or after Buyer/Vendor
    /// submits their Round 2.
    pub async fn maybe_generate_round2(&self, escrow_id: &str) -> Result<bool> {
        debug!(escrow_id = %escrow_id, "Checking if Arbiter Round 2 auto-generation needed");

        let mut conn = self
            .db_pool
            .get()
            .context("Failed to get DB connection for Arbiter R2 auto-DKG")?;

        // Check if we should generate
        let should_gen =
            FrostCoordinator::should_auto_generate_arbiter_round2(&mut conn, escrow_id)
                .context("Failed to check if Arbiter R2 should be generated")?;

        if !should_gen {
            debug!(escrow_id = %escrow_id, "Arbiter Round 2 auto-gen not needed yet");
            return Ok(false);
        }

        info!(escrow_id = %escrow_id, "🤖 Auto-generating Arbiter Round 2");

        // Retrieve Round 1 secret from vault
        let arbiter_r1_secret = self
            .key_vault
            .get_dkg_round1_secret(escrow_id)
            .await
            .context("Failed to retrieve Arbiter R1 secret from Redis vault")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Arbiter R1 secret not found in vault for escrow {}. \
                 This may indicate Redis connection issues or key expiration.",
                    escrow_id
                )
            })?;

        debug!(escrow_id = %escrow_id, "Retrieved Arbiter R1 secret, generating Round 2 packages");

        // Generate Round 2 (sync crypto operation)
        let (packages, round2_secret) =
            FrostCoordinator::generate_arbiter_round2(&mut conn, escrow_id, &arbiter_r1_secret)
                .context("Crypto error generating Arbiter Round 2 packages")?;

        debug!(
            escrow_id = %escrow_id,
            package_count = packages.len(),
            "Arbiter Round 2 packages generated, storing R2 secret"
        );

        // Store Round 2 secret in vault (async Redis)
        self.key_vault
            .store_dkg_round2_secret(escrow_id, &round2_secret)
            .await
            .context("Failed to store Arbiter R2 secret in Redis vault")?;

        // Submit Round 2 packages to DB (sync)
        let all_submitted =
            FrostCoordinator::submit_round2(&mut conn, escrow_id, FrostRole::Arbiter, &packages)
                .context("Failed to submit Arbiter R2 packages to database")?;

        info!(
            escrow_id = %escrow_id,
            all_submitted = all_submitted,
            packages_to_buyer = packages.contains_key("1"),
            packages_to_vendor = packages.contains_key("2"),
            "✅ Arbiter Round 2 auto-generated and submitted"
        );

        // If all 6 submitted, also trigger Round 3
        if all_submitted {
            debug!(escrow_id = %escrow_id, "All 6 Round 2 packages complete, triggering Round 3 auto-gen");
            self.maybe_generate_round3(escrow_id).await?;
        }

        Ok(true)
    }

    /// Check and trigger Arbiter Round 3 auto-generation (finalization)
    ///
    /// Should be called after Round 2 is complete.
    pub async fn maybe_generate_round3(&self, escrow_id: &str) -> Result<bool> {
        debug!(escrow_id = %escrow_id, "Checking if Arbiter Round 3 (finalization) needed");

        let mut conn = self
            .db_pool
            .get()
            .context("Failed to get DB connection for Arbiter R3 auto-DKG")?;

        // Check if we should generate
        let should_gen =
            FrostCoordinator::should_auto_generate_arbiter_round3(&mut conn, escrow_id)
                .context("Failed to check if Arbiter R3 should be generated")?;

        if !should_gen {
            debug!(escrow_id = %escrow_id, "Arbiter Round 3 auto-gen not needed yet");
            return Ok(false);
        }

        info!(escrow_id = %escrow_id, "🤖 Auto-generating Arbiter Round 3 (finalization)");

        // Retrieve Round 2 secret from vault
        let arbiter_r2_secret = self
            .key_vault
            .get_dkg_round2_secret(escrow_id)
            .await
            .context("Failed to retrieve Arbiter R2 secret from Redis vault")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Arbiter R2 secret not found in vault for escrow {}. \
                 This may indicate Redis connection issues or key expiration.",
                    escrow_id
                )
            })?;

        debug!(escrow_id = %escrow_id, "Retrieved Arbiter R2 secret, finalizing key package");

        // Generate Round 3 (sync crypto operation)
        let (key_package, group_public_key) =
            FrostCoordinator::generate_arbiter_round3(&mut conn, escrow_id, &arbiter_r2_secret)
                .context("Crypto error generating Arbiter Round 3 (finalization)")?;

        debug!(
            escrow_id = %escrow_id,
            key_package_len = key_package.len(),
            "Arbiter key_package generated, storing in vault"
        );

        // Store final key_package in vault (for auto-signing later)
        self.key_vault
            .store_key_package(escrow_id, &key_package)
            .await
            .context("Failed to store Arbiter key_package in Redis vault")?;

        // Clean up temporary DKG secrets
        self.key_vault
            .cleanup_dkg_secrets(escrow_id)
            .await
            .context("Failed to cleanup temporary DKG secrets from Redis")?;

        info!(
            escrow_id = %escrow_id,
            group_pubkey_prefix = &group_public_key[..16.min(group_public_key.len())],
            "✅ Arbiter DKG COMPLETE - key_package stored for auto-signing"
        );

        Ok(true)
    }

    /// Full auto-DKG check - runs all phases if needed
    ///
    /// Useful for recovery or manual triggering.
    pub async fn run_full_check(&self, escrow_id: &str) -> Result<()> {
        // Try each phase in order
        if self.maybe_generate_round1(escrow_id).await? {
            info!(escrow_id = %escrow_id, "Round 1 auto-generated");
        }

        if self.maybe_generate_round2(escrow_id).await? {
            info!(escrow_id = %escrow_id, "Round 2 auto-generated");
        }

        if self.maybe_generate_round3(escrow_id).await? {
            info!(escrow_id = %escrow_id, "Round 3 auto-generated");
        }

        Ok(())
    }
}
