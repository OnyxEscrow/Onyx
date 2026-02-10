//! FROST Auto-Signer - Generates arbiter partial signatures
//!
//! Uses the stored arbiter key_package to compute FROST partial signatures
//! for escrow release or refund transactions.

use anyhow::{Context, Result};
use diesel::prelude::*;
use frost_ed25519::{
    keys::KeyPackage,
    round1::{self, SigningCommitments},
    round2, Identifier, SigningPackage,
};
use tracing::info;

use crate::db::DbPool;
use crate::models::escrow::Escrow;
use crate::schema::escrows;
use crate::services::arbiter_watchdog::key_vault::ArbiterKeyVault;

/// FROST Auto-Signer for generating arbiter partial signatures
pub struct FrostAutoSigner {
    key_vault: ArbiterKeyVault,
    db_pool: DbPool,
}

impl FrostAutoSigner {
    /// Create a new FrostAutoSigner
    pub fn new(key_vault: ArbiterKeyVault, db_pool: DbPool) -> Self {
        Self { key_vault, db_pool }
    }

    /// Sign for release (vendor payout)
    ///
    /// # Arguments
    /// * `escrow_id` - The escrow ID
    /// * `vendor_address` - Vendor's payout address (for audit log only)
    ///
    /// # Process
    /// 1. Retrieve arbiter key_package from vault
    /// 2. Generate signing nonces
    /// 3. Compute partial signature
    /// 4. Store partial signature in escrow record
    pub async fn sign_release(&self, escrow_id: &str, _vendor_address: &str) -> Result<()> {
        info!(
            escrow_id = %escrow_id,
            action = "release",
            "Auto-signing for vendor payout"
        );

        // Get escrow details
        let escrow = self.get_escrow(escrow_id).await?;

        // Validate escrow state for release
        self.validate_release_state(&escrow)?;

        // Perform the signing
        let partial_sig = self.compute_partial_signature(escrow_id, &escrow).await?;

        // Store the partial signature
        self.store_partial_signature(escrow_id, &partial_sig)
            .await?;

        info!(
            escrow_id = %escrow_id,
            action = "release",
            "Auto-signing complete"
        );

        Ok(())
    }

    /// Sign for refund (buyer refund)
    ///
    /// # Arguments
    /// * `escrow_id` - The escrow ID
    /// * `buyer_address` - Buyer's refund address (for audit log only)
    pub async fn sign_refund(&self, escrow_id: &str, _buyer_address: &str) -> Result<()> {
        info!(
            escrow_id = %escrow_id,
            action = "refund",
            "Auto-signing for buyer refund"
        );

        // Get escrow details
        let escrow = self.get_escrow(escrow_id).await?;

        // Validate escrow state for refund
        self.validate_refund_state(&escrow)?;

        // Perform the signing
        let partial_sig = self.compute_partial_signature(escrow_id, &escrow).await?;

        // Store the partial signature
        self.store_partial_signature(escrow_id, &partial_sig)
            .await?;

        info!(
            escrow_id = %escrow_id,
            action = "refund",
            "Auto-signing complete"
        );

        Ok(())
    }

    /// Get escrow from database
    async fn get_escrow(&self, escrow_id: &str) -> Result<Escrow> {
        let db_pool = self.db_pool.clone();
        let escrow_id = escrow_id.to_string();

        tokio::task::spawn_blocking(move || {
            let mut conn = db_pool.get().context("Failed to get DB connection")?;
            Escrow::find_by_id(&mut conn, escrow_id)
        })
        .await
        .context("Task join error")?
    }

    /// Validate escrow state for release
    fn validate_release_state(&self, escrow: &Escrow) -> Result<()> {
        // For dispute-resolved releases, skip normal party consent checks
        if escrow.status == "disputed"
            && escrow.dispute_signing_pair.as_deref() == Some("arbiter_vendor")
        {
            // Arbiter decided in favor of vendor — skip buyer_release_requested check
            if escrow.vendor_payout_address.is_none() {
                return Err(anyhow::anyhow!("Vendor payout address not set"));
            }
            if escrow.arbiter_frost_partial_sig.is_some() {
                return Err(anyhow::anyhow!("Arbiter has already signed"));
            }
            return Ok(());
        }

        // Must have buyer release request
        if !escrow.buyer_release_requested {
            return Err(anyhow::anyhow!("Buyer has not requested release"));
        }

        // Must have vendor signature
        if escrow.vendor_signature.is_none() {
            return Err(anyhow::anyhow!("Vendor has not signed yet"));
        }

        // Must have vendor payout address
        if escrow.vendor_payout_address.is_none() {
            return Err(anyhow::anyhow!("Vendor payout address not set"));
        }

        // Must not be disputed (unless arbiter already decided via dispute_signing_pair)
        if escrow.status == "disputed" && escrow.dispute_signing_pair.is_none() {
            return Err(anyhow::anyhow!(
                "Cannot auto-sign disputed escrow without arbiter decision"
            ));
        }

        // Must not already have arbiter signature
        if escrow.arbiter_frost_partial_sig.is_some() {
            return Err(anyhow::anyhow!("Arbiter has already signed"));
        }

        Ok(())
    }

    /// Validate escrow state for refund
    fn validate_refund_state(&self, escrow: &Escrow) -> Result<()> {
        // For dispute-resolved refunds, skip normal party consent checks
        if escrow.status == "disputed"
            && escrow.dispute_signing_pair.as_deref() == Some("arbiter_buyer")
        {
            // Arbiter decided in favor of buyer — skip vendor_refund_requested check
            if escrow.buyer_refund_address.is_none() {
                return Err(anyhow::anyhow!("Buyer refund address not set"));
            }
            if escrow.arbiter_frost_partial_sig.is_some() {
                return Err(anyhow::anyhow!("Arbiter has already signed"));
            }
            return Ok(());
        }

        // Must have vendor refund request
        if !escrow.vendor_refund_requested {
            return Err(anyhow::anyhow!("Vendor has not requested refund"));
        }

        // Must have buyer signature
        if escrow.buyer_signature.is_none() {
            return Err(anyhow::anyhow!("Buyer has not signed yet"));
        }

        // Must have buyer refund address
        if escrow.buyer_refund_address.is_none() {
            return Err(anyhow::anyhow!("Buyer refund address not set"));
        }

        // Must not be disputed (unless arbiter already decided via dispute_signing_pair)
        if escrow.status == "disputed" && escrow.dispute_signing_pair.is_none() {
            return Err(anyhow::anyhow!(
                "Cannot auto-sign disputed escrow without arbiter decision"
            ));
        }

        // Must not already have arbiter signature
        if escrow.arbiter_frost_partial_sig.is_some() {
            return Err(anyhow::anyhow!("Arbiter has already signed"));
        }

        Ok(())
    }

    /// Compute partial FROST signature
    ///
    /// This is the core signing logic using frost-ed25519.
    async fn compute_partial_signature(&self, escrow_id: &str, escrow: &Escrow) -> Result<String> {
        // 1. Retrieve key_package from vault
        let key_package_hex = self
            .key_vault
            .retrieve_key_package(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Arbiter key_package not found in vault"))?;

        // 2. Deserialize key_package
        let key_package_bytes =
            hex::decode(&key_package_hex).context("Failed to decode key_package hex")?;
        let key_package: KeyPackage = postcard::from_bytes(&key_package_bytes)
            .context("Failed to deserialize key_package")?;

        // 3. Get the message to sign (tx_prefix_hash from signing session)
        let message = self
            .get_signing_message(escrow)
            .context("Failed to get signing message")?;

        // 4. Generate signing nonces (Round 1)
        let mut rng = rand::rngs::OsRng;
        let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);

        // 5. Get other signers' commitments from escrow
        // In a 2-of-3 setup, we need the other signer's commitment
        let signing_package = self.build_signing_package(escrow, &commitments, &message)?;

        // 6. Generate partial signature (Round 2)
        let signature_share = round2::sign(&signing_package, &nonces, &key_package)
            .context("FROST Round 2 signing failed")?;

        // 7. Serialize and return as hex
        let sig_bytes = postcard::to_allocvec(&signature_share)
            .context("Failed to serialize signature share")?;

        Ok(hex::encode(&sig_bytes))
    }

    /// Get the message to sign from the escrow's signing session
    fn get_signing_message(&self, escrow: &Escrow) -> Result<Vec<u8>> {
        // The signing message is typically the tx_prefix_hash stored during signing setup
        // This should be available from the ring_data_json or a dedicated field

        // For now, we'll use a placeholder approach
        // In production, this would fetch from signing_sessions table or escrow.ring_data_json
        let ring_data = escrow
            .ring_data_json
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ring_data_json not set - signing not prepared"))?;

        // Parse ring_data to extract tx_prefix_hash
        let parsed: serde_json::Value =
            serde_json::from_str(ring_data).context("Failed to parse ring_data_json")?;

        let tx_prefix_hash = parsed["tx_prefix_hash"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("tx_prefix_hash not found in ring_data"))?;

        hex::decode(tx_prefix_hash).context("Failed to decode tx_prefix_hash")
    }

    /// Build FROST signing package from escrow state
    fn build_signing_package(
        &self,
        escrow: &Escrow,
        our_commitments: &SigningCommitments,
        message: &[u8],
    ) -> Result<SigningPackage> {
        // Get other signer's commitments
        // In FROST 2-of-3, we need exactly 2 signers including ourselves

        // Arbiter is identifier 3 in our scheme
        let arbiter_id =
            Identifier::try_from(3u16).context("Failed to create arbiter identifier")?;

        // Determine other signer and their identifier
        let (other_id, other_commitments_hex) = if escrow.vendor_signature.is_some() {
            // Vendor signed first (identifier 2)
            let vendor_id =
                Identifier::try_from(2u16).context("Failed to create vendor identifier")?;
            let commitments = escrow
                .vendor_nonce_commitment
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Vendor nonce commitment not found"))?;
            (vendor_id, commitments.clone())
        } else if escrow.buyer_signature.is_some() {
            // Buyer signed first (identifier 1)
            let buyer_id =
                Identifier::try_from(1u16).context("Failed to create buyer identifier")?;
            let commitments = escrow
                .buyer_nonce_commitment
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Buyer nonce commitment not found"))?;
            (buyer_id, commitments.clone())
        } else {
            return Err(anyhow::anyhow!("No other signer's commitments found"));
        };

        // Deserialize other signer's commitments
        let other_commitments_bytes = hex::decode(&other_commitments_hex)
            .context("Failed to decode other signer's commitments")?;
        let other_commitments: SigningCommitments = postcard::from_bytes(&other_commitments_bytes)
            .context("Failed to deserialize other signer's commitments")?;

        // Build commitments map
        let mut commitments_map = std::collections::BTreeMap::new();
        commitments_map.insert(arbiter_id, our_commitments.clone());
        commitments_map.insert(other_id, other_commitments);

        // Create signing package
        let signing_package = SigningPackage::new(commitments_map, message);

        Ok(signing_package)
    }

    /// Extract arbiter's raw FROST signing share from the vault as hex
    ///
    /// Used for dispute resolution, where the signing path uses the CLI binary
    /// (full_offline_broadcast_dispute) instead of interactive FROST signing.
    /// Returns the signing share as a 64-char hex string (32 bytes scalar).
    pub async fn extract_arbiter_share_hex(&self, escrow_id: &str) -> Result<String> {
        let key_package_hex = self
            .key_vault
            .retrieve_key_package(escrow_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Arbiter key_package not found in vault for escrow {}",
                    escrow_id
                )
            })?;

        let key_package_bytes =
            hex::decode(&key_package_hex).context("Failed to decode key_package hex")?;
        let key_package: KeyPackage = postcard::from_bytes(&key_package_bytes)
            .context("Failed to deserialize key_package")?;

        // Extract the raw signing share (curve25519-dalek Scalar, 32 bytes LE)
        let share_bytes = key_package.signing_share().serialize();
        Ok(hex::encode(share_bytes))
    }

    /// Store the partial signature in the escrow record
    async fn store_partial_signature(&self, escrow_id: &str, partial_sig: &str) -> Result<()> {
        let db_pool = self.db_pool.clone();
        let escrow_id = escrow_id.to_string();
        let partial_sig = partial_sig.to_string();
        let now = chrono::Utc::now().naive_utc();

        tokio::task::spawn_blocking(move || {
            let mut conn = db_pool.get().context("Failed to get DB connection")?;

            diesel::update(escrows::table.filter(escrows::id.eq(&escrow_id)))
                .set((
                    escrows::arbiter_frost_partial_sig.eq(Some(&partial_sig)),
                    escrows::arbiter_auto_signed.eq(true),
                    escrows::arbiter_auto_signed_at.eq(Some(now)),
                    escrows::updated_at.eq(diesel::dsl::now),
                ))
                .execute(&mut conn)
                .context("Failed to store arbiter partial signature")?;

            info!(
                escrow_id = %escrow_id,
                "Arbiter partial signature stored in database"
            );

            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Task join error")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require mocked Redis and DB
    // These are placeholder tests for logic validation

    #[test]
    fn test_identifier_creation() {
        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        let id3 = Identifier::try_from(3u16).unwrap();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }
}
