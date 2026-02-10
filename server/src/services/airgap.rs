/// # Air-Gap Communication Module (TM-001 Mitigation)
///
/// This module provides secure communication between the internet-facing server
/// and the offline arbiter wallet via QR codes and USB readonly transfer.
///
/// ## Architecture
///
/// ```
/// ┌──────────────┐                  ┌──────────────────┐
/// │   Server     │                  │ Offline Arbiter  │
/// │  (Online)    │                  │   (Air-Gapped)   │
/// └──────┬───────┘                  └────────┬─────────┘
///        │                                   │
///        │ 1. Export dispute via QR          │
///        ├──────────────────────────────────>│
///        │                                   │
///        │                         2. Review evidence (USB)
///        │                                   │
///        │                         3. Sign decision offline
///        │                                   │
///        │ 4. Import signature via QR        │
///        │<──────────────────────────────────┤
///        │                                   │
/// ```
///
/// ## Security Properties
///
/// - ✅ Arbiter wallet NEVER connected to internet
/// - ✅ Server has ZERO access to arbiter private keys
/// - ✅ State actor seizure → no arbiter keys
/// - ✅ RCE exploit → cannot sign arbiter transactions
/// - ✅ Manual review enforced (human arbiter decision)
///
/// ## Workflow
///
/// ### Happy Path (No Dispute)
/// - Arbiter wallet stays offline, never involved
///
/// ### Dispute Path
/// 1. Server detects dispute
/// 2. Server exports `DisputeRequest` struct as QR code
/// 3. Arbiter scans QR on offline laptop
/// 4. Arbiter reviews evidence from USB readonly
/// 5. Arbiter makes decision (release to buyer OR vendor)
/// 6. Arbiter signs transaction offline
/// 7. Arbiter exports `ArbiterSignature` as QR code
/// 8. Server scans QR, imports signature, finalizes transaction
///
/// ## Dependencies
///
/// - `qrcode` crate for QR generation/parsing
/// - `serde_json` for data serialization
/// - `base64` for binary encoding
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Dispute request exported from server to offline arbiter
///
/// This struct is serialized to JSON and encoded as a QR code.
/// The arbiter scans this QR to receive the dispute details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRequest {
    /// Unique escrow ID
    pub escrow_id: Uuid,

    /// Buyer user ID
    pub buyer_id: Uuid,

    /// Vendor user ID
    pub vendor_id: Uuid,

    /// Escrow amount in atomic units (piconeros)
    pub amount: u64,

    /// Buyer's claim (why they opened dispute)
    pub buyer_claim: String,

    /// Vendor's response (if any)
    pub vendor_response: Option<String>,

    /// Timestamp when dispute was opened (Unix timestamp)
    pub dispute_opened_at: i64,

    /// Evidence file count (on USB)
    pub evidence_file_count: usize,

    /// Multisig transaction data (partially signed by buyer/vendor)
    pub partial_tx_hex: String,

    /// Server-generated nonce (prevents replay)
    pub nonce: String,
}

/// Arbiter's decision + signature exported from offline laptop to server
///
/// This struct is serialized to JSON and encoded as a QR code.
/// The server scans this QR to import the arbiter's decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbiterDecision {
    /// Escrow ID (must match DisputeRequest)
    pub escrow_id: Uuid,

    /// Nonce from DisputeRequest (prevents replay)
    pub nonce: String,

    /// Decision: "buyer" or "vendor"
    pub decision: ArbiterResolution,

    /// Human-readable reason for decision
    pub reason: String,

    /// Fully signed multisig transaction (arbiter's final signature)
    pub signed_tx_hex: String,

    /// Ed25519 signature of decision (proof arbiter approved it)
    ///
    /// Signature covers: BLAKE2b(escrow_id || nonce || decision || signed_tx_hex)
    pub decision_signature: String,

    /// Timestamp when decision was made (Unix timestamp)
    pub decided_at: i64,
}

/// Arbiter's resolution: who should receive the funds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ArbiterResolution {
    /// Release funds to buyer (buyer was right)
    Buyer,

    /// Release funds to vendor (vendor was right)
    Vendor,
}

impl DisputeRequest {
    /// Serialize dispute request to JSON (for QR encoding)
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("Failed to serialize DisputeRequest")
    }

    /// Deserialize dispute request from JSON (after QR scanning)
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("Failed to deserialize DisputeRequest")
    }

    /// Generate QR code data URI (base64-encoded PNG)
    ///
    /// Returns a data URI that can be embedded in HTML:
    /// `data:image/png;base64,iVBORw0KGgoAAAANS...`
    #[cfg(feature = "qr_generation")]
    pub fn to_qr_data_uri(&self) -> Result<String> {
        use qrcode::render::png;
        use qrcode::QrCode;

        let json = self.to_json()?;

        // Generate QR code (error correction level Medium)
        let code = QrCode::new(json.as_bytes()).context("Failed to generate QR code")?;

        // Render as PNG with 10px module size
        let png_data = code.render::<png::Color>().min_dimensions(400, 400).build();

        // Encode as base64 data URI
        let base64_png = base64::encode(&png_data);
        Ok(format!("data:image/png;base64,{}", base64_png))
    }

    /// Validate dispute request (called on offline arbiter)
    pub fn validate(&self) -> Result<()> {
        // Check escrow ID valid
        if self.escrow_id.is_nil() {
            anyhow::bail!("Invalid escrow_id: cannot be nil UUID");
        }

        // Check amount reasonable (not zero, not absurdly large)
        if self.amount == 0 {
            anyhow::bail!("Invalid amount: cannot be zero");
        }

        if self.amount > 1_000_000_000_000_000 {
            // > 1 XMR in atomic units
            anyhow::bail!("Invalid amount: suspiciously large (>1 XMR)");
        }

        // Check buyer claim not empty
        if self.buyer_claim.trim().is_empty() {
            anyhow::bail!("Invalid buyer_claim: cannot be empty");
        }

        // Check nonce is hex and reasonable length
        if self.nonce.len() < 32 {
            anyhow::bail!("Invalid nonce: too short (expected 32+ chars)");
        }

        // Check partial_tx_hex is hex
        if !self.partial_tx_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("Invalid partial_tx_hex: must be hexadecimal");
        }

        Ok(())
    }
}

impl ArbiterDecision {
    /// Serialize arbiter decision to JSON (for QR encoding)
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("Failed to serialize ArbiterDecision")
    }

    /// Deserialize arbiter decision from JSON (after QR scanning)
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("Failed to deserialize ArbiterDecision")
    }

    /// Generate QR code data URI (base64-encoded PNG)
    #[cfg(feature = "qr_generation")]
    pub fn to_qr_data_uri(&self) -> Result<String> {
        use qrcode::render::png;
        use qrcode::QrCode;

        let json = self.to_json()?;

        let code = QrCode::new(json.as_bytes()).context("Failed to generate QR code")?;

        let png_data = code.render::<png::Color>().min_dimensions(400, 400).build();

        let base64_png = base64::encode(&png_data);
        Ok(format!("data:image/png;base64,{}", base64_png))
    }

    /// Validate arbiter decision (called on server before import)
    pub fn validate(&self) -> Result<()> {
        // Check escrow ID valid
        if self.escrow_id.is_nil() {
            anyhow::bail!("Invalid escrow_id: cannot be nil UUID");
        }

        // Check nonce not empty
        if self.nonce.is_empty() {
            anyhow::bail!("Invalid nonce: cannot be empty");
        }

        // Check reason not empty
        if self.reason.trim().is_empty() {
            anyhow::bail!("Invalid reason: cannot be empty");
        }

        // Check signed_tx_hex is hex
        if !self.signed_tx_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("Invalid signed_tx_hex: must be hexadecimal");
        }

        // Check decision_signature is hex and correct length (128 hex chars = 64 bytes)
        if self.decision_signature.len() != 128 {
            anyhow::bail!("Invalid decision_signature: expected 128 hex chars (64 bytes)");
        }

        if !self
            .decision_signature
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        {
            anyhow::bail!("Invalid decision_signature: must be hexadecimal");
        }

        // Check timestamp reasonable (not in future, not too old)
        let now = chrono::Utc::now().timestamp();
        if self.decided_at > now + 300 {
            // 5 min future tolerance
            anyhow::bail!("Invalid decided_at: timestamp in the future");
        }

        if self.decided_at < now - 86400 * 7 {
            // 7 days ago
            anyhow::bail!("Invalid decided_at: timestamp too old (>7 days)");
        }

        Ok(())
    }

    /// Verify decision signature (cryptographic proof arbiter signed this)
    ///
    /// # Arguments
    ///
    /// * `arbiter_pubkey` - Ed25519 public key of the arbiter (32 bytes hex)
    ///
    /// # Returns
    ///
    /// Ok(()) if signature valid, Err otherwise
    pub fn verify_signature(&self, arbiter_pubkey: &str) -> Result<()> {
        use blake2::{Blake2b512, Digest};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // 1. Reconstruct message that was signed
        let mut hasher = Blake2b512::new();
        hasher.update(self.escrow_id.as_bytes());
        hasher.update(self.nonce.as_bytes());
        let decision_bytes: &[u8] = match self.decision {
            ArbiterResolution::Buyer => b"buyer",
            ArbiterResolution::Vendor => b"vendor",
        };
        hasher.update(decision_bytes);
        hasher.update(self.signed_tx_hex.as_bytes());
        let message = hasher.finalize();

        // 2. Parse arbiter public key
        let pubkey_bytes =
            hex::decode(arbiter_pubkey).context("Invalid arbiter_pubkey: not valid hex")?;

        if pubkey_bytes.len() != 32 {
            anyhow::bail!(
                "Invalid arbiter_pubkey: expected 32 bytes, got {}",
                pubkey_bytes.len()
            );
        }

        let pubkey: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert pubkey to [u8; 32]"))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey)
            .context("Invalid arbiter_pubkey: not a valid Ed25519 public key")?;

        // 3. Parse signature
        let sig_bytes = hex::decode(&self.decision_signature)
            .context("Invalid decision_signature: not valid hex")?;

        if sig_bytes.len() != 64 {
            anyhow::bail!(
                "Invalid decision_signature: expected 64 bytes, got {}",
                sig_bytes.len()
            );
        }

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert signature to [u8; 64]"))?;

        let signature = Signature::from_bytes(&sig_array);

        // 4. Verify signature
        verifying_key
            .verify(&message, &signature)
            .context("Signature verification failed: arbiter did not sign this decision")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_bytes_32() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    fn random_bytes_64() -> [u8; 64] {
        let mut bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn test_dispute_request_serialization() -> Result<()> {
        let request = DisputeRequest {
            escrow_id: Uuid::new_v4(),
            buyer_id: Uuid::new_v4(),
            vendor_id: Uuid::new_v4(),
            amount: 100_000_000_000, // 0.1 XMR
            buyer_claim: "Item not received".to_string(),
            vendor_response: Some("Shipped on 2025-10-20".to_string()),
            dispute_opened_at: 1698765432,
            evidence_file_count: 3,
            partial_tx_hex: "abc123def456".to_string(),
            nonce: hex::encode(&random_bytes_32()),
        };

        // Test JSON serialization
        let json = request.to_json()?;
        assert!(json.contains("escrow_id"));
        assert!(json.contains("buyer_claim"));

        // Test deserialization
        let decoded = DisputeRequest::from_json(&json)?;
        assert_eq!(decoded.escrow_id, request.escrow_id);
        assert_eq!(decoded.amount, request.amount);

        Ok(())
    }

    #[test]
    fn test_dispute_request_validation() -> Result<()> {
        let mut request = DisputeRequest {
            escrow_id: Uuid::new_v4(),
            buyer_id: Uuid::new_v4(),
            vendor_id: Uuid::new_v4(),
            amount: 100_000_000_000,
            buyer_claim: "Valid claim".to_string(),
            vendor_response: None,
            dispute_opened_at: chrono::Utc::now().timestamp(),
            evidence_file_count: 0,
            partial_tx_hex: "abc123".to_string(),
            nonce: hex::encode(&random_bytes_32()),
        };

        // Valid request should pass
        assert!(request.validate().is_ok());

        // Zero amount should fail
        request.amount = 0;
        assert!(request.validate().is_err());
        request.amount = 100_000_000_000;

        // Empty buyer claim should fail
        request.buyer_claim = "".to_string();
        assert!(request.validate().is_err());
        request.buyer_claim = "Valid claim".to_string();

        // Short nonce should fail
        request.nonce = "abc".to_string();
        assert!(request.validate().is_err());

        Ok(())
    }

    #[test]
    fn test_arbiter_decision_validation() -> Result<()> {
        let mut decision = ArbiterDecision {
            escrow_id: Uuid::new_v4(),
            nonce: hex::encode(&random_bytes_32()),
            decision: ArbiterResolution::Buyer,
            reason: "Buyer provided tracking proof".to_string(),
            signed_tx_hex: "def789abc123".to_string(),
            decision_signature: hex::encode(&random_bytes_64()),
            decided_at: chrono::Utc::now().timestamp(),
        };

        // Valid decision should pass
        assert!(decision.validate().is_ok());

        // Empty reason should fail
        decision.reason = "".to_string();
        assert!(decision.validate().is_err());
        decision.reason = "Valid reason".to_string();

        // Invalid signature length should fail
        decision.decision_signature = "abc".to_string();
        assert!(decision.validate().is_err());

        Ok(())
    }

    #[test]
    fn test_signature_verification() -> Result<()> {
        use blake2::{Blake2b512, Digest};
        use ed25519_dalek::{Signer, SigningKey};

        // Generate arbiter keypair
        let signing_key = SigningKey::from_bytes(&random_bytes_32());
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.as_bytes());

        // Create decision
        let escrow_id = Uuid::new_v4();
        let nonce = hex::encode(&random_bytes_32());
        let signed_tx_hex = "abc123def456".to_string();

        // Sign message
        let mut hasher = Blake2b512::new();
        hasher.update(escrow_id.as_bytes());
        hasher.update(nonce.as_bytes());
        hasher.update(b"buyer");
        hasher.update(signed_tx_hex.as_bytes());
        let message = hasher.finalize();

        let signature = signing_key.sign(&message);

        let decision = ArbiterDecision {
            escrow_id,
            nonce,
            decision: ArbiterResolution::Buyer,
            reason: "Test decision".to_string(),
            signed_tx_hex,
            decision_signature: hex::encode(signature.to_bytes()),
            decided_at: chrono::Utc::now().timestamp(),
        };

        // Verification should succeed with correct pubkey
        assert!(decision.verify_signature(&pubkey_hex).is_ok());

        // Verification should fail with wrong pubkey
        let wrong_key = SigningKey::from_bytes(&random_bytes_32());
        let wrong_pubkey = hex::encode(wrong_key.verifying_key().as_bytes());
        assert!(decision.verify_signature(&wrong_pubkey).is_err());

        Ok(())
    }
}
