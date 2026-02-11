//! Monero Transaction Builder
//!
//! This module constructs valid Monero transactions from CLSAG signatures
//! collected during the escrow release process.
//!
//! ## Transaction Structure (RingCT v6 - Bulletproofs+)
//!
//! ```text
//! Transaction {
//!     prefix: TransactionPrefix {
//!         version: 2,
//!         unlock_time: 0,
//!         vin: Vec<TxIn>,       // Inputs with key images
//!         vout: Vec<TxOut>,     // Outputs with stealth addresses
//!         extra: Vec<u8>,       // TX public key
//!     },
//!     rct_signatures: RctSig {
//!         type: RCTTypeBulletproofPlus (6),  // UPDATED from 5
//!         txnFee: u64,
//!         ecdhInfo: Vec<EcdhInfo>,     // Encrypted amounts (8 bytes each)
//!         outPk: Vec<Key>,             // Output commitments
//!         p: RctSigPrunable {
//!             nbp: 1,                  // Number of bulletproofs
//!             bp_plus: Bulletproof+,   // Range proof
//!             CLSAGs: Vec<Clsag>,      // CLSAG signatures (BEFORE pseudoOuts!)
//!             pseudoOuts: Vec<Key>,    // Pseudo output commitments (LAST!)
//!         }
//!     }
//! }
//! ```

use anyhow::{Context, Result};
use monero_bulletproofs_mirror::Bulletproof;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tracing::{info, warn, error, debug};

use crate::services::bulletproofs_builder::generate_bulletproof_plus;

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum TransactionBuildError {
    #[error("Invalid hex encoding: {0}")]
    InvalidHex(String),
    #[error("Invalid point: {0}")]
    InvalidPoint(String),
    #[error("Invalid scalar: {0}")]
    InvalidScalar(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid ring size: expected {expected}, got {actual}")]
    InvalidRingSize { expected: usize, actual: usize },
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Address parse error: {0}")]
    AddressError(String),
    #[error("TX validation failed: {0}")]
    ValidationError(String),
    #[error("FCMP++ error: {0}")]
    FcmpError(String),
}

// ============================================================================
// FCMP++ TYPES — Post-hard-fork transaction proof structures
// ============================================================================

/// FCMP++ proof data for a single input.
///
/// Contains the re-randomized tuple `(O~, I~, R)` and the SA+L proof
/// (6 group elements + 6 scalars = 384 bytes), matching the wire format
/// from `FcmpPlusPlus::write()` in the vendor crate.
pub struct FcmpInputProof {
    /// Re-randomized output key O~ (32 bytes).
    pub o_tilde: [u8; 32],
    /// Re-randomized key-image hash I~ (32 bytes).
    pub i_tilde: [u8; 32],
    /// Blinding opening R (32 bytes).
    pub r: [u8; 32],
    /// SA+L proof points: P, A, B, R_O, R_P, R_L (6 × 32 bytes).
    pub sal_points: [[u8; 32]; 6],
    /// SA+L proof scalars: s_alpha, s_beta, s_delta, s_y, s_z, s_r_p (6 × 32 bytes).
    pub sal_scalars: [[u8; 32]; 6],
}

/// FCMP membership proof — Generalized Bulletproof circuit proof + root PoK.
///
/// The `proof_bytes` field is the output of `Fcmp::write()` (variable length),
/// while `root_blind_pok` is the fixed 64-byte proof-of-knowledge of the root blind.
///
/// **Wire format**: `proof_bytes || root_blind_pok` — NO length prefix.
/// `Fcmp::read(inputs, layers)` computes the exact split via `proof_size(inputs, layers) - 64`.
/// The format is NOT self-delimiting: the deserializer MUST know `inputs` and `layers`
/// (from TX prefix and consensus params respectively) to locate the boundary.
///
/// Validation: `proof_bytes.len()` must equal `32 * N` for some integer N (all proof
/// elements are 32-byte group elements/scalars). The full size including PoK must equal
/// `Fcmp::proof_size(inputs, layers)`, but we cannot compute that server-side without
/// the curve type parameters. The `expected_proof_len` field carries the client-computed
/// expected length for validation.
pub struct FcmpMembershipProofData {
    /// Serialized Fcmp proof bytes (variable length — depends on input count and tree depth).
    pub proof_bytes: Vec<u8>,
    /// Proof-of-knowledge of the root blind (64 bytes, fixed).
    pub root_blind_pok: [u8; 64],
    /// Client-computed expected proof length from `Fcmp::proof_size(inputs, layers) - 64`.
    /// Used to validate that `proof_bytes.len()` matches before serialization.
    /// If the client lies about this, the proof will fail verification on the network.
    pub expected_proof_len: usize,
}

/// Complete FCMP++ prunable data for a transaction.
///
/// This replaces `Vec<ClsagBinary>` in the prunable section for v3 transactions.
/// Serialization order (from `FcmpPlusPlus::write()`):
///
/// ```text
/// For each input:  O~ | I~ | R (96B) + SA+L (384B)
/// Then:            Fcmp proof (variable) + root_blind_pok (64B)
/// Then:            Pseudo-outs C~ (32B each, separate field)
/// ```
pub struct FcmpPrunableData {
    /// Per-input proofs (SA+L + re-randomized tuple).
    pub input_proofs: Vec<FcmpInputProof>,
    /// Membership proof covering all inputs.
    pub membership: FcmpMembershipProofData,
}

// ============================================================================
// BUILD RESULT (with correct TX hash)
// ============================================================================

/// Result of building a transaction, includes the correct TX hash
///
/// Monero TX hash for RCT is: H(prefix_hash || base_hash || prunable_hash)
/// NOT just H(entire_blob)
#[derive(Debug, Clone)]
pub struct BuildResult {
    /// Full transaction hex (for broadcast)
    pub tx_hex: String,
    /// Transaction hash (txid) computed correctly per Monero spec
    /// txid = Keccak256(prefix_hash || base_hash || prunable_hash)
    pub tx_hash: [u8; 32],
    /// Prefix hash component
    pub prefix_hash: [u8; 32],
    /// RCT base hash component
    pub base_hash: [u8; 32],
    /// RCT prunable hash component
    pub prunable_hash: [u8; 32],
}

// ============================================================================
// TX STRUCTURE VALIDATION (Pre-broadcast sanity check)
// ============================================================================

/// Validation result for serialized transaction
#[derive(Debug)]
pub struct TxValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub parsed: TxParsedFields,
}

/// Parsed transaction fields for validation
#[derive(Debug, Default)]
pub struct TxParsedFields {
    pub version: u64,
    pub unlock_time: u64,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub output_types: Vec<u8>,
    pub extra_length: usize,
    pub rct_type: u8,
}

// ============================================================================
// CLSAG SIGNATURE STRUCTURE (Matches WASM output)
// ============================================================================

/// CLSAG signature structure from WASM signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClsagSignatureJson {
    /// D point (hex, 32 bytes compressed)
    #[serde(rename = "D")]
    pub d: String,
    /// s values (hex array, ring_size elements)
    pub s: Vec<String>,
    /// c1 scalar (hex, 32 bytes)
    pub c1: String,
}

/// Complete signature data from client
/// Accepts both camelCase (from WASM) and snake_case (from DB storage)
///
/// **IMPORTANT FOR MULTISIG:**
/// - `key_image` is DEPRECATED for multisig - each signer computed different key images
/// - `partial_key_image` is the CORRECT field - signers compute `pKI = x * Hp(P_multisig)`
/// - Server aggregates partial key images: `KI = pKI_buyer + pKI_vendor`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSignature {
    pub signature: ClsagSignatureJson,
    /// DEPRECATED for multisig: Individual key image (different per signer)
    /// Use partial_key_image instead for multisig scenarios
    #[serde(alias = "keyImage", alias = "key_image")]
    pub key_image: String,
    /// Partial key image for multisig: pKI = x * Hp(P_multisig)
    /// Server aggregates these: KI = pKI_1 + pKI_2
    #[serde(default)]
    #[serde(alias = "partialKeyImage", alias = "partial_key_image")]
    pub partial_key_image: Option<String>,
    #[serde(alias = "pseudoOut", alias = "pseudo_out")]
    pub pseudo_out: String,
}

/// Aggregate two partial key images into a combined key image
///
/// For 2-of-3 multisig, each signer computes: `pKI = x * Hp(P_multisig)`
/// The aggregated key image is: `KI = pKI_1 + pKI_2` (Edwards point addition)
///
/// This ensures both signers produce the SAME final key image for the same input,
/// which is required for valid Monero ring signatures.
pub fn aggregate_partial_key_images(
    partial_ki_1_hex: &str,
    partial_ki_2_hex: &str,
) -> Result<String, TransactionBuildError> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    info!(
        "[TX-BUILD][PKI-AGG] Aggregating partial key images"
    );
    debug!(
        "[TX-BUILD][PKI-AGG] pKI_1: {}...",
        &partial_ki_1_hex[..16.min(partial_ki_1_hex.len())]
    );
    debug!(
        "[TX-BUILD][PKI-AGG] pKI_2: {}...",
        &partial_ki_2_hex[..16.min(partial_ki_2_hex.len())]
    );

    // Decode first partial key image
    let pki1_bytes = hex::decode(partial_ki_1_hex)
        .map_err(|e| TransactionBuildError::InvalidHex(format!("partial_ki_1: {}", e)))?;
    if pki1_bytes.len() != 32 {
        error!(
            "[TX-BUILD][PKI-AGG] pKI_1 invalid length: {} bytes (expected 32)",
            pki1_bytes.len()
        );
        return Err(TransactionBuildError::InvalidPoint(
            format!("partial_ki_1 must be 32 bytes, got {}", pki1_bytes.len())
        ));
    }
    let mut pki1_arr = [0u8; 32];
    pki1_arr.copy_from_slice(&pki1_bytes);

    // Decode second partial key image
    let pki2_bytes = hex::decode(partial_ki_2_hex)
        .map_err(|e| TransactionBuildError::InvalidHex(format!("partial_ki_2: {}", e)))?;
    if pki2_bytes.len() != 32 {
        error!(
            "[TX-BUILD][PKI-AGG] pKI_2 invalid length: {} bytes (expected 32)",
            pki2_bytes.len()
        );
        return Err(TransactionBuildError::InvalidPoint(
            format!("partial_ki_2 must be 32 bytes, got {}", pki2_bytes.len())
        ));
    }
    let mut pki2_arr = [0u8; 32];
    pki2_arr.copy_from_slice(&pki2_bytes);

    // Decompress both partial key images as Edwards points
    let pki1_point = CompressedEdwardsY(pki1_arr)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][PKI-AGG] pKI_1 decompression failed - not a valid curve point");
            TransactionBuildError::InvalidPoint("partial_ki_1 is not a valid point".into())
        })?;

    let pki2_point = CompressedEdwardsY(pki2_arr)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][PKI-AGG] pKI_2 decompression failed - not a valid curve point");
            TransactionBuildError::InvalidPoint("partial_ki_2 is not a valid point".into())
        })?;

    // Aggregate: KI = pKI_1 + pKI_2 (Edwards point addition)
    let combined = pki1_point + pki2_point;
    let result = hex::encode(combined.compress().to_bytes());

    info!(
        "[TX-BUILD][PKI-AGG] SUCCESS: Aggregated KI = {}...",
        &result[..16.min(result.len())]
    );

    Ok(result)
}

// ============================================================================
// TRANSACTION INPUT STRUCTURE
// ============================================================================

/// Ring member data (from get_outs RPC)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingMember {
    /// Global output index
    pub global_index: u64,
    /// Public key (hex, 32 bytes)
    pub public_key: String,
    /// Commitment (hex, 32 bytes)
    pub commitment: String,
}

/// Transaction input with ring data
#[derive(Debug, Clone)]
pub struct TransactionInput {
    /// Key image (32 bytes)
    pub key_image: [u8; 32],
    /// Ring member offsets (relative indices for serialization)
    pub key_offsets: Vec<u64>,
    /// Ring size (typically 16)
    pub ring_size: usize,
}

// ============================================================================
// TRANSACTION OUTPUT STRUCTURE
// ============================================================================

/// Transaction output with stealth address
#[derive(Debug, Clone)]
pub struct TransactionOutput {
    /// Amount (0 for RingCT)
    pub amount: u64,
    /// One-time stealth address (32 bytes)
    pub target_key: [u8; 32],
    /// View tag (1 byte) - required since Monero HF16 for txout_to_tagged_key (type 0x02)
    pub view_tag: u8,
}

// ============================================================================
// ECDH INFO (Encrypted amount)
// ============================================================================

/// Encrypted amount info for output
#[derive(Debug, Clone)]
pub struct EcdhInfo {
    /// Encrypted amount (8 bytes)
    pub amount: [u8; 8],
}

// ============================================================================
// CLSAG SIGNATURE (Binary format)
// ============================================================================

/// CLSAG signature for serialization
#[derive(Debug, Clone)]
pub struct ClsagBinary {
    /// s values (ring_size * 32 bytes)
    pub s: Vec<[u8; 32]>,
    /// c1 scalar (32 bytes)
    pub c1: [u8; 32],
    /// D point (32 bytes)
    pub d: [u8; 32],
}

// ============================================================================
// TRANSACTION BUILDER
// ============================================================================

/// Monero transaction builder
pub struct MoneroTransactionBuilder {
    /// Transaction version (2 for RingCT)
    version: u8,
    /// Unlock time (0 = immediate)
    unlock_time: u64,
    /// Transaction inputs
    inputs: Vec<TransactionInput>,
    /// Transaction outputs
    outputs: Vec<TransactionOutput>,
    /// Extra field (TX pubkey + optional payment ID)
    extra: Vec<u8>,
    /// CLSAG signatures
    clsag_signatures: Vec<ClsagBinary>,
    /// Pseudo outputs
    pseudo_outputs: Vec<[u8; 32]>,
    /// Output commitments
    output_commitments: Vec<[u8; 32]>,
    /// ECDH info (encrypted amounts)
    ecdh_info: Vec<EcdhInfo>,
    /// Transaction fee (atomic units)
    fee: u64,
    /// Bulletproof+ range proof (for RCT v6)
    bulletproof_plus: Option<Bulletproof>,
    /// Output masks for Bulletproof+ generation (blinding factors)
    output_masks: Vec<[u8; 32]>,
    /// Output amounts for Bulletproof+ generation (plaintext amounts)
    output_amounts: Vec<u64>,
    /// FCMP++ prunable data — replaces CLSAG signatures for v3 transactions.
    /// When `Some`, the builder serializes FCMP++ proofs instead of CLSAGs.
    fcmp_data: Option<FcmpPrunableData>,
}

impl MoneroTransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            version: 2,
            unlock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            extra: Vec::new(),
            clsag_signatures: Vec::new(),
            pseudo_outputs: Vec::new(),
            output_commitments: Vec::new(),
            ecdh_info: Vec::new(),
            fee: 0,
            bulletproof_plus: None,
            output_masks: Vec::new(),
            output_amounts: Vec::new(),
            fcmp_data: None,
        }
    }

    /// Set transaction fee
    pub fn set_fee(&mut self, fee: u64) -> &mut Self {
        self.fee = fee;
        self
    }

    /// Add an input to the transaction
    pub fn add_input(
        &mut self,
        key_image: [u8; 32],
        ring_member_indices: &[u64],
    ) -> Result<&mut Self, TransactionBuildError> {
        // Convert absolute indices to relative offsets
        let key_offsets = self.indices_to_offsets(ring_member_indices);

        self.inputs.push(TransactionInput {
            key_image,
            key_offsets,
            ring_size: ring_member_indices.len(),
        });

        Ok(self)
    }

    /// Add an output to the transaction
    ///
    /// # Arguments
    /// * `target_key` - One-time stealth address (32 bytes)
    /// * `commitment` - Pedersen commitment C = mask*G + amount*H (32 bytes)
    /// * `encrypted_amount` - ECDH encrypted amount (8 bytes)
    /// * `mask` - Commitment blinding factor for BP+ generation (32 bytes)
    /// * `plaintext_amount` - Plaintext amount for BP+ generation (atomic units)
    /// * `view_tag` - View tag (1 byte) for txout_to_tagged_key (HF16+)
    pub fn add_output(
        &mut self,
        target_key: [u8; 32],
        commitment: [u8; 32],
        encrypted_amount: [u8; 8],
        mask: [u8; 32],
        plaintext_amount: u64,
        view_tag: u8,
    ) -> &mut Self {
        self.outputs.push(TransactionOutput {
            amount: 0, // Always 0 for RingCT
            target_key,
            view_tag,
        });

        self.output_commitments.push(commitment);
        self.ecdh_info.push(EcdhInfo { amount: encrypted_amount });

        // Store for Bulletproof+ generation
        self.output_masks.push(mask);
        self.output_amounts.push(plaintext_amount);

        self
    }

    /// Add a dummy output with 0 XMR using a PRE-COMPUTED mask for commitment balance
    ///
    /// v0.35.0 FIX: When mask_delta=0 (pseudo_out = input_commitment), we need:
    ///   dummy_mask = commitment_mask - out0_mask
    /// This ensures: pseudo_out = out0 + dummy + fee*H balances correctly.
    ///
    /// # Arguments
    /// * `tx_secret_key` - The ephemeral transaction secret key (r)
    /// * `recipient_spend_pub` - Recipient's public spend key (B)
    /// * `recipient_view_pub` - Recipient's public view key (V)
    /// * `dummy_mask` - Pre-computed mask for balance: commitment_mask - out0_mask
    ///
    /// # Returns
    /// `Result<&mut Self, TransactionBuildError>`
    pub fn add_dummy_output_with_mask(
        &mut self,
        tx_secret_key: &[u8; 32],
        recipient_spend_pub: &[u8; 32],
        recipient_view_pub: &[u8; 32],
        dummy_mask: &[u8; 32],
    ) -> Result<&mut Self, TransactionBuildError> {
        info!("[TX-BUILD][DUMMY-OUTPUT-v0.35.0] Adding dummy output with PRE-COMPUTED mask for balance");

        // Output index 1 for the dummy output (index 0 is the real output)
        let output_index: u64 = 1;

        // Generate stealth address for dummy output
        let (stealth_address, view_tag) = generate_stealth_address_with_view_tag(
            tx_secret_key,
            recipient_spend_pub,
            recipient_view_pub,
            output_index,
        )?;
        info!(
            "[TX-BUILD][DUMMY-OUTPUT-v0.35.0] stealth_address: {}",
            hex::encode(&stealth_address)
        );
        info!("[TX-BUILD][DUMMY-OUTPUT-v0.35.0] view_tag: 0x{:02x}", view_tag);
        info!(
            "[TX-BUILD][DUMMY-OUTPUT-v0.35.0] dummy_mask (pre-computed): {}",
            hex::encode(dummy_mask)
        );

        // Compute commitment = mask*G + 0*H = mask*G
        let dummy_commitment = compute_pedersen_commitment(dummy_mask, 0)?;
        info!(
            "[TX-BUILD][DUMMY-OUTPUT-v0.35.0] commitment (mask*G): {}",
            hex::encode(&dummy_commitment)
        );

        // Encrypt amount 0
        let encrypted_amount = encrypt_amount_ecdh(
            tx_secret_key,
            recipient_view_pub,
            output_index,
            0, // 0 XMR
        )?;
        info!(
            "[TX-BUILD][DUMMY-OUTPUT-v0.35.0] encrypted_amount: {}",
            hex::encode(&encrypted_amount)
        );

        // Add the dummy output
        self.outputs.push(TransactionOutput {
            amount: 0, // Always 0 for RingCT
            target_key: stealth_address,
            view_tag,
        });

        self.output_commitments.push(dummy_commitment);
        self.ecdh_info.push(EcdhInfo { amount: encrypted_amount });

        // Store for Bulletproof+ generation
        self.output_masks.push(*dummy_mask);
        self.output_amounts.push(0); // 0 XMR

        info!("[TX-BUILD][DUMMY-OUTPUT-v0.35.0] SUCCESS: dummy output added with balanced mask");

        Ok(self)
    }

    /// Add a dummy output with 0 XMR to satisfy Monero's minimum 2-output requirement (HF16+)
    ///
    /// This creates a second output at output_index=1 with 0 XMR sent to the same recipient.
    /// The recipient can detect this output but it has no value.
    ///
    /// NOTE: This derives a random mask. Use add_dummy_output_with_mask for v0.35.0 balance.
    ///
    /// # Arguments
    /// * `tx_secret_key` - The ephemeral transaction secret key (r)
    /// * `recipient_spend_pub` - Recipient's public spend key (B)
    /// * `recipient_view_pub` - Recipient's public view key (V)
    ///
    /// # Returns
    /// `Result<&mut Self, TransactionBuildError>`
    #[allow(dead_code)]
    pub fn add_dummy_output(
        &mut self,
        tx_secret_key: &[u8; 32],
        recipient_spend_pub: &[u8; 32],
        recipient_view_pub: &[u8; 32],
    ) -> Result<&mut Self, TransactionBuildError> {
        info!("[TX-BUILD][DUMMY-OUTPUT] Adding dummy output (0 XMR) at index 1");

        // Output index 1 for the dummy output (index 0 is the real output)
        let output_index: u64 = 1;

        // Generate stealth address for dummy output
        let (stealth_address, view_tag) = generate_stealth_address_with_view_tag(
            tx_secret_key,
            recipient_spend_pub,
            recipient_view_pub,
            output_index,
        )?;
        info!(
            "[TX-BUILD][DUMMY-OUTPUT] stealth_address: {}",
            hex::encode(&stealth_address)
        );
        info!("[TX-BUILD][DUMMY-OUTPUT] view_tag: 0x{:02x}", view_tag);

        // Derive commitment mask for this output
        let dummy_mask = derive_output_mask(tx_secret_key, recipient_view_pub, output_index)?;
        info!(
            "[TX-BUILD][DUMMY-OUTPUT] dummy_mask: {}",
            hex::encode(&dummy_mask)
        );

        // Compute commitment = mask*G + 0*H = mask*G
        // For 0 amount, commitment is just mask*G
        let dummy_commitment = compute_pedersen_commitment(&dummy_mask, 0)?;
        info!(
            "[TX-BUILD][DUMMY-OUTPUT] commitment (mask*G): {}",
            hex::encode(&dummy_commitment)
        );

        // Encrypt amount 0
        let encrypted_amount = encrypt_amount_ecdh(
            tx_secret_key,
            recipient_view_pub,
            output_index,
            0, // 0 XMR
        )?;
        info!(
            "[TX-BUILD][DUMMY-OUTPUT] encrypted_amount: {}",
            hex::encode(&encrypted_amount)
        );

        // Add the dummy output
        self.outputs.push(TransactionOutput {
            amount: 0, // Always 0 for RingCT
            target_key: stealth_address,
            view_tag,
        });

        self.output_commitments.push(dummy_commitment);
        self.ecdh_info.push(EcdhInfo { amount: encrypted_amount });

        // Store for Bulletproof+ generation
        self.output_masks.push(dummy_mask);
        self.output_amounts.push(0); // 0 XMR

        info!("[TX-BUILD][DUMMY-OUTPUT] SUCCESS: dummy output added at index 1");

        Ok(self)
    }

    /// Set the transaction extra field (TX public key)
    pub fn set_tx_pubkey(&mut self, tx_pubkey: &[u8; 32]) -> &mut Self {
        // Extra format: 0x01 (TX_EXTRA_TAG_PUBKEY) || pubkey (32 bytes)
        self.extra.clear();
        self.extra.push(0x01); // TX_EXTRA_TAG_PUBKEY
        self.extra.extend_from_slice(tx_pubkey);
        self
    }

    /// Attach a CLSAG signature from client
    pub fn attach_clsag(
        &mut self,
        signature_json: &ClientSignature,
    ) -> Result<&mut Self, TransactionBuildError> {
        info!(
            "[TX-BUILD][CLSAG-ATTACH] =========================================="
        );
        info!(
            "[TX-BUILD][CLSAG-ATTACH] Attaching CLSAG signature #{}",
            self.clsag_signatures.len()
        );

        // Parse D point
        info!(
            "[TX-BUILD][CLSAG-ATTACH] D point: {}...",
            &signature_json.signature.d[..16.min(signature_json.signature.d.len())]
        );
        let d_bytes = hex::decode(&signature_json.signature.d)
            .map_err(|e| {
                error!("[TX-BUILD][CLSAG-ATTACH] D point decode failed: {}", e);
                TransactionBuildError::InvalidHex(format!("D: {}", e))
            })?;
        if d_bytes.len() != 32 {
            error!(
                "[TX-BUILD][CLSAG-ATTACH] D point invalid length: {} (expected 32)",
                d_bytes.len()
            );
            return Err(TransactionBuildError::InvalidPoint("D must be 32 bytes".into()));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&d_bytes);

        // Parse c1 scalar
        info!(
            "[TX-BUILD][CLSAG-ATTACH] c1 scalar: {}...",
            &signature_json.signature.c1[..16.min(signature_json.signature.c1.len())]
        );
        let c1_bytes = hex::decode(&signature_json.signature.c1)
            .map_err(|e| {
                error!("[TX-BUILD][CLSAG-ATTACH] c1 decode failed: {}", e);
                TransactionBuildError::InvalidHex(format!("c1: {}", e))
            })?;
        if c1_bytes.len() != 32 {
            error!(
                "[TX-BUILD][CLSAG-ATTACH] c1 invalid length: {} (expected 32)",
                c1_bytes.len()
            );
            return Err(TransactionBuildError::InvalidScalar("c1 must be 32 bytes".into()));
        }
        let mut c1 = [0u8; 32];
        c1.copy_from_slice(&c1_bytes);

        // Parse s values
        info!(
            "[TX-BUILD][CLSAG-ATTACH] s-values: {} elements (ring_size)",
            signature_json.signature.s.len()
        );
        let mut s_values = Vec::new();
        for (i, s_hex) in signature_json.signature.s.iter().enumerate() {
            let s_bytes = hex::decode(s_hex)
                .map_err(|e| {
                    error!("[TX-BUILD][CLSAG-ATTACH] s[{}] decode failed: {}", i, e);
                    TransactionBuildError::InvalidHex(format!("s[{}]: {}", i, e))
                })?;
            if s_bytes.len() != 32 {
                error!(
                    "[TX-BUILD][CLSAG-ATTACH] s[{}] invalid length: {} (expected 32)",
                    i, s_bytes.len()
                );
                return Err(TransactionBuildError::InvalidScalar(
                    format!("s[{}] must be 32 bytes", i)
                ));
            }
            let mut s = [0u8; 32];
            s.copy_from_slice(&s_bytes);
            s_values.push(s);

            // Log first 3 s-values for debugging
            if i < 3 {
                debug!(
                    "[TX-BUILD][CLSAG-ATTACH] s[{}] = {}",
                    i, s_hex
                );
            }
        }

        // Parse pseudo output
        info!(
            "[TX-BUILD][CLSAG-ATTACH] pseudo_out: {}...",
            &signature_json.pseudo_out[..16.min(signature_json.pseudo_out.len())]
        );
        let pseudo_out_bytes = hex::decode(&signature_json.pseudo_out)
            .map_err(|e| {
                error!("[TX-BUILD][CLSAG-ATTACH] pseudo_out decode failed: {}", e);
                TransactionBuildError::InvalidHex(format!("pseudoOut: {}", e))
            })?;
        if pseudo_out_bytes.len() != 32 {
            error!(
                "[TX-BUILD][CLSAG-ATTACH] pseudo_out invalid length: {} (expected 32)",
                pseudo_out_bytes.len()
            );
            return Err(TransactionBuildError::InvalidPoint("pseudoOut must be 32 bytes".into()));
        }
        let mut pseudo_out = [0u8; 32];
        pseudo_out.copy_from_slice(&pseudo_out_bytes);

        // Log key image
        info!(
            "[TX-BUILD][CLSAG-ATTACH] key_image: {}...",
            &signature_json.key_image[..16.min(signature_json.key_image.len())]
        );

        self.clsag_signatures.push(ClsagBinary {
            s: s_values.clone(),
            c1,
            d,
        });
        self.pseudo_outputs.push(pseudo_out);

        info!(
            "[TX-BUILD][CLSAG-ATTACH] SUCCESS: CLSAG #{} attached (s_count={}, D={}..., c1={}...)",
            self.clsag_signatures.len() - 1,
            s_values.len(),
            hex::encode(&d[..8]),
            hex::encode(&c1[..8])
        );

        Ok(self)
    }

    // ========================================================================
    // FCMP++ methods — post-hard-fork transaction construction
    // ========================================================================

    /// Add an FCMP++ input (key image only, no ring members).
    ///
    /// FCMP++ replaces ring signatures with full-chain membership proofs,
    /// so inputs only need a key image — no decoy selection required.
    pub fn add_fcmp_input(&mut self, key_image: [u8; 32]) -> &mut Self {
        self.inputs.push(TransactionInput {
            key_image,
            key_offsets: vec![],
            ring_size: 0,
        });
        self
    }

    /// Attach FCMP++ proof data to the transaction.
    ///
    /// This replaces `attach_clsag()` for v3 transactions. The proof data
    /// contains per-input SA+L proofs and a single membership proof covering
    /// all inputs.
    ///
    /// # Validation
    /// - `input_proofs.len()` must equal `self.inputs.len()`
    /// - Membership proof must be non-empty
    pub fn attach_fcmp_proof(
        &mut self,
        data: FcmpPrunableData,
    ) -> Result<&mut Self, TransactionBuildError> {
        info!(
            "[TX-BUILD][FCMP-ATTACH] Attaching FCMP++ proof: {} inputs, membership={}B",
            data.input_proofs.len(),
            data.membership.proof_bytes.len()
        );

        if data.input_proofs.len() != self.inputs.len() {
            return Err(TransactionBuildError::FcmpError(format!(
                "FCMP++ input proof count ({}) does not match transaction input count ({})",
                data.input_proofs.len(),
                self.inputs.len()
            )));
        }

        if data.membership.proof_bytes.is_empty() {
            return Err(TransactionBuildError::FcmpError(
                "FCMP membership proof is empty".into()
            ));
        }

        // Validate proof_bytes length against client-declared expected size.
        // Fcmp::read(inputs, layers) uses proof_size(inputs, layers) - 64 to determine
        // how many bytes to read as proof vs root_blind_pok. If proof_bytes.len() doesn't
        // match, the deserializer will split at the wrong boundary → silent corruption.
        if data.membership.proof_bytes.len() != data.membership.expected_proof_len {
            return Err(TransactionBuildError::FcmpError(format!(
                "Membership proof length ({}) does not match expected length ({}). \
                 The expected length comes from Fcmp::proof_size(inputs={}, layers) - 64. \
                 A mismatch means the proof/root_blind_pok boundary will be wrong on deserialization.",
                data.membership.proof_bytes.len(),
                data.membership.expected_proof_len,
                data.input_proofs.len()
            )));
        }

        // Every proof element is a 32-byte group element or scalar.
        // proof_size() returns (32 * N) + 64, so proof_bytes must be 32-aligned.
        if data.membership.proof_bytes.len() % 32 != 0 {
            return Err(TransactionBuildError::FcmpError(format!(
                "Membership proof length ({}) is not 32-byte aligned. \
                 All FCMP proof elements are 32-byte scalars/points.",
                data.membership.proof_bytes.len()
            )));
        }

        // Validate each input proof has non-zero O~ (identity check)
        for (i, proof) in data.input_proofs.iter().enumerate() {
            if proof.o_tilde == [0u8; 32] {
                return Err(TransactionBuildError::FcmpError(format!(
                    "Input {}: O~ is zero (identity point)", i
                )));
            }
            if proof.i_tilde == [0u8; 32] {
                return Err(TransactionBuildError::FcmpError(format!(
                    "Input {}: I~ is zero (identity point)", i
                )));
            }
        }

        self.fcmp_data = Some(data);

        info!(
            "[TX-BUILD][FCMP-ATTACH] SUCCESS: FCMP++ proof attached for {} inputs",
            self.inputs.len()
        );

        Ok(self)
    }

    /// Compute the FCMP++ signable transaction hash.
    ///
    /// This is the hash that binds the SA+L proof to the transaction.
    /// From `FcmpPlusPlus::verify()`: "`signable_tx_hash` must be binding to
    /// the transaction prefix, the RingCT base, and the pseudo-outs."
    ///
    /// Formula: `H(prefix_hash || base_with_pseudoouts_hash || bp_hash)`
    pub fn compute_fcmp_signable_hash(&self) -> Result<[u8; 32], TransactionBuildError> {
        // Component 1: prefix hash
        let mut prefix_buf = Vec::new();
        self.serialize_prefix(&mut prefix_buf)?;
        let prefix_hash = Keccak256::digest(&prefix_buf);

        // Component 2: RCT base hash — includes pseudo-outs for FCMP++ binding.
        //
        // From vendor `FcmpPlusPlus::verify()` doc:
        //   "`signable_tx_hash` must be binding to the transaction prefix,
        //    the RingCT base, and the pseudo-outs."
        //
        // In CLSAG, pseudo-outs are in the prunable section (component 3).
        // For FCMP++, we bind them here in component 2 so the SA+L challenge
        // commits to the exact pseudo-out values. This prevents a verifier
        // from accepting a proof over a different commitment balance.
        let mut base_buf = Vec::new();
        self.serialize_rct_base(&mut base_buf)?;
        for pseudo_out in &self.pseudo_outputs {
            base_buf.extend_from_slice(pseudo_out);
        }
        let base_hash = Keccak256::digest(&base_buf);

        // Component 3: BP+ hash (range proof commitment)
        let mut bp_buf = Vec::new();
        if let Some(ref bp) = self.bulletproof_plus {
            self.serialize_bulletproof_plus(bp, &mut bp_buf)?;
        }
        let bp_hash = Keccak256::digest(&bp_buf);

        // Final: H(prefix_hash || base_hash || bp_hash)
        let signable: [u8; 32] = Keccak256::new()
            .chain_update(prefix_hash)
            .chain_update(base_hash)
            .chain_update(bp_hash)
            .finalize()
            .into();

        info!(
            "[TX-BUILD][FCMP-HASH] signable_tx_hash = {}",
            hex::encode(&signable)
        );

        Ok(signable)
    }

    /// Build the transaction and serialize to hex
    ///
    /// This method generates the Bulletproof+ range proof from the stored
    /// output masks and amounts, then serializes the complete transaction.
    ///
    /// Returns a BuildResult containing the TX hex and correctly computed
    /// TX hash (txid = H(prefix_hash || base_hash || prunable_hash))
    pub fn build(&mut self) -> Result<BuildResult, TransactionBuildError> {
        info!(
            "[TX-BUILD][PHASE-0] =========================================="
        );
        info!(
            "[TX-BUILD][PHASE-0] Starting transaction build"
        );
        info!(
            "[TX-BUILD][PHASE-0] Inputs: {}, Outputs: {}, CLSAGs: {}",
            self.inputs.len(),
            self.outputs.len(),
            self.clsag_signatures.len()
        );
        info!(
            "[TX-BUILD][PHASE-0] Fee: {} piconero ({:.12} XMR)",
            self.fee,
            self.fee as f64 / 1_000_000_000_000.0
        );

        // Log input details
        for (i, input) in self.inputs.iter().enumerate() {
            info!(
                "[TX-BUILD][PHASE-0][INPUT-{}] key_image={}..., ring_size={}, first_offset={}",
                i,
                hex::encode(&input.key_image[..8]),
                input.ring_size,
                input.key_offsets.first().unwrap_or(&0)
            );
        }

        // Log output details
        for (i, output) in self.outputs.iter().enumerate() {
            info!(
                "[TX-BUILD][PHASE-0][OUTPUT-{}] target_key={}..., amount_stored={}",
                i,
                hex::encode(&output.target_key[..8]),
                self.output_amounts.get(i).unwrap_or(&0)
            );
        }

        // Log extra field
        info!(
            "[TX-BUILD][PHASE-0] Extra field: {} bytes (tx_pubkey={}...)",
            self.extra.len(),
            if self.extra.len() >= 9 {
                hex::encode(&self.extra[1..9])
            } else {
                "NONE".to_string()
            }
        );

        // 0. Generate Bulletproof+ range proof if we have outputs
        if !self.output_amounts.is_empty() && self.bulletproof_plus.is_none() {
            info!("[TX-BUILD][PHASE-1] Generating Bulletproof+ range proof...");
            info!(
                "[TX-BUILD][PHASE-1] Amounts: {:?} piconero",
                self.output_amounts
            );
            for (i, mask) in self.output_masks.iter().enumerate() {
                info!(
                    "[TX-BUILD][PHASE-1] Mask[{}]: {}...{}",
                    i,
                    hex::encode(&mask[..4]),
                    hex::encode(&mask[28..32])
                );
            }
            self.generate_bulletproof()?;
            info!("[TX-BUILD][PHASE-1] SUCCESS: Bulletproof+ generated");
        }

        let mut tx_blob = Vec::new();

        // 1. Serialize transaction prefix
        info!("[TX-BUILD][PHASE-2] Serializing transaction prefix...");
        let prefix_start = tx_blob.len();
        self.serialize_prefix(&mut tx_blob)?;
        let prefix_len = tx_blob.len() - prefix_start;
        info!(
            "[TX-BUILD][PHASE-2] Prefix serialized: {} bytes",
            prefix_len
        );

        // Compute prefix hash (component 1 of 3 for txid)
        let prefix_hash: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(&tx_blob[prefix_start..]);
            hasher.finalize().into()
        };
        info!(
            "[TX-BUILD][PHASE-2] tx_prefix_hash (for CLSAG verification): {}",
            hex::encode(&prefix_hash)
        );

        // 2. Serialize RCT base (type, fee, ecdh, outPk)
        info!("[TX-BUILD][PHASE-3] Serializing RCT base...");
        let rct_base_start = tx_blob.len();
        self.serialize_rct_base(&mut tx_blob)?;
        let rct_base_len = tx_blob.len() - rct_base_start;
        info!(
            "[TX-BUILD][PHASE-3] RCT base serialized: {} bytes (type=6, fee={})",
            rct_base_len,
            self.fee
        );

        // Compute base hash (component 2 of 3 for txid)
        let base_hash: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(&tx_blob[rct_base_start..]);
            hasher.finalize().into()
        };
        info!(
            "[TX-BUILD][PHASE-3] rct_base_hash: {}",
            hex::encode(&base_hash)
        );

        // Log output commitments
        for (i, commitment) in self.output_commitments.iter().enumerate() {
            info!(
                "[TX-BUILD][PHASE-3][OutPk-{}] {}",
                i,
                hex::encode(commitment)
            );
        }

        // 3. Serialize RCT prunable (BP+, CLSAGs, pseudoOuts)
        info!("[TX-BUILD][PHASE-4] Serializing RCT prunable...");
        let rct_prunable_start = tx_blob.len();
        self.serialize_rct_prunable(&mut tx_blob)?;
        let rct_prunable_len = tx_blob.len() - rct_prunable_start;

        // Compute prunable hash (component 3 of 3 for txid)
        let prunable_hash: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(&tx_blob[rct_prunable_start..]);
            hasher.finalize().into()
        };
        info!(
            "[TX-BUILD][PHASE-4] rct_prunable_hash: {}",
            hex::encode(&prunable_hash)
        );
        info!(
            "[TX-BUILD][PHASE-4] RCT prunable serialized: {} bytes",
            rct_prunable_len
        );

        // Log CLSAG signature details
        for (i, clsag) in self.clsag_signatures.iter().enumerate() {
            info!(
                "[TX-BUILD][PHASE-4][CLSAG-{}] s_count={}, c1={}..., D={}...",
                i,
                clsag.s.len(),
                hex::encode(&clsag.c1[..8]),
                hex::encode(&clsag.d[..8])
            );
            // Log first few s-values
            for (j, s) in clsag.s.iter().take(3).enumerate() {
                debug!(
                    "[TX-BUILD][PHASE-4][CLSAG-{}][s-{}] {}",
                    i, j, hex::encode(s)
                );
            }
        }

        // Log pseudo outputs
        for (i, pseudo_out) in self.pseudo_outputs.iter().enumerate() {
            info!(
                "[TX-BUILD][PHASE-4][PseudoOut-{}] {}",
                i,
                hex::encode(pseudo_out)
            );
        }

        // Compute final TX hash: H(prefix_hash || base_hash || prunable_hash)
        // This is the CORRECT Monero txid computation for RCT transactions
        let tx_hash: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(&prefix_hash);
            hasher.update(&base_hash);
            hasher.update(&prunable_hash);
            hasher.finalize().into()
        };

        let total_len = tx_blob.len();
        info!(
            "[TX-BUILD][PHASE-5] =========================================="
        );
        info!(
            "[TX-BUILD][PHASE-5] Transaction build COMPLETE"
        );
        info!(
            "[TX-BUILD][PHASE-5] Total size: {} bytes ({} prefix + {} rct_base + {} rct_prunable)",
            total_len,
            prefix_len,
            rct_base_len,
            rct_prunable_len
        );
        info!(
            "[TX-BUILD][PHASE-5] TX hash (txid): {}",
            hex::encode(&tx_hash)
        );
        info!(
            "[TX-BUILD][PHASE-5] Components: prefix={}, base={}, prunable={}",
            hex::encode(&prefix_hash[..8]),
            hex::encode(&base_hash[..8]),
            hex::encode(&prunable_hash[..8])
        );

        // Log first and last 32 bytes of tx blob for verification
        debug!(
            "[TX-BUILD][PHASE-5] TX blob first 64 chars: {}",
            hex::encode(&tx_blob[..32.min(tx_blob.len())])
        );
        debug!(
            "[TX-BUILD][PHASE-5] TX blob last 64 chars: {}",
            hex::encode(&tx_blob[tx_blob.len().saturating_sub(32)..])
        );

        // PHASE-6: Pre-broadcast validation (catches format bugs before monerod rejection)
        info!("[TX-BUILD][PHASE-6] Running pre-broadcast validation...");
        let validation = Self::validate_tx_bytes(&tx_blob);

        if !validation.valid {
            error!("[TX-BUILD][PHASE-6] TX VALIDATION FAILED!");
            for err in &validation.errors {
                error!("[TX-BUILD][PHASE-6] ERROR: {}", err);
            }
            return Err(TransactionBuildError::ValidationError(
                validation.errors.join("; ")
            ));
        }

        for warning in &validation.warnings {
            warn!("[TX-BUILD][PHASE-6] WARNING: {}", warning);
        }

        info!("[TX-BUILD][PHASE-6] Validation PASSED: version={}, inputs={}, outputs={}, output_types={:?}, extra_len={}, rct_type={}",
            validation.parsed.version,
            validation.parsed.num_inputs,
            validation.parsed.num_outputs,
            validation.parsed.output_types,
            validation.parsed.extra_length,
            validation.parsed.rct_type
        );

        Ok(BuildResult {
            tx_hex: hex::encode(&tx_blob),
            tx_hash,
            prefix_hash,
            base_hash,
            prunable_hash,
        })
    }

    /// Generate Bulletproof+ range proof from stored output data
    fn generate_bulletproof(&mut self) -> Result<(), TransactionBuildError> {
        info!(
            "[TX-BUILD][BP+] =========================================="
        );
        info!(
            "[TX-BUILD][BP+] Generating Bulletproof+ range proof"
        );
        info!(
            "[TX-BUILD][BP+] Outputs: {}, Masks: {}",
            self.output_amounts.len(),
            self.output_masks.len()
        );

        if self.output_amounts.is_empty() {
            error!("[TX-BUILD][BP+] ERROR: No outputs - cannot generate");
            return Err(TransactionBuildError::MissingField(
                "No outputs added - cannot generate Bulletproof+".into()
            ));
        }

        if self.output_amounts.len() != self.output_masks.len() {
            error!(
                "[TX-BUILD][BP+] ERROR: Mismatch: {} amounts vs {} masks",
                self.output_amounts.len(),
                self.output_masks.len()
            );
            return Err(TransactionBuildError::MissingField(
                format!(
                    "Mismatched output counts: {} amounts vs {} masks",
                    self.output_amounts.len(),
                    self.output_masks.len()
                )
            ));
        }

        // Log detailed output data
        for (i, (amount, mask)) in self.output_amounts.iter().zip(self.output_masks.iter()).enumerate() {
            info!(
                "[TX-BUILD][BP+][OUTPUT-{}] amount={} piconero ({:.12} XMR)",
                i, amount, *amount as f64 / 1_000_000_000_000.0
            );
            info!(
                "[TX-BUILD][BP+][OUTPUT-{}] mask={}",
                i, hex::encode(mask)
            );

            // Check for zero mask (potential issue)
            if mask.iter().all(|&b| b == 0) {
                warn!(
                    "[TX-BUILD][BP+][OUTPUT-{}] WARNING: Mask is all zeros - this may cause BP+ verification failure!",
                    i
                );
            }
        }

        // Generate BP+ using the bulletproofs_builder
        info!("[TX-BUILD][BP+] Calling generate_bulletproof_plus...");
        let start_time = std::time::Instant::now();

        let bp = generate_bulletproof_plus(&self.output_amounts, &self.output_masks)
            .map_err(|e| {
                error!("[TX-BUILD][BP+] FAILED: {:?}", e);
                TransactionBuildError::SerializationError(
                    format!("Bulletproof+ generation failed: {}", e)
                )
            })?;

        let elapsed = start_time.elapsed();
        info!(
            "[TX-BUILD][BP+] SUCCESS: Bulletproof+ generated in {:?}",
            elapsed
        );

        // Log proof variant
        match &bp {
            monero_bulletproofs_mirror::Bulletproof::Plus(_plus) => {
                // Fields are private, serialize to get actual size
                let mut size_buf = Vec::new();
                let size = bp.write(&mut size_buf).map(|_| size_buf.len()).unwrap_or(0);
                info!(
                    "[TX-BUILD][BP+] Proof variant: Plus (serialized_size={} bytes)",
                    size
                );
            }
            monero_bulletproofs_mirror::Bulletproof::Original(_) => {
                warn!("[TX-BUILD][BP+] Proof variant: Original (unexpected for RCT v6!)");
            }
        }

        self.bulletproof_plus = Some(bp);
        Ok(())
    }

    /// Compute transaction prefix hash for signing
    pub fn compute_prefix_hash(&self) -> Result<[u8; 32], TransactionBuildError> {
        let mut prefix_blob = Vec::new();
        self.serialize_prefix(&mut prefix_blob)?;

        let mut hasher = Keccak256::new();
        hasher.update(&prefix_blob);
        let result: [u8; 32] = hasher.finalize().into();
        Ok(result)
    }

    /// Prepare transaction for signing by generating Bulletproof+ range proof
    ///
    /// This MUST be called before `compute_clsag_message()` because the CLSAG
    /// message includes the hash of the range proofs.
    pub fn prepare_for_signing(&mut self) -> Result<(), TransactionBuildError> {
        if self.bulletproof_plus.is_none() {
            info!("[TX-BUILD][PREPARE] Generating Bulletproof+ for CLSAG message computation...");
            self.generate_bulletproof()?;
        }
        Ok(())
    }

    /// Export the generated Bulletproof+ as serialized bytes
    ///
    /// This MUST be called after `prepare_for_signing()` to get the BP+ bytes
    /// for storage. The same bytes MUST be imported during broadcast to ensure
    /// the CLSAG message matches what was signed.
    ///
    /// v0.61.0: Critical fix for web flow where signing and broadcast are separate requests.
    pub fn export_bulletproof_bytes(&self) -> Result<Vec<u8>, TransactionBuildError> {
        let bp = self.bulletproof_plus.as_ref().ok_or_else(|| {
            TransactionBuildError::MissingField("bulletproof_plus not generated - call prepare_for_signing first".into())
        })?;

        let mut bytes = Vec::new();
        bp.write(&mut bytes).map_err(|e| {
            TransactionBuildError::SerializationError(format!("BP+ export failed: {:?}", e))
        })?;

        info!(
            "[TX-BUILD][BP+] Exported BP+ bytes: {} bytes",
            bytes.len()
        );

        Ok(bytes)
    }

    /// Import pre-generated Bulletproof+ bytes
    ///
    /// This MUST be called BEFORE `build()` when reusing a BP+ from a previous
    /// `prepare_for_signing()` call. This is required for the web flow where
    /// signing and broadcast happen in separate HTTP requests.
    ///
    /// v0.61.0: Critical fix to prevent BP+ regeneration which causes clsag_message mismatch.
    pub fn import_bulletproof_bytes(&mut self, bytes: &[u8]) -> Result<(), TransactionBuildError> {
        use std::io::Cursor;

        let mut cursor = Cursor::new(bytes);
        // v0.61.1 FIX: MUST use read_plus() NOT read()!
        // - read() returns Bulletproof::Original (old BP format)
        // - read_plus() returns Bulletproof::Plus (new BP+ format we use)
        let bp = Bulletproof::read_plus(&mut cursor).map_err(|e| {
            TransactionBuildError::SerializationError(format!("BP+ import failed: {:?}", e))
        })?;

        info!(
            "[TX-BUILD][BP+] Imported BP+ bytes: {} bytes",
            bytes.len()
        );

        self.bulletproof_plus = Some(bp);
        Ok(())
    }

    /// Compute the full CLSAG message (get_pre_mlsag_hash)
    ///
    /// This is the actual message that CLSAG signs, NOT just tx_prefix_hash.
    /// The message is: hash(tx_prefix_hash || ss_hash || pseudo_outs_hash)
    ///
    /// Where:
    /// - tx_prefix_hash: hash of the transaction prefix
    /// - ss_hash: hash of the rctSigPrunable EXCLUDING CLSAGs (i.e., just the BP+ data)
    /// - pseudo_outs_hash: hash of pseudo_out commitments
    ///
    /// Reference: monero/src/ringct/rctSigs.cpp::get_pre_mlsag_hash()
    /// Verified against real stagenet transactions in verify_real_clsag.rs
    ///
    /// IMPORTANT: Must call `prepare_for_signing()` first to generate BP+!
    ///
    /// The CLSAG message is computed as:
    ///   cn_fast_hash(tx_prefix_hash || rctSigBase_hash || bp_kv_hash)
    /// Where:
    ///   - tx_prefix_hash = cn_fast_hash(tx_prefix_blob)
    ///   - rctSigBase_hash = cn_fast_hash(type || fee || ecdhInfo || outPk)
    ///   - bp_kv_hash = cn_fast_hash(BP+ keys only: A,A1,B,r1,s1,d1,L[],R[])
    ///
    /// CRITICAL: NO sc_reduce32 on any of the hashes! Raw 32-byte hashes concatenated.
    pub fn compute_clsag_message(&self, _pseudo_outs: &[[u8; 32]]) -> Result<[u8; 32], TransactionBuildError> {
        // 1. Compute tx_prefix_hash (hashes[0])
        let tx_prefix_hash = self.compute_prefix_hash()?;
        info!(
            "[TX-BUILD][CLSAG-MSG] hashes[0] tx_prefix_hash: {}",
            hex::encode(&tx_prefix_hash)
        );

        // 2. Compute rctSigBase hash (hashes[1])
        // rctSigBase = type(1 byte) + fee(varint) + ecdhInfo(8 bytes * outputs) + outPk(32 bytes * outputs)
        let mut rct_base = Vec::new();

        // RCT type = 6 (BulletproofPlus)
        rct_base.push(6u8);

        // Fee as varint
        self.write_varint(&mut rct_base, self.fee);

        // ecdhInfo - 8 bytes per output (encrypted amounts)
        for ecdh in &self.ecdh_info {
            rct_base.extend_from_slice(&ecdh.amount);
        }

        // outPk - output commitments (32 bytes each)
        for commitment in &self.output_commitments {
            rct_base.extend_from_slice(commitment);
        }

        let rct_base_hash: [u8; 32] = Keccak256::digest(&rct_base).into();
        info!(
            "[TX-BUILD][CLSAG-MSG] hashes[1] rctSigBase_hash: {} ({} bytes)",
            hex::encode(&rct_base_hash),
            rct_base.len()
        );

        // 3. Compute BP+ keyV hash (hashes[2])
        // Just the 32-byte keys, NO varint counts: A, A1, B, r1, s1, d1, L[], R[]
        let bp = self.bulletproof_plus.as_ref().ok_or_else(|| {
            TransactionBuildError::MissingField(
                "Bulletproof+ not generated - call prepare_for_signing() first".into()
            )
        })?;

        // Serialize BP+ to bytes, then extract just the keys (skip varints)
        let mut bp_full = Vec::new();
        bp.write(&mut bp_full).map_err(|e| {
            TransactionBuildError::SerializationError(format!("BP+ serialization failed: {}", e))
        })?;

        // Parse BP+ serialization to extract just keys:
        // Format: A(32) + A1(32) + B(32) + r1(32) + s1(32) + d1(32) + L_count(varint) + L[](32 each) + R_count(varint) + R[](32 each)
        let mut bp_kv = Vec::new();
        let mut pos = 0;

        // A, A1, B, r1, s1, d1 (6 x 32 bytes)
        for _ in 0..6 {
            if pos + 32 > bp_full.len() {
                return Err(TransactionBuildError::SerializationError(
                    "BP+ serialization too short".into()
                ));
            }
            bp_kv.extend_from_slice(&bp_full[pos..pos + 32]);
            pos += 32;
        }

        // L vector: read count varint, then L keys
        let (l_count, new_pos) = Self::read_varint(&bp_full, pos);
        pos = new_pos;
        for _ in 0..l_count {
            bp_kv.extend_from_slice(&bp_full[pos..pos + 32]);
            pos += 32;
        }

        // R vector: read count varint, then R keys
        let (r_count, new_pos) = Self::read_varint(&bp_full, pos);
        pos = new_pos;
        for _ in 0..r_count {
            bp_kv.extend_from_slice(&bp_full[pos..pos + 32]);
            pos += 32;
        }

        let bp_kv_hash: [u8; 32] = Keccak256::digest(&bp_kv).into();
        info!(
            "[TX-BUILD][CLSAG-MSG] hashes[2] bp_kv_hash: {} ({} keys = {} bytes)",
            hex::encode(&bp_kv_hash),
            bp_kv.len() / 32,
            bp_kv.len()
        );

        // 4. Final CLSAG message = cn_fast_hash(hashes[0] || hashes[1] || hashes[2])
        // CRITICAL: NO sc_reduce32! Just concatenate the raw 32-byte hashes.
        let clsag_message: [u8; 32] = Keccak256::new()
            .chain_update(&tx_prefix_hash)  // raw 32 bytes
            .chain_update(&rct_base_hash)   // raw 32 bytes
            .chain_update(&bp_kv_hash)      // raw 32 bytes
            .finalize()
            .into();

        info!(
            "[TX-BUILD][CLSAG-MSG] CLSAG message (get_pre_mlsag_hash): {}",
            hex::encode(&clsag_message)
        );

        Ok(clsag_message)
    }

    // ========================================================================
    // SERIALIZATION HELPERS
    // ========================================================================

    /// Serialize the transaction prefix
    fn serialize_prefix(&self, out: &mut Vec<u8>) -> Result<(), TransactionBuildError> {
        // Version (varint): 2 for CLSAG, 3 for FCMP++
        let version = if self.fcmp_data.is_some() { 3u64 } else { self.version as u64 };
        self.write_varint(out, version);

        // Unlock time (varint)
        self.write_varint(out, self.unlock_time);

        // Number of inputs (varint)
        self.write_varint(out, self.inputs.len() as u64);

        let is_fcmp = self.fcmp_data.is_some();

        // Serialize each input
        for input in &self.inputs {
            // Input type: 0x02 = txin_to_key
            out.push(0x02);

            // Amount (varint) - always 0 for RingCT inputs
            self.write_varint(out, 0);

            if is_fcmp {
                // FCMP++: No ring members — membership proved via Curve Trees
                self.write_varint(out, 0u64);
            } else {
                // CLSAG: Ring members with decoy offsets
                self.write_varint(out, input.key_offsets.len() as u64);
                for offset in &input.key_offsets {
                    self.write_varint(out, *offset);
                }
            }

            // Key image (32 bytes) — present in both v2 and v3
            out.extend_from_slice(&input.key_image);
        }

        // Number of outputs (varint)
        self.write_varint(out, self.outputs.len() as u64);

        // Serialize each output
        for output in &self.outputs {
            // Amount (varint) - always 0 for RingCT
            self.write_varint(out, output.amount);

            // Output type: 0x03 = txout_to_tagged_key (HF15+, with view_tag)
            // NOTE: 0x02 = txout_to_key (NO view_tag), 0x03 = txout_to_tagged_key (WITH view_tag)
            out.push(0x03);

            // Target key (32 bytes)
            out.extend_from_slice(&output.target_key);

            // View tag (1 byte) - required since Monero HF16
            out.push(output.view_tag);
        }

        // Extra field length (varint)
        self.write_varint(out, self.extra.len() as u64);

        // Extra data
        out.extend_from_slice(&self.extra);

        Ok(())
    }

    /// Serialize RCT base (non-prunable)
    ///
    /// CRITICAL: Order for RCT v6 (Bulletproofs+) per Monero spec:
    /// 1. rct_type (1 byte) = 6
    /// 2. txnFee (varint)
    /// 3. ecdhInfo (8 bytes each for BP+)
    /// 4. outPk (32 bytes each)
    ///
    /// NOTE: pseudo_outs are in PRUNABLE for type 6, NOT in base!
    /// Reference: monero/src/ringct/rctTypes.h serialize_rctsig_base()
    fn serialize_rct_base(&self, out: &mut Vec<u8>) -> Result<(), TransactionBuildError> {
        // 1. RCT type: 6 = RCTTypeBulletproofPlus (CLSAG), 7 = FCMP++
        let rct_type: u8 = if self.fcmp_data.is_some() { 7 } else { 6 };
        out.push(rct_type);

        // 2. Transaction fee (varint)
        self.write_varint(out, self.fee);

        // NOTE: pseudo_outs are NOT serialized here for RCT v6 or v7!
        // They go in rctSigPrunable AFTER the signatures/proofs.
        // Reference: monero/src/ringct/rctTypes.h line ~290

        // 3. ECDH info (encrypted amounts)
        for ecdh in &self.ecdh_info {
            out.extend_from_slice(&ecdh.amount);
        }

        // 4. Output commitments (outPk)
        for commitment in &self.output_commitments {
            out.extend_from_slice(commitment);
        }

        info!(
            "[TX-BUILD][RCT-BASE] type={}, fee={}, ecdhInfo={}, outPk={} (pseudo_outs in prunable)",
            rct_type, self.fee, self.ecdh_info.len(), self.output_commitments.len()
        );

        Ok(())
    }

    /// Serialize RCT prunable (signatures)
    ///
    /// For RCT v6 (Bulletproofs+), the prunable section contains:
    /// 1. nbp (varint) - number of bulletproofs (always 1)
    /// 2. Bulletproof+ data (A, A1, B, r1, s1, d1, L[], R[])
    /// 3. CLSAGs (s[], c1, D per CLSAG) - NO count varint, implicit = vin_count
    /// 4. pseudo_outs (32 bytes each) - NO count varint, implicit = vin_count
    ///
    /// Reference: monero/src/ringct/rctTypes.h serialize_rctsig_prunable()
    fn serialize_rct_prunable(&self, out: &mut Vec<u8>) -> Result<(), TransactionBuildError> {
        // FCMP++ dispatch: if FCMP proof data is attached, use v3 serialization
        if self.fcmp_data.is_some() {
            return self.serialize_rct_prunable_fcmp(out);
        }

        // === CLSAG path (v2, RCT type 6) ===

        // 1. Number of Bulletproofs+ (varint) - always 1 for our transactions
        self.write_varint(out, 1u64);

        // 2. Bulletproof+ data
        if let Some(ref bp) = self.bulletproof_plus {
            self.serialize_bulletproof_plus(bp, out)?;
        } else {
            return Err(TransactionBuildError::MissingField(
                "bulletproof_plus required for RCT v6".into()
            ));
        }

        // 3. CLSAGs (NO count varint - count is implicit = number of inputs)
        // Reference: https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp
        for clsag in &self.clsag_signatures {
            // s values FIRST (all ring members)
            for s in &clsag.s {
                out.extend_from_slice(s);
            }

            // c1 SECOND (challenge scalar)
            out.extend_from_slice(&clsag.c1);

            // D THIRD (key image auxiliary point)
            out.extend_from_slice(&clsag.d);
        }

        // 4. pseudo_outs (NO count varint - count is implicit = number of inputs)
        for pseudo_out in &self.pseudo_outputs {
            out.extend_from_slice(pseudo_out);
        }
        info!(
            "[TX-BUILD][RCT-PRUNABLE] BP+, {} CLSAGs, {} pseudo_outs",
            self.clsag_signatures.len(), self.pseudo_outputs.len()
        );

        Ok(())
    }

    /// Serialize RCT prunable section for FCMP++ (v3) transactions.
    ///
    /// Wire format (from `FcmpPlusPlus::write()`):
    /// ```text
    /// 1. BP+ range proof (same as CLSAG — amount privacy unchanged)
    /// 2. Per-input: O~ | I~ | R (96B) + SA+L proof (384B) = 480B each
    /// 3. FCMP membership proof (variable) + root_blind_pok (64B)
    /// 4. Pseudo-outs C~ (32B each) — same position as CLSAG pseudo-outs
    /// ```
    fn serialize_rct_prunable_fcmp(&self, out: &mut Vec<u8>) -> Result<(), TransactionBuildError> {
        let fcmp = self.fcmp_data.as_ref().ok_or_else(|| {
            TransactionBuildError::FcmpError("FCMP data not attached".into())
        })?;

        // 1. BP+ range proof (amount privacy is independent of signature scheme)
        self.write_varint(out, 1u64);
        if let Some(ref bp) = self.bulletproof_plus {
            self.serialize_bulletproof_plus(bp, out)?;
        } else {
            return Err(TransactionBuildError::MissingField(
                "bulletproof_plus required for FCMP++ TX".into()
            ));
        }

        // 2. Per-input: Input::write_partial() + SpendAuthAndLinkability::write()
        // NO count varint — implicit from input count (same convention as CLSAG)
        for (i, input_proof) in fcmp.input_proofs.iter().enumerate() {
            // Input::write_partial() → O~ | I~ | R (96 bytes)
            out.extend_from_slice(&input_proof.o_tilde);
            out.extend_from_slice(&input_proof.i_tilde);
            out.extend_from_slice(&input_proof.r);

            // SpendAuthAndLinkability::write() → 6 points + 6 scalars (384 bytes)
            // Points: P, A, B, R_O, R_P, R_L
            for point in &input_proof.sal_points {
                out.extend_from_slice(point);
            }
            // Scalars: s_alpha, s_beta, s_delta, s_y, s_z, s_r_p
            for scalar in &input_proof.sal_scalars {
                out.extend_from_slice(scalar);
            }

            debug!(
                "[TX-BUILD][FCMP-PRUNABLE] Input {} serialized: 480 bytes (96B tuple + 384B SA+L)",
                i
            );
        }

        // 3. Fcmp::write() → proof bytes (variable) + root_blind_pok (64 bytes)
        //
        // No length prefix: `Fcmp::read(inputs, layers)` computes the exact split
        // via `proof_size(inputs, layers) - 64`. The format is NOT self-delimiting —
        // the reader must know `inputs` (from TX prefix) and `layers` (consensus param).
        //
        // Size validated at attach time: proof_bytes.len() == expected_proof_len
        // and proof_bytes.len() % 32 == 0 (all elements are 32-byte scalars/points).
        out.extend_from_slice(&fcmp.membership.proof_bytes);
        out.extend_from_slice(&fcmp.membership.root_blind_pok);

        // 4. Pseudo-outs C~ (same position as CLSAG pseudo-outs)
        // Per vendor: C_tilde is NOT inside FcmpPlusPlus::write(), passed separately
        for pseudo_out in &self.pseudo_outputs {
            out.extend_from_slice(pseudo_out);
        }

        info!(
            "[TX-BUILD][FCMP-PRUNABLE] FCMP++ prunable: {} inputs ({}B each), membership={}B, {} pseudo_outs",
            fcmp.input_proofs.len(),
            480,
            fcmp.membership.proof_bytes.len() + 64,
            self.pseudo_outputs.len()
        );

        Ok(())
    }

    /// Serialize Bulletproof+ to binary format
    ///
    /// Format follows Monero's serialization:
    /// - A (32 bytes) - commitment to alpha
    /// - S (32 bytes) - commitment to s_L and s_R
    /// - T1 (32 bytes) - commitment to t1
    /// - T2 (32 bytes) - commitment to t2
    /// - taux (32 bytes) - scalar
    /// - mu (32 bytes) - scalar
    /// - L (n * 32 bytes) - inner product left
    /// - R (n * 32 bytes) - inner product right
    /// - a (32 bytes) - inner product a
    /// - b (32 bytes) - inner product b
    /// - t (32 bytes) - inner product t
    fn serialize_bulletproof_plus(
        &self,
        bp: &Bulletproof,
        out: &mut Vec<u8>,
    ) -> Result<(), TransactionBuildError> {
        // Use the write method from monero-bulletproofs-mirror
        bp.write(out).map_err(|e| {
            TransactionBuildError::SerializationError(format!("BP+ serialization failed: {:?}", e))
        })?;

        Ok(())
    }

    /// Convert absolute indices to relative offsets
    fn indices_to_offsets(&self, indices: &[u64]) -> Vec<u64> {
        if indices.is_empty() {
            return Vec::new();
        }

        let mut sorted = indices.to_vec();
        sorted.sort();

        let mut offsets = Vec::with_capacity(sorted.len());
        offsets.push(sorted[0]);

        for i in 1..sorted.len() {
            offsets.push(sorted[i] - sorted[i - 1]);
        }

        offsets
    }

    /// Write a varint to output buffer
    fn write_varint(&self, out: &mut Vec<u8>, value: u64) {
        let mut v = value;
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
    }

    // ========================================================================
    // PRE-BROADCAST VALIDATION (Systematic TX structure check)
    // ========================================================================

    /// Read a varint from bytes, return (value, new_offset)
    fn read_varint(data: &[u8], mut offset: usize) -> (u64, usize) {
        let mut result: u64 = 0;
        let mut shift = 0;
        while offset < data.len() {
            let byte = data[offset];
            offset += 1;
            result |= ((byte & 0x7F) as u64) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                break; // Prevent overflow
            }
        }
        (result, offset)
    }

    /// Validate serialized transaction bytes BEFORE broadcast
    ///
    /// This catches format bugs that would cause monerod rejection:
    /// - Wrong output type (0x02 vs 0x03)
    /// - Corrupted extra length
    /// - Invalid RCT type
    /// - Misaligned structure
    ///
    /// SYSTEMATIC CHECK: This runs automatically in build() to prevent
    /// broadcasting malformed transactions.
    pub fn validate_tx_bytes(data: &[u8]) -> TxValidationResult {
        let mut result = TxValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            parsed: TxParsedFields::default(),
        };

        if data.is_empty() {
            result.valid = false;
            result.errors.push("Empty transaction data".to_string());
            return result;
        }

        let mut offset = 0;

        // Version
        let (version, new_offset) = Self::read_varint(data, offset);
        offset = new_offset;
        result.parsed.version = version;
        if version != 2 && version != 3 {
            result.valid = false;
            result.errors.push(format!("Invalid TX version {}, expected 2 (CLSAG) or 3 (FCMP++)", version));
        }

        // Unlock time
        let (unlock_time, new_offset) = Self::read_varint(data, offset);
        offset = new_offset;
        result.parsed.unlock_time = unlock_time;

        // F6 FIX: Validate unlock_time is 0 for standard marketplace transactions
        // Non-zero unlock_time could lock funds or indicate a malicious transaction
        if unlock_time != 0 {
            result.valid = false;
            result.errors.push(format!(
                "Non-zero unlock_time: {} (expected 0 for standard transactions)",
                unlock_time
            ));
        }

        // Number of inputs
        let (num_inputs, new_offset) = Self::read_varint(data, offset);
        offset = new_offset;
        result.parsed.num_inputs = num_inputs as usize;

        if num_inputs == 0 {
            result.valid = false;
            result.errors.push("Zero inputs".to_string());
        }

        // Skip inputs (we just need to parse to outputs)
        for _ in 0..num_inputs {
            if offset >= data.len() {
                result.valid = false;
                result.errors.push("Truncated input data".to_string());
                return result;
            }

            let input_type = data[offset];
            offset += 1;

            if input_type == 0x02 {
                // txin_to_key: amount(varint) + num_offsets(varint) + offsets(varints) + key_image(32)
                let (_, new_offset) = Self::read_varint(data, offset); // amount
                offset = new_offset;
                let (num_offsets, new_offset) = Self::read_varint(data, offset);
                offset = new_offset;
                for _ in 0..num_offsets {
                    let (_, new_offset) = Self::read_varint(data, offset);
                    offset = new_offset;
                }
                offset += 32; // key_image
            } else {
                result.valid = false;
                result.errors.push(format!("Unknown input type 0x{:02x}", input_type));
                return result;
            }
        }

        // Number of outputs
        let (num_outputs, new_offset) = Self::read_varint(data, offset);
        offset = new_offset;
        result.parsed.num_outputs = num_outputs as usize;

        if num_outputs == 0 {
            result.valid = false;
            result.errors.push("Zero outputs".to_string());
        }

        // Parse outputs (CRITICAL: check output type)
        for i in 0..num_outputs {
            if offset >= data.len() {
                result.valid = false;
                result.errors.push(format!("Truncated output {} data", i));
                return result;
            }

            // Amount (always 0 for RingCT)
            let (_, new_offset) = Self::read_varint(data, offset);
            offset = new_offset;

            // Output type - THIS IS THE CRITICAL CHECK
            let output_type = data[offset];
            offset += 1;
            result.parsed.output_types.push(output_type);

            match output_type {
                0x02 => {
                    // txout_to_key: NO view_tag
                    result.valid = false;
                    result.errors.push(format!(
                        "Output {}: type 0x02 (txout_to_key) - MUST be 0x03 (txout_to_tagged_key) for HF15+",
                        i
                    ));
                    offset += 32; // pubkey only
                }
                0x03 => {
                    // txout_to_tagged_key: WITH view_tag (correct for HF15+)
                    offset += 32; // pubkey
                    offset += 1;  // view_tag
                }
                _ => {
                    result.valid = false;
                    result.errors.push(format!(
                        "Output {}: unknown type 0x{:02x}",
                        i, output_type
                    ));
                    return result;
                }
            }
        }

        // Extra field length
        if offset >= data.len() {
            result.valid = false;
            result.errors.push("Missing extra field".to_string());
            return result;
        }

        let (extra_len, new_offset) = Self::read_varint(data, offset);
        offset = new_offset;
        result.parsed.extra_length = extra_len as usize;

        // Sanity check extra length
        if extra_len > 1000 {
            result.valid = false;
            result.errors.push(format!(
                "Extra length {} is too large (>1000) - likely parsing error from wrong output type",
                extra_len
            ));
        } else if extra_len < 33 {
            result.warnings.push(format!(
                "Extra length {} is small (<33), expected ~34 for tx_pubkey",
                extra_len
            ));
        }

        // Skip extra data
        offset += extra_len as usize;

        // RCT type
        if offset >= data.len() {
            result.valid = false;
            result.errors.push("Missing RCT signature".to_string());
            return result;
        }

        let rct_type = data[offset];
        result.parsed.rct_type = rct_type;

        match rct_type {
            6 => {
                // RCTTypeBulletproofPlus (CLSAG) - correct for current network
            }
            7 => {
                // RCTTypeFcmpPlusPlus - post-hard-fork FCMP++ transactions
            }
            5 => {
                result.warnings.push("RCT type 5 (CLSAG) - old type, current is 6 (BP+)".to_string());
            }
            0..=4 => {
                result.warnings.push(format!(
                    "RCT type {} is very old, current is 6 (BP+)",
                    rct_type
                ));
            }
            _ => {
                result.valid = false;
                result.errors.push(format!("Invalid RCT type {}", rct_type));
            }
        }

        result
    }
}

impl Default for MoneroTransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ADDRESS PARSING UTILITIES
// ============================================================================

/// Parse a Monero address and extract spend/view public keys
pub fn parse_monero_address(address: &str) -> Result<([u8; 32], [u8; 32]), TransactionBuildError> {
    info!(
        "[TX-BUILD][ADDR-PARSE] Parsing Monero address: {}...{}",
        &address[..8.min(address.len())],
        &address[address.len().saturating_sub(8)..]
    );

    // Decode base58 with checksum
    let decoded = base58_monero::decode_check(address)
        .map_err(|e| {
            error!("[TX-BUILD][ADDR-PARSE] Base58 decode failed: {}", e);
            TransactionBuildError::AddressError(format!("Base58 decode: {}", e))
        })?;

    // Address format: network_byte (1) + spend_pub (32) + view_pub (32) = 65 bytes
    if decoded.len() != 65 {
        error!(
            "[TX-BUILD][ADDR-PARSE] Invalid address length: {} (expected 65)",
            decoded.len()
        );
        return Err(TransactionBuildError::AddressError(
            format!("Invalid address length: {} (expected 65)", decoded.len())
        ));
    }

    let network_byte = decoded[0];
    let mut spend_pub = [0u8; 32];
    let mut view_pub = [0u8; 32];
    spend_pub.copy_from_slice(&decoded[1..33]);
    view_pub.copy_from_slice(&decoded[33..65]);

    // Determine network type
    let network_type = match network_byte {
        18 => "mainnet",
        53 => "testnet",
        24 => "stagenet",
        _ => "unknown",
    };

    info!(
        "[TX-BUILD][ADDR-PARSE] SUCCESS: network={} (byte={})",
        network_type, network_byte
    );
    debug!(
        "[TX-BUILD][ADDR-PARSE] spend_pub: {}",
        hex::encode(&spend_pub)
    );
    debug!(
        "[TX-BUILD][ADDR-PARSE] view_pub: {}",
        hex::encode(&view_pub)
    );

    Ok((spend_pub, view_pub))
}

/// Generate a stealth address for an output
///
/// P = H_s(r*V) * G + S
/// where:
/// - r is the TX secret key
/// - V is recipient's public view key
/// - S is recipient's public spend key
/// - H_s is hash-to-scalar
pub fn generate_stealth_address(
    tx_secret_key: &[u8; 32],
    recipient_spend_pub: &[u8; 32],
    recipient_view_pub: &[u8; 32],
    output_index: u64,
) -> Result<[u8; 32], TransactionBuildError> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    info!(
        "[TX-BUILD][STEALTH] Generating stealth address for output_index={}",
        output_index
    );
    debug!(
        "[TX-BUILD][STEALTH] tx_secret_key: {}...{}",
        hex::encode(&tx_secret_key[..4]),
        hex::encode(&tx_secret_key[28..32])
    );

    // Parse keys
    let r = Scalar::from_bytes_mod_order(*tx_secret_key);

    let view_pub_point = CompressedEdwardsY(*recipient_view_pub)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][STEALTH] Invalid view public key - decompression failed");
            TransactionBuildError::InvalidPoint("Invalid view public key".into())
        })?;

    let spend_pub_point = CompressedEdwardsY(*recipient_spend_pub)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][STEALTH] Invalid spend public key - decompression failed");
            TransactionBuildError::InvalidPoint("Invalid spend public key".into())
        })?;

    // Compute shared secret: r * V
    // BUG #C1 FIX: Apply cofactor (multiply by 8) for Monero ECDH derivation
    // Monero derivation = 8 * r * V to ensure result is in prime-order subgroup
    let shared_secret = (r * view_pub_point).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();
    debug!(
        "[TX-BUILD][STEALTH] shared_secret (r*V): {}...",
        hex::encode(&shared_secret_bytes[..8])
    );

    // Compute H_s(r*V || output_index) - Monero uses varint encoding for output_index
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    // CRITICAL FIX (v0.9.5): Use varint encoding, not to_le_bytes()
    // Monero's derivation_to_scalar uses tools::write_varint(end, output_index)
    let mut output_index_varint = Vec::new();
    encode_varint_to_vec(&mut output_index_varint, output_index);
    hasher.update(&output_index_varint);
    let hash: [u8; 32] = hasher.finalize().into();
    let h_s = Scalar::from_bytes_mod_order(hash);
    debug!(
        "[TX-BUILD][STEALTH] H_s derivation: {}...",
        hex::encode(&hash[..8])
    );

    // Compute stealth address: H_s(r*V || i) * G + S
    let h_s_g = &*ED25519_BASEPOINT_TABLE * &h_s;
    let stealth_address = h_s_g + spend_pub_point;
    let result = stealth_address.compress().to_bytes();

    info!(
        "[TX-BUILD][STEALTH] SUCCESS: stealth_address = {}",
        hex::encode(&result)
    );

    Ok(result)
}

/// Generate stealth address AND view_tag (required since Monero HF16)
///
/// The view_tag is computed as:
/// view_tag = keccak256("view_tag" || derivation || output_index)[0]
///
/// Returns (stealth_address, view_tag)
pub fn generate_stealth_address_with_view_tag(
    tx_secret_key: &[u8; 32],
    recipient_spend_pub: &[u8; 32],
    recipient_view_pub: &[u8; 32],
    output_index: u64,
) -> Result<([u8; 32], u8), TransactionBuildError> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    info!(
        "[TX-BUILD][STEALTH+VIEWTAG] Generating stealth address + view_tag for output_index={}",
        output_index
    );

    // Parse keys
    let r = Scalar::from_bytes_mod_order(*tx_secret_key);

    let view_pub_point = CompressedEdwardsY(*recipient_view_pub)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][STEALTH+VIEWTAG] Invalid view public key");
            TransactionBuildError::InvalidPoint("Invalid view public key".into())
        })?;

    let spend_pub_point = CompressedEdwardsY(*recipient_spend_pub)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][STEALTH+VIEWTAG] Invalid spend public key");
            TransactionBuildError::InvalidPoint("Invalid spend public key".into())
        })?;

    // Compute shared secret (derivation): r * V
    // BUG #C1b FIX: Apply cofactor (multiply by 8) for Monero ECDH derivation
    // Monero derivation = 8 * r * V to ensure result is in prime-order subgroup
    let derivation = (r * view_pub_point).mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();

    // Compute view_tag: H("view_tag" || derivation || varint(output_index))[0]
    // CRITICAL FIX (v0.54.0):
    // 1. Uses "view_tag" salt (8 bytes, NO null terminator)
    // 2. Takes RAW first byte of hash (NO sc_reduce32!)
    // Reference: crypto/crypto.cpp derive_view_tag() uses hash_to_view_tag()
    // which is cn_fast_hash with truncated output - NOT hash_to_scalar!
    let mut view_tag_hasher = Keccak256::new();
    view_tag_hasher.update(b"view_tag");  // 8-byte salt, no null
    view_tag_hasher.update(&derivation_bytes);
    let mut vt_output_index_varint = Vec::new();
    encode_varint_to_vec(&mut vt_output_index_varint, output_index);
    view_tag_hasher.update(&vt_output_index_varint);
    let view_tag_hash: [u8; 32] = view_tag_hasher.finalize().into();
    // CRITICAL: Use RAW first byte - NO sc_reduce32!
    let view_tag = view_tag_hash[0];

    debug!(
        "[TX-BUILD][STEALTH+VIEWTAG] derivation: {}..., view_tag: 0x{:02x}",
        hex::encode(&derivation_bytes[..8]),
        view_tag
    );

    // Compute H_s(r*V || output_index) for stealth address
    // CRITICAL FIX (v0.9.5): Use varint encoding, not to_le_bytes()
    // Monero's derivation_to_scalar uses tools::write_varint(end, output_index)
    let mut hasher = Keccak256::new();
    hasher.update(&derivation_bytes);
    let mut stealth_output_index_varint = Vec::new();
    encode_varint_to_vec(&mut stealth_output_index_varint, output_index);
    hasher.update(&stealth_output_index_varint);
    let hash: [u8; 32] = hasher.finalize().into();
    let h_s = Scalar::from_bytes_mod_order(hash);

    // Compute stealth address: H_s(r*V || i) * G + S
    let h_s_g = &*ED25519_BASEPOINT_TABLE * &h_s;
    let stealth_address = h_s_g + spend_pub_point;
    let result = stealth_address.compress().to_bytes();

    info!(
        "[TX-BUILD][STEALTH+VIEWTAG] SUCCESS: stealth_address = {}, view_tag = 0x{:02x}",
        hex::encode(&result),
        view_tag
    );

    Ok((result, view_tag))
}

/// Generate TX public key R = r * G
pub fn generate_tx_pubkey(tx_secret_key: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let r = Scalar::from_bytes_mod_order(*tx_secret_key);
    let tx_pubkey = &*ED25519_BASEPOINT_TABLE * &r;
    tx_pubkey.compress().to_bytes()
}

// ============================================================================
// PEDERSEN COMMITMENT UTILITIES
// ============================================================================

/// Monero H generator point (used for commitment amounts)
/// H = 8 * hash_to_point("H") - pre-computed value from monero source
const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Compute output commitment that balances with pseudo_out and fee
///
/// For a single input/output transaction:
/// `output_commitment = pseudo_out - fee * H`
///
/// This ensures: `pseudo_out = output_commitment + fee * H`
///
/// # Arguments
/// * `pseudo_out` - The pseudo output commitment from the CLSAG signature
/// * `fee_atomic` - The transaction fee in atomic units
///
/// # Returns
/// The 32-byte output commitment
pub fn compute_balanced_output_commitment(
    pseudo_out: &[u8; 32],
    fee_atomic: u64,
) -> Result<[u8; 32], TransactionBuildError> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    info!(
        "[TX-BUILD][COMMITMENT] Computing balanced output commitment"
    );
    info!(
        "[TX-BUILD][COMMITMENT] pseudo_out: {}",
        hex::encode(pseudo_out)
    );
    info!(
        "[TX-BUILD][COMMITMENT] fee: {} piconero ({:.12} XMR)",
        fee_atomic,
        fee_atomic as f64 / 1_000_000_000_000.0
    );

    // Parse pseudo_out as a point
    let pseudo_out_point = CompressedEdwardsY(*pseudo_out)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][COMMITMENT] pseudo_out decompression failed - not a valid curve point");
            TransactionBuildError::InvalidPoint("Invalid pseudo_out point".into())
        })?;

    // Parse H generator point
    let h_point = CompressedEdwardsY(H_BYTES)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][COMMITMENT] H generator decompression failed");
            TransactionBuildError::InvalidPoint("Invalid H generator".into())
        })?;

    // Compute fee * H
    let fee_scalar = Scalar::from(fee_atomic);
    let fee_h = fee_scalar * h_point;
    debug!(
        "[TX-BUILD][COMMITMENT] fee * H = {}",
        hex::encode(fee_h.compress().to_bytes())
    );

    // Compute output_commitment = pseudo_out - fee * H
    let output_commitment_point = pseudo_out_point - fee_h;
    let result = output_commitment_point.compress().to_bytes();

    info!(
        "[TX-BUILD][COMMITMENT] output_commitment (pseudo_out - fee*H) = {}",
        hex::encode(&result)
    );

    // Verification: pseudo_out should equal output_commitment + fee*H
    let verification = output_commitment_point + fee_h;
    let matches = verification.compress() == pseudo_out_point.compress();
    if matches {
        info!("[TX-BUILD][COMMITMENT] VERIFIED: pseudo_out == output_commitment + fee*H");
    } else {
        error!("[TX-BUILD][COMMITMENT] ERROR: Balance verification failed!");
    }

    Ok(result)
}

/// Compute output commitment for 2-output transaction (real output + dummy)
///
/// For a transaction with 2 outputs where output[1] is a dummy with 0 XMR:
/// - pseudo_out = out0_commitment + out1_commitment + fee*H
/// - out1_commitment = dummy_mask*G + 0*H = dummy_mask*G
/// - Therefore: out0_commitment = pseudo_out - dummy_mask*G - fee*H
///
/// # Arguments
/// * `pseudo_out` - The pseudo output commitment from the CLSAG signature
/// * `fee_atomic` - The transaction fee in atomic units
/// * `dummy_mask` - The blinding factor for the dummy output (output index 1)
///
/// # Returns
/// The 32-byte output commitment for output[0] (the real output)
pub fn compute_balanced_output_commitment_2outputs(
    pseudo_out: &[u8; 32],
    fee_atomic: u64,
    dummy_mask: &[u8; 32],
) -> Result<[u8; 32], TransactionBuildError> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    info!(
        "[TX-BUILD][COMMITMENT-2OUT] Computing balanced output commitment for 2-output TX"
    );
    info!(
        "[TX-BUILD][COMMITMENT-2OUT] pseudo_out: {}",
        hex::encode(pseudo_out)
    );
    info!(
        "[TX-BUILD][COMMITMENT-2OUT] fee: {} piconero ({:.12} XMR)",
        fee_atomic,
        fee_atomic as f64 / 1_000_000_000_000.0
    );
    info!(
        "[TX-BUILD][COMMITMENT-2OUT] dummy_mask: {}",
        hex::encode(dummy_mask)
    );

    // Parse pseudo_out as a point
    let pseudo_out_point = CompressedEdwardsY(*pseudo_out)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][COMMITMENT-2OUT] pseudo_out decompression failed");
            TransactionBuildError::InvalidPoint("Invalid pseudo_out point".into())
        })?;

    // Parse H generator point
    let h_point = CompressedEdwardsY(H_BYTES)
        .decompress()
        .ok_or_else(|| {
            error!("[TX-BUILD][COMMITMENT-2OUT] H generator decompression failed");
            TransactionBuildError::InvalidPoint("Invalid H generator".into())
        })?;

    // Compute fee * H
    let fee_scalar = Scalar::from(fee_atomic);
    let fee_h = fee_scalar * h_point;
    debug!(
        "[TX-BUILD][COMMITMENT-2OUT] fee * H = {}",
        hex::encode(fee_h.compress().to_bytes())
    );

    // Compute dummy_mask * G (this is the dummy output commitment since amount=0)
    let dummy_mask_scalar = Scalar::from_bytes_mod_order(*dummy_mask);
    let dummy_commitment_point = &*ED25519_BASEPOINT_TABLE * &dummy_mask_scalar;
    debug!(
        "[TX-BUILD][COMMITMENT-2OUT] dummy_mask * G = {}",
        hex::encode(dummy_commitment_point.compress().to_bytes())
    );

    // Compute out0_commitment = pseudo_out - dummy_mask*G - fee*H
    let out0_commitment_point = pseudo_out_point - dummy_commitment_point - fee_h;
    let result = out0_commitment_point.compress().to_bytes();

    info!(
        "[TX-BUILD][COMMITMENT-2OUT] out0_commitment = {}",
        hex::encode(&result)
    );

    // Verification: pseudo_out should equal out0 + dummy + fee*H
    let verification = out0_commitment_point + dummy_commitment_point + fee_h;
    let matches = verification.compress() == pseudo_out_point.compress();
    if matches {
        info!("[TX-BUILD][COMMITMENT-2OUT] VERIFIED: pseudo_out == out0 + dummy + fee*H");
    } else {
        error!("[TX-BUILD][COMMITMENT-2OUT] ERROR: Balance verification failed!");
    }

    Ok(result)
}

/// Generate a new Pedersen commitment: C = mask * G + amount * H
///
/// # Arguments
/// * `mask` - The blinding factor (32 bytes scalar)
/// * `amount` - The amount in atomic units
///
/// # Returns
/// The 32-byte commitment point
pub fn compute_pedersen_commitment(
    mask: &[u8; 32],
    amount: u64,
) -> Result<[u8; 32], TransactionBuildError> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    // Parse H generator point
    let h_point = CompressedEdwardsY(H_BYTES)
        .decompress()
        .ok_or_else(|| TransactionBuildError::InvalidPoint("Invalid H generator".into()))?;

    // Compute mask * G
    let mask_scalar = Scalar::from_bytes_mod_order(*mask);
    let mask_g = &*ED25519_BASEPOINT_TABLE * &mask_scalar;

    // Compute amount * H
    let amount_scalar = Scalar::from(amount);
    let amount_h = amount_scalar * h_point;

    // Commitment = mask * G + amount * H
    let commitment = mask_g + amount_h;

    Ok(commitment.compress().to_bytes())
}

/// Verify that commitments balance: sum(pseudo_outs) = sum(output_commitments) + fee * H
///
/// # Arguments
/// * `pseudo_outs` - Vector of pseudo output commitments
/// * `output_commitments` - Vector of output commitments
/// * `fee_atomic` - Transaction fee in atomic units
///
/// # Returns
/// true if commitments balance, false otherwise
pub fn verify_commitment_balance(
    pseudo_outs: &[[u8; 32]],
    output_commitments: &[[u8; 32]],
    fee_atomic: u64,
) -> Result<bool, TransactionBuildError> {
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::Identity;

    // Parse H generator point
    let h_point = CompressedEdwardsY(H_BYTES)
        .decompress()
        .ok_or_else(|| TransactionBuildError::InvalidPoint("Invalid H generator".into()))?;

    // Sum all pseudo_outs
    let mut sum_pseudo = EdwardsPoint::identity();
    for pseudo in pseudo_outs {
        let point = CompressedEdwardsY(*pseudo)
            .decompress()
            .ok_or_else(|| TransactionBuildError::InvalidPoint("Invalid pseudo_out".into()))?;
        sum_pseudo = sum_pseudo + point;
    }

    // Sum all output_commitments
    let mut sum_outputs = EdwardsPoint::identity();
    for commitment in output_commitments {
        let point = CompressedEdwardsY(*commitment)
            .decompress()
            .ok_or_else(|| TransactionBuildError::InvalidPoint("Invalid output commitment".into()))?;
        sum_outputs = sum_outputs + point;
    }

    // Compute fee * H
    let fee_scalar = Scalar::from(fee_atomic);
    let fee_h = fee_scalar * h_point;

    // Check: sum(pseudo_outs) == sum(outputs) + fee * H
    let expected = sum_outputs + fee_h;

    Ok(sum_pseudo.compress() == expected.compress())
}

// ============================================================================
// ECDH AMOUNT ENCRYPTION
// ============================================================================

/// Encrypt an amount using ECDH shared secret for RingCT v2
///
/// The encrypted amount is computed as:
/// 1. shared_secret = r * V (tx_secret_key * recipient_view_pub)
/// 2. derivation_hash = Hs(shared_secret || output_index)
/// 3. amount_key = Hs("amount" || derivation_hash)
/// 4. encrypted_amount = amount XOR amount_key[0..8]
///
/// # Arguments
/// * `tx_secret_key` - The ephemeral transaction secret key (r)
/// * `recipient_view_pub` - Recipient's public view key (V)
/// * `output_index` - The output index in the transaction
/// * `amount` - The amount to encrypt (atomic units)
///
/// # Returns
/// 8-byte encrypted amount
pub fn encrypt_amount_ecdh(
    tx_secret_key: &[u8; 32],
    recipient_view_pub: &[u8; 32],
    output_index: u64,  // Used in derivation_to_scalar step
    amount: u64,
) -> Result<[u8; 8], TransactionBuildError> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    // Parse tx_secret_key as scalar
    let r = Scalar::from_bytes_mod_order(*tx_secret_key);

    // Parse recipient view pubkey as point
    let view_pub_point = CompressedEdwardsY(*recipient_view_pub)
        .decompress()
        .ok_or_else(|| TransactionBuildError::InvalidPoint("Invalid recipient view key".into()))?;

    // Compute shared secret (derivation): 8 * r * V
    // CRITICAL: Monero uses cofactor multiplication for ECDH
    let derivation = (r * view_pub_point).mul_by_cofactor();
    let derivation_bytes = derivation.compress().to_bytes();

    // Monero v2 ECDH (RCTTypeBulletproofPlus) - CORRECTED per official spec:
    // Reference: rctOps.cpp genAmountEncodingFactor() and ecdhEncode()
    //
    // Step 1: derivation_to_scalar (compute sharedSec from derivation + output_index)
    //   sharedSec = Hs(derivation || varint(output_index))  [WITH sc_reduce32]
    //
    // Step 2: genAmountEncodingFactor (compute XOR mask with "amount" domain separator)
    //   encoding_factor = Keccak256("amount" || sharedSec)  [NO reduction - raw hash]
    //
    // Step 3: XOR first 8 bytes
    //   encrypted_amount = amount XOR encoding_factor[0..8]

    // Step 1: derivation_to_scalar = Hs(derivation || varint(output_index))
    let mut derivation_input = derivation_bytes.to_vec();
    // Encode output_index as varint
    let mut idx = output_index;
    while idx >= 0x80 {
        derivation_input.push((idx as u8 & 0x7f) | 0x80);
        idx >>= 7;
    }
    derivation_input.push(idx as u8);

    let shared_sec_hash: [u8; 32] = Keccak256::digest(&derivation_input).into();
    let shared_sec = Scalar::from_bytes_mod_order(shared_sec_hash);  // sc_reduce32
    let shared_sec_bytes = shared_sec.to_bytes();

    // Step 2: genAmountEncodingFactor = Keccak256("amount" || sharedSec)
    // Domain separator: "amount" (6 bytes, NO null terminator)
    let mut amount_hasher = Keccak256::new();
    amount_hasher.update(b"amount");  // 6-byte domain separator
    amount_hasher.update(&shared_sec_bytes);
    let encoding_factor: [u8; 32] = amount_hasher.finalize().into();  // NO reduction!

    // Step 3: XOR amount with first 8 bytes of encoding_factor
    let amount_bytes = amount.to_le_bytes();
    let mut encrypted = [0u8; 8];
    for i in 0..8 {
        encrypted[i] = amount_bytes[i] ^ encoding_factor[i];
    }

    Ok(encrypted)
}

/// Helper to encode varint to a Vec
fn encode_varint_to_vec(out: &mut Vec<u8>, value: u64) {
    let mut v = value;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Derive the output mask for commitment from shared secret
///
/// mask = Hs("commitment_mask" || Hs(derivation || output_index))
///
/// This is needed when we want to generate a fresh commitment instead of
/// deriving from pseudo_out.
pub fn derive_output_mask(
    tx_secret_key: &[u8; 32],
    recipient_view_pub: &[u8; 32],
    output_index: u64,
) -> Result<[u8; 32], TransactionBuildError> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    // Parse tx_secret_key as scalar
    let r = Scalar::from_bytes_mod_order(*tx_secret_key);

    // Parse recipient view pubkey as point
    let view_pub_point = CompressedEdwardsY(*recipient_view_pub)
        .decompress()
        .ok_or_else(|| TransactionBuildError::InvalidPoint("Invalid recipient view key".into()))?;

    // Compute shared secret with cofactor: 8 * r * V
    let shared_secret = (r * view_pub_point).mul_by_cofactor();
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    // Compute Hs(derivation || varint(output_index))
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret_bytes);
    let mut varint_buf = Vec::new();
    encode_varint_to_vec(&mut varint_buf, output_index);
    hasher.update(&varint_buf);
    let derivation_hash: [u8; 32] = hasher.finalize().into();

    // Reduce to scalar
    let derivation_scalar = Scalar::from_bytes_mod_order(derivation_hash);

    // Compute mask = Hs("commitment_mask" || derivation_scalar)
    // Reference: rctOps.cpp genCommitmentMask() uses memcpy(..., 15) = 15 bytes NO null
    let mut mask_hasher = Keccak256::new();
    mask_hasher.update(b"commitment_mask");  // 15 bytes, NO null terminator
    mask_hasher.update(derivation_scalar.as_bytes());
    let mask_bytes: [u8; 32] = mask_hasher.finalize().into();

    // Reduce to scalar (mod curve order)
    let mask_scalar = Scalar::from_bytes_mod_order(mask_bytes);

    Ok(mask_scalar.to_bytes())
}

// ============================================================================
// FROST SHARE POLYNOMIAL VALIDATION
// ============================================================================

/// Result of FROST share validation
#[derive(Debug)]
pub struct FrostShareValidation {
    /// Whether shares satisfy polynomial constraint
    pub valid: bool,
    /// Explanation of result
    pub message: String,
    /// Computed buyer share from polynomial (for debugging)
    pub expected_buyer: Option<String>,
    /// Actual buyer share (for debugging)
    pub actual_buyer: Option<String>,
}

/// Validate that FROST shares satisfy polynomial constraint
///
/// For valid 2-of-3 Shamir shares from the same polynomial f(x) = s + ax:
/// - share_1 = f(1) = s + a
/// - share_2 = f(2) = s + 2a
/// - share_3 = f(3) = s + 3a
///
/// This implies: share_1 = 2*share_2 - share_3 (mod L)
///
/// If this constraint is NOT satisfied, the shares are from different polynomials
/// and cannot be used together for threshold signing.
pub fn validate_frost_shares(
    buyer_share_hex: &str,
    vendor_share_hex: &str,
    arbiter_share_hex: &str,
) -> FrostShareValidation {
    use curve25519_dalek::scalar::Scalar;

    // Parse shares
    let buyer_bytes = match hex::decode(buyer_share_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return FrostShareValidation {
            valid: false,
            message: "Invalid buyer share hex (must be 64 hex chars / 32 bytes)".to_string(),
            expected_buyer: None,
            actual_buyer: Some(buyer_share_hex.to_string()),
        },
    };

    let vendor_bytes = match hex::decode(vendor_share_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return FrostShareValidation {
            valid: false,
            message: "Invalid vendor share hex (must be 64 hex chars / 32 bytes)".to_string(),
            expected_buyer: None,
            actual_buyer: None,
        },
    };

    let arbiter_bytes = match hex::decode(arbiter_share_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return FrostShareValidation {
            valid: false,
            message: "Invalid arbiter share hex (must be 64 hex chars / 32 bytes)".to_string(),
            expected_buyer: None,
            actual_buyer: None,
        },
    };

    // Convert to scalars
    let buyer = Scalar::from_bytes_mod_order(buyer_bytes);
    let vendor = Scalar::from_bytes_mod_order(vendor_bytes);
    let arbiter = Scalar::from_bytes_mod_order(arbiter_bytes);

    // Check polynomial constraint: buyer = 2*vendor - arbiter (mod L)
    let two = Scalar::from(2u64);
    let expected_buyer = two * vendor - arbiter;

    let expected_hex = hex::encode(expected_buyer.to_bytes());
    let actual_hex = hex::encode(buyer.to_bytes());

    if buyer == expected_buyer {
        FrostShareValidation {
            valid: true,
            message: "FROST shares satisfy polynomial constraint: buyer = 2*vendor - arbiter".to_string(),
            expected_buyer: Some(expected_hex),
            actual_buyer: Some(actual_hex),
        }
    } else {
        FrostShareValidation {
            valid: false,
            message: format!(
                "FROST shares do NOT satisfy polynomial constraint!\n\
                 Expected buyer = 2*vendor - arbiter = {}\n\
                 Actual buyer                       = {}\n\
                 \n\
                 This means the shares are NOT from the same FROST DKG.\n\
                 Possible causes:\n\
                 1. DKG didn't complete properly for all 3 participants\n\
                 2. Shares got mixed up from different DKG runs\n\
                 3. localStorage returned wrong keys (personal wallet vs FROST share)\n\
                 \n\
                 Resolution: All 3 parties must re-run DKG together.",
                expected_hex,
                actual_hex
            ),
            expected_buyer: Some(expected_hex),
            actual_buyer: Some(actual_hex),
        }
    }
}

/// Validate that two shares can reconstruct the group pubkey
///
/// This is a weaker check than validate_frost_shares but useful when we only have 2 shares.
/// It verifies: (lambda_1 * share_1 + lambda_2 * share_2) * G = group_pubkey
pub fn validate_frost_pair(
    share1_hex: &str,
    share2_hex: &str,
    index1: u16,
    index2: u16,
    group_pubkey_hex: &str,
) -> Result<bool, String> {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;

    // Parse shares
    let share1_bytes: [u8; 32] = hex::decode(share1_hex)
        .map_err(|e| format!("Invalid share1 hex: {}", e))?
        .try_into()
        .map_err(|_| "share1 must be 32 bytes")?;

    let share2_bytes: [u8; 32] = hex::decode(share2_hex)
        .map_err(|e| format!("Invalid share2 hex: {}", e))?
        .try_into()
        .map_err(|_| "share2 must be 32 bytes")?;

    let group_pubkey_bytes: [u8; 32] = hex::decode(group_pubkey_hex)
        .map_err(|e| format!("Invalid group_pubkey hex: {}", e))?
        .try_into()
        .map_err(|_| "group_pubkey must be 32 bytes")?;

    let share1 = Scalar::from_bytes_mod_order(share1_bytes);
    let share2 = Scalar::from_bytes_mod_order(share2_bytes);
    let group_pubkey = CompressedEdwardsY(group_pubkey_bytes)
        .decompress()
        .ok_or("Invalid group pubkey point")?;

    // Compute Lagrange coefficients
    // lambda_i = j / (j - i) for signers at indices i and j
    let i = index1 as i64;
    let j = index2 as i64;

    // lambda_1 = j / (j - i)
    let num1 = Scalar::from(j as u64);
    let denom1 = if j > i {
        Scalar::from((j - i) as u64)
    } else {
        -Scalar::from((i - j) as u64)
    };
    let lambda1 = num1 * denom1.invert();

    // lambda_2 = i / (i - j)
    let num2 = Scalar::from(i as u64);
    let denom2 = if i > j {
        Scalar::from((i - j) as u64)
    } else {
        -Scalar::from((j - i) as u64)
    };
    let lambda2 = num2 * denom2.invert();

    // Reconstruct: (lambda_1 * share_1 + lambda_2 * share_2) * G
    let reconstructed = &(lambda1 * share1 + lambda2 * share2) * ED25519_BASEPOINT_TABLE;

    Ok(reconstructed == group_pubkey)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        let builder = MoneroTransactionBuilder::new();

        let mut buf = Vec::new();
        builder.write_varint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        builder.write_varint(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);

        buf.clear();
        builder.write_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        builder.write_varint(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_indices_to_offsets() {
        let builder = MoneroTransactionBuilder::new();

        let indices = vec![10, 20, 25, 100];
        let offsets = builder.indices_to_offsets(&indices);

        // First is absolute, rest are relative
        assert_eq!(offsets, vec![10, 10, 5, 75]);
    }

    #[test]
    fn test_builder_creation() {
        let builder = MoneroTransactionBuilder::new();
        assert_eq!(builder.version, 2);
        assert_eq!(builder.unlock_time, 0);
        assert!(builder.inputs.is_empty());
        assert!(builder.outputs.is_empty());
    }

    #[test]
    fn test_parse_stagenet_address() {
        // Real stagenet multisig address from escrow 5a49a064-51c2-47bf-bbed-b962f95fed5a
        let stagenet_addr = "54FYy396FN5SXMhYsCgY49JzH2FyPM9ei14guJpsTCY8jGXbfDKsTNfdeAWJ5ThRLr9ye95tb5yWWUAzcS5vdJdkEaqYhKj";

        let result = parse_monero_address(stagenet_addr);

        match &result {
            Ok((spend_pub, view_pub)) => {
                println!("SUCCESS: Parsed stagenet address");
                println!("Spend pub: {}", hex::encode(spend_pub));
                println!("View pub: {}", hex::encode(view_pub));
                assert_eq!(spend_pub.len(), 32);
                assert_eq!(view_pub.len(), 32);
            }
            Err(e) => {
                println!("ERROR: Failed to parse: {}", e);
            }
        }

        assert!(result.is_ok(), "Failed to parse stagenet address: {:?}", result);
    }
}
