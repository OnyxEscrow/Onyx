//! Pre-computed Test Fixtures for Offline E2E Testing
//!
//! Contains deterministic test vectors for:
//! - CLSAG signatures (valid and invalid variants)
//! - Ring data (16 members, standard ring size)
//! - Partial key images for aggregation
//! - Valid/invalid Monero addresses
//! - Transaction blobs for structure validation

use super::DeterministicRng;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

/// Standard ring size for Monero v6 (Bulletproofs+)
pub const RING_SIZE: usize = 16;

/// Atomic units per XMR
pub const XMR_TO_ATOMIC: u64 = 1_000_000_000_000;

// ============================================================================
// ESCROW FIXTURE
// ============================================================================

/// Complete escrow test fixture with all cryptographic data
#[derive(Clone, Debug)]
pub struct EscrowFixture {
    pub escrow_id: String,
    pub buyer_id: String,
    pub vendor_id: String,
    pub arbiter_id: String,
    pub amount_atomic: i64,
    pub multisig_address: String,
    pub funding_tx_hash: String,
    pub funding_output_index: u32,
    pub funding_global_index: u64,
    pub ring_fixture: RingFixture,
    pub key_image_fixture: KeyImageFixture,
}

impl EscrowFixture {
    /// Generate a deterministic escrow fixture
    pub fn generate(rng: &mut DeterministicRng) -> Self {
        let escrow_id = format!("escrow_{}", hex::encode(&rng.gen_32_bytes()[..8]));
        let buyer_id = format!("buyer_{}", hex::encode(&rng.gen_32_bytes()[..8]));
        let vendor_id = format!("vendor_{}", hex::encode(&rng.gen_32_bytes()[..8]));
        let arbiter_id = format!("arbiter_{}", hex::encode(&rng.gen_32_bytes()[..8]));

        let ring_fixture = RingFixture::generate(rng);
        let key_image_fixture = KeyImageFixture::generate(rng);

        Self {
            escrow_id,
            buyer_id,
            vendor_id,
            arbiter_id,
            amount_atomic: (rng.gen_range(100) as i64 + 1) * XMR_TO_ATOMIC as i64 / 100, // 0.01-1.00 XMR
            multisig_address: generate_testnet_address(rng),
            funding_tx_hash: rng.gen_hex(32),
            funding_output_index: (rng.gen_range(4) as u32),
            funding_global_index: rng.gen_range(1_000_000) + 100_000,
            ring_fixture,
            key_image_fixture,
        }
    }
}

// ============================================================================
// RING DATA FIXTURE
// ============================================================================

/// Ring data for CLSAG signing
#[derive(Clone, Debug)]
pub struct RingFixture {
    /// 16 ring member public keys (compressed, hex)
    pub ring_public_keys: Vec<String>,
    /// 16 ring member commitments (compressed, hex)
    pub ring_commitments: Vec<String>,
    /// Global indices for ring members
    pub ring_indices: Vec<u64>,
    /// Position of real output in ring (0-15)
    pub signer_index: usize,
    /// Real output's commitment mask (blinding factor)
    pub real_commitment_mask: [u8; 32],
    /// Amount for the real output
    pub real_amount: u64,
}

impl RingFixture {
    /// Generate deterministic ring data
    pub fn generate(rng: &mut DeterministicRng) -> Self {
        let signer_index = (rng.gen_range(RING_SIZE as u64)) as usize;

        let mut ring_public_keys = Vec::with_capacity(RING_SIZE);
        let mut ring_commitments = Vec::with_capacity(RING_SIZE);
        let mut ring_indices = Vec::with_capacity(RING_SIZE);

        let base_index = rng.gen_range(1_000_000) + 100_000;

        for i in 0..RING_SIZE {
            let pk = rng.gen_point();
            ring_public_keys.push(hex::encode(pk.compress().to_bytes()));

            let commitment = rng.gen_point();
            ring_commitments.push(hex::encode(commitment.compress().to_bytes()));

            ring_indices.push(base_index + (i as u64) * (rng.gen_range(100) + 1));
        }

        // Sort indices and reorder arrays accordingly
        let mut indexed: Vec<(u64, String, String)> = ring_indices
            .iter()
            .zip(ring_public_keys.iter())
            .zip(ring_commitments.iter())
            .map(|((idx, pk), com)| (*idx, pk.clone(), com.clone()))
            .collect();
        indexed.sort_by_key(|(idx, _, _)| *idx);

        ring_indices = indexed.iter().map(|(idx, _, _)| *idx).collect();
        ring_public_keys = indexed.iter().map(|(_, pk, _)| pk.clone()).collect();
        ring_commitments = indexed.iter().map(|(_, _, com)| com.clone()).collect();

        Self {
            ring_public_keys,
            ring_commitments,
            ring_indices,
            signer_index,
            real_commitment_mask: rng.gen_32_bytes(),
            real_amount: (rng.gen_range(100) + 1) * XMR_TO_ATOMIC / 100,
        }
    }

    /// Generate ring fixture with specific invalid properties
    pub fn generate_invalid(rng: &mut DeterministicRng, invalid_type: RingInvalidType) -> Self {
        let mut fixture = Self::generate(rng);

        match invalid_type {
            RingInvalidType::MismatchedLengths => {
                // Remove one commitment to cause length mismatch
                fixture.ring_commitments.pop();
            }
            RingInvalidType::InvalidPublicKey => {
                // Replace first public key with invalid point
                fixture.ring_public_keys[0] = "ff".repeat(32);
            }
            RingInvalidType::InvalidCommitment => {
                // Replace first commitment with invalid point
                fixture.ring_commitments[0] = "ff".repeat(32);
            }
            RingInvalidType::WrongRingSize => {
                // Make ring size 11 instead of 16
                fixture.ring_public_keys.truncate(11);
                fixture.ring_commitments.truncate(11);
                fixture.ring_indices.truncate(11);
            }
            RingInvalidType::UnsortedIndices => {
                // Shuffle indices out of order
                fixture.ring_indices.swap(0, 8);
                fixture.ring_indices.swap(3, 12);
            }
        }

        fixture
    }
}

/// Types of invalid ring data for testing validation
#[derive(Clone, Copy, Debug)]
pub enum RingInvalidType {
    MismatchedLengths,
    InvalidPublicKey,
    InvalidCommitment,
    WrongRingSize,
    UnsortedIndices,
}

// ============================================================================
// KEY IMAGE FIXTURE
// ============================================================================

/// Key image data for multisig aggregation tests
#[derive(Clone, Debug)]
pub struct KeyImageFixture {
    /// Buyer's partial key image (hex)
    pub buyer_pki: String,
    /// Vendor's partial key image (hex)
    pub vendor_pki: String,
    /// Arbiter's partial key image (hex)
    pub arbiter_pki: String,
    /// Expected aggregated key image using simple sum
    pub expected_simple_sum: String,
    /// Expected aggregated key image using Lagrange (buyer+vendor)
    pub expected_lagrange_buyer_vendor: String,
    /// The underlying scalars (for verification)
    pub buyer_scalar: Scalar,
    pub vendor_scalar: Scalar,
    pub arbiter_scalar: Scalar,
    /// Base point Hp(P) used for key image computation
    pub hp_p: EdwardsPoint,
}

impl KeyImageFixture {
    /// Generate deterministic key image fixture
    pub fn generate(rng: &mut DeterministicRng) -> Self {
        // Generate spend key shares
        let buyer_scalar = rng.gen_scalar();
        let vendor_scalar = rng.gen_scalar();
        let arbiter_scalar = rng.gen_scalar();

        // Generate base point Hp(P) deterministically
        // In real code this is hash_to_point(pubkey), but for testing we use a deterministic point
        let hp_p = rng.gen_point();

        // Compute partial key images: pKI = scalar * Hp(P)
        let buyer_pki_point = buyer_scalar * hp_p;
        let vendor_pki_point = vendor_scalar * hp_p;
        let arbiter_pki_point = arbiter_scalar * hp_p;

        // Simple sum: KI = pKI_buyer + pKI_vendor
        let simple_sum = buyer_pki_point + vendor_pki_point;

        // Lagrange for buyer+vendor (indices 1,2):
        // λ_buyer = 2 / (2-1) = 2
        // λ_vendor = 1 / (1-2) = -1
        let lambda_buyer = Scalar::from(2u64);
        let lambda_vendor = -Scalar::ONE;
        let lagrange_sum = (lambda_buyer * buyer_pki_point) + (lambda_vendor * vendor_pki_point);

        Self {
            buyer_pki: hex::encode(buyer_pki_point.compress().to_bytes()),
            vendor_pki: hex::encode(vendor_pki_point.compress().to_bytes()),
            arbiter_pki: hex::encode(arbiter_pki_point.compress().to_bytes()),
            expected_simple_sum: hex::encode(simple_sum.compress().to_bytes()),
            expected_lagrange_buyer_vendor: hex::encode(lagrange_sum.compress().to_bytes()),
            buyer_scalar,
            vendor_scalar,
            arbiter_scalar,
            hp_p,
        }
    }

    /// Generate key image with specific invalid properties
    pub fn generate_invalid(rng: &mut DeterministicRng, invalid_type: KeyImageInvalidType) -> Self {
        let mut fixture = Self::generate(rng);

        match invalid_type {
            KeyImageInvalidType::InvalidBuyerPki => {
                fixture.buyer_pki = "ff".repeat(32);
            }
            KeyImageInvalidType::InvalidVendorPki => {
                fixture.vendor_pki = "ff".repeat(32);
            }
            KeyImageInvalidType::WrongLength => {
                fixture.buyer_pki = "abcd".to_string(); // Only 2 bytes
            }
            KeyImageInvalidType::ZeroPoint => {
                // Identity point (0, 1) compressed
                fixture.buyer_pki =
                    "0100000000000000000000000000000000000000000000000000000000000000".to_string();
            }
        }

        fixture
    }
}

/// Types of invalid key images for testing validation
#[derive(Clone, Copy, Debug)]
pub enum KeyImageInvalidType {
    InvalidBuyerPki,
    InvalidVendorPki,
    WrongLength,
    ZeroPoint,
}

// ============================================================================
// CLSAG FIXTURE
// ============================================================================

/// CLSAG signature fixture for verification tests
#[derive(Clone, Debug)]
pub struct ClsagFixture {
    /// s values (ring_size * 32 bytes hex)
    pub s_values: Vec<String>,
    /// c1 scalar (hex)
    pub c1: String,
    /// D point (hex) - D_inv8, stores D/8
    pub d_inv8: String,
    /// Key image (hex)
    pub key_image: String,
    /// Pseudo output commitment (hex)
    pub pseudo_out: String,
    /// Ring public keys (hex)
    pub ring_keys: Vec<String>,
    /// Ring commitments (hex)
    pub ring_commitments: Vec<String>,
    /// TX prefix hash (32 bytes hex)
    pub tx_prefix_hash: String,
    /// Whether this fixture is valid (should verify)
    pub should_verify: bool,
    /// Description of why it's valid/invalid
    pub description: String,
}

impl ClsagFixture {
    /// Generate a valid CLSAG fixture
    ///
    /// Note: This generates structurally valid data for parsing tests,
    /// but not cryptographically valid signatures (those require proper CLSAG generation)
    pub fn generate_structural(rng: &mut DeterministicRng) -> Self {
        let mut s_values = Vec::with_capacity(RING_SIZE);
        let mut ring_keys = Vec::with_capacity(RING_SIZE);
        let mut ring_commitments = Vec::with_capacity(RING_SIZE);

        for _ in 0..RING_SIZE {
            s_values.push(rng.gen_hex(32));
            ring_keys.push(hex::encode(rng.gen_point().compress().to_bytes()));
            ring_commitments.push(hex::encode(rng.gen_point().compress().to_bytes()));
        }

        Self {
            s_values,
            c1: rng.gen_hex(32),
            d_inv8: hex::encode(rng.gen_point().compress().to_bytes()),
            key_image: hex::encode(rng.gen_point().compress().to_bytes()),
            pseudo_out: hex::encode(rng.gen_point().compress().to_bytes()),
            ring_keys,
            ring_commitments,
            tx_prefix_hash: rng.gen_hex(32),
            should_verify: false, // Structural data won't verify cryptographically
            description: "Structurally valid CLSAG data (for parsing tests only)".to_string(),
        }
    }

    /// Generate CLSAG with specific invalid properties
    pub fn generate_invalid(rng: &mut DeterministicRng, invalid_type: ClsagInvalidType) -> Self {
        let mut fixture = Self::generate_structural(rng);

        match invalid_type {
            ClsagInvalidType::InvalidKeyImage => {
                fixture.key_image = "ff".repeat(32);
                fixture.description = "Invalid key image (not on curve)".to_string();
            }
            ClsagInvalidType::InvalidD => {
                fixture.d_inv8 = "ff".repeat(32);
                fixture.description = "Invalid D point (not on curve)".to_string();
            }
            ClsagInvalidType::InvalidPseudoOut => {
                fixture.pseudo_out = "ff".repeat(32);
                fixture.description = "Invalid pseudo_out (not on curve)".to_string();
            }
            ClsagInvalidType::WrongRingSize => {
                fixture.s_values.pop();
                fixture.description = "Wrong ring size (15 instead of 16)".to_string();
            }
            ClsagInvalidType::MismatchedRingData => {
                fixture.ring_keys.pop();
                fixture.description =
                    "Mismatched ring data (15 keys vs 16 commitments)".to_string();
            }
            ClsagInvalidType::CorruptedC1 => {
                fixture.c1 = "00".repeat(32);
                fixture.description = "Corrupted c1 (all zeros)".to_string();
            }
        }

        fixture.should_verify = false;
        fixture
    }
}

/// Types of invalid CLSAG signatures for testing
#[derive(Clone, Copy, Debug)]
pub enum ClsagInvalidType {
    InvalidKeyImage,
    InvalidD,
    InvalidPseudoOut,
    WrongRingSize,
    MismatchedRingData,
    CorruptedC1,
}

// ============================================================================
// TRANSACTION FIXTURE
// ============================================================================

/// Transaction structure fixture for validation tests
#[derive(Clone, Debug)]
pub struct TransactionFixture {
    /// Transaction version (should be 2)
    pub version: u64,
    /// Unlock time (should be 0)
    pub unlock_time: u64,
    /// Number of inputs
    pub num_inputs: usize,
    /// Number of outputs
    pub num_outputs: usize,
    /// Output types (0x03 = txout_to_tagged_key for HF15+)
    pub output_types: Vec<u8>,
    /// Extra field length
    pub extra_length: usize,
    /// RCT type (6 = BulletproofPlus)
    pub rct_type: u8,
    /// Fee in atomic units
    pub fee: u64,
    /// Whether this fixture should pass validation
    pub should_be_valid: bool,
    /// Description
    pub description: String,
}

impl TransactionFixture {
    /// Generate a valid transaction structure fixture
    pub fn generate_valid(rng: &mut DeterministicRng) -> Self {
        Self {
            version: 2,
            unlock_time: 0,
            num_inputs: 1,
            num_outputs: 2,                 // Minimum 2 outputs required
            output_types: vec![0x03, 0x03], // txout_to_tagged_key
            extra_length: 34 + (rng.gen_range(10) as usize), // ~34-44 bytes
            rct_type: 6,                    // BulletproofPlus
            fee: 30000000,                  // ~0.00003 XMR typical fee
            should_be_valid: true,
            description: "Valid RCT v6 transaction".to_string(),
        }
    }

    /// Generate transaction fixture with specific invalid properties
    pub fn generate_invalid(rng: &mut DeterministicRng, invalid_type: TxInvalidType) -> Self {
        let mut fixture = Self::generate_valid(rng);

        match invalid_type {
            TxInvalidType::WrongVersion => {
                fixture.version = 1;
                fixture.description = "Wrong version (1 instead of 2)".to_string();
            }
            TxInvalidType::NonZeroUnlockTime => {
                fixture.unlock_time = 1000;
                fixture.description = "Non-zero unlock_time".to_string();
            }
            TxInvalidType::ZeroInputs => {
                fixture.num_inputs = 0;
                fixture.description = "Zero inputs".to_string();
            }
            TxInvalidType::ZeroOutputs => {
                fixture.num_outputs = 0;
                fixture.output_types.clear();
                fixture.description = "Zero outputs".to_string();
            }
            TxInvalidType::SingleOutput => {
                fixture.num_outputs = 1;
                fixture.output_types = vec![0x03];
                fixture.description = "Single output (minimum 2 required)".to_string();
            }
            TxInvalidType::WrongOutputType => {
                fixture.output_types = vec![0x02, 0x02]; // txout_to_key (old)
                fixture.description = "Wrong output type (0x02 instead of 0x03)".to_string();
            }
            TxInvalidType::OldRctType => {
                fixture.rct_type = 5; // CLSAG without BP+
                fixture.description = "Old RCT type (5 instead of 6)".to_string();
            }
            TxInvalidType::ExtraTooBig => {
                fixture.extra_length = 2000;
                fixture.description = "Extra field too large".to_string();
            }
        }

        fixture.should_be_valid = false;
        fixture
    }
}

/// Types of invalid transactions for testing
#[derive(Clone, Copy, Debug)]
pub enum TxInvalidType {
    WrongVersion,
    NonZeroUnlockTime,
    ZeroInputs,
    ZeroOutputs,
    SingleOutput,
    WrongOutputType,
    OldRctType,
    ExtraTooBig,
}

// ============================================================================
// ADDRESS FIXTURE
// ============================================================================

/// Monero address fixture
#[derive(Clone, Debug)]
pub struct AddressFixture {
    pub address: String,
    pub network: Network,
    pub is_valid: bool,
    pub description: String,
}

#[derive(Clone, Copy, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

impl AddressFixture {
    /// Generate valid testnet addresses
    pub fn valid_testnet() -> Vec<Self> {
        vec![
            Self {
                // Standard testnet address (95 chars, starts with '9')
                address: "9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5NWUyVF7iQhcDLmBWvKFgQFr7K3hfExGqSLKZRf6hfYh7VqR3jQj3h2UhJBtF".to_string(),
                network: Network::Testnet,
                is_valid: true,
                description: "Valid testnet standard address".to_string(),
            },
        ]
    }

    /// Generate invalid addresses
    pub fn invalid() -> Vec<Self> {
        vec![
            Self {
                address: "invalid".to_string(),
                network: Network::Testnet,
                is_valid: false,
                description: "Too short".to_string(),
            },
            Self {
                address: "0".repeat(95),
                network: Network::Testnet,
                is_valid: false,
                description: "Invalid base58 characters".to_string(),
            },
            Self {
                address: "9".repeat(200),
                network: Network::Testnet,
                is_valid: false,
                description: "Too long".to_string(),
            },
        ]
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Generate a deterministic testnet address (structurally valid)
fn generate_testnet_address(rng: &mut DeterministicRng) -> String {
    // Testnet addresses start with '9' or 'A'
    // Generate 94 valid base58 characters after the '9' prefix
    // Valid base58: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    const BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut chars = String::with_capacity(95);
    chars.push('9'); // Testnet prefix

    // Generate 94 random base58 characters
    for _ in 0..94 {
        let byte = rng.gen_32_bytes()[0];
        let idx = (byte as usize) % BASE58_CHARS.len();
        chars.push(BASE58_CHARS[idx] as char);
    }

    chars
}

/// Convert scalar bytes to hex string
pub fn scalar_to_hex(scalar: &Scalar) -> String {
    hex::encode(scalar.to_bytes())
}

/// Convert point to compressed hex string
pub fn point_to_hex(point: &EdwardsPoint) -> String {
    hex::encode(point.compress().to_bytes())
}

/// Parse hex string to compressed Edwards point
pub fn hex_to_point(hex_str: &str) -> Option<EdwardsPoint> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr).decompress()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escrow_fixture_generation() {
        let mut rng = DeterministicRng::new();
        let fixture = EscrowFixture::generate(&mut rng);

        assert!(!fixture.escrow_id.is_empty());
        assert!(fixture.amount_atomic > 0);
        assert_eq!(fixture.ring_fixture.ring_public_keys.len(), RING_SIZE);
    }

    #[test]
    fn test_ring_fixture_sorted_indices() {
        let mut rng = DeterministicRng::new();
        let fixture = RingFixture::generate(&mut rng);

        // Verify indices are sorted
        for i in 1..fixture.ring_indices.len() {
            assert!(
                fixture.ring_indices[i] > fixture.ring_indices[i - 1],
                "Indices should be sorted in ascending order"
            );
        }
    }

    #[test]
    fn test_key_image_fixture_math() {
        let mut rng = DeterministicRng::new();
        let fixture = KeyImageFixture::generate(&mut rng);

        // Verify simple sum
        let buyer_pki = hex_to_point(&fixture.buyer_pki).unwrap();
        let vendor_pki = hex_to_point(&fixture.vendor_pki).unwrap();
        let simple_sum = buyer_pki + vendor_pki;
        assert_eq!(
            point_to_hex(&simple_sum),
            fixture.expected_simple_sum,
            "Simple sum should match"
        );

        // Verify Lagrange sum
        let lambda_buyer = Scalar::from(2u64);
        let lambda_vendor = -Scalar::ONE;
        let lagrange_sum = (lambda_buyer * buyer_pki) + (lambda_vendor * vendor_pki);
        assert_eq!(
            point_to_hex(&lagrange_sum),
            fixture.expected_lagrange_buyer_vendor,
            "Lagrange sum should match"
        );
    }

    #[test]
    fn test_deterministic_fixtures() {
        let mut rng1 = DeterministicRng::new();
        let mut rng2 = DeterministicRng::new();

        let fixture1 = EscrowFixture::generate(&mut rng1);
        let fixture2 = EscrowFixture::generate(&mut rng2);

        // Same RNG seed → same fixtures
        assert_eq!(fixture1.escrow_id, fixture2.escrow_id);
        assert_eq!(fixture1.amount_atomic, fixture2.amount_atomic);
    }
}
