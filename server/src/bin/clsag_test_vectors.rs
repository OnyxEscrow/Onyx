//! CLSAG 2-of-3 Multisig Test Vector Generator
//!
//! Generates deterministic test vectors for validating the complete CLSAG signing flow.
//! All values are computed from fixed seeds to ensure reproducibility.
//!
//! IMPORTANT: Uses the EXACT SAME hash_to_point as Monero (monero-generators crate)
//!
//! Usage: cargo run --release --bin clsag_test_vectors

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar,
};
use hex;
use monero_generators::hash_to_point as monero_hash_to_point;
use sha3::{Digest, Keccak256};

/// Monero's hash-to-point (Hp) function - uses the REAL Monero implementation
fn hash_to_point(data: &[u8]) -> EdwardsPoint {
    // Use the official Monero hash_to_point from monero-generators
    // This uses ge_fromfe_frombytes_vartime (Elligator-like field-to-curve mapping)
    //
    // For inputs shorter than 32 bytes, we first hash with Keccak256 to get 32 bytes
    let arr: [u8; 32] = if data.len() >= 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(&data[..32]);
        a
    } else {
        // Hash short inputs to get 32 bytes
        let hash = Keccak256::digest(data);
        let mut a = [0u8; 32];
        a.copy_from_slice(&hash);
        a
    };
    monero_hash_to_point(arr)
}

/// Monero's hash-to-scalar (Hn) function
fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = Keccak256::digest(data);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order(bytes)
}

/// Compute Lagrange coefficient for index i given set of indices
/// λ_i = Π_{j≠i} (j / (j - i))
fn lagrange_coefficient(i: u32, indices: &[u32]) -> Scalar {
    let mut result = Scalar::ONE;
    let i_scalar = Scalar::from(i);

    for &j in indices {
        if j != i {
            let j_scalar = Scalar::from(j);
            // λ_i *= j / (j - i)
            let numerator = j_scalar;
            let denominator = j_scalar - i_scalar;
            result *= numerator * denominator.invert();
        }
    }
    result
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         CLSAG 2-of-3 MULTISIG TEST VECTORS                       ║");
    println!("║         Deterministic values for flow validation                 ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 1: INPUT VALUES (Fixed Seeds)
    // ═══════════════════════════════════════════════════════════════════════════

    println!("══════════════════════════════════════════════════════════════════");
    println!("PHASE 1: INPUT VALUES");
    println!("══════════════════════════════════════════════════════════════════\n");

    // Private keys (spend keys) - using simple deterministic values
    let x1_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x00, // Last byte 0 to ensure < L
    ];
    let x2_bytes: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x00,
    ];

    let x1 = Scalar::from_bytes_mod_order(x1_bytes);
    let x2 = Scalar::from_bytes_mod_order(x2_bytes);

    println!("x1 (buyer private key):  {}", hex::encode(x1.as_bytes()));
    println!("x2 (vendor private key): {}", hex::encode(x2.as_bytes()));

    // Nonces (alpha) - deterministic
    let alpha1_bytes: [u8; 32] = [
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0x0a,
    ];
    let alpha2_bytes: [u8; 32] = [
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0x0b,
    ];

    let alpha1 = Scalar::from_bytes_mod_order(alpha1_bytes);
    let alpha2 = Scalar::from_bytes_mod_order(alpha2_bytes);

    println!(
        "α1 (buyer nonce):        {}",
        hex::encode(alpha1.as_bytes())
    );
    println!(
        "α2 (vendor nonce):       {}",
        hex::encode(alpha2.as_bytes())
    );

    // Masks
    let z_bytes: [u8; 32] = [
        // funding_mask (input commitment mask)
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x01,
    ];
    let pseudo_out_mask_bytes: [u8; 32] = [
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x02,
    ];

    let z = Scalar::from_bytes_mod_order(z_bytes);
    let pseudo_out_mask = Scalar::from_bytes_mod_order(pseudo_out_mask_bytes);
    let mask_delta = z - pseudo_out_mask;

    println!("z (funding_mask):        {}", hex::encode(z.as_bytes()));
    println!(
        "pseudo_out_mask:         {}",
        hex::encode(pseudo_out_mask.as_bytes())
    );
    println!(
        "mask_delta (z - pom):    {}",
        hex::encode(mask_delta.as_bytes())
    );

    // Ring configuration
    let ring_size: usize = 16;
    let real_index: usize = 7;
    println!("\nRing size: {}", ring_size);
    println!("Real index: {}", real_index);

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 2: LAGRANGE COEFFICIENTS
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 2: LAGRANGE COEFFICIENTS (2-of-3, indices {{1,2}})");
    println!("══════════════════════════════════════════════════════════════════\n");

    // For 2-of-3 with buyer=1, vendor=2 participating
    let indices = [1u32, 2u32];
    let lambda1 = lagrange_coefficient(1, &indices);
    let lambda2 = lagrange_coefficient(2, &indices);

    println!("λ1 (buyer):  {}", hex::encode(lambda1.as_bytes()));
    println!("λ2 (vendor): {}", hex::encode(lambda2.as_bytes()));

    // Verify: λ1 + λ2 should equal 1 for threshold scheme
    let lambda_sum = lambda1 + lambda2;
    println!(
        "λ1 + λ2:     {} (should be 01000...)",
        hex::encode(lambda_sum.as_bytes())
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 3: AGGREGATED VALUES
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 3: AGGREGATED VALUES");
    println!("══════════════════════════════════════════════════════════════════\n");

    // Aggregated private key: x_agg = λ1*x1 + λ2*x2
    let x_agg = lambda1 * x1 + lambda2 * x2;
    println!("x_agg = λ1*x1 + λ2*x2:   {}", hex::encode(x_agg.as_bytes()));

    // Public keys
    let p1 = x1 * G;
    let p2 = x2 * G;
    let p_agg = x_agg * G; // This should equal the ring member at real_index

    println!(
        "\nP1 = x1*G:               {}",
        hex::encode(p1.compress().as_bytes())
    );
    println!(
        "P2 = x2*G:               {}",
        hex::encode(p2.compress().as_bytes())
    );
    println!(
        "P_agg = x_agg*G:         {}",
        hex::encode(p_agg.compress().as_bytes())
    );

    // Verify P_agg = λ1*P1 + λ2*P2
    let p_agg_verify = lambda1 * p1 + lambda2 * p2;
    println!(
        "λ1*P1 + λ2*P2:           {}",
        hex::encode(p_agg_verify.compress().as_bytes())
    );
    println!("P_agg matches: {}", p_agg == p_agg_verify);

    // Aggregated nonce: α_agg = α1 + α2 (simple sum for MuSig2-style)
    let alpha_agg = alpha1 + alpha2;
    println!(
        "\nα_agg = α1 + α2:         {}",
        hex::encode(alpha_agg.as_bytes())
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 4: KEY IMAGE AND D
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 4: KEY IMAGE AND D");
    println!("══════════════════════════════════════════════════════════════════\n");

    // Hp(P) - hash of public key to point
    let hp_p = hash_to_point(p_agg.compress().as_bytes());
    println!(
        "Hp(P_agg):               {}",
        hex::encode(hp_p.compress().as_bytes())
    );

    // Key Image: I = x_agg * Hp(P)
    let key_image = x_agg * hp_p;
    println!(
        "I = x_agg * Hp(P):       {}",
        hex::encode(key_image.compress().as_bytes())
    );

    // Partial key images (for aggregation verification)
    let pki1 = x1 * hp_p;
    let pki2 = x2 * hp_p;
    println!(
        "\nPKI1 = x1 * Hp(P):       {}",
        hex::encode(pki1.compress().as_bytes())
    );
    println!(
        "PKI2 = x2 * Hp(P):       {}",
        hex::encode(pki2.compress().as_bytes())
    );

    // Verify: λ1*PKI1 + λ2*PKI2 = I
    let ki_verify = lambda1 * pki1 + lambda2 * pki2;
    println!(
        "λ1*PKI1 + λ2*PKI2:       {}",
        hex::encode(ki_verify.compress().as_bytes())
    );
    println!("Key image matches: {}", key_image == ki_verify);

    // D = mask_delta * Hp(P) - CRITICAL: must not be identity!
    let d = mask_delta * hp_p;
    println!(
        "\nD = mask_delta * Hp(P):  {}",
        hex::encode(d.compress().as_bytes())
    );

    // Check if D is identity (would be a bug!)
    let identity = EdwardsPoint::default();
    println!("D is identity: {} (MUST BE FALSE!)", d == identity);

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 5: GENERATE RING MEMBERS
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 5: RING MEMBERS");
    println!("══════════════════════════════════════════════════════════════════\n");

    // Generate deterministic ring members (except real_index which is P_agg)
    let mut ring: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        if i == real_index {
            ring.push(p_agg);
            println!(
                "ring[{}] (REAL): {}",
                i,
                hex::encode(p_agg.compress().as_bytes())
            );
        } else {
            // Generate decoy: hash(i) -> point
            let decoy_seed = format!("decoy_ring_member_{}", i);
            let decoy = hash_to_point(decoy_seed.as_bytes());
            ring.push(decoy);
            println!(
                "ring[{}] (decoy): {}",
                i,
                hex::encode(decoy.compress().as_bytes())
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 6: CLSAG ROUND 1 (L, R at real index)
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 6: CLSAG ROUND 1 (L, R at real index)");
    println!("══════════════════════════════════════════════════════════════════\n");

    // L[real] = α_agg * G
    let l_real = alpha_agg * G;
    println!(
        "L[{}] = α_agg * G:        {}",
        real_index,
        hex::encode(l_real.compress().as_bytes())
    );

    // R[real] = α_agg * Hp(P)
    let r_real = alpha_agg * hp_p;
    println!(
        "R[{}] = α_agg * Hp(P):    {}",
        real_index,
        hex::encode(r_real.compress().as_bytes())
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 7: COMPUTE mu_P AND mu_C
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 7: CLSAG MIXING COEFFICIENTS (mu_P, mu_C)");
    println!("══════════════════════════════════════════════════════════════════\n");

    // Build the hash inputs for mu_P and mu_C
    // mu_P = Hn("CLSAG_agg_0" || ring || I || D || pseudo_out)
    // mu_C = Hn("CLSAG_agg_1" || ring || I || D || pseudo_out)

    // For simplicity, we'll use a mock pseudo_out commitment
    let amount: u64 = 1_000_000_000_000; // 1 XMR in atomic units
    let h_point = hash_to_point(b"H"); // Simplified H generator
    let pseudo_out = pseudo_out_mask * G + Scalar::from(amount) * h_point;
    println!(
        "pseudo_out:              {}",
        hex::encode(pseudo_out.compress().as_bytes())
    );

    // Construct mu_P input
    let mut mu_p_input = Vec::new();
    mu_p_input.extend_from_slice(b"CLSAG_agg_0");
    for member in &ring {
        mu_p_input.extend_from_slice(member.compress().as_bytes());
    }
    mu_p_input.extend_from_slice(key_image.compress().as_bytes());
    mu_p_input.extend_from_slice(d.compress().as_bytes());
    mu_p_input.extend_from_slice(pseudo_out.compress().as_bytes());

    let mu_p = hash_to_scalar(&mu_p_input);
    println!("mu_P:                    {}", hex::encode(mu_p.as_bytes()));

    // Construct mu_C input
    let mut mu_c_input = Vec::new();
    mu_c_input.extend_from_slice(b"CLSAG_agg_1");
    for member in &ring {
        mu_c_input.extend_from_slice(member.compress().as_bytes());
    }
    mu_c_input.extend_from_slice(key_image.compress().as_bytes());
    mu_c_input.extend_from_slice(d.compress().as_bytes());
    mu_c_input.extend_from_slice(pseudo_out.compress().as_bytes());

    let mu_c = hash_to_scalar(&mu_c_input);
    println!("mu_C:                    {}", hex::encode(mu_c.as_bytes()));

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 8: COMPUTE CHALLENGE c[real+1]
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 8: CHALLENGE COMPUTATION");
    println!("══════════════════════════════════════════════════════════════════\n");

    // Mock message (tx prefix hash)
    let message = Keccak256::digest(b"test_transaction_prefix");
    println!("message (tx_prefix):     {}", hex::encode(&message));

    // c[real+1] = Hn(ring || message || L[real] || R[real])
    let mut c_input = Vec::new();
    for member in &ring {
        c_input.extend_from_slice(member.compress().as_bytes());
    }
    c_input.extend_from_slice(&message);
    c_input.extend_from_slice(l_real.compress().as_bytes());
    c_input.extend_from_slice(r_real.compress().as_bytes());

    let c_next = hash_to_scalar(&c_input);
    let next_index = (real_index + 1) % ring_size;
    println!(
        "c[{}]:                    {}",
        next_index,
        hex::encode(c_next.as_bytes())
    );

    // For this test, we'll use c_next as c[real] (simplified)
    // In real CLSAG, you'd propagate through the full ring
    let c_real = c_next;
    println!(
        "c[{}] (for signing):      {}",
        real_index,
        hex::encode(c_real.as_bytes())
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 9: WEIGHTED CHALLENGES (c_p, c_c)
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 9: WEIGHTED CHALLENGES");
    println!("══════════════════════════════════════════════════════════════════\n");

    let c_p = mu_p * c_real;
    let c_c = mu_c * c_real;

    println!("c_p = mu_P * c[real]:    {}", hex::encode(c_p.as_bytes()));
    println!("c_c = mu_C * c[real]:    {}", hex::encode(c_c.as_bytes()));

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 10: S-VALUE COMPUTATION (2-of-3 Multisig)
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 10: S-VALUE COMPUTATION (2-of-3 MULTISIG)");
    println!("══════════════════════════════════════════════════════════════════\n");

    // ═══════════════════════════════════════════════════════════════════════════
    // APPROACH A: WASM STYLE (both signers include λ-weighted mask_delta)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  APPROACH A: WASM STYLE (both include λ-weighted mask_delta)     ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // First signer: s1 = α1 - c_p*(λ1*x1) - c_c*(λ1*mask_delta)
    let effective_mask_delta_1 = lambda1 * mask_delta;
    let s1_wasm = alpha1 - c_p * (lambda1 * x1) - c_c * effective_mask_delta_1;
    println!("=== FIRST SIGNER (WASM style) ===");
    println!("s1 = α1 - c_p*(λ1*x1) - c_c*(λ1*mask_delta)");
    println!(
        "λ1*mask_delta:           {}",
        hex::encode(effective_mask_delta_1.as_bytes())
    );
    println!(
        "s1:                      {}",
        hex::encode(s1_wasm.as_bytes())
    );

    // Second signer: s2 = α2 - c_p*(λ2*x2) - c_c*(λ2*mask_delta)
    let effective_mask_delta_2 = lambda2 * mask_delta;
    let s2_wasm = alpha2 - c_p * (lambda2 * x2) - c_c * effective_mask_delta_2;
    println!("\n=== SECOND SIGNER (WASM style) ===");
    println!("s2 = α2 - c_p*(λ2*x2) - c_c*(λ2*mask_delta)");
    println!(
        "λ2*mask_delta:           {}",
        hex::encode(effective_mask_delta_2.as_bytes())
    );
    println!(
        "s2:                      {}",
        hex::encode(s2_wasm.as_bytes())
    );

    // Aggregated
    let s_agg_wasm = s1_wasm + s2_wasm;
    println!("\n=== AGGREGATED (WASM style) ===");
    println!("s = s1 + s2 = α_agg - c_p*x_agg - c_c*(λ1+λ2)*mask_delta");
    println!(
        "s_agg (WASM):            {}",
        hex::encode(s_agg_wasm.as_bytes())
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // APPROACH B: ROUND-ROBIN STYLE (first has full, second has none)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║  APPROACH B: ROUND-ROBIN (first=full mask_delta, second=none)    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // First signer: s1 = α1 - c_p*(λ1*x1) - c_c*mask_delta (FULL)
    let s1_partial = alpha1 - c_p * (lambda1 * x1) - c_c * mask_delta;
    println!("=== FIRST SIGNER (round-robin) ===");
    println!("s1 = α1 - c_p*(λ1*x1) - c_c*mask_delta (FULL)");
    println!(
        "s1_partial:              {}",
        hex::encode(s1_partial.as_bytes())
    );

    // Second signer: s2 = α2 - c_p*(λ2*x2) (NO mask_delta)
    let s2_contribution = alpha2 - c_p * (lambda2 * x2);
    println!("\n=== SECOND SIGNER (round-robin) ===");
    println!("s2 = α2 - c_p*(λ2*x2) (NO mask_delta)");
    println!(
        "s2_contribution:         {}",
        hex::encode(s2_contribution.as_bytes())
    );

    // Aggregated
    let s_agg_rr = s1_partial + s2_contribution;
    println!("\n=== AGGREGATED (round-robin) ===");
    println!(
        "s_agg (round-robin):     {}",
        hex::encode(s_agg_rr.as_bytes())
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // COMPARISON
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║  COMPARISON: Are both approaches equivalent?                      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    println!(
        "s_agg (WASM):        {}",
        hex::encode(s_agg_wasm.as_bytes())
    );
    println!("s_agg (round-robin): {}", hex::encode(s_agg_rr.as_bytes()));
    println!("MATCH: {}", s_agg_wasm == s_agg_rr);

    // Use the WASM-style value for verification
    let s_agg = s_agg_wasm;

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE 11: VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("PHASE 11: VERIFICATION");
    println!("══════════════════════════════════════════════════════════════════\n");

    // Verification equation at real_index:
    // L'[real] = s[real] * G + c_p * P[real] + c_c * (C - pseudo_out)
    // R'[real] = s[real] * Hp(P) + c_p * I + c_c * D

    // For simplicity, assume C = z*G + amount*H (the input commitment)
    let input_commitment = z * G + Scalar::from(amount) * h_point;
    let c_minus_pseudo = input_commitment - pseudo_out;

    let l_verify = s_agg * G + c_p * p_agg + c_c * c_minus_pseudo;
    let r_verify = s_agg * hp_p + c_p * key_image + c_c * d;

    println!("L_verify = s*G + c_p*P + c_c*(C-pseudo):");
    println!("           {}", hex::encode(l_verify.compress().as_bytes()));
    println!("L_original:");
    println!("           {}", hex::encode(l_real.compress().as_bytes()));
    println!("L matches: {}", l_verify == l_real);

    println!("\nR_verify = s*Hp + c_p*I + c_c*D:");
    println!("           {}", hex::encode(r_verify.compress().as_bytes()));
    println!("R_original:");
    println!("           {}", hex::encode(r_real.compress().as_bytes()));
    println!("R matches: {}", r_verify == r_real);

    // ═══════════════════════════════════════════════════════════════════════════
    // SUMMARY - JSON OUTPUT
    // ═══════════════════════════════════════════════════════════════════════════

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("SUMMARY - TEST VECTORS (JSON format)");
    println!("══════════════════════════════════════════════════════════════════\n");

    println!(
        r#"{{
  "inputs": {{
    "x1": "{}",
    "x2": "{}",
    "alpha1": "{}",
    "alpha2": "{}",
    "z_funding_mask": "{}",
    "pseudo_out_mask": "{}",
    "ring_size": {},
    "real_index": {}
  }},
  "intermediate": {{
    "lambda1": "{}",
    "lambda2": "{}",
    "x_agg": "{}",
    "P_agg": "{}",
    "alpha_agg": "{}",
    "Hp_P": "{}",
    "key_image": "{}",
    "mask_delta": "{}",
    "D": "{}",
    "mu_P": "{}",
    "mu_C": "{}",
    "c_p": "{}",
    "c_c": "{}"
  }},
  "signing": {{
    "s1_partial_first_signer": "{}",
    "s2_contribution_second_signer": "{}",
    "s_aggregated": "{}"
  }},
  "verification": {{
    "L_matches": {},
    "R_matches": {}
  }}
}}"#,
        hex::encode(x1.as_bytes()),
        hex::encode(x2.as_bytes()),
        hex::encode(alpha1.as_bytes()),
        hex::encode(alpha2.as_bytes()),
        hex::encode(z.as_bytes()),
        hex::encode(pseudo_out_mask.as_bytes()),
        ring_size,
        real_index,
        hex::encode(lambda1.as_bytes()),
        hex::encode(lambda2.as_bytes()),
        hex::encode(x_agg.as_bytes()),
        hex::encode(p_agg.compress().as_bytes()),
        hex::encode(alpha_agg.as_bytes()),
        hex::encode(hp_p.compress().as_bytes()),
        hex::encode(key_image.compress().as_bytes()),
        hex::encode(mask_delta.as_bytes()),
        hex::encode(d.compress().as_bytes()),
        hex::encode(mu_p.as_bytes()),
        hex::encode(mu_c.as_bytes()),
        hex::encode(c_p.as_bytes()),
        hex::encode(c_c.as_bytes()),
        hex::encode(s1_partial.as_bytes()),
        hex::encode(s2_contribution.as_bytes()),
        hex::encode(s_agg.as_bytes()),
        l_verify == l_real,
        r_verify == r_real
    );
}
