//! CLSAG Debug Instrumentation
//!
//! This module provides comprehensive logging and validation for CLSAG signatures.
//! Every intermediate value is logged to allow comparison with reference implementations.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use monero_generators::{hash_to_point, H};
use sha3::{Digest, Keccak256};

/// Debug context that captures all intermediate CLSAG values
#[derive(Default)]
pub struct ClsagDebugContext {
    pub logs: Vec<String>,
}

impl ClsagDebugContext {
    pub fn new() -> Self {
        Self { logs: Vec::new() }
    }

    pub fn log(&mut self, msg: &str) {
        self.logs.push(msg.to_string());
        web_sys::console::log_1(&format!("[CLSAG-DEBUG] {}", msg).into());
    }

    pub fn log_scalar(&mut self, name: &str, scalar: &Scalar) {
        let hex = hex::encode(scalar.to_bytes());
        self.log(&format!("{}: {}", name, hex));
    }

    pub fn log_point(&mut self, name: &str, point: &EdwardsPoint) {
        let hex = hex::encode(point.compress().to_bytes());
        self.log(&format!("{}: {}", name, hex));
    }

    pub fn log_bytes(&mut self, name: &str, bytes: &[u8]) {
        let hex = hex::encode(bytes);
        self.log(&format!("{}: {} (len={})", name, hex, bytes.len()));
    }

    /// Dump all logs as a single string for export
    pub fn dump(&self) -> String {
        self.logs.join("\n")
    }
}

/// Compute and log mu_P and mu_C with full intermediate values
pub fn compute_mu_with_debug(
    ctx: &mut ClsagDebugContext,
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_inv8: &EdwardsPoint, // D * inv8
    pseudo_out: &EdwardsPoint,
) -> (Scalar, Scalar) {
    ctx.log("=== Computing mu_P and mu_C ===");
    ctx.log(&format!("Ring size: {}", ring_keys.len()));

    // Build hash input exactly as Monero does
    let mut hash_input: Vec<u8> = Vec::new();

    // Domain separator: "CLSAG_agg_0" padded to 32 bytes
    let mut domain = [0u8; 32];
    domain[..11].copy_from_slice(b"CLSAG_agg_0");
    hash_input.extend_from_slice(&domain);
    ctx.log_bytes("Domain (agg_0)", &domain);

    // Ring keys
    for (i, key) in ring_keys.iter().enumerate() {
        let bytes = key.compress().to_bytes();
        hash_input.extend_from_slice(&bytes);
        if i < 3 || i == ring_keys.len() - 1 {
            ctx.log(&format!("P[{}]: {}", i, hex::encode(&bytes)));
        }
    }

    // Ring commitments (original, not adjusted)
    for (i, commit) in ring_commitments.iter().enumerate() {
        let bytes = commit.compress().to_bytes();
        hash_input.extend_from_slice(&bytes);
        if i < 3 || i == ring_commitments.len() - 1 {
            ctx.log(&format!("C[{}]: {}", i, hex::encode(&bytes)));
        }
    }

    // Key image
    let ki_bytes = key_image.compress().to_bytes();
    hash_input.extend_from_slice(&ki_bytes);
    ctx.log_bytes("I (key_image)", &ki_bytes);

    // D * inv8 (NOT original D!)
    let d_bytes = d_inv8.compress().to_bytes();
    hash_input.extend_from_slice(&d_bytes);
    ctx.log_bytes("D_inv8", &d_bytes);

    // Pseudo-out
    let po_bytes = pseudo_out.compress().to_bytes();
    hash_input.extend_from_slice(&po_bytes);
    ctx.log_bytes("pseudo_out", &po_bytes);

    ctx.log(&format!(
        "Total hash input length for mu_P: {}",
        hash_input.len()
    ));

    // Compute mu_P
    let mu_p_hash: [u8; 32] = Keccak256::digest(&hash_input).into();
    let mu_p = Scalar::from_bytes_mod_order(mu_p_hash);
    ctx.log_bytes("mu_P hash", &mu_p_hash);
    ctx.log_scalar("mu_P", &mu_p);

    // Compute mu_C (change domain to agg_1)
    hash_input[10] = b'1'; // Change "CLSAG_agg_0" to "CLSAG_agg_1"
    let mu_c_hash: [u8; 32] = Keccak256::digest(&hash_input).into();
    let mu_c = Scalar::from_bytes_mod_order(mu_c_hash);
    ctx.log_bytes("mu_C hash", &mu_c_hash);
    ctx.log_scalar("mu_C", &mu_c);

    (mu_p, mu_c)
}

/// Compute one iteration of the CLSAG ring loop with debug
pub fn ring_loop_iteration_debug(
    ctx: &mut ClsagDebugContext,
    i: usize,
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    key_image: &EdwardsPoint,
    d_original: &EdwardsPoint, // Original D (NOT * inv8)
    pseudo_out: &EdwardsPoint,
    msg: &[u8; 32],
    s_i: &Scalar,
    c: &Scalar,
    mu_p: &Scalar,
    mu_c: &Scalar,
) -> (EdwardsPoint, EdwardsPoint, Scalar) {
    ctx.log(&format!("=== Ring loop iteration i={} ===", i));

    let c_p = c * mu_p;
    let c_c = c * mu_c;
    ctx.log_scalar(&format!("c[{}]", i), c);
    ctx.log_scalar("c_p = c * mu_P", &c_p);
    ctx.log_scalar("c_c = c * mu_C", &c_c);

    // C_adjusted = C[i] - pseudo_out
    let c_adjusted = ring_commitments[i] - pseudo_out;
    ctx.log_point(&format!("C_adjusted[{}]", i), &c_adjusted);

    // L = s[i] * G + c_p * P[i] + c_c * C_adjusted[i]
    let l_point = EdwardsPoint::vartime_multiscalar_mul(
        [*s_i, c_p, c_c],
        [ED25519_BASEPOINT_POINT, ring_keys[i], c_adjusted],
    );
    ctx.log_point(&format!("L[{}]", i), &l_point);

    // Hp(P[i])
    let hp_i = hash_to_point(ring_keys[i].compress().to_bytes());
    ctx.log_point(&format!("Hp(P[{}])", i), &hp_i);

    // R = s[i] * Hp(P[i]) + c_p * I + c_c * D
    // NOTE: Uses ORIGINAL D, not D * inv8!
    let r_point =
        EdwardsPoint::vartime_multiscalar_mul([*s_i, c_p, c_c], [hp_i, *key_image, *d_original]);
    ctx.log_point(&format!("R[{}]", i), &r_point);

    // Compute next challenge
    let c_next = compute_round_hash_debug(
        ctx,
        i,
        ring_keys,
        ring_commitments,
        pseudo_out,
        msg,
        &l_point,
        &r_point,
    );

    (l_point, r_point, c_next)
}

/// Compute round hash with debug
pub fn compute_round_hash_debug(
    ctx: &mut ClsagDebugContext,
    i: usize,
    ring_keys: &[EdwardsPoint],
    ring_commitments: &[EdwardsPoint],
    pseudo_out: &EdwardsPoint,
    msg: &[u8; 32],
    l_point: &EdwardsPoint,
    r_point: &EdwardsPoint,
) -> Scalar {
    // Build hash input for round
    let mut hash_input: Vec<u8> = Vec::new();

    // Domain separator: "CLSAG_round" padded to 32 bytes
    let mut domain = [0u8; 32];
    domain[..11].copy_from_slice(b"CLSAG_round");
    hash_input.extend_from_slice(&domain);

    // Ring keys
    for key in ring_keys {
        hash_input.extend_from_slice(&key.compress().to_bytes());
    }

    // Ring commitments (original, not adjusted)
    for commit in ring_commitments {
        hash_input.extend_from_slice(&commit.compress().to_bytes());
    }

    // pseudo_out (NOT I or D!)
    hash_input.extend_from_slice(&pseudo_out.compress().to_bytes());

    // Message
    hash_input.extend_from_slice(msg);

    // L and R
    hash_input.extend_from_slice(&l_point.compress().to_bytes());
    hash_input.extend_from_slice(&r_point.compress().to_bytes());

    ctx.log(&format!("Round hash input length: {}", hash_input.len()));

    let c_hash: [u8; 32] = Keccak256::digest(&hash_input).into();
    let c_next = Scalar::from_bytes_mod_order(c_hash);
    ctx.log_scalar(&format!("c[{}+1]", i), &c_next);

    c_next
}

/// Verify commitment balance: pseudo_out == output_commitment + fee * H
pub fn verify_commitment_balance_debug(
    ctx: &mut ClsagDebugContext,
    pseudo_out: &EdwardsPoint,
    output_commitment: &EdwardsPoint,
    fee: u64,
) -> bool {
    ctx.log("=== Verifying commitment balance ===");
    ctx.log_point("pseudo_out", pseudo_out);
    ctx.log_point("output_commitment", output_commitment);
    ctx.log(&format!("fee: {}", fee));

    let h_point = *H;
    ctx.log_point("H", &h_point);

    let fee_scalar = Scalar::from(fee);
    let fee_commitment = h_point * fee_scalar;
    ctx.log_point("fee * H", &fee_commitment);

    let expected = output_commitment + fee_commitment;
    ctx.log_point("output + fee*H", &expected);

    let matches = pseudo_out.compress() == expected.compress();
    ctx.log(&format!(
        "Balance check: {}",
        if matches { "PASS" } else { "FAIL" }
    ));

    matches
}

/// Log all signature components
pub fn log_signature_components(
    ctx: &mut ClsagDebugContext,
    s_values: &[Scalar],
    c1: &Scalar,
    d: &EdwardsPoint,
    key_image: &EdwardsPoint,
    pseudo_out: &EdwardsPoint,
) {
    ctx.log("=== Final Signature Components ===");
    ctx.log_scalar("c1", c1);
    ctx.log_point("D (stored, = D*inv8)", d);
    ctx.log_point("Key Image", key_image);
    ctx.log_point("Pseudo-out", pseudo_out);
    ctx.log(&format!("s_values count: {}", s_values.len()));

    for (i, s) in s_values.iter().enumerate() {
        ctx.log_scalar(&format!("s[{}]", i), s);
    }
}
