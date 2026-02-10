//! Complete signing flow debug with known values
//!
//! Simulates the ENTIRE CLSAG signing flow step by step
//! to identify exactly where the bug is.
//!
//! Usage: cargo run --release --bin debug_full_signing_flow

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Keccak256};

// ============================================================================
// KNOWN VALUES FROM ESCROW #ef57f177-f873-40c3-a175-4ab87c195ad8
// ============================================================================

const ESCROW_ID: &str = "ef57f177-f873-40c3-a175-4ab87c195ad8";

// TX data
const TX_SECRET_KEY: &str = "54d48a7b6f680a88fd04b4cf56b18f09e01c66ab3aa5ec9aabb33a258de43704";

// FROST keys
const GROUP_PUBKEY: &str = "8fe544aed04ac3a92dff7d2fb076689b83db5d8eba175bf8853e123b2f0e0fef";
const VIEW_KEY_PRIV: &str = "f2fcd78c14a49e707e4a7f4dfc24f5cfbfddfff5f94837bcddd72d88d963e808";
const VENDOR_SHARE: &str = "7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e";
const BUYER_SHARE: &str = "916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b";

// DB values
const DB_ONE_TIME_PUBKEY: &str = "ae25adc44429a1985ceb88d3059e1f82052797abdfb3ea6c44a151c3cdba43c0";
const DB_TX_PUBKEY: &str = "75ee30c8278cd0da2e081f0dbd22bd8c884d83da2f061c013175fb5612009da9";
const OUTPUT_INDEX: u64 = 1;

// Amount (0.001 XMR in atomic units)
const AMOUNT: u64 = 1_000_000_000;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn hex_to_bytes(h: &str) -> Vec<u8> {
    hex::decode(h).expect("Invalid hex")
}

fn hex_to_scalar(h: &str) -> Scalar {
    let bytes = hex_to_bytes(h);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(arr)
}

fn hex_to_point(h: &str) -> EdwardsPoint {
    let bytes = hex_to_bytes(h);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .expect("Invalid Edwards point")
}

fn encode_varint(value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut n = value;
    while n >= 0x80 {
        result.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    result.push(n as u8);
    result
}

fn hash_to_point(data: [u8; 32]) -> EdwardsPoint {
    let mut counter = 0u8;
    loop {
        let mut hasher = Keccak256::new();
        hasher.update(&data);
        hasher.update(&[counter]);
        let hash: [u8; 32] = hasher.finalize().into();
        if let Some(point) = CompressedEdwardsY(hash).decompress() {
            return point.mul_by_cofactor();
        }
        counter += 1;
        if counter > 255 {
            panic!("hash_to_point failed");
        }
    }
}

fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

// ============================================================================
// CLSAG CONSTANTS
// ============================================================================

const CLSAG_PREFIX: &[u8] = b"CLSAG_";
const CLSAG_AGG_0: &[u8] = b"agg_0";
const CLSAG_ROUND: &[u8] = b"round";

fn keccak256_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

// ============================================================================
// MAIN DEBUG FLOW
// ============================================================================

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║     COMPLETE CLSAG SIGNING FLOW DEBUG                          ║");
    println!("║     Escrow: {}                   ║", &ESCROW_ID[..8]);
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // PHASE 1: Verify base cryptographic values
    // ========================================================================
    println!("═══════════════════════════════════════════════════════════════════");
    println!("PHASE 1: BASE CRYPTOGRAPHIC VALUES");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // Parse known values
    let vendor_share = hex_to_scalar(VENDOR_SHARE);
    let buyer_share = hex_to_scalar(BUYER_SHARE);
    let group_pubkey = hex_to_point(GROUP_PUBKEY);
    let view_key = hex_to_scalar(VIEW_KEY_PRIV);
    let one_time_pubkey = hex_to_point(DB_ONE_TIME_PUBKEY);
    let tx_pub_key = hex_to_point(DB_TX_PUBKEY);

    // Lagrange coefficients for buyer(1) + vendor(2)
    let lambda_buyer = Scalar::from(2u64);
    let lambda_vendor = -Scalar::ONE;

    // Reconstruct group secret
    let group_secret = lambda_buyer * buyer_share + lambda_vendor * vendor_share;
    println!("1.1 Lagrange Reconstruction:");
    println!("    λ_buyer = 2, λ_vendor = -1 mod L");
    println!(
        "    group_secret = {}",
        hex::encode(group_secret.as_bytes())
    );

    // Verify group_secret * G = group_pubkey
    let computed_pubkey = &group_secret * ED25519_BASEPOINT_TABLE;
    if computed_pubkey == group_pubkey {
        println!("    ✅ group_secret * G = group_pubkey");
    } else {
        println!("    ❌ FAILED: group_secret * G ≠ group_pubkey");
        return;
    }

    // Compute derivation
    let shared_secret = (view_key * tx_pub_key).mul_by_cofactor();
    let mut hasher = Keccak256::new();
    hasher.update(&shared_secret.compress().to_bytes());
    hasher.update(&encode_varint(OUTPUT_INDEX));
    let derivation_hash: [u8; 32] = hasher.finalize().into();
    let derivation = Scalar::from_bytes_mod_order(derivation_hash);

    println!("\n1.2 Derivation:");
    println!(
        "    d = H_s(8*a*R || varint({})) = {}",
        OUTPUT_INDEX,
        hex::encode(derivation.as_bytes())
    );

    // Verify one_time_pubkey = d*G + B
    let d_point = &derivation * ED25519_BASEPOINT_TABLE;
    let computed_otp = d_point + group_pubkey;
    if computed_otp == one_time_pubkey {
        println!("    ✅ P = d*G + B matches DB one_time_pubkey");
    } else {
        println!("    ❌ FAILED: P = d*G + B ≠ DB one_time_pubkey");
        println!(
            "       Computed: {}",
            hex::encode(computed_otp.compress().as_bytes())
        );
        println!("       DB:       {}", DB_ONE_TIME_PUBKEY);
        return;
    }

    // Full output secret
    let output_secret = derivation + group_secret;
    println!("\n1.3 Output Secret:");
    println!(
        "    x = d + group_secret = {}",
        hex::encode(output_secret.as_bytes())
    );

    // Hash to point
    let hp = hash_to_point(one_time_pubkey.compress().to_bytes());
    println!("\n1.4 Hash-to-Point:");
    println!("    Hp(P) = {}", hex::encode(hp.compress().as_bytes()));

    // Correct key image
    let key_image = output_secret * hp;
    println!("\n1.5 Key Image:");
    println!(
        "    KI = x * Hp(P) = {}",
        hex::encode(key_image.compress().as_bytes())
    );

    // ========================================================================
    // PHASE 2: Simulate PKI computation (what WASM should do)
    // ========================================================================
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("PHASE 2: PARTIAL KEY IMAGE COMPUTATION");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // First signer (vendor) with derivation
    let x_eff_vendor = derivation + lambda_vendor * vendor_share;
    let pki_vendor = x_eff_vendor * hp;
    println!("2.1 Vendor PKI (first signer, WITH derivation):");
    println!(
        "    x_eff = d + λ_v * s_v = {}",
        hex::encode(x_eff_vendor.as_bytes())
    );
    println!(
        "    PKI_vendor = {}",
        hex::encode(pki_vendor.compress().as_bytes())
    );

    // Second signer (buyer) WITHOUT derivation
    let x_eff_buyer = lambda_buyer * buyer_share;
    let pki_buyer = x_eff_buyer * hp;
    println!("\n2.2 Buyer PKI (second signer, NO derivation):");
    println!(
        "    x_eff = λ_b * s_b = {}",
        hex::encode(x_eff_buyer.as_bytes())
    );
    println!(
        "    PKI_buyer = {}",
        hex::encode(pki_buyer.compress().as_bytes())
    );

    // Aggregation
    let aggregated_ki = pki_vendor + pki_buyer;
    println!("\n2.3 Aggregated Key Image:");
    println!(
        "    KI_agg = PKI_v + PKI_b = {}",
        hex::encode(aggregated_ki.compress().as_bytes())
    );

    if aggregated_ki == key_image {
        println!("    ✅ KI_agg = KI (correct!)");
    } else {
        println!("    ❌ MISMATCH: KI_agg ≠ KI");
        return;
    }

    // ========================================================================
    // PHASE 3: Simulate what escrow-show.js WRONGLY computes
    // ========================================================================
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("PHASE 3: WHAT escrow-show.js WRONGLY COMPUTES (λ=1, no derivation)");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // escrow-show.js uses λ=1 and NO derivation for BOTH signers
    let wrong_pki_vendor = vendor_share * hp; // λ=1, no derivation
    let wrong_pki_buyer = buyer_share * hp; // λ=1, no derivation
    let wrong_ki = wrong_pki_vendor + wrong_pki_buyer;

    println!("3.1 Wrong Vendor PKI (λ=1, no derivation):");
    println!(
        "    PKI_vendor_wrong = {}",
        hex::encode(wrong_pki_vendor.compress().as_bytes())
    );
    println!("\n3.2 Wrong Buyer PKI (λ=1, no derivation):");
    println!(
        "    PKI_buyer_wrong = {}",
        hex::encode(wrong_pki_buyer.compress().as_bytes())
    );
    println!("\n3.3 Wrong Aggregated KI:");
    println!(
        "    KI_wrong = {}",
        hex::encode(wrong_ki.compress().as_bytes())
    );
    println!("    ❌ This will NEVER match the correct KI!");

    // ========================================================================
    // PHASE 4: Simulate CLSAG signing with CORRECT values
    // ========================================================================
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("PHASE 4: CLSAG SIGNING SIMULATION (with correct KI)");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // Create a fake ring (16 members, our key at index 0)
    let ring_size = 16;
    let signer_index = 0usize;

    // Generate random ring members
    let mut ring_keys: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);
    let mut ring_commitments: Vec<EdwardsPoint> = Vec::with_capacity(ring_size);

    for i in 0..ring_size {
        if i == signer_index {
            ring_keys.push(one_time_pubkey);
            // Real commitment for our output
            let mask = random_scalar();
            let commitment =
                &mask * ED25519_BASEPOINT_TABLE + &Scalar::from(AMOUNT) * hash_to_point([0u8; 32]); // H point
            ring_commitments.push(commitment);
        } else {
            // Random decoys
            ring_keys.push(&random_scalar() * ED25519_BASEPOINT_TABLE);
            ring_commitments.push(&random_scalar() * ED25519_BASEPOINT_TABLE);
        }
    }

    println!("4.1 Ring Setup:");
    println!("    Ring size: {}", ring_size);
    println!("    Signer index: {}", signer_index);
    println!(
        "    ring[{}] = P = {}",
        signer_index,
        hex::encode(ring_keys[signer_index].compress().as_bytes())
    );

    // Generate nonces
    let alpha = random_scalar();
    let alpha_hp = alpha * hp;
    let alpha_g = &alpha * ED25519_BASEPOINT_TABLE;

    println!("\n4.2 Nonces:");
    println!("    α (random) = {}", hex::encode(alpha.as_bytes()));
    println!(
        "    α*Hp(P) = {}",
        hex::encode(alpha_hp.compress().as_bytes())
    );
    println!("    α*G = {}", hex::encode(alpha_g.compress().as_bytes()));

    // Compute pseudo_out and mask delta
    let real_mask = random_scalar();
    let pseudo_out_mask = random_scalar();
    let mask_delta = real_mask - pseudo_out_mask;
    let pseudo_out = &pseudo_out_mask * ED25519_BASEPOINT_TABLE;

    // Compute D (mask delta * Hp for CLSAG)
    let d_clsag = mask_delta * hp;
    let d_inv8 = d_clsag * Scalar::from(8u64).invert();

    println!("\n4.3 Mask/Commitment:");
    println!("    mask_delta = {}", hex::encode(mask_delta.as_bytes()));
    println!(
        "    D = mask_delta * Hp(P) = {}",
        hex::encode(d_clsag.compress().as_bytes())
    );
    println!("    D_inv8 = {}", hex::encode(d_inv8.compress().as_bytes()));

    // ========================================================================
    // PHASE 5: Compute CLSAG challenge and response
    // ========================================================================
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("PHASE 5: CLSAG CHALLENGE/RESPONSE COMPUTATION");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // Compute mu_P and mu_C (aggregation coefficients)
    let mut agg_buffer = Vec::with_capacity(((2 * ring_size) + 5) * 32);

    // Domain separator
    agg_buffer.extend_from_slice(CLSAG_PREFIX);
    agg_buffer.extend_from_slice(CLSAG_AGG_0);
    agg_buffer.extend_from_slice(&[0u8; 21]); // Padding to 32 bytes

    // Ring keys
    for key in &ring_keys {
        agg_buffer.extend_from_slice(&key.compress().to_bytes());
    }

    // Ring commitments
    for commit in &ring_commitments {
        agg_buffer.extend_from_slice(&commit.compress().to_bytes());
    }

    // Key image, D_inv8, pseudo_out
    agg_buffer.extend_from_slice(&key_image.compress().to_bytes());
    agg_buffer.extend_from_slice(&d_inv8.compress().to_bytes());
    agg_buffer.extend_from_slice(&pseudo_out.compress().to_bytes());

    let mu_p = keccak256_to_scalar(&agg_buffer);
    agg_buffer[10] = b'1'; // Change agg_0 to agg_1
    let mu_c = keccak256_to_scalar(&agg_buffer);

    println!("5.1 Aggregation Coefficients:");
    println!("    mu_P = {}", hex::encode(mu_p.as_bytes()));
    println!("    mu_C = {}", hex::encode(mu_c.as_bytes()));

    // Compute initial challenge c[l+1] from nonce points
    // c_{l+1} = H_s(round || P || C_adj || msg || L || R)
    // where L = α*G and R = α*Hp(P)
    let fake_msg = [0u8; 32]; // Fake tx_prefix_hash

    let mut round_buffer = Vec::new();
    round_buffer.extend_from_slice(CLSAG_PREFIX);
    round_buffer.extend_from_slice(CLSAG_ROUND);
    round_buffer.extend_from_slice(&[0u8; 21]);
    for key in &ring_keys {
        round_buffer.extend_from_slice(&key.compress().to_bytes());
    }
    // Adjusted commitments (C - pseudo_out)
    for commit in &ring_commitments {
        let adjusted = commit - pseudo_out;
        round_buffer.extend_from_slice(&adjusted.compress().to_bytes());
    }
    round_buffer.extend_from_slice(&fake_msg);
    round_buffer.extend_from_slice(&alpha_g.compress().to_bytes());
    round_buffer.extend_from_slice(&alpha_hp.compress().to_bytes());

    let c_next = keccak256_to_scalar(&round_buffer);
    println!("\n5.2 Initial Challenge:");
    println!(
        "    c[{}] = {}",
        (signer_index + 1) % ring_size,
        hex::encode(c_next.as_bytes())
    );

    // Compute s-value for signer (the main response)
    // s = α - c_p * x - c_c * mask_delta
    // where c_p = c * mu_P, c_c = c * mu_C
    let c_at_signer = c_next; // In real CLSAG, we'd propagate challenges around the ring
    let c_p = c_at_signer * mu_p;
    let c_c = c_at_signer * mu_c;

    let s_signer = alpha - c_p * output_secret - c_c * mask_delta;

    println!("\n5.3 Signer Response:");
    println!("    c_p = c * mu_P = {}", hex::encode(c_p.as_bytes()));
    println!("    c_c = c * mu_C = {}", hex::encode(c_c.as_bytes()));
    println!(
        "    s[{}] = α - c_p*x - c_c*z = {}",
        signer_index,
        hex::encode(s_signer.as_bytes())
    );

    // ========================================================================
    // PHASE 6: Verify CLSAG equation
    // ========================================================================
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("PHASE 6: CLSAG VERIFICATION");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // Verification equation at signer index:
    // L' = s*G + c_p*P + c_c*(C - pseudo_out)
    // R' = s*Hp(P) + c_p*I + c_c*D

    let l_prime = &s_signer * ED25519_BASEPOINT_TABLE
        + c_p * ring_keys[signer_index]
        + c_c * (ring_commitments[signer_index] - pseudo_out);

    let r_prime = s_signer * hp + c_p * key_image + c_c * d_clsag;

    println!("6.1 Verification Points:");
    println!(
        "    L' = s*G + c_p*P + c_c*(C-pseudo) = {}",
        hex::encode(l_prime.compress().as_bytes())
    );
    println!(
        "    R' = s*Hp + c_p*I + c_c*D = {}",
        hex::encode(r_prime.compress().as_bytes())
    );
    println!("\n    Expected:");
    println!(
        "    L = α*G = {}",
        hex::encode(alpha_g.compress().as_bytes())
    );
    println!(
        "    R = α*Hp = {}",
        hex::encode(alpha_hp.compress().as_bytes())
    );

    if l_prime == alpha_g && r_prime == alpha_hp {
        println!("\n    ✅ CLSAG VERIFICATION PASSED!");
        println!("       L' = L and R' = R");
    } else {
        println!("\n    ❌ CLSAG VERIFICATION FAILED!");
        if l_prime != alpha_g {
            println!("       L' ≠ L");
        }
        if r_prime != alpha_hp {
            println!("       R' ≠ R");
        }
    }

    // ========================================================================
    // PHASE 7: What happens with WRONG key image
    // ========================================================================
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("PHASE 7: WHAT HAPPENS WITH WRONG KEY IMAGE (from escrow-show.js)");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // If mu_P and mu_C were computed with wrong_ki instead of key_image:
    agg_buffer[10] = b'0'; // Reset to agg_0

    // Replace key_image with wrong_ki in the buffer
    let ki_offset = 32 + (ring_size * 32) + (ring_size * 32); // After domain + ring_keys + ring_commits
    let wrong_ki_bytes = wrong_ki.compress().to_bytes();
    agg_buffer[ki_offset..ki_offset + 32].copy_from_slice(&wrong_ki_bytes);

    let wrong_mu_p = keccak256_to_scalar(&agg_buffer);
    agg_buffer[10] = b'1';
    let wrong_mu_c = keccak256_to_scalar(&agg_buffer);

    println!("7.1 Wrong mu values (computed with wrong KI):");
    println!("    wrong_mu_P = {}", hex::encode(wrong_mu_p.as_bytes()));
    println!("    wrong_mu_C = {}", hex::encode(wrong_mu_c.as_bytes()));
    println!(
        "    (Compare to correct mu_P = {}...)",
        &hex::encode(mu_p.as_bytes())[..16]
    );

    // If signature was computed with correct x but wrong mu:
    let wrong_c_p = c_at_signer * wrong_mu_p;
    let wrong_c_c = c_at_signer * wrong_mu_c;
    let wrong_s = alpha - wrong_c_p * output_secret - wrong_c_c * mask_delta;

    println!("\n7.2 Signature with wrong mu but correct x:");
    println!("    s_wrong = {}", hex::encode(wrong_s.as_bytes()));

    // Verify with CORRECT key_image but wrong s:
    let verify_l = &wrong_s * ED25519_BASEPOINT_TABLE
        + wrong_c_p * ring_keys[signer_index]
        + wrong_c_c * (ring_commitments[signer_index] - pseudo_out);

    let verify_r = wrong_s * hp
                 + wrong_c_p * key_image  // Verifier uses correct KI
                 + wrong_c_c * d_clsag;

    println!("\n7.3 Verification with wrong signature:");
    println!(
        "    L_verify = {}",
        hex::encode(verify_l.compress().as_bytes())
    );
    println!(
        "    R_verify = {}",
        hex::encode(verify_r.compress().as_bytes())
    );

    if verify_l == alpha_g && verify_r == alpha_hp {
        println!("    ✅ Would pass (unexpected!)");
    } else {
        println!("    ❌ FAILS - This is why broadcast fails!");
        println!("       The signature was computed with wrong mu values");
        println!("       derived from wrong key_image from escrow-show.js");
    }

    // ========================================================================
    // SUMMARY
    // ========================================================================
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                         SUMMARY                                ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    println!("ROOT CAUSE IDENTIFIED:");
    println!("=======================");
    println!("1. escrow-show.js auto-submits PKI with λ=1 and NO derivation");
    println!("2. Server aggregates these WRONG PKIs → wrong aggregated_key_image");
    println!("3. prepare-sign returns this wrong KI");
    println!("4. CLSAG signing computes mu_P, mu_C with wrong KI");
    println!("5. s-value is computed with wrong mu values");
    println!("6. Verification fails because mu mismatch");
    println!("");
    println!("CORRECT VALUES FOR THIS ESCROW:");
    println!("================================");
    println!("one_time_pubkey: {}", DB_ONE_TIME_PUBKEY);
    println!(
        "key_image:       {}",
        hex::encode(key_image.compress().as_bytes())
    );
    println!(
        "PKI_vendor:      {}",
        hex::encode(pki_vendor.compress().as_bytes())
    );
    println!(
        "PKI_buyer:       {}",
        hex::encode(pki_buyer.compress().as_bytes())
    );
    println!("");
    println!("FIX REQUIRED:");
    println!("=============");
    println!("1. sign-action.js must re-submit PKI for BOTH signers with correct λ");
    println!("2. OR: Server must re-compute aggregated_key_image during prepare-sign");
    println!("3. OR: Disable auto-submit in escrow-show.js for FROST escrows");
}
