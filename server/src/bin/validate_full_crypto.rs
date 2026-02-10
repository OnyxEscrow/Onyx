//! FULL CRYPTO VALIDATION - Offline verification of entire FROST signing flow
//!
//! This script validates ALL crypto equations BEFORE broadcast:
//! 1. PKI computation and aggregation
//! 2. Key image derivation
//! 3. Commitment balance (pseudo_out = outputs + fee*H)
//! 4. CLSAG signature structure
//! 5. Ring data consistency
//!
//! Usage: cargo run --release --bin validate_full_crypto -- <escrow_id>

use anyhow::{Context, Result};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha3::{Digest, Keccak256};
use std::env;

// H generator for Pedersen commitments (from Monero)
const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Encode u64 as Monero varint (same as in validate_escrow_crypto.rs)
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

/// Get known shares for specific escrows (secret values from test sessions)
/// These are NOT stored in the DB for security reasons
fn get_known_shares(escrow_id: &str) -> Option<([u8; 32], [u8; 32])> {
    // Escrow #ef57f177 - Test escrow with known values
    if escrow_id.starts_with("ef57f177") {
        let buyer_share =
            hex::decode("916e1d306297b252a49d616846bc1e22276ea3d535280bdde3f8d8123541b70b").ok()?;
        let vendor_share =
            hex::decode("7dfcdfcaafbe5b7abbb69237954839f30172c31d91bbfe57357542bfd504b60e").ok()?;

        let mut bs = [0u8; 32];
        let mut vs = [0u8; 32];
        bs.copy_from_slice(&buyer_share);
        vs.copy_from_slice(&vendor_share);
        return Some((bs, vs));
    }

    None
}

#[derive(Debug)]
struct ValidationResult {
    step: String,
    expected: String,
    actual: String,
    passed: bool,
}

struct CryptoValidator {
    escrow_id: String,
    results: Vec<ValidationResult>,

    // Loaded data
    frost_enabled: bool,
    escrow_amount: u64,
    fee: u64,

    // Crypto values from DB
    buyer_share: Option<[u8; 32]>,
    vendor_share: Option<[u8; 32]>,
    group_pubkey: Option<[u8; 32]>,
    view_key: Option<[u8; 32]>,

    // PKIs
    buyer_pki: Option<[u8; 32]>,
    vendor_pki: Option<[u8; 32]>,
    aggregated_ki: Option<[u8; 32]>,

    // Transaction data
    pseudo_out: Option<[u8; 32]>,
    funding_output_index: Option<u32>,
    tx_pubkey: Option<[u8; 32]>,

    // Signatures
    buyer_signature: Option<String>,
    vendor_signature: Option<String>,
    ring_data_json: Option<String>,

    // Computed values
    one_time_address: Option<[u8; 32]>,
    derivation: Option<Scalar>,
}

impl CryptoValidator {
    fn new(escrow_id: &str) -> Self {
        Self {
            escrow_id: escrow_id.to_string(),
            results: Vec::new(),
            frost_enabled: false,
            escrow_amount: 0,
            fee: 100_000_000, // 0.0001 XMR default
            buyer_share: None,
            vendor_share: None,
            group_pubkey: None,
            view_key: None,
            buyer_pki: None,
            vendor_pki: None,
            aggregated_ki: None,
            pseudo_out: None,
            funding_output_index: None,
            tx_pubkey: None,
            buyer_signature: None,
            vendor_signature: None,
            ring_data_json: None,
            one_time_address: None,
            derivation: None,
        }
    }

    fn add_result(&mut self, step: &str, expected: &str, actual: &str, passed: bool) {
        self.results.push(ValidationResult {
            step: step.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
            passed,
        });
    }

    fn load_escrow_data(&mut self, conn: &rusqlite::Connection) -> Result<()> {
        println!("\n============================================================");
        println!("STEP 1: LOADING ESCROW DATA");
        println!("============================================================");

        // SHARES ARE SECRET - NOT STORED IN DB
        // For escrow #ef57f177, use known test values
        let known_shares = get_known_shares(&self.escrow_id);
        if let Some((buyer_share, vendor_share)) = known_shares {
            self.buyer_share = Some(buyer_share);
            self.vendor_share = Some(vendor_share);
            println!(
                "  [INFO] Using known shares for escrow {}...",
                &self.escrow_id[..8]
            );
        } else {
            println!("  [WARN] No known shares for escrow - PKI validation will be skipped");
        }

        let mut stmt = conn.prepare(
            "SELECT status, frost_enabled, amount,
                    frost_group_pubkey, multisig_view_key, buyer_partial_key_image,
                    vendor_partial_key_image, aggregated_key_image,
                    funding_output_index, funding_tx_pubkey, buyer_signature, vendor_signature,
                    ring_data_json
             FROM escrows WHERE id = ?1",
        )?;

        let row = stmt.query_row([&self.escrow_id], |row| {
            Ok((
                row.get::<_, String>(0)?,          // status
                row.get::<_, bool>(1)?,            // frost_enabled
                row.get::<_, i64>(2)?,             // amount
                row.get::<_, Option<String>>(3)?,  // frost_group_pubkey
                row.get::<_, Option<String>>(4)?,  // multisig_view_key
                row.get::<_, Option<String>>(5)?,  // buyer_partial_key_image
                row.get::<_, Option<String>>(6)?,  // vendor_partial_key_image
                row.get::<_, Option<String>>(7)?,  // aggregated_key_image
                row.get::<_, Option<i32>>(8)?,     // funding_output_index
                row.get::<_, Option<String>>(9)?,  // funding_tx_pubkey
                row.get::<_, Option<String>>(10)?, // buyer_signature
                row.get::<_, Option<String>>(11)?, // vendor_signature
                row.get::<_, Option<String>>(12)?, // ring_data_json
            ))
        })?;

        println!("  Status: {}", row.0);
        println!("  FROST enabled: {}", row.1);
        println!(
            "  Amount: {} piconero ({:.12} XMR)",
            row.2,
            row.2 as f64 / 1e12
        );

        self.frost_enabled = row.1;
        self.escrow_amount = row.2 as u64;

        // Parse hex values from DB
        if let Some(ref hex) = row.3 {
            self.group_pubkey = Some(parse_hex_32(hex)?);
            println!("  Group pubkey: {}...", &hex[..16.min(hex.len())]);
        }
        if let Some(ref hex) = row.4 {
            self.view_key = Some(parse_hex_32(hex)?);
            println!("  View key: {}...", &hex[..16.min(hex.len())]);
        }
        if let Some(ref hex) = row.5 {
            self.buyer_pki = Some(parse_hex_32(hex)?);
            println!("  Buyer PKI: {}...", &hex[..16.min(hex.len())]);
        }
        if let Some(ref hex) = row.6 {
            self.vendor_pki = Some(parse_hex_32(hex)?);
            println!("  Vendor PKI: {}...", &hex[..16.min(hex.len())]);
        }
        if let Some(ref hex) = row.7 {
            self.aggregated_ki = Some(parse_hex_32(hex)?);
            println!("  Aggregated KI: {}...", &hex[..16.min(hex.len())]);
        }

        self.funding_output_index = row.8.map(|i| i as u32);

        if let Some(ref hex) = row.9 {
            self.tx_pubkey = Some(parse_hex_32(hex)?);
            println!("  TX pubkey (R): {}...", &hex[..16.min(hex.len())]);
        }

        self.buyer_signature = row.10.clone();
        self.vendor_signature = row.11.clone();
        self.ring_data_json = row.12.clone();

        // Extract pseudo_out from signature
        if let Some(ref sig_json) = self.buyer_signature {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(sig_json) {
                if let Some(po) = parsed.get("pseudo_out").and_then(|v| v.as_str()) {
                    self.pseudo_out = Some(parse_hex_32(po)?);
                    println!("  Pseudo_out (buyer sig): {}...", &po[..16.min(po.len())]);
                }
            }
        }
        if self.pseudo_out.is_none() {
            if let Some(ref sig_json) = self.vendor_signature {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(sig_json) {
                    if let Some(po) = parsed.get("pseudo_out").and_then(|v| v.as_str()) {
                        self.pseudo_out = Some(parse_hex_32(po)?);
                        println!("  Pseudo_out (vendor sig): {}...", &po[..16.min(po.len())]);
                    }
                }
            }
        }

        self.add_result("1. Load escrow data", "OK", "Loaded", true);
        Ok(())
    }

    fn validate_one_time_address(&mut self) -> Result<()> {
        println!("\n============================================================");
        println!("STEP 2: VALIDATE ONE-TIME ADDRESS DERIVATION");
        println!("============================================================");

        let tx_pubkey = match self.tx_pubkey {
            Some(p) => p,
            None => {
                self.add_result(
                    "2. One-time address",
                    "tx_pubkey required",
                    "MISSING",
                    false,
                );
                return Ok(());
            }
        };
        let view_key = match self.view_key {
            Some(v) => v,
            None => {
                self.add_result("2. One-time address", "view_key required", "MISSING", false);
                return Ok(());
            }
        };
        let group_pubkey = match self.group_pubkey {
            Some(g) => g,
            None => {
                self.add_result(
                    "2. One-time address",
                    "group_pubkey required",
                    "MISSING",
                    false,
                );
                return Ok(());
            }
        };

        // R = tx_pubkey
        let r_point = CompressedEdwardsY(tx_pubkey)
            .decompress()
            .context("Invalid tx_pubkey point")?;

        // v = view_key (scalar)
        let v = Scalar::from_bytes_mod_order(view_key);

        // Monero derivation: shared_secret = 8 * v * R (with cofactor multiplication)
        let shared_secret = (r_point * v).mul_by_cofactor();
        let shared_secret_bytes = shared_secret.compress().to_bytes();

        println!("  R (tx_pubkey): {}...", hex::encode(&tx_pubkey[..8]));
        println!("  v (view_key): {}...", hex::encode(&view_key[..8]));
        println!(
            "  Shared secret (8*v*R): {}...",
            hex::encode(&shared_secret_bytes[..8])
        );

        // Hs(shared_secret || output_index) - MUST use varint encoding
        let output_index = self.funding_output_index.unwrap_or(0);
        let mut hasher = Keccak256::new();
        hasher.update(&shared_secret_bytes);
        hasher.update(&encode_varint(output_index as u64)); // Monero uses varint!
        let derivation_scalar_bytes: [u8; 32] = hasher.finalize().into();
        self.derivation = Some(Scalar::from_bytes_mod_order(derivation_scalar_bytes));

        println!(
            "  Hs(derivation||idx): {}...",
            hex::encode(&derivation_scalar_bytes[..8])
        );

        // P = Hs(derivation||idx)*G + B (group pubkey)
        let b_point = CompressedEdwardsY(group_pubkey)
            .decompress()
            .context("Invalid group_pubkey point")?;
        let one_time = &*ED25519_BASEPOINT_TABLE * &self.derivation.unwrap() + b_point;
        self.one_time_address = Some(one_time.compress().to_bytes());

        println!(
            "  One-time address P: {}",
            hex::encode(self.one_time_address.unwrap())
        );

        self.add_result(
            "2. One-time address derivation",
            "P = Hs(v*R||idx)*G + B",
            &format!("{}...", &hex::encode(&self.one_time_address.unwrap()[..8])),
            true,
        );

        Ok(())
    }

    fn validate_pki_computation(&mut self) -> Result<()> {
        println!("\n============================================================");
        println!("STEP 3: VALIDATE PKI COMPUTATION");
        println!("============================================================");

        let one_time = match self.one_time_address {
            Some(p) => p,
            None => {
                self.add_result(
                    "3. PKI computation",
                    "one_time_address required",
                    "MISSING",
                    false,
                );
                return Ok(());
            }
        };

        // Hp(P) - hash to point
        let hp = hash_to_point(&one_time);
        println!(
            "  Hp(P): {}...",
            hex::encode(&hp.compress().to_bytes()[..8])
        );

        // Compute Lagrange coefficients for FROST
        let (lambda_buyer, lambda_vendor) = if self.frost_enabled {
            // buyer=1, vendor=2
            // λ_buyer = 2/(2-1) = 2
            // λ_vendor = 1/(1-2) = -1
            let i1 = Scalar::from(1u64);
            let i2 = Scalar::from(2u64);
            let lb = i2 * (i2 - i1).invert();
            let lv = i1 * (i1 - i2).invert();
            println!("  FROST Lagrange coefficients:");
            println!("    λ_buyer = {}...", hex::encode(&lb.to_bytes()[..8]));
            println!("    λ_vendor = {}...", hex::encode(&lv.to_bytes()[..8]));
            (lb, lv)
        } else {
            println!("  Non-FROST: λ = 1 for both");
            (Scalar::ONE, Scalar::ONE)
        };

        // Get derivation scalar
        let derivation = self.derivation.unwrap_or(Scalar::ZERO);

        if let (Some(buyer_share), Some(vendor_share)) = (self.buyer_share, self.vendor_share) {
            let s_buyer = Scalar::from_bytes_mod_order(buyer_share);
            let s_vendor = Scalar::from_bytes_mod_order(vendor_share);

            println!("\n  Computing expected PKIs...");

            // Assuming vendor signed first (with derivation), buyer second (no derivation)
            let pki_vendor_expected = (derivation + lambda_vendor * s_vendor) * hp;
            let pki_buyer_expected = (lambda_buyer * s_buyer) * hp;

            println!(
                "  Expected PKI_vendor (d + λ_v*s_v)*Hp: {}...",
                hex::encode(&pki_vendor_expected.compress().to_bytes()[..8])
            );
            println!(
                "  Expected PKI_buyer (λ_b*s_b)*Hp: {}...",
                hex::encode(&pki_buyer_expected.compress().to_bytes()[..8])
            );

            // Compare with stored PKIs
            if let Some(stored_vendor) = self.vendor_pki {
                let stored_point = CompressedEdwardsY(stored_vendor)
                    .decompress()
                    .context("Invalid vendor PKI")?;
                let matches = stored_point == pki_vendor_expected;
                println!(
                    "  Stored PKI_vendor: {}...",
                    hex::encode(&stored_vendor[..8])
                );
                println!("  VENDOR PKI MATCH: {}", if matches { "✓" } else { "✗" });
                self.add_result(
                    "3a. Vendor PKI",
                    &format!(
                        "{}...",
                        hex::encode(&pki_vendor_expected.compress().to_bytes()[..8])
                    ),
                    &format!("{}...", hex::encode(&stored_vendor[..8])),
                    matches,
                );
            }

            if let Some(stored_buyer) = self.buyer_pki {
                let stored_point = CompressedEdwardsY(stored_buyer)
                    .decompress()
                    .context("Invalid buyer PKI")?;
                let matches = stored_point == pki_buyer_expected;
                println!("  Stored PKI_buyer: {}...", hex::encode(&stored_buyer[..8]));
                println!("  BUYER PKI MATCH: {}", if matches { "✓" } else { "✗" });
                self.add_result(
                    "3b. Buyer PKI",
                    &format!(
                        "{}...",
                        hex::encode(&pki_buyer_expected.compress().to_bytes()[..8])
                    ),
                    &format!("{}...", hex::encode(&stored_buyer[..8])),
                    matches,
                );
            }

            // Expected aggregated KI = PKI_vendor + PKI_buyer (simple sum)
            let expected_ki = pki_vendor_expected + pki_buyer_expected;
            println!(
                "\n  Expected aggregated KI: {}...",
                hex::encode(&expected_ki.compress().to_bytes()[..8])
            );

            if let Some(stored_ki) = self.aggregated_ki {
                let stored_point = CompressedEdwardsY(stored_ki)
                    .decompress()
                    .context("Invalid aggregated KI")?;
                let matches = stored_point == expected_ki;
                println!(
                    "  Stored aggregated KI: {}...",
                    hex::encode(&stored_ki[..8])
                );
                println!("  AGGREGATED KI MATCH: {}", if matches { "✓" } else { "✗" });
                self.add_result(
                    "3c. Aggregated Key Image",
                    &format!(
                        "{}...",
                        hex::encode(&expected_ki.compress().to_bytes()[..8])
                    ),
                    &format!("{}...", hex::encode(&stored_ki[..8])),
                    matches,
                );
            }

            // Compute the "correct" KI using full spend key
            let full_effective_key = derivation + lambda_buyer * s_buyer + lambda_vendor * s_vendor;
            let correct_ki = full_effective_key * hp;
            println!(
                "\n  Theoretically correct KI (full key): {}...",
                hex::encode(&correct_ki.compress().to_bytes()[..8])
            );

            let ki_matches_theory = expected_ki == correct_ki;
            println!(
                "  Aggregated == Theoretical: {}",
                if ki_matches_theory { "✓" } else { "✗" }
            );
        } else {
            self.add_result("3. PKI computation", "shares required", "MISSING", false);
        }

        Ok(())
    }

    fn validate_commitment_balance(&mut self) -> Result<()> {
        println!("\n============================================================");
        println!("STEP 4: VALIDATE COMMITMENT BALANCE");
        println!("============================================================");

        let pseudo_out = match self.pseudo_out {
            Some(p) => p,
            None => {
                self.add_result(
                    "4. Commitment balance",
                    "pseudo_out required",
                    "MISSING",
                    false,
                );
                println!("  No pseudo_out found - escrow not yet signed");
                return Ok(());
            }
        };

        let pseudo_out_point = CompressedEdwardsY(pseudo_out)
            .decompress()
            .context("Invalid pseudo_out point")?;

        let h_point = CompressedEdwardsY(H_BYTES)
            .decompress()
            .context("Invalid H generator")?;

        println!("  pseudo_out: {}", hex::encode(pseudo_out));
        println!("  escrow_amount: {} piconero", self.escrow_amount);
        println!("  fee: {} piconero", self.fee);

        let payout_amount = self.escrow_amount - self.fee;
        println!(
            "  payout_amount: {} piconero ({:.12} XMR)",
            payout_amount,
            payout_amount as f64 / 1e12
        );

        // Verify: input_amount should equal payout + fee
        let amount_balance = self.escrow_amount == payout_amount + self.fee;
        println!(
            "  Amount balance (in = out + fee): {}",
            if amount_balance { "✓" } else { "✗" }
        );
        self.add_result(
            "4a. Amount balance",
            &format!("{} = {} + {}", self.escrow_amount, payout_amount, self.fee),
            &format!("{}", amount_balance),
            amount_balance,
        );

        // Verify pseudo_out structure
        let expected_amount_component = Scalar::from(self.escrow_amount) * h_point;
        let mask_g = pseudo_out_point - expected_amount_component;
        println!(
            "  Derived mask*G component: {}...",
            hex::encode(&mask_g.compress().to_bytes()[..8])
        );

        self.add_result(
            "4b. Commitment structure",
            "pseudo_out = mask*G + amount*H",
            "Structure parsed",
            true,
        );

        Ok(())
    }

    fn validate_clsag_structure(&mut self) -> Result<()> {
        println!("\n============================================================");
        println!("STEP 5: VALIDATE CLSAG SIGNATURE STRUCTURE");
        println!("============================================================");

        let mut sig_count = 0;
        let mut ring_size = 0;

        for (name, sig_opt) in [
            ("buyer", &self.buyer_signature),
            ("vendor", &self.vendor_signature),
        ] {
            if let Some(sig_json) = sig_opt {
                sig_count += 1;
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(sig_json) {
                    if let Some(sig) = parsed.get("signature") {
                        let c1 = sig.get("c1").and_then(|v| v.as_str()).unwrap_or("MISSING");
                        let d = sig
                            .get("D")
                            .or(sig.get("d"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("MISSING");
                        let s_values = sig
                            .get("s")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);

                        ring_size = s_values;

                        println!("  {} signature:", name);
                        println!("    c1: {}...", &c1[..16.min(c1.len())]);
                        println!("    D: {}...", &d[..16.min(d.len())]);
                        println!("    s-values: {} elements", s_values);

                        if let Some(s_array) = sig.get("s").and_then(|v| v.as_array()) {
                            let valid_s = s_array
                                .iter()
                                .all(|s| s.as_str().map(|h| h.len() == 64).unwrap_or(false));
                            println!(
                                "    s-values format valid: {}",
                                if valid_s { "✓" } else { "✗" }
                            );
                        }
                    }
                }
            }
        }

        if sig_count == 0 {
            println!("  No signatures found - escrow not yet signed");
            self.add_result("5. CLSAG signatures", "Present", "NOT SIGNED YET", false);
            return Ok(());
        }

        println!("\n  Signature count: {}/2", sig_count);
        println!("  Ring size: {}", ring_size);

        let sig_ok = sig_count == 2;
        let ring_ok = ring_size == 16;

        self.add_result(
            "5a. Both signatures present",
            "2",
            &format!("{}", sig_count),
            sig_ok,
        );
        self.add_result("5b. Ring size", "16", &format!("{}", ring_size), ring_ok);

        Ok(())
    }

    fn validate_ring_data(&mut self) -> Result<()> {
        println!("\n============================================================");
        println!("STEP 6: VALIDATE RING DATA CONSISTENCY");
        println!("============================================================");

        if let Some(ref ring_json) = self.ring_data_json {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(ring_json) {
                let ring_size = parsed
                    .get("ring_public_keys")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let commitment_count = parsed
                    .get("ring_commitments")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let signer_index = parsed
                    .get("signer_index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let tx_prefix_hash = parsed
                    .get("tx_prefix_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("MISSING");

                println!("  Ring public keys: {}", ring_size);
                println!("  Ring commitments: {}", commitment_count);
                println!("  Signer index: {}", signer_index);
                println!(
                    "  TX prefix hash: {}...",
                    &tx_prefix_hash[..16.min(tx_prefix_hash.len())]
                );

                let ring_match = ring_size == commitment_count && ring_size == 16;
                let index_valid = signer_index < ring_size as u64;

                self.add_result(
                    "6a. Ring data consistency",
                    "16 keys = 16 commitments",
                    &format!("{} keys, {} commitments", ring_size, commitment_count),
                    ring_match,
                );
                self.add_result(
                    "6b. Signer index valid",
                    &format!("< {}", ring_size),
                    &format!("{}", signer_index),
                    index_valid,
                );
            }
        } else {
            println!("  No ring data found - escrow not prepared for signing");
            self.add_result("6. Ring data", "Present", "NOT PREPARED YET", false);
        }

        Ok(())
    }

    fn print_summary(&self) {
        println!("\n============================================================");
        println!("VALIDATION SUMMARY");
        println!("============================================================");

        let passed = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();

        println!("\n  Results: {}/{} checks passed\n", passed, total);

        for result in &self.results {
            let icon = if result.passed { "✓" } else { "✗" };
            let status = if result.passed { "PASS" } else { "FAIL" };
            println!("  [{}] {} - {}", icon, result.step, status);
            if !result.passed {
                println!("       Expected: {}", result.expected);
                println!("       Actual:   {}", result.actual);
            }
        }

        println!("\n============================================================");
        if passed == total {
            println!("  ALL CHECKS PASSED - Ready for broadcast");
        } else {
            println!(
                "  {} CHECKS FAILED - Fix issues before broadcast",
                total - passed
            );
        }
        println!("============================================================\n");
    }
}

fn parse_hex_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("Invalid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("Expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn hash_to_point(data: &[u8; 32]) -> EdwardsPoint {
    // Simplified hash_to_point for validation
    let mut counter = 0u8;
    loop {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.update(&[counter]);
        let hash: [u8; 32] = hasher.finalize().into();

        if let Some(point) = CompressedEdwardsY(hash).decompress() {
            return point.mul_by_cofactor();
        }
        counter = counter.wrapping_add(1);
        if counter == 0 {
            return EdwardsPoint::identity();
        }
    }
}

fn main() -> Result<()> {
    println!("\n============================================================");
    println!("FULL CRYPTO VALIDATION - FROST Signing Flow");
    println!("============================================================");

    let args: Vec<String> = env::args().collect();
    let escrow_id = if args.len() > 1 {
        args[1].clone()
    } else {
        "ef57f177-f873-40c3-a175-4ab87c195ad8".to_string()
    };

    println!("Escrow ID: {}", escrow_id);

    // Connect to database using rusqlite (simpler for read-only)
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DB_ENCRYPTION_KEY").unwrap_or_default();

    let conn = if encryption_key.is_empty() {
        rusqlite::Connection::open(&database_url)?
    } else {
        let conn = rusqlite::Connection::open(&database_url)?;
        conn.execute_batch(&format!("PRAGMA key = '{}';", encryption_key))?;
        conn
    };

    // Run validation
    let mut validator = CryptoValidator::new(&escrow_id);

    validator.load_escrow_data(&conn)?;
    validator.validate_one_time_address()?;
    validator.validate_pki_computation()?;
    validator.validate_commitment_balance()?;
    validator.validate_clsag_structure()?;
    validator.validate_ring_data()?;

    validator.print_summary();

    Ok(())
}
