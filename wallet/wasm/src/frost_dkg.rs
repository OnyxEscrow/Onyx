//! FROST Distributed Key Generation (RFC 9591) for 2-of-3 Threshold CLSAG
//!
//! This module implements FROST DKG to generate unique secret shares without overlap.
//! Unlike Monero's native multisig where shares overlap (causing CLSAG failures),
//! FROST uses Shamir Secret Sharing with Lagrange interpolation.
//!
//! ## Why FROST Solves the Overlap Problem
//!
//! ```text
//! Monero Native:  (k1+k2) + (k2+k3) = k1 + 2*k2 + k3  <- k2 DOUBLE-COUNTED!
//! FROST:          λ₁*s₁ + λ₂*s₂ = x_reconstructed     <- NO OVERLAP!
//! ```
//!
//! ## DKG Flow (Async - each party can participate independently)
//!
//! ```text
//! Phase 1: Each party calls frost_dkg_part1() -> round1_package (public) + secret_package (local)
//! Phase 2: Server collects all 3 round1_packages, each party calls frost_dkg_part2()
//! Phase 3: Each party calls frost_dkg_part3() -> KeyPackage (secret share) + GroupPublicKey
//! ```

use frost_ed25519::{
    keys::{
        dkg::{self, round1, round2},
        KeyPackage, PublicKeyPackage,
    },
    Identifier,
};
use rand_core::OsRng;
use serde::ser::Serialize as SerializeTrait; // For explicit .serialize() calls
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Result from DKG Round 1
#[derive(Serialize, Deserialize)]
pub struct DkgRound1Result {
    /// Public package to share with other participants (hex encoded)
    pub round1_package: String,
    /// Secret package to keep locally for Round 2 (hex encoded)
    pub secret_package: String,
}

/// Result from DKG Round 2
#[derive(Serialize, Deserialize)]
pub struct DkgRound2Result {
    /// Packages to send to each other participant (participant_id -> hex package)
    pub round2_packages: std::collections::HashMap<String, String>,
    /// Secret material for Round 3 (hex encoded)
    pub round2_secret: String,
}

/// Result from DKG Round 3 (finalization)
#[derive(Serialize, Deserialize)]
pub struct DkgFinalResult {
    /// The participant's secret key package (hex encoded, store encrypted!)
    pub key_package: String,
    /// The group's public key (hex encoded, same for all participants)
    pub group_public_key: String,
    /// The participant's public verifying share (hex encoded)
    pub verifying_share: String,
}

/// DKG Round 1: Generate commitment and secret polynomial
///
/// Each participant calls this independently. Returns:
/// - `round1_package`: Public data to share with all other participants
/// - `secret_package`: Private data to keep locally for Round 2
///
/// # Arguments
/// * `participant_index` - 1, 2, or 3 (buyer=1, vendor=2, arbiter=3)
/// * `threshold` - Minimum signers required (always 2 for 2-of-3)
/// * `max_signers` - Total number of signers (always 3)
#[wasm_bindgen]
pub fn frost_dkg_part1(
    participant_index: u16,
    threshold: u16,
    max_signers: u16,
) -> Result<JsValue, JsValue> {
    // Validate inputs
    if participant_index < 1 || participant_index > max_signers {
        return Err(JsValue::from_str(&format!(
            "participant_index must be 1-{}, got {}",
            max_signers, participant_index
        )));
    }
    if threshold < 2 || threshold > max_signers {
        return Err(JsValue::from_str(&format!(
            "threshold must be 2-{}, got {}",
            max_signers, threshold
        )));
    }

    // Create identifier for this participant
    let identifier = Identifier::try_from(participant_index)
        .map_err(|e| JsValue::from_str(&format!("Invalid identifier: {:?}", e)))?;

    // Generate Round 1 package
    let (round1_secret, round1_package) =
        dkg::part1(identifier, max_signers, threshold, &mut OsRng)
            .map_err(|e| JsValue::from_str(&format!("DKG Round 1 failed: {:?}", e)))?;

    // Serialize for storage/transmission
    let secret_bytes = round1_secret
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize secret: {:?}", e)))?;
    let package_bytes = round1_package
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize package: {:?}", e)))?;

    let result = DkgRound1Result {
        round1_package: hex::encode(&package_bytes),
        secret_package: hex::encode(&secret_bytes),
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
}

/// DKG Round 2: Compute secret shares from OTHER participants' Round 1 packages
///
/// Called after all participants have submitted their Round 1 packages.
///
/// # Arguments
/// * `secret_package_hex` - The secret_package from frost_dkg_part1 (hex)
/// * `other_round1_packages_json` - JSON with ONLY OTHER participants: { "2": "hex...", "3": "hex..." }
///                                   (exclude your own package - it's in secret_package)
#[wasm_bindgen]
pub fn frost_dkg_part2(
    secret_package_hex: &str,
    all_round1_packages_json: &str,
) -> Result<JsValue, JsValue> {
    // Deserialize secret package
    let secret_bytes = hex::decode(secret_package_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret_package hex: {:?}", e)))?;
    let round1_secret = round1::SecretPackage::deserialize(&secret_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize secret: {:?}", e)))?;

    // Parse all round1 packages
    let packages_map: std::collections::HashMap<String, String> =
        serde_json::from_str(all_round1_packages_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {:?}", e)))?;

    let mut round1_packages: std::collections::BTreeMap<Identifier, round1::Package> =
        std::collections::BTreeMap::new();

    for (id_str, pkg_hex) in packages_map {
        let id_num: u16 = id_str
            .parse()
            .map_err(|_| JsValue::from_str(&format!("Invalid participant ID: {}", id_str)))?;
        let identifier = Identifier::try_from(id_num)
            .map_err(|e| JsValue::from_str(&format!("Invalid identifier {}: {:?}", id_num, e)))?;

        let pkg_bytes = hex::decode(&pkg_hex).map_err(|e| {
            JsValue::from_str(&format!("Invalid package hex for {}: {:?}", id_str, e))
        })?;
        let package = round1::Package::deserialize(&pkg_bytes).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize package {}: {:?}",
                id_str, e
            ))
        })?;

        round1_packages.insert(identifier, package);
    }

    // Execute Round 2
    let (round2_secret, round2_packages) = dkg::part2(round1_secret, &round1_packages)
        .map_err(|e| JsValue::from_str(&format!("DKG Round 2 failed: {:?}", e)))?;

    // Serialize Round 2 packages for each recipient
    let mut packages_out: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (recipient_id, package) in round2_packages {
        let id_bytes = recipient_id.serialize();
        let id_num = u16::from_le_bytes([id_bytes[0], id_bytes[1]]);
        let pkg_bytes = package.serialize().map_err(|e| {
            JsValue::from_str(&format!("Failed to serialize round2 package: {:?}", e))
        })?;
        packages_out.insert(id_num.to_string(), hex::encode(&pkg_bytes));
    }

    // Serialize secret for Round 3
    let secret_bytes = round2_secret
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize round2 secret: {:?}", e)))?;

    let result = DkgRound2Result {
        round2_packages: packages_out,
        round2_secret: hex::encode(&secret_bytes),
    };

    // CRITICAL: Use serialize_maps_as_objects(true) so HashMap becomes a plain JS Object
    // not a JS Map (which JSON.stringify converts to {})
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    result
        .serialize(&serializer)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
}

/// DKG Round 3: Finalize and get KeyPackage
///
/// Called after receiving Round 2 packages from other participants.
///
/// # Arguments
/// * `round2_secret_hex` - The round2_secret from frost_dkg_part2 (hex)
/// * `round1_packages_json` - All Round 1 packages: { "1": "hex...", "2": "hex...", "3": "hex..." }
/// * `round2_packages_json` - Round 2 packages received from others: { "1": "hex...", "2": "hex..." }
#[wasm_bindgen]
pub fn frost_dkg_part3(
    round2_secret_hex: &str,
    round1_packages_json: &str,
    round2_packages_json: &str,
) -> Result<JsValue, JsValue> {
    // Deserialize Round 2 secret
    let secret_bytes = hex::decode(round2_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid round2_secret hex: {:?}", e)))?;
    let round2_secret = round2::SecretPackage::deserialize(&secret_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize round2 secret: {:?}", e)))?;

    // Parse Round 1 packages
    let r1_map: std::collections::HashMap<String, String> =
        serde_json::from_str(round1_packages_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid round1 JSON: {:?}", e)))?;

    let mut round1_packages: std::collections::BTreeMap<Identifier, round1::Package> =
        std::collections::BTreeMap::new();

    for (id_str, pkg_hex) in r1_map {
        let id_num: u16 = id_str
            .parse()
            .map_err(|_| JsValue::from_str("Invalid ID"))?;
        let identifier =
            Identifier::try_from(id_num).map_err(|_| JsValue::from_str("Invalid identifier"))?;
        let pkg_bytes = hex::decode(&pkg_hex).map_err(|_| JsValue::from_str("Invalid hex"))?;
        let package = round1::Package::deserialize(&pkg_bytes)
            .map_err(|_| JsValue::from_str("Deserialize failed"))?;
        round1_packages.insert(identifier, package);
    }

    // Parse Round 2 packages
    let r2_map: std::collections::HashMap<String, String> =
        serde_json::from_str(round2_packages_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid round2 JSON: {:?}", e)))?;

    let mut round2_packages: std::collections::BTreeMap<Identifier, round2::Package> =
        std::collections::BTreeMap::new();

    for (id_str, pkg_hex) in r2_map {
        let id_num: u16 = id_str
            .parse()
            .map_err(|_| JsValue::from_str("Invalid ID"))?;
        let identifier =
            Identifier::try_from(id_num).map_err(|_| JsValue::from_str("Invalid identifier"))?;
        let pkg_bytes = hex::decode(&pkg_hex).map_err(|_| JsValue::from_str("Invalid hex"))?;
        let package = round2::Package::deserialize(&pkg_bytes)
            .map_err(|_| JsValue::from_str("Deserialize failed"))?;
        round2_packages.insert(identifier, package);
    }

    // Execute Round 3 - finalize
    let (key_package, public_key_package) =
        dkg::part3(&round2_secret, &round1_packages, &round2_packages)
            .map_err(|e| JsValue::from_str(&format!("DKG Round 3 failed: {:?}", e)))?;

    // Serialize results
    let key_pkg_bytes = key_package
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize key_package: {:?}", e)))?;

    let group_key_bytes = public_key_package
        .verifying_key()
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize group key: {:?}", e)))?;

    let verifying_share_bytes = key_package
        .verifying_share()
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize verifying share: {:?}", e)))?;

    let result = DkgFinalResult {
        key_package: hex::encode(&key_pkg_bytes),
        group_public_key: hex::encode(&group_key_bytes),
        verifying_share: hex::encode(&verifying_share_bytes),
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
}

/// Extract the secret share scalar from a KeyPackage
///
/// Returns the raw 32-byte secret share as hex, suitable for use in CLSAG signing.
#[wasm_bindgen]
pub fn frost_extract_secret_share(key_package_hex: &str) -> Result<String, JsValue> {
    let key_bytes = hex::decode(key_package_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid key_package hex: {:?}", e)))?;
    let key_package = KeyPackage::deserialize(&key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize key_package: {:?}", e)))?;

    // Get the signing share (secret scalar)
    let signing_share = key_package.signing_share();
    let share_bytes = signing_share.serialize();

    Ok(hex::encode(&share_bytes))
}

/// Compute Lagrange coefficient for a signer in a signing session
///
/// For 2-of-3 threshold signing, the Lagrange coefficient determines how to
/// reconstruct the group secret from the participating shares.
///
/// # Arguments
/// * `signer_index` - The index of the signer (1, 2, or 3)
/// * `all_signer_indices` - Array of all participating signer indices (e.g., [1, 2])
///
/// # Returns
/// The Lagrange coefficient as a 32-byte hex scalar
#[wasm_bindgen]
pub fn frost_compute_lagrange_coefficient(
    signer_index: u16,
    signer1_index: u16,
    signer2_index: u16,
) -> Result<String, JsValue> {
    use curve25519_dalek::scalar::Scalar;

    // Validate indices
    if signer_index != signer1_index && signer_index != signer2_index {
        return Err(JsValue::from_str(&format!(
            "signer_index {} must be one of the participating indices [{}, {}]",
            signer_index, signer1_index, signer2_index
        )));
    }

    // Compute Lagrange coefficient: λ_i = ∏(0 - j) / (i - j) for j ≠ i
    // For 2-of-3 with indices i and j participating:
    // λ_i = (0 - j) / (i - j) = -j / (i - j) = j / (j - i)

    let i = signer_index as i64;
    let j = if signer_index == signer1_index {
        signer2_index
    } else {
        signer1_index
    } as i64;

    // λ_i = j / (j - i)
    // In scalar field: λ_i = j * inverse(j - i)

    let numerator = Scalar::from(j as u64);
    let denominator_val = j - i;

    let denominator = if denominator_val < 0 {
        -Scalar::from((-denominator_val) as u64)
    } else {
        Scalar::from(denominator_val as u64)
    };

    let denominator_inv = denominator.invert();
    let lambda = numerator * denominator_inv;

    Ok(hex::encode(lambda.as_bytes()))
}

/// Get the participant index from a role string
#[wasm_bindgen]
pub fn frost_role_to_index(role: &str) -> Result<u16, JsValue> {
    match role.to_lowercase().as_str() {
        "buyer" => Ok(1),
        "vendor" => Ok(2),
        "arbiter" => Ok(3),
        _ => Err(JsValue::from_str(&format!("Unknown role: {}", role))),
    }
}

/// Result from deriving FROST escrow address
#[derive(Serialize, Deserialize)]
pub struct FrostAddressResult {
    /// The Monero address (95 characters, starts with network-specific prefix)
    pub address: String,
    /// The shared view private key (hex, 64 chars) - needed for blockchain monitoring
    pub view_key_private: String,
    /// The view public key (hex, 64 chars)
    pub view_key_public: String,
    /// The network used for address generation
    pub network: String,
}

/// Derive Monero address and shared view key for a FROST escrow
///
/// The spend public key is the group_pubkey from DKG.
/// The view key is deterministically derived from the escrow_id and group_pubkey,
/// ensuring all participants compute the same keys.
///
/// # Arguments
/// * `group_pubkey_hex` - The group public key from DKG (64 hex chars = 32 bytes)
/// * `escrow_id` - The escrow identifier (used as domain separator)
/// * `network` - Optional network: "mainnet", "stagenet", "testnet". Defaults to "mainnet".
///
/// # Returns
/// * `address` - The Monero address for this FROST escrow
/// * `view_key_private` - The shared view key (hex) - used for blockchain monitoring
/// * `view_key_public` - The view public key (hex)
/// * `network` - The network used
#[wasm_bindgen]
pub fn frost_derive_address(
    group_pubkey_hex: &str,
    escrow_id: &str,
    network: Option<String>,
) -> Result<JsValue, JsValue> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use sha3::{Digest, Keccak256};

    // Parse network (default to mainnet for production safety)
    let network_str = network.as_deref().unwrap_or("mainnet");
    let network_byte =
        crate::network_string_to_byte(network_str).map_err(|e| JsValue::from_str(&e))?;

    // Parse group public key (spend key)
    let group_pubkey_bytes = hex::decode(group_pubkey_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid group_pubkey hex: {:?}", e)))?;

    if group_pubkey_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "group_pubkey must be 32 bytes, got {}",
            group_pubkey_bytes.len()
        )));
    }

    // Derive shared view key: view_priv = Hs("frost_escrow_view_key" || escrow_id || group_pubkey)
    // This is deterministic - all participants derive the same key
    let mut view_hasher = Keccak256::new();
    view_hasher.update(b"frost_escrow_view_key");
    view_hasher.update(escrow_id.as_bytes());
    view_hasher.update(&group_pubkey_bytes);
    let view_hash: [u8; 32] = view_hasher.finalize().into();

    // Reduce to valid scalar (Monero convention)
    let view_scalar = Scalar::from_bytes_mod_order(view_hash);
    let view_priv_bytes = view_scalar.to_bytes();

    // Compute view public key: view_pub = view_priv * G
    let view_public = ED25519_BASEPOINT_TABLE * &view_scalar;
    let view_pub_bytes = view_public.compress().to_bytes();

    // Generate Monero address with explicit network
    let mut spend_pub_array = [0u8; 32];
    spend_pub_array.copy_from_slice(&group_pubkey_bytes);

    let address = crate::generate_monero_address_with_network(
        &spend_pub_array,
        &view_pub_bytes,
        network_byte,
    )
    .map_err(|e| JsValue::from_str(&format!("Address generation failed: {}", e)))?;

    let result = FrostAddressResult {
        address,
        view_key_private: hex::encode(view_priv_bytes),
        view_key_public: hex::encode(view_pub_bytes),
        network: network_str.to_string(),
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ed25519::keys::dkg;

    #[test]
    fn test_lagrange_coefficients() {
        // For 2-of-3 with signers 1 and 2:
        // λ_1 = 2 / (2 - 1) = 2
        // λ_2 = 1 / (1 - 2) = 1 / (-1) = -1

        let lambda1 = frost_compute_lagrange_coefficient(1, 1, 2).unwrap();
        let lambda2 = frost_compute_lagrange_coefficient(2, 1, 2).unwrap();

        println!("λ_1 = {}", lambda1);
        println!("λ_2 = {}", lambda2);

        // Verify reconstruction: λ_1 * s_1 + λ_2 * s_2 should equal the group secret
        // when s_1 and s_2 are proper Shamir shares
    }

    /// Test that frost_extract_secret_share produces a scalar that
    /// when multiplied by G, equals the verifying_share
    #[test]
    fn test_frost_secret_share_matches_verifying_share() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        use rand_core::OsRng;

        // Generate a complete 3-party DKG
        let threshold = 2;
        let max_signers = 3;

        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        let id3 = Identifier::try_from(3u16).unwrap();

        // Round 1: Each participant generates commitment
        let (r1_secret_1, r1_pkg_1) = dkg::part1(id1, max_signers, threshold, &mut OsRng).unwrap();
        let (r1_secret_2, r1_pkg_2) = dkg::part1(id2, max_signers, threshold, &mut OsRng).unwrap();
        let (r1_secret_3, r1_pkg_3) = dkg::part1(id3, max_signers, threshold, &mut OsRng).unwrap();

        // All round 1 packages (for reference later)
        let mut all_r1_pkgs = std::collections::BTreeMap::new();
        all_r1_pkgs.insert(id1, r1_pkg_1.clone());
        all_r1_pkgs.insert(id2, r1_pkg_2.clone());
        all_r1_pkgs.insert(id3, r1_pkg_3.clone());

        // Round 2: Each participant computes packages for others
        // part2 takes our secret + all OTHER participants' round1 packages
        let mut other_r1_for_1 = std::collections::BTreeMap::new();
        other_r1_for_1.insert(id2, r1_pkg_2.clone());
        other_r1_for_1.insert(id3, r1_pkg_3.clone());

        let mut other_r1_for_2 = std::collections::BTreeMap::new();
        other_r1_for_2.insert(id1, r1_pkg_1.clone());
        other_r1_for_2.insert(id3, r1_pkg_3.clone());

        let mut other_r1_for_3 = std::collections::BTreeMap::new();
        other_r1_for_3.insert(id1, r1_pkg_1.clone());
        other_r1_for_3.insert(id2, r1_pkg_2.clone());

        let (r2_secret_1, r2_pkgs_1) = dkg::part2(r1_secret_1, &other_r1_for_1).unwrap();
        let (r2_secret_2, r2_pkgs_2) = dkg::part2(r1_secret_2, &other_r1_for_2).unwrap();
        let (r2_secret_3, r2_pkgs_3) = dkg::part2(r1_secret_3, &other_r1_for_3).unwrap();

        // Round 3: Participant 1 finalizes
        // part3 takes: round2_secret, ALL round1 packages (except own), round2 packages FOR ME
        let mut r2_for_1 = std::collections::BTreeMap::new();
        r2_for_1.insert(id2, r2_pkgs_2.get(&id1).unwrap().clone());
        r2_for_1.insert(id3, r2_pkgs_3.get(&id1).unwrap().clone());

        let (key_package_1, _pub_pkg_1) =
            dkg::part3(&r2_secret_1, &other_r1_for_1, &r2_for_1).unwrap();

        // Now test our extraction function
        // Serialize key_package
        let key_pkg_bytes = key_package_1.serialize().unwrap();
        let key_pkg_hex = hex::encode(&key_pkg_bytes);

        // Extract secret share using our function
        let extracted_share_hex = frost_extract_secret_share(&key_pkg_hex).unwrap();
        let extracted_share_bytes = hex::decode(&extracted_share_hex).unwrap();

        // Get verifying share
        let verifying_share_bytes = key_package_1.verifying_share().serialize().unwrap();
        let verifying_share_hex = hex::encode(&verifying_share_bytes);

        println!("Extracted secret share: {}", extracted_share_hex);
        println!("Verifying share:        {}", verifying_share_hex);

        // Convert extracted share to curve25519-dalek Scalar
        let mut share_arr = [0u8; 32];
        share_arr.copy_from_slice(&extracted_share_bytes);
        let share_scalar = Scalar::from_bytes_mod_order(share_arr);

        // Compute share * G
        let computed_pubkey = &*ED25519_BASEPOINT_TABLE * &share_scalar;
        let computed_pubkey_bytes = computed_pubkey.compress().to_bytes();
        let computed_pubkey_hex = hex::encode(&computed_pubkey_bytes);

        println!("Computed pubkey (share * G): {}", computed_pubkey_hex);

        // They should match!
        assert_eq!(
            computed_pubkey_hex, verifying_share_hex,
            "ERROR: extracted_share * G != verifying_share!\n\
             This means frost_extract_secret_share returns incorrect data!"
        );

        println!("✅ SUCCESS: extracted_share * G == verifying_share");
    }

    // Note: frost_derive_address test requires wasm-bindgen environment
    // Use wasm-pack test --headless --chrome to run this test
    #[cfg(target_arch = "wasm32")]
    mod wasm_tests {
        use super::*;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[wasm_bindgen_test]
        fn test_frost_derive_address() {
            let group_pubkey = "0000000000000000000000000000000000000000000000000000000000000001";
            let escrow_id = "escrow_test_123";

            let result = frost_derive_address(group_pubkey, escrow_id);
            assert!(result.is_ok(), "Address derivation should succeed");
        }
    }
}
