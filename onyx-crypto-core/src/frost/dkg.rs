//! FROST DKG Implementation
//!
//! Pure-Rust implementation of FROST Distributed Key Generation (RFC 9591).
//! This module provides the core DKG functionality without WASM dependencies.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

use frost_ed25519::{
    keys::{
        dkg::{self, round1, round2},
        KeyPackage,
    },
    Identifier,
};
use rand_core::{CryptoRng, RngCore};

/// A simple RNG wrapper using getrandom for no_std compatibility.
struct GetrandomRng;

impl RngCore for GetrandomRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|e| {
            // rand_core::Error requires NonZeroU32, use getrandom's error code
            rand_core::Error::from(
                core::num::NonZeroU32::new(e.code().get())
                    .unwrap_or(core::num::NonZeroU32::new(1).unwrap()),
            )
        })
    }
}

impl CryptoRng for GetrandomRng {}

use crate::types::errors::{CryptoError, CryptoResult};

use super::types::{DkgFinalResult, DkgRound1Result, DkgRound2Result};

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
///
/// # Returns
/// * `Ok(DkgRound1Result)` - Contains round1_package and secret_package (hex encoded)
/// * `Err(CryptoError)` - If parameters are invalid
///
/// # Example
/// ```rust,ignore
/// let result = dkg_part1(1, 2, 3)?;
/// // Share result.round1_package with other participants
/// // Keep result.secret_package locally (encrypted!)
/// ```
pub fn dkg_part1(
    participant_index: u16,
    threshold: u16,
    max_signers: u16,
) -> CryptoResult<DkgRound1Result> {
    // Validate inputs
    if participant_index < 1 || participant_index > max_signers {
        return Err(CryptoError::FrostDkgError(format!(
            "participant_index must be 1-{}, got {}",
            max_signers, participant_index
        )));
    }
    if threshold < 2 || threshold > max_signers {
        return Err(CryptoError::FrostDkgError(format!(
            "threshold must be 2-{}, got {}",
            max_signers, threshold
        )));
    }

    // Create identifier for this participant
    let identifier = Identifier::try_from(participant_index)
        .map_err(|e| CryptoError::FrostDkgError(format!("Invalid identifier: {:?}", e)))?;

    // Generate Round 1 package
    let (round1_secret, round1_package) =
        dkg::part1(identifier, max_signers, threshold, &mut GetrandomRng)
            .map_err(|e| CryptoError::FrostDkgError(format!("DKG Round 1 failed: {:?}", e)))?;

    // Serialize for storage/transmission
    let secret_bytes = round1_secret.serialize().map_err(|e| {
        CryptoError::SerializationError(format!("Failed to serialize secret: {:?}", e))
    })?;
    let package_bytes = round1_package.serialize().map_err(|e| {
        CryptoError::SerializationError(format!("Failed to serialize package: {:?}", e))
    })?;

    Ok(DkgRound1Result {
        round1_package: hex::encode(&package_bytes),
        secret_package: hex::encode(&secret_bytes),
    })
}

/// DKG Round 2: Compute secret shares from OTHER participants' Round 1 packages
///
/// Called after all participants have submitted their Round 1 packages.
///
/// # Arguments
/// * `secret_package_hex` - The secret_package from dkg_part1 (hex)
/// * `all_round1_packages` - All participants' Round 1 packages: { "1": "hex...", "2": "hex...", "3": "hex..." }
///
/// # Returns
/// * `Ok(DkgRound2Result)` - Contains round2_packages for each recipient and round2_secret
/// * `Err(CryptoError)` - If deserialization or computation fails
///
/// # Security
/// The returned `round2_secret` must be stored securely (encrypted) for Round 3.
pub fn dkg_part2(
    secret_package_hex: &str,
    all_round1_packages: &BTreeMap<String, String>,
) -> CryptoResult<DkgRound2Result> {
    // Deserialize secret package
    let secret_bytes = hex::decode(secret_package_hex).map_err(|e| {
        CryptoError::HexDecodeFailed(format!("Invalid secret_package hex: {:?}", e))
    })?;
    let round1_secret = round1::SecretPackage::deserialize(&secret_bytes).map_err(|e| {
        CryptoError::DeserializationError(format!("Failed to deserialize secret: {:?}", e))
    })?;

    // Parse all round1 packages
    let mut round1_packages: BTreeMap<Identifier, round1::Package> = BTreeMap::new();

    for (id_str, pkg_hex) in all_round1_packages {
        let id_num: u16 = id_str.parse().map_err(|_| {
            CryptoError::FrostDkgError(format!("Invalid participant ID: {}", id_str))
        })?;
        let identifier = Identifier::try_from(id_num).map_err(|e| {
            CryptoError::FrostDkgError(format!("Invalid identifier {}: {:?}", id_num, e))
        })?;

        let pkg_bytes = hex::decode(pkg_hex).map_err(|e| {
            CryptoError::HexDecodeFailed(format!("Invalid package hex for {}: {:?}", id_str, e))
        })?;
        let package = round1::Package::deserialize(&pkg_bytes).map_err(|e| {
            CryptoError::DeserializationError(format!(
                "Failed to deserialize package {}: {:?}",
                id_str, e
            ))
        })?;

        round1_packages.insert(identifier, package);
    }

    // Execute Round 2
    let (round2_secret, round2_packages) = dkg::part2(round1_secret, &round1_packages)
        .map_err(|e| CryptoError::FrostDkgError(format!("DKG Round 2 failed: {:?}", e)))?;

    // Serialize Round 2 packages for each recipient
    let mut packages_out: BTreeMap<String, String> = BTreeMap::new();
    for (recipient_id, package) in round2_packages {
        let id_bytes = recipient_id.serialize();
        let id_num = u16::from_le_bytes([id_bytes[0], id_bytes[1]]);
        let pkg_bytes = package.serialize().map_err(|e| {
            CryptoError::SerializationError(format!("Failed to serialize round2 package: {:?}", e))
        })?;
        packages_out.insert(id_num.to_string(), hex::encode(&pkg_bytes));
    }

    // Serialize secret for Round 3
    let secret_bytes = round2_secret.serialize().map_err(|e| {
        CryptoError::SerializationError(format!("Failed to serialize round2 secret: {:?}", e))
    })?;

    Ok(DkgRound2Result {
        round2_packages: packages_out,
        round2_secret: hex::encode(&secret_bytes),
    })
}

/// DKG Round 3: Finalize and get KeyPackage
///
/// Called after receiving Round 2 packages from other participants.
///
/// # Arguments
/// * `round2_secret_hex` - The round2_secret from dkg_part2 (hex)
/// * `round1_packages` - All Round 1 packages: { "1": "hex...", "2": "hex...", "3": "hex..." }
/// * `round2_packages` - Round 2 packages received from others: { "1": "hex...", "2": "hex..." }
///
/// # Returns
/// * `Ok(DkgFinalResult)` - Contains key_package, group_public_key, and verifying_share
/// * `Err(CryptoError)` - If finalization fails
///
/// # Security
/// The `key_package` in the result is the signing secret. Store it encrypted!
pub fn dkg_part3(
    round2_secret_hex: &str,
    round1_packages: &BTreeMap<String, String>,
    round2_packages: &BTreeMap<String, String>,
) -> CryptoResult<DkgFinalResult> {
    // Deserialize Round 2 secret
    let secret_bytes = hex::decode(round2_secret_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid round2_secret hex: {:?}", e)))?;
    let round2_secret = round2::SecretPackage::deserialize(&secret_bytes).map_err(|e| {
        CryptoError::DeserializationError(format!("Failed to deserialize round2 secret: {:?}", e))
    })?;

    // Parse Round 1 packages
    let mut r1_packages: BTreeMap<Identifier, round1::Package> = BTreeMap::new();
    for (id_str, pkg_hex) in round1_packages {
        let id_num: u16 = id_str
            .parse()
            .map_err(|_| CryptoError::FrostDkgError("Invalid ID".to_string()))?;
        let identifier = Identifier::try_from(id_num)
            .map_err(|_| CryptoError::FrostDkgError("Invalid identifier".to_string()))?;
        let pkg_bytes = hex::decode(pkg_hex)
            .map_err(|_| CryptoError::HexDecodeFailed("Invalid hex".to_string()))?;
        let package = round1::Package::deserialize(&pkg_bytes)
            .map_err(|_| CryptoError::DeserializationError("Deserialize failed".to_string()))?;
        r1_packages.insert(identifier, package);
    }

    // Parse Round 2 packages
    let mut r2_packages: BTreeMap<Identifier, round2::Package> = BTreeMap::new();
    for (id_str, pkg_hex) in round2_packages {
        let id_num: u16 = id_str
            .parse()
            .map_err(|_| CryptoError::FrostDkgError("Invalid ID".to_string()))?;
        let identifier = Identifier::try_from(id_num)
            .map_err(|_| CryptoError::FrostDkgError("Invalid identifier".to_string()))?;
        let pkg_bytes = hex::decode(pkg_hex)
            .map_err(|_| CryptoError::HexDecodeFailed("Invalid hex".to_string()))?;
        let package = round2::Package::deserialize(&pkg_bytes)
            .map_err(|_| CryptoError::DeserializationError("Deserialize failed".to_string()))?;
        r2_packages.insert(identifier, package);
    }

    // Execute Round 3 - finalize
    let (key_package, public_key_package) = dkg::part3(&round2_secret, &r1_packages, &r2_packages)
        .map_err(|e| CryptoError::FrostDkgError(format!("DKG Round 3 failed: {:?}", e)))?;

    // Serialize results
    let key_pkg_bytes = key_package.serialize().map_err(|e| {
        CryptoError::SerializationError(format!("Failed to serialize key_package: {:?}", e))
    })?;

    let group_key_bytes = public_key_package
        .verifying_key()
        .serialize()
        .map_err(|e| {
            CryptoError::SerializationError(format!("Failed to serialize group key: {:?}", e))
        })?;

    let verifying_share_bytes = key_package.verifying_share().serialize().map_err(|e| {
        CryptoError::SerializationError(format!("Failed to serialize verifying share: {:?}", e))
    })?;

    Ok(DkgFinalResult {
        key_package: hex::encode(&key_pkg_bytes),
        group_public_key: hex::encode(&group_key_bytes),
        verifying_share: hex::encode(&verifying_share_bytes),
    })
}

/// Extract the secret share scalar from a KeyPackage
///
/// Returns the raw 32-byte secret share as hex, suitable for use in CLSAG signing.
///
/// # Arguments
/// * `key_package_hex` - The hex-encoded KeyPackage from DKG Round 3
///
/// # Returns
/// * `Ok(String)` - The 64-character hex string of the secret share scalar
/// * `Err(CryptoError)` - If deserialization fails
///
/// # Security
/// This exposes the raw secret scalar. Handle with extreme care!
pub fn extract_secret_share(key_package_hex: &str) -> CryptoResult<String> {
    let key_bytes = hex::decode(key_package_hex)
        .map_err(|e| CryptoError::HexDecodeFailed(format!("Invalid key_package hex: {:?}", e)))?;
    let key_package = KeyPackage::deserialize(&key_bytes).map_err(|e| {
        CryptoError::DeserializationError(format!("Failed to deserialize key_package: {:?}", e))
    })?;

    // Get the signing share (secret scalar)
    let signing_share = key_package.signing_share();
    let share_bytes = signing_share.serialize();

    Ok(hex::encode(&share_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_part1_invalid_participant_index() {
        let result = dkg_part1(0, 2, 3);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::FrostDkgError(_))));
    }

    #[test]
    fn test_dkg_part1_invalid_threshold() {
        let result = dkg_part1(1, 1, 3); // threshold must be >= 2
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::FrostDkgError(_))));
    }

    #[test]
    fn test_dkg_part1_valid() {
        let result = dkg_part1(1, 2, 3);
        assert!(result.is_ok());
        let round1 = result.unwrap();
        assert!(!round1.round1_package.is_empty());
        assert!(!round1.secret_package.is_empty());
    }

    #[test]
    fn test_full_dkg_round_trip() {
        // Round 1 for all 3 participants
        let r1_p1 = dkg_part1(1, 2, 3).expect("R1 P1");
        let r1_p2 = dkg_part1(2, 2, 3).expect("R1 P2");
        let r1_p3 = dkg_part1(3, 2, 3).expect("R1 P3");

        // Collect all round1 packages (for reference)
        let mut all_r1 = BTreeMap::new();
        all_r1.insert("1".to_string(), r1_p1.round1_package.clone());
        all_r1.insert("2".to_string(), r1_p2.round1_package.clone());
        all_r1.insert("3".to_string(), r1_p3.round1_package.clone());

        // Round 2: Each participant needs ONLY OTHER participants' packages
        // Participant 1 needs packages from 2 and 3
        let mut other_r1_for_p1 = BTreeMap::new();
        other_r1_for_p1.insert("2".to_string(), r1_p2.round1_package.clone());
        other_r1_for_p1.insert("3".to_string(), r1_p3.round1_package.clone());

        // Participant 2 needs packages from 1 and 3
        let mut other_r1_for_p2 = BTreeMap::new();
        other_r1_for_p2.insert("1".to_string(), r1_p1.round1_package.clone());
        other_r1_for_p2.insert("3".to_string(), r1_p3.round1_package.clone());

        // Participant 3 needs packages from 1 and 2
        let mut other_r1_for_p3 = BTreeMap::new();
        other_r1_for_p3.insert("1".to_string(), r1_p1.round1_package.clone());
        other_r1_for_p3.insert("2".to_string(), r1_p2.round1_package.clone());

        let r2_p1 = dkg_part2(&r1_p1.secret_package, &other_r1_for_p1).expect("R2 P1");
        let r2_p2 = dkg_part2(&r1_p2.secret_package, &other_r1_for_p2).expect("R2 P2");
        let r2_p3 = dkg_part2(&r1_p3.secret_package, &other_r1_for_p3).expect("R2 P3");

        // Collect round2 packages for participant 1 (from 2 and 3)
        let mut r2_for_p1 = BTreeMap::new();
        r2_for_p1.insert(
            "2".to_string(),
            r2_p2.round2_packages.get("1").unwrap().clone(),
        );
        r2_for_p1.insert(
            "3".to_string(),
            r2_p3.round2_packages.get("1").unwrap().clone(),
        );

        // Round 3 for participant 1 (uses OTHER participants' R1 packages)
        let result_p1 =
            dkg_part3(&r2_p1.round2_secret, &other_r1_for_p1, &r2_for_p1).expect("R3 P1");

        // Verify we got a valid result
        assert!(!result_p1.key_package.is_empty());
        assert!(!result_p1.group_public_key.is_empty());
        assert!(!result_p1.verifying_share.is_empty());

        // Extract secret share
        let secret_share = extract_secret_share(&result_p1.key_package).expect("Extract share");
        assert_eq!(secret_share.len(), 64); // 32 bytes = 64 hex chars

        // Complete DKG for participant 2 and verify same group public key
        let mut r2_for_p2 = BTreeMap::new();
        r2_for_p2.insert(
            "1".to_string(),
            r2_p1.round2_packages.get("2").unwrap().clone(),
        );
        r2_for_p2.insert(
            "3".to_string(),
            r2_p3.round2_packages.get("2").unwrap().clone(),
        );

        let result_p2 =
            dkg_part3(&r2_p2.round2_secret, &other_r1_for_p2, &r2_for_p2).expect("R3 P2");

        // Group public key should be identical for all participants
        assert_eq!(
            result_p1.group_public_key, result_p2.group_public_key,
            "Group public keys must match"
        );
    }

    #[test]
    fn test_extract_secret_share_invalid_hex() {
        let result = extract_secret_share("not_valid_hex_at_all!");
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::HexDecodeFailed(_))));
    }
}
