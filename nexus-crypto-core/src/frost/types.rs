//! FROST DKG Type Definitions
//!
//! Serialization-friendly types for FROST DKG rounds.

use alloc::collections::BTreeMap;
use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Result from DKG Round 1
///
/// Contains the public package to share with other participants
/// and the secret package to keep locally for Round 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound1Result {
    /// Public package to share with other participants (hex encoded)
    pub round1_package: String,
    /// Secret package to keep locally for Round 2 (hex encoded)
    ///
    /// **SECURITY**: Store this encrypted or in secure memory!
    pub secret_package: String,
}

/// Result from DKG Round 2
///
/// Contains packages to send to each other participant
/// and secret material for Round 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound2Result {
    /// Packages to send to each other participant (participant_id -> hex package)
    ///
    /// Each participant receives a unique package encrypted for them.
    pub round2_packages: BTreeMap<String, String>,
    /// Secret material for Round 3 (hex encoded)
    ///
    /// **SECURITY**: Store this encrypted or in secure memory!
    pub round2_secret: String,
}

/// Result from DKG Round 3 (finalization)
///
/// Contains the final key share and group public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgFinalResult {
    /// The participant's secret key package (hex encoded)
    ///
    /// **CRITICAL SECURITY**: Store this encrypted! This is your signing capability.
    pub key_package: String,
    /// The group's public key (hex encoded, same for all participants)
    ///
    /// This is the public key for the threshold signature scheme.
    /// All participants derive the same group public key.
    pub group_public_key: String,
    /// The participant's public verifying share (hex encoded)
    ///
    /// Used to verify partial signatures from this participant.
    pub verifying_share: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_round1_result_serialization() {
        let result = DkgRound1Result {
            round1_package: "deadbeef".to_string(),
            secret_package: "cafebabe".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: DkgRound1Result = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.round1_package, result.round1_package);
        assert_eq!(parsed.secret_package, result.secret_package);
    }

    #[test]
    fn test_dkg_round2_result_serialization() {
        let mut packages = BTreeMap::new();
        packages.insert("2".to_string(), "package_for_2".to_string());
        packages.insert("3".to_string(), "package_for_3".to_string());

        let result = DkgRound2Result {
            round2_packages: packages,
            round2_secret: "secret_data".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: DkgRound2Result = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.round2_packages.len(), 2);
        assert_eq!(
            parsed.round2_packages.get("2"),
            Some(&"package_for_2".to_string())
        );
    }

    #[test]
    fn test_dkg_final_result_serialization() {
        let result = DkgFinalResult {
            key_package: "key_package_hex".to_string(),
            group_public_key: "group_pubkey_hex".to_string(),
            verifying_share: "verifying_share_hex".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: DkgFinalResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.key_package, result.key_package);
        assert_eq!(parsed.group_public_key, result.group_public_key);
        assert_eq!(parsed.verifying_share, result.verifying_share);
    }
}
