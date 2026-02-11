//! Multisig State Persistence Models
//!
//! Production-grade state management for multisig wallet setup with crash recovery.
//!
//! # Architecture
//! - Persistent state snapshots in DB
//! - Automatic recovery on restart
//! - Stuck escrow detection via timestamps
//! - JSON serialization for flexibility
//!
//! # Security
//! - Sensitive data (multisig_info) encrypted before storage
//! - No plaintext keys in snapshots
//! - Audit trail via phase transitions

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Multisig setup phase states
///
/// Represents the current stage of multisig wallet initialization.
/// Each phase corresponds to specific Monero RPC calls required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MultisigPhase {
    /// Initial state - no setup started
    NotStarted,

    /// Participants are calling prepare_multisig()
    ///
    /// Each participant must generate their multisig_info string.
    /// Progress tracked via `completed` list.
    Preparing {
        /// Roles that have completed preparation: ["buyer", "vendor", "arbiter"]
        completed: Vec<String>,
    },

    /// Participants are exchanging multisig info via make_multisig() and sync rounds
    ///
    /// This phase may require multiple rounds of info exchange.
    /// Round 1: initial make_multisig with all participant infos
    /// Round 2+: export_multisig_info + import_multisig_info cycles
    Exchanging {
        /// Current exchange round (1-based, typically 1-2 rounds for 2-of-3)
        round: u8,

        /// Participant multisig info strings (base64 encoded, encrypted in DB)
        /// Key format: "buyer", "vendor", "arbiter"
        infos: HashMap<String, String>,
    },

    /// Multisig setup complete and verified
    ///
    /// Wallet is ready for transactions. Address generated and validated.
    Ready {
        /// Final multisig address for escrow deposits
        address: String,

        /// Unix timestamp when finalization completed
        finalized_at: i64,
    },

    /// Setup failed - requires manual intervention or retry
    ///
    /// Triggers alert systems and prevents further automatic processing.
    Failed {
        /// Human-readable error description
        reason: String,

        /// Unix timestamp of failure
        failed_at: i64,
    },
}

impl MultisigPhase {
    /// Convert phase to database string representation
    ///
    /// Used for the `multisig_phase` TEXT column for efficient indexing.
    pub fn as_db_string(&self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Preparing { .. } => "preparing",
            Self::Exchanging { .. } => "exchanging",
            Self::Ready { .. } => "ready",
            Self::Failed { .. } => "failed",
        }
    }

    /// Serialize phase to JSON for storage
    ///
    /// # Errors
    /// Returns error if serialization fails (should never happen with valid data)
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("Failed to serialize MultisigPhase")
    }

    /// Deserialize phase from JSON
    ///
    /// # Errors
    /// Returns error if JSON is malformed or doesn't match schema
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("Failed to deserialize MultisigPhase")
    }

    /// Check if phase allows state transitions
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Ready { .. } | Self::Failed { .. })
    }

    /// Get human-readable status description
    pub fn status_description(&self) -> String {
        match self {
            Self::NotStarted => "Multisig setup not started".to_string(),
            Self::Preparing { completed } => {
                format!(
                    "Preparing multisig ({}/3 participants ready)",
                    completed.len()
                )
            }
            Self::Exchanging { round, infos } => {
                format!(
                    "Exchanging multisig info - Round {} ({}/3 infos collected)",
                    round,
                    infos.len()
                )
            }
            Self::Ready { address, .. } => {
                format!("Multisig ready - Address: {}...", &address[..8])
            }
            Self::Failed { reason, .. } => format!("Setup failed: {reason}"),
        }
    }
}

/// Complete snapshot of multisig state for recovery
///
/// Contains all information needed to reconstruct WalletManager state after restart.
/// Stored as JSON in `escrows.multisig_state_json`.
///
/// # Security Note
/// The `multisig_infos` field contains sensitive cryptographic data.
/// This should be encrypted before DB storage using project encryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSnapshot {
    /// Current phase (duplicates escrows.multisig_phase for convenience)
    pub phase: MultisigPhase,

    /// Mapping of role to wallet UUID
    ///
    /// Example: {"buyer": "uuid-1", "vendor": "uuid-2", "arbiter": "uuid-3"}
    /// Used to rebuild WalletInstance map in WalletManager
    pub wallet_ids: HashMap<String, Uuid>,

    /// Mapping of role to Monero RPC URL
    ///
    /// Example: {"buyer": "http://127.0.0.1:18082", ...}
    /// Required to reconnect to wallet RPC on recovery
    pub rpc_urls: HashMap<String, String>,

    /// Optional: Encrypted multisig info blobs for each participant
    ///
    /// Only populated during Exchanging phase if persistence is needed.
    /// Format: HashMap<role, encrypted_multisig_info_base64>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multisig_infos: Option<HashMap<String, Vec<u8>>>,

    /// Snapshot version for future schema migrations
    pub version: u8,
}

impl MultisigSnapshot {
    /// Create a new snapshot with required fields
    pub fn new(
        phase: MultisigPhase,
        wallet_ids: HashMap<String, Uuid>,
        rpc_urls: HashMap<String, String>,
    ) -> Self {
        Self {
            phase,
            wallet_ids,
            rpc_urls,
            multisig_infos: None,
            version: 1, // Schema version
        }
    }

    /// Serialize to JSON for DB storage
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("Failed to serialize MultisigSnapshot")
    }

    /// Deserialize from JSON
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("Failed to deserialize MultisigSnapshot")
    }

    /// Validate snapshot integrity
    ///
    /// Ensures snapshot has consistent state (e.g., all 3 roles present)
    pub fn validate(&self) -> Result<()> {
        // Check we have exactly 3 participants (buyer, vendor, arbiter)
        let expected_roles = vec!["buyer", "vendor", "arbiter"];
        for role in &expected_roles {
            if !self.wallet_ids.contains_key(*role) {
                anyhow::bail!("Missing wallet_id for role: {role}");
            }
            if !self.rpc_urls.contains_key(*role) {
                anyhow::bail!("Missing rpc_url for role: {role}");
            }
        }

        // Phase-specific validation
        match &self.phase {
            MultisigPhase::Preparing { completed } => {
                for role in completed {
                    if !expected_roles.contains(&role.as_str()) {
                        anyhow::bail!("Invalid role in Preparing phase: {role}");
                    }
                }
            }
            MultisigPhase::Exchanging { round, infos } => {
                if *round == 0 {
                    anyhow::bail!("Exchange round must be >= 1");
                }
                for role in infos.keys() {
                    if !expected_roles.contains(&role.as_str()) {
                        anyhow::bail!("Invalid role in Exchanging phase: {role}");
                    }
                }
            }
            MultisigPhase::Ready { address, .. } => {
                if address.is_empty() {
                    anyhow::bail!("Ready phase must have non-empty address");
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_serialization() {
        let phase = MultisigPhase::Preparing {
            completed: vec!["buyer".to_string(), "vendor".to_string()],
        };

        let json = phase.to_json().unwrap();
        let deserialized = MultisigPhase::from_json(&json).unwrap();

        assert_eq!(phase, deserialized);
        assert_eq!(phase.as_db_string(), "preparing");
    }

    #[test]
    fn test_snapshot_validation() {
        let mut wallet_ids = HashMap::new();
        wallet_ids.insert("buyer".to_string(), Uuid::new_v4());
        wallet_ids.insert("vendor".to_string(), Uuid::new_v4());
        wallet_ids.insert("arbiter".to_string(), Uuid::new_v4());

        let mut rpc_urls = HashMap::new();
        rpc_urls.insert("buyer".to_string(), "http://127.0.0.1:18082".to_string());
        rpc_urls.insert("vendor".to_string(), "http://127.0.0.1:18083".to_string());
        rpc_urls.insert("arbiter".to_string(), "http://127.0.0.1:18084".to_string());

        let snapshot = MultisigSnapshot::new(MultisigPhase::NotStarted, wallet_ids, rpc_urls);

        assert!(snapshot.validate().is_ok());
    }

    #[test]
    fn test_snapshot_invalid_missing_role() {
        let mut wallet_ids = HashMap::new();
        wallet_ids.insert("buyer".to_string(), Uuid::new_v4());
        // Missing vendor and arbiter

        let rpc_urls = HashMap::new();

        let snapshot = MultisigSnapshot::new(MultisigPhase::NotStarted, wallet_ids, rpc_urls);

        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn test_phase_terminal_states() {
        assert!(MultisigPhase::Ready {
            address: "4xxx".to_string(),
            finalized_at: 123456,
        }
        .is_terminal());

        assert!(MultisigPhase::Failed {
            reason: "timeout".to_string(),
            failed_at: 123456,
        }
        .is_terminal());

        assert!(!MultisigPhase::NotStarted.is_terminal());
        assert!(!MultisigPhase::Preparing { completed: vec![] }.is_terminal());
    }

    #[test]
    fn test_status_description() {
        let phase = MultisigPhase::Exchanging {
            round: 2,
            infos: HashMap::from([
                ("buyer".to_string(), "info1".to_string()),
                ("vendor".to_string(), "info2".to_string()),
            ]),
        };

        let desc = phase.status_description();
        assert!(desc.contains("Round 2"));
        assert!(desc.contains("2/3"));
    }
}
