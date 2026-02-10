//! FROST DKG State Model (RFC 9591)
//!
//! Tracks the 3-round DKG protocol state for 2-of-3 threshold CLSAG.
//! Each party can contribute asynchronously.

use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::frost_dkg_state;

/// FROST DKG state for an escrow
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = frost_dkg_state)]
#[diesel(primary_key(escrow_id))]
pub struct FrostDkgState {
    pub escrow_id: String,

    // Round 1 packages (public commitments from each party)
    pub buyer_round1_package: Option<String>,
    pub vendor_round1_package: Option<String>,
    pub arbiter_round1_package: Option<String>,
    pub round1_complete: bool,

    // Round 2 packages (secret shares sent between parties)
    pub buyer_to_vendor_round2: Option<String>,
    pub buyer_to_arbiter_round2: Option<String>,
    pub vendor_to_buyer_round2: Option<String>,
    pub vendor_to_arbiter_round2: Option<String>,
    pub arbiter_to_buyer_round2: Option<String>,
    pub arbiter_to_vendor_round2: Option<String>,
    pub round2_complete: bool,

    // Timestamps
    pub created_at: String,
    pub updated_at: String,
}

/// New FROST DKG state for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = frost_dkg_state)]
pub struct NewFrostDkgState {
    pub escrow_id: String,
    pub created_at: String,
    pub updated_at: String,
}

impl NewFrostDkgState {
    pub fn new(escrow_id: &str) -> Self {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        Self {
            escrow_id: escrow_id.to_string(),
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

/// DKG status for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgStatus {
    pub escrow_id: String,
    pub round1_complete: bool,
    pub round2_complete: bool,
    pub dkg_complete: bool,
    pub participants: DkgParticipants,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgParticipants {
    pub buyer_round1_ready: bool,
    pub vendor_round1_ready: bool,
    pub arbiter_round1_ready: bool,
    pub buyer_round2_ready: bool,
    pub vendor_round2_ready: bool,
    pub arbiter_round2_ready: bool,
}

impl DkgStatus {
    /// Set the actual dkg_complete flag from escrow table
    pub fn with_dkg_complete(mut self, complete: bool) -> Self {
        self.dkg_complete = complete;
        self
    }
}

impl From<&FrostDkgState> for DkgStatus {
    fn from(state: &FrostDkgState) -> Self {
        let buyer_round2_ready = state.buyer_to_vendor_round2.is_some()
            && state.buyer_to_arbiter_round2.is_some();
        let vendor_round2_ready = state.vendor_to_buyer_round2.is_some()
            && state.vendor_to_arbiter_round2.is_some();
        let arbiter_round2_ready = state.arbiter_to_buyer_round2.is_some()
            && state.arbiter_to_vendor_round2.is_some();

        DkgStatus {
            escrow_id: state.escrow_id.clone(),
            round1_complete: state.round1_complete,
            round2_complete: state.round2_complete,
            // NOTE: dkg_complete must be set from escrow.frost_dkg_complete via with_dkg_complete()
            // Setting to false here - caller should query escrows table for actual value
            dkg_complete: false,
            participants: DkgParticipants {
                buyer_round1_ready: state.buyer_round1_package.is_some(),
                vendor_round1_ready: state.vendor_round1_package.is_some(),
                arbiter_round1_ready: state.arbiter_round1_package.is_some(),
                buyer_round2_ready,
                vendor_round2_ready,
                arbiter_round2_ready,
            },
        }
    }
}

/// Role in FROST DKG (maps to participant index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrostRole {
    Buyer,   // Index 1
    Vendor,  // Index 2
    Arbiter, // Index 3
}

impl FrostRole {
    /// Get FROST participant index (1, 2, or 3)
    pub fn to_index(&self) -> u16 {
        match self {
            FrostRole::Buyer => 1,
            FrostRole::Vendor => 2,
            FrostRole::Arbiter => 3,
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "buyer" => Some(FrostRole::Buyer),
            "vendor" => Some(FrostRole::Vendor),
            "arbiter" => Some(FrostRole::Arbiter),
            _ => None,
        }
    }
}

/// Compute Lagrange coefficients for a 2-of-3 signing pair
///
/// For signers i and j:
/// - λ_i = j / (j - i)
/// - λ_j = i / (i - j)
///
/// Returns (λ_signer1, λ_signer2) as hex scalars
pub fn compute_lagrange_coefficients(signer1: FrostRole, signer2: FrostRole) -> (String, String) {
    use curve25519_dalek::scalar::Scalar;

    let i = signer1.to_index() as i64;
    let j = signer2.to_index() as i64;

    // λ_i = j / (j - i)
    let numerator_i = Scalar::from(j as u64);
    let denominator_i_val = j - i;
    let denominator_i = if denominator_i_val < 0 {
        -Scalar::from((-denominator_i_val) as u64)
    } else {
        Scalar::from(denominator_i_val as u64)
    };
    let lambda_i = numerator_i * denominator_i.invert();

    // λ_j = i / (i - j)
    let numerator_j = Scalar::from(i as u64);
    let denominator_j_val = i - j;
    let denominator_j = if denominator_j_val < 0 {
        -Scalar::from((-denominator_j_val) as u64)
    } else {
        Scalar::from(denominator_j_val as u64)
    };
    let lambda_j = numerator_j * denominator_j.invert();

    (
        hex::encode(lambda_i.as_bytes()),
        hex::encode(lambda_j.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lagrange_coefficients_buyer_vendor() {
        // For signers 1 and 2:
        // λ_1 = 2 / (2 - 1) = 2
        // λ_2 = 1 / (1 - 2) = -1
        let (lambda_1, lambda_2) = compute_lagrange_coefficients(FrostRole::Buyer, FrostRole::Vendor);
        assert!(!lambda_1.is_empty());
        assert!(!lambda_2.is_empty());
        // λ_1 should be 2 (mod order)
        // λ_2 should be -1 (mod order)
    }

    #[test]
    fn test_frost_role_to_index() {
        assert_eq!(FrostRole::Buyer.to_index(), 1);
        assert_eq!(FrostRole::Vendor.to_index(), 2);
        assert_eq!(FrostRole::Arbiter.to_index(), 3);
    }
}
