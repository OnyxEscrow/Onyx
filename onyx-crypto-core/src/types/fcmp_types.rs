//! FCMP++ specific types for Onyx.
//!
//! These types represent the new FCMP++ proof system constructs
//! that replace CLSAG ring signatures.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Re-randomized output for FCMP++ membership proofs.
///
/// K' = K + a*T  (re-randomized output key)
/// I' = H(K) + b*U  (re-randomized hash point)
/// B  = b*V  (blinding factor opening)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RerandomizedOutput {
    /// Original output key K (compressed Edwards point, 32 bytes)
    pub output_key: [u8; 32],
    /// Re-randomized output key K' = K + a*T
    pub rerandomized_key: [u8; 32],
    /// Re-randomized hash point I' = H(K) + b*U
    pub rerandomized_hash: [u8; 32],
    /// Blinding opening B = b*V
    pub blinding_opening: [u8; 32],
    /// Pedersen commitment C (may be re-randomized)
    pub commitment: [u8; 32],
}

/// GSP partial signature from a threshold signer.
///
/// Contains response scalars for the 3 scalar positions (x, a, b)
/// in the GSP matrix proof.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct GspPartialSignature {
    /// Signer identifier (1-indexed)
    pub signer_index: u8,
    /// Partial response for spend key: z_x_i = r_x_i + c * lambda_i * x_i
    pub z_x: [u8; 32],
    /// Partial response for output re-randomization: z_a_i = r_a_i + c * lambda_i * a_i
    pub z_a: [u8; 32],
    /// Partial response for key image blinding: z_b_i = r_b_i + c * lambda_i * b_i
    pub z_b: [u8; 32],
}

/// GSP nonce commitment triple for a single signer.
///
/// In the 2-round GSP protocol, each signer generates nonces
/// for each scalar position and publishes commitments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GspNonceCommitment {
    /// Signer identifier
    pub signer_index: u8,
    /// R_x = r_x * G (spend key nonce commitment)
    pub r_x_commitment: [u8; 32],
    /// R_a = r_a * T (re-randomization nonce commitment)
    pub r_a_commitment: [u8; 32],
    /// R_b = r_b * V (blinding nonce commitment)
    pub r_b_commitment: [u8; 32],
}

/// Aggregated GSP nonce commitments from all participating signers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedGspNonces {
    /// Combined R_x = sum(R_x_i)
    pub combined_r_x: [u8; 32],
    /// Combined R_a = sum(R_a_i)
    pub combined_r_a: [u8; 32],
    /// Combined R_b = sum(R_b_i)
    pub combined_r_b: [u8; 32],
}

/// Complete GSP proof (Spend Authorization + Linkability).
///
/// This replaces ClsagSignature in the FCMP++ world.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GspProof {
    /// Aggregated response scalar z_x
    pub z_x: [u8; 32],
    /// Aggregated response scalar z_a
    pub z_a: [u8; 32],
    /// Aggregated response scalar z_b
    pub z_b: [u8; 32],
    /// Challenge scalar c
    pub challenge: [u8; 32],
    /// Key image (nullifier): I = x * H(K)
    pub key_image: [u8; 32],
}

/// FCMP++ membership proof (M-proof).
///
/// Proves that a re-randomized output exists in the global
/// Curve Tree without revealing which leaf.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FcmpMembershipProof {
    /// Serialized GBP circuit proof bytes
    pub proof_bytes: Vec<u8>,
    /// Tree root hash at the time of proving
    pub tree_root: [u8; 32],
    /// Reference block height (tree state anchor)
    pub reference_block: u64,
}

/// Complete FCMP++ transaction proof (M-proof + SA+L).
///
/// This is the full replacement for a CLSAG ring signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FcmpTransactionProof {
    /// Membership proof (proves output exists in chain)
    pub membership: FcmpMembershipProof,
    /// Spend authorization + linkability proof
    pub sal: GspProof,
    /// Re-randomized output data
    pub rerandomized: RerandomizedOutput,
}

/// GSP signing session state.
///
/// Tracks the state of a 2-round threshold GSP signing session
/// for escrow coordination.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GspSigningState {
    /// Waiting for nonce commitments (Round 1)
    AwaitingNonces {
        /// Nonce commitments received so far
        received: Vec<GspNonceCommitment>,
        /// Required number of signers (threshold)
        threshold: u8,
    },
    /// Waiting for partial signatures (Round 2)
    AwaitingSignatures {
        /// Aggregated nonces for this session
        aggregated_nonces: AggregatedGspNonces,
        /// Partial signatures received so far
        received: Vec<GspPartialSignature>,
        /// Required number of signers
        threshold: u8,
    },
    /// Signing complete
    Complete {
        /// Final aggregated GSP proof
        proof: GspProof,
    },
    /// Signing aborted (identifiable abort)
    Aborted {
        /// Index of the misbehaving signer
        faulty_signer: u8,
        /// Reason for abort
        reason: &'static str,
    },
}
