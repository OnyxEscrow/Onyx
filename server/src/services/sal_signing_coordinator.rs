//! SA+L Signing Coordinator — FCMP++ 2-round parallel FROST protocol.
//!
//! This coordinator replaces the sequential CLSAG signing from
//! `frost_signing_coordinator.rs` with the parallel SA+L signing protocol
//! from `monero-fcmp-plus-plus`.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────┐  Round 1: nonces  ┌──────────┐  Round 1: nonces  ┌──────────┐
//! │ Signer A ├──────────────────►│          │◄──────────────────┤ Signer B │
//! │ (buyer)  │                   │  Server  │                   │ (vendor) │
//! │          │◄──────────────────┤  (relay) ├──────────────────►│          │
//! │          │  both nonces      │          │  both nonces      │          │
//! │          │                   │          │                   │          │
//! │          │  Round 2: partial │          │  Round 2: partial │          │
//! │          ├──────────────────►│          │◄──────────────────┤          │
//! └──────────┘                   │          │                   └──────────┘
//!                                │ aggregate│
//!                                │  verify  │
//!                                │broadcast │
//!                                └──────────┘
//! ```
//!
//! ## Key Properties
//!
//! 1. **Non-custodial**: Server never sees secret keys or nonce secrets.
//!    Only commitments (public nonces) and partial signatures (public shares).
//!
//! 2. **Identifiable Abort**: If a signer submits an invalid partial signature,
//!    `modular_frost::complete()` identifies the faulty participant via
//!    `FrostError::InvalidShare(participant)`.
//!
//! 3. **Clean Rollback**: Each round has a timeout. If one signer fails to
//!    submit, the session is rolled back to the previous state. No partial
//!    state leaks.
//!
//! 4. **Parallel Rounds**: Both signers submit simultaneously in each round.
//!    No sequential ordering required.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

// =============================================================================
// Types
// =============================================================================

/// Signing session state machine.
///
/// ```text
/// Created → Round1Active → Round1Complete → Round2Active → Round2Complete → Finalized
///    │           │               │               │               │
///    └───────────┴───────────────┴───────────────┴───────────────┘
///                            (→ Failed / TimedOut)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SalSigningState {
    /// Session created, waiting for signers to submit nonces.
    Created,
    /// At least one signer has submitted round 1 nonces.
    Round1Active,
    /// Both signers have submitted round 1 nonces.
    Round1Complete,
    /// At least one signer has submitted round 2 partial signature.
    Round2Active,
    /// Both signers have submitted — aggregation pending.
    Round2Complete,
    /// SA+L proof verified and TX broadcast.
    Finalized,
    /// Session failed (timeout, invalid share, network error).
    Failed,
    /// Session timed out waiting for a signer.
    TimedOut,
}

impl std::fmt::Display for SalSigningState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Round1Active => write!(f, "round1_active"),
            Self::Round1Complete => write!(f, "round1_complete"),
            Self::Round2Active => write!(f, "round2_active"),
            Self::Round2Complete => write!(f, "round2_complete"),
            Self::Finalized => write!(f, "finalized"),
            Self::Failed => write!(f, "failed"),
            Self::TimedOut => write!(f, "timed_out"),
        }
    }
}

/// A signer's round 1 submission (FROST preprocess output).
///
/// Contains the public nonce commitments — the nonce *secrets*
/// never leave the signer's device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalRound1Submission {
    /// Signer role (buyer=1, vendor=2, arbiter=3).
    pub signer_index: u16,
    /// Hex-encoded FROST preprocess bytes (nonce commitments).
    /// This is the serialized output of `PreprocessMachine::preprocess()`.
    pub preprocess_hex: String,
}

/// A signer's round 2 submission (FROST partial signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalRound2Submission {
    /// Signer role.
    pub signer_index: u16,
    /// Hex-encoded FROST signature share bytes.
    /// This is the serialized output of `SignMachine::sign()`.
    pub share_hex: String,
}

/// Data needed by signers to construct the SA+L algorithm locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalSigningData {
    /// Transaction hash that binds the proof to this specific TX.
    pub signable_tx_hash: String,
    /// Hex-encoded re-randomized output (serialized `RerandomizedOutput`).
    pub rerandomized_output_hex: String,
    /// The escrow's multisig public key (hex, 32 bytes).
    pub multisig_pubkey: String,
    /// Recipient address for fund release.
    pub recipient_address: String,
    /// Amount in atomic units.
    pub amount_atomic: String,
    /// Which signers are participating (e.g., [1, 2] for buyer+vendor).
    pub signer_indices: Vec<u16>,
}

/// Status response for the signing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalSigningStatus {
    /// Current state of the signing session.
    pub state: SalSigningState,
    /// Which signers have submitted round 1 nonces.
    pub round1_submitted: Vec<u16>,
    /// Which signers have submitted round 2 shares.
    pub round2_submitted: Vec<u16>,
    /// TX hash if finalized.
    pub tx_hash: Option<String>,
    /// Error message if failed.
    pub error: Option<String>,
    /// Identified faulty signer if blame detected.
    pub blame_signer: Option<u16>,
}

/// In-memory signing session (stored in DB as JSON blob).
///
/// The server holds ONLY public data: nonce commitments and partial
/// signatures. It never sees nonce secrets or signing keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalSigningSession {
    /// Escrow ID this signing session belongs to.
    pub escrow_id: String,
    /// Current state.
    pub state: SalSigningState,
    /// Participating signer indices (exactly 2 for 2-of-3).
    pub signers: Vec<u16>,
    /// Round 1 submissions (nonce commitments).
    pub round1: Vec<SalRound1Submission>,
    /// Round 2 submissions (partial signatures).
    pub round2: Vec<SalRound2Submission>,
    /// Signing data provided to clients.
    pub signing_data: SalSigningData,
    /// TX hash if broadcast succeeded.
    pub tx_hash: Option<String>,
    /// Error details if session failed.
    pub error: Option<String>,
    /// Faulty signer index if blame identified.
    pub blame_signer: Option<u16>,
    /// Serialized FCMP membership proof (hex-encoded `Fcmp::write()` output).
    ///
    /// Submitted by the prover (typically the client that generated the
    /// membership proof via WASM) after SA+L signing completes.
    /// The membership proof covers all inputs simultaneously.
    pub membership_proof_hex: Option<String>,
    /// Serialized root_blind_pok (hex-encoded, 64 bytes).
    pub root_blind_pok_hex: Option<String>,
    /// Client-computed `Fcmp::proof_size(inputs, layers) - 64`.
    /// Stored at submission time, used by `attach_fcmp_proof()` for size validation.
    pub expected_proof_len: Option<usize>,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
    /// Last update timestamp (ISO 8601).
    pub updated_at: String,
}

// =============================================================================
// Coordinator
// =============================================================================

/// SA+L Signing Coordinator.
///
/// Manages the 2-round FROST signing protocol for FCMP++ escrow transactions.
/// The coordinator is stateless — all session state is stored in the database.
pub struct SalSigningCoordinator;

impl SalSigningCoordinator {
    /// Initialize a new SA+L signing session.
    ///
    /// # Arguments
    /// * `escrow_id` - The escrow this signing session is for
    /// * `signers` - Exactly 2 signer indices (from {1=buyer, 2=vendor, 3=arbiter})
    /// * `signing_data` - Transaction data for signers
    ///
    /// # Returns
    /// The initial signing session (state = Created).
    pub fn init_session(
        escrow_id: &str,
        signers: &[u16],
        signing_data: SalSigningData,
    ) -> Result<SalSigningSession> {
        // Validate: exactly 2 signers for 2-of-3 threshold
        if signers.len() != 2 {
            anyhow::bail!(
                "SA+L signing requires exactly 2 signers, got {}",
                signers.len()
            );
        }

        // Validate signer indices are in {1, 2, 3}
        for &idx in signers {
            if !(1..=3).contains(&idx) {
                anyhow::bail!("Invalid signer index: {} (must be 1-3)", idx);
            }
        }

        // No duplicate signers
        if signers[0] == signers[1] {
            anyhow::bail!("Duplicate signer index: {}", signers[0]);
        }

        let now = chrono::Utc::now().to_rfc3339();

        let session = SalSigningSession {
            escrow_id: escrow_id.to_string(),
            state: SalSigningState::Created,
            signers: signers.to_vec(),
            round1: Vec::new(),
            round2: Vec::new(),
            signing_data,
            tx_hash: None,
            error: None,
            blame_signer: None,
            membership_proof_hex: None,
            root_blind_pok_hex: None,
            expected_proof_len: None,
            created_at: now.clone(),
            updated_at: now,
        };

        info!(
            escrow_id = %escrow_id,
            signers = ?signers,
            "SA+L signing session initialized"
        );

        Ok(session)
    }

    /// Submit round 1 nonces (FROST preprocess).
    ///
    /// Both signers call this independently. When the second signer submits,
    /// the state advances to `Round1Complete` and both signers can retrieve
    /// all nonce commitments to proceed to round 2.
    ///
    /// # Rollback Safety
    /// If only one signer submits within the timeout, the session can be
    /// rolled back to `Created` state. No nonce secrets are exposed because
    /// the server only receives public commitments.
    pub fn submit_round1(
        session: &mut SalSigningSession,
        submission: SalRound1Submission,
    ) -> Result<bool> {
        // State check: must be Created or Round1Active
        match session.state {
            SalSigningState::Created | SalSigningState::Round1Active => {}
            other => {
                anyhow::bail!(
                    "Cannot submit round 1 in state '{}' (expected created or round1_active)",
                    other
                );
            }
        }

        // Validate signer is a participant
        if !session.signers.contains(&submission.signer_index) {
            anyhow::bail!(
                "Signer {} is not a participant in this session (participants: {:?})",
                submission.signer_index,
                session.signers
            );
        }

        // Check for duplicate submission
        if session.round1.iter().any(|s| s.signer_index == submission.signer_index) {
            anyhow::bail!(
                "Signer {} already submitted round 1 nonces",
                submission.signer_index
            );
        }

        // Validate preprocess data is non-empty hex
        if submission.preprocess_hex.is_empty() {
            anyhow::bail!("Round 1 preprocess data cannot be empty");
        }
        hex::decode(&submission.preprocess_hex)
            .context("Round 1 preprocess data is not valid hex")?;

        session.round1.push(submission.clone());
        session.updated_at = chrono::Utc::now().to_rfc3339();

        let all_submitted = session.round1.len() == session.signers.len();
        if all_submitted {
            session.state = SalSigningState::Round1Complete;
            info!(
                escrow_id = %session.escrow_id,
                "SA+L round 1 complete — both nonces received"
            );
        } else {
            session.state = SalSigningState::Round1Active;
            debug!(
                escrow_id = %session.escrow_id,
                signer = submission.signer_index,
                "SA+L round 1 nonce received ({}/{})",
                session.round1.len(),
                session.signers.len()
            );
        }

        Ok(all_submitted)
    }

    /// Retrieve all round 1 nonce commitments.
    ///
    /// Called by each signer after round 1 is complete. Returns all
    /// nonce commitments so the signer can proceed to round 2.
    pub fn get_round1_commitments(
        session: &SalSigningSession,
    ) -> Result<Vec<SalRound1Submission>> {
        match session.state {
            SalSigningState::Round1Complete
            | SalSigningState::Round2Active
            | SalSigningState::Round2Complete => {}
            other => {
                anyhow::bail!(
                    "Round 1 commitments not available in state '{}' (need round1_complete+)",
                    other
                );
            }
        }

        Ok(session.round1.clone())
    }

    /// Submit round 2 partial signature (FROST sign).
    ///
    /// Both signers call this independently after receiving round 1 commitments.
    /// When the second signer submits, the state advances to `Round2Complete`.
    ///
    /// # Rollback Safety
    /// If only one signer submits within the timeout, the session can be
    /// rolled back. The partial signature is useless without the other share
    /// (threshold property).
    pub fn submit_round2(
        session: &mut SalSigningSession,
        submission: SalRound2Submission,
    ) -> Result<bool> {
        // State check: must be Round1Complete or Round2Active
        match session.state {
            SalSigningState::Round1Complete | SalSigningState::Round2Active => {}
            other => {
                anyhow::bail!(
                    "Cannot submit round 2 in state '{}' (expected round1_complete or round2_active)",
                    other
                );
            }
        }

        // Validate signer is a participant
        if !session.signers.contains(&submission.signer_index) {
            anyhow::bail!(
                "Signer {} is not a participant in this session",
                submission.signer_index
            );
        }

        // Check for duplicate submission
        if session.round2.iter().any(|s| s.signer_index == submission.signer_index) {
            anyhow::bail!(
                "Signer {} already submitted round 2 share",
                submission.signer_index
            );
        }

        // Validate share data is non-empty hex
        if submission.share_hex.is_empty() {
            anyhow::bail!("Round 2 share data cannot be empty");
        }
        hex::decode(&submission.share_hex)
            .context("Round 2 share data is not valid hex")?;

        session.round2.push(submission.clone());
        session.updated_at = chrono::Utc::now().to_rfc3339();

        let all_submitted = session.round2.len() == session.signers.len();
        if all_submitted {
            session.state = SalSigningState::Round2Complete;
            info!(
                escrow_id = %session.escrow_id,
                "SA+L round 2 complete — both shares received, ready to aggregate"
            );
        } else {
            session.state = SalSigningState::Round2Active;
            debug!(
                escrow_id = %session.escrow_id,
                signer = submission.signer_index,
                "SA+L round 2 share received ({}/{})",
                session.round2.len(),
                session.signers.len()
            );
        }

        Ok(all_submitted)
    }

    /// Retrieve all round 2 shares for aggregation.
    pub fn get_round2_shares(
        session: &SalSigningSession,
    ) -> Result<Vec<SalRound2Submission>> {
        if session.state != SalSigningState::Round2Complete {
            anyhow::bail!(
                "Round 2 shares not ready in state '{}' (need round2_complete)",
                session.state
            );
        }

        Ok(session.round2.clone())
    }

    /// Mark session as finalized with a TX hash.
    ///
    /// Called after the SA+L proof is verified and the TX is broadcast.
    pub fn finalize(session: &mut SalSigningSession, tx_hash: &str) -> Result<()> {
        if session.state != SalSigningState::Round2Complete {
            anyhow::bail!(
                "Cannot finalize in state '{}' (need round2_complete)",
                session.state
            );
        }

        session.state = SalSigningState::Finalized;
        session.tx_hash = Some(tx_hash.to_string());
        session.updated_at = chrono::Utc::now().to_rfc3339();

        info!(
            escrow_id = %session.escrow_id,
            tx_hash = %tx_hash,
            "SA+L signing session finalized — TX broadcast"
        );

        Ok(())
    }

    /// Mark session as failed with an error.
    ///
    /// Optionally identifies the faulty signer (blame).
    pub fn fail(
        session: &mut SalSigningSession,
        error: &str,
        blame_signer: Option<u16>,
    ) {
        session.state = SalSigningState::Failed;
        session.error = Some(error.to_string());
        session.blame_signer = blame_signer;
        session.updated_at = chrono::Utc::now().to_rfc3339();

        if let Some(faulty) = blame_signer {
            error!(
                escrow_id = %session.escrow_id,
                blame_signer = faulty,
                error = %error,
                "SA+L signing failed — faulty signer identified"
            );
        } else {
            error!(
                escrow_id = %session.escrow_id,
                error = %error,
                "SA+L signing failed"
            );
        }
    }

    /// Rollback to previous state (timeout handling).
    ///
    /// If a round times out waiting for a signer, roll back to the
    /// previous completed state. This is safe because:
    /// - Round 1 nonces are public commitments (no secret leaked)
    /// - Round 2 partial shares are useless without threshold (t shares needed)
    pub fn rollback(session: &mut SalSigningSession) -> Result<SalSigningState> {
        let previous = match session.state {
            SalSigningState::Round1Active => {
                // Timeout in round 1 — clear partial nonces, go back to Created
                session.round1.clear();
                session.state = SalSigningState::Created;
                SalSigningState::Created
            }
            SalSigningState::Round2Active => {
                // Timeout in round 2 — clear partial shares, go back to Round1Complete
                // Note: round 1 nonces are NOT cleared, so signers can retry round 2
                // with fresh shares (the nonces are already committed).
                //
                // HOWEVER: FROST requires that nonces are used exactly once.
                // If round 2 is rolled back, the nonces are "burned" and a new
                // round 1 must be started. This prevents nonce reuse attacks.
                warn!(
                    escrow_id = %session.escrow_id,
                    "Round 2 rollback — clearing both rounds (nonce reuse prevention)"
                );
                session.round1.clear();
                session.round2.clear();
                session.state = SalSigningState::Created;
                SalSigningState::Created
            }
            other => {
                anyhow::bail!(
                    "Cannot rollback from state '{}' (only round1_active or round2_active)",
                    other
                );
            }
        };

        session.updated_at = chrono::Utc::now().to_rfc3339();

        info!(
            escrow_id = %session.escrow_id,
            previous_state = %session.state,
            "SA+L session rolled back"
        );

        Ok(previous)
    }

    /// Get current signing status.
    pub fn status(session: &SalSigningSession) -> SalSigningStatus {
        SalSigningStatus {
            state: session.state,
            round1_submitted: session.round1.iter().map(|s| s.signer_index).collect(),
            round2_submitted: session.round2.iter().map(|s| s.signer_index).collect(),
            tx_hash: session.tx_hash.clone(),
            error: session.error.clone(),
            blame_signer: session.blame_signer,
        }
    }

    /// Submit the FCMP membership proof for the transaction.
    ///
    /// The membership proof is generated by the client (via WASM) and covers
    /// all inputs simultaneously. It must be submitted before `aggregate_and_build()`
    /// can assemble the final transaction.
    ///
    /// The proof consists of:
    /// - `proof_hex`: The main GBP circuit proof (variable length, 32-byte aligned)
    /// - `root_blind_pok_hex`: Proof-of-knowledge of the root blind (128 hex chars = 64 bytes)
    /// - `expected_proof_len`: Client-computed `Fcmp::proof_size(inputs, layers) - 64`
    ///
    /// **Why `expected_proof_len`?** The FCMP wire format is NOT self-delimiting.
    /// `Fcmp::read(inputs, layers)` splits `proof || root_blind_pok` using a size
    /// computed from `proof_size(inputs, layers) - 64`. We can't compute this server-side
    /// (requires curve type parameters), so the client provides it and we validate
    /// `proof_hex.len()/2 == expected_proof_len`. If the client lies, the proof fails
    /// network verification — but if the length is accidentally wrong, we catch it here
    /// instead of silently producing a corrupt TX blob.
    pub fn submit_membership_proof(
        session: &mut SalSigningSession,
        proof_hex: &str,
        root_blind_pok_hex: &str,
        expected_proof_len: usize,
    ) -> Result<()> {
        // State: must be Round2Complete (both SA+L shares received)
        if session.state != SalSigningState::Round2Complete {
            anyhow::bail!(
                "Cannot submit membership proof in state '{}' (need round2_complete)",
                session.state
            );
        }

        // Validate hex encoding
        if proof_hex.is_empty() {
            anyhow::bail!("Membership proof data cannot be empty");
        }
        let proof_bytes = hex::decode(proof_hex)
            .context("Membership proof is not valid hex")?;

        let pok_bytes = hex::decode(root_blind_pok_hex)
            .context("root_blind_pok is not valid hex")?;
        if pok_bytes.len() != 64 {
            anyhow::bail!(
                "root_blind_pok must be 64 bytes, got {}",
                pok_bytes.len()
            );
        }

        // Validate proof length matches client-declared expected size.
        // This catches accidental size mismatches that would cause silent deserialization
        // corruption: Fcmp::read() would split proof/pok at the wrong boundary.
        if proof_bytes.len() != expected_proof_len {
            anyhow::bail!(
                "Membership proof length ({}) does not match expected_proof_len ({}). \
                 expected_proof_len must equal Fcmp::proof_size(inputs, layers) - 64.",
                proof_bytes.len(),
                expected_proof_len
            );
        }

        // All proof elements are 32-byte scalars/group elements.
        if proof_bytes.len() % 32 != 0 {
            anyhow::bail!(
                "Membership proof length ({}) is not 32-byte aligned. \
                 All FCMP proof elements are 32-byte scalars/points.",
                proof_bytes.len()
            );
        }

        session.membership_proof_hex = Some(proof_hex.to_string());
        session.root_blind_pok_hex = Some(root_blind_pok_hex.to_string());
        session.expected_proof_len = Some(expected_proof_len);
        session.updated_at = chrono::Utc::now().to_rfc3339();

        info!(
            escrow_id = %session.escrow_id,
            proof_len = proof_bytes.len(),
            expected_proof_len,
            "FCMP membership proof submitted (size validated)"
        );

        Ok(())
    }

    /// Aggregate SA+L partial signatures and build the final FCMP++ transaction.
    ///
    /// This is the FCMP++ equivalent of `FrostSigningCoordinator::aggregate_and_broadcast()`.
    ///
    /// # Prerequisites
    /// - Both signers have submitted Round 1 (preprocess) and Round 2 (shares)
    /// - Membership proof has been submitted via `submit_membership_proof()`
    ///
    /// # Returns
    /// The assembled `FcmpPrunableData` ready to attach to the transaction builder.
    ///
    /// # Note
    /// The actual FROST aggregation (deserializing preprocess/share bytes and calling
    /// `modular_frost::SignatureMachine::complete()`) requires the WASM client to produce
    /// compatible serialized bytes. The aggregation call site is structured but will need
    /// adaptation when the client-side WASM is wired up.
    pub fn aggregate_sal_proof(
        session: &SalSigningSession,
    ) -> Result<()> {
        // Validate state
        if session.state != SalSigningState::Round2Complete {
            anyhow::bail!(
                "Cannot aggregate in state '{}' (need round2_complete)",
                session.state
            );
        }

        if session.membership_proof_hex.is_none() {
            anyhow::bail!("Membership proof not yet submitted");
        }

        // =====================================================================
        // FIXME(fcmp-hardfork): Wire up FROST aggregation when client WASM
        // produces compatible preprocess/share serialization.
        // This is the critical integration point — without it, no FCMP++ TX
        // can be broadcast. Blocked on client-side WASM completion.
        // =====================================================================
        //
        // The full aggregation flow:
        //
        // 1. Deserialize Round 1 preprocess bytes → HashMap<Participant, Preprocess>
        //    let preprocesses: HashMap<Participant, Vec<u8>> = session.round1
        //        .iter()
        //        .map(|r| (Participant::new(r.signer_index).unwrap(), hex::decode(&r.preprocess_hex).unwrap()))
        //        .collect();
        //
        // 2. Deserialize Round 2 signature shares → HashMap<Participant, SignatureShare>
        //    let shares: HashMap<Participant, Vec<u8>> = session.round2
        //        .iter()
        //        .map(|r| (Participant::new(r.signer_index).unwrap(), hex::decode(&r.share_hex).unwrap()))
        //        .collect();
        //
        // 3. Complete signing → SpendAuthAndLinkability proof
        //    let (key_image, sal_proof) = SignatureMachine::complete(shares)?;
        //
        // 4. Serialize SAL proof → FcmpInputProof
        //    let mut sal_bytes = Vec::new();
        //    sal_proof.write(&mut sal_bytes)?;
        //    // Parse 12 × 32-byte chunks: 6 points + 6 scalars
        //
        // 5. Combine with membership proof → FcmpPrunableData
        //
        // This will be wired up when the client WASM produces compatible
        // preprocess/share serialization.
        // =====================================================================

        info!(
            escrow_id = %session.escrow_id,
            round1_count = session.round1.len(),
            round2_count = session.round2.len(),
            has_membership = session.membership_proof_hex.is_some(),
            "SA+L aggregation — data ready, pending FROST machine integration"
        );

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_data() -> SalSigningData {
        SalSigningData {
            signable_tx_hash: "ab".repeat(32),
            rerandomized_output_hex: "cd".repeat(64),
            multisig_pubkey: "ef".repeat(32),
            recipient_address: "4".to_string() + &"A".repeat(94),
            amount_atomic: "1000000000000".to_string(),
            signer_indices: vec![1, 2],
        }
    }

    #[test]
    fn test_init_session() {
        let session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        );
        assert!(session.is_ok());
        let s = session.unwrap();
        assert_eq!(s.state, SalSigningState::Created);
        assert_eq!(s.signers, vec![1, 2]);
    }

    #[test]
    fn test_init_session_rejects_single_signer() {
        let result = SalSigningCoordinator::init_session(
            "esc_001",
            &[1],
            test_signing_data(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_init_session_rejects_duplicate_signers() {
        let result = SalSigningCoordinator::init_session(
            "esc_001",
            &[2, 2],
            test_signing_data(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_init_session_rejects_invalid_index() {
        let result = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 4],
            test_signing_data(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_round1_flow() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        // First signer submits
        let done = SalSigningCoordinator::submit_round1(
            &mut session,
            SalRound1Submission {
                signer_index: 1,
                preprocess_hex: "aabb".to_string(),
            },
        ).unwrap();
        assert!(!done);
        assert_eq!(session.state, SalSigningState::Round1Active);

        // Second signer submits
        let done = SalSigningCoordinator::submit_round1(
            &mut session,
            SalRound1Submission {
                signer_index: 2,
                preprocess_hex: "ccdd".to_string(),
            },
        ).unwrap();
        assert!(done);
        assert_eq!(session.state, SalSigningState::Round1Complete);
    }

    #[test]
    fn test_round1_rejects_duplicate() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        SalSigningCoordinator::submit_round1(
            &mut session,
            SalRound1Submission {
                signer_index: 1,
                preprocess_hex: "aabb".to_string(),
            },
        ).unwrap();

        let result = SalSigningCoordinator::submit_round1(
            &mut session,
            SalRound1Submission {
                signer_index: 1,
                preprocess_hex: "eeff".to_string(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_round1_rejects_non_participant() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        let result = SalSigningCoordinator::submit_round1(
            &mut session,
            SalRound1Submission {
                signer_index: 3, // arbiter not in signers
                preprocess_hex: "aabb".to_string(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_round2_flow() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        // Complete round 1
        SalSigningCoordinator::submit_round1(
            &mut session,
            SalRound1Submission { signer_index: 1, preprocess_hex: "aa".to_string() },
        ).unwrap();
        SalSigningCoordinator::submit_round1(
            &mut session,
            SalRound1Submission { signer_index: 2, preprocess_hex: "bb".to_string() },
        ).unwrap();

        // Round 2
        let done = SalSigningCoordinator::submit_round2(
            &mut session,
            SalRound2Submission { signer_index: 1, share_hex: "1122".to_string() },
        ).unwrap();
        assert!(!done);
        assert_eq!(session.state, SalSigningState::Round2Active);

        let done = SalSigningCoordinator::submit_round2(
            &mut session,
            SalRound2Submission { signer_index: 2, share_hex: "3344".to_string() },
        ).unwrap();
        assert!(done);
        assert_eq!(session.state, SalSigningState::Round2Complete);
    }

    #[test]
    fn test_round2_rejects_before_round1_complete() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        let result = SalSigningCoordinator::submit_round2(
            &mut session,
            SalRound2Submission { signer_index: 1, share_hex: "aa".to_string() },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_finalize() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        // Complete both rounds
        SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 1, preprocess_hex: "aa".to_string() }).unwrap();
        SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 2, preprocess_hex: "bb".to_string() }).unwrap();
        SalSigningCoordinator::submit_round2(&mut session,
            SalRound2Submission { signer_index: 1, share_hex: "11".to_string() }).unwrap();
        SalSigningCoordinator::submit_round2(&mut session,
            SalRound2Submission { signer_index: 2, share_hex: "22".to_string() }).unwrap();

        // Finalize
        SalSigningCoordinator::finalize(&mut session, "abcd1234").unwrap();
        assert_eq!(session.state, SalSigningState::Finalized);
        assert_eq!(session.tx_hash.as_deref(), Some("abcd1234"));
    }

    #[test]
    fn test_fail_with_blame() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        SalSigningCoordinator::fail(&mut session, "Invalid share from signer 2", Some(2));
        assert_eq!(session.state, SalSigningState::Failed);
        assert_eq!(session.blame_signer, Some(2));
    }

    #[test]
    fn test_rollback_round1() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 1, preprocess_hex: "aa".to_string() }).unwrap();

        assert_eq!(session.state, SalSigningState::Round1Active);

        // Timeout → rollback
        SalSigningCoordinator::rollback(&mut session).unwrap();
        assert_eq!(session.state, SalSigningState::Created);
        assert!(session.round1.is_empty());
    }

    #[test]
    fn test_rollback_round2_clears_nonces() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        // Complete round 1
        SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 1, preprocess_hex: "aa".to_string() }).unwrap();
        SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 2, preprocess_hex: "bb".to_string() }).unwrap();

        // Partial round 2
        SalSigningCoordinator::submit_round2(&mut session,
            SalRound2Submission { signer_index: 1, share_hex: "11".to_string() }).unwrap();

        assert_eq!(session.state, SalSigningState::Round2Active);

        // Timeout → rollback (clears BOTH rounds — nonce reuse prevention)
        SalSigningCoordinator::rollback(&mut session).unwrap();
        assert_eq!(session.state, SalSigningState::Created);
        assert!(session.round1.is_empty());
        assert!(session.round2.is_empty());
    }

    #[test]
    fn test_status() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 3], // buyer + arbiter (dispute scenario)
            test_signing_data(),
        ).unwrap();

        SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 1, preprocess_hex: "aa".to_string() }).unwrap();

        let status = SalSigningCoordinator::status(&session);
        assert_eq!(status.state, SalSigningState::Round1Active);
        assert_eq!(status.round1_submitted, vec![1]);
        assert!(status.round2_submitted.is_empty());
        assert!(status.tx_hash.is_none());
    }

    #[test]
    fn test_get_round1_commitments_before_complete() {
        let session = SalSigningCoordinator::init_session(
            "esc_001",
            &[1, 2],
            test_signing_data(),
        ).unwrap();

        let result = SalSigningCoordinator::get_round1_commitments(&session);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_happy_path() {
        let mut session = SalSigningCoordinator::init_session(
            "esc_001",
            &[2, 3], // vendor + arbiter (dispute resolution)
            test_signing_data(),
        ).unwrap();

        // Round 1: both submit nonces (parallel)
        assert!(!SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 3, preprocess_hex: "aa".to_string() }).unwrap());
        assert!(SalSigningCoordinator::submit_round1(&mut session,
            SalRound1Submission { signer_index: 2, preprocess_hex: "bb".to_string() }).unwrap());

        // Both retrieve commitments
        let commitments = SalSigningCoordinator::get_round1_commitments(&session).unwrap();
        assert_eq!(commitments.len(), 2);

        // Round 2: both submit partial sigs (parallel)
        assert!(!SalSigningCoordinator::submit_round2(&mut session,
            SalRound2Submission { signer_index: 2, share_hex: "1122".to_string() }).unwrap());
        assert!(SalSigningCoordinator::submit_round2(&mut session,
            SalRound2Submission { signer_index: 3, share_hex: "3344".to_string() }).unwrap());

        // Retrieve shares for aggregation
        let shares = SalSigningCoordinator::get_round2_shares(&session).unwrap();
        assert_eq!(shares.len(), 2);

        // Finalize
        SalSigningCoordinator::finalize(&mut session, "deadbeef01234567").unwrap();

        let status = SalSigningCoordinator::status(&session);
        assert_eq!(status.state, SalSigningState::Finalized);
        assert_eq!(status.tx_hash.as_deref(), Some("deadbeef01234567"));
    }
}
