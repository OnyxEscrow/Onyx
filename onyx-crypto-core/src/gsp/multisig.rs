//! GSP 2-round threshold signing using `monero-fcmp-plus-plus`'s `SalAlgorithm`.
//!
//! This wraps kayabaNerve's `SalAlgorithm<R, T>` which implements
//! `Algorithm<Ed25519T>` for `modular-frost`. The signing flow:
//!
//! 1. **DKG**: Generate `ThresholdKeys<Ed25519T>` via `modular-frost` DKG
//! 2. **Preprocess**: Each signer generates nonces via FROST preprocess
//! 3. **Sign**: Each signer computes partial SAL proof share
//! 4. **Aggregate**: `modular-frost` aggregates shares into final `SpendAuthAndLinkability`
//!
//! ## Key Insight: Ed25519T Ciphersuite
//!
//! The SAL multisig uses `Ed25519T` — a custom ciphersuite where the
//! generator is `T` (not `G`). This is because the FROST signing protocol
//! produces nonces on `T` for the `y` secret (the `yT` component of `O = xG + yT`).
//!
//! The `x` secret is NOT threshold-shared in the standard `SalAlgorithm`;
//! it's provided directly. Only `y` (the `T`-component) is threshold-distributed.
//!
//! For legacy compatibility, `SalLegacyAlgorithm` shares `x` instead.
//!
//! ## Identifiable Abort
//!
//! `verify_share()` checks each signer's share against their verification key,
//! enabling identification of misbehaving signers.

use alloc::format;

use rand_core::{CryptoRng, RngCore};

use ciphersuite::{
    group::{ff::PrimeField, GroupEncoding},
    Ciphersuite, Ed25519,
};
use dalek_ff_group::{EdwardsPoint, Scalar};
use flexible_transcript::Transcript;
use monero_fcmp_plus_plus::sal::{
    multisig::SalAlgorithm,
    RerandomizedOutput, SpendAuthAndLinkability,
};
use modular_frost::Participant;

use crate::types::errors::{CryptoError, CryptoResult};

/// Onyx wrapper for FCMP++ SA+L threshold signing.
///
/// Manages the 2-of-3 FROST signing protocol using `SalAlgorithm`
/// from the `monero-fcmp-plus-plus` crate.
///
/// # Lifecycle
///
/// ```text
/// 1. OnyxSalSigner::new(rng, tx_hash, rerandomized_output, x_secret)
/// 2. Use with modular_frost::sign() protocol
/// 3. Produces SpendAuthAndLinkability proof
/// ```
pub struct OnyxSalSigner<R: Send + Sync + Clone + RngCore + CryptoRng> {
    /// The underlying SalAlgorithm instance
    algorithm: SalAlgorithm<R, flexible_transcript::RecommendedTranscript>,
}

impl<R: Send + Sync + Clone + RngCore + CryptoRng> OnyxSalSigner<R> {
    /// Create a new SA+L signer for FCMP++ multisig.
    ///
    /// # Arguments
    /// * `rng` - Cryptographic RNG (must be Clone + Send + Sync)
    /// * `signable_tx_hash` - 32-byte hash binding to the transaction
    /// * `rerandomized_output` - The re-randomized output being spent
    /// * `x_secret` - The spend key scalar `x` (from `O = xG + yT`)
    ///
    /// # Note
    ///
    /// The `y` secret is the ThresholdKeys secret — it's NOT passed here.
    /// It comes from the FROST DKG as `ThresholdKeys<Ed25519T>`.
    pub fn new(
        rng: R,
        signable_tx_hash: [u8; 32],
        rerandomized_output: RerandomizedOutput,
        x_secret: Scalar,
    ) -> Self {
        let transcript = flexible_transcript::RecommendedTranscript::new(
            b"Onyx FCMP++ SA+L Signing v1",
        );

        let algorithm = SalAlgorithm::new(
            rng,
            transcript,
            signable_tx_hash,
            rerandomized_output,
            x_secret,
        );

        Self { algorithm }
    }

    /// Consume the signer and return the underlying `SalAlgorithm`.
    ///
    /// This is needed to pass into `modular_frost::sign()`.
    pub fn into_algorithm(self) -> SalAlgorithm<R, flexible_transcript::RecommendedTranscript> {
        self.algorithm
    }
}

/// Convert a raw 32-byte scalar to the vendor's `Scalar` type.
pub fn bytes_to_scalar(bytes: &[u8; 32]) -> CryptoResult<Scalar> {
    let repr = <Scalar as PrimeField>::Repr::from(*bytes);
    Option::from(Scalar::from_repr(repr)).ok_or_else(|| {
        CryptoError::InvalidSecretKey("Invalid scalar encoding".into())
    })
}

/// Convert a raw 32-byte point to the vendor's `EdwardsPoint`.
pub fn bytes_to_point(bytes: &[u8; 32]) -> CryptoResult<EdwardsPoint> {
    let repr = <EdwardsPoint as GroupEncoding>::Repr::from(*bytes);
    Option::from(EdwardsPoint::from_bytes(&repr)).ok_or_else(|| {
        CryptoError::InvalidPublicKey("Invalid point encoding".into())
    })
}

/// Verify a `SpendAuthAndLinkability` proof.
///
/// This queues the proof for batch verification. The returned `BatchVerifier`
/// MUST be verified before the proof is considered valid.
///
/// # Arguments
/// * `rng` - Cryptographic RNG for batch verification randomization
/// * `proof` - The SAL proof to verify
/// * `signable_tx_hash` - The transaction hash that was signed
/// * `input` - The input tuple (O~, I~, R, C~)
/// * `key_image` - The key image L
pub fn verify_sal_proof(
    rng: &mut (impl RngCore + CryptoRng),
    proof: &SpendAuthAndLinkability,
    signable_tx_hash: [u8; 32],
    input: &monero_fcmp_plus_plus::Input,
    key_image: <Ed25519 as Ciphersuite>::G,
) -> CryptoResult<bool> {
    let mut verifier = multiexp::BatchVerifier::new(4);
    proof.verify(rng, &mut verifier, signable_tx_hash, input, key_image);

    if verifier.verify_vartime() {
        Ok(true)
    } else {
        Err(CryptoError::GspProofVerificationFailed(
            "SA+L batch verification failed".into(),
        ))
    }
}

/// Create a FROST `Participant` from a 1-indexed signer ID.
pub fn participant(index: u16) -> CryptoResult<Participant> {
    Participant::new(index).ok_or_else(|| {
        CryptoError::InvalidIdentifier(format!("Invalid participant index: {index}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_scalar_zero() {
        let zero = [0u8; 32];
        let scalar = bytes_to_scalar(&zero).expect("zero is valid");
        assert_eq!(scalar, Scalar::from(0u64));
    }

    #[test]
    fn test_bytes_to_scalar_one() {
        let mut one = [0u8; 32];
        one[0] = 1;
        let scalar = bytes_to_scalar(&one).expect("one is valid");
        assert_eq!(scalar, Scalar::from(1u64));
    }

    #[test]
    fn test_participant_valid() {
        assert!(participant(1).is_ok());
        assert!(participant(2).is_ok());
        assert!(participant(3).is_ok());
    }

    #[test]
    fn test_participant_zero_invalid() {
        assert!(participant(0).is_err());
    }
}
