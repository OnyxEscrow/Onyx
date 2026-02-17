//! GSP proof verification.
//!
//! Wraps the batch verification from `monero-fcmp-plus-plus`.

#[cfg(feature = "fcmp")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "fcmp")]
use ciphersuite::{Ciphersuite, Ed25519};
#[cfg(feature = "fcmp")]
use monero_fcmp_plus_plus::sal::SpendAuthAndLinkability;
#[cfg(feature = "fcmp")]
use monero_fcmp_plus_plus::Input;

use crate::types::errors::{CryptoError, CryptoResult};

/// Verify a single SA+L proof with immediate (non-batched) verification.
///
/// For batched verification of multiple proofs, use `verify_sal_proofs_batch`.
///
/// # Arguments
/// * `rng` - Cryptographic RNG for batch randomization
/// * `proof` - The SpendAuthAndLinkability proof
/// * `signable_tx_hash` - Transaction hash the proof was signed for
/// * `input` - The input tuple (O~, I~, R, C~)
/// * `key_image` - The key image L = x * H(K)
#[cfg(feature = "fcmp")]
pub fn verify_sal_single(
    rng: &mut (impl RngCore + CryptoRng),
    proof: &SpendAuthAndLinkability,
    signable_tx_hash: [u8; 32],
    input: &Input,
    key_image: <Ed25519 as Ciphersuite>::G,
) -> CryptoResult<()> {
    let mut verifier = multiexp::BatchVerifier::new(4);
    proof.verify(rng, &mut verifier, signable_tx_hash, input, key_image);

    if verifier.verify_vartime() {
        Ok(())
    } else {
        Err(CryptoError::GspProofVerificationFailed(
            "SA+L verification failed".into(),
        ))
    }
}

/// Batch-verify multiple SA+L proofs.
///
/// More efficient than verifying each proof individually because
/// the multi-exponentiation is batched across all proofs.
///
/// # Arguments
/// * `rng` - Cryptographic RNG
/// * `proofs` - Slice of (proof, tx_hash, input, key_image) tuples
#[cfg(feature = "fcmp")]
pub fn verify_sal_proofs_batch(
    rng: &mut (impl RngCore + CryptoRng),
    proofs: &[(
        &SpendAuthAndLinkability,
        [u8; 32],
        &Input,
        <Ed25519 as Ciphersuite>::G,
    )],
) -> CryptoResult<()> {
    if proofs.is_empty() {
        return Ok(());
    }

    // 4 verification equations per proof
    let mut verifier = multiexp::BatchVerifier::new(4 * proofs.len());

    for (proof, tx_hash, input, key_image) in proofs {
        proof.verify(rng, &mut verifier, *tx_hash, input, *key_image);
    }

    if verifier.verify_vartime() {
        Ok(())
    } else {
        Err(CryptoError::GspProofVerificationFailed(
            "SA+L batch verification failed — at least one proof is invalid".into(),
        ))
    }
}

/// Stub verification when `fcmp` feature is disabled.
#[cfg(not(feature = "fcmp"))]
pub fn verify_gsp_proof(
    _proof: &super::types::GspProof,
    _rerandomized: &crate::types::fcmp_types::RerandomizedOutput,
    _tx_hash: &[u8; 32],
) -> CryptoResult<bool> {
    Err(CryptoError::NotImplemented(
        "GSP verification requires 'fcmp' feature".into(),
    ))
}
