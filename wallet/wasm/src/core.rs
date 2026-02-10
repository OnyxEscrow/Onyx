//! Re-exports from onyx-crypto-core for gradual migration.
//!
//! This module provides compatibility imports from the extracted crypto core.
//! WASM code can gradually migrate to use these re-exports.

// Re-export error types
pub use onyx_crypto_core::{CryptoError, CryptoResult};

// Re-export address types and functions
pub use onyx_crypto_core::{AddressType, DecodedAddress, MoneroNetwork};

// Re-export key validation
pub use onyx_crypto_core::keys::{
    decode_address, extract_payment_id, extract_public_keys, is_integrated_address, is_subaddress,
    quick_network_check, validate_address, validate_address_for_network,
};

// Re-export key image functions
pub use onyx_crypto_core::{
    aggregate_partial_key_images, compute_key_image, compute_partial_key_image,
    compute_partial_key_image_with_derivation, KeyImageResult, PartialKeyImageResult,
    PartialKeyImageWithDerivationResult,
};

// Re-export FROST DKG functions
pub use onyx_crypto_core::{
    compute_lagrange_coefficient, dkg_part1, dkg_part2, dkg_part3, extract_secret_share,
    DkgFinalResult, DkgRound1Result, DkgRound2Result,
};

// Re-export CMD functions
pub use onyx_crypto_core::{
    decode_encrypted_amount, derive_commitment_mask, encode_varint, extract_tx_pub_key_from_extra,
    find_our_output_and_derive_mask, OutputOwnershipResult,
};

// Re-export nonce functions
pub use onyx_crypto_core::{
    aggregate_nonces, aggregate_nonces_full, compute_nonce_commitment_hash,
    generate_nonce_commitment, verify_nonce_aggregation, verify_nonce_commitment,
    verify_nonce_commitment_ct, AggregatedNonces, NonceCommitmentResult,
};

// Re-export CLSAG functions
pub use onyx_crypto_core::{
    compute_mixing_coefficients, compute_round_hash, verify_clsag, ClsagVerificationResult,
};

// Re-export encryption functions
pub use onyx_crypto_core::{
    decrypt_data, derive_shared_key, encrypt_data,
    generate_ephemeral_keypair as core_generate_ephemeral_keypair, DecryptedResult,
    EncryptedResult, EphemeralKeypair,
};

// Re-export escrow types
pub use onyx_crypto_core::{EscrowRole, FrostKeyShare, NonceCommitment, SigningPair};
