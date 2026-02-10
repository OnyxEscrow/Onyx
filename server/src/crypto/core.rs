//! Re-exports from nexus-crypto-core for gradual migration.
//!
//! This module provides compatibility imports from the extracted crypto core.
//! Existing code can gradually migrate to use these re-exports.
//!
//! ## Migration Path
//!
//! Old import:
//! ```rust,ignore
//! use crate::crypto::address_validation::validate_address_for_network;
//! ```
//!
//! New import:
//! ```rust,ignore
//! use crate::crypto::core::validate_address_for_network;
//! ```

// Re-export error types
pub use nexus_crypto_core::{CryptoError, CryptoResult};

// Re-export address types and functions
pub use nexus_crypto_core::{
    AddressType, DecodedAddress, MoneroNetwork,
};

// Re-export key validation (from keys module)
pub use nexus_crypto_core::keys::{
    validate_address, validate_address_for_network,
    quick_network_check, extract_public_keys,
    is_subaddress, is_integrated_address, extract_payment_id,
    decode_address,
};

// Re-export key derivation
pub use nexus_crypto_core::keys::{
    derive_public_key, derive_public_key_from_hex,
    validate_view_key_matches_address,
    extract_spend_pub_from_address, extract_view_pub_from_address,
};

// Re-export key image functions
pub use nexus_crypto_core::{
    compute_key_image, compute_partial_key_image,
    compute_partial_key_image_with_derivation,
    aggregate_partial_key_images,
    KeyImageResult, PartialKeyImageResult, PartialKeyImageWithDerivationResult,
};

// Re-export FROST DKG functions
pub use nexus_crypto_core::{
    dkg_part1, dkg_part2, dkg_part3,
    extract_secret_share, compute_lagrange_coefficient,
    DkgRound1Result, DkgRound2Result, DkgFinalResult,
};

// Re-export CMD functions
pub use nexus_crypto_core::{
    derive_commitment_mask, find_our_output_and_derive_mask,
    decode_encrypted_amount, encode_varint,
    extract_tx_pub_key_from_extra,
    OutputOwnershipResult,
};

// Re-export nonce functions
pub use nexus_crypto_core::{
    generate_nonce_commitment, compute_nonce_commitment_hash,
    verify_nonce_commitment, verify_nonce_commitment_ct,
    aggregate_nonces, aggregate_nonces_full, verify_nonce_aggregation,
    NonceCommitmentResult, AggregatedNonces,
};

// Re-export CLSAG functions
pub use nexus_crypto_core::{
    verify_clsag, compute_mixing_coefficients, compute_round_hash,
    ClsagVerificationResult,
};

// Re-export encryption functions
pub use nexus_crypto_core::{
    generate_ephemeral_keypair, derive_shared_key,
    encrypt_data, decrypt_data,
    EphemeralKeypair, EncryptedResult, DecryptedResult,
};

// Re-export escrow types
pub use nexus_crypto_core::{
    EscrowRole, SigningPair, FrostKeyShare, NonceCommitment,
};

// Re-export transaction types
pub use nexus_crypto_core::{
    ClsagSig, KeyImage, TxHash, RingMember, PartialSignatureData,
};
