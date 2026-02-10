#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments,
    deprecated
)]
//! # onyx-crypto-core
//!
//! Core cryptographic library for Onyx Escrow-as-a-Service (EaaS).
//!
//! This crate provides the cryptographic primitives for non-custodial Monero escrow:
//!
//! - **FROST DKG** (RFC 9591): Distributed Key Generation for 2-of-3 threshold signatures
//! - **CMD Protocol**: Commitment Mask Derivation for view-key-only output identification
//! - **CLSAG Signing**: Linkable ring signatures for Monero transactions
//! - **Key Image Generation**: Partial and aggregated key images for spend detection
//! - **Address Validation**: Full Monero address checksum verification
//!
//! ## Architecture
//!
//! The crate is designed with the following principles:
//!
//! 1. **no_std Compatible**: Can run in WASM environments
//! 2. **Constant-Time Operations**: Prevents timing side-channels
//! 3. **Zeroize on Drop**: Sensitive data is cleared from memory
//! 4. **Type-Safe**: Strong typing prevents key misuse
//!
//! ## Modules
//!
//! - [`types`]: Core type definitions and error types
//! - [`frost`]: FROST DKG and threshold signatures (RFC 9591)
//! - [`keys`]: Key derivation, address validation, and key image generation
//! - [`cmd`]: Commitment Mask Derivation protocol for output identification
//! - [`nonce`]: MuSig2-style nonce commitments and aggregation
//! - [`clsag`]: CLSAG ring signature verification
//! - [`encryption`]: X25519 ECDH and ChaCha20Poly1305 encryption
//!
//! ## Example
//!
//! ```rust,ignore
//! use onyx_crypto_core::prelude::*;
//!
//! // Generate FROST key shares for 2-of-3 multisig
//! let (round1_secret, round1_package) = frost_dkg_part1(
//!     Identifier::from(1),
//!     2, // threshold
//!     3, // total signers
//! )?;
//!
//! // ... exchange round1 packages ...
//!
//! // Complete DKG rounds 2 and 3
//! // ... see frost module documentation ...
//! ```
//!
//! ## Security Considerations
//!
//! This crate handles cryptographic secrets. Users should:
//!
//! - Never log or serialize secret keys
//! - Use memory protection features of the OS when available
//! - Prefer hardware security modules for production deployments
//! - Audit all code paths that handle `SecretKey` or `*Secret*` types

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

extern crate alloc;

pub mod clsag;
pub mod cmd;
pub mod encryption;
pub mod frost;
pub mod keys;
pub mod nonce;
pub mod types;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::types::errors::*;
    pub use crate::types::*;
}

/// Re-export commonly used types at crate root
pub use types::errors::{CryptoError, CryptoResult};

// Re-export address types
pub use types::address::{AddressType, DecodedAddress, MoneroNetwork};

// Re-export transaction types
pub use types::transaction::{ClsagSignature, KeyImage, PartialSignatureData, RingMember, TxHash};

// Re-export escrow types
pub use types::escrow::{EscrowRole, FrostKeyShare, NonceCommitment, SigningPair};

// Re-export FROST types and functions
pub use frost::types::{DkgFinalResult, DkgRound1Result, DkgRound2Result};
pub use frost::{
    compute_lagrange_coefficient, dkg_part1, dkg_part2, dkg_part3, extract_secret_share,
};

// Re-export CMD types and functions
pub use cmd::{
    decode_encrypted_amount, derive_commitment_mask, encode_varint, extract_tx_pub_key_from_extra,
    find_our_output_and_derive_mask, OutputOwnershipResult,
};

// Re-export nonce types and functions
pub use nonce::{
    aggregate_nonces, aggregate_nonces_full, compute_nonce_commitment_hash,
    generate_nonce_commitment, verify_nonce_aggregation, verify_nonce_commitment,
    verify_nonce_commitment_ct, AggregatedNonces, NonceCommitmentResult,
};

// Re-export key image types and functions
pub use keys::{
    aggregate_partial_key_images, compute_key_image, compute_partial_key_image,
    compute_partial_key_image_with_derivation, KeyImageResult, PartialKeyImageResult,
    PartialKeyImageWithDerivationResult,
};

// Re-export CLSAG types and functions
pub use clsag::{
    compute_mask_delta, compute_mixing_coefficients, compute_pseudo_out, compute_round_hash,
    sign_clsag_complete, sign_clsag_partial, verify_clsag, ClsagSignature as ClsagSig,
    ClsagVerificationResult, PartialClsagSignature,
};

// Re-export encryption types and functions
pub use encryption::{
    decrypt_data, derive_shared_key, encrypt_data, generate_ephemeral_keypair, DecryptedResult,
    EncryptedResult, EphemeralKeypair,
};

// Re-export backup encryption functions
pub use encryption::{
    decrypt_key_from_backup, derive_backup_id, encrypt_key_for_backup, encrypted_size,
    verify_backup_password,
};
