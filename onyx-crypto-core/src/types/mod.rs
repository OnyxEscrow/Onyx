//! Core type definitions for onyx-crypto-core
//!
//! This module contains:
//! - Error types for cryptographic operations
//! - Address types and network definitions
//! - Transaction types for CLSAG signing
//! - Escrow types for 2-of-3 multisig

pub mod address;
pub mod errors;
pub mod escrow;
pub mod transaction;

/// FCMP++ specific types (GSP proofs, re-randomized outputs, membership proofs).
pub mod fcmp_types;

// Re-export error types
pub use errors::{CryptoError, CryptoResult};

// Re-export address types
pub use address::{
    AddressType, DecodedAddress, MoneroNetwork, CHECKSUM_LENGTH, INTEGRATED_ADDRESS_DECODED_LENGTH,
    PUBLIC_KEY_LENGTH, STANDARD_ADDRESS_DECODED_LENGTH,
};

// Re-export transaction types
pub use transaction::{
    ClsagSignature, KeyImage, OutputInfo, PartialSignatureData, RingMember, TxHash,
    KEY_IMAGE_LENGTH, TX_HASH_LENGTH,
};

// Re-export escrow types
pub use escrow::{
    EscrowAddressInfo, EscrowRole, FrostKeyShare, NonceCommitment, NonceReveal, SigningPair,
    VerificationShare,
};
