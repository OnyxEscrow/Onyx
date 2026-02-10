//! MuSig2-style nonce generation and commitment for CLSAG multisig.
//!
//! This module implements nonce handling for 2-of-3 threshold CLSAG signatures:
//!
//! 1. Each signer generates a random nonce α (alpha)
//! 2. Computes R = α*G and R' = α*Hp(P)
//! 3. Computes commitment hash H("MUSIG2_NONCE_COMMITMENT" || R || R')
//! 4. Server aggregates: R_agg = R₁ + R₂
//! 5. Both signers use R_agg for L in their signatures
//!
//! ## Security Notes
//!
//! - Nonce secrets (alpha) MUST be kept in memory only, never persisted
//! - Each nonce MUST be used exactly once
//! - Nonce reuse leads to private key extraction
//!
//! ## Example
//!
//! ```rust,ignore
//! use nexus_crypto_core::nonce::{generate_nonce_commitment, aggregate_nonces};
//!
//! // Signer 1 generates nonce
//! let nonce1 = generate_nonce_commitment(&multisig_pubkey)?;
//!
//! // Signer 2 generates nonce
//! let nonce2 = generate_nonce_commitment(&multisig_pubkey)?;
//!
//! // Server aggregates (after commitment reveal)
//! let r_agg = aggregate_nonces(&nonce1.r_public, &nonce2.r_public)?;
//! ```

mod aggregate;
mod commit;
mod generate;

pub use aggregate::{
    aggregate_nonces, aggregate_nonces_full, verify_nonce_aggregation, AggregatedNonces,
};
pub use commit::{
    compute_nonce_commitment_hash, verify_nonce_commitment, verify_nonce_commitment_ct,
};
pub use generate::{generate_nonce_commitment, NonceCommitmentResult};
