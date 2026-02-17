//! FCMP++ Membership Proofs — Full-Chain Membership via Curve Trees.
//!
//! This module handles the M-proof component of FCMP++. It proves that
//! a re-randomized output `(K', I', C')` is a valid leaf in the global
//! Curve Tree spanning the entire UTXO set.
//!
//! ## Curve Tree Structure
//!
//! - **Leaves:** `(O, I, C)` tuples on Ed25519 (Wei25519)
//! - **Odd layers:** Pedersen commitments on **Selene** curve (C1)
//! - **Even layers:** Pedersen commitments on **Helios** curve (C2)
//!
//! Proofs scale logarithmically with the UTXO set size (~150M+ outputs).
//!
//! ## Module Structure
//!
//! - [`curves`] — Helios/Selene curve operations, type conversions, re-exports
//! - [`tree`] — Tree path construction, layer hashing, root computation
//! - [`membership`] — Full proof generation and verification
//! - [`nullifier`] — Key image validation

#[cfg(feature = "fcmp")]
pub mod curves;

#[cfg(feature = "fcmp")]
pub mod tree;

#[cfg(feature = "fcmp")]
pub mod membership;

#[cfg(feature = "fcmp")]
pub mod nullifier;
