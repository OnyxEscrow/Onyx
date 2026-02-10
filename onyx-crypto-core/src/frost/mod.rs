//! FROST Distributed Key Generation (RFC 9591) for 2-of-3 Threshold Signatures
//!
//! This module implements FROST DKG to generate unique secret shares without overlap.
//! Unlike Monero's native multisig where shares overlap (causing CLSAG failures),
//! FROST uses Shamir Secret Sharing with Lagrange interpolation.
//!
//! ## Why FROST Solves the Overlap Problem
//!
//! ```text
//! Monero Native:  (k1+k2) + (k2+k3) = k1 + 2*k2 + k3  <- k2 DOUBLE-COUNTED!
//! FROST:          λ₁*s₁ + λ₂*s₂ = x_reconstructed     <- NO OVERLAP!
//! ```
//!
//! ## DKG Flow (Async - each party can participate independently)
//!
//! ```text
//! Phase 1: Each party calls frost_dkg_part1() -> round1_package (public) + secret_package (local)
//! Phase 2: Server collects all 3 round1_packages, each party calls frost_dkg_part2()
//! Phase 3: Each party calls frost_dkg_part3() -> KeyPackage (secret share) + GroupPublicKey
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use onyx_crypto_core::frost::{dkg_part1, dkg_part2, dkg_part3};
//!
//! // Round 1 - Generate commitment
//! let (round1_pkg, secret_pkg) = dkg_part1(1, 2, 3)?;
//!
//! // Round 2 - Compute secret shares
//! let (round2_pkgs, round2_secret) = dkg_part2(&secret_pkg, &all_round1_packages)?;
//!
//! // Round 3 - Finalize
//! let result = dkg_part3(&round2_secret, &all_round1_packages, &round2_packages_for_me)?;
//! ```

pub mod dkg;
pub mod lagrange;
pub mod types;

// Re-export core types and functions
pub use dkg::{dkg_part1, dkg_part2, dkg_part3, extract_secret_share};
pub use lagrange::compute_lagrange_coefficient;
pub use types::{DkgFinalResult, DkgRound1Result, DkgRound2Result};
