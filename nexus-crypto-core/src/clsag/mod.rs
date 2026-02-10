//! CLSAG (Compact Linkable Spontaneous Anonymous Group) ring signatures.
//!
//! This module implements CLSAG signing and verification for Monero transactions.
//! CLSAG is the ring signature scheme used in Monero since protocol version 13.
//!
//! ## Components
//!
//! - [`types`]: Core CLSAG types (signature, verification result)
//! - [`constants`]: Domain separators and generator constants
//! - [`hash`]: Hashing functions for mixing coefficients and round challenges
//! - [`verify`]: Full CLSAG signature verification
//! - [`sign`]: CLSAG signature generation for 2-of-3 FROST multisig
//!
//! ## Verification Equation
//!
//! For each ring member i:
//! ```text
//! L[i] = s[i]*G + c * (μ_P * P[i] + μ_C * (C[i] - pseudo_out))
//! R[i] = s[i]*Hp(P[i]) + c * (μ_P * I + μ_C * D)
//! c[i+1] = H(CLSAG_round || ring || pseudo_out || m || I || D || L[i] || R[i])
//! ```
//!
//! Valid if `c_computed` (after full loop) equals `c1`.
//!
//! ## Security Notes
//!
//! - Uses Monero's `hash_to_point` (ge_fromfe_frombytes_vartime)
//! - Domain separators are 32-byte padded
//! - All scalars are reduced mod l (ed25519 group order)

pub mod constants;
pub mod hash;
pub mod sign;
pub mod types;
pub mod verify;

// Re-export main types
pub use types::{ClsagSignature, ClsagVerificationResult};

// Re-export verification function
pub use verify::verify_clsag;

// Re-export hash functions (useful for signing implementations)
pub use hash::{compute_mixing_coefficients, compute_round_hash};

// Re-export signing functions
pub use sign::{
    sign_clsag_partial, sign_clsag_complete,
    compute_pseudo_out, compute_mask_delta,
    PartialClsagSignature,
};
