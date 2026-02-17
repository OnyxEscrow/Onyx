//! Additive re-randomization for FCMP++.
//!
//! Wraps `monero-fcmp-plus-plus`'s `RerandomizedOutput` which implements:
//!
//! ```text
//! O~ = O + r_o * T          (re-randomized output key)
//! I~ = I + r_i * U          (re-randomized key image base)
//! R  = r_i * V + r_r_i * T  (re-randomization helper point)
//! C~ = C + r_c * G           (re-randomized commitment)
//! ```
//!
//! Where `r_o, r_i, r_r_i, r_c` are fresh random scalars, and
//! `T, U, V` are the FCMP++ generators from `monero-generators`.

#[cfg(feature = "fcmp")]
mod real;

#[cfg(feature = "fcmp")]
pub use real::*;

#[cfg(not(feature = "fcmp"))]
mod stub;

#[cfg(not(feature = "fcmp"))]
pub use stub::*;
