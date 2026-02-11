//! Generalized Schnorr Protocol (GSP) for FCMP++ Spend Authorization + Linkability.
//!
//! This module replaces CLSAG ring signatures with the SA+L proof from
//! `monero-fcmp-plus-plus`. The proof is a conjunction of:
//!
//! - **BP+**: Proves knowledge of consistent `(x, r_i)` linking P to the input
//! - **O~ GSP**: Proves opening of the re-randomized output key
//! - **P' GSP**: Proves correct structure of the linking helper
//! - **L GSP**: Proves correct key image computation
//!
//! ## Architecture
//!
//! ```text
//! +-----------------+     +------------------+     +---------------------+
//! | modular-frost   | --> | SalAlgorithm     | --> | SpendAuth+Linkability|
//! | (DKG + signing) |     | (Ed25519T)       |     | (12-field proof)     |
//! +-----------------+     +------------------+     +---------------------+
//!         ^                       ^
//!         |                       |
//!   ThresholdKeys<Ed25519T>  RerandomizedOutput
//!   (y shared, x direct)    (from rerandomize/)
//! ```
//!
//! ## 2-of-3 Escrow Flow
//!
//! 1. **DKG** (once): Generate `ThresholdKeys<Ed25519T>` for `y` secret
//! 2. **Re-randomize**: Create `RerandomizedOutput` from the output being spent
//! 3. **Create SalAlgorithm**: Provide `x`, `tx_hash`, `rerandomized_output`
//! 4. **FROST sign()**: 2-of-3 parties cooperate to produce `SpendAuthAndLinkability`
//! 5. **Verify**: Batch-verify the proof before broadcasting

/// GSP type re-exports (legacy stub types + vendor types).
pub mod types;

/// GSP multisig signing (real implementation when `fcmp` feature enabled).
#[cfg(feature = "fcmp")]
pub mod multisig;

/// GSP proof verification.
pub mod verify;

pub use types::*;
