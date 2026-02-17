//! Stub re-randomization when `fcmp` feature is disabled.

use crate::types::errors::{CryptoError, CryptoResult};
use crate::types::fcmp_types::RerandomizedOutput;

/// Re-randomize an output for FCMP++ proving (stub).
pub fn rerandomize_output(
    _output_key: &[u8; 32],
    _commitment: &[u8; 32],
) -> CryptoResult<RerandomizedOutput> {
    Err(CryptoError::NotImplemented(
        "Re-randomization requires 'fcmp' feature".into(),
    ))
}
