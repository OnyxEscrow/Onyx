//! GSP type definitions.

// Re-export FCMP types for convenience
#[cfg(feature = "fcmp")]
pub use crate::types::fcmp_types::{
    AggregatedGspNonces, GspNonceCommitment, GspPartialSignature, GspProof, GspSigningState,
};
