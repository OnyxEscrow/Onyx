//! Regression Tests for Documented Bugs
//!
//! Tests to prevent re-introduction of previously fixed bugs.

pub mod bug_cofactor_test;
pub mod bug_commitment_test;
pub mod bug_hash_mismatch_test;
pub mod bug_output_type_test;

pub use bug_cofactor_test::*;
pub use bug_commitment_test::*;
pub use bug_hash_mismatch_test::*;
pub use bug_output_type_test::*;
