//! Mock Infrastructure for Offline E2E Testing
//!
//! Provides deterministic mocks for all external dependencies:
//! - MockMoneroRpc: Simulates Monero RPC responses
//! - MockBlockchain: Simulates blockchain state
//! - TestFixtures: Pre-computed cryptographic test vectors
//! - DeterministicRng: Seeded RNG for reproducibility

pub mod deterministic_rng;
pub mod mock_blockchain;
pub mod mock_monero_rpc;
pub mod test_fixtures;

pub use deterministic_rng::*;
pub use mock_blockchain::*;
pub use mock_monero_rpc::*;
pub use test_fixtures::*;
