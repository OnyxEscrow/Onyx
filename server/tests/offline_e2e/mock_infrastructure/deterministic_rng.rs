//! Deterministic RNG for Reproducible Tests
//!
//! All cryptographic tests must be deterministic to ensure:
//! 1. Reproducible results across runs
//! 2. Debuggable failures (same inputs → same outputs)
//! 3. CI/CD reliability

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Default seed for test reproducibility
/// Using a fixed seed ensures all tests produce identical results every run
pub const DEFAULT_TEST_SEED: [u8; 32] = [
    0x4E, 0x45, 0x58, 0x55, 0x53, 0x5F, 0x54, 0x45, // "NEXUS_TE"
    0x53, 0x54, 0x5F, 0x53, 0x45, 0x45, 0x44, 0x5F, // "ST_SEED_"
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // "01234567"
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, // "89ABCDEF"
];

/// Deterministic RNG wrapper for testing
///
/// Wraps ChaCha20Rng with a fixed seed for reproducible cryptographic operations.
/// All test fixtures and mock data should use this RNG.
pub struct DeterministicRng {
    inner: ChaCha20Rng,
    seed: [u8; 32],
    bytes_generated: u64,
}

impl DeterministicRng {
    /// Create a new deterministic RNG with the default test seed
    pub fn new() -> Self {
        Self::with_seed(DEFAULT_TEST_SEED)
    }

    /// Create a deterministic RNG with a custom seed
    pub fn with_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
            seed,
            bytes_generated: 0,
        }
    }

    /// Create a deterministic RNG with a named seed (for test isolation)
    ///
    /// Different test categories can use different named seeds to ensure
    /// they don't interfere with each other while remaining deterministic.
    pub fn with_name(name: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"NEXUS_TEST_RNG_");
        hasher.update(name.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        Self::with_seed(hash)
    }

    /// Get the seed used for this RNG (for debugging/logging)
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get total bytes generated (for debugging)
    pub fn bytes_generated(&self) -> u64 {
        self.bytes_generated
    }

    /// Generate a deterministic 32-byte value (e.g., for scalars, keys)
    pub fn gen_32_bytes(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a deterministic scalar (reduced mod l)
    pub fn gen_scalar(&mut self) -> curve25519_dalek::scalar::Scalar {
        let bytes = self.gen_32_bytes();
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order(bytes)
    }

    /// Generate a deterministic Edwards point
    pub fn gen_point(&mut self) -> curve25519_dalek::edwards::EdwardsPoint {
        let scalar = self.gen_scalar();
        scalar * curve25519_dalek::constants::ED25519_BASEPOINT_POINT
    }

    /// Generate a deterministic hex string of given length
    pub fn gen_hex(&mut self, byte_length: usize) -> String {
        let mut bytes = vec![0u8; byte_length];
        self.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Reset to initial state (re-seed with same seed)
    pub fn reset(&mut self) {
        self.inner = ChaCha20Rng::from_seed(self.seed);
        self.bytes_generated = 0;
    }

    /// Fill a byte slice with deterministic random bytes
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
        self.bytes_generated += dest.len() as u64;
    }

    /// Generate a u64 in range [0, max)
    pub fn gen_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes) % max
    }

    /// Generate a bool with given probability of true (0.0 to 1.0)
    pub fn gen_bool(&mut self, probability: f64) -> bool {
        let threshold = (probability * u64::MAX as f64) as u64;
        let value = self.gen_range(u64::MAX);
        value < threshold
    }
}

impl Default for DeterministicRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
        self.bytes_generated += dest.len() as u64;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.inner.try_fill_bytes(dest)?;
        self.bytes_generated += dest.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determinism() {
        let mut rng1 = DeterministicRng::new();
        let mut rng2 = DeterministicRng::new();

        // Same seed → same sequence
        for _ in 0..100 {
            assert_eq!(rng1.gen_32_bytes(), rng2.gen_32_bytes());
        }
    }

    #[test]
    fn test_different_seeds_different_output() {
        let mut rng1 = DeterministicRng::with_name("test1");
        let mut rng2 = DeterministicRng::with_name("test2");

        // Different seeds → different sequences
        let bytes1 = rng1.gen_32_bytes();
        let bytes2 = rng2.gen_32_bytes();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_reset() {
        let mut rng = DeterministicRng::new();

        let first_run: Vec<[u8; 32]> = (0..10).map(|_| rng.gen_32_bytes()).collect();

        rng.reset();

        let second_run: Vec<[u8; 32]> = (0..10).map(|_| rng.gen_32_bytes()).collect();

        assert_eq!(first_run, second_run);
    }

    #[test]
    fn test_bytes_generated_tracking() {
        let mut rng = DeterministicRng::new();
        assert_eq!(rng.bytes_generated(), 0);

        let _ = rng.gen_32_bytes();
        assert_eq!(rng.bytes_generated(), 32);

        let _ = rng.gen_32_bytes();
        assert_eq!(rng.bytes_generated(), 64);
    }
}
