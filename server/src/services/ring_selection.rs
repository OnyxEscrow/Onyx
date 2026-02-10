//! Ring member selection using Gamma distribution (Monero-compliant)
//!
//! This module implements the standard Monero ring member selection algorithm
//! based on gamma distribution with parameters derived from empirical analysis
//! of spend patterns on the Monero blockchain.
//!
//! Reference: Monero source code - src/wallet/wallet2.cpp gamma_picker

use rand_distr::{Distribution, Gamma};
use rand::rngs::OsRng;

/// Shape parameter (α) from Monero reference implementation
/// Derived from empirical analysis of output spend times
const GAMMA_SHAPE: f64 = 19.28;

/// Scale parameter (θ) from Monero reference implementation
/// Combined with shape to model realistic spend time distribution
const GAMMA_SCALE: f64 = 1.61;

/// Average block time in seconds (Monero standard)
const AVERAGE_BLOCK_TIME: u64 = 120;

/// Seconds per day for time conversion
const SECONDS_PER_DAY: f64 = 86400.0;

/// Ring member selector using gamma distribution
///
/// This provides EAE-attack resistant decoy selection by mimicking
/// the natural spending patterns observed on the Monero network.
pub struct RingSelector {
    gamma: Gamma<f64>,
}

impl Default for RingSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl RingSelector {
    /// Create a new ring selector with Monero-standard gamma parameters
    pub fn new() -> Self {
        Self {
            gamma: Gamma::new(GAMMA_SHAPE, GAMMA_SCALE)
                .expect("Invalid gamma parameters - this should never happen"),
        }
    }

    /// Select decoys for a ring using gamma distribution
    ///
    /// # Arguments
    /// * `histogram` - Available output indices (sorted by block height)
    /// * `real_output_index` - The actual output being spent (excluded from decoys)
    /// * `num_decoys` - Number of decoys to select (typically RING_SIZE - 1 = 15)
    ///
    /// # Returns
    /// Vector of decoy global indices
    pub fn select_decoys(
        &self,
        histogram: &[u64],
        real_output_index: u64,
        num_decoys: usize,
    ) -> Vec<u64> {
        let mut rng = OsRng;
        let mut decoys = Vec::with_capacity(num_decoys);
        let hist_len = histogram.len();

        if hist_len == 0 {
            return decoys;
        }

        while decoys.len() < num_decoys {
            // Sample from gamma distribution (days since output creation)
            let days = self.gamma.sample(&mut rng);

            // Convert days -> seconds -> blocks -> offset
            let seconds = (days * SECONDS_PER_DAY) as u64;
            let block_offset = seconds / AVERAGE_BLOCK_TIME;

            // Apply offset from most recent outputs (index backwards from end)
            let idx = if block_offset >= hist_len as u64 {
                // If offset exceeds histogram, wrap around
                (block_offset % hist_len as u64) as usize
            } else {
                // Normal case: select from recent outputs biased by gamma
                hist_len.saturating_sub(1 + block_offset as usize)
            };

            let global_idx = histogram[idx];

            // Ensure not duplicate and not the real output
            if global_idx != real_output_index && !decoys.contains(&global_idx) {
                decoys.push(global_idx);
            }
        }

        decoys
    }

    /// Select decoys with age-based offset (alternative method)
    ///
    /// This method computes offsets directly from the real output's position,
    /// useful when you have the real output's global index but not a full histogram.
    ///
    /// # Arguments
    /// * `real_index` - Global index of the real output
    /// * `total_outputs` - Total number of outputs in the blockchain
    /// * `num_decoys` - Number of decoys to select
    ///
    /// # Returns
    /// Vector of decoy global indices
    pub fn select_decoys_by_offset(
        &self,
        real_index: u64,
        total_outputs: u64,
        num_decoys: usize,
    ) -> Vec<u64> {
        let mut rng = OsRng;
        let mut decoys = Vec::with_capacity(num_decoys);

        if total_outputs == 0 {
            return decoys;
        }

        while decoys.len() < num_decoys {
            // Sample gamma and convert to output offset
            let days = self.gamma.sample(&mut rng);
            let seconds = (days * SECONDS_PER_DAY) as u64;
            let block_offset = seconds / AVERAGE_BLOCK_TIME;

            // Convert block offset to output index offset
            // Assume ~10 outputs per block on average (Monero typical)
            let output_offset = block_offset.saturating_mul(10);

            // Calculate candidate index (biased towards recent)
            let candidate = if output_offset > real_index {
                // If offset would go negative, use modulo
                real_index.saturating_sub(output_offset % (real_index.max(1)))
            } else {
                real_index.saturating_sub(output_offset)
            };

            // Ensure within bounds, not duplicate, not real output
            if candidate > 0
                && candidate < total_outputs
                && candidate != real_index
                && !decoys.contains(&candidate)
            {
                decoys.push(candidate);
            }
        }

        decoys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gamma_distribution_creates_correct_count() {
        let selector = RingSelector::new();
        let histogram: Vec<u64> = (0..1000).collect();
        let decoys = selector.select_decoys(&histogram, 500, 15);

        assert_eq!(decoys.len(), 15);
    }

    #[test]
    fn test_real_output_excluded() {
        let selector = RingSelector::new();
        let histogram: Vec<u64> = (0..1000).collect();
        let real_output = 500;
        let decoys = selector.select_decoys(&histogram, real_output, 15);

        assert!(!decoys.contains(&real_output));
    }

    #[test]
    fn test_no_duplicate_decoys() {
        let selector = RingSelector::new();
        let histogram: Vec<u64> = (0..100).collect();
        let decoys = selector.select_decoys(&histogram, 50, 15);

        let unique: std::collections::HashSet<_> = decoys.iter().collect();
        assert_eq!(unique.len(), decoys.len());
    }

    #[test]
    fn test_offset_method() {
        let selector = RingSelector::new();
        let decoys = selector.select_decoys_by_offset(1000000, 2000000, 15);

        assert_eq!(decoys.len(), 15);
        assert!(!decoys.contains(&1000000));
    }

    #[test]
    fn test_small_histogram() {
        let selector = RingSelector::new();
        let histogram: Vec<u64> = (0..20).collect();
        let decoys = selector.select_decoys(&histogram, 10, 15);

        assert_eq!(decoys.len(), 15);
        assert!(!decoys.contains(&10));
    }

    #[test]
    fn test_empty_histogram() {
        let selector = RingSelector::new();
        let histogram: Vec<u64> = vec![];
        let decoys = selector.select_decoys(&histogram, 0, 15);

        assert!(decoys.is_empty());
    }

    #[test]
    fn test_default_trait() {
        let selector = RingSelector::default();
        let histogram: Vec<u64> = (0..100).collect();
        let decoys = selector.select_decoys(&histogram, 50, 15);

        assert_eq!(decoys.len(), 15);
    }
}
