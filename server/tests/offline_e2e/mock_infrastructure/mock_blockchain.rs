//! Mock Blockchain for Offline E2E Testing
//!
//! Simulates blockchain state without external dependencies:
//! - Output tracking and key image detection
//! - Transaction verification
//! - Balance tracking

use std::collections::{HashMap, HashSet};

use super::{DeterministicRng, test_fixtures::*};

/// Simulated blockchain state
pub struct MockBlockchain {
    /// Outputs indexed by global output index
    outputs: HashMap<u64, MockOutput>,
    /// Spent key images (for double-spend detection)
    spent_key_images: HashSet<String>,
    /// Transactions by hash
    transactions: HashMap<String, MockTransaction>,
    /// Current blockchain height
    height: u64,
    /// Next available global output index
    next_output_index: u64,
}

/// A mock output on the blockchain
#[derive(Clone, Debug)]
pub struct MockOutput {
    pub global_index: u64,
    pub public_key: String,
    pub commitment: String,
    pub amount: u64,
    pub tx_hash: String,
    pub tx_output_index: u32,
    pub block_height: u64,
    pub unlocked: bool,
}

/// A mock transaction on the blockchain
#[derive(Clone, Debug)]
pub struct MockTransaction {
    pub hash: String,
    pub block_height: u64,
    pub confirmations: u64,
    pub inputs: Vec<MockInput>,
    pub outputs: Vec<MockOutput>,
    pub fee: u64,
    pub timestamp: u64,
}

/// A mock transaction input
#[derive(Clone, Debug)]
pub struct MockInput {
    pub key_image: String,
    pub ring_member_indices: Vec<u64>,
    pub amount: u64,
}

impl MockBlockchain {
    /// Create a new mock blockchain with initial state
    pub fn new() -> Self {
        Self {
            outputs: HashMap::new(),
            spent_key_images: HashSet::new(),
            transactions: HashMap::new(),
            height: 100_000,
            next_output_index: 1_000_000,
        }
    }

    /// Create a mock blockchain pre-populated with test data
    pub fn with_test_data(rng: &mut DeterministicRng, num_outputs: usize) -> Self {
        let mut blockchain = Self::new();

        // Generate test outputs
        for _ in 0..num_outputs {
            let output = MockOutput {
                global_index: blockchain.next_output_index,
                public_key: hex::encode(rng.gen_point().compress().to_bytes()),
                commitment: hex::encode(rng.gen_point().compress().to_bytes()),
                amount: 0, // Hidden in RingCT
                tx_hash: rng.gen_hex(32),
                tx_output_index: rng.gen_range(4) as u32,
                block_height: blockchain.height - rng.gen_range(1000),
                unlocked: true,
            };
            blockchain.outputs.insert(output.global_index, output);
            blockchain.next_output_index += 1;
        }

        blockchain
    }

    /// Get current blockchain height
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Set blockchain height (for testing time-locked outputs)
    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    /// Advance blockchain by N blocks
    pub fn advance_blocks(&mut self, blocks: u64) {
        self.height += blocks;
    }

    /// Get an output by global index
    pub fn get_output(&self, global_index: u64) -> Option<&MockOutput> {
        self.outputs.get(&global_index)
    }

    /// Get multiple outputs by global indices
    pub fn get_outputs(&self, global_indices: &[u64]) -> Vec<&MockOutput> {
        global_indices
            .iter()
            .filter_map(|idx| self.outputs.get(idx))
            .collect()
    }

    /// Check if a key image is already spent
    pub fn is_key_image_spent(&self, key_image: &str) -> bool {
        self.spent_key_images.contains(key_image)
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, hash: &str) -> Option<&MockTransaction> {
        self.transactions.get(hash)
    }

    /// Add a new output to the blockchain
    pub fn add_output(&mut self, output: MockOutput) -> u64 {
        let index = output.global_index;
        self.outputs.insert(index, output);
        index
    }

    /// Submit a transaction to the mock blockchain
    ///
    /// Returns Ok(tx_hash) if valid, Err(reason) if rejected
    pub fn submit_transaction(&mut self, tx: MockTransaction) -> Result<String, String> {
        // Check for double-spends
        for input in &tx.inputs {
            if self.is_key_image_spent(&input.key_image) {
                return Err(format!("Double spend detected: key image {} already spent", &input.key_image[..16]));
            }
        }

        // Verify all ring members exist
        for input in &tx.inputs {
            for idx in &input.ring_member_indices {
                if !self.outputs.contains_key(idx) {
                    return Err(format!("Ring member {} not found", idx));
                }
            }
        }

        // Mark key images as spent
        for input in &tx.inputs {
            self.spent_key_images.insert(input.key_image.clone());
        }

        // Add outputs
        for output in &tx.outputs {
            self.outputs.insert(output.global_index, output.clone());
        }

        let hash = tx.hash.clone();
        self.transactions.insert(tx.hash.clone(), tx);

        Ok(hash)
    }

    /// Get available ring members (unspent outputs older than 10 blocks)
    pub fn get_ring_members(&self, exclude_index: u64, count: usize) -> Vec<u64> {
        let min_height = self.height.saturating_sub(10);

        let mut candidates: Vec<_> = self
            .outputs
            .values()
            .filter(|o| o.unlocked && o.global_index != exclude_index && o.block_height <= min_height)
            .map(|o| o.global_index)
            .collect();

        candidates.sort();

        if candidates.len() <= count {
            candidates
        } else {
            // Select evenly distributed indices
            let step = candidates.len() / count;
            candidates.into_iter().step_by(step.max(1)).take(count).collect()
        }
    }

    /// Get balance for an address (sum of unspent outputs)
    pub fn get_balance(&self, address_public_key: &str) -> u64 {
        self.outputs
            .values()
            .filter(|o| o.public_key == address_public_key && o.unlocked)
            .map(|o| o.amount)
            .sum()
    }

    /// Get number of confirmations for a transaction
    pub fn get_confirmations(&self, tx_hash: &str) -> Option<u64> {
        self.transactions
            .get(tx_hash)
            .map(|tx| self.height.saturating_sub(tx.block_height))
    }

    /// Generate ring data for a specific output
    pub fn generate_ring_for_output(&self, real_global_index: u64, ring_size: usize) -> Option<RingResult> {
        let real_output = self.get_output(real_global_index)?;

        // Get ring members
        let mut ring_indices: Vec<u64> = self.get_ring_members(real_global_index, ring_size - 1);

        // Find position to insert real output
        let signer_index = ring_indices
            .iter()
            .position(|&idx| idx > real_global_index)
            .unwrap_or(ring_indices.len());

        ring_indices.insert(signer_index, real_global_index);

        // Truncate to ring_size
        ring_indices.truncate(ring_size);

        // Get public keys and commitments
        let ring_public_keys: Vec<String> = ring_indices
            .iter()
            .filter_map(|idx| self.outputs.get(idx))
            .map(|o| o.public_key.clone())
            .collect();

        let ring_commitments: Vec<String> = ring_indices
            .iter()
            .filter_map(|idx| self.outputs.get(idx))
            .map(|o| o.commitment.clone())
            .collect();

        if ring_public_keys.len() != ring_size || ring_commitments.len() != ring_size {
            return None;
        }

        Some(RingResult {
            ring_indices,
            ring_public_keys,
            ring_commitments,
            signer_index,
        })
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        self.outputs.clear();
        self.spent_key_images.clear();
        self.transactions.clear();
        self.height = 100_000;
        self.next_output_index = 1_000_000;
    }

    /// Get statistics about the mock blockchain
    pub fn stats(&self) -> BlockchainStats {
        BlockchainStats {
            height: self.height,
            total_outputs: self.outputs.len(),
            spent_key_images: self.spent_key_images.len(),
            transactions: self.transactions.len(),
        }
    }
}

impl Default for MockBlockchain {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of ring generation
#[derive(Clone, Debug)]
pub struct RingResult {
    pub ring_indices: Vec<u64>,
    pub ring_public_keys: Vec<String>,
    pub ring_commitments: Vec<String>,
    pub signer_index: usize,
}

/// Statistics about the mock blockchain
#[derive(Clone, Debug)]
pub struct BlockchainStats {
    pub height: u64,
    pub total_outputs: usize,
    pub spent_key_images: usize,
    pub transactions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_blockchain_creation() {
        let mut rng = DeterministicRng::new();
        let blockchain = MockBlockchain::with_test_data(&mut rng, 100);

        assert_eq!(blockchain.height(), 100_000);
        assert_eq!(blockchain.outputs.len(), 100);
    }

    #[test]
    fn test_double_spend_detection() {
        let mut blockchain = MockBlockchain::new();
        let mut rng = DeterministicRng::new();

        let key_image = rng.gen_hex(32);

        let tx1 = MockTransaction {
            hash: rng.gen_hex(32),
            block_height: blockchain.height,
            confirmations: 0,
            inputs: vec![MockInput {
                key_image: key_image.clone(),
                ring_member_indices: vec![],
                amount: 1_000_000_000_000,
            }],
            outputs: vec![],
            fee: 30_000_000,
            timestamp: 0,
        };

        // First submission should succeed
        assert!(blockchain.submit_transaction(tx1).is_ok());

        let tx2 = MockTransaction {
            hash: rng.gen_hex(32),
            block_height: blockchain.height,
            confirmations: 0,
            inputs: vec![MockInput {
                key_image: key_image.clone(),
                ring_member_indices: vec![],
                amount: 1_000_000_000_000,
            }],
            outputs: vec![],
            fee: 30_000_000,
            timestamp: 0,
        };

        // Second submission with same key image should fail
        let result = blockchain.submit_transaction(tx2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Double spend"));
    }

    #[test]
    fn test_ring_generation() {
        let mut rng = DeterministicRng::new();
        let blockchain = MockBlockchain::with_test_data(&mut rng, 100);

        // Get a random output index
        let real_index = *blockchain.outputs.keys().next().unwrap();

        let ring = blockchain.generate_ring_for_output(real_index, 16);
        assert!(ring.is_some());

        let ring = ring.unwrap();
        assert_eq!(ring.ring_indices.len(), 16);
        assert_eq!(ring.ring_public_keys.len(), 16);
        assert_eq!(ring.ring_commitments.len(), 16);
        assert!(ring.ring_indices.contains(&real_index));
    }

    #[test]
    fn test_confirmations() {
        let mut blockchain = MockBlockchain::new();
        let mut rng = DeterministicRng::new();

        let tx = MockTransaction {
            hash: rng.gen_hex(32),
            block_height: 99_990, // 10 blocks behind current
            confirmations: 10,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            timestamp: 0,
        };

        let hash = tx.hash.clone();
        blockchain.transactions.insert(tx.hash.clone(), tx);

        assert_eq!(blockchain.get_confirmations(&hash), Some(10));

        // Advance 5 blocks
        blockchain.advance_blocks(5);
        assert_eq!(blockchain.get_confirmations(&hash), Some(15));
    }
}
