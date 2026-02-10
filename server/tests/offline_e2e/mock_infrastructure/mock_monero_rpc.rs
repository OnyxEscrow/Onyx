//! Mock Monero RPC for Offline E2E Testing
//!
//! Simulates Monero wallet-rpc and daemon-rpc responses without network calls.
//! All responses are deterministic based on the test fixtures.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{test_fixtures::*, DeterministicRng, MockBlockchain};

/// Mock RPC error types (matching Monero's error codes)
#[derive(Clone, Debug)]
pub enum MockRpcError {
    WalletNotFound,
    InvalidAddress,
    InsufficientFunds,
    DoubleSpend,
    InvalidSignature,
    NetworkError(String),
    Custom(i64, String),
}

impl std::fmt::Display for MockRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WalletNotFound => write!(f, "Wallet not found"),
            Self::InvalidAddress => write!(f, "Invalid address"),
            Self::InsufficientFunds => write!(f, "Insufficient funds"),
            Self::DoubleSpend => write!(f, "Double spend attempt"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::Custom(code, msg) => write!(f, "Error {}: {}", code, msg),
        }
    }
}

/// Balance response from get_balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub balance: u64,
    pub unlocked_balance: u64,
    pub multisig_import_needed: bool,
    pub time_to_unlock: u64,
    pub blocks_to_unlock: u64,
}

/// Transfer info from get_transfer_by_txid
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferInfo {
    pub txid: String,
    pub payment_id: String,
    pub height: u64,
    pub timestamp: u64,
    pub amount: u64,
    pub fee: u64,
    pub confirmations: u64,
    #[serde(rename = "type")]
    pub transfer_type: String,
    pub unlock_time: u64,
    pub address: String,
}

/// Output info from get_outs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputInfo {
    pub key: String,
    pub mask: String,
    pub unlocked: bool,
    pub height: u64,
    pub txid: String,
}

/// Multisig info from is_multisig
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigInfo {
    pub multisig: bool,
    pub ready: bool,
    pub threshold: u32,
    pub total: u32,
}

/// Mock wallet state for testing
pub struct MockWallet {
    pub name: String,
    pub address: String,
    pub balance: u64,
    pub unlocked_balance: u64,
    pub is_multisig: bool,
    pub multisig_ready: bool,
    pub multisig_threshold: u32,
    pub multisig_total: u32,
    pub pending_transfers: Vec<TransferInfo>,
}

/// Mock Monero RPC client
///
/// Provides deterministic responses for all RPC methods used in Onyx.
/// Thread-safe with internal mutex for multi-threaded testing.
pub struct MockMoneroRpc {
    /// Wallets indexed by name
    wallets: Arc<Mutex<HashMap<String, MockWallet>>>,
    /// Currently open wallet
    current_wallet: Arc<Mutex<Option<String>>>,
    /// Mock blockchain for output/tx tracking
    blockchain: Arc<Mutex<MockBlockchain>>,
    /// Deterministic RNG for generating responses
    rng: Arc<Mutex<DeterministicRng>>,
    /// Whether to simulate network failures
    simulate_failures: Arc<Mutex<bool>>,
    /// Failure rate (0.0-1.0) when simulate_failures is true
    failure_rate: Arc<Mutex<f64>>,
}

impl MockMoneroRpc {
    /// Create a new mock RPC client
    pub fn new() -> Self {
        Self {
            wallets: Arc::new(Mutex::new(HashMap::new())),
            current_wallet: Arc::new(Mutex::new(None)),
            blockchain: Arc::new(Mutex::new(MockBlockchain::new())),
            rng: Arc::new(Mutex::new(DeterministicRng::with_name("mock_rpc"))),
            simulate_failures: Arc::new(Mutex::new(false)),
            failure_rate: Arc::new(Mutex::new(0.0)),
        }
    }

    /// Create a mock RPC with pre-populated test data
    pub fn with_test_data(seed: &str) -> Self {
        let mut rng = DeterministicRng::with_name(seed);
        let blockchain = MockBlockchain::with_test_data(&mut rng, 1000);

        let mock = Self {
            wallets: Arc::new(Mutex::new(HashMap::new())),
            current_wallet: Arc::new(Mutex::new(None)),
            blockchain: Arc::new(Mutex::new(blockchain)),
            rng: Arc::new(Mutex::new(rng)),
            simulate_failures: Arc::new(Mutex::new(false)),
            failure_rate: Arc::new(Mutex::new(0.0)),
        };

        // Create some test wallets
        let _ = mock.create_wallet("test_wallet_1", "password123");
        let _ = mock.create_wallet("test_wallet_2", "password456");

        mock
    }

    /// Enable failure simulation for testing error handling
    pub fn enable_failure_simulation(&self, rate: f64) {
        *self.simulate_failures.lock().unwrap() = true;
        *self.failure_rate.lock().unwrap() = rate.clamp(0.0, 1.0);
    }

    /// Disable failure simulation
    pub fn disable_failure_simulation(&self) {
        *self.simulate_failures.lock().unwrap() = false;
    }

    /// Check if this call should fail (for failure simulation)
    fn should_fail(&self) -> bool {
        let simulate = *self.simulate_failures.lock().unwrap();
        if !simulate {
            return false;
        }

        let rate = *self.failure_rate.lock().unwrap();
        self.rng.lock().unwrap().gen_bool(rate)
    }

    // ========================================================================
    // WALLET RPC METHODS
    // ========================================================================

    /// Create a new wallet
    pub fn create_wallet(&self, name: &str, _password: &str) -> Result<(), MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let mut rng = self.rng.lock().unwrap();
        let hex_encoded = hex::encode(&rng.gen_32_bytes());
        let address = format!("9{}", &hex_encoded[..hex_encoded.len().min(94)]);

        let wallet = MockWallet {
            name: name.to_string(),
            address,
            balance: 0,
            unlocked_balance: 0,
            is_multisig: false,
            multisig_ready: false,
            multisig_threshold: 0,
            multisig_total: 0,
            pending_transfers: Vec::new(),
        };

        self.wallets
            .lock()
            .unwrap()
            .insert(name.to_string(), wallet);
        Ok(())
    }

    /// Open an existing wallet
    pub fn open_wallet(&self, name: &str, _password: &str) -> Result<(), MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let wallets = self.wallets.lock().unwrap();
        if !wallets.contains_key(name) {
            return Err(MockRpcError::WalletNotFound);
        }

        *self.current_wallet.lock().unwrap() = Some(name.to_string());
        Ok(())
    }

    /// Close the current wallet
    pub fn close_wallet(&self) -> Result<(), MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        *self.current_wallet.lock().unwrap() = None;
        Ok(())
    }

    /// Get balance of current wallet
    pub fn get_balance(&self) -> Result<BalanceResponse, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let current = self.current_wallet.lock().unwrap();
        let wallet_name = current.as_ref().ok_or(MockRpcError::WalletNotFound)?;

        let wallets = self.wallets.lock().unwrap();
        let wallet = wallets
            .get(wallet_name)
            .ok_or(MockRpcError::WalletNotFound)?;

        Ok(BalanceResponse {
            balance: wallet.balance,
            unlocked_balance: wallet.unlocked_balance,
            multisig_import_needed: wallet.is_multisig && !wallet.multisig_ready,
            time_to_unlock: 0,
            blocks_to_unlock: 0,
        })
    }

    /// Get address of current wallet
    pub fn get_address(&self) -> Result<String, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let current = self.current_wallet.lock().unwrap();
        let wallet_name = current.as_ref().ok_or(MockRpcError::WalletNotFound)?;

        let wallets = self.wallets.lock().unwrap();
        let wallet = wallets
            .get(wallet_name)
            .ok_or(MockRpcError::WalletNotFound)?;

        Ok(wallet.address.clone())
    }

    /// Check if wallet is multisig
    pub fn is_multisig(&self) -> Result<MultisigInfo, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let current = self.current_wallet.lock().unwrap();
        let wallet_name = current.as_ref().ok_or(MockRpcError::WalletNotFound)?;

        let wallets = self.wallets.lock().unwrap();
        let wallet = wallets
            .get(wallet_name)
            .ok_or(MockRpcError::WalletNotFound)?;

        Ok(MultisigInfo {
            multisig: wallet.is_multisig,
            ready: wallet.multisig_ready,
            threshold: wallet.multisig_threshold,
            total: wallet.multisig_total,
        })
    }

    /// Prepare multisig info
    pub fn prepare_multisig(&self) -> Result<String, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let mut rng = self.rng.lock().unwrap();
        // Multisig info is typically 300-500 bytes of base64
        let info_bytes: Vec<u8> = (0..350).map(|_| rng.gen_range(256) as u8).collect();
        Ok(base64::encode(&info_bytes))
    }

    /// Make multisig wallet
    pub fn make_multisig(&self, infos: &[String], threshold: u32) -> Result<String, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let current = self.current_wallet.lock().unwrap();
        let wallet_name = current.as_ref().ok_or(MockRpcError::WalletNotFound)?;

        let mut wallets = self.wallets.lock().unwrap();
        let wallet = wallets
            .get_mut(wallet_name)
            .ok_or(MockRpcError::WalletNotFound)?;

        wallet.is_multisig = true;
        wallet.multisig_threshold = threshold;
        wallet.multisig_total = infos.len() as u32;

        // Generate new multisig address
        let mut rng = self.rng.lock().unwrap();
        let hex_encoded = hex::encode(&rng.gen_32_bytes());
        wallet.address = format!("9{}", &hex_encoded[..hex_encoded.len().min(94)]);

        // Generate additional round info
        let info_bytes: Vec<u8> = (0..350).map(|_| rng.gen_range(256) as u8).collect();
        Ok(base64::encode(&info_bytes))
    }

    /// Exchange multisig keys (finalize setup)
    pub fn exchange_multisig_keys(&self, infos: &[String]) -> Result<String, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let current = self.current_wallet.lock().unwrap();
        let wallet_name = current.as_ref().ok_or(MockRpcError::WalletNotFound)?;

        let mut wallets = self.wallets.lock().unwrap();
        let wallet = wallets
            .get_mut(wallet_name)
            .ok_or(MockRpcError::WalletNotFound)?;

        if infos.len() >= (wallet.multisig_total - 1) as usize {
            wallet.multisig_ready = true;
        }

        Ok(wallet.address.clone())
    }

    /// Get transfer by txid
    pub fn get_transfer_by_txid(&self, txid: &str) -> Result<TransferInfo, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let blockchain = self.blockchain.lock().unwrap();

        if let Some(tx) = blockchain.get_transaction(txid) {
            Ok(TransferInfo {
                txid: tx.hash.clone(),
                payment_id: String::new(),
                height: tx.block_height,
                timestamp: tx.timestamp,
                amount: tx.outputs.iter().map(|o| o.amount).sum(),
                fee: tx.fee,
                confirmations: tx.confirmations,
                transfer_type: "in".to_string(),
                unlock_time: 0,
                address: String::new(),
            })
        } else {
            Err(MockRpcError::Custom(
                -1,
                format!("Transaction {} not found", txid),
            ))
        }
    }

    /// Submit a raw transaction
    pub fn submit_transfer(&self, tx_blob: &str) -> Result<String, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let mut rng = self.rng.lock().unwrap();
        let tx_hash = rng.gen_hex(32);

        // In a real mock, we'd parse tx_blob and validate it
        // For now, just return a hash

        Ok(tx_hash)
    }

    // ========================================================================
    // DAEMON RPC METHODS
    // ========================================================================

    /// Get outputs (for ring members)
    pub fn get_outs(&self, indices: &[u64]) -> Result<Vec<OutputInfo>, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let blockchain = self.blockchain.lock().unwrap();
        let mut rng = self.rng.lock().unwrap();

        let mut outputs = Vec::new();
        for &idx in indices {
            if let Some(output) = blockchain.get_output(idx) {
                outputs.push(OutputInfo {
                    key: output.public_key.clone(),
                    mask: rng.gen_hex(32), // Commitment mask
                    unlocked: output.unlocked,
                    height: output.block_height,
                    txid: output.tx_hash.clone(),
                });
            } else {
                // Generate dummy output for missing indices
                outputs.push(OutputInfo {
                    key: hex::encode(rng.gen_point().compress().to_bytes()),
                    mask: rng.gen_hex(32),
                    unlocked: true,
                    height: blockchain.height() - rng.gen_range(1000),
                    txid: rng.gen_hex(32),
                });
            }
        }

        Ok(outputs)
    }

    /// Get blockchain height
    pub fn get_height(&self) -> Result<u64, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        Ok(self.blockchain.lock().unwrap().height())
    }

    /// Get info about the blockchain
    pub fn get_info(&self) -> Result<HashMap<String, serde_json::Value>, MockRpcError> {
        if self.should_fail() {
            return Err(MockRpcError::NetworkError("Simulated failure".to_string()));
        }

        let blockchain = self.blockchain.lock().unwrap();
        let stats = blockchain.stats();

        let mut info = HashMap::new();
        info.insert("height".to_string(), serde_json::json!(stats.height));
        info.insert("testnet".to_string(), serde_json::json!(true));
        info.insert("stagenet".to_string(), serde_json::json!(false));
        info.insert("mainnet".to_string(), serde_json::json!(false));
        info.insert("synchronized".to_string(), serde_json::json!(true));

        Ok(info)
    }

    // ========================================================================
    // TEST HELPERS
    // ========================================================================

    /// Set balance for a wallet (for testing)
    pub fn set_wallet_balance(&self, wallet_name: &str, balance: u64, unlocked: u64) {
        let mut wallets = self.wallets.lock().unwrap();
        if let Some(wallet) = wallets.get_mut(wallet_name) {
            wallet.balance = balance;
            wallet.unlocked_balance = unlocked;
        }
    }

    /// Add funds to the blockchain and wallet
    pub fn fund_wallet(&self, wallet_name: &str, amount: u64) -> Option<String> {
        let mut wallets = self.wallets.lock().unwrap();
        let wallet = wallets.get_mut(wallet_name)?;

        let mut rng = self.rng.lock().unwrap();
        let mut blockchain = self.blockchain.lock().unwrap();

        let tx_hash = rng.gen_hex(32);
        let global_index = blockchain.stats().total_outputs as u64 + 1_000_000;

        let output = super::mock_blockchain::MockOutput {
            global_index,
            public_key: wallet.address.clone(),
            commitment: rng.gen_hex(32),
            amount,
            tx_hash: tx_hash.clone(),
            tx_output_index: 0,
            block_height: blockchain.height(),
            unlocked: true,
        };

        blockchain.add_output(output);

        wallet.balance += amount;
        wallet.unlocked_balance += amount;

        Some(tx_hash)
    }

    /// Advance blockchain height
    pub fn advance_blocks(&self, blocks: u64) {
        self.blockchain.lock().unwrap().advance_blocks(blocks);
    }

    /// Get the mock blockchain for direct manipulation
    pub fn blockchain(&self) -> Arc<Mutex<MockBlockchain>> {
        Arc::clone(&self.blockchain)
    }
}

impl Default for MockMoneroRpc {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MockMoneroRpc {
    fn clone(&self) -> Self {
        Self {
            wallets: Arc::clone(&self.wallets),
            current_wallet: Arc::clone(&self.current_wallet),
            blockchain: Arc::clone(&self.blockchain),
            rng: Arc::clone(&self.rng),
            simulate_failures: Arc::clone(&self.simulate_failures),
            failure_rate: Arc::clone(&self.failure_rate),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_operations() {
        let rpc = MockMoneroRpc::new();

        // Create and open wallet
        assert!(rpc.create_wallet("test", "pass").is_ok());
        assert!(rpc.open_wallet("test", "pass").is_ok());

        // Get address
        let address = rpc.get_address().unwrap();
        assert!(address.starts_with('9')); // Testnet address

        // Get balance (should be 0)
        let balance = rpc.get_balance().unwrap();
        assert_eq!(balance.balance, 0);
    }

    #[test]
    fn test_multisig_setup() {
        let rpc = MockMoneroRpc::new();
        rpc.create_wallet("msig", "pass").unwrap();
        rpc.open_wallet("msig", "pass").unwrap();

        // Prepare multisig
        let info1 = rpc.prepare_multisig().unwrap();
        assert!(!info1.is_empty());

        // Make multisig (2-of-3)
        let other_infos = vec!["dummy1".to_string(), "dummy2".to_string()];
        let _ = rpc.make_multisig(&other_infos, 2).unwrap();

        // Check multisig status
        let status = rpc.is_multisig().unwrap();
        assert!(status.multisig);
        assert_eq!(status.threshold, 2);
        assert_eq!(status.total, 2);
    }

    #[test]
    fn test_failure_simulation() {
        let rpc = MockMoneroRpc::new();
        rpc.create_wallet("test", "pass").unwrap();

        // Enable 100% failure rate
        rpc.enable_failure_simulation(1.0);

        // Operations should fail
        assert!(rpc.open_wallet("test", "pass").is_err());

        // Disable failures
        rpc.disable_failure_simulation();

        // Operations should succeed again
        assert!(rpc.open_wallet("test", "pass").is_ok());
    }

    #[test]
    fn test_fund_wallet() {
        let rpc = MockMoneroRpc::new();
        rpc.create_wallet("funded", "pass").unwrap();

        // Fund wallet
        let tx_hash = rpc.fund_wallet("funded", XMR_TO_ATOMIC).unwrap();
        assert_eq!(tx_hash.len(), 64);

        // Check balance
        rpc.open_wallet("funded", "pass").unwrap();
        let balance = rpc.get_balance().unwrap();
        assert_eq!(balance.balance, XMR_TO_ATOMIC);
    }
}
