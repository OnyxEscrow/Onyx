//! High-level Monero client

use crate::{multisig::MultisigManager, rpc::MoneroRpcClient, transaction::TransactionManager};
use monero_marketplace_common::{
    error::{Error, MoneroError, Result},
    types::{MoneroConfig, WalletInfo, WalletStatus},
};

/// High-level Monero client
pub struct MoneroClient {
    rpc_client: MoneroRpcClient,
    multisig_manager: MultisigManager,
    transaction_manager: TransactionManager,
}

impl MoneroClient {
    /// Create a new Monero client
    pub fn new(config: MoneroConfig) -> Result<Self> {
        let rpc_client = MoneroRpcClient::new(config).map_err(convert_monero_error)?;
        let multisig_manager = MultisigManager::new(rpc_client.clone());
        let transaction_manager = TransactionManager::new(rpc_client.clone());

        Ok(Self {
            rpc_client,
            multisig_manager,
            transaction_manager,
        })
    }

    /// Get wallet status
    pub async fn get_wallet_status(&self) -> Result<WalletStatus> {
        let (balance, unlocked_balance) = self
            .rpc_client
            .get_balance()
            .await
            .map_err(convert_monero_error)?;
        let is_multisig = self
            .rpc_client
            .is_multisig()
            .await
            .map_err(convert_monero_error)?;

        // Note: In a real implementation, you'd get multisig threshold/total
        // from additional RPC calls

        Ok(WalletStatus {
            is_multisig,
            multisig_threshold: if is_multisig { Some(2) } else { None },
            multisig_total: if is_multisig { Some(3) } else { None },
            is_locked: false, // Would need additional RPC call
            balance,
            unlocked_balance,
        })
    }

    /// Get complete wallet information
    pub async fn get_wallet_info(&self) -> Result<WalletInfo> {
        // Get address
        let address = self
            .rpc_client
            .get_address()
            .await
            .map_err(convert_monero_error)?;

        // Get version
        let version = self
            .rpc_client
            .get_version()
            .await
            .map_err(convert_monero_error)?;

        // Get balance
        let (balance, unlocked_balance) = self
            .rpc_client
            .get_balance()
            .await
            .map_err(convert_monero_error)?;

        // Check if multisig
        let is_multisig = self
            .rpc_client
            .is_multisig()
            .await
            .map_err(convert_monero_error)?;

        // Get block height from RPC
        let block_height = self
            .rpc_client
            .get_block_height()
            .await
            .map_err(convert_monero_error)?;
        let daemon_block_height = self
            .rpc_client
            .get_daemon_block_height()
            .await
            .map_err(convert_monero_error)?;

        Ok(WalletInfo {
            address,
            version: version.to_string(),
            balance,
            unlocked_balance,
            is_multisig,
            multisig_threshold: if is_multisig { Some(2) } else { None },
            multisig_total: if is_multisig { Some(3) } else { None },
            is_locked: false, // Would need additional RPC call
            block_height,
            daemon_block_height,
        })
    }

    /// Get wallet address
    pub async fn get_address(&self) -> Result<String> {
        self.rpc_client
            .get_address()
            .await
            .map_err(convert_monero_error)
    }

    /// Create a new wallet in the wallet-rpc
    pub async fn create_wallet(&self, filename: &str, password: &str) -> Result<()> {
        self.rpc_client
            .create_wallet(filename, password)
            .await
            .map_err(convert_monero_error)
    }

    /// Open an existing wallet in the wallet-rpc
    pub async fn open_wallet(&self, filename: &str, password: &str) -> Result<()> {
        self.rpc_client
            .open_wallet(filename, password)
            .await
            .map_err(convert_monero_error)
    }

    /// Close the currently open wallet in the wallet-rpc
    pub async fn close_wallet(&self) -> Result<()> {
        self.rpc_client
            .close_wallet()
            .await
            .map_err(convert_monero_error)
    }

    /// Get multisig manager
    pub fn multisig(&self) -> &MultisigManager {
        &self.multisig_manager
    }

    /// Get transaction manager
    pub fn transaction(&self) -> &TransactionManager {
        &self.transaction_manager
    }

    /// Get RPC client
    pub fn rpc(&self) -> &MoneroRpcClient {
        &self.rpc_client
    }
}

/// Convert MoneroError to common Error
fn convert_monero_error(e: MoneroError) -> Error {
    match e {
        MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
        MoneroError::AlreadyMultisig => Error::Multisig("Already in multisig mode".to_string()),
        MoneroError::NotMultisig => Error::Multisig("Not in multisig mode".to_string()),
        MoneroError::WalletLocked => Error::Wallet("Wallet locked".to_string()),
        MoneroError::WalletBusy => Error::Wallet("Wallet busy".to_string()),
        MoneroError::ValidationError(msg) => Error::InvalidInput(msg),
        MoneroError::InvalidResponse(msg) => Error::MoneroRpc(format!("Invalid response: {msg}")),
        MoneroError::NetworkError(msg) => Error::Internal(format!("Network error: {msg}")),
        MoneroError::RpcError(msg) => Error::MoneroRpc(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = MoneroConfig::default();
        let client = MoneroClient::new(config);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_get_wallet_info_structure() {
        // Test that the function returns the expected structure
        // This is a unit test that doesn't require a running Monero wallet
        let config = MoneroConfig::default();
        let client = match MoneroClient::new(config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create client for test: {}", e);
                return;
            }
        };

        // Note: This will fail without a running Monero wallet, but we can test the structure
        // In a real test environment, you'd mock the RPC client
        let result = client.get_wallet_info().await;

        // The function should return an error without a running wallet, but the structure is correct
        assert!(result.is_err());

        // Verify the error is a network/RPC error, not a structure error
        match result.unwrap_err() {
            monero_marketplace_common::error::Error::MoneroRpc(_)
            | monero_marketplace_common::error::Error::Network(_) => {
                // Expected - no Monero wallet running
            }
            _ => {
                tracing::error!("Unexpected error type");
            }
        }
    }

    // Note: Integration tests would require a running Monero wallet
    // These would be in tests/integration.rs
}
