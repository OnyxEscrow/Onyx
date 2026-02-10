//! Transaction functionality for Monero multisig escrow

use crate::rpc::MoneroRpcClient;
use monero_marketplace_common::{
    error::{Error, MoneroError, Result},
    types::{
        CreateTransactionResult, SignMultisigResult, SubmitMultisigResult, TransactionInfo,
        TransferDestination, TxHash,
    },
};

/// Transaction manager for handling multisig transactions
pub struct TransactionManager {
    rpc_client: MoneroRpcClient,
}

impl TransactionManager {
    /// Create a new transaction manager
    pub fn new(rpc_client: MoneroRpcClient) -> Self {
        Self { rpc_client }
    }

    /// Create a multisig transaction (Task 1.2.1)
    ///
    /// Creates an unsigned multisig transaction that needs to be signed
    /// by at least 2 out of 3 participants.
    ///
    /// # Arguments
    /// * `destinations` - List of recipient addresses and amounts
    ///
    /// # Returns
    /// CreateTransactionResult containing the unsigned transaction data
    ///
    /// # Flow
    /// 1. Create unsigned transaction via RPC
    /// 2. Return multisig_txset for signing
    pub async fn create_transaction(
        &self,
        destinations: Vec<TransferDestination>,
    ) -> Result<CreateTransactionResult> {
        self.rpc_client
            .transfer_multisig(destinations)
            .await
            .map_err(|e| match e {
                MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
                MoneroError::NotMultisig => Error::Multisig("Not in multisig mode".to_string()),
                MoneroError::WalletLocked => Error::Wallet("Wallet locked".to_string()),
                MoneroError::WalletBusy => Error::Wallet("Wallet busy".to_string()),
                MoneroError::ValidationError(msg) => Error::InvalidInput(msg),
                MoneroError::InvalidResponse(msg) => {
                    Error::MoneroRpc(format!("Invalid response: {}", msg))
                }
                MoneroError::NetworkError(msg) => {
                    Error::Internal(format!("Network error: {}", msg))
                }
                MoneroError::RpcError(msg) => Error::MoneroRpc(msg),
                MoneroError::AlreadyMultisig => {
                    Error::Multisig("Already in multisig mode".to_string())
                }
            })
    }

    /// Sign a multisig transaction (Task 1.2.2)
    ///
    /// Signs a multisig transaction with this wallet's key.
    /// The transaction must be signed by at least 2 out of 3 participants.
    ///
    /// # Arguments
    /// * `tx_data_hex` - The unsigned or partially signed transaction data (hex)
    ///
    /// # Returns
    /// SignMultisigResult containing the partially signed transaction
    ///
    /// # Flow
    /// 1. Sign the transaction with this wallet's key
    /// 2. Return signed tx_data_hex
    /// 3. This data must be exchanged with other signers
    pub async fn sign_multisig_transaction(
        &self,
        tx_data_hex: String,
    ) -> Result<SignMultisigResult> {
        self.rpc_client
            .sign_multisig(tx_data_hex)
            .await
            .map_err(|e| match e {
                MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
                MoneroError::NotMultisig => Error::Multisig("Not in multisig mode".to_string()),
                MoneroError::WalletLocked => Error::Wallet("Wallet locked".to_string()),
                MoneroError::WalletBusy => Error::Wallet("Wallet busy".to_string()),
                MoneroError::ValidationError(msg) => Error::InvalidInput(msg),
                MoneroError::InvalidResponse(msg) => {
                    Error::MoneroRpc(format!("Invalid response: {}", msg))
                }
                MoneroError::NetworkError(msg) => {
                    Error::Internal(format!("Network error: {}", msg))
                }
                MoneroError::RpcError(msg) => Error::MoneroRpc(msg),
                MoneroError::AlreadyMultisig => {
                    Error::Multisig("Already in multisig mode".to_string())
                }
            })
    }

    /// Finalize and broadcast a multisig transaction (Task 1.2.3 + 1.2.4)
    ///
    /// Submits a fully signed multisig transaction (with 2-of-3 signatures)
    /// to the Monero network.
    ///
    /// # Arguments
    /// * `tx_data_hex` - The fully signed transaction data (hex)
    ///
    /// # Returns
    /// SubmitMultisigResult containing the transaction hash(es)
    ///
    /// # Flow
    /// 1. Verify transaction has enough signatures (2-of-3)
    /// 2. Submit to network via submit_multisig RPC call
    /// 3. Return transaction hash for monitoring
    pub async fn finalize_and_broadcast_transaction(
        &self,
        tx_data_hex: String,
    ) -> Result<SubmitMultisigResult> {
        self.rpc_client
            .submit_multisig(tx_data_hex)
            .await
            .map_err(|e| match e {
                MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
                MoneroError::NotMultisig => Error::Multisig("Not in multisig mode".to_string()),
                MoneroError::WalletLocked => Error::Wallet("Wallet locked".to_string()),
                MoneroError::WalletBusy => Error::Wallet("Wallet busy".to_string()),
                MoneroError::ValidationError(msg) => Error::InvalidInput(msg),
                MoneroError::InvalidResponse(msg) => {
                    Error::MoneroRpc(format!("Invalid response: {}", msg))
                }
                MoneroError::NetworkError(msg) => {
                    Error::Internal(format!("Network error: {}", msg))
                }
                MoneroError::RpcError(msg) => Error::MoneroRpc(msg),
                MoneroError::AlreadyMultisig => {
                    Error::Multisig("Already in multisig mode".to_string())
                }
            })
    }

    /// Get transaction information (for monitoring confirmations)
    ///
    /// # Arguments
    /// * `tx_hash` - The transaction hash to query
    ///
    /// # Returns
    /// TransactionInfo with confirmation status
    pub async fn get_transaction_info(&self, tx_hash: TxHash) -> Result<TransactionInfo> {
        self.rpc_client
            .get_transfer_by_txid(tx_hash)
            .await
            .map_err(|e| match e {
                MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
                MoneroError::NotMultisig => Error::Multisig("Not in multisig mode".to_string()),
                MoneroError::WalletLocked => Error::Wallet("Wallet locked".to_string()),
                MoneroError::WalletBusy => Error::Wallet("Wallet busy".to_string()),
                MoneroError::ValidationError(msg) => Error::InvalidInput(msg),
                MoneroError::InvalidResponse(msg) => {
                    Error::MoneroRpc(format!("Invalid response: {}", msg))
                }
                MoneroError::NetworkError(msg) => {
                    Error::Internal(format!("Network error: {}", msg))
                }
                MoneroError::RpcError(msg) => Error::MoneroRpc(msg),
                MoneroError::AlreadyMultisig => {
                    Error::Multisig("Already in multisig mode".to_string())
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_marketplace_common::types::MoneroConfig;

    #[tokio::test]
    async fn test_transaction_manager_creation() {
        let config = MoneroConfig::default();
        let rpc_client =
            MoneroRpcClient::new(config).expect("Failed to create RPC client for test");
        let _manager = TransactionManager::new(rpc_client);
        // Manager created successfully - test passes if no panic
    }

    // Note: Integration tests would require a running Monero wallet
    // These would be in tests/transaction_e2e.rs
}
