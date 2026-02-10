//! Multisig functionality for Monero escrow

use crate::rpc::MoneroRpcClient;
use monero_marketplace_common::{
    error::{Error, MoneroError, Result},
    types::{
        ExchangeMultisigKeysResult, ExportMultisigInfoResult, ImportMultisigInfoResult,
        MakeMultisigResult, MultisigInfo,
    },
};

/// Multisig manager for handling escrow operations
pub struct MultisigManager {
    rpc_client: MoneroRpcClient,
}

impl MultisigManager {
    /// Create a new multisig manager
    pub fn new(rpc_client: MoneroRpcClient) -> Self {
        Self { rpc_client }
    }

    /// Prepare multisig (step 1/6 of multisig setup)
    ///
    /// Generates multisig info for this wallet that must be shared
    /// with other participants.
    pub async fn prepare_multisig(&self) -> Result<MultisigInfo> {
        self.rpc_client
            .prepare_multisig()
            .await
            .map_err(|e| match e {
                MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
                MoneroError::AlreadyMultisig => {
                    Error::Multisig("Already in multisig mode".to_string())
                }
                MoneroError::NotMultisig => Error::Multisig("Not in multisig mode".to_string()),
                MoneroError::WalletLocked => Error::Wallet("Wallet locked".to_string()),
                MoneroError::ValidationError(msg) => Error::InvalidInput(msg),
                MoneroError::InvalidResponse(msg) => {
                    Error::MoneroRpc(format!("Invalid response: {}", msg))
                }
                MoneroError::NetworkError(msg) => {
                    Error::Internal(format!("Network error: {}", msg))
                }
                MoneroError::RpcError(msg) => Error::MoneroRpc(msg),
                MoneroError::WalletBusy => Error::Wallet("Wallet busy".to_string()),
            })
    }

    /// Make multisig (step 2/6 of multisig setup)
    ///
    /// Creates a 2-of-3 multisig wallet by combining multisig info
    /// from all participants.
    ///
    /// # Arguments
    /// * `threshold` - Number of signatures required (2 for 2-of-3)
    /// * `multisig_infos` - Vec of multisig_info from other participants
    ///
    /// # Returns
    /// MakeMultisigResult containing:
    /// - `address`: Shared multisig address
    /// - `multisig_info`: Info for next step (export/import)
    pub async fn make_multisig(
        &self,
        threshold: u32,
        multisig_infos: Vec<String>,
    ) -> Result<MakeMultisigResult> {
        self.rpc_client
            .make_multisig(threshold, multisig_infos)
            .await
            .map_err(|e| match e {
                MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
                MoneroError::AlreadyMultisig => {
                    Error::Multisig("Already in multisig mode".to_string())
                }
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
            })
    }

    /// Exchange multisig keys (Round 2 finalization for 2-of-3)
    ///
    /// **CRITIQUE**: Cette méthode finalise le setup multisig 2-of-3 en échangeant
    /// les clés retournées par `make_multisig` (Round 1).
    ///
    /// # Protocole Monero Multisig 2-of-3
    /// ```text
    /// Round 0: prepare_multisig()           → prepare_info
    /// Round 1: make_multisig(prepare_infos) → address + multisig_info
    /// Round 2: exchange_multisig_keys(round1_infos) → finalise le wallet ✅
    /// ```
    ///
    /// Après cet appel, le wallet peut appeler `export_multisig_info()` et voir
    /// les transactions entrantes.
    ///
    /// # Arguments
    /// * `multisig_infos` - Vec des `multisig_info` retournés par `make_multisig` (Round 1)
    ///                      des AUTRES participants (N-1 = 2 pour 2-of-3)
    ///
    /// # Returns
    /// ExchangeMultisigKeysResult containing:
    /// - `address`: Adresse multisig finale (identique à Round 1)
    /// - `multisig_info`: Info de clé (peut être vide après finalisation)
    ///
    /// # Références
    /// - https://www.getmonero.org/resources/developer-guides/wallet-rpc.html
    /// - https://www.getmonero.org/resources/user-guides/multisig-messaging-system.html
    pub async fn exchange_multisig_keys(
        &self,
        multisig_infos: Vec<String>,
    ) -> Result<ExchangeMultisigKeysResult> {
        self.rpc_client
            .exchange_multisig_keys(multisig_infos)
            .await
            .map_err(|e| match e {
                MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
                MoneroError::AlreadyMultisig => {
                    Error::Multisig("Already in multisig mode".to_string())
                }
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
            })
    }

    /// Export multisig info (step 3/6 of multisig setup)
    ///
    /// Exporte les informations de synchronisation du wallet.
    /// Cette fonction doit être appelée DEUX fois:
    /// - Round 1: Après make_multisig
    /// - Round 2: Après premier import_multisig_info
    ///
    /// # Returns
    /// ExportMultisigInfoResult containing the info to share with other participants
    pub async fn export_multisig_info(&self) -> Result<ExportMultisigInfoResult> {
        self.rpc_client
            .export_multisig_info()
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

    /// Import multisig info (step 4/6 of multisig setup)
    ///
    /// Importe les informations de synchronisation des autres participants.
    /// Cette fonction doit être appelée DEUX fois:
    /// - Round 1: Importer infos après make_multisig
    /// - Round 2: Importer infos après premier export round 2
    ///
    /// # Arguments
    /// * `multisig_infos` - Vec des infos exportées des AUTRES participants (N-1)
    ///
    /// # Returns
    /// ImportMultisigInfoResult with number of outputs imported
    pub async fn import_multisig_info(
        &self,
        multisig_infos: Vec<String>,
    ) -> Result<ImportMultisigInfoResult> {
        self.rpc_client
            .import_multisig_info(multisig_infos)
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

    /// Helper: Effectue un round complet d'export/import pour synchronisation
    ///
    /// Cette fonction doit être appelée DEUX fois pour compléter la synchronisation multisig.
    /// Elle encapsule le pattern export → échanger → importer.
    ///
    /// # Arguments
    /// * `get_other_exports` - Fonction async qui récupère les exports des autres participants
    ///   Cette fonction permet l'échange out-of-band (PGP, Tor, Signal, etc.)
    ///
    /// # Returns
    /// (export_info, import_result) - Les infos exportées et le résultat de l'import
    ///
    /// # Examples
    /// ```no_run
    /// # use monero_marketplace_wallet::multisig::MultisigManager;
    /// # use monero_marketplace_common::error::Result;
    /// # async fn example(manager: &MultisigManager) -> Result<()> {
    /// // Round 1
    /// let (my_export_r1, import_r1) = manager
    ///     .sync_multisig_round(|| async {
    ///         // Ici: échanger les exports via canal sécurisé
    ///         // Par exemple: récupérer via Tor .onion, PGP email, etc.
    ///         let other_exports = vec!["...".to_string(), "...".to_string()];
    ///         Ok(other_exports)
    ///     })
    ///     .await?;
    ///
    /// // Round 2
    /// let (my_export_r2, import_r2) = manager
    ///     .sync_multisig_round(|| async {
    ///         let other_exports = vec!["...".to_string(), "...".to_string()];
    ///         Ok(other_exports)
    ///     })
    ///     .await?;
    ///
    /// // Maintenant synchronisé!
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sync_multisig_round<F, Fut>(
        &self,
        get_other_exports: F,
    ) -> Result<(ExportMultisigInfoResult, ImportMultisigInfoResult)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<String>>>,
    {
        // 1. Exporter nos infos
        let my_export = self.export_multisig_info().await?;

        // 2. Récupérer exports des autres (via canal sécurisé)
        let other_exports = get_other_exports().await?;

        // 3. Importer les infos des autres
        let import_result = self.import_multisig_info(other_exports).await?;

        Ok((my_export, import_result))
    }

    /// Check if wallet is multisig
    pub async fn is_multisig(&self) -> Result<bool> {
        self.rpc_client.is_multisig().await.map_err(|e| match e {
            MoneroError::RpcUnreachable => Error::MoneroRpc("RPC unreachable".to_string()),
            MoneroError::AlreadyMultisig => Error::Multisig("Already in multisig mode".to_string()),
            MoneroError::NotMultisig => Error::Multisig("Not in multisig mode".to_string()),
            MoneroError::WalletLocked => Error::Wallet("Wallet locked".to_string()),
            MoneroError::WalletBusy => Error::Wallet("Wallet busy".to_string()),
            MoneroError::ValidationError(msg) => Error::InvalidInput(msg),
            MoneroError::InvalidResponse(msg) => {
                Error::MoneroRpc(format!("Invalid response: {}", msg))
            }
            MoneroError::NetworkError(msg) => Error::Internal(format!("Network error: {}", msg)),
            MoneroError::RpcError(msg) => Error::MoneroRpc(msg),
        })
    }

    /// Get multisig info
    pub async fn get_multisig_info(&self) -> Result<MultisigInfo> {
        // Note: This delegates to the RPC client's export_multisig_info method
        // which returns the multisig info for this wallet
        let export_result = self
            .rpc_client
            .export_multisig_info()
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
            })?;

        Ok(MultisigInfo {
            multisig_info: export_result.info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_marketplace_common::types::MoneroConfig;

    #[tokio::test]
    async fn test_multisig_manager_creation() {
        let config = MoneroConfig::default();
        let rpc_client =
            MoneroRpcClient::new(config).expect("Failed to create RPC client for test");
        let _manager = MultisigManager::new(rpc_client);
        // Manager created successfully - test passes if no panic
    }

    // Note: Integration tests would require a running Monero wallet
    // These would be in tests/integration.rs
}
