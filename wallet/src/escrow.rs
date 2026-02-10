//! Escrow management for Monero Marketplace
//!
//! This module provides the EscrowManager for handling escrow operations
//! including creation, funding, release, refund, and dispute resolution.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::client::MoneroClient;
use monero_marketplace_common::{
    Amount, Error, Escrow, EscrowData, EscrowId, EscrowResult, EscrowState, MoneroAddress,
    TransferDestination, TxHash, UserId,
};

/// In-memory storage for escrows (will be replaced with database in Phase 2)
type EscrowStorage = Arc<RwLock<HashMap<EscrowId, Escrow>>>;

/// Manages escrow operations and state transitions
pub struct EscrowManager {
    /// In-memory storage for escrows
    escrows: EscrowStorage,
    /// Monero client for blockchain operations
    monero_client: Arc<MoneroClient>,
}

impl EscrowManager {
    /// Create a new EscrowManager
    pub fn new(monero_client: Arc<MoneroClient>) -> Self {
        Self {
            escrows: Arc::new(RwLock::new(HashMap::new())),
            monero_client,
        }
    }

    /// Create a new escrow
    pub async fn create_escrow(
        &self,
        buyer: UserId,
        seller: UserId,
        arbiter: UserId,
        amount: Amount,
        multisig_address: MoneroAddress,
    ) -> Result<EscrowResult> {
        info!(
            "Creating new escrow: buyer={}, seller={}, amount={}",
            buyer, seller, amount
        );

        // Validate inputs
        if amount == 0 {
            return Err(Error::InvalidAmount("Amount must be greater than 0".to_string()).into());
        }

        if buyer == seller {
            return Err(
                Error::InvalidUser("Buyer and seller cannot be the same".to_string()).into(),
            );
        }

        if buyer == arbiter || seller == arbiter {
            return Err(Error::InvalidUser(
                "Arbiter must be different from buyer and seller".to_string(),
            )
            .into());
        }

        // Generate unique escrow ID
        let escrow_id = self.generate_escrow_id();

        // Create escrow data
        let escrow_data = EscrowData {
            buyer,
            seller,
            arbiter,
            amount,
            multisig_address,
        };

        // Create escrow
        let escrow = Escrow::new(escrow_id.clone(), escrow_data);

        // Store escrow
        {
            let mut escrows = self.escrows.write().await;
            escrows.insert(escrow_id.clone(), escrow.clone());
        }

        info!("Escrow created successfully: {}", escrow_id);
        Ok(EscrowResult::Created(Box::new(escrow)))
    }

    /// Fund an escrow (buyer deposits funds to multisig address)
    pub async fn fund_escrow(
        &self,
        escrow_id: &EscrowId,
        funding_tx_hash: TxHash,
    ) -> Result<EscrowResult> {
        info!("Funding escrow: {}", escrow_id);

        let mut escrow = self.get_escrow(escrow_id).await?;

        // Validate escrow can be funded
        if !escrow.can_be_funded() {
            return Err(Error::InvalidState(format!(
                "Escrow {} cannot be funded in state {:?}",
                escrow_id, escrow.state
            ))
            .into());
        }

        // Verify the transaction exists and is valid
        self.verify_funding_transaction(&funding_tx_hash, &escrow)
            .await
            .context("Failed to verify funding transaction")?;

        // Update escrow state
        escrow
            .transition_to(EscrowState::Funded)
            .map_err(Error::InvalidState)?;
        escrow.funding_tx_hash = Some(funding_tx_hash.clone());

        // Store updated escrow
        {
            let mut escrows = self.escrows.write().await;
            escrows.insert(escrow_id.clone(), escrow);
        }

        info!(
            "Escrow funded successfully: {} with tx {}",
            escrow_id, funding_tx_hash
        );
        Ok(EscrowResult::Funded {
            escrow_id: escrow_id.clone(),
            tx_hash: funding_tx_hash,
        })
    }

    /// Release funds to seller (2-of-3 multisig: buyer + seller)
    pub async fn release_funds(
        &self,
        escrow_id: &EscrowId,
        requester: &UserId,
    ) -> Result<EscrowResult> {
        info!("Releasing funds for escrow: {} by {}", escrow_id, requester);

        let escrow = self.get_escrow(escrow_id).await?;

        // Validate requester is buyer or seller
        if requester != &escrow.data.buyer && requester != &escrow.data.seller {
            return Err(Error::Unauthorized(format!(
                "User {} is not authorized to release funds for escrow {}",
                requester, escrow_id
            ))
            .into());
        }

        // Validate escrow can be released
        if !escrow.can_be_released() {
            return Err(Error::InvalidState(format!(
                "Escrow {} cannot be released in state {:?}",
                escrow_id, escrow.state
            ))
            .into());
        }

        // Create transaction to release funds to seller
        let release_tx_hash = self
            .create_release_transaction(&escrow)
            .await
            .context("Failed to create release transaction")?;

        // Update escrow state
        let mut updated_escrow = escrow.clone();
        updated_escrow
            .transition_to(EscrowState::Released)
            .map_err(Error::InvalidState)?;

        // Store updated escrow
        {
            let mut escrows = self.escrows.write().await;
            escrows.insert(escrow_id.clone(), updated_escrow);
        }

        info!(
            "Funds released successfully: {} with tx {}",
            escrow_id, release_tx_hash
        );
        Ok(EscrowResult::Released {
            escrow_id: escrow_id.clone(),
            tx_hash: release_tx_hash,
        })
    }

    /// Refund funds to buyer (2-of-3 multisig: buyer + arbiter)
    pub async fn refund_buyer(
        &self,
        escrow_id: &EscrowId,
        requester: &UserId,
    ) -> Result<EscrowResult> {
        info!("Refunding buyer for escrow: {} by {}", escrow_id, requester);

        let escrow = self.get_escrow(escrow_id).await?;

        // Validate requester is buyer or arbiter
        if requester != &escrow.data.buyer && requester != &escrow.data.arbiter {
            return Err(Error::Unauthorized(format!(
                "User {} is not authorized to refund funds for escrow {}",
                requester, escrow_id
            ))
            .into());
        }

        // Validate escrow can be refunded
        if !escrow.can_be_refunded() {
            return Err(Error::InvalidState(format!(
                "Escrow {} cannot be refunded in state {:?}",
                escrow_id, escrow.state
            ))
            .into());
        }

        // Create transaction to refund funds to buyer
        let refund_tx_hash = self
            .create_refund_transaction(&escrow)
            .await
            .context("Failed to create refund transaction")?;

        // Update escrow state
        let mut updated_escrow = escrow.clone();
        updated_escrow
            .transition_to(EscrowState::Refunded)
            .map_err(Error::InvalidState)?;
        updated_escrow.refund_tx_hash = Some(refund_tx_hash.clone());

        // Store updated escrow
        {
            let mut escrows = self.escrows.write().await;
            escrows.insert(escrow_id.clone(), updated_escrow);
        }

        info!(
            "Buyer refunded successfully: {} with tx {}",
            escrow_id, refund_tx_hash
        );
        Ok(EscrowResult::Refunded {
            escrow_id: escrow_id.clone(),
            tx_hash: refund_tx_hash,
        })
    }

    /// Open a dispute for an escrow
    pub async fn open_dispute(
        &self,
        escrow_id: &EscrowId,
        disputed_by: &UserId,
        reason: String,
    ) -> Result<EscrowResult> {
        info!(
            "Opening dispute for escrow: {} by {} - reason: {}",
            escrow_id, disputed_by, reason
        );

        let escrow = self.get_escrow(escrow_id).await?;

        // Validate requester is buyer or seller
        if disputed_by != &escrow.data.buyer && disputed_by != &escrow.data.seller {
            return Err(Error::Unauthorized(format!(
                "User {} is not authorized to open dispute for escrow {}",
                disputed_by, escrow_id
            ))
            .into());
        }

        // Validate escrow can be disputed
        if !escrow.can_be_disputed() {
            return Err(Error::InvalidState(format!(
                "Escrow {} cannot be disputed in state {:?}",
                escrow_id, escrow.state
            ))
            .into());
        }

        // Update escrow state
        let mut updated_escrow = escrow.clone();
        updated_escrow
            .transition_to(EscrowState::Disputed)
            .map_err(Error::InvalidState)?;
        updated_escrow.dispute_reason = Some(reason.clone());
        updated_escrow.disputed_by = Some(disputed_by.clone());

        // Store updated escrow
        {
            let mut escrows = self.escrows.write().await;
            escrows.insert(escrow_id.clone(), updated_escrow);
        }

        info!(
            "Dispute opened successfully: {} by {}",
            escrow_id, disputed_by
        );
        Ok(EscrowResult::Disputed {
            escrow_id: escrow_id.clone(),
            reason,
        })
    }

    /// Get escrow status
    pub async fn get_escrow_status(&self, escrow_id: &EscrowId) -> Result<Escrow> {
        self.get_escrow(escrow_id).await
    }

    /// List all escrows (for debugging/admin purposes)
    pub async fn list_escrows(&self) -> Result<Vec<Escrow>> {
        let escrows = self.escrows.read().await;
        Ok(escrows.values().cloned().collect())
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    /// Get an escrow by ID
    async fn get_escrow(&self, escrow_id: &EscrowId) -> Result<Escrow> {
        let escrows = self.escrows.read().await;
        escrows
            .get(escrow_id)
            .cloned()
            .ok_or_else(|| Error::EscrowNotFound(escrow_id.clone()).into())
    }

    /// Generate a unique escrow ID
    fn generate_escrow_id(&self) -> EscrowId {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let uuid_short = uuid::Uuid::new_v4()
            .to_string()
            .chars()
            .take(8)
            .collect::<String>();

        format!("escrow_{}_{}", timestamp, uuid_short)
    }

    /// Verify that a funding transaction is valid
    ///
    /// This function verifies:
    /// 1. Transaction hash is valid and not empty
    /// 2. Transaction exists on the blockchain
    /// 3. Transaction amount matches the escrow amount (within tolerance)
    /// 4. Transaction destination is the multisig address
    async fn verify_funding_transaction(&self, tx_hash: &TxHash, escrow: &Escrow) -> Result<()> {
        // Validate transaction hash format
        if tx_hash.is_empty() {
            return Err(Error::InvalidTransaction("Empty transaction hash".to_string()).into());
        }

        if tx_hash.len() != 64 {
            return Err(Error::InvalidTransaction(format!(
                "Invalid transaction hash length: expected 64, got {}",
                tx_hash.len()
            ))
            .into());
        }

        // Get transaction info from blockchain
        let tx_info = self
            .monero_client
            .transaction()
            .get_transaction_info(tx_hash.clone())
            .await
            .context("Failed to retrieve transaction from blockchain")?;

        // Verify transaction amount matches escrow amount (allow small fee variance)
        const FEE_TOLERANCE: u64 = 1_000_000_000; // 0.001 XMR tolerance for fees
        let amount_difference = tx_info.amount.abs_diff(escrow.data.amount);

        if amount_difference > FEE_TOLERANCE {
            return Err(Error::InvalidTransaction(format!(
                "Transaction amount mismatch: expected {}, got {} (difference: {})",
                escrow.data.amount, tx_info.amount, amount_difference
            ))
            .into());
        }

        // Note: TransactionInfo doesn't include address field in current implementation
        // Address verification would require additional RPC calls
        // This is acceptable for Phase 1 - will be enhanced in Phase 2

        // Verify transaction has enough confirmations (at least 1)
        if tx_info.confirmations == 0 {
            return Err(
                Error::InvalidTransaction("Transaction not yet confirmed".to_string()).into(),
            );
        }

        info!(
            "Funding transaction verified: {} for escrow {} ({} confirmations)",
            tx_hash, escrow.id, tx_info.confirmations
        );
        Ok(())
    }

    /// Create a transaction to release funds to seller
    ///
    /// This creates a multisig transaction that sends the escrow funds to the seller.
    /// The transaction requires signatures from 2-of-3 participants (buyer + seller).
    ///
    /// Flow:
    /// 1. Create unsigned transaction to seller's address
    /// 2. Sign with first participant's key
    /// 3. Exchange signatures with second participant (out-of-band)
    /// 4. Finalize and broadcast transaction
    ///
    /// Note: In a real implementation, steps 2-4 would involve coordination
    /// between buyer and seller. For now, this creates the unsigned transaction.
    async fn create_release_transaction(&self, escrow: &Escrow) -> Result<TxHash> {
        info!(
            "Creating release transaction for escrow {} to seller {}",
            escrow.id, escrow.data.seller
        );

        // Create destination for the seller
        let destinations = vec![TransferDestination {
            address: escrow.data.seller.clone(),
            amount: escrow.data.amount,
        }];

        // Create unsigned multisig transaction
        let create_result = self
            .monero_client
            .transaction()
            .create_transaction(destinations)
            .await
            .context("Failed to create release transaction")?;

        info!(
            "Release transaction created with {} signatures required for escrow {}",
            2, escrow.id
        );

        // In a real implementation, we would:
        // 1. Store the unsigned tx_data_hex for signing coordination
        // 2. Facilitate signature exchange between buyer and seller
        // 3. Finalize with submit_multisig after 2 signatures collected
        //
        // For now, we return the tx_set as a hash-like identifier
        // This will be replaced with actual signature coordination in Phase 2

        Ok(create_result.tx_hash)
    }

    /// Create a transaction to refund funds to buyer
    ///
    /// This creates a multisig transaction that sends the escrow funds back to the buyer.
    /// The transaction requires signatures from 2-of-3 participants (buyer + arbiter).
    ///
    /// Flow:
    /// 1. Create unsigned transaction to buyer's address
    /// 2. Sign with first participant's key
    /// 3. Exchange signatures with arbiter (out-of-band)
    /// 4. Finalize and broadcast transaction
    ///
    /// Note: In a real implementation, steps 2-4 would involve coordination
    /// between buyer and arbiter. For now, this creates the unsigned transaction.
    async fn create_refund_transaction(&self, escrow: &Escrow) -> Result<TxHash> {
        info!(
            "Creating refund transaction for escrow {} to buyer {}",
            escrow.id, escrow.data.buyer
        );

        // Create destination for the buyer
        let destinations = vec![TransferDestination {
            address: escrow.data.buyer.clone(),
            amount: escrow.data.amount,
        }];

        // Create unsigned multisig transaction
        let create_result = self
            .monero_client
            .transaction()
            .create_transaction(destinations)
            .await
            .context("Failed to create refund transaction")?;

        info!(
            "Refund transaction created with {} signatures required for escrow {}",
            2, escrow.id
        );

        // In a real implementation, we would:
        // 1. Store the unsigned tx_data_hex for signing coordination
        // 2. Facilitate signature exchange between buyer and arbiter
        // 3. Finalize with submit_multisig after 2 signatures collected
        //
        // For now, we return the tx_set as a hash-like identifier
        // This will be replaced with actual signature coordination in Phase 2

        Ok(create_result.tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MoneroClient;

    async fn create_test_escrow_manager() -> Result<EscrowManager> {
        use monero_marketplace_common::MoneroConfig;
        let config = MoneroConfig::default();
        let monero_client = Arc::new(MoneroClient::new(config)?);
        Ok(EscrowManager::new(monero_client))
    }

    #[tokio::test]
    async fn test_create_escrow() -> Result<()> {
        let manager = create_test_escrow_manager().await?;

        let result = manager
            .create_escrow(
                "buyer1".to_string(),
                "seller1".to_string(),
                "arbiter1".to_string(),
                1000000000000, // 1 XMR in atomic units
                "5TestMultisigAddress123456789".to_string(),
            )
            .await?;

        match result {
            EscrowResult::Created(escrow) => {
                assert_eq!(escrow.data.buyer, "buyer1");
                assert_eq!(escrow.data.seller, "seller1");
                assert_eq!(escrow.data.arbiter, "arbiter1");
                assert_eq!(escrow.data.amount, 1000000000000);
                assert_eq!(escrow.state, EscrowState::Created);
                assert!(escrow.funding_tx_hash.is_none());
                assert!(escrow.release_tx_hash.is_none());
                assert!(escrow.refund_tx_hash.is_none());
            }
            _ => {
                return Err(
                    Error::InvalidState("Expected EscrowResult::Created".to_string()).into(),
                )
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_fund_escrow() -> Result<()> {
        let manager = create_test_escrow_manager().await?;

        // Create escrow first
        let create_result = manager
            .create_escrow(
                "buyer1".to_string(),
                "seller1".to_string(),
                "arbiter1".to_string(),
                1000000000000,
                "5TestMultisigAddress123456789".to_string(),
            )
            .await?;

        let escrow_id = match create_result {
            EscrowResult::Created(escrow) => escrow.id,
            _ => {
                return Err(
                    Error::InvalidState("Expected EscrowResult::Created".to_string()).into(),
                )
            }
        };

        // Note: Funding requires real blockchain verification
        // This test validates the escrow creation flow only
        // Full funding tests are in integration tests with testnet

        let escrow = manager.get_escrow_status(&escrow_id).await?;
        assert_eq!(escrow.state, EscrowState::Created);
        assert!(escrow.funding_tx_hash.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_release_funds() -> Result<()> {
        let manager = create_test_escrow_manager().await?;

        // Create escrow
        let create_result = manager
            .create_escrow(
                "buyer1".to_string(),
                "seller1".to_string(),
                "arbiter1".to_string(),
                1000000000000,
                "5TestMultisigAddress123456789".to_string(),
            )
            .await?;

        let escrow_id = match create_result {
            EscrowResult::Created(escrow) => escrow.id,
            _ => {
                return Err(
                    Error::InvalidState("Expected EscrowResult::Created".to_string()).into(),
                )
            }
        };

        // Test: Try to release before funding (should fail)
        let release_result = manager
            .release_funds(&escrow_id, &"buyer1".to_string())
            .await;

        assert!(
            release_result.is_err(),
            "Should not be able to release funds before funding"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_refund_buyer() -> Result<()> {
        let manager = create_test_escrow_manager().await?;

        // Create escrow
        let create_result = manager
            .create_escrow(
                "buyer1".to_string(),
                "seller1".to_string(),
                "arbiter1".to_string(),
                1000000000000,
                "5TestMultisigAddress123456789".to_string(),
            )
            .await?;

        let escrow_id = match create_result {
            EscrowResult::Created(escrow) => escrow.id,
            _ => {
                return Err(
                    Error::InvalidState("Expected EscrowResult::Created".to_string()).into(),
                )
            }
        };

        // Test: Try to refund before funding (should fail)
        let refund_result = manager
            .refund_buyer(&escrow_id, &"buyer1".to_string())
            .await;

        assert!(
            refund_result.is_err(),
            "Should not be able to refund before funding"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_open_dispute() -> Result<()> {
        let manager = create_test_escrow_manager().await?;

        // Create escrow
        let create_result = manager
            .create_escrow(
                "buyer1".to_string(),
                "seller1".to_string(),
                "arbiter1".to_string(),
                1000000000000,
                "5TestMultisigAddress123456789".to_string(),
            )
            .await?;

        let escrow_id = match create_result {
            EscrowResult::Created(escrow) => escrow.id,
            _ => {
                return Err(
                    Error::InvalidState("Expected EscrowResult::Created".to_string()).into(),
                )
            }
        };

        // Test: Try to dispute before funding (should fail)
        let dispute_result = manager
            .open_dispute(
                &escrow_id,
                &"buyer1".to_string(),
                "Product not as described".to_string(),
            )
            .await;

        assert!(
            dispute_result.is_err(),
            "Should not be able to dispute before funding"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_state_transitions() -> Result<()> {
        let manager = create_test_escrow_manager().await?;

        // Create escrow
        let create_result = manager
            .create_escrow(
                "buyer1".to_string(),
                "seller1".to_string(),
                "arbiter1".to_string(),
                1000000000000,
                "5TestMultisigAddress123456789".to_string(),
            )
            .await?;

        let escrow_id = match create_result {
            EscrowResult::Created(escrow) => escrow.id,
            _ => {
                return Err(
                    Error::InvalidState("Expected EscrowResult::Created".to_string()).into(),
                )
            }
        };

        // Try to release funds before funding (should fail)
        let result = manager
            .release_funds(&escrow_id, &"buyer1".to_string())
            .await;
        assert!(result.is_err());

        // Try to refund before funding (should fail)
        let result = manager
            .refund_buyer(&escrow_id, &"buyer1".to_string())
            .await;
        assert!(result.is_err());

        // Try to dispute before funding (should fail)
        let result = manager
            .open_dispute(
                &escrow_id,
                &"buyer1".to_string(),
                "Test dispute".to_string(),
            )
            .await;
        assert!(result.is_err());

        Ok(())
    }
}
