//! Non-custodial escrow coordination
//!
//! This module provides the EscrowCoordinator which acts as a pure coordinator
//! for client-side wallets, inspired by Haveno DEX architecture.
//!
//! **CRITICAL SECURITY PRINCIPLE:**
//! The server NEVER creates or manages wallets. It ONLY coordinates the exchange
//! of public multisig info between clients who run their own local wallet-rpc instances.
//!
//! **Architecture:**
//! - Clients: Run local monero-wallet-rpc, execute prepare_multisig locally
//! - Server: Coordinates multisig info exchange, validates formats and thresholds
//! - Private keys: NEVER leave client wallets
//!
//! **Comparison to Haveno DEX:**
//! This implementation follows Haveno's pattern where the server is a pure coordinator
//! without any access to wallet private keys or multisig operations.

pub mod db_multisig_coordinator;
pub mod escrow_coordinator;
pub mod multisig_coordinator;

pub use db_multisig_coordinator::DbMultisigCoordinator;
pub use escrow_coordinator::{
    CoordinationState, EscrowCoordination, EscrowCoordinator, EscrowRole, MultisigExchangeResult,
};

pub use multisig_coordinator::{
    MultisigCoordinationError, MultisigCoordinator, MultisigSession, MultisigStage,
    MultisigStatusResponse, ParticipantState, ParticipantType,
};
