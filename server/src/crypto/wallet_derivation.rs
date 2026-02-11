//! Phase 6: Wallet Derivation Integration Module
//!
//! This module integrates all Phase 6 components to provide server-side
//! wallet derivation from user master seeds for escrow signing.
//!
//! # Architecture
//!
//! ```text
//! User Password + Salt
//!   └─> PBKDF2 (100k iterations)
//!       └─> Decryption Key
//!           └─> Decrypt Master Seed (AES-256-GCM)
//!               └─> HKDF(master_seed, escrow_id, role)
//!                   └─> Escrow Wallet Seed (32 bytes)
//!                       └─> restore_deterministic_wallet()
//!                           └─> Monero Wallet (ephemeral, <100ms lifetime)
//!                               └─> Sign Transaction
//!                                   └─> close_wallet() (zeroize keys)
//! ```
//!
//! # Security Model (Phase 6 MVP)
//!
//! - **Semi-custodial**: Server decrypts master seed during signing
//! - **Password required**: User must enter password for each signature
//! - **Ephemeral keys**: Keys exist in memory for <100ms
//! - **Zeroization**: All sensitive data cleared after use
//! - **No persistence**: Seeds never written to disk on server
//!
//! # Phase 7 Migration Path
//!
//! This module will be replaced with client-side WASM signing where:
//! - Master seed never leaves user's browser
//! - Server never has access to private keys
//! - True non-custodial architecture

use anyhow::Result;
use monero_marketplace_common::error::MoneroError;
use monero_marketplace_wallet::rpc::MoneroRpcClient;

use crate::crypto::{
    encryption::{decrypt_bytes, derive_key_from_password},
    seed_generation::{derive_escrow_wallet_seed, SensitiveBytes},
};

/// Restore ephemeral escrow wallet from user's encrypted master seed
///
/// This is the main entry point for Phase 6 server-side signing.
/// It orchestrates the full derivation pipeline.
///
/// # Arguments
///
/// * `encrypted_master_seed` - User's encrypted master seed (from database)
/// * `salt` - User's PBKDF2 salt (from database)
/// * `password` - User's password (entered at signing time)
/// * `escrow_id` - Escrow identifier for derivation
/// * `role` - User's role ("buyer", "seller", "arbiter")
/// * `rpc_client` - Monero wallet RPC client
///
/// # Returns
///
/// * `Ok(String)` - Wallet address (for verification)
///
/// # Security
///
/// - Password is validated against encrypted seed
/// - Master seed is decrypted in memory (never persisted)
/// - Escrow seed is derived deterministically
/// - Wallet is restored in RPC daemon
/// - **CRITICAL**: Caller MUST call `rpc_client.close_wallet()` after signing
///
/// # Errors
///
/// - Password incorrect (decryption fails)
/// - Invalid seed format
/// - RPC connection failure
/// - Wallet restoration failure
///
/// # Examples
///
/// ```no_run
/// use server::crypto::wallet_derivation::restore_ephemeral_wallet;
/// use monero_marketplace_wallet::rpc::MoneroRpcClient;
/// use monero_marketplace_common::types::MoneroConfig;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let rpc_client = MoneroRpcClient::new(MoneroConfig::default())?;
///
/// // From database
/// let encrypted_seed = vec![/* ... */];
/// let salt = vec![/* ... */];
///
/// // From user input
/// let password = "UserPassword123!";
///
/// let address = restore_ephemeral_wallet(
///     &encrypted_seed,
///     &salt,
///     password,
///     "escrow_001",
///     "buyer",
///     &rpc_client
/// ).await?;
///
/// println!("Wallet restored: {}", address);
///
/// // Sign transaction here...
///
/// // CRITICAL: Close wallet after signing
/// rpc_client.close_wallet().await?;
/// # Ok(())
/// # }
/// ```
pub async fn restore_ephemeral_wallet(
    encrypted_master_seed: &[u8],
    salt: &[u8],
    password: &str,
    escrow_id: &str,
    role: &str,
    rpc_client: &MoneroRpcClient,
) -> Result<String, MoneroError> {
    // Step 1: Derive decryption key from password
    let decryption_key = derive_key_from_password(password, salt)
        .map_err(|e| MoneroError::InvalidResponse(format!("Password derivation failed: {e}")))?;

    // Step 2: Decrypt master seed
    let master_seed = SensitiveBytes::new(
        decrypt_bytes(encrypted_master_seed, &decryption_key).map_err(|e| {
            MoneroError::InvalidResponse(format!("Decryption failed (wrong password?): {e}"))
        })?,
    );

    // Step 3: Derive escrow-specific wallet seed
    let escrow_seed = SensitiveBytes::new(
        derive_escrow_wallet_seed(master_seed.as_slice(), escrow_id, role)
            .map_err(|e| MoneroError::InvalidResponse(format!("Seed derivation failed: {e}")))?,
    );

    // Step 4: Convert to hex for Monero RPC
    let escrow_seed_hex = hex::encode(escrow_seed.as_slice());

    // Step 5: Restore wallet in RPC daemon
    let wallet_name = format!("escrow_{escrow_id}_{role}");

    let address = rpc_client
        .restore_deterministic_wallet(
            &wallet_name,
            &escrow_seed_hex,
            0,  // restore_height = 0 for new wallets
            "", // Empty password for ephemeral wallet
        )
        .await?;

    // Step 6: Explicit cleanup (zeroize happens on drop, but be explicit)
    drop(master_seed);
    drop(escrow_seed);

    tracing::debug!(
        "Ephemeral wallet restored for escrow {} role {} (address: {}...)",
        escrow_id,
        role,
        &address[..8]
    );

    Ok(address)
}

/// Derive wallet address WITHOUT restoring wallet (for display purposes)
///
/// This function derives the escrow wallet seed and converts it to a
/// Monero address WITHOUT creating a wallet in the RPC daemon.
///
/// **Use case**: Display expected address to user before signing.
///
/// # Note
///
/// This is a placeholder for Phase 6. Monero address derivation from
/// seed requires either:
/// 1. monero-rs library (not available for seed->address)
/// 2. Calling wallet RPC (which we do in restore_ephemeral_wallet)
///
/// For MVP, we'll just derive the seed and return it as hex.
/// The actual address is returned by restore_ephemeral_wallet().
///
/// # Arguments
///
/// * `master_seed` - User's master seed (16 bytes)
/// * `escrow_id` - Escrow identifier
/// * `role` - User's role
///
/// # Returns
///
/// * `String` - Derived seed as hex (not actual Monero address)
pub fn derive_expected_address(master_seed: &[u8], escrow_id: &str, role: &str) -> Result<String> {
    let escrow_seed = derive_escrow_wallet_seed(master_seed, escrow_id, role)?;
    Ok(hex::encode(&escrow_seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        encryption::{encrypt_bytes, generate_random_salt},
        seed_generation::generate_random_seed,
    };

    #[test]
    fn test_derive_expected_address() -> Result<()> {
        let master_seed = generate_random_seed(16)?;
        let escrow_id = "escrow_test_001";
        let role = "buyer";

        let address_hex = derive_expected_address(&master_seed, escrow_id, role)?;

        // Should be 64 hex chars (32 bytes)
        assert_eq!(address_hex.len(), 64);
        assert!(address_hex.chars().all(|c| c.is_ascii_hexdigit()));

        Ok(())
    }

    #[test]
    fn test_derive_expected_address_deterministic() -> Result<()> {
        let master_seed = vec![0x42; 16];
        let escrow_id = "escrow_123";
        let role = "seller";

        let addr1 = derive_expected_address(&master_seed, escrow_id, role)?;
        let addr2 = derive_expected_address(&master_seed, escrow_id, role)?;

        assert_eq!(addr1, addr2, "Derivation must be deterministic");

        Ok(())
    }

    #[test]
    fn test_derive_expected_address_different_roles() -> Result<()> {
        let master_seed = vec![0x42; 16];
        let escrow_id = "escrow_456";

        let buyer_addr = derive_expected_address(&master_seed, escrow_id, "buyer")?;
        let seller_addr = derive_expected_address(&master_seed, escrow_id, "seller")?;
        let arbiter_addr = derive_expected_address(&master_seed, escrow_id, "arbiter")?;

        assert_ne!(buyer_addr, seller_addr);
        assert_ne!(seller_addr, arbiter_addr);
        assert_ne!(buyer_addr, arbiter_addr);

        Ok(())
    }

    #[tokio::test]
    async fn test_restore_ephemeral_wallet_invalid_password() {
        let password = "CorrectPassword123!";
        let wrong_password = "WrongPassword123!";
        let salt = generate_random_salt(16).expect("Salt generation failed");

        // Generate and encrypt master seed
        let master_seed = generate_random_seed(16).expect("Seed generation failed");
        let key = derive_key_from_password(password, &salt).expect("Key derivation failed");
        let encrypted_seed = encrypt_bytes(&master_seed, &key).expect("Encryption failed");

        // Mock RPC client (will fail before reaching RPC)
        let config = monero_marketplace_common::types::MoneroConfig {
            rpc_url: "http://127.0.0.1:18082/json_rpc".to_string(),
            timeout_seconds: 30,
            rpc_user: None,
            rpc_password: None,
        };
        let rpc_client = MoneroRpcClient::new(config).expect("RPC client creation failed");

        // Attempt restoration with wrong password
        let result = restore_ephemeral_wallet(
            &encrypted_seed,
            &salt,
            wrong_password,
            "escrow_test",
            "buyer",
            &rpc_client,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Decryption failed"));
    }
}
