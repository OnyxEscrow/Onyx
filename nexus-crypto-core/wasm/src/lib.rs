//! # nexus-crypto-wasm
//!
//! WASM bindings for nexus-crypto-core, enabling browser-based Monero multisig.
//!
//! All cryptographic operations happen client-side in the browser. The server
//! never has access to private keys or secrets.
//!
//! ## Functions Exported
//!
//! - **FROST DKG**: `frost_dkg_part1`, `frost_dkg_part2`, `frost_dkg_part3`
//! - **CMD Protocol**: `derive_commitment_mask`, `find_our_output`
//! - **Key Images**: `compute_partial_key_image`, `aggregate_key_images`
//! - **Nonces**: `generate_nonce_commitment`, `verify_nonce_commitment`, `aggregate_nonces`
//! - **Encryption**: `generate_keypair`, `encrypt_data`, `decrypt_data`
//! - **Utilities**: `sha3_256`, `is_valid_hex`, `bytes_to_hex`, `hex_to_bytes`

use serde::Serialize;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ============================================================================
// FROST DKG Functions
// ============================================================================

/// FROST DKG Round 1 - Generate initial key share data
///
/// # Arguments
/// * `participant_id` - Unique identifier (1-3 for 2-of-3)
/// * `threshold` - Required signers (2 for 2-of-3)
/// * `total_signers` - Total signers (3 for 2-of-3)
///
/// # Returns
/// JSON: `{ "round1_package": "hex...", "secret_package": "hex..." }`
#[wasm_bindgen]
pub fn frost_dkg_part1(
    participant_id: u16,
    threshold: u16,
    total_signers: u16,
) -> Result<JsValue, JsError> {
    use nexus_crypto_core::frost::dkg_part1;

    let result = dkg_part1(participant_id, threshold, total_signers)
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// FROST DKG Round 2 - Process round 1 packages
///
/// # Arguments
/// * `secret_package_hex` - Your secret from round 1
/// * `round1_packages_json` - All round 1 packages: `{"1": "hex...", "2": "hex...", "3": "hex..."}`
///
/// # Returns
/// JSON: `{ "round2_packages": {...}, "round2_secret": "hex..." }`
#[wasm_bindgen]
pub fn frost_dkg_part2(
    secret_package_hex: &str,
    round1_packages_json: &str,
) -> Result<JsValue, JsError> {
    use nexus_crypto_core::frost::dkg_part2;
    use serde::Serialize;

    let packages: BTreeMap<String, String> = serde_json::from_str(round1_packages_json)
        .map_err(|e| JsError::new(&format!("Invalid JSON: {}", e)))?;

    let result =
        dkg_part2(secret_package_hex, &packages).map_err(|e| JsError::new(&format!("{:?}", e)))?;

    // CRITICAL: Use serialize_maps_as_objects(true) to convert BTreeMap to JS plain object
    // instead of JS Map. Object.keys() returns [] for Map objects!
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    result
        .serialize(&serializer)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// FROST DKG Round 3 (Final) - Generate final key share
///
/// # Arguments
/// * `round2_secret_hex` - Your secret from round 2
/// * `round1_packages_json` - All round 1 packages
/// * `round2_packages_json` - Round 2 packages received
///
/// # Returns
/// JSON: `{ "key_package": "hex...", "public_key_package": "hex...", "group_public_key": "hex..." }`
#[wasm_bindgen]
pub fn frost_dkg_part3(
    round2_secret_hex: &str,
    round1_packages_json: &str,
    round2_packages_json: &str,
) -> Result<JsValue, JsError> {
    use nexus_crypto_core::frost::dkg_part3;

    let round1_packages: BTreeMap<String, String> = serde_json::from_str(round1_packages_json)
        .map_err(|e| JsError::new(&format!("Invalid round1 JSON: {}", e)))?;

    let round2_packages: BTreeMap<String, String> = serde_json::from_str(round2_packages_json)
        .map_err(|e| JsError::new(&format!("Invalid round2 JSON: {}", e)))?;

    let result = dkg_part3(round2_secret_hex, &round1_packages, &round2_packages)
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ============================================================================
// CMD Protocol Functions
// ============================================================================

/// Derive commitment mask from view key and transaction public key
///
/// # Arguments
/// * `view_key_priv_hex` - View secret key (hex, 32 bytes)
/// * `tx_pub_key_hex` - Transaction public key (hex, 32 bytes)
/// * `output_index` - Output index in the transaction
///
/// # Returns
/// Commitment mask as hex string (32 bytes)
#[wasm_bindgen]
pub fn derive_commitment_mask(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    output_index: u64,
) -> Result<String, JsError> {
    use nexus_crypto_core::cmd::derive_commitment_mask as derive_mask;

    derive_mask(view_key_priv_hex, tx_pub_key_hex, output_index)
        .map_err(|e| JsError::new(&format!("{:?}", e)))
}

/// Find our output in a transaction and derive commitment mask
///
/// # Arguments
/// * `view_key_priv_hex` - View secret key (hex)
/// * `tx_pub_key_hex` - Transaction public key (hex)
/// * `multisig_address` - The multisig address to match against
/// * `output_keys_json` - Array of output public keys: `["hex1", "hex2", ...]`
///
/// # Returns
/// JSON: `{ "output_index": N, "commitment_mask": "hex...", "decoded_amount": N|null }`
#[wasm_bindgen]
pub fn find_our_output(
    view_key_priv_hex: &str,
    tx_pub_key_hex: &str,
    multisig_address: &str,
    output_keys_json: &str,
) -> Result<JsValue, JsError> {
    use nexus_crypto_core::cmd::find_our_output_and_derive_mask;

    let output_keys: Vec<String> = serde_json::from_str(output_keys_json)
        .map_err(|e| JsError::new(&format!("Invalid output_keys: {}", e)))?;

    let result = find_our_output_and_derive_mask(
        view_key_priv_hex,
        tx_pub_key_hex,
        multisig_address,
        &output_keys,
        None, // No encrypted amounts
    )
    .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    // Manually serialize since the type may not have Serialize
    #[derive(Serialize)]
    struct OutputResult {
        output_index: u64,
        commitment_mask: String,
        decoded_amount: Option<u64>,
    }

    let output = OutputResult {
        output_index: result.output_index,
        commitment_mask: result.commitment_mask,
        decoded_amount: result.decoded_amount,
    };

    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ============================================================================
// Key Image Functions
// ============================================================================

/// Compute partial key image for threshold signing
///
/// # Arguments
/// * `spend_key_priv_hex` - Spend secret key share (hex, 32 bytes)
/// * `one_time_pubkey_hex` - Output's one-time public key (hex, 32 bytes)
/// * `lagrange_coeff_hex` - Lagrange coefficient for this signer (hex, 32 bytes)
///
/// # Returns
/// JSON: `{ "partial_key_image": "hex...", "one_time_pubkey": "hex...", "lagrange_applied": true }`
#[wasm_bindgen]
pub fn compute_partial_key_image(
    spend_key_priv_hex: &str,
    one_time_pubkey_hex: &str,
    lagrange_coeff_hex: &str,
) -> Result<JsValue, JsError> {
    use nexus_crypto_core::keys::compute_partial_key_image as compute_pki;

    let result = compute_pki(spend_key_priv_hex, one_time_pubkey_hex, lagrange_coeff_hex)
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    // Manually serialize
    #[derive(Serialize)]
    struct PkiResult {
        partial_key_image: String,
        one_time_pubkey: String,
        lagrange_applied: bool,
    }

    let output = PkiResult {
        partial_key_image: result.partial_key_image,
        one_time_pubkey: result.one_time_pubkey,
        lagrange_applied: result.lagrange_applied,
    };

    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// Aggregate two partial key images into final key image
///
/// # Arguments
/// * `pki1_hex` - First partial key image (hex, 32 bytes)
/// * `pki2_hex` - Second partial key image (hex, 32 bytes)
///
/// # Returns
/// Aggregated key image as hex string (32 bytes)
#[wasm_bindgen]
pub fn aggregate_key_images(pki1_hex: &str, pki2_hex: &str) -> Result<String, JsError> {
    use nexus_crypto_core::keys::aggregate_partial_key_images;

    aggregate_partial_key_images(pki1_hex, pki2_hex).map_err(|e| JsError::new(&format!("{:?}", e)))
}

// ============================================================================
// Nonce Commitment Functions
// ============================================================================

/// Generate nonce commitment for signing (MuSig2-style)
///
/// # Arguments
/// * `multisig_pub_key_hex` - Group public key (hex, 32 bytes)
///
/// # Returns
/// JSON: `{ "commitment_hash": "hex...", "r_public": "hex...", "r_prime_public": "hex...",
///          "r_secret": "hex...", "r_prime_secret": "hex..." }`
#[wasm_bindgen]
pub fn generate_nonce_commitment(multisig_pub_key_hex: &str) -> Result<JsValue, JsError> {
    use nexus_crypto_core::nonce::generate_nonce_commitment as gen_nonce;

    let result = gen_nonce(multisig_pub_key_hex).map_err(|e| JsError::new(&format!("{:?}", e)))?;

    // Manually serialize
    #[derive(Serialize)]
    struct NonceResult {
        commitment_hash: String,
        r_public: String,
        r_prime_public: String,
        alpha_secret: String,
    }

    let output = NonceResult {
        commitment_hash: result.commitment_hash.clone(),
        r_public: result.r_public.clone(),
        r_prime_public: result.r_prime_public.clone(),
        alpha_secret: result.alpha_secret.clone(),
    };

    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// Verify a nonce commitment
///
/// # Arguments
/// * `commitment_hash_hex` - The commitment hash to verify (hex, 32 bytes)
/// * `r_public_hex` - First nonce point R (hex, 32 bytes)
/// * `r_prime_public_hex` - Second nonce point R' (hex, 32 bytes)
///
/// # Returns
/// true if commitment is valid
#[wasm_bindgen]
pub fn verify_nonce_commitment(
    commitment_hash_hex: &str,
    r_public_hex: &str,
    r_prime_public_hex: &str,
) -> Result<bool, JsError> {
    use nexus_crypto_core::nonce::verify_nonce_commitment as verify;

    verify(commitment_hash_hex, r_public_hex, r_prime_public_hex)
        .map_err(|e| JsError::new(&format!("{:?}", e)))
}

/// Aggregate two nonces (for 2-of-3 signing)
///
/// # Arguments
/// * `r1_hex` - First signer's nonce R (hex, 32 bytes)
/// * `r2_hex` - Second signer's nonce R (hex, 32 bytes)
///
/// # Returns
/// Aggregated nonce as hex string (32 bytes)
#[wasm_bindgen]
pub fn aggregate_nonces(r1_hex: &str, r2_hex: &str) -> Result<String, JsError> {
    use nexus_crypto_core::nonce::aggregate_nonces as agg;

    agg(r1_hex, r2_hex).map_err(|e| JsError::new(&format!("{:?}", e)))
}

// ============================================================================
// Encryption Functions (X25519 + ChaCha20Poly1305)
// ============================================================================

/// Generate X25519 keypair for encryption
///
/// # Returns
/// JSON: `{ "private_key_hex": "hex...", "public_key_hex": "hex..." }`
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsError> {
    use nexus_crypto_core::encryption::generate_ephemeral_keypair;

    let result = generate_ephemeral_keypair().map_err(|e| JsError::new(&format!("{:?}", e)))?;

    // Wrap in Serialize struct
    #[derive(Serialize)]
    struct KeypairResult {
        private_key_hex: String,
        public_key_hex: String,
    }

    let output = KeypairResult {
        private_key_hex: result.private_key_hex.clone(),
        public_key_hex: result.public_key_hex.clone(),
    };

    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// Encrypt data using X25519 ECDH + ChaCha20Poly1305
///
/// # Arguments
/// * `plaintext` - UTF-8 string to encrypt
/// * `my_private_key_hex` - Your private key (hex, 32 bytes)
/// * `peer_public_key_hex` - Recipient's public key (hex, 32 bytes)
///
/// # Returns
/// JSON: `{ "encrypted_blob": "base64...", "nonce_hex": "hex...", "ephemeral_pubkey_hex": "hex..." }`
#[wasm_bindgen]
pub fn encrypt_data(
    plaintext: &str,
    my_private_key_hex: &str,
    peer_public_key_hex: &str,
) -> Result<JsValue, JsError> {
    use nexus_crypto_core::encryption::encrypt_data as encrypt;

    let result = encrypt(plaintext, my_private_key_hex, peer_public_key_hex)
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    // Wrap in Serialize struct
    #[derive(Serialize)]
    struct EncryptResult {
        encrypted_blob: String,
        nonce_hex: String,
        ephemeral_pubkey_hex: String,
    }

    let output = EncryptResult {
        encrypted_blob: result.encrypted_blob,
        nonce_hex: result.nonce_hex,
        ephemeral_pubkey_hex: result.ephemeral_pubkey_hex,
    };

    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// Decrypt data using X25519 ECDH + ChaCha20Poly1305
///
/// # Arguments
/// * `encrypted_blob_base64` - Encrypted data (base64)
/// * `nonce_hex` - Encryption nonce (hex, 12 bytes)
/// * `peer_public_key_hex` - Sender's public key (hex, 32 bytes)
/// * `my_private_key_hex` - Your private key (hex, 32 bytes)
///
/// # Returns
/// Decrypted plaintext as UTF-8 string
#[wasm_bindgen]
pub fn decrypt_data(
    encrypted_blob_base64: &str,
    nonce_hex: &str,
    peer_public_key_hex: &str,
    my_private_key_hex: &str,
) -> Result<String, JsError> {
    use nexus_crypto_core::encryption::decrypt_data as decrypt;

    decrypt(
        encrypted_blob_base64,
        nonce_hex,
        peer_public_key_hex,
        my_private_key_hex,
    )
    .map_err(|e| JsError::new(&format!("{:?}", e)))
}

// ============================================================================
// Key Backup Encryption Functions (Argon2id + ChaCha20Poly1305)
// ============================================================================

/// Encrypt a FROST key_package for secure backup.
///
/// Uses Argon2id (m=64MB, t=3, p=4) for password-based key derivation
/// and ChaCha20Poly1305 for authenticated encryption.
///
/// # Arguments
/// * `key_package_hex` - The FROST key_package to encrypt (hex encoded)
/// * `password` - User-provided backup password
///
/// # Returns
/// Encrypted backup blob as hex string: salt (16) || nonce (12) || ciphertext
///
/// # Security
/// - Memory-hard KDF resists GPU/ASIC brute-force attacks
/// - Random salt ensures unique encryption per backup
/// - AEAD provides confidentiality + integrity
/// - NEVER log the plaintext key_package
#[wasm_bindgen]
pub fn encrypt_key_for_backup(key_package_hex: &str, password: &str) -> Result<String, JsError> {
    use nexus_crypto_core::encryption::backup::encrypt_key_for_backup as encrypt_backup;

    let key_package =
        hex::decode(key_package_hex).map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;

    let encrypted =
        encrypt_backup(&key_package, password).map_err(|e| JsError::new(&format!("{:?}", e)))?;

    Ok(hex::encode(encrypted))
}

/// Decrypt a FROST key_package from backup.
///
/// # Arguments
/// * `encrypted_hex` - The encrypted backup blob (hex encoded)
/// * `password` - The password used during encryption
///
/// # Returns
/// Decrypted key_package as hex string
///
/// # Errors
/// Returns error if:
/// - Password is incorrect (AEAD verification fails)
/// - Backup data is corrupted or tampered with
/// - Backup data is truncated
#[wasm_bindgen]
pub fn decrypt_key_from_backup(encrypted_hex: &str, password: &str) -> Result<String, JsError> {
    use nexus_crypto_core::encryption::backup::decrypt_key_from_backup as decrypt_backup;

    let encrypted =
        hex::decode(encrypted_hex).map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;

    let decrypted =
        decrypt_backup(&encrypted, password).map_err(|e| JsError::new(&format!("{:?}", e)))?;

    Ok(hex::encode(decrypted))
}

/// Derive a backup identifier from key_package (without exposing the key).
///
/// This allows matching backups to escrows without decryption.
/// Uses SHA3-256 with domain separation.
///
/// # Arguments
/// * `key_package_hex` - The FROST key_package (hex encoded)
///
/// # Returns
/// 64-character hex string (SHA3-256 hash)
///
/// # Security
/// - One-way function: cannot derive key from ID
/// - Deterministic: same key always produces same ID
/// - Different keys won't collide (collision-resistant)
#[wasm_bindgen]
pub fn derive_backup_id(key_package_hex: &str) -> Result<String, JsError> {
    use nexus_crypto_core::encryption::backup::derive_backup_id as derive_id;

    let key_package =
        hex::decode(key_package_hex).map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;

    Ok(derive_id(&key_package))
}

/// Verify that a password can decrypt a backup without returning the key.
///
/// Useful for password validation UX without exposing decrypted material.
///
/// # Arguments
/// * `encrypted_hex` - The encrypted backup blob (hex encoded)
/// * `password` - Password to verify
///
/// # Returns
/// `true` if password is correct, `false` otherwise
#[wasm_bindgen]
pub fn verify_backup_password(encrypted_hex: &str, password: &str) -> Result<bool, JsError> {
    use nexus_crypto_core::encryption::backup::verify_backup_password as verify;

    let encrypted =
        hex::decode(encrypted_hex).map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;

    Ok(verify(&encrypted, password))
}

/// Get the expected encrypted size for a given plaintext size.
///
/// # Arguments
/// * `plaintext_len` - Size of the key_package in bytes
///
/// # Returns
/// Total size of encrypted backup in bytes: salt (16) + nonce (12) + ciphertext + tag (16)
#[wasm_bindgen]
pub fn backup_encrypted_size(plaintext_len: usize) -> usize {
    nexus_crypto_core::encryption::backup::encrypted_size(plaintext_len)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get library version
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Compute SHA3-256 hash
///
/// # Arguments
/// * `data_hex` - Data to hash (hex encoded)
///
/// # Returns
/// Hash as hex string (64 chars = 32 bytes)
#[wasm_bindgen]
pub fn sha3_256(data_hex: &str) -> Result<String, JsError> {
    use sha3::{Digest, Sha3_256};

    let data = hex::decode(data_hex).map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;

    let mut hasher = Sha3_256::new();
    hasher.update(&data);
    let result = hasher.finalize();

    Ok(hex::encode(result))
}

/// Validate hex string format
#[wasm_bindgen]
pub fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && hex::decode(s).is_ok()
}

/// Convert bytes to hex string
#[wasm_bindgen]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
#[wasm_bindgen]
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, JsError> {
    hex::decode(hex_str).map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))
}

/// Compute Lagrange coefficient for participant in 2-of-3 signing
///
/// # Arguments
/// * `signer_index` - This signer's index (1, 2, or 3)
/// * `signer1_index` - First participating signer's index
/// * `signer2_index` - Second participating signer's index
///
/// # Returns
/// Lagrange coefficient as hex string (32 bytes scalar)
#[wasm_bindgen]
pub fn compute_lagrange_coefficient(
    signer_index: u16,
    signer1_index: u16,
    signer2_index: u16,
) -> Result<String, JsError> {
    use nexus_crypto_core::frost::compute_lagrange_coefficient as compute_lc;

    compute_lc(signer_index, signer1_index, signer2_index)
        .map_err(|e| JsError::new(&format!("{:?}", e)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_version() {
        let version = get_version();
        assert_eq!(version, "0.1.0");
    }

    #[wasm_bindgen_test]
    fn test_sha3_256() {
        // "hello" = 68656c6c6f
        let result = sha3_256("68656c6c6f").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[wasm_bindgen_test]
    fn test_is_valid_hex() {
        assert!(is_valid_hex("deadbeef"));
        assert!(!is_valid_hex("not hex"));
        assert!(!is_valid_hex("deadbee")); // odd
        assert!(!is_valid_hex(""));
    }

    #[wasm_bindgen_test]
    fn test_bytes_hex_roundtrip() {
        let original = vec![0xde, 0xad, 0xbe, 0xef];
        let hex_str = bytes_to_hex(&original);
        let bytes = hex_to_bytes(&hex_str).unwrap();
        assert_eq!(bytes, original);
    }

    #[wasm_bindgen_test]
    fn test_frost_dkg_part1() {
        let result = frost_dkg_part1(1, 2, 3);
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_generate_keypair() {
        let result = generate_keypair();
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_backup_encrypt_decrypt_roundtrip() {
        // Simulate a FROST key_package (200 bytes)
        let key_package_hex = "0".repeat(400); // 200 bytes = 400 hex chars
        let password = "test_password_123";

        let encrypted = encrypt_key_for_backup(&key_package_hex, password).unwrap();
        let decrypted = decrypt_key_from_backup(&encrypted, password).unwrap();

        assert_eq!(decrypted, key_package_hex);
    }

    #[wasm_bindgen_test]
    fn test_backup_wrong_password_fails() {
        let key_package_hex = "deadbeef".repeat(50);
        let encrypted = encrypt_key_for_backup(&key_package_hex, "correct").unwrap();

        let result = decrypt_key_from_backup(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_derive_backup_id_deterministic() {
        let key_package_hex = "abcd1234".repeat(25);

        let id1 = derive_backup_id(&key_package_hex).unwrap();
        let id2 = derive_backup_id(&key_package_hex).unwrap();

        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA3-256 = 64 hex chars
    }

    #[wasm_bindgen_test]
    fn test_verify_backup_password() {
        let key_package_hex = "cafe0123".repeat(50);
        let password = "verification_test";

        let encrypted = encrypt_key_for_backup(&key_package_hex, password).unwrap();

        assert!(verify_backup_password(&encrypted, password).unwrap());
        assert!(!verify_backup_password(&encrypted, "wrong").unwrap());
    }

    #[wasm_bindgen_test]
    fn test_backup_encrypted_size() {
        let plaintext_len = 200;
        let expected = 16 + 12 + 200 + 16; // salt + nonce + plaintext + tag

        assert_eq!(backup_encrypted_size(plaintext_len), expected);
    }
}
