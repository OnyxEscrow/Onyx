//! Error types for cryptographic operations
//!
//! This module defines all error types used throughout onyx-crypto-core.
//! Errors are categorized by the operation that caused them.

use alloc::string::String;
use core::fmt;

/// Result type alias for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Comprehensive error type for all cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    // =========================================================================
    // FROST DKG Errors
    // =========================================================================
    /// General FROST DKG error
    FrostDkgError(String),

    /// Invalid participant identifier (must be 1-255)
    InvalidIdentifier(String),

    /// Invalid threshold parameters (threshold > max_signers or threshold < 2)
    InvalidThreshold {
        /// The requested threshold
        threshold: u16,
        /// The maximum number of signers
        max_signers: u16,
    },

    /// Round 1 package verification failed
    Round1VerificationFailed(String),

    /// Round 2 package verification failed
    Round2VerificationFailed(String),

    /// Missing round 1 packages from participants
    MissingRound1Packages {
        /// Expected participant identifiers
        expected: u16,
        /// Received participant identifiers
        received: u16,
    },

    /// Missing round 2 packages from participants
    MissingRound2Packages {
        /// Expected participant identifiers
        expected: u16,
        /// Received participant identifiers
        received: u16,
    },

    /// Key package extraction failed
    KeyPackageExtractionFailed(String),

    /// Lagrange coefficient computation failed
    LagrangeCoefficientFailed(String),

    // =========================================================================
    // CMD (Commitment Mask Derivation) Errors
    // =========================================================================
    /// Failed to derive commitment mask
    MaskDerivationFailed(String),

    /// Output not found in transaction
    OutputNotFound {
        /// Transaction hash
        tx_hash: String,
        /// Expected output index
        output_index: u32,
    },

    /// Failed to decode encrypted amount
    AmountDecodeFailed(String),

    /// Invalid transaction extra field
    InvalidTxExtra(String),

    // =========================================================================
    // CLSAG Signing Errors
    // =========================================================================
    /// Ring size too small (minimum 11 for mainnet)
    RingSizeTooSmall {
        /// Actual ring size
        actual: usize,
        /// Minimum required
        minimum: usize,
    },

    /// Signer index out of ring bounds
    SignerIndexOutOfBounds {
        /// The signer index
        index: usize,
        /// Ring size
        ring_size: usize,
    },

    /// Partial signature creation failed
    PartialSignatureFailed(String),

    /// Signature completion failed
    SignatureCompletionFailed(String),

    /// CLSAG verification failed
    ClsagVerificationFailed(String),

    /// Invalid s-value in signature
    InvalidSValue(String),

    /// Key image mismatch during aggregation
    KeyImageMismatch,

    // =========================================================================
    // Key Operations Errors
    // =========================================================================
    /// Key image computation failed
    KeyImageComputationFailed(String),

    /// Partial key image aggregation failed
    PartialKeyImageAggregationFailed(String),

    /// Invalid public key format or value
    InvalidPublicKey(String),

    /// Invalid private/secret key format or value
    InvalidSecretKey(String),

    // =========================================================================
    // Address Validation Errors
    // =========================================================================
    /// Address checksum mismatch
    ChecksumMismatch {
        /// Expected checksum (hex)
        expected: String,
        /// Actual checksum (hex)
        actual: String,
    },

    /// Address network mismatch
    NetworkMismatch {
        /// Expected network
        expected: String,
        /// Actual network detected
        actual: String,
    },

    /// Invalid address length
    InvalidAddressLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Invalid address prefix
    InvalidAddressPrefix(String),

    /// Base58 decode failed
    Base58DecodeFailed(String),

    // =========================================================================
    // Nonce Errors
    // =========================================================================
    /// Nonce generation failed
    NonceGenerationFailed(String),

    /// Nonce commitment mismatch
    NonceCommitmentMismatch,

    /// Invalid nonce format
    InvalidNonce(String),

    // =========================================================================
    // Encryption Errors
    // =========================================================================
    /// ECDH key exchange failed
    EcdhFailed(String),

    /// Encryption operation failed
    EncryptionFailed(String),

    /// Decryption operation failed (wrong key or corrupted data)
    DecryptionFailed(String),

    /// Invalid ciphertext format
    InvalidCiphertext(String),

    // =========================================================================
    // Serialization Errors
    // =========================================================================
    /// Serialization failed
    SerializationError(String),

    /// Deserialization failed
    DeserializationError(String),

    // =========================================================================
    // General Errors
    // =========================================================================
    /// Hex decode failed
    HexDecodeFailed(String),

    /// Invalid input length
    InvalidLength {
        /// Name of the field
        field: String,
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// JSON serialization/deserialization failed
    JsonError(String),

    /// Operation not supported in current configuration
    NotSupported(String),

    /// Internal error (should not happen in normal operation)
    InternalError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // FROST DKG
            CryptoError::FrostDkgError(msg) => {
                write!(f, "FROST DKG error: {msg}")
            }
            CryptoError::InvalidIdentifier(msg) => {
                write!(f, "Invalid FROST identifier: {msg}")
            }
            CryptoError::InvalidThreshold {
                threshold,
                max_signers,
            } => {
                write!(f, "Invalid threshold {threshold}/{max_signers}: threshold must be >= 2 and <= max_signers")
            }
            CryptoError::Round1VerificationFailed(msg) => {
                write!(f, "FROST round 1 verification failed: {msg}")
            }
            CryptoError::Round2VerificationFailed(msg) => {
                write!(f, "FROST round 2 verification failed: {msg}")
            }
            CryptoError::MissingRound1Packages { expected, received } => {
                write!(
                    f,
                    "Missing round 1 packages: expected {expected}, got {received}"
                )
            }
            CryptoError::MissingRound2Packages { expected, received } => {
                write!(
                    f,
                    "Missing round 2 packages: expected {expected}, got {received}"
                )
            }
            CryptoError::KeyPackageExtractionFailed(msg) => {
                write!(f, "Key package extraction failed: {msg}")
            }
            CryptoError::LagrangeCoefficientFailed(msg) => {
                write!(f, "Lagrange coefficient computation failed: {msg}")
            }

            // CMD
            CryptoError::MaskDerivationFailed(msg) => {
                write!(f, "Commitment mask derivation failed: {msg}")
            }
            CryptoError::OutputNotFound {
                tx_hash,
                output_index,
            } => {
                write!(
                    f,
                    "Output {output_index} not found in transaction {tx_hash}"
                )
            }
            CryptoError::AmountDecodeFailed(msg) => {
                write!(f, "Encrypted amount decode failed: {msg}")
            }
            CryptoError::InvalidTxExtra(msg) => {
                write!(f, "Invalid transaction extra field: {msg}")
            }

            // CLSAG
            CryptoError::RingSizeTooSmall { actual, minimum } => {
                write!(f, "Ring size {actual} too small, minimum is {minimum}")
            }
            CryptoError::SignerIndexOutOfBounds { index, ring_size } => {
                write!(
                    f,
                    "Signer index {index} out of bounds for ring size {ring_size}"
                )
            }
            CryptoError::PartialSignatureFailed(msg) => {
                write!(f, "Partial signature creation failed: {msg}")
            }
            CryptoError::SignatureCompletionFailed(msg) => {
                write!(f, "Signature completion failed: {msg}")
            }
            CryptoError::ClsagVerificationFailed(msg) => {
                write!(f, "CLSAG verification failed: {msg}")
            }
            CryptoError::InvalidSValue(msg) => {
                write!(f, "Invalid s-value: {msg}")
            }
            CryptoError::KeyImageMismatch => {
                write!(f, "Key image mismatch during signature aggregation")
            }

            // Key Operations
            CryptoError::KeyImageComputationFailed(msg) => {
                write!(f, "Key image computation failed: {msg}")
            }
            CryptoError::PartialKeyImageAggregationFailed(msg) => {
                write!(f, "Partial key image aggregation failed: {msg}")
            }
            CryptoError::InvalidPublicKey(msg) => {
                write!(f, "Invalid public key: {msg}")
            }
            CryptoError::InvalidSecretKey(msg) => {
                write!(f, "Invalid secret key: {msg}")
            }

            // Address
            CryptoError::ChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "Address checksum mismatch: expected {expected}, got {actual}"
                )
            }
            CryptoError::NetworkMismatch { expected, actual } => {
                write!(f, "Network mismatch: expected {expected}, got {actual}")
            }
            CryptoError::InvalidAddressLength { expected, actual } => {
                write!(
                    f,
                    "Invalid address length: expected {expected}, got {actual}"
                )
            }
            CryptoError::InvalidAddressPrefix(prefix) => {
                write!(f, "Invalid address prefix: {prefix}")
            }
            CryptoError::Base58DecodeFailed(msg) => {
                write!(f, "Base58 decode failed: {msg}")
            }

            // Nonce
            CryptoError::NonceGenerationFailed(msg) => {
                write!(f, "Nonce generation failed: {msg}")
            }
            CryptoError::NonceCommitmentMismatch => {
                write!(f, "Nonce commitment does not match provided nonce")
            }
            CryptoError::InvalidNonce(msg) => {
                write!(f, "Invalid nonce: {msg}")
            }

            // Encryption
            CryptoError::EcdhFailed(msg) => {
                write!(f, "ECDH key exchange failed: {msg}")
            }
            CryptoError::EncryptionFailed(msg) => {
                write!(f, "Encryption failed: {msg}")
            }
            CryptoError::DecryptionFailed(msg) => {
                write!(f, "Decryption failed: {msg}")
            }
            CryptoError::InvalidCiphertext(msg) => {
                write!(f, "Invalid ciphertext: {msg}")
            }

            // Serialization
            CryptoError::SerializationError(msg) => {
                write!(f, "Serialization error: {msg}")
            }
            CryptoError::DeserializationError(msg) => {
                write!(f, "Deserialization error: {msg}")
            }

            // General
            CryptoError::HexDecodeFailed(msg) => {
                write!(f, "Hex decode failed: {msg}")
            }
            CryptoError::InvalidLength {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid {field} length: expected {expected}, got {actual}"
                )
            }
            CryptoError::JsonError(msg) => {
                write!(f, "JSON error: {msg}")
            }
            CryptoError::NotSupported(msg) => {
                write!(f, "Operation not supported: {msg}")
            }
            CryptoError::InternalError(msg) => {
                write!(f, "Internal error: {msg}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidThreshold {
            threshold: 5,
            max_signers: 3,
        };
        assert!(err.to_string().contains("5/3"));
    }

    #[test]
    fn test_error_equality() {
        let err1 = CryptoError::KeyImageMismatch;
        let err2 = CryptoError::KeyImageMismatch;
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_checksum_error() {
        let err = CryptoError::ChecksumMismatch {
            expected: "abcd".into(),
            actual: "1234".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("abcd"));
        assert!(msg.contains("1234"));
    }
}
