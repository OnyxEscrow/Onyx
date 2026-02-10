// P0 Security: CSP Nonce generation for secure inline scripts/styles
// Replaces 'unsafe-inline' with cryptographically random nonces

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{thread_rng, RngCore};
use std::sync::Arc;

/// Length of the raw random bytes for nonce (16 bytes = 128 bits)
const NONCE_BYTES_LEN: usize = 16;

/// Generates a cryptographically secure random nonce for CSP
/// Returns base64-encoded string suitable for use in CSP headers and HTML attributes
pub fn generate_csp_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES_LEN];
    thread_rng().fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

/// Request extension to store the CSP nonce for the current request
#[derive(Clone)]
pub struct CspNonce(pub Arc<String>);

impl CspNonce {
    pub fn new() -> Self {
        Self(Arc::new(generate_csp_nonce()))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl Default for CspNonce {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_csp_nonce();
        let nonce2 = generate_csp_nonce();

        // Nonces should be different
        assert_ne!(nonce1, nonce2);

        // Should be valid base64 (22 chars for 16 bytes + padding)
        assert!(nonce1.len() >= 22);

        // Should be decodable
        let decoded = STANDARD.decode(&nonce1);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap().len(), NONCE_BYTES_LEN);
    }

    #[test]
    fn test_csp_nonce_struct() {
        let nonce = CspNonce::new();
        assert!(!nonce.value().is_empty());
    }
}
