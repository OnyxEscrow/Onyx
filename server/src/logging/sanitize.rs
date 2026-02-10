/// Sanitization des logs pour OPSEC
///
/// TM-006 Fix: Empêche la corrélation via logs complets
/// Production Hardening: Extended for full OPSEC compliance

// ============================================================================
// UUID/ID Sanitization
// ============================================================================

/// Sanitize un UUID pour les logs
///
/// Format: "abc12345...90ef" (8 premiers + 4 derniers chars)
///
/// Empêche la corrélation complète tout en permettant le debug
pub fn sanitize_uuid(uuid: &uuid::Uuid) -> String {
    let uuid_str = uuid.to_string();
    if uuid_str.len() < 12 {
        return "<invalid-uuid>".to_string();
    }
    format!("{}...{}", &uuid_str[..8], &uuid_str[uuid_str.len()-4..])
}

/// Sanitize une adresse Monero pour les logs
///
/// Format: "9w...XYZ" (2 premiers + 3 derniers chars)
///
/// Les 2 premiers chars identifient le network (9 = mainnet, A = testnet)
/// Les 3 derniers permettent de différencier les addresses en debug
pub fn sanitize_address(address: &str) -> String {
    if address.len() < 6 {
        return "<invalid-address>".to_string();
    }
    format!("{}...{}", &address[..2], &address[address.len()-3..])
}

/// Sanitize un montant XMR (optionnel, si vraiment paranoid)
///
/// Arrondit à 2 décimales pour empêcher l'identification exacte
pub fn sanitize_amount(piconeros: u64) -> String {
    let xmr = piconeros as f64 / 1_000_000_000_000.0;
    format!("~{:.2} XMR", xmr)
}

// ============================================================================
// Transaction Sanitization
// ============================================================================

/// Sanitize a transaction hash (txid) for logs
///
/// Format: "abc12345...90ef" (first 8 + last 4 chars)
///
/// TX hashes are 64 hex chars - revealing full hash allows blockchain correlation
pub fn sanitize_txid(txid: &str) -> String {
    if txid.len() < 16 {
        return "[invalid_txid]".to_string();
    }
    format!("{}...{}", &txid[..8], &txid[txid.len()-4..])
}

/// Sanitize a broadcast transaction hash with confirmation context
///
/// Use for logging TX broadcasts where we need status info
pub fn sanitize_broadcast_txid(txid: &str, confirmations: Option<u32>) -> String {
    let base = sanitize_txid(txid);
    match confirmations {
        Some(n) => format!("{} ({} conf)", base, n),
        None => format!("{} (unconfirmed)", base),
    }
}

// ============================================================================
// Network/RPC Sanitization
// ============================================================================

/// Sanitize RPC URL - NEVER log actual URLs
///
/// URLs may reveal:
/// - Internal network topology
/// - .onion addresses
/// - Port configurations
/// - IP addresses
pub fn sanitize_rpc_url(_url: &str) -> &'static str {
    "[rpc_endpoint]"
}

/// Sanitize any URL for logs
///
/// Only reveals the scheme (http/https/socks5) for debugging
pub fn sanitize_url(url: &str) -> String {
    // Check for .onion FIRST (before http/https) since onion URLs use http:// scheme
    if url.contains(".onion") {
        "[onion_service]".to_string()
    } else if url.starts_with("socks5") {
        "[tor_proxy]".to_string()
    } else if url.starts_with("https://") {
        "[https_endpoint]".to_string()
    } else if url.starts_with("http://") {
        "[http_endpoint]".to_string()
    } else {
        "[endpoint]".to_string()
    }
}

// ============================================================================
// Cryptographic Data Sanitization
// ============================================================================

/// Sanitize multisig info string for logs
///
/// Multisig info contains sensitive wallet cryptographic data
/// Only log the length for debugging purposes
pub fn sanitize_multisig_info(info: &str) -> String {
    format!("[multisig_info: {} bytes]", info.len())
}

/// Sanitize view key for logs - NEVER expose
///
/// View keys allow transaction history surveillance
pub fn sanitize_view_key(_key: &str) -> &'static str {
    "[view_key_redacted]"
}

/// Sanitize spend key for logs - NEVER expose
///
/// Spend keys allow fund theft
pub fn sanitize_spend_key(_key: &str) -> &'static str {
    "[spend_key_redacted]"
}

/// Sanitize seed/mnemonic for logs - NEVER expose
///
/// Seeds allow complete wallet recovery and fund theft
pub fn sanitize_seed(_seed: &str) -> &'static str {
    "[seed_redacted]"
}

/// Sanitize any cryptographic hex string
///
/// Generic sanitization for hex-encoded keys, signatures, etc.
pub fn sanitize_hex_data(data: &str, label: &str) -> String {
    if data.len() < 8 {
        return format!("[{}:invalid]", label);
    }
    format!("[{}:{}...{}]", label, &data[..4], &data[data.len()-4..])
}

// ============================================================================
// User Identity Sanitization
// ============================================================================

/// Sanitize escrow ID for logs (alias for UUID sanitization)
///
/// Escrow IDs should not be fully exposed in logs to prevent
/// correlation between escrow operations and users
pub fn sanitize_escrow_id(id: &str) -> String {
    if let Ok(uuid) = uuid::Uuid::parse_str(id) {
        sanitize_uuid(&uuid)
    } else if id.len() >= 12 {
        // Fallback for non-UUID string IDs
        format!("{}...{}", &id[..8], &id[id.len()-4..])
    } else {
        "[invalid_escrow_id]".to_string()
    }
}

/// Sanitize user ID for logs
///
/// User IDs should not be correlated with operations
pub fn sanitize_user_id(id: &str) -> String {
    sanitize_escrow_id(id) // Same format
}

/// Sanitize order ID for logs
pub fn sanitize_order_id(id: &str) -> String {
    sanitize_escrow_id(id) // Same format
}

// ============================================================================
// Operation Logging Helpers
// ============================================================================

/// Create sanitized log context for escrow operations
///
/// Returns a string safe for logging without exposing correlatable data
pub fn escrow_log_context(escrow_id: &str, operation: &str) -> String {
    format!("[escrow:{}] {}", sanitize_escrow_id(escrow_id), operation)
}

/// Create sanitized log context for user operations
///
/// Logs operation without exposing user identity
pub fn user_log_context(user_id: &str, operation: &str) -> String {
    format!("[user:{}] {}", sanitize_user_id(user_id), operation)
}

/// Create sanitized log context for transaction operations
pub fn tx_log_context(txid: &str, operation: &str) -> String {
    format!("[tx:{}] {}", sanitize_txid(txid), operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_sanitize_uuid() {
        let uuid = Uuid::parse_str("abc12345-6789-0123-4567-890ef1234567").unwrap();
        let sanitized = sanitize_uuid(&uuid);

        assert_eq!(sanitized, "abc12345...4567");
        assert!(!sanitized.contains("6789")); // Partie du milieu cachée
    }

    #[test]
    fn test_sanitize_address() {
        let addr = "9wHq7XM8ZtKpVqnEQB8X...ABCXYZ";
        let sanitized = sanitize_address(addr);

        assert_eq!(sanitized, "9w...XYZ");
        assert!(!sanitized.contains("Hq7XM8")); // Milieu caché
    }

    #[test]
    fn test_sanitize_amount() {
        // 1 XMR = 1_000_000_000_000 piconeros
        let amount = 1_234_567_890_123;
        let sanitized = sanitize_amount(amount);

        assert_eq!(sanitized, "~1.23 XMR");
    }

    #[test]
    fn test_sanitize_txid() {
        // Standard 64-char Monero txid
        let txid = "abc123def456789012345678901234567890123456789012345678901234wxyz";
        let sanitized = sanitize_txid(txid);

        assert_eq!(sanitized, "abc123de...wxyz");
        assert!(!sanitized.contains("456789"));
    }

    #[test]
    fn test_sanitize_txid_invalid() {
        let short = "abc";
        assert_eq!(sanitize_txid(short), "[invalid_txid]");
    }

    #[test]
    fn test_sanitize_rpc_url() {
        // Should always return redacted
        assert_eq!(sanitize_rpc_url("http://127.0.0.1:18082"), "[rpc_endpoint]");
        assert_eq!(sanitize_rpc_url("http://localhost:18082/json_rpc"), "[rpc_endpoint]");
        assert_eq!(sanitize_rpc_url("http://abcdef.onion:18082"), "[rpc_endpoint]");
    }

    #[test]
    fn test_sanitize_url_schemes() {
        assert_eq!(sanitize_url("https://example.com"), "[https_endpoint]");
        assert_eq!(sanitize_url("http://127.0.0.1"), "[http_endpoint]");
        assert_eq!(sanitize_url("socks5h://127.0.0.1:9050"), "[tor_proxy]");
        assert_eq!(sanitize_url("http://xyz.onion/api"), "[onion_service]");
    }

    #[test]
    fn test_sanitize_multisig_info() {
        let info = "MultisigV1abc...long_data_here".repeat(10);
        let sanitized = sanitize_multisig_info(&info);

        assert!(sanitized.starts_with("[multisig_info:"));
        assert!(sanitized.contains("bytes]"));
        assert!(!sanitized.contains("abc"));
    }

    #[test]
    fn test_sanitize_keys_never_exposed() {
        let view_key = "secret_view_key_data_abc123def456";
        let spend_key = "secret_spend_key_data_xyz789";
        let seed = "word1 word2 word3 word4 word5";

        assert_eq!(sanitize_view_key(view_key), "[view_key_redacted]");
        assert_eq!(sanitize_spend_key(spend_key), "[spend_key_redacted]");
        assert_eq!(sanitize_seed(seed), "[seed_redacted]");

        // Ensure no data leakage
        assert!(!sanitize_view_key(view_key).contains("secret"));
        assert!(!sanitize_spend_key(spend_key).contains("xyz"));
        assert!(!sanitize_seed(seed).contains("word"));
    }

    #[test]
    fn test_sanitize_escrow_id() {
        // UUID format
        let uuid_id = "abc12345-6789-0123-4567-890ef1234567";
        let sanitized = sanitize_escrow_id(uuid_id);
        assert_eq!(sanitized, "abc12345...4567");

        // Non-UUID string ID
        let string_id = "escrow_1234567890abcdef";
        let sanitized = sanitize_escrow_id(string_id);
        assert_eq!(sanitized, "escrow_1...cdef");

        // Too short
        let short = "abc";
        assert_eq!(sanitize_escrow_id(short), "[invalid_escrow_id]");
    }

    #[test]
    fn test_log_context_helpers() {
        let escrow = escrow_log_context("abc12345-6789-0123-4567-890ef1234567", "created");
        assert!(escrow.contains("[escrow:abc12345...4567]"));
        assert!(escrow.contains("created"));

        // Test with string that produces expected output (last 4 chars = 0001)
        let user = user_log_context("user12345-6789-0123-4567-890efus0001", "logged_in");
        assert!(user.contains("[user:user1234...0001]"));

        let tx = tx_log_context("abc123def456789012345678901234567890123456789012345678901234wxyz", "broadcast");
        assert!(tx.contains("[tx:abc123de...wxyz]"));
        assert!(tx.contains("broadcast"));
    }

    #[test]
    fn test_sanitize_hex_data() {
        let data = "abcdef1234567890abcdef";
        let sanitized = sanitize_hex_data(data, "signature");

        assert_eq!(sanitized, "[signature:abcd...cdef]");
        assert!(!sanitized.contains("1234567890"));
    }
}
