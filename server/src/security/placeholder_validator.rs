//! Placeholder validation module
//!
//! Detects insecure placeholder values in production configuration
//! to prevent deployment with example/default credentials.
//!
//! # Security Rationale
//!
//! A common vulnerability is deploying applications with example configuration
//! values (e.g., copying .env.example directly). This module validates critical
//! environment variables at startup and panics in production if placeholders
//! are detected.
//!
//! # Example
//!
//! ```rust
//! use server::security::placeholder_validator::validate_no_placeholders;
//!
//! // This will panic in production if DB_ENCRYPTION_KEY contains "your-xxx-here"
//! validate_no_placeholders("DB_ENCRYPTION_KEY", "your-64-char-hex-key-here");
//! ```

use std::env;

/// Common placeholder patterns that indicate insecure configuration
const PLACEHOLDER_PATTERNS: &[&str] = &[
    "your-",
    "your_",
    "xxx",
    "example",
    "changeme",
    "change_me",
    "placeholder",
    "todo",
    "fixme",
    "dummy",
    "test123",
    "password123",
    "secret123",
    "key123",
    "-here",
    "_here",
    "default",
    "sample",
];

/// Validates that an environment variable does not contain placeholder values
///
/// # Arguments
///
/// * `var_name` - Name of the environment variable to validate
/// * `value` - Value to check for placeholders
///
/// # Panics
///
/// In production (release builds), panics if placeholder patterns are detected.
/// In development (debug builds), logs a warning instead.
///
/// # Examples
///
/// ```rust,no_run
/// use server::security::placeholder_validator::validate_no_placeholders;
///
/// // Safe value - no panic
/// validate_no_placeholders("DB_ENCRYPTION_KEY", "a1b2c3d4e5f6...");
///
/// // Unsafe value - will panic in production
/// validate_no_placeholders("DB_ENCRYPTION_KEY", "your-64-char-hex-key-here");
/// ```
pub fn validate_no_placeholders(var_name: &str, value: &str) {
    // Skip validation if value is empty or very short (likely not set)
    if value.is_empty() || value.len() < 10 {
        return;
    }

    let value_lower = value.to_lowercase();

    for pattern in PLACEHOLDER_PATTERNS {
        if value_lower.contains(pattern) {
            let msg = format!(
                "🚨 SECURITY ERROR: {} contains placeholder pattern '{}'\n\
                 Value: {}\n\
                 This indicates you copied .env.example without changing the values.\n\
                 Generate secure credentials before deploying to production.\n\
                 See README.md for credential generation instructions.",
                var_name,
                pattern,
                if value.len() > 50 {
                    format!("{}...", &value[..50])
                } else {
                    value.to_string()
                }
            );

            if cfg!(debug_assertions) {
                tracing::warn!("{}", msg);
                tracing::warn!("⚠️  This would PANIC in production!");
            } else {
                panic!("{}", msg);
            }

            return;
        }
    }
}

/// Validates all critical environment variables for placeholder patterns
///
/// This function should be called during application startup to ensure
/// all critical configuration values have been properly set.
///
/// # Panics
///
/// In production, panics if any critical variable contains placeholder patterns.
///
/// # Example
///
/// ```rust,no_run
/// use server::security::placeholder_validator::validate_all_critical_env_vars;
///
/// fn main() {
///     // Call this early in main() before any other initialization
///     validate_all_critical_env_vars();
///     // ... rest of application startup
/// }
/// ```
pub fn validate_all_critical_env_vars() {
    tracing::info!("🔍 Validating critical environment variables for placeholder patterns...");

    let critical_vars = vec![
        "DB_ENCRYPTION_KEY",
        "SESSION_SECRET_KEY",
        "JWT_SECRET",
        "ARBITER_PUBKEY",
    ];

    let mut found_placeholders = false;

    for var_name in critical_vars {
        if let Ok(value) = env::var(var_name) {
            validate_no_placeholders(var_name, &value);
        } else {
            // Variable not set - this is handled by other validation
            tracing::debug!("{} not set (handled by other validation)", var_name);
        }
    }

    if !found_placeholders {
        tracing::info!("✅ All critical environment variables validated successfully");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_patterns_detected() {
        let test_cases = vec![
            ("your-64-char-hex-key-here", true),
            ("your_secret_key_here", true),
            ("changeme123456", true),
            ("example-key-value", true),
            ("placeholder_value_123", true),
            ("dummy-encryption-key", true),
            ("test123-key", true),
            ("fixme-update-this", true),
            ("a1b2c3d4e5f6789012345678", false), // legitimate hex
            ("dK3mN8pQvL2xYwZ6tB9jR4sA7fH1gE5n", false), // legitimate base64
            ("8dca8a38790f2ce50422553309fa4f75", false), // legitimate hex
        ];

        for (value, should_contain_placeholder) in test_cases {
            let contains_placeholder = PLACEHOLDER_PATTERNS
                .iter()
                .any(|pattern| value.to_lowercase().contains(pattern));

            assert_eq!(
                contains_placeholder, should_contain_placeholder,
                "Failed for value: {}",
                value
            );
        }
    }

    #[test]
    fn test_validate_safe_values() {
        // These should not panic or warn
        validate_no_placeholders(
            "DB_ENCRYPTION_KEY",
            "8dca8a38790f2ce50422553309fa4f756dfd50d7c67a0aba2009d688b64ea811",
        );
        validate_no_placeholders(
            "SESSION_SECRET_KEY",
            "dK3mN8pQvL2xYwZ6tB9jR4sA7fH1gE5nC0uI2oM3kP8vT6qX9rW1lJ4hD7yS0bF=",
        );
    }

    #[test]
    #[should_panic(expected = "placeholder pattern")]
    #[cfg(not(debug_assertions))] // Only panic in release mode
    fn test_validate_unsafe_values_production() {
        validate_no_placeholders("DB_ENCRYPTION_KEY", "your-64-char-hex-key-here");
    }

    #[test]
    fn test_validate_empty_values() {
        // Empty values should not trigger validation (handled elsewhere)
        validate_no_placeholders("DB_ENCRYPTION_KEY", "");
        validate_no_placeholders("SESSION_SECRET_KEY", "short");
    }

    #[test]
    fn test_case_insensitive_detection() {
        // Should detect placeholders regardless of case
        let test_cases = vec![
            "YOUR-SECRET-HERE",
            "Your-Secret-Here",
            "CHANGEME",
            "ChangeMe",
            "EXAMPLE",
            "Example",
        ];

        for value in test_cases {
            let contains_placeholder = PLACEHOLDER_PATTERNS
                .iter()
                .any(|pattern| value.to_lowercase().contains(pattern));

            assert!(
                contains_placeholder,
                "Should detect placeholder in: {}",
                value
            );
        }
    }
}
