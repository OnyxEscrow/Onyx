//! Arbiter Watchdog Configuration

use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::time::Duration;

/// Watchdog configuration for automated arbiter signing
#[derive(Clone)]
pub struct WatchdogConfig {
    /// How often to poll for pending escrows
    pub poll_interval: Duration,

    /// Master password for encrypting/decrypting arbiter key packages
    pub vault_master_password: SecretString,

    /// Whether auto-signing is enabled
    pub auto_sign_enabled: bool,

    /// Require both parties to have signed before arbiter auto-signs
    pub require_both_signatures: bool,

    /// Telegram bot token for notifications (optional)
    pub telegram_bot_token: Option<String>,

    /// Telegram chat ID for notifications (optional)
    pub telegram_chat_id: Option<String>,

    /// Email address for arbiter alerts (optional)
    pub arbiter_alert_email: Option<String>,

    /// Webhook URL for notifications (optional)
    pub webhook_url: Option<String>,

    /// SMTP configuration for email notifications
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<SecretString>,
    pub smtp_from_address: Option<String>,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            vault_master_password: SecretString::new("INSECURE_DEFAULT_DO_NOT_USE_IN_PRODUCTION".into()),
            auto_sign_enabled: true,
            require_both_signatures: true,
            telegram_bot_token: None,
            telegram_chat_id: None,
            arbiter_alert_email: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            smtp_from_address: None,
        }
    }
}

impl WatchdogConfig {
    /// Create configuration from environment variables
    ///
    /// # Environment Variables
    /// - `ARBITER_WATCHDOG_POLL_INTERVAL_SECS` - Poll interval (default: 30)
    /// - `ARBITER_VAULT_MASTER_PASSWORD` - Master password for key encryption (REQUIRED)
    /// - `ARBITER_AUTO_SIGN_ENABLED` - Enable auto-signing (default: true)
    /// - `ARBITER_REQUIRE_BOTH_SIGNATURES` - Require both parties signed (default: true)
    /// - `ARBITER_TELEGRAM_BOT_TOKEN` - Telegram bot token
    /// - `ARBITER_TELEGRAM_CHAT_ID` - Telegram chat ID
    /// - `ARBITER_ALERT_EMAIL` - Email for alerts
    /// - `ARBITER_WEBHOOK_URL` - Webhook URL for notifications
    /// - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS` - SMTP config
    pub fn from_env() -> Result<Self, ConfigError> {
        let poll_interval_secs: u64 = env::var("ARBITER_WATCHDOG_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let vault_master_password = env::var("ARBITER_VAULT_MASTER_PASSWORD")
            .map(SecretString::new)
            .map_err(|_| ConfigError::MissingVaultPassword)?;

        // Validate password strength
        if vault_master_password.expose_secret().len() < 16 {
            return Err(ConfigError::WeakVaultPassword);
        }

        let auto_sign_enabled = env::var("ARBITER_AUTO_SIGN_ENABLED")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        let require_both_signatures = env::var("ARBITER_REQUIRE_BOTH_SIGNATURES")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        let telegram_bot_token = env::var("ARBITER_TELEGRAM_BOT_TOKEN").ok();
        let telegram_chat_id = env::var("ARBITER_TELEGRAM_CHAT_ID").ok();
        let arbiter_alert_email = env::var("ARBITER_ALERT_EMAIL").ok();
        let webhook_url = env::var("ARBITER_WEBHOOK_URL").ok();

        let smtp_host = env::var("SMTP_HOST").ok();
        let smtp_port = env::var("SMTP_PORT").ok().and_then(|s| s.parse().ok());
        let smtp_username = env::var("SMTP_USERNAME").ok();
        let smtp_password = env::var("SMTP_PASSWORD").ok().map(SecretString::new);
        let smtp_from_address = env::var("SMTP_FROM_ADDRESS").ok();

        Ok(Self {
            poll_interval: Duration::from_secs(poll_interval_secs),
            vault_master_password,
            auto_sign_enabled,
            require_both_signatures,
            telegram_bot_token,
            telegram_chat_id,
            arbiter_alert_email,
            webhook_url,
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_from_address,
        })
    }

    /// Check if Telegram notifications are configured
    pub fn has_telegram(&self) -> bool {
        self.telegram_bot_token.is_some() && self.telegram_chat_id.is_some()
    }

    /// Check if email notifications are configured
    pub fn has_email(&self) -> bool {
        self.arbiter_alert_email.is_some()
            && self.smtp_host.is_some()
            && self.smtp_from_address.is_some()
    }

    /// Check if webhook notifications are configured
    pub fn has_webhook(&self) -> bool {
        self.webhook_url.is_some()
    }

    /// Check if any notification channel is configured
    pub fn has_any_notification_channel(&self) -> bool {
        self.has_telegram() || self.has_email() || self.has_webhook()
    }
}

/// Configuration errors for WatchdogConfig
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// ARBITER_VAULT_MASTER_PASSWORD not set
    MissingVaultPassword,
    /// Password is too short (< 16 characters)
    WeakVaultPassword,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingVaultPassword => {
                write!(f, "ARBITER_VAULT_MASTER_PASSWORD environment variable is required")
            }
            ConfigError::WeakVaultPassword => {
                write!(f, "ARBITER_VAULT_MASTER_PASSWORD must be at least 16 characters")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WatchdogConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        assert!(config.auto_sign_enabled);
        assert!(config.require_both_signatures);
        assert!(!config.has_telegram());
        assert!(!config.has_email());
        assert!(!config.has_webhook());
    }
}
