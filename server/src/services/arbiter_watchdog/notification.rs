//! Notification Service - Multi-channel alerts for arbiter watchdog
//!
//! Supports Telegram, Email, and Webhook notifications for:
//! - Dispute escalation
//! - Auto-sign events
//! - Error conditions

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use serde::Serialize;
use tracing::{error, info, warn};

use crate::models::escrow::Escrow;
use crate::services::arbiter_watchdog::config::WatchdogConfig;

/// Notification channel configuration
#[derive(Clone)]
pub enum NotificationChannel {
    /// Telegram bot notification
    Telegram { bot_token: String, chat_id: String },
    /// Email notification via SMTP
    Email {
        smtp_host: String,
        smtp_port: u16,
        smtp_username: String,
        smtp_password: String,
        from_address: String,
        recipient: String,
    },
    /// Webhook notification
    Webhook { url: String },
}

/// Notification service for multi-channel alerts
pub struct NotificationService {
    channels: Vec<NotificationChannel>,
    http_client: reqwest::Client,
}

impl NotificationService {
    /// Create a new NotificationService with the given channels
    pub fn new(channels: Vec<NotificationChannel>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        info!(
            channel_count = channels.len(),
            "NotificationService initialized"
        );

        Self {
            channels,
            http_client,
        }
    }

    /// Create NotificationService from WatchdogConfig
    pub fn from_config(config: &WatchdogConfig) -> Result<Self> {
        let mut channels = Vec::new();

        // Add Telegram channel if configured
        if let (Some(bot_token), Some(chat_id)) =
            (&config.telegram_bot_token, &config.telegram_chat_id)
        {
            channels.push(NotificationChannel::Telegram {
                bot_token: bot_token.clone(),
                chat_id: chat_id.clone(),
            });
            info!("Telegram notification channel configured");
        }

        // Add Email channel if configured
        if let (Some(smtp_host), Some(from_addr), Some(recipient)) = (
            &config.smtp_host,
            &config.smtp_from_address,
            &config.arbiter_alert_email,
        ) {
            channels.push(NotificationChannel::Email {
                smtp_host: smtp_host.clone(),
                smtp_port: config.smtp_port.unwrap_or(587),
                smtp_username: config.smtp_username.clone().unwrap_or_default(),
                smtp_password: config
                    .smtp_password
                    .as_ref()
                    .map(|p| p.expose_secret().clone())
                    .unwrap_or_default(),
                from_address: from_addr.clone(),
                recipient: recipient.clone(),
            });
            info!("Email notification channel configured");
        }

        // Add Webhook channel if configured
        if let Some(webhook_url) = &config.webhook_url {
            channels.push(NotificationChannel::Webhook {
                url: webhook_url.clone(),
            });
            info!("Webhook notification channel configured");
        }

        if channels.is_empty() {
            warn!("No notification channels configured - alerts will only be logged");
        }

        Ok(NotificationService::new(channels))
    }

    /// Send dispute alert to all configured channels
    pub async fn alert_dispute(&self, escrow: &Escrow, reason: &str) -> Result<()> {
        let amount_xmr = escrow.amount as f64 / 1_000_000_000_000.0;
        let dispute_days = escrow
            .dispute_created_at
            .map(|d| {
                let now = chrono::Utc::now().naive_utc();
                (now - d).num_days()
            })
            .unwrap_or(0);

        let message = format!(
            "🚨 DISPUTE ALERT - ARBITER ACTION REQUIRED\n\n\
             📦 Escrow: {}\n\
             💰 Amount: {:.6} XMR\n\
             📅 Days in dispute: {}\n\
             ❓ Reason: {}\n\n\
             ⚠️ Action Required: Manual resolution needed.\n\
             🔗 Dashboard: /admin/disputes/{}",
            &escrow.id[..8],
            amount_xmr,
            dispute_days,
            reason,
            escrow.id
        );

        self.send_all(&message).await
    }

    /// Send auto-sign notification (informational)
    pub async fn notify_auto_signed(&self, escrow_id: &str, action: &str) -> Result<()> {
        let message = format!(
            "✅ AUTO-SIGN COMPLETE\n\n\
             📦 Escrow: {}\n\
             ✍️ Action: {}\n\
             🤖 Signed by: Arbiter Watchdog\n\n\
             No manual action required.",
            &escrow_id[..8],
            action
        );

        self.send_all(&message).await
    }

    /// Send error notification
    pub async fn notify_error(&self, escrow_id: &str, error: &str) -> Result<()> {
        let message = format!(
            "❌ WATCHDOG ERROR\n\n\
             📦 Escrow: {}\n\
             🔥 Error: {}\n\n\
             ⚠️ Manual investigation may be required.",
            &escrow_id[..8],
            error
        );

        self.send_all(&message).await
    }

    /// Send message to all configured channels
    async fn send_all(&self, message: &str) -> Result<()> {
        if self.channels.is_empty() {
            warn!(
                "No notification channels - message only logged: {}",
                message
            );
            return Ok(());
        }

        let mut errors = Vec::new();

        for channel in &self.channels {
            if let Err(e) = self.send_to_channel(channel, message).await {
                error!(error = %e, "Failed to send notification");
                errors.push(e.to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else if errors.len() == self.channels.len() {
            Err(anyhow::anyhow!(
                "All notification channels failed: {}",
                errors.join("; ")
            ))
        } else {
            // Some channels succeeded
            warn!("Some notification channels failed: {}", errors.join("; "));
            Ok(())
        }
    }

    /// Send message to a specific channel
    async fn send_to_channel(&self, channel: &NotificationChannel, message: &str) -> Result<()> {
        match channel {
            NotificationChannel::Telegram { bot_token, chat_id } => {
                self.send_telegram(bot_token, chat_id, message).await
            }
            NotificationChannel::Email {
                smtp_host,
                smtp_port,
                smtp_username,
                smtp_password,
                from_address,
                recipient,
            } => {
                self.send_email(
                    smtp_host,
                    *smtp_port,
                    smtp_username,
                    smtp_password,
                    from_address,
                    recipient,
                    message,
                )
                .await
            }
            NotificationChannel::Webhook { url } => self.send_webhook(url, message).await,
        }
    }

    /// Send Telegram message via Bot API
    async fn send_telegram(&self, bot_token: &str, chat_id: &str, message: &str) -> Result<()> {
        let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");

        #[derive(Serialize)]
        struct TelegramMessage<'a> {
            chat_id: &'a str,
            text: &'a str,
            parse_mode: &'a str,
        }

        let payload = TelegramMessage {
            chat_id,
            text: message,
            parse_mode: "HTML",
        };

        let response = self
            .http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Telegram request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Telegram API error: {status} - {body}"));
        }

        info!("Telegram notification sent");
        Ok(())
    }

    /// Send email via SMTP
    ///
    /// Note: Full SMTP implementation would use lettre crate.
    /// This is a simplified version using external SMTP relay.
    async fn send_email(
        &self,
        smtp_host: &str,
        smtp_port: u16,
        _smtp_username: &str,
        _smtp_password: &str,
        from_address: &str,
        recipient: &str,
        _message: &str,
    ) -> Result<()> {
        // For production, use lettre crate for full SMTP support
        // This is a placeholder that logs the email intent

        info!(
            smtp_host = %smtp_host,
            smtp_port = %smtp_port,
            from = %from_address,
            to = %recipient,
            "Email notification would be sent (SMTP not fully implemented)"
        );

        // In production, implement with lettre:
        // use lettre::{transport::smtp::authentication::Credentials, SmtpTransport, Transport, Message};
        // let email = Message::builder()
        //     .from(from_address.parse()?)
        //     .to(recipient.parse()?)
        //     .subject("Onyx Arbiter Alert")
        //     .body(message.to_string())?;
        // let mailer = SmtpTransport::relay(smtp_host)?
        //     .port(smtp_port)
        //     .credentials(Credentials::new(smtp_username.into(), smtp_password.into()))
        //     .build();
        // mailer.send(&email)?;

        Ok(())
    }

    /// Send webhook notification
    async fn send_webhook(&self, url: &str, message: &str) -> Result<()> {
        #[derive(Serialize)]
        struct WebhookPayload<'a> {
            event: &'a str,
            timestamp: String,
            message: &'a str,
        }

        let payload = WebhookPayload {
            event: "arbiter_watchdog_alert",
            timestamp: chrono::Utc::now().to_rfc3339(),
            message,
        };

        let response = self
            .http_client
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send webhook request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Webhook error: {status} - {body}"));
        }

        info!("Webhook notification sent");
        Ok(())
    }

    /// Check if any notification channels are configured
    pub fn has_channels(&self) -> bool {
        !self.channels.is_empty()
    }

    /// Get the number of configured channels
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_service_empty() {
        let service = NotificationService::new(vec![]);
        assert!(!service.has_channels());
        assert_eq!(service.channel_count(), 0);
    }

    #[test]
    fn test_notification_service_with_channels() {
        let channels = vec![
            NotificationChannel::Telegram {
                bot_token: "test_token".to_string(),
                chat_id: "12345".to_string(),
            },
            NotificationChannel::Webhook {
                url: "https://example.com/webhook".to_string(),
            },
        ];

        let service = NotificationService::new(channels);
        assert!(service.has_channels());
        assert_eq!(service.channel_count(), 2);
    }
}
