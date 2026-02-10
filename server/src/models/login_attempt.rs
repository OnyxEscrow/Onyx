//! Login attempt tracking model for per-username brute-force protection
//!
//! P0 Security: Tracks failed login attempts per username to prevent
//! distributed brute-force attacks that bypass IP-based rate limiting.

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::login_attempts;

/// Maximum failed attempts before lockout
pub const MAX_FAILED_ATTEMPTS: i64 = 5;

/// Lockout duration in seconds (15 minutes)
pub const LOCKOUT_DURATION_SECS: i64 = 900;

/// Window for counting failed attempts (1 hour)
pub const ATTEMPT_WINDOW_SECS: i64 = 3600;

/// Login attempt type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptType {
    Failed,
    Success,
    Lockout,
}

impl AttemptType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttemptType::Failed => "failed",
            AttemptType::Success => "success",
            AttemptType::Lockout => "lockout",
        }
    }
}

/// Login attempt record (Queryable)
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = login_attempts)]
pub struct LoginAttempt {
    pub id: String,
    pub username: String,
    pub ip_address: Option<String>,
    pub attempt_type: String,
    pub created_at: NaiveDateTime,
}

/// New login attempt for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = login_attempts)]
pub struct NewLoginAttempt {
    pub id: String,
    pub username: String,
    pub ip_address: Option<String>,
    pub attempt_type: String,
}

impl NewLoginAttempt {
    pub fn new(username: &str, ip_address: Option<&str>, attempt_type: AttemptType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            username: username.to_lowercase(),
            ip_address: ip_address.map(|s| s.to_string()),
            attempt_type: attempt_type.as_str().to_string(),
        }
    }
}

impl LoginAttempt {
    /// Record a login attempt
    pub fn record(
        conn: &mut SqliteConnection,
        username: &str,
        ip_address: Option<&str>,
        attempt_type: AttemptType,
    ) -> Result<LoginAttempt> {
        let new_attempt = NewLoginAttempt::new(username, ip_address, attempt_type);
        let attempt_id = new_attempt.id.clone();

        diesel::insert_into(login_attempts::table)
            .values(&new_attempt)
            .execute(conn)
            .context("Failed to insert login attempt")?;

        login_attempts::table
            .filter(login_attempts::id.eq(&attempt_id))
            .first(conn)
            .context("Failed to retrieve created login attempt")
    }

    /// Count recent failed attempts for a username
    ///
    /// Returns the number of failed attempts in the last ATTEMPT_WINDOW_SECS
    pub fn count_recent_failed(conn: &mut SqliteConnection, username: &str) -> Result<i64> {
        use diesel::dsl::*;

        let cutoff =
            chrono::Utc::now().naive_utc() - chrono::Duration::seconds(ATTEMPT_WINDOW_SECS);

        let count: i64 = login_attempts::table
            .filter(login_attempts::username.eq(username.to_lowercase()))
            .filter(login_attempts::attempt_type.eq("failed"))
            .filter(login_attempts::created_at.gt(cutoff))
            .count()
            .get_result(conn)
            .context("Failed to count recent failed attempts")?;

        Ok(count)
    }

    /// Check if username is currently locked out
    ///
    /// Returns true if:
    /// 1. There are MAX_FAILED_ATTEMPTS or more failed attempts in the window
    /// 2. The most recent lockout record is within LOCKOUT_DURATION_SECS
    pub fn is_locked_out(conn: &mut SqliteConnection, username: &str) -> Result<bool> {
        let username_lower = username.to_lowercase();

        // Check for active lockout record
        let lockout_cutoff =
            chrono::Utc::now().naive_utc() - chrono::Duration::seconds(LOCKOUT_DURATION_SECS);

        let active_lockout: i64 = login_attempts::table
            .filter(login_attempts::username.eq(&username_lower))
            .filter(login_attempts::attempt_type.eq("lockout"))
            .filter(login_attempts::created_at.gt(lockout_cutoff))
            .count()
            .get_result(conn)
            .context("Failed to check active lockout")?;

        if active_lockout > 0 {
            return Ok(true);
        }

        // Check if we should create a lockout (too many failed attempts)
        let failed_count = Self::count_recent_failed(conn, &username_lower)?;

        if failed_count >= MAX_FAILED_ATTEMPTS {
            // Record the lockout
            let _ = Self::record(conn, &username_lower, None, AttemptType::Lockout);
            return Ok(true);
        }

        Ok(false)
    }

    /// Get remaining lockout time in seconds
    ///
    /// Returns 0 if not locked out
    pub fn lockout_remaining_secs(conn: &mut SqliteConnection, username: &str) -> Result<i64> {
        let username_lower = username.to_lowercase();

        // Find most recent lockout
        let recent_lockout: Option<LoginAttempt> = login_attempts::table
            .filter(login_attempts::username.eq(&username_lower))
            .filter(login_attempts::attempt_type.eq("lockout"))
            .order(login_attempts::created_at.desc())
            .first(conn)
            .optional()
            .context("Failed to query recent lockout")?;

        if let Some(lockout) = recent_lockout {
            let lockout_ends =
                lockout.created_at + chrono::Duration::seconds(LOCKOUT_DURATION_SECS);
            let now = chrono::Utc::now().naive_utc();

            if lockout_ends > now {
                return Ok((lockout_ends - now).num_seconds());
            }
        }

        Ok(0)
    }

    /// Clear successful login - reset failed attempt tracking
    ///
    /// On successful login, we don't delete old records (for audit),
    /// but we record a success which implicitly resets the lockout check.
    pub fn record_success(
        conn: &mut SqliteConnection,
        username: &str,
        ip_address: Option<&str>,
    ) -> Result<()> {
        Self::record(conn, username, ip_address, AttemptType::Success)?;
        Ok(())
    }

    /// Clean up old attempts (older than 7 days)
    ///
    /// Should be run periodically to prevent table bloat
    pub fn cleanup_old(conn: &mut SqliteConnection) -> Result<usize> {
        let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::days(7);

        let deleted =
            diesel::delete(login_attempts::table.filter(login_attempts::created_at.lt(cutoff)))
                .execute(conn)
                .context("Failed to cleanup old login attempts")?;

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attempt_type_as_str() {
        assert_eq!(AttemptType::Failed.as_str(), "failed");
        assert_eq!(AttemptType::Success.as_str(), "success");
        assert_eq!(AttemptType::Lockout.as_str(), "lockout");
    }

    #[test]
    fn test_new_login_attempt_normalizes_username() {
        let attempt = NewLoginAttempt::new("TestUser", Some("127.0.0.1"), AttemptType::Failed);
        assert_eq!(attempt.username, "testuser");
    }
}
