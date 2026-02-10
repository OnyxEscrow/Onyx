//! Shield Backup Model
//!
//! Tracks Mandatory Shield file downloads and verification.
//! The Shield is an encrypted backup of FROST key_package that users
//! MUST download after DKG Round 3 completion.

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use crate::schema::shield_backups;

/// Shield backup record
#[derive(Debug, Clone, Queryable, Identifiable, Serialize)]
#[diesel(table_name = shield_backups)]
pub struct ShieldBackup {
    pub id: String,
    pub escrow_id: String,
    pub user_id: String,
    pub role: String,
    pub backup_id: String,
    pub created_at: NaiveDateTime,
    pub verified_at: Option<NaiveDateTime>,
    pub download_count: i32,
    pub last_verified_at: Option<NaiveDateTime>,
}

/// Insertable shield backup
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = shield_backups)]
pub struct NewShieldBackup {
    pub id: String,
    pub escrow_id: String,
    pub user_id: String,
    pub role: String,
    pub backup_id: String,
}

/// DTO for API responses
#[derive(Debug, Serialize)]
pub struct ShieldBackupStatus {
    pub has_shield: bool,
    pub backup_id: Option<String>,
    pub created_at: Option<String>,
    pub verified: bool,
    pub download_count: i32,
}

impl ShieldBackup {
    /// Create a new shield backup record
    pub fn create(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        user_id: &str,
        role: &str,
        backup_id: &str,
    ) -> Result<Self> {
        let new_backup = NewShieldBackup {
            id: format!(
                "shld_{}",
                Uuid::new_v4().to_string().replace("-", "")[..16].to_string()
            ),
            escrow_id: escrow_id.to_string(),
            user_id: user_id.to_string(),
            role: role.to_string(),
            backup_id: backup_id.to_string(),
        };

        diesel::insert_into(shield_backups::table)
            .values(&new_backup)
            .execute(conn)
            .context("Failed to insert shield backup")?;

        shield_backups::table
            .filter(shield_backups::id.eq(&new_backup.id))
            .first(conn)
            .context("Failed to retrieve created shield backup")
    }

    /// Find shield backup for user in escrow
    pub fn find_by_user_escrow(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        user_id: &str,
    ) -> Result<Option<Self>> {
        shield_backups::table
            .filter(shield_backups::escrow_id.eq(escrow_id))
            .filter(shield_backups::user_id.eq(user_id))
            .first(conn)
            .optional()
            .context("Failed to query shield backup")
    }

    /// Find shield backup by backup_id
    pub fn find_by_backup_id(conn: &mut SqliteConnection, backup_id: &str) -> Result<Option<Self>> {
        shield_backups::table
            .filter(shield_backups::backup_id.eq(backup_id))
            .first(conn)
            .optional()
            .context("Failed to query shield backup by backup_id")
    }

    /// Verify shield backup exists for escrow
    pub fn verify_for_escrow(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        backup_id: &str,
    ) -> Result<Option<Self>> {
        shield_backups::table
            .filter(shield_backups::escrow_id.eq(escrow_id))
            .filter(shield_backups::backup_id.eq(backup_id))
            .first(conn)
            .optional()
            .context("Failed to verify shield backup")
    }

    /// Mark shield as verified (used during recovery)
    pub fn mark_verified(conn: &mut SqliteConnection, id: &str) -> Result<()> {
        let now = chrono::Utc::now().naive_utc();
        diesel::update(shield_backups::table.filter(shield_backups::id.eq(id)))
            .set((
                shield_backups::verified_at.eq(Some(now)),
                shield_backups::last_verified_at.eq(Some(now)),
            ))
            .execute(conn)
            .context("Failed to mark shield as verified")?;
        Ok(())
    }

    /// Update backup_id (during Shield recovery with a different derived ID)
    pub fn update_backup_id(
        conn: &mut SqliteConnection,
        id: &str,
        new_backup_id: &str,
    ) -> Result<()> {
        diesel::update(shield_backups::table.filter(shield_backups::id.eq(id)))
            .set(shield_backups::backup_id.eq(new_backup_id))
            .execute(conn)
            .context("Failed to update shield backup_id")?;
        Ok(())
    }

    /// Increment download count (user re-downloaded shield)
    pub fn increment_download_count(conn: &mut SqliteConnection, id: &str) -> Result<()> {
        diesel::update(shield_backups::table.filter(shield_backups::id.eq(id)))
            .set(shield_backups::download_count.eq(shield_backups::download_count + 1))
            .execute(conn)
            .context("Failed to increment download count")?;
        Ok(())
    }

    /// Get status for API response
    pub fn get_status(
        conn: &mut SqliteConnection,
        escrow_id: &str,
        user_id: &str,
    ) -> ShieldBackupStatus {
        match Self::find_by_user_escrow(conn, escrow_id, user_id) {
            Ok(Some(backup)) => ShieldBackupStatus {
                has_shield: true,
                backup_id: Some(backup.backup_id),
                created_at: Some(backup.created_at.format("%Y-%m-%d %H:%M UTC").to_string()),
                verified: backup.verified_at.is_some(),
                download_count: backup.download_count,
            },
            _ => ShieldBackupStatus {
                has_shield: false,
                backup_id: None,
                created_at: None,
                verified: false,
                download_count: 0,
            },
        }
    }

    /// Check if all participants have shields for an escrow
    pub fn all_participants_have_shields(
        conn: &mut SqliteConnection,
        escrow_id: &str,
    ) -> Result<bool> {
        let count: i64 = shield_backups::table
            .filter(shield_backups::escrow_id.eq(escrow_id))
            .count()
            .get_result(conn)
            .context("Failed to count shield backups")?;

        // Need 3 shields (buyer, vendor, arbiter) - but arbiter is auto-managed
        // So we check for at least 2 (buyer + vendor)
        Ok(count >= 2)
    }
}
