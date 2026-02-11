use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

/// Configuration for the DatabaseManager
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub database_path: PathBuf,
    pub backup_dir: PathBuf,
    pub backup_retention_days: u32,
}

impl DatabaseConfig {
    /// Load configuration from environment or use defaults
    pub fn from_env() -> Result<Self> {
        let database_path = PathBuf::from(
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string()),
        );

        let backup_dir = PathBuf::from(
            std::env::var("DATABASE_BACKUP_DIR").unwrap_or_else(|_| "./backups".to_string()),
        );

        let backup_retention_days = std::env::var("DATABASE_BACKUP_RETENTION_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        Ok(Self {
            database_path,
            backup_dir,
            backup_retention_days,
        })
    }
}

/// Manages database backups and integrity verification
#[derive(Clone)]
pub struct DatabaseManager {
    config: DatabaseConfig,
}

impl DatabaseManager {
    /// Create a new DatabaseManager
    pub fn new(config: DatabaseConfig) -> Result<Self> {
        // Create backup directory if it doesn't exist
        fs::create_dir_all(&config.backup_dir).context("Failed to create backup directory")?;

        info!(
            "DatabaseManager initialized: backups at {:?}",
            config.backup_dir
        );

        Ok(Self { config })
    }

    /// Verify database integrity using PRAGMA integrity_check
    pub fn verify_integrity(&self, db_path: &Path) -> Result<()> {
        if !db_path.exists() {
            debug!(
                "Database file {:?} does not exist (OK for new databases)",
                db_path
            );
            return Ok(());
        }

        // Get encryption key from environment
        let encryption_key = std::env::var("DB_ENCRYPTION_KEY")
            .context("DB_ENCRYPTION_KEY not set - required for SQLCipher integrity check")?;

        // Use sqlcipher command-line tool with encryption key
        let pragma_cmd = format!("PRAGMA key = '{encryption_key}'; PRAGMA integrity_check;");
        let output = std::process::Command::new("sqlcipher")
            .arg(db_path)
            .arg(&pragma_cmd)
            .output()
            .context("Failed to run sqlcipher integrity check")?;

        let result = String::from_utf8_lossy(&output.stdout);

        if !result.contains("ok") {
            error!(
                "Database integrity check failed for {:?}: {}",
                db_path, result
            );
            anyhow::bail!(
                "Database corrupted: {}",
                result.trim().lines().next().unwrap_or("unknown error")
            );
        }

        debug!("Database integrity check passed: {:?}", db_path);
        Ok(())
    }

    /// Create an atomic backup of the database
    /// Returns the path to the backup file
    pub fn create_backup(&self, backup_reason: &str) -> Result<PathBuf> {
        if !self.config.database_path.exists() {
            debug!(
                "Database {:?} does not exist, skipping backup",
                self.config.database_path
            );
            return Ok(PathBuf::new());
        }

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_path = self
            .config
            .backup_dir
            .join(format!("nexus_{backup_reason}_{timestamp}.db"));

        info!(
            "Creating backup: {:?} (reason: {})",
            backup_path, backup_reason
        );

        // For SQLCipher databases, use file copy instead of .backup command
        // SQLCipher CLI doesn't support .backup on encrypted databases
        // This is safe because SQLite uses WAL mode with atomic writes
        std::fs::copy(&self.config.database_path, &backup_path)
            .context("Failed to copy database file for backup")?;

        // Verify the backup is valid (can be skipped via env var)
        let skip_integrity = std::env::var("SKIP_DB_INTEGRITY_CHECK")
            .ok()
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        if !skip_integrity {
            self.verify_integrity(&backup_path)
                .context("Backup integrity check failed")?;
        }

        let size = fs::metadata(&backup_path)
            .context("Failed to get backup file size")?
            .len();

        info!(
            "Backup created successfully: {:?} ({} bytes)",
            backup_path, size
        );

        Ok(backup_path)
    }

    /// Restore database from a backup file
    pub fn restore_from_backup(&self, backup_path: &Path) -> Result<()> {
        if !backup_path.exists() {
            anyhow::bail!("Backup file {backup_path:?} does not exist");
        }

        // Verify backup is valid before restoring
        self.verify_integrity(backup_path)
            .context("Backup file is corrupted")?;

        warn!("Restoring database from backup: {:?}", backup_path);

        // Backup the corrupted file for analysis
        let corrupted_path = self.config.database_path.with_extension("corrupted");
        if self.config.database_path.exists() {
            fs::rename(&self.config.database_path, &corrupted_path)
                .context("Failed to backup corrupted database")?;
            warn!("Corrupted database backed up to: {:?}", corrupted_path);
        }

        // Restore from backup
        fs::copy(backup_path, &self.config.database_path)
            .context("Failed to restore database from backup")?;

        info!("Database restored successfully from: {:?}", backup_path);

        Ok(())
    }

    /// Clean up old backups based on retention policy
    pub fn cleanup_old_backups(&self) -> Result<()> {
        let entries =
            fs::read_dir(&self.config.backup_dir).context("Failed to read backup directory")?;

        let now = std::time::SystemTime::now();
        let retention_duration =
            std::time::Duration::from_secs(self.config.backup_retention_days as u64 * 86400);

        let mut cleaned_count = 0;
        let mut total_freed = 0u64;

        for entry in entries {
            let entry = entry.context("Failed to read backup directory entry")?;
            let path = entry.path();

            // Only process .db files
            if path.extension().and_then(|s| s.to_str()) != Some("db") {
                continue;
            }

            // Skip non-backup files
            if !path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.contains("nexus_"))
                .unwrap_or(false)
            {
                continue;
            }

            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = now.duration_since(modified) {
                        if elapsed > retention_duration {
                            let size = metadata.len();
                            fs::remove_file(&path)
                                .context(format!("Failed to remove backup: {path:?}"))?;
                            cleaned_count += 1;
                            total_freed += size;
                            debug!("Removed old backup: {:?}", path);
                        }
                    }
                }
            }
        }

        if cleaned_count > 0 {
            info!(
                "Cleaned {} old backups, freed {} MB",
                cleaned_count,
                total_freed / (1024 * 1024)
            );
        }

        Ok(())
    }

    /// Get statistics about backups
    pub fn get_backup_stats(&self) -> Result<BackupStats> {
        let mut backup_count = 0;
        let mut total_size = 0u64;
        let mut oldest_backup: Option<PathBuf> = None;
        let mut oldest_time: Option<std::time::SystemTime> = None;

        let entries =
            fs::read_dir(&self.config.backup_dir).context("Failed to read backup directory")?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("db") {
                if let Ok(metadata) = entry.metadata() {
                    backup_count += 1;
                    total_size += metadata.len();

                    if let Ok(modified) = metadata.modified() {
                        if oldest_time.is_none() || Some(&modified) < oldest_time.as_ref() {
                            oldest_time = Some(modified);
                            oldest_backup = Some(path);
                        }
                    }
                }
            }
        }

        Ok(BackupStats {
            backup_count,
            total_size_mb: total_size / (1024 * 1024),
            oldest_backup,
        })
    }
}

/// Statistics about backups
#[derive(Debug)]
pub struct BackupStats {
    pub backup_count: usize,
    pub total_size_mb: u64,
    pub oldest_backup: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_config_from_env() {
        std::env::set_var("DATABASE_URL", "/tmp/test.db");
        std::env::set_var("DATABASE_BACKUP_DIR", "/tmp/backups");
        std::env::set_var("DATABASE_BACKUP_RETENTION_DAYS", "15");

        let config = DatabaseConfig::from_env().unwrap();
        assert_eq!(config.database_path, PathBuf::from("/tmp/test.db"));
        assert_eq!(config.backup_dir, PathBuf::from("/tmp/backups"));
        assert_eq!(config.backup_retention_days, 15);
    }

    #[test]
    fn test_config_defaults() {
        // Clear environment variables
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("DATABASE_BACKUP_DIR");
        std::env::remove_var("DATABASE_BACKUP_RETENTION_DAYS");

        let config = DatabaseConfig::from_env().unwrap();
        assert_eq!(config.database_path, PathBuf::from("marketplace.db"));
        assert_eq!(config.backup_dir, PathBuf::from("./backups"));
        assert_eq!(config.backup_retention_days, 30);
    }

    #[test]
    fn test_database_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = DatabaseConfig {
            database_path: temp_dir.path().join("test.db"),
            backup_dir: temp_dir.path().join("backups"),
            backup_retention_days: 30,
        };

        let manager = DatabaseManager::new(config).unwrap();
        assert!(manager.config.backup_dir.exists());
    }

    #[test]
    fn test_backup_stats_empty() {
        let temp_dir = TempDir::new().unwrap();
        let config = DatabaseConfig {
            database_path: temp_dir.path().join("test.db"),
            backup_dir: temp_dir.path().join("backups"),
            backup_retention_days: 30,
        };

        let manager = DatabaseManager::new(config).unwrap();
        let stats = manager.get_backup_stats().unwrap();
        assert_eq!(stats.backup_count, 0);
        assert_eq!(stats.total_size_mb, 0);
    }

    #[test]
    fn test_cleanup_old_backups() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = temp_dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();

        let config = DatabaseConfig {
            database_path: temp_dir.path().join("test.db"),
            backup_dir: backup_dir.clone(),
            backup_retention_days: 0, // Keep nothing
        };

        // Create a fake backup
        fs::write(
            backup_dir.join("nexus_test_20250101_000000.db"),
            "fake data",
        )
        .unwrap();

        let manager = DatabaseManager::new(config).unwrap();
        manager.cleanup_old_backups().unwrap();

        // File should be deleted since retention_days = 0
        assert!(!backup_dir.join("nexus_test_20250101_000000.db").exists());
    }
}
