//! Database Backup Tool
//!
//! Creates atomic, encrypted backups of the marketplace database.
//! Handles WAL checkpointing and rotation automatically.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::env;
use std::fs;

const DB_PATH: &str = "marketplace.db";
const BACKUP_DIR: &str = "./backups";
const MAX_BACKUPS: usize = 10;

fn main() -> Result<()> {
    println!("💾 Database Backup Tool");
    println!("======================\n");

    // Load encryption key
    dotenvy::dotenv().ok();
    let encryption_key = env::var("DB_ENCRYPTION_KEY")
        .context("DB_ENCRYPTION_KEY not set")?;

    let db_path = PathBuf::from(DB_PATH);
    if !db_path.exists() {
        bail!("Database not found: {}", DB_PATH);
    }

    // Create backup directory
    let backup_dir = PathBuf::from(BACKUP_DIR);
    fs::create_dir_all(&backup_dir)
        .context("Failed to create backup directory")?;

    println!("📁 Source: {}", db_path.display());
    println!("📂 Backup dir: {}", backup_dir.display());

    // Checkpoint WAL before backup
    println!("\n1️⃣ Checkpointing WAL...");
    checkpoint_wal(&db_path, &encryption_key)?;

    // Create backup
    println!("2️⃣ Creating backup...");
    let backup_path = create_backup(&db_path, &backup_dir, &encryption_key)?;

    let size = fs::metadata(&backup_path)?.len();
    println!("   ✅ Backup created: {} ({} bytes)", backup_path.display(), size);

    // Verify backup
    println!("3️⃣ Verifying backup integrity...");
    verify_backup(&backup_path, &encryption_key)?;
    println!("   ✅ Backup verified");

    // Rotate old backups
    println!("4️⃣ Rotating old backups...");
    rotate_backups(&backup_dir, MAX_BACKUPS)?;

    println!("\n✅ Backup complete!\n");
    list_backups(&backup_dir)?;

    Ok(())
}

fn checkpoint_wal(db_path: &Path, key: &str) -> Result<()> {
    let sql = format!(
        "PRAGMA key = '{}'; PRAGMA wal_checkpoint(TRUNCATE);",
        key
    );

    let output = Command::new("sqlcipher")
        .arg(db_path)
        .arg(&sql)
        .output()
        .context("Failed to checkpoint WAL")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("WAL checkpoint failed: {}", stderr);
    }

    Ok(())
}

fn create_backup(db_path: &Path, backup_dir: &Path, key: &str) -> Result<PathBuf> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_filename = format!("nexus_backup_{}.db", timestamp);
    let backup_path = backup_dir.join(&backup_filename);

    // Use VACUUM INTO for atomic backup
    let sql = format!(
        "PRAGMA key = '{}'; VACUUM INTO '{}';",
        key,
        backup_path.display()
    );

    let output = Command::new("sqlcipher")
        .arg(db_path)
        .arg(&sql)
        .output()
        .context("Failed to create backup")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Backup creation failed: {}", stderr);
    }

    Ok(backup_path)
}

fn verify_backup(backup_path: &Path, key: &str) -> Result<()> {
    let sql = format!("PRAGMA key = '{}'; PRAGMA integrity_check;", key);

    let output = Command::new("sqlcipher")
        .arg(backup_path)
        .arg(&sql)
        .output()
        .context("Failed to verify backup")?;

    let result = String::from_utf8_lossy(&output.stdout);
    if !result.contains("ok") {
        bail!("Backup integrity check failed: {}", result);
    }

    Ok(())
}

fn rotate_backups(backup_dir: &Path, max_backups: usize) -> Result<()> {
    let mut backups: Vec<_> = fs::read_dir(backup_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "db")
                .unwrap_or(false)
        })
        .collect();

    // Sort by modification time (oldest first)
    backups.sort_by_key(|entry| {
        entry.metadata().ok().and_then(|m| m.modified().ok())
    });

    let to_remove = backups.len().saturating_sub(max_backups);

    for entry in backups.iter().take(to_remove) {
        let path = entry.path();
        println!("   🗑️  Removing old backup: {}", path.display());
        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove {}", path.display()))?;
    }

    println!("   Kept {} most recent backups", backups.len().saturating_sub(to_remove));

    Ok(())
}

fn list_backups(backup_dir: &Path) -> Result<()> {
    let mut backups: Vec<_> = fs::read_dir(backup_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "db")
                .unwrap_or(false)
        })
        .collect();

    backups.sort_by_key(|entry| {
        entry.metadata().ok().and_then(|m| m.modified().ok())
    });

    println!("📋 Available backups:");
    for entry in backups.iter().rev() {
        let path = entry.path();
        let metadata = entry.metadata()?;
        let size = metadata.len();
        let modified = metadata.modified()?;
        let datetime: chrono::DateTime<chrono::Utc> = modified.into();

        println!(
            "   - {} ({} bytes, {})",
            path.file_name().unwrap().to_string_lossy(),
            size,
            datetime.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DB_PATH, "marketplace.db");
        assert_eq!(BACKUP_DIR, "./backups");
        assert_eq!(MAX_BACKUPS, 10);
    }
}
