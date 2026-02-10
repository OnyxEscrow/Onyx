//! Database Restore Tool
//!
//! Safely restores database from backup with verification.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::env;
use std::fs;
use std::io::{self, Write};

const DB_PATH: &str = "marketplace.db";
const BACKUP_DIR: &str = "./backups";

fn main() -> Result<()> {
    println!("♻️  Database Restore Tool");
    println!("========================\n");

    // Load encryption key
    dotenvy::dotenv().ok();
    let encryption_key = env::var("DB_ENCRYPTION_KEY")
        .context("DB_ENCRYPTION_KEY not set")?;

    let backup_dir = PathBuf::from(BACKUP_DIR);
    if !backup_dir.exists() {
        bail!("Backup directory not found: {}", BACKUP_DIR);
    }

    // List available backups
    let backups = list_backups(&backup_dir)?;
    if backups.is_empty() {
        bail!("No backups found in {}", BACKUP_DIR);
    }

    println!("📋 Available backups:\n");
    for (idx, (path, size, modified)) in backups.iter().enumerate() {
        println!(
            "{}. {} ({} bytes, {})",
            idx + 1,
            path.file_name().unwrap().to_string_lossy(),
            size,
            modified.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    // Get user selection
    print!("\nSelect backup to restore (1-{}): ", backups.len());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let selection: usize = input.trim().parse()
        .context("Invalid selection")?;

    if selection == 0 || selection > backups.len() {
        bail!("Selection out of range");
    }

    let (backup_path, _, _) = &backups[selection - 1];

    // Verify backup before restore
    println!("\n🔍 Verifying backup integrity...");
    verify_backup(backup_path, &encryption_key)?;
    println!("   ✅ Backup is valid");

    // Warn user
    println!("\n⚠️  WARNING: This will replace the current database!");
    print!("Continue? (yes/no): ");
    io::stdout().flush()?;

    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;

    if confirm.trim().to_lowercase() != "yes" {
        println!("Restore cancelled");
        return Ok(());
    }

    // Check if server is running
    if is_server_running() {
        println!("\n⚠️  Server is still running!");
        println!("Please stop the server before restoring:");
        println!("   pkill -9 -f 'target/release/server'");
        bail!("Server must be stopped before restore");
    }

    // Perform restore
    println!("\n🔄 Restoring database...");
    restore_database(backup_path, &encryption_key)?;

    println!("\n✅ Database restored successfully!");
    println!("You can now start the server.");

    Ok(())
}

fn list_backups(backup_dir: &Path) -> Result<Vec<(PathBuf, u64, chrono::DateTime<chrono::Utc>)>> {
    let mut backups: Vec<_> = fs::read_dir(backup_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().map(|ext| ext == "db").unwrap_or(false) {
                let metadata = entry.metadata().ok()?;
                let size = metadata.len();
                let modified = metadata.modified().ok()?;
                let datetime: chrono::DateTime<chrono::Utc> = modified.into();
                Some((path, size, datetime))
            } else {
                None
            }
        })
        .collect();

    // Sort by modification time (newest first)
    backups.sort_by(|a, b| b.2.cmp(&a.2));

    Ok(backups)
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

fn is_server_running() -> bool {
    Command::new("pgrep")
        .arg("-f")
        .arg("target/release/server")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn restore_database(backup_path: &Path, key: &str) -> Result<()> {
    let db_path = PathBuf::from(DB_PATH);

    // Backup current database
    if db_path.exists() {
        let backup_current = db_path.with_extension(
            format!("pre_restore.{}.backup", chrono::Utc::now().timestamp())
        );
        println!("1️⃣ Backing up current database to {}", backup_current.display());
        fs::copy(&db_path, &backup_current)
            .context("Failed to backup current database")?;
    }

    // Copy backup to main location
    println!("2️⃣ Copying backup to {}", db_path.display());
    fs::copy(backup_path, &db_path)
        .context("Failed to copy backup")?;

    // Clean WAL/SHM files
    println!("3️⃣ Cleaning WAL/SHM files...");
    let wal_path = db_path.with_extension("db-wal");
    let shm_path = db_path.with_extension("db-shm");
    let _ = fs::remove_file(wal_path);
    let _ = fs::remove_file(shm_path);

    // Verify restored database
    println!("4️⃣ Verifying restored database...");
    verify_backup(&db_path, key)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DB_PATH, "marketplace.db");
        assert_eq!(BACKUP_DIR, "./backups");
    }
}
