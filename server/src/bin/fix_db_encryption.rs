//! Database Encryption Fix Tool
//!
//! Detects unencrypted databases and encrypts them in-place using SQLCipher.
//! This tool is idempotent - running it multiple times is safe.

use anyhow::{bail, Context, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const DB_PATH: &str = "marketplace.db";

fn main() -> Result<()> {
    println!("🔐 Database Encryption Fix Tool");
    println!("================================\n");

    // Load encryption key from environment
    dotenvy::dotenv().ok();
    let encryption_key = env::var("DB_ENCRYPTION_KEY")
        .context("DB_ENCRYPTION_KEY not set in environment or .env file")?;

    let db_path = PathBuf::from(DB_PATH);

    if !db_path.exists() {
        bail!("Database file not found: {DB_PATH}");
    }

    println!("📁 Database: {}", db_path.display());
    println!("🔍 Checking encryption status...\n");

    // Check if database is already encrypted
    match check_encryption_status(&db_path, &encryption_key)? {
        EncryptionStatus::AlreadyEncrypted => {
            println!("✅ Database is already encrypted with SQLCipher");
            println!("✅ No action needed");
            return Ok(());
        }
        EncryptionStatus::Unencrypted => {
            println!("⚠️  Database is UNENCRYPTED");
            println!("🔧 Starting encryption process...\n");
            encrypt_database(&db_path, &encryption_key)?;
            println!("\n✅ Database successfully encrypted!");
        }
        EncryptionStatus::WrongKey => {
            bail!("Database appears encrypted but key doesn't match. Check DB_ENCRYPTION_KEY.");
        }
    }

    // Verify the encrypted database
    println!("\n🔍 Verifying encrypted database...");
    verify_encrypted_database(&db_path, &encryption_key)?;
    println!("✅ Verification complete - database is healthy\n");

    Ok(())
}

#[derive(Debug)]
enum EncryptionStatus {
    AlreadyEncrypted,
    Unencrypted,
    WrongKey,
}

fn check_encryption_status(db_path: &Path, key: &str) -> Result<EncryptionStatus> {
    // Try to open with encryption key
    let encrypted_test = Command::new("sqlcipher")
        .arg(db_path)
        .arg(format!(
            "PRAGMA key = '{key}'; SELECT COUNT(*) FROM sqlite_master;"
        ))
        .output()
        .context("Failed to run sqlcipher (is it installed?)")?;

    if encrypted_test.status.success() {
        let output = String::from_utf8_lossy(&encrypted_test.stdout);
        if output.trim().chars().all(|c| c.is_numeric()) {
            return Ok(EncryptionStatus::AlreadyEncrypted);
        }
    }

    // Try to open without encryption key
    let unencrypted_test = Command::new("sqlite3")
        .arg(db_path)
        .arg("SELECT COUNT(*) FROM sqlite_master;")
        .output()
        .context("Failed to run sqlite3")?;

    if unencrypted_test.status.success() {
        let output = String::from_utf8_lossy(&unencrypted_test.stdout);
        if output.trim().chars().all(|c| c.is_numeric()) {
            return Ok(EncryptionStatus::Unencrypted);
        }
    }

    Ok(EncryptionStatus::WrongKey)
}

fn encrypt_database(db_path: &Path, key: &str) -> Result<()> {
    let temp_encrypted = db_path.with_extension("encrypted.tmp");

    println!("1️⃣ Creating encrypted copy at {}", temp_encrypted.display());

    // Method: Use init_db binary which already handles encryption correctly
    // This is safer and reuses existing tested code

    // First, rename current DB to temp location
    let temp_unencrypted = db_path.with_extension("unencrypted.tmp");
    std::fs::rename(db_path, &temp_unencrypted).context("Failed to move unencrypted database")?;

    // Run init_db to create encrypted database
    let output = Command::new("./target/release/init_db").output().context(
        "Failed to run init_db. Make sure it's built with: cargo build --release --bin init_db",
    )?;

    if !output.status.success() {
        // Restore original if failed
        std::fs::rename(&temp_unencrypted, db_path).ok();
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("init_db failed: {stderr}");
    }

    // Now we have an empty encrypted DB at db_path
    // Import data from unencrypted backup using sqlcipher
    println!("   Importing data from unencrypted database...");

    let import_sql = format!(
        "PRAGMA key = '{}';\n\
         ATTACH DATABASE '{}' AS plaintext KEY '';\n\
         SELECT name FROM plaintext.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__diesel%';",
        key,
        temp_unencrypted.display()
    );

    // Get list of tables
    let table_output = Command::new("sqlcipher")
        .arg(db_path)
        .arg(&import_sql)
        .output()
        .context("Failed to list tables")?;

    if !table_output.status.success() {
        let stderr = String::from_utf8_lossy(&table_output.stderr);
        bail!("Failed to list tables: {stderr}");
    }

    let tables = String::from_utf8_lossy(&table_output.stdout);

    // Copy each table
    for table in tables.lines().filter(|l| !l.is_empty()) {
        let copy_sql = format!(
            "PRAGMA key = '{}';\n\
             ATTACH DATABASE '{}' AS plaintext KEY '';\n\
             INSERT INTO main.{} SELECT * FROM plaintext.{};\n\
             DETACH DATABASE plaintext;",
            key,
            temp_unencrypted.display(),
            table,
            table
        );

        let output = Command::new("sqlcipher")
            .arg(db_path)
            .arg(&copy_sql)
            .output()
            .context(format!("Failed to copy table {table}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to copy table {table}: {stderr}");
        }
        println!("   ✓ Copied table: {table}");
    }

    println!("2️⃣ Verifying encrypted copy...");
    verify_encrypted_database(&temp_encrypted, key)?;

    println!("3️⃣ Backing up original database...");
    let backup_path = db_path.with_extension(format!("backup.{}", chrono::Utc::now().timestamp()));
    std::fs::copy(db_path, &backup_path).context("Failed to backup original database")?;
    println!("   Backup saved to: {}", backup_path.display());

    println!("4️⃣ Replacing database with encrypted version...");
    std::fs::rename(&temp_encrypted, db_path)
        .context("Failed to replace database with encrypted version")?;

    // Clean up WAL/SHM files
    let wal_path = db_path.with_extension("db-wal");
    let shm_path = db_path.with_extension("db-shm");
    let _ = std::fs::remove_file(wal_path);
    let _ = std::fs::remove_file(shm_path);

    Ok(())
}

fn verify_encrypted_database(db_path: &Path, key: &str) -> Result<()> {
    // Run integrity check
    let integrity_sql = format!("PRAGMA key = '{key}'; PRAGMA integrity_check;");

    let output = Command::new("sqlcipher")
        .arg(db_path)
        .arg(&integrity_sql)
        .output()
        .context("Failed to verify database integrity")?;

    let result = String::from_utf8_lossy(&output.stdout);

    if !result.contains("ok") {
        bail!("Integrity check failed: {result}");
    }

    // Count tables
    let count_sql =
        format!("PRAGMA key = '{key}'; SELECT COUNT(*) FROM sqlite_master WHERE type='table';");

    let output = Command::new("sqlcipher")
        .arg(db_path)
        .arg(&count_sql)
        .output()
        .context("Failed to count tables")?;

    let count = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("   Tables found: {count}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_status_enum() {
        // Ensure enum variants exist
        let _encrypted = EncryptionStatus::AlreadyEncrypted;
        let _unencrypted = EncryptionStatus::Unencrypted;
        let _wrong = EncryptionStatus::WrongKey;
    }
}
