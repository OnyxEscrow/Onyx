//! Migration utility for adding secure messaging tables
//!
//! This utility applies the secure messaging migration to an encrypted SQLCipher database.

use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::Text;
use dotenvy::dotenv;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    println!("🔐 Secure Messaging Migration Tool");
    println!("===================================\n");

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "marketplace.db".to_string());
    let encryption_key = env::var("DATABASE_ENCRYPTION_KEY")
        .expect("DATABASE_ENCRYPTION_KEY must be set in .env");

    println!("📁 Database: {}", database_url);

    // Create connection pool with SQLCipher
    let pool = server::db::create_pool(&database_url, &encryption_key)?;
    let mut conn = pool.get()?;

    // Check if secure_messages table already exists
    let tables: Vec<TableName> = sql_query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='secure_messages'"
    )
    .load(&mut conn)?;

    if !tables.is_empty() {
        println!("⚠️  secure_messages table already exists! Migration was already applied.");
        println!("   Nothing to do.");
        return Ok(());
    }

    println!("📝 Tables do not exist - proceeding with migration...\n");

    // Create message_keypairs table
    println!("🔨 Step 1/3: Creating message_keypairs table...");
    sql_query(
        "CREATE TABLE message_keypairs (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            key_salt TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )"
    )
    .execute(&mut conn)?;

    sql_query("CREATE UNIQUE INDEX idx_message_keypairs_user_active ON message_keypairs(user_id, is_active) WHERE is_active = 1")
        .execute(&mut conn)?;
    sql_query("CREATE INDEX idx_message_keypairs_user ON message_keypairs(user_id)")
        .execute(&mut conn)?;
    println!("   ✅ message_keypairs table created");

    // Create secure_messages table
    println!("🔨 Step 2/3: Creating secure_messages table...");
    sql_query(
        "CREATE TABLE secure_messages (
            id TEXT PRIMARY KEY NOT NULL,
            conversation_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            nonce TEXT NOT NULL,
            sender_ephemeral_pubkey TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            is_deleted_by_sender INTEGER NOT NULL DEFAULT 0,
            is_deleted_by_recipient INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
        )"
    )
    .execute(&mut conn)?;

    sql_query("CREATE INDEX idx_secure_messages_conversation ON secure_messages(conversation_id, created_at DESC)")
        .execute(&mut conn)?;
    sql_query("CREATE INDEX idx_secure_messages_recipient ON secure_messages(recipient_id, created_at DESC)")
        .execute(&mut conn)?;
    sql_query("CREATE INDEX idx_secure_messages_sender ON secure_messages(sender_id, created_at DESC)")
        .execute(&mut conn)?;
    sql_query("CREATE INDEX idx_secure_messages_expires ON secure_messages(expires_at) WHERE expires_at IS NOT NULL")
        .execute(&mut conn)?;
    println!("   ✅ secure_messages table created");

    // Create message_read_receipts table
    println!("🔨 Step 3/3: Creating message_read_receipts table...");
    sql_query(
        "CREATE TABLE message_read_receipts (
            message_id TEXT PRIMARY KEY NOT NULL,
            read_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (message_id) REFERENCES secure_messages(id) ON DELETE CASCADE
        )"
    )
    .execute(&mut conn)?;
    println!("   ✅ message_read_receipts table created");

    println!("\n✅ Secure messaging migration completed successfully!");
    println!("🎉 Tables created: message_keypairs, secure_messages, message_read_receipts\n");

    Ok(())
}

#[derive(QueryableByName)]
struct TableName {
    #[diesel(sql_type = Text)]
    #[allow(dead_code)]
    name: String,
}
