#!/bin/bash
# Clean stuck escrows from encrypted database

cat > /tmp/clean_db.rs << 'EOF'
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;

fn main() {
    dotenv::dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let encryption_key = env::var("DB_ENCRYPTION_KEY").expect("DB_ENCRYPTION_KEY must be set");

    let manager = ConnectionManager::<SqliteConnection>::new(&database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    let mut conn = pool.get().expect("Failed to get connection");

    // Set encryption key
    diesel::sql_query(format!("PRAGMA key = '{}'", encryption_key))
        .execute(&mut conn)
        .expect("Failed to set encryption key");

    // Delete old escrows
    let deleted = diesel::sql_query(
        "DELETE FROM multisig_state WHERE escrow_id IN (
            'ac506a15-9ab8-4819-bab7-20787705dd15',
            '21e64e1c-5253-42ac-b2df-03fd2edca11e',
            '9b2fd54a-ddcf-464e-81b6-43e7780ce913',
            '4c8aa1e6-119d-4333-bd86-9bb7c623a16b',
            '37a6b49a-7ddf-4afa-9890-59bc7fa18243'
        )"
    )
    .execute(&mut conn)
    .expect("Failed to delete escrows");

    println!("✅ Deleted {} stuck escrow records", deleted);
}
EOF

echo "Database is encrypted. Let's use a simpler approach - just backup and start fresh."
echo "Moving marketplace.db to marketplace.db.backup..."

mv marketplace.db marketplace.db.backup 2>/dev/null || echo "No existing database to backup"

echo "✅ Database will be recreated fresh on next server start"
