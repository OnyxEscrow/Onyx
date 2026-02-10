#!/bin/bash
# Recreate encrypted database from schema.rs

set -e

cd /home/malix/Desktop/NEXUS

# Load encryption key from .env
if [ -f .env ]; then
    export $(grep -E "^DB_ENCRYPTION_KEY=" .env | xargs)
fi

if [ -z "$DB_ENCRYPTION_KEY" ]; then
    echo "ERROR: DB_ENCRYPTION_KEY not found in .env"
    exit 1
fi

echo "=== Step 1: Backup old database ==="
BACKUP_NAME="marketplace.db.backup.$(date +%Y%m%d%H%M%S)"
if [ -f marketplace.db ]; then
    cp marketplace.db "$BACKUP_NAME"
    echo "Backed up to: $BACKUP_NAME"
fi

echo "=== Step 2: Create plain text database ==="
rm -f marketplace.db.plain
sqlite3 marketplace.db.plain < scripts/create_db_plain.sql
echo "Plain text database created"

echo "=== Step 3: Verify plain text database ==="
echo "Tables in plain DB:"
sqlite3 marketplace.db.plain "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
echo ""
echo "Escrow columns count:"
sqlite3 marketplace.db.plain "PRAGMA table_info(escrows);" | wc -l
echo ""
echo "Checking funding_output_pubkey exists:"
sqlite3 marketplace.db.plain "PRAGMA table_info(escrows);" | grep -i funding_output_pubkey || echo "NOT FOUND!"

echo "=== Step 4: Encrypt with SQLCipher ==="
rm -f marketplace.db.new

# Use sqlcipher to encrypt
sqlcipher marketplace.db.plain <<EOF
ATTACH DATABASE 'marketplace.db.new' AS encrypted KEY 'x''${DB_ENCRYPTION_KEY}''';
SELECT sqlcipher_export('encrypted');
DETACH DATABASE encrypted;
EOF

echo "Encrypted database created"

echo "=== Step 5: Verify encrypted database ==="
sqlcipher marketplace.db.new <<EOF
PRAGMA key = 'x''${DB_ENCRYPTION_KEY}''';
SELECT count(*) FROM sqlite_master WHERE type='table';
PRAGMA table_info(escrows);
EOF

echo "=== Step 6: Replace old database ==="
rm -f marketplace.db
mv marketplace.db.new marketplace.db
rm -f marketplace.db.plain

echo "=== DONE ==="
echo "New encrypted database: marketplace.db"
echo "Backup of old database: $BACKUP_NAME"
echo ""
echo "Verify with:"
echo "  sqlcipher marketplace.db \"PRAGMA key = 'x''${DB_ENCRYPTION_KEY}'''; PRAGMA table_info(escrows);\" | grep funding_output_pubkey"
