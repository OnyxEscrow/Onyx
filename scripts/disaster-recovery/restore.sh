#!/bin/bash
# restore.sh - Disaster recovery restoration
#
# Restores encrypted backup to recover from:
# - Server compromise
# - Database corruption
# - Accidental deletion
# - Hardware failure

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file.tar.gz.gpg>"
    echo ""
    echo "Example:"
    echo "  $0 /var/backups/marketplace/marketplace_backup_20250127_120000.tar.gz.gpg"
    exit 1
fi

BACKUP_FILE="$1"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Monero Marketplace - Disaster Recovery Restore           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo -e "${RED}ERROR: Backup file not found: $BACKUP_FILE${NC}"
    exit 1
fi

echo "Backup file: $BACKUP_FILE"
echo "Size: $(du -h "$BACKUP_FILE" | cut -f1)"
echo ""

# Confirm restore
echo -e "${YELLOW}WARNING: This will OVERWRITE existing data!${NC}"
echo ""
read -p "Are you sure you want to restore? (yes/NO): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1: Decrypt Backup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

if [[ "$BACKUP_FILE" == *.gpg ]]; then
    echo "Decrypting (you may be prompted for GPG passphrase)..."
    gpg --decrypt "$BACKUP_FILE" | tar xzf - -C "$TEMP_DIR"
    echo -e "${GREEN}✓${NC} Backup decrypted"
else
    echo "Extracting unencrypted backup..."
    tar xzf "$BACKUP_FILE" -C "$TEMP_DIR"
    echo -e "${GREEN}✓${NC} Backup extracted"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2: Verify Backup Contents"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "$TEMP_DIR/MANIFEST.txt" ]; then
    echo "Backup Manifest:"
    cat "$TEMP_DIR/MANIFEST.txt"
    echo ""
else
    echo -e "${YELLOW}⚠${NC} No manifest found in backup"
fi

echo "Files in backup:"
ls -lh "$TEMP_DIR/"
echo ""

read -p "Continue with restore? (yes/NO): " CONFIRM2
if [ "$CONFIRM2" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3: Stop Running Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Stopping marketplace server..."
if pgrep -f "target/release/server" > /dev/null; then
    killall -9 server 2>/dev/null || true
    pkill -9 -f "target/release/server" 2>/dev/null || true
    sleep 2
    echo -e "${GREEN}✓${NC} Server stopped"
else
    echo "Server not running"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4: Backup Current State (safety)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SAFETY_BACKUP="/tmp/marketplace_pre_restore_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SAFETY_BACKUP"

if [ -f "marketplace.db" ]; then
    cp marketplace.db "$SAFETY_BACKUP/"
    echo -e "${GREEN}✓${NC} Current database backed up to $SAFETY_BACKUP"
fi

if [ -f ".env" ]; then
    cp .env "$SAFETY_BACKUP/"
    echo -e "${GREEN}✓${NC} Current config backed up"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5: Restore Database"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "$TEMP_DIR/marketplace.db" ]; then
    cp "$TEMP_DIR/marketplace.db" ./marketplace.db
    chmod 600 marketplace.db
    echo -e "${GREEN}✓${NC} Database restored"

    # Verify database integrity
    if sqlite3 marketplace.db "PRAGMA integrity_check;" | grep -q "ok"; then
        echo -e "${GREEN}✓${NC} Database integrity verified"
    else
        echo -e "${RED}✗${NC} Database integrity check FAILED!"
        echo "Restoring from safety backup..."
        cp "$SAFETY_BACKUP/marketplace.db" ./marketplace.db
        exit 1
    fi
else
    echo -e "${YELLOW}⚠${NC} No database in backup - skipping"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 6: Restore Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "$TEMP_DIR/.env" ]; then
    cp "$TEMP_DIR/.env" ./.env
    chmod 600 .env
    echo -e "${GREEN}✓${NC} Configuration restored"
else
    echo -e "${YELLOW}⚠${NC} No .env in backup - skipping"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 7: Restore Encryption Keys"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -d "$TEMP_DIR/keys" ]; then
    mkdir -p ./keys
    cp -r "$TEMP_DIR/keys/"* ./keys/
    chmod 700 ./keys
    chmod 600 ./keys/*
    echo -e "${GREEN}✓${NC} Encryption keys restored"
else
    echo -e "${YELLOW}⚠${NC} No keys/ in backup - skipping"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 8: Restore Wallet Files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

WALLET_RESTORED=0
for wallet_file in wallet wallet.keys monero-wallet-rpc.log; do
    if [ -f "$TEMP_DIR/$wallet_file" ]; then
        cp "$TEMP_DIR/$wallet_file" ./"$wallet_file"
        chmod 600 "$wallet_file"
        WALLET_RESTORED=1
    fi
done

if [ $WALLET_RESTORED -eq 1 ]; then
    echo -e "${GREEN}✓${NC} Wallet files restored"
else
    echo -e "${YELLOW}⚠${NC} No wallet files in backup"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 9: Verify Restore"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Count escrows in database
if [ -f "marketplace.db" ]; then
    ESCROW_COUNT=$(sqlite3 marketplace.db "SELECT COUNT(*) FROM escrows;" 2>/dev/null || echo "N/A")
    echo "Escrows in database: $ESCROW_COUNT"
fi

# Verify schema matches
if cargo build --release --quiet 2>&1 | grep -q "error"; then
    echo -e "${RED}✗${NC} Compilation failed - database schema may be incompatible"
    echo "You may need to run migrations: diesel migration run"
else
    echo -e "${GREEN}✓${NC} Compilation successful"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✓ Restore Complete                                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Safety backup location: $SAFETY_BACKUP"
echo ""
echo "Next steps:"
echo "  1. Verify database: sqlite3 marketplace.db '.tables'"
echo "  2. Run migrations: diesel migration run"
echo "  3. Start server: ./target/release/server"
echo "  4. Test functionality"
echo ""
echo "If restore failed, rollback with:"
echo "  cp $SAFETY_BACKUP/marketplace.db ./marketplace.db"
echo ""
