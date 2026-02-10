#!/bin/bash
# backup.sh - Automated disaster recovery backup
#
# Creates encrypted backups of:
# - Database (marketplace.db)
# - Encryption keys (if present)
# - Configuration (.env)
# - Wallet state
#
# OPSEC: Backups are encrypted with GPG before storage

set -e

BACKUP_DIR="${BACKUP_DIR:-/var/backups/marketplace}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="marketplace_backup_${TIMESTAMP}"
GPG_RECIPIENT="${GPG_RECIPIENT:-admin@marketplace.local}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Monero Marketplace - Disaster Recovery Backup            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
if ! command -v gpg &> /dev/null; then
    echo -e "${RED}ERROR: gpg not found. Install with: sudo apt install gnupg${NC}"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1: Backup Database"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "marketplace.db" ]; then
    # Create SQLite backup (ensures consistency)
    sqlite3 marketplace.db ".backup '$TEMP_DIR/marketplace.db'"
    echo -e "${GREEN}✓${NC} Database backed up ($(du -h marketplace.db | cut -f1))"
else
    echo -e "${YELLOW}⚠${NC} marketplace.db not found - skipping"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2: Backup Encryption Keys"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -d "keys" ]; then
    cp -r keys "$TEMP_DIR/"
    echo -e "${GREEN}✓${NC} Encryption keys backed up"
else
    echo -e "${YELLOW}⚠${NC} keys/ directory not found - skipping"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3: Backup Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f ".env" ]; then
    cp .env "$TEMP_DIR/.env"
    echo -e "${GREEN}✓${NC} Configuration (.env) backed up"
else
    echo -e "${YELLOW}⚠${NC} .env not found - skipping"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4: Backup Wallet State"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Backup Monero wallet files if present
WALLET_FOUND=0
for wallet_file in monero-wallet-rpc.log wallet.keys wallet; do
    if [ -f "$wallet_file" ]; then
        cp "$wallet_file" "$TEMP_DIR/"
        WALLET_FOUND=1
    fi
done

if [ $WALLET_FOUND -eq 1 ]; then
    echo -e "${GREEN}✓${NC} Wallet files backed up"
else
    echo -e "${YELLOW}⚠${NC} No wallet files found - skipping"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5: Create Manifest"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat > "$TEMP_DIR/MANIFEST.txt" <<EOF
Monero Marketplace Backup
Date: $(date)
Hostname: $(hostname)
Backup Name: $BACKUP_NAME

Files Included:
$(find "$TEMP_DIR" -type f -exec basename {} \; | sort)

Checksums (SHA256):
$(cd "$TEMP_DIR" && sha256sum * 2>/dev/null || echo "N/A")

Restore Instructions:
1. Decrypt backup: gpg -d ${BACKUP_NAME}.tar.gz.gpg | tar xzf -
2. Stop server: killall server
3. Restore database: cp marketplace.db /path/to/project/
4. Restore config: cp .env /path/to/project/
5. Restart server: ./target/release/server
EOF

echo -e "${GREEN}✓${NC} Manifest created"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 6: Create Encrypted Archive"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create tar.gz archive
cd "$TEMP_DIR"
tar czf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" .
cd - > /dev/null

# Encrypt with GPG
if gpg --list-keys "$GPG_RECIPIENT" &> /dev/null; then
    gpg --encrypt --recipient "$GPG_RECIPIENT" \
        --output "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" \
        "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

    # Remove unencrypted archive
    rm "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

    BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" | cut -f1)
    echo -e "${GREEN}✓${NC} Encrypted backup created: ${BACKUP_NAME}.tar.gz.gpg (${BACKUP_SIZE})"
else
    echo -e "${YELLOW}⚠${NC} GPG key for '$GPG_RECIPIENT' not found"
    echo "   Backup created WITHOUT encryption: ${BACKUP_NAME}.tar.gz"
    echo "   To encrypt: gpg --encrypt --recipient <key> ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 7: Verify Backup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test decryption (if encrypted)
if [ -f "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" ]; then
    if gpg --decrypt "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Backup decryption verified"
    else
        echo -e "${RED}✗${NC} Backup decryption FAILED - backup may be corrupted!"
        exit 1
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 8: Cleanup Old Backups"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Keep only last 7 backups
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "marketplace_backup_*.tar.gz.gpg" | wc -l)
if [ "$BACKUP_COUNT" -gt 7 ]; then
    echo "Found $BACKUP_COUNT backups, keeping last 7..."
    find "$BACKUP_DIR" -name "marketplace_backup_*.tar.gz.gpg" -type f | \
        sort | head -n -7 | xargs rm -f
    echo -e "${GREEN}✓${NC} Cleaned up old backups"
else
    echo "Found $BACKUP_COUNT backups (retention: 7)"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✓ Backup Complete                                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Backup Location: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg"
echo ""
echo "To restore:"
echo "  ./scripts/disaster-recovery/restore.sh ${BACKUP_NAME}.tar.gz.gpg"
echo ""
echo "To test restore:"
echo "  ./scripts/disaster-recovery/test-restore.sh ${BACKUP_NAME}.tar.gz.gpg"
echo ""
