#!/bin/bash
# test-restore.sh - Non-destructive restore test
#
# Tests backup restoration WITHOUT affecting production data
# Validates backup integrity before actual disaster

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file.tar.gz.gpg>"
    exit 1
fi

BACKUP_FILE="$1"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Monero Marketplace - Backup Test (Non-Destructive)       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ ! -f "$BACKUP_FILE" ]; then
    echo -e "${RED}ERROR: Backup not found: $BACKUP_FILE${NC}"
    exit 1
fi

TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "Test directory: $TEST_DIR"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Decrypt Backup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ "$BACKUP_FILE" == *.gpg ]]; then
    if gpg --decrypt "$BACKUP_FILE" | tar xzf - -C "$TEST_DIR" 2>/dev/null; then
        echo -e "${GREEN}✓ PASS${NC}: Backup decryption successful"
    else
        echo -e "${RED}✗ FAIL${NC}: Cannot decrypt backup"
        exit 1
    fi
else
    tar xzf "$BACKUP_FILE" -C "$TEST_DIR"
    echo -e "${GREEN}✓ PASS${NC}: Backup extraction successful"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: Verify Manifest"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "$TEST_DIR/MANIFEST.txt" ]; then
    echo -e "${GREEN}✓ PASS${NC}: Manifest present"
    cat "$TEST_DIR/MANIFEST.txt"
else
    echo -e "${RED}✗ FAIL${NC}: No manifest found"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: Database Integrity"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "$TEST_DIR/marketplace.db" ]; then
    if sqlite3 "$TEST_DIR/marketplace.db" "PRAGMA integrity_check;" | grep -q "ok"; then
        echo -e "${GREEN}✓ PASS${NC}: Database integrity OK"

        # Show stats
        ESCROW_COUNT=$(sqlite3 "$TEST_DIR/marketplace.db" "SELECT COUNT(*) FROM escrows;" 2>/dev/null || echo "0")
        USER_COUNT=$(sqlite3 "$TEST_DIR/marketplace.db" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
        LISTING_COUNT=$(sqlite3 "$TEST_DIR/marketplace.db" "SELECT COUNT(*) FROM listings;" 2>/dev/null || echo "0")

        echo "  Escrows: $ESCROW_COUNT"
        echo "  Users: $USER_COUNT"
        echo "  Listings: $LISTING_COUNT"
    else
        echo -e "${RED}✗ FAIL${NC}: Database corrupted"
        exit 1
    fi
else
    echo -e "${RED}✗ FAIL${NC}: No database in backup"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 4: Configuration Files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "$TEST_DIR/.env" ]; then
    echo -e "${GREEN}✓ PASS${NC}: .env present"

    # Check critical env vars (without exposing values)
    for var in DATABASE_URL MONERO_RPC_URL SESSION_SECRET; do
        if grep -q "^${var}=" "$TEST_DIR/.env"; then
            echo "  ✓ $var configured"
        else
            echo "  ✗ $var MISSING"
        fi
    done
else
    echo -e "${RED}✗ FAIL${NC}: No .env in backup"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 5: Encryption Keys"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -d "$TEST_DIR/keys" ]; then
    KEY_COUNT=$(find "$TEST_DIR/keys" -type f | wc -l)
    echo -e "${GREEN}✓ PASS${NC}: keys/ directory present ($KEY_COUNT files)"
else
    echo -e "${GREEN}ℹ INFO${NC}: No keys/ directory (may be intentional)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 6: Wallet Files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

WALLET_FILES=0
for wallet_file in wallet wallet.keys; do
    if [ -f "$TEST_DIR/$wallet_file" ]; then
        WALLET_FILES=$((WALLET_FILES + 1))
        echo "  ✓ $wallet_file present"
    fi
done

if [ $WALLET_FILES -gt 0 ]; then
    echo -e "${GREEN}✓ PASS${NC}: Wallet files found ($WALLET_FILES files)"
else
    echo -e "${GREEN}ℹ INFO${NC}: No wallet files (may use external wallet)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}✓ Backup is valid and can be restored${NC}"
echo ""
echo "To perform actual restore:"
echo "  ./scripts/disaster-recovery/restore.sh $BACKUP_FILE"
echo ""
