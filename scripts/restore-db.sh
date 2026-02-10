#!/bin/bash
# Database Restore Script for Monero Marketplace
# Safely restore from backup with verification

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
DB_FILE="${DB_FILE:-marketplace.db}"
BACKUP_KEY="${BACKUP_KEY:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check if backup directory exists
if [[ ! -d "$BACKUP_DIR" ]]; then
    log_error "Backup directory not found: $BACKUP_DIR"
    exit 1
fi

# List available backups
log_info "Available backups:"
echo ""
BACKUPS=($(find "$BACKUP_DIR" -name "marketplace-*.db*" -type f ! -name "*.sha256" -printf '%T+ %p\n' | sort -r | cut -d' ' -f2-))

if [[ ${#BACKUPS[@]} -eq 0 ]]; then
    log_error "No backups found in $BACKUP_DIR"
    exit 1
fi

# Display backups with index
for i in "${!BACKUPS[@]}"; do
    backup="${BACKUPS[$i]}"
    size=$(stat -c%s "$backup" 2>/dev/null || stat -f%z "$backup")
    timestamp=$(stat -c%y "$backup" 2>/dev/null || stat -f%Sm "$backup")
    echo -e "${BLUE}[$i]${NC} $(basename "$backup")"
    echo "    Size: $(numfmt --to=iec-i --suffix=B "$size" 2>/dev/null || echo "$size bytes")"
    echo "    Date: $timestamp"
done

echo ""
read -p "Enter backup number to restore (or 'q' to quit): " selection

if [[ "$selection" == "q" ]] || [[ "$selection" == "Q" ]]; then
    log_info "Restore cancelled"
    exit 0
fi

# Validate selection
if ! [[ "$selection" =~ ^[0-9]+$ ]] || [[ $selection -ge ${#BACKUPS[@]} ]]; then
    log_error "Invalid selection"
    exit 1
fi

SELECTED_BACKUP="${BACKUPS[$selection]}"
log_info "Selected backup: $(basename "$SELECTED_BACKUP")"

# Verify checksum if exists
if [[ -f "${SELECTED_BACKUP}.sha256" ]]; then
    log_info "Verifying backup checksum..."
    EXPECTED_CHECKSUM=$(cat "${SELECTED_BACKUP}.sha256")
    ACTUAL_CHECKSUM=$(sha256sum "$SELECTED_BACKUP" | cut -d' ' -f1)

    if [[ "$EXPECTED_CHECKSUM" == "$ACTUAL_CHECKSUM" ]]; then
        log_info "✓ Checksum verification passed"
    else
        log_error "Checksum mismatch! Backup may be corrupted."
        log_error "Expected: $EXPECTED_CHECKSUM"
        log_error "Actual:   $ACTUAL_CHECKSUM"
        exit 1
    fi
else
    log_warn "No checksum file found, skipping verification"
fi

# Create safety backup of current DB
if [[ -f "$DB_FILE" ]]; then
    SAFETY_BACKUP="${DB_FILE}.pre-restore-$(date +%Y%m%d-%H%M%S)"
    log_warn "Creating safety backup of current database..."
    cp "$DB_FILE" "$SAFETY_BACKUP"
    log_info "Safety backup: $SAFETY_BACKUP"
fi

# Prepare restore file
RESTORE_FILE="$SELECTED_BACKUP"

# Decrypt if encrypted
if [[ "$SELECTED_BACKUP" == *.enc ]]; then
    if [[ -z "$BACKUP_KEY" ]]; then
        read -sp "Enter decryption key: " BACKUP_KEY
        echo ""
    fi
    log_info "Decrypting backup..."
    RESTORE_FILE="${SELECTED_BACKUP%.enc}"
    openssl enc -aes-256-cbc -d -pbkdf2 -in "$SELECTED_BACKUP" -out "$RESTORE_FILE" -k "$BACKUP_KEY" || {
        log_error "Decryption failed"
        exit 1
    }
fi

# Decompress if compressed
if [[ "$RESTORE_FILE" == *.gz ]]; then
    log_info "Decompressing backup..."
    gunzip -k "$RESTORE_FILE"
    RESTORE_FILE="${RESTORE_FILE%.gz}"
fi

# Verify integrity of restored file
log_info "Verifying restored database integrity..."
if sqlite3 "$RESTORE_FILE" "PRAGMA integrity_check;" > /dev/null 2>&1; then
    log_info "✓ Database integrity check passed"
else
    log_error "Restored database failed integrity check"
    rm -f "$RESTORE_FILE"
    exit 1
fi

# Final confirmation
echo ""
log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_warn "WARNING: This will REPLACE the current database"
log_warn "Current DB: $DB_FILE"
log_warn "Restore from: $(basename "$SELECTED_BACKUP")"
log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
read -p "Are you sure? (type 'yes' to confirm): " confirm

if [[ "$confirm" != "yes" ]]; then
    log_info "Restore cancelled"
    # Clean up temp files
    [[ "$RESTORE_FILE" != "$SELECTED_BACKUP" ]] && rm -f "$RESTORE_FILE"
    exit 0
fi

# Stop server if running
if pgrep -f "target/release/server" > /dev/null; then
    log_warn "Stopping server..."
    pkill -9 -f "target/release/server" || true
    sleep 2
fi

# Remove WAL files
rm -f "${DB_FILE}-wal" "${DB_FILE}-shm"

# Perform restore
log_info "Restoring database..."
cp "$RESTORE_FILE" "$DB_FILE"

log_info "✓ Database restored successfully"
log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Clean up temp files
if [[ "$RESTORE_FILE" != "$SELECTED_BACKUP" ]]; then
    rm -f "$RESTORE_FILE"
fi

# Prompt to restart server
echo ""
read -p "Start server now? (y/n): " start_server
if [[ "$start_server" == "y" ]] || [[ "$start_server" == "Y" ]]; then
    log_info "Starting server..."
    ./target/release/server > server.log 2>&1 &
    sleep 2
    log_info "Server started"
fi

exit 0
