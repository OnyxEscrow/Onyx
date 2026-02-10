#!/bin/bash
# Database Backup Script for Monero Marketplace
# Production-grade backup with rotation, integrity checks, and encryption support

set -euo pipefail

# Configuration
DB_FILE="${DB_FILE:-marketplace.db}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
MAX_BACKUPS="${MAX_BACKUPS:-50}"  # Keep last 50 backups
COMPRESSION="${COMPRESSION:-true}"
ENCRYPT_BACKUP="${ENCRYPT_BACKUP:-false}"
BACKUP_KEY="${BACKUP_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Validation
if [[ ! -f "$DB_FILE" ]]; then
    log_error "Database file not found: $DB_FILE"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate backup filename with timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="marketplace-${TIMESTAMP}"
BACKUP_FILE="${BACKUP_DIR}/${BACKUP_NAME}.db"

log_info "Starting database backup..."
log_info "Source: $DB_FILE"
log_info "Destination: $BACKUP_FILE"

# Check if DB is in use (has WAL files)
if [[ -f "${DB_FILE}-wal" ]] || [[ -f "${DB_FILE}-shm" ]]; then
    log_warn "Database is in use (WAL mode active)"
    log_info "Performing online backup using SQLite checkpoint..."

    # Checkpoint WAL to ensure all data is in main DB file
    sqlite3 "$DB_FILE" "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || {
        log_warn "WAL checkpoint failed, performing hot copy instead"
    }
fi

# Perform the backup
cp "$DB_FILE" "$BACKUP_FILE"

# Verify backup integrity
log_info "Verifying backup integrity..."
if file "$BACKUP_FILE" | grep -q "SQLite"; then
    # Unencrypted DB - can check integrity
    if sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" > /dev/null 2>&1; then
        log_info "✓ Backup integrity check passed"
    else
        log_error "Backup integrity check FAILED"
        rm -f "$BACKUP_FILE"
        exit 1
    fi
else
    # Encrypted DB - just verify it's a valid file
    log_warn "Database appears to be encrypted, skipping SQLite integrity check"
    if [[ -s "$BACKUP_FILE" ]] && [[ $(stat -c%s "$BACKUP_FILE") -gt 1000 ]]; then
        log_info "✓ Backup file created and non-empty (size check passed)"
    else
        log_error "Backup file is too small or empty"
        rm -f "$BACKUP_FILE"
        exit 1
    fi
fi

# Get file sizes
ORIGINAL_SIZE=$(stat -c%s "$DB_FILE" 2>/dev/null || stat -f%z "$DB_FILE")
BACKUP_SIZE=$(stat -c%s "$BACKUP_FILE" 2>/dev/null || stat -f%z "$BACKUP_FILE")

log_info "Original size: $(numfmt --to=iec-i --suffix=B "$ORIGINAL_SIZE" 2>/dev/null || echo "${ORIGINAL_SIZE} bytes")"
log_info "Backup size: $(numfmt --to=iec-i --suffix=B "$BACKUP_SIZE" 2>/dev/null || echo "${BACKUP_SIZE} bytes")"

# Compress backup if enabled
if [[ "$COMPRESSION" == "true" ]]; then
    log_info "Compressing backup..."
    gzip -9 "$BACKUP_FILE"
    BACKUP_FILE="${BACKUP_FILE}.gz"
    COMPRESSED_SIZE=$(stat -c%s "$BACKUP_FILE" 2>/dev/null || stat -f%z "$BACKUP_FILE")
    RATIO=$(awk "BEGIN {printf \"%.1f\", ($ORIGINAL_SIZE - $COMPRESSED_SIZE) / $ORIGINAL_SIZE * 100}")
    log_info "Compressed size: $(numfmt --to=iec-i --suffix=B "$COMPRESSED_SIZE" 2>/dev/null || echo "${COMPRESSED_SIZE} bytes") (${RATIO}% reduction)"
fi

# Encrypt backup if enabled
if [[ "$ENCRYPT_BACKUP" == "true" ]] && [[ -n "$BACKUP_KEY" ]]; then
    log_info "Encrypting backup..."
    openssl enc -aes-256-cbc -salt -pbkdf2 -in "$BACKUP_FILE" -out "${BACKUP_FILE}.enc" -k "$BACKUP_KEY"
    rm -f "$BACKUP_FILE"
    BACKUP_FILE="${BACKUP_FILE}.enc"
    log_info "✓ Backup encrypted with AES-256"
fi

# Create checksum
CHECKSUM=$(sha256sum "$BACKUP_FILE" | cut -d' ' -f1)
echo "$CHECKSUM" > "${BACKUP_FILE}.sha256"
log_info "Checksum: $CHECKSUM"

# Backup rotation - keep only MAX_BACKUPS most recent
log_info "Performing backup rotation (keeping last $MAX_BACKUPS backups)..."
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "marketplace-*.db*" -type f | wc -l)

if [[ $BACKUP_COUNT -gt $MAX_BACKUPS ]]; then
    # Delete oldest backups (excluding .sha256 files in initial count)
    find "$BACKUP_DIR" -name "marketplace-*.db*" -type f ! -name "*.sha256" -printf '%T+ %p\n' | \
        sort | \
        head -n -$MAX_BACKUPS | \
        cut -d' ' -f2- | \
        while read -r old_backup; do
            log_info "Removing old backup: $(basename "$old_backup")"
            rm -f "$old_backup" "${old_backup}.sha256"
        done
fi

# Summary
FINAL_COUNT=$(find "$BACKUP_DIR" -name "marketplace-*.db*" -type f ! -name "*.sha256" | wc -l)
log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_info "✓ Backup completed successfully"
log_info "Backup file: $(basename "$BACKUP_FILE")"
log_info "Total backups: $FINAL_COUNT"
log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Optional: Show backup history
if [[ "${SHOW_HISTORY:-false}" == "true" ]]; then
    log_info ""
    log_info "Backup History:"
    find "$BACKUP_DIR" -name "marketplace-*.db*" -type f ! -name "*.sha256" -printf '%T+ %p\n' | \
        sort -r | \
        head -n 10 | \
        while read -r timestamp filepath; do
            size=$(stat -c%s "$filepath" 2>/dev/null || stat -f%z "$filepath")
            echo "  $(basename "$filepath") - $(numfmt --to=iec-i --suffix=B "$size" 2>/dev/null || echo "$size bytes")"
        done
fi

exit 0
