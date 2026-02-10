#!/bin/bash
# =============================================================================
# NEXUS Atomic Database Backup Script
# =============================================================================
# Purpose: Create atomic SQLite backups with encryption and verification
# Usage: ./backup-db-atomic.sh [database_path] [backup_dir] [encryption_key]
# =============================================================================

set -euo pipefail

# Configuration
DB_PATH="${1:-marketplace.db}"
BACKUP_DIR="${2:-./backups}"
ENCRYPTION_KEY="${3:?ERROR: Encryption key required as third argument}"
RETENTION_DAYS="${4:-30}"

# Create backup directory first
mkdir -p "$BACKUP_DIR"

# Logging
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ℹ️  $*" | tee -a "${BACKUP_DIR}/backup.log"
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ $*" | tee -a "${BACKUP_DIR}/backup.log"
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  $*" | tee -a "${BACKUP_DIR}/backup.log"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ $*" | tee -a "${BACKUP_DIR}/backup.log" >&2
}

# =============================================================================
# Step 1: Validate environment
# =============================================================================

log_info "Validating environment..."

if [ ! -f "$DB_PATH" ]; then
    log_warn "Database file not found: $DB_PATH (OK for new installations)"
    exit 0
fi

if ! command -v sqlite3 &> /dev/null; then
    log_error "sqlite3 is not installed. Please install sqlite3."
    exit 1
fi

if ! command -v gpg &> /dev/null; then
    log_warn "GPG not found. Backup will be unencrypted."
    ENCRYPT=false
else
    ENCRYPT=true
fi

log_success "Backup directory ready: $BACKUP_DIR"

# =============================================================================
# Step 2: Create atomic snapshot
# =============================================================================

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEMP_BACKUP="${BACKUP_DIR}/.nexus_backup_temp_${TIMESTAMP}.db"
SNAPSHOT_PATH="${BACKUP_DIR}/nexus_snapshot_${TIMESTAMP}.db"

log_info "Creating atomic snapshot..."

# Use sqlite3 .backup command for atomic snapshot
# This ensures database consistency even if writes are happening
if ! sqlite3 "$DB_PATH" ".backup '${TEMP_BACKUP}'" 2>/dev/null; then
    log_error "Failed to create backup snapshot"
    rm -f "$TEMP_BACKUP"
    exit 1
fi

# Rename temp to final (atomic operation)
if ! mv "$TEMP_BACKUP" "$SNAPSHOT_PATH" 2>/dev/null; then
    log_error "Failed to finalize snapshot"
    rm -f "$TEMP_BACKUP"
    exit 1
fi

SIZE=$(du -h "$SNAPSHOT_PATH" | cut -f1)
log_success "Atomic snapshot created: ${SIZE}"

# =============================================================================
# Step 3: Verify snapshot integrity
# =============================================================================

log_info "Verifying snapshot integrity..."

INTEGRITY_RESULT=$(sqlite3 "$SNAPSHOT_PATH" "PRAGMA integrity_check;" 2>&1)

if [[ ! "$INTEGRITY_RESULT" =~ "ok" ]]; then
    log_error "Snapshot integrity check failed: $INTEGRITY_RESULT"
    rm -f "$SNAPSHOT_PATH"
    exit 1
fi

log_success "Snapshot integrity verified"

# =============================================================================
# Step 4: Encrypt snapshot (optional)
# =============================================================================

FINAL_BACKUP="$SNAPSHOT_PATH"

if [ "$ENCRYPT" = true ]; then
    log_info "Encrypting snapshot with GPG..."

    ENCRYPTED_PATH="${SNAPSHOT_PATH}.gpg"

    if gpg --symmetric --cipher-algo AES256 \
        --passphrase "$ENCRYPTION_KEY" \
        --batch --quiet \
        "$SNAPSHOT_PATH" \
        -o "$ENCRYPTED_PATH" 2>/dev/null; then

        rm -f "$SNAPSHOT_PATH"
        FINAL_BACKUP="$ENCRYPTED_PATH"

        # Verify encrypted backup can be decrypted
        if ! gpg --decrypt --batch --quiet \
            --passphrase "$ENCRYPTION_KEY" \
            "$ENCRYPTED_PATH" 2>/dev/null | \
            sqlite3 -readonly "" "SELECT 1;" > /dev/null 2>&1; then
            log_error "Encrypted backup verification failed"
            rm -f "$ENCRYPTED_PATH"
            exit 1
        fi

        SIZE=$(du -h "$ENCRYPTED_PATH" | cut -f1)
        log_success "Backup encrypted: ${SIZE}"
    else
        log_warn "GPG encryption failed, keeping unencrypted backup"
    fi
fi

# =============================================================================
# Step 5: Rotate old backups
# =============================================================================

log_info "Rotating old backups (keeping ${RETENTION_DAYS} days)..."

CUTOFF_DATE=$(date -d "${RETENTION_DAYS} days ago" +%Y%m%d 2>/dev/null || \
              date -v-${RETENTION_DAYS}d +%Y%m%d 2>/dev/null)

CLEANED_COUNT=0
FREED_SPACE=0

for backup in "${BACKUP_DIR}"/nexus_snapshot_*.db*; do
    if [ -f "$backup" ]; then
        BACKUP_DATE=$(basename "$backup" | sed 's/nexus_snapshot_\([0-9]*\).*/\1/')

        if [ "$BACKUP_DATE" -lt "$CUTOFF_DATE" ] 2>/dev/null; then
            SIZE=$(stat -f%z "$backup" 2>/dev/null || stat -c%s "$backup" 2>/dev/null || echo 0)
            rm -f "$backup"
            CLEANED_COUNT=$((CLEANED_COUNT + 1))
            FREED_SPACE=$((FREED_SPACE + SIZE))
        fi
    fi
done

if [ $CLEANED_COUNT -gt 0 ]; then
    FREED_MB=$((FREED_SPACE / (1024 * 1024)))
    log_success "Cleaned $CLEANED_COUNT old backups, freed ${FREED_MB}MB"
fi

# =============================================================================
# Step 6: Report statistics
# =============================================================================

BACKUP_COUNT=$(ls -1 "${BACKUP_DIR}"/nexus_snapshot_*.db* 2>/dev/null | wc -l)
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)

log_success "Backup complete"
log_info "Location: $FINAL_BACKUP"
log_info "Backups in directory: $BACKUP_COUNT"
log_info "Total backup storage: $TOTAL_SIZE"

# =============================================================================
# Exit
# =============================================================================

exit 0
