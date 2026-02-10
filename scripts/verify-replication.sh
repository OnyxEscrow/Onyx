#!/bin/bash
# =============================================================================
# NEXUS Replication Verification Script
# =============================================================================
# Purpose: Verify that backups are healthy and replicated correctly
# Usage: ./verify-replication.sh [local_backup_dir] [remote_host] [remote_dir]
# =============================================================================

set -euo pipefail

# Configuration
LOCAL_BACKUP_DIR="${1:-./ backups}"
REMOTE_HOST="${2:-}"
REMOTE_DIR="${3:-}"

# Thresholds
MAX_BACKUP_AGE_MINUTES=15
MIN_BACKUP_SIZE_KB=100

# Logging
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ℹ️  $*"
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ $*"
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ $*" >&2
}

# =============================================================================
# Step 1: Check local backups
# =============================================================================

log_info "Checking local backups..."

if [ ! -d "$LOCAL_BACKUP_DIR" ]; then
    log_error "Backup directory not found: $LOCAL_BACKUP_DIR"
    exit 1
fi

# Find most recent backup
LATEST_BACKUP=$(ls -1t "${LOCAL_BACKUP_DIR}"/nexus_snapshot_*.db* 2>/dev/null | head -1)

if [ -z "$LATEST_BACKUP" ]; then
    log_error "No backups found in $LOCAL_BACKUP_DIR"
    exit 1
fi

log_success "Latest backup: $(basename "$LATEST_BACKUP")"

# =============================================================================
# Step 2: Check backup age
# =============================================================================

log_info "Checking backup age..."

# Get modification time
if [ "$(uname)" = "Darwin" ]; then
    # macOS
    BACKUP_MTIME=$(stat -f%m "$LATEST_BACKUP")
    NOW_MTIME=$(date +%s)
else
    # Linux
    BACKUP_MTIME=$(stat -c%Y "$LATEST_BACKUP")
    NOW_MTIME=$(date +%s)
fi

BACKUP_AGE_SECONDS=$((NOW_MTIME - BACKUP_MTIME))
BACKUP_AGE_MINUTES=$((BACKUP_AGE_SECONDS / 60))

log_info "Backup age: ${BACKUP_AGE_MINUTES} minutes"

if [ "$BACKUP_AGE_MINUTES" -gt "$MAX_BACKUP_AGE_MINUTES" ]; then
    log_warn "Backup is older than ${MAX_BACKUP_AGE_MINUTES} minutes!"
    exit 1
fi

log_success "Backup is fresh (< ${MAX_BACKUP_AGE_MINUTES} min)"

# =============================================================================
# Step 3: Check backup size
# =============================================================================

log_info "Checking backup size..."

if [ "$(uname)" = "Darwin" ]; then
    BACKUP_SIZE_KB=$(du -k "$LATEST_BACKUP" | cut -f1)
else
    BACKUP_SIZE_KB=$(du -k "$LATEST_BACKUP" | cut -f1)
fi

log_info "Backup size: ${BACKUP_SIZE_KB}KB"

if [ "$BACKUP_SIZE_KB" -lt "$MIN_BACKUP_SIZE_KB" ]; then
    log_warn "Backup is suspiciously small (${BACKUP_SIZE_KB}KB < ${MIN_BACKUP_SIZE_KB}KB)"
    exit 1
fi

log_success "Backup size looks reasonable"

# =============================================================================
# Step 4: Verify backup integrity (if not encrypted)
# =============================================================================

log_info "Verifying backup integrity..."

# Check if backup is encrypted (.gpg)
if [[ "$LATEST_BACKUP" == *.gpg ]]; then
    log_info "Backup is encrypted, skipping direct integrity check"
else
    # SQLite integrity check
    if ! sqlite3 "$LATEST_BACKUP" "PRAGMA integrity_check;" 2>/dev/null | grep -q "ok"; then
        log_error "Backup integrity check failed!"
        exit 1
    fi
    log_success "Backup integrity verified"
fi

# =============================================================================
# Step 5: Check remote replication (if configured)
# =============================================================================

if [ -z "$REMOTE_HOST" ] || [ -z "$REMOTE_DIR" ]; then
    log_info "No remote host configured, skipping remote checks"
    log_success "Local backup verification complete"
    exit 0
fi

log_info "Checking remote replication..."

# Check SSH connectivity
if ! ssh -o ConnectTimeout=5 "$REMOTE_HOST" "test -d '$REMOTE_DIR'" 2>/dev/null; then
    log_warn "Cannot connect to remote host: $REMOTE_HOST"
    exit 1
fi

log_success "Remote host reachable"

# =============================================================================
# Step 6: Compare local and remote
# =============================================================================

log_info "Comparing local and remote backups..."

REMOTE_LATEST=$(ssh "$REMOTE_HOST" "ls -1t '${REMOTE_DIR}'/nexus_snapshot_*.db* 2>/dev/null | head -1" || echo "")

if [ -z "$REMOTE_LATEST" ]; then
    log_warn "No backups found on remote host"
    exit 1
fi

LATEST_LOCAL=$(basename "$LATEST_BACKUP")
LATEST_REMOTE=$(basename "$REMOTE_LATEST")

log_info "Local:  $LATEST_LOCAL"
log_info "Remote: $LATEST_REMOTE"

if [ "$LATEST_LOCAL" != "$LATEST_REMOTE" ]; then
    log_warn "Local and remote backups don't match!"
    exit 1
fi

log_success "Local and remote backups match"

# =============================================================================
# Step 7: Check remote backup size
# =============================================================================

log_info "Checking remote backup size..."

REMOTE_SIZE=$(ssh "$REMOTE_HOST" "du -k '${REMOTE_DIR}/${LATEST_REMOTE}' | cut -f1" || echo "0")

log_info "Remote backup size: ${REMOTE_SIZE}KB"

if [ "$REMOTE_SIZE" -lt "$MIN_BACKUP_SIZE_KB" ]; then
    log_warn "Remote backup is suspiciously small!"
    exit 1
fi

if [ "$BACKUP_SIZE_KB" != "$REMOTE_SIZE" ]; then
    log_warn "Backup sizes don't match (local: ${BACKUP_SIZE_KB}KB, remote: ${REMOTE_SIZE}KB)"
    exit 1
fi

log_success "Remote backup size matches local"

# =============================================================================
# Summary
# =============================================================================

log_success "✅ All replication checks passed!"
log_info "Summary:"
log_info "  - Latest backup: $LATEST_LOCAL"
log_info "  - Backup age: ${BACKUP_AGE_MINUTES}m"
log_info "  - Local size: ${BACKUP_SIZE_KB}KB"
log_info "  - Remote replicated: ✅"

exit 0
