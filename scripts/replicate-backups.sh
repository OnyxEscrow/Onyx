#!/bin/bash
# =============================================================================
# NEXUS Off-Site Backup Replication Script
# =============================================================================
# Purpose: Replicate local backups to secondary VPS via rsync/SSH
# Usage: ./replicate-backups.sh [local_dir] [remote_host] [remote_user] [remote_dir] [ssh_key]
# =============================================================================

set -euo pipefail

# Configuration
LOCAL_BACKUP_DIR="${1:-./backups}"
REMOTE_HOST="${2:-backup.server.com}"
REMOTE_USER="${3:-nexus-backup}"
REMOTE_DIR="${4:-/mnt/backups/nexus}"
SSH_KEY="${5:-$HOME/.ssh/id_nexus_backup}"

# Logging - Create daily logs
LOG_DIR="${LOCAL_BACKUP_DIR}/logs"
mkdir -p "$LOG_DIR"

# Create daily log file
LOG_FILE="${LOG_DIR}/replication-$(date '+%Y-%m-%d').log"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ℹ️  $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ $*" | tee -a "$LOG_FILE"
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ $*" | tee -a "$LOG_FILE" >&2
}

# =============================================================================
# Step 1: Validate Environment
# =============================================================================

log_info "Starting backup replication to $REMOTE_HOST:$REMOTE_DIR"

if [ ! -d "$LOCAL_BACKUP_DIR" ]; then
    log_error "Local backup directory not found: $LOCAL_BACKUP_DIR"
    exit 1
fi

if [ ! -f "$SSH_KEY" ]; then
    log_error "SSH key not found: $SSH_KEY"
    exit 1
fi

if ! command -v rsync &> /dev/null; then
    log_error "rsync is not installed"
    exit 1
fi

log_success "Environment validated"

# =============================================================================
# Step 2: Test SSH Connectivity
# =============================================================================

log_info "Testing SSH connection to $REMOTE_HOST..."

if ! ssh -i "$SSH_KEY" -o ConnectTimeout=10 "$REMOTE_USER@$REMOTE_HOST" "test -d '$REMOTE_DIR'" 2>/dev/null; then
    log_error "Cannot connect to $REMOTE_HOST or remote directory does not exist"
    exit 1
fi

log_success "SSH connection verified"

# =============================================================================
# Step 3: Replicate Backups via rsync
# =============================================================================

log_info "Replicating backups via rsync..."

START_TIME=$(date +%s)

# rsync options:
# --archive        : preserve permissions, times, ownership
# --verbose        : show progress
# --delete         : delete remote files not in local (mirror)
# --checksum       : verify by checksum not just mod-time/size
# --compress       : compress during transfer
# --partial        : keep partial transfers (resume-friendly)
# -e               : specify SSH command with key

if rsync \
    --archive \
    --verbose \
    --delete \
    --checksum \
    --compress \
    --partial \
    --timeout=300 \
    -e "ssh -i $SSH_KEY" \
    "$LOCAL_BACKUP_DIR/" \
    "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/" \
    >> "$LOG_FILE" 2>&1; then

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    log_success "Rsync completed in ${DURATION}s"
else
    log_error "Rsync failed (exit code: $?)"
    exit 1
fi

# =============================================================================
# Step 4: Verify Remote Backups
# =============================================================================

log_info "Verifying remote backups..."

# Count backup files
LOCAL_COUNT=$(ls -1 "$LOCAL_BACKUP_DIR"/nexus_snapshot_*.db* 2>/dev/null | wc -l)
REMOTE_COUNT=$(ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "ls -1 '$REMOTE_DIR'/nexus_snapshot_*.db* 2>/dev/null | wc -l")

log_info "Local backup count: $LOCAL_COUNT"
log_info "Remote backup count: $REMOTE_COUNT"

if [ "$LOCAL_COUNT" -ne "$REMOTE_COUNT" ]; then
    log_error "Backup count mismatch! Local: $LOCAL_COUNT, Remote: $REMOTE_COUNT"
    exit 1
fi

# Verify latest backup filename matches
if [ "$LOCAL_COUNT" -gt 0 ]; then
    LATEST_LOCAL=$(ls -1t "$LOCAL_BACKUP_DIR"/nexus_snapshot_*.db* 2>/dev/null | head -1 | xargs basename)
    LATEST_REMOTE=$(ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "ls -1t '$REMOTE_DIR'/nexus_snapshot_*.db* 2>/dev/null | head -1 | xargs basename")

    log_info "Latest local backup: $LATEST_LOCAL"
    log_info "Latest remote backup: $LATEST_REMOTE"

    if [ "$LATEST_LOCAL" != "$LATEST_REMOTE" ]; then
        log_error "Latest backup mismatch!"
        exit 1
    fi

    log_success "Latest backup verified: $LATEST_LOCAL"
fi

# =============================================================================
# Step 5: Report Statistics
# =============================================================================

LOCAL_SIZE=$(du -sh "$LOCAL_BACKUP_DIR" | cut -f1)
REMOTE_SIZE=$(ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "du -sh '$REMOTE_DIR'" 2>/dev/null | cut -f1)

log_success "Replication complete"
log_info "Local backup size: $LOCAL_SIZE"
log_info "Remote backup size: $REMOTE_SIZE"

exit 0
