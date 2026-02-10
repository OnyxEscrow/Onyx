#!/bin/bash
# =============================================================================
# NEXUS SQLCipher Encryption Progress Monitor
# =============================================================================
# Purpose: Track database encryption progress during soft encryption rollout
# Usage: ./monitor-encryption.sh [database_path] [interval_seconds]
# Date: November 21, 2025
# =============================================================================

set -euo pipefail

# Configuration
DATABASE_PATH="${1:-./marketplace.db}"
INTERVAL="${2:-30}"  # Check every 30 seconds by default
LOG_DIR="${DATABASE_PATH%/*}/logs"

# Create log directory
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/encryption-$(date '+%Y-%m-%d').log"

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
# Step 1: Validate Database
# =============================================================================

log_info "Starting SQLCipher encryption progress monitor"

if [ ! -f "$DATABASE_PATH" ]; then
    log_error "Database not found: $DATABASE_PATH"
    exit 1
fi

# =============================================================================
# Step 2: Get Initial Stats
# =============================================================================

log_info "Monitoring encryption progress..."
log_info "Database: $DATABASE_PATH"
log_info "Check interval: ${INTERVAL}s"
log_info "Log file: $LOG_FILE"
echo ""

# Initial state
INITIAL_SIZE=$(stat -c%s "$DATABASE_PATH" 2>/dev/null || echo 0)
START_TIME=$(date +%s)

log_info "Initial database size: $((INITIAL_SIZE / 1024))KB"

# =============================================================================
# Step 3: Monitor Encryption Progress
# =============================================================================

LAST_SIZE=$INITIAL_SIZE
CHECK_COUNT=0
STABLE_COUNT=0

while true; do
    # Get current database size and WAL size
    DB_SIZE=$(stat -c%s "$DATABASE_PATH" 2>/dev/null || echo 0)
    WAL_SIZE=$(stat -c%s "${DATABASE_PATH}-wal" 2>/dev/null || echo 0)
    SHM_SIZE=$(stat -c%s "${DATABASE_PATH}-shm" 2>/dev/null || echo 0)

    TOTAL_SIZE=$((DB_SIZE + WAL_SIZE + SHM_SIZE))
    TIME_ELAPSED=$(($(date +%s) - START_TIME))
    CHECK_COUNT=$((CHECK_COUNT + 1))

    # Calculate change
    SIZE_CHANGE=$((DB_SIZE - LAST_SIZE))
    SIZE_CHANGE_KB=$((SIZE_CHANGE / 1024))

    # Check if size is changing (indicates active encryption)
    if [ "$DB_SIZE" -eq "$LAST_SIZE" ]; then
        STABLE_COUNT=$((STABLE_COUNT + 1))
    else
        STABLE_COUNT=0
    fi

    # Get page count and encrypted page estimate
    PAGE_COUNT=$(sqlite3 "$DATABASE_PATH" "PRAGMA page_count;" 2>/dev/null || echo "?")
    FREELIST=$(sqlite3 "$DATABASE_PATH" "PRAGMA freelist_count;" 2>/dev/null || echo "?")

    # Estimate encryption progress
    if [ "$PAGE_COUNT" != "?" ] && [ "$FREELIST" != "?" ]; then
        ENCRYPTED_PAGES=$((PAGE_COUNT - FREELIST))
        if [ "$PAGE_COUNT" -gt 0 ]; then
            PROGRESS=$((ENCRYPTED_PAGES * 100 / PAGE_COUNT))
        else
            PROGRESS=0
        fi
    else
        PROGRESS="?"
    fi

    # Log status
    STATUS="[Size: $((DB_SIZE / 1024))KB | WAL: $((WAL_SIZE / 1024))KB | Progress: $PROGRESS%]"

    if [ "$SIZE_CHANGE_KB" -ne 0 ]; then
        log_info "Encrypting... $STATUS (change: ${SIZE_CHANGE_KB}KB)"
    else
        if [ "$STABLE_COUNT" -lt 3 ]; then
            log_info "Monitoring... $STATUS (no change for ${STABLE_COUNT}/${INTERVAL}s)"
        else
            # Size stable for 90+ seconds = likely done
            log_success "Encryption appears complete! $STATUS"

            # Verify integrity
            INTEGRITY=$(sqlite3 "$DATABASE_PATH" "PRAGMA integrity_check;" 2>/dev/null || echo "FAILED")
            if [ "$INTEGRITY" = "ok" ]; then
                log_success "Integrity check: PASSED"
            else
                log_warn "Integrity check: FAILED - $INTEGRITY"
            fi

            echo ""
            log_info "Encryption Monitor Summary:"
            log_info "  Total time: ${TIME_ELAPSED}s"
            log_info "  Final size: $((DB_SIZE / 1024))KB"
            log_info "  Total pages: $PAGE_COUNT"
            log_info "  Final progress: $PROGRESS%"
            log_info "  Integrity: $INTEGRITY"
            echo ""

            # Exit if fully encrypted (100%)
            if [ "$PROGRESS" = "100" ]; then
                log_success "✅ DATABASE FULLY ENCRYPTED"
                exit 0
            fi

            # Otherwise continue monitoring
        fi
    fi

    # Update last size
    LAST_SIZE=$DB_SIZE

    # Check timeout (12 hours)
    if [ "$TIME_ELAPSED" -gt 43200 ]; then
        log_error "Encryption monitor timeout (12 hours)"
        exit 1
    fi

    # Sleep before next check
    sleep "$INTERVAL"
done
