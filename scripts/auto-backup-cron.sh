#!/bin/bash
# Automated Backup Cron Setup for Monero Marketplace
# Run this script to install automatic database backups

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Monero Marketplace - Backup Automation Setup${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if cron is available
if ! command -v crontab &> /dev/null; then
    echo -e "${YELLOW}[WARN]${NC} crontab not found. Install cron to enable automated backups."
    echo "On Ubuntu/Debian: sudo apt install cron"
    exit 1
fi

# Backup frequency options
echo "Select backup frequency:"
echo "  1) Every 30 minutes (recommended for active development)"
echo "  2) Every hour"
echo "  3) Every 6 hours"
echo "  4) Daily at 2 AM"
echo "  5) Custom cron expression"
echo ""
read -p "Enter choice (1-5): " frequency

case $frequency in
    1)
        CRON_SCHEDULE="*/30 * * * *"
        DESCRIPTION="every 30 minutes"
        ;;
    2)
        CRON_SCHEDULE="0 * * * *"
        DESCRIPTION="every hour"
        ;;
    3)
        CRON_SCHEDULE="0 */6 * * *"
        DESCRIPTION="every 6 hours"
        ;;
    4)
        CRON_SCHEDULE="0 2 * * *"
        DESCRIPTION="daily at 2 AM"
        ;;
    5)
        read -p "Enter custom cron expression: " CRON_SCHEDULE
        DESCRIPTION="custom schedule"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

# Backup retention
echo ""
read -p "Number of backups to keep (default: 50): " max_backups
max_backups=${max_backups:-50}

# Compression
echo ""
read -p "Enable compression? (y/n, default: y): " enable_compression
enable_compression=${enable_compression:-y}
if [[ "$enable_compression" == "y" ]]; then
    COMPRESSION="true"
else
    COMPRESSION="false"
fi

# Create cron job entry
BACKUP_SCRIPT="${SCRIPT_DIR}/backup-db.sh"
CRON_JOB="$CRON_SCHEDULE cd $PROJECT_ROOT && DB_FILE=marketplace.db BACKUP_DIR=./backups MAX_BACKUPS=$max_backups COMPRESSION=$COMPRESSION $BACKUP_SCRIPT >> ./logs/backup.log 2>&1"

# Create logs directory
mkdir -p "$PROJECT_ROOT/logs"

# Show summary
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "Configuration Summary:"
echo "  Schedule: $DESCRIPTION"
echo "  Cron Expression: $CRON_SCHEDULE"
echo "  Max Backups: $max_backups"
echo "  Compression: $COMPRESSION"
echo "  Backup Directory: $PROJECT_ROOT/backups"
echo "  Log File: $PROJECT_ROOT/logs/backup.log"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -p "Install cron job? (y/n): " confirm
if [[ "$confirm" != "y" ]]; then
    echo "Installation cancelled"
    exit 0
fi

# Add to crontab
(crontab -l 2>/dev/null | grep -v "$BACKUP_SCRIPT"; echo "$CRON_JOB") | crontab -

echo -e "${GREEN}✓ Automated backup installed successfully${NC}"
echo ""
echo "Cron job added:"
echo "  $CRON_JOB"
echo ""
echo "Manual commands:"
echo "  Run backup now:       $BACKUP_SCRIPT"
echo "  View backup log:      tail -f $PROJECT_ROOT/logs/backup.log"
echo "  List cron jobs:       crontab -l"
echo "  Remove cron job:      crontab -e (then delete the backup line)"
echo ""

# Test backup immediately
read -p "Run initial backup now? (y/n): " run_now
if [[ "$run_now" == "y" ]]; then
    echo ""
    cd "$PROJECT_ROOT"
    DB_FILE=marketplace.db BACKUP_DIR=./backups MAX_BACKUPS=$max_backups COMPRESSION=$COMPRESSION SHOW_HISTORY=true "$BACKUP_SCRIPT"
fi

exit 0
