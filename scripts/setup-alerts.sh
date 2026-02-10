#!/bin/bash
# =============================================================================
# NEXUS Alert System Setup - Syslog-Based Monitoring
# =============================================================================
# Purpose: Configure automated alerts for backup system failures
# Method: Syslog logging + optional Monit/systemd integration
# Date: November 21, 2025
# =============================================================================

set -euo pipefail

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        NEXUS Alert System Setup - Syslog Configuration         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# =============================================================================
# Step 1: Create syslog monitoring configuration
# =============================================================================

echo "📝 Step 1: Creating syslog monitoring configuration..."

# Create rsyslog configuration for NEXUS logs
sudo tee /etc/rsyslog.d/30-nexus.conf > /dev/null << 'EOF'
# NEXUS Backup System Logging
# Route NEXUS backup logs to dedicated file

# Capture output from cron jobs for nexus user
:programname, iequal, "CRON" and :msg, icontains, "nexus" -/var/log/nexus/cron.log
& stop

# Capture general application logs (if piped)
:programname, iequal, "NEXUS" -/var/log/nexus/app.log
& stop

# Route errors to alert file
:severity, gte, 4 -/var/log/nexus/alerts.log
EOF

echo "✅ Syslog configuration created"

# =============================================================================
# Step 2: Create log directories
# =============================================================================

echo "📁 Step 2: Creating log directories..."

sudo mkdir -p /var/log/nexus
sudo mkdir -p /home/marketplace/backups/logs

# Set permissions
sudo chown syslog:adm /var/log/nexus
sudo chmod 755 /var/log/nexus

echo "✅ Log directories created"

# =============================================================================
# Step 3: Restart syslog daemon
# =============================================================================

echo "🔄 Step 3: Restarting syslog daemon..."

if sudo systemctl restart rsyslog; then
    echo "✅ Rsyslog restarted successfully"
else
    echo "⚠️  Failed to restart rsyslog - may already be configured"
fi

# =============================================================================
# Step 4: Create monitoring alert script
# =============================================================================

echo "📝 Step 4: Creating monitoring alert script..."

# Create alert monitoring script
sudo tee /usr/local/bin/nexus-check-alerts.sh > /dev/null << 'EOF'
#!/bin/bash
# Check for backup system failures and log alerts to syslog

set -euo pipefail

LOG_DIR="/home/marketplace/backups/logs"
ALERT_LOG="/var/log/nexus/alerts.log"
REPLICATION_LOG="$LOG_DIR/replication-$(date '+%Y-%m-%d').log"

# Function to log alert
alert() {
    local severity="$1"
    local message="$2"
    logger -t NEXUS -p "user.$severity" "$message"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$severity] $message" >> "$ALERT_LOG"
}

# Check 1: Replication not running
if [ -f "$REPLICATION_LOG" ]; then
    LATEST=$(stat -c%Y "$REPLICATION_LOG" 2>/dev/null || echo 0)
    NOW=$(date +%s)
    AGE=$((NOW - LATEST))

    if [ $AGE -gt 600 ]; then
        alert "warning" "Backup replication stale - no activity for ${AGE}s (>10min)"
    fi
fi

# Check 2: Backup count mismatch (requires SSH key)
SSH_KEY="$HOME/.ssh/id_nexus_backup"
REMOTE_HOST="${BACKUP_REMOTE_HOST:-backup.secondary.vps}"
REMOTE_USER="${BACKUP_REMOTE_USER:-nexus-backup}"
REMOTE_DIR="${BACKUP_REMOTE_DIR:-/mnt/backups/nexus}"

if [ -f "$SSH_KEY" ]; then
    LOCAL_COUNT=$(ls -1 "$LOG_DIR"/../nexus_snapshot_*.db* 2>/dev/null | wc -l)

    if REMOTE_COUNT=$(ssh -i "$SSH_KEY" -o ConnectTimeout=5 "$REMOTE_USER@$REMOTE_HOST" "ls -1 '$REMOTE_DIR'/nexus_snapshot_*.db* 2>/dev/null | wc -l"); then
        if [ "$LOCAL_COUNT" -ne "$REMOTE_COUNT" ]; then
            alert "warning" "Backup count mismatch - Local: $LOCAL_COUNT, Remote: $REMOTE_COUNT"
        fi
    else
        alert "critical" "Cannot connect to backup server for verification"
    fi
fi

# Check 3: Disk space
USAGE=$(df "$LOG_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$USAGE" -gt 80 ]; then
    alert "warning" "Disk usage high - $USAGE% of capacity"
fi

# Check 4: Replication failures in logs
if [ -f "$REPLICATION_LOG" ]; then
    FAILURE_COUNT=$(grep -c "❌" "$REPLICATION_LOG" || echo 0)
    if [ "$FAILURE_COUNT" -gt 0 ]; then
        alert "warning" "Found $FAILURE_COUNT failures in replication log"
    fi
fi

exit 0
EOF

sudo chmod +x /usr/local/bin/nexus-check-alerts.sh
echo "✅ Alert monitoring script created"

# =============================================================================
# Step 5: Create systemd timer for periodic checks
# =============================================================================

echo "⏱️  Step 5: Creating systemd timer for periodic alerts..."

# Create systemd service
sudo tee /etc/systemd/system/nexus-alerts.service > /dev/null << 'EOF'
[Unit]
Description=NEXUS Backup Alert Check
After=network.target

[Service]
Type=oneshot
User=nexus
ExecStart=/usr/local/bin/nexus-check-alerts.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer
sudo tee /etc/systemd/system/nexus-alerts.timer > /dev/null << 'EOF'
[Unit]
Description=NEXUS Backup Alert Check Timer
Requires=nexus-alerts.service

[Timer]
# Run every 5 minutes
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF

# Enable and start timer
sudo systemctl daemon-reload
sudo systemctl enable nexus-alerts.timer
sudo systemctl start nexus-alerts.timer

echo "✅ Systemd timer configured"

# =============================================================================
# Step 6: Create alerting script for critical issues
# =============================================================================

echo "📢 Step 6: Creating critical alert handler..."

# Create script for critical alerts (can be extended for email/webhook later)
sudo tee /usr/local/bin/nexus-alert-critical.sh > /dev/null << 'EOF'
#!/bin/bash
# Handle critical alerts (can escalate to email/Slack/PagerDuty in future)

set -euo pipefail

ALERT_MSG="$1"
PRIORITY="${2:-critical}"

# Log to syslog
logger -t NEXUS -p "user.crit" "CRITICAL: $ALERT_MSG"

# Log to file
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [CRITICAL] $ALERT_MSG" >> /var/log/nexus/critical.log

# Future: Send to monitoring system
# - Email to ops team
# - Slack webhook
# - PagerDuty incident
# - SMS alert

echo "⚠️  CRITICAL ALERT: $ALERT_MSG"

exit 0
EOF

sudo chmod +x /usr/local/bin/nexus-alert-critical.sh
echo "✅ Critical alert handler created"

# =============================================================================
# Step 7: Configure log rotation
# =============================================================================

echo "🔄 Step 7: Configuring log rotation..."

sudo tee /etc/logrotate.d/nexus > /dev/null << 'EOF'
/var/log/nexus/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

/home/marketplace/backups/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nexus nexus
}
EOF

echo "✅ Log rotation configured"

# =============================================================================
# Step 8: Test alerts
# =============================================================================

echo "🧪 Step 8: Testing alert system..."

# Test syslog logging
logger -t NEXUS -p "user.info" "NEXUS alert system test - INFO level"
logger -t NEXUS -p "user.warning" "NEXUS alert system test - WARNING level"
logger -t NEXUS -p "user.crit" "NEXUS alert system test - CRITICAL level"

echo "✅ Test alerts sent"

# =============================================================================
# Step 9: Verify configuration
# =============================================================================

echo "✓ Step 9: Verifying configuration..."

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                   VERIFICATION RESULTS                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check syslog config
if [ -f /etc/rsyslog.d/30-nexus.conf ]; then
    echo "✅ Syslog configuration installed"
else
    echo "❌ Syslog configuration missing"
fi

# Check log directories
if [ -d /var/log/nexus ]; then
    echo "✅ Log directory created: /var/log/nexus"
else
    echo "❌ Log directory missing"
fi

# Check alert scripts
if [ -x /usr/local/bin/nexus-check-alerts.sh ]; then
    echo "✅ Alert monitoring script installed"
else
    echo "❌ Alert monitoring script missing"
fi

# Check systemd timer
if systemctl is-enabled nexus-alerts.timer > /dev/null 2>&1; then
    echo "✅ Systemd timer enabled"
else
    echo "❌ Systemd timer not enabled"
fi

# Check recent logs
echo ""
echo "📋 Recent alert system activity:"
sudo tail -5 /var/log/nexus/alerts.log 2>/dev/null || echo "   (No alerts yet)"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETE ✅                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "📚 Next steps:"
echo "   1. Monitor logs: sudo tail -f /var/log/nexus/alerts.log"
echo "   2. Check timer: systemctl status nexus-alerts.timer"
echo "   3. View syslog: sudo journalctl -u NEXUS -f"
echo "   4. Manual test: /usr/local/bin/nexus-check-alerts.sh"
echo ""

echo "🔗 For future enhancements (Phase 2):"
echo "   - Email alerts (sendmail integration)"
echo "   - Slack webhooks"
echo "   - PagerDuty integration"
echo "   - Prometheus metrics"
echo ""
