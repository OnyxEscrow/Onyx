# Database Backup System

Production-grade backup system for Monero Marketplace with automatic rotation, compression, and integrity verification.

## Features

✅ **Automated Backups** - Cron-based scheduling
✅ **Compression** - Reduces backup size by ~40-60%
✅ **Encryption** - Optional AES-256 encryption for backups
✅ **Rotation** - Automatically keeps last N backups
✅ **Integrity** - SHA-256 checksums and verification
✅ **Hot Backup** - Works while server is running (WAL mode)
✅ **Encrypted DB Support** - Handles encrypted production databases

## Quick Start

### 1. Manual Backup (Right Now)

```bash
./scripts/backup-db.sh
```

This creates a timestamped backup in `./backups/` directory.

### 2. Restore from Backup

```bash
./scripts/restore-db.sh
```

Interactive menu to select and restore from available backups.

### 3. Automated Backups (Production)

```bash
./scripts/auto-backup-cron.sh
```

Follow the prompts to set up automatic backups via cron.

## Usage Examples

### Basic Backup
```bash
./scripts/backup-db.sh
```

### Backup with Custom Settings
```bash
# Keep 100 backups, no compression
MAX_BACKUPS=100 COMPRESSION=false ./scripts/backup-db.sh

# Encrypt backups with key
ENCRYPT_BACKUP=true BACKUP_KEY="your-secret-key" ./scripts/backup-db.sh

# Custom DB file and backup directory
DB_FILE=/path/to/db BACKUP_DIR=/backups ./scripts/backup-db.sh
```

### List Available Backups
```bash
ls -lht backups/
```

### Restore Specific Backup
```bash
# Interactive restore
./scripts/restore-db.sh

# The script will:
# 1. Show all available backups with timestamps
# 2. Verify checksums
# 3. Create safety backup of current DB
# 4. Restore selected backup
# 5. Verify integrity
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_FILE` | `marketplace.db` | Database file to backup |
| `BACKUP_DIR` | `./backups` | Backup destination directory |
| `MAX_BACKUPS` | `50` | Number of backups to keep |
| `COMPRESSION` | `true` | Enable gzip compression |
| `ENCRYPT_BACKUP` | `false` | Enable AES-256 encryption |
| `BACKUP_KEY` | `""` | Encryption key (required if ENCRYPT_BACKUP=true) |

### Backup File Naming

```
marketplace-20251120-062640.db.gz
          ^^^^^^^^^^^       ^^ ^^
          Date (YYYYMMDD)   |  Extension (.gz if compressed)
                            |
                            Time (HHMMSS)
```

## Automated Backup Setup

### Install Cron Job

```bash
./scripts/auto-backup-cron.sh
```

This will guide you through:
1. Backup frequency (every 30min, hourly, daily, custom)
2. Retention policy (how many backups to keep)
3. Compression settings
4. Cron job installation

### Manual Cron Setup

Edit crontab:
```bash
crontab -e
```

Add line (example: backup every 30 minutes):
```cron
*/30 * * * * cd /home/malix/Desktop/NEXUS && ./scripts/backup-db.sh >> ./logs/backup.log 2>&1
```

### View Backup Logs

```bash
tail -f logs/backup.log
```

## Production Best Practices

### 1. Off-Site Backups

Sync backups to remote server:
```bash
# Add to cron after local backup
rsync -avz --delete backups/ user@backup-server:/backups/marketplace/
```

### 2. Backup Monitoring

Check if backups are current:
```bash
# Alert if latest backup is older than 2 hours
LATEST=$(ls -t backups/marketplace-*.db* | head -1)
AGE=$(($(date +%s) - $(stat -c%Y "$LATEST")))
if [[ $AGE -gt 7200 ]]; then
    echo "WARNING: Latest backup is $((AGE / 3600)) hours old"
fi
```

### 3. Test Restores Regularly

```bash
# Monthly restore test (use a test environment)
./scripts/restore-db.sh
```

### 4. Encrypted Database Backups

Your production DB is encrypted with `DB_ENCRYPTION_KEY`. Backups preserve the encryption.

**CRITICAL:**
- Store `DB_ENCRYPTION_KEY` separately from backups
- If you lose the key, **all data is lost forever**
- Consider using Shamir Secret Sharing (3-of-5) for the key

### 5. Backup Before Risky Operations

```bash
# Before migration
./scripts/backup-db.sh
diesel migration run

# Before major upgrade
./scripts/backup-db.sh
git pull && cargo build --release
```

## Disaster Recovery

### Scenario 1: Accidental Data Loss

```bash
# 1. Stop server
pkill -9 -f "target/release/server"

# 2. Restore backup
./scripts/restore-db.sh

# 3. Restart server
./target/release/server &
```

### Scenario 2: Database Corruption

```bash
# 1. Check integrity
sqlite3 marketplace.db "PRAGMA integrity_check;"

# 2. If corrupted, restore latest good backup
./scripts/restore-db.sh

# 3. Verify restored DB
sqlite3 marketplace.db "PRAGMA integrity_check;"
```

### Scenario 3: Server Crash During Transaction

```bash
# WAL mode auto-recovery
# Just restart server - SQLite will replay WAL log
./target/release/server &
```

## Backup Storage

### Disk Space Estimation

| Scenario | DB Size | Compressed Backup | 50 Backups Total |
|----------|---------|-------------------|------------------|
| Empty DB | 264 KB | 265 KB | ~13 MB |
| 100 orders | ~2 MB | ~800 KB | ~40 MB |
| 1000 orders | ~15 MB | ~6 MB | ~300 MB |
| 10000 orders | ~120 MB | ~50 MB | ~2.5 GB |

### Cleanup Old Backups

Automatic rotation is enabled by default. Manual cleanup:
```bash
# Remove backups older than 30 days
find backups/ -name "marketplace-*.db*" -mtime +30 -delete

# Keep only last 20 backups
ls -t backups/marketplace-*.db.gz | tail -n +21 | xargs rm -f
```

## Troubleshooting

### Backup Fails with "database is locked"

```bash
# Stop server first
pkill -9 -f "target/release/server"

# Run backup
./scripts/backup-db.sh

# Restart server
./target/release/server &
```

### Encrypted DB Backup Issues

The script automatically detects encrypted databases and skips SQLite integrity checks. Backups are still valid.

### Restore Checksum Mismatch

```bash
# Checksum file may be missing or corrupted
# Restore without checksum verification (at your own risk)
# Edit restore-db.sh and skip checksum check, or:
cp backups/marketplace-TIMESTAMP.db.gz /tmp/
gunzip /tmp/marketplace-TIMESTAMP.db.gz
cp /tmp/marketplace-TIMESTAMP.db marketplace.db
```

### No Backups Found

```bash
# Check backup directory
ls -la backups/

# Create initial backup
./scripts/backup-db.sh
```

## Security Considerations

1. **Backup Encryption**: For sensitive data, enable `ENCRYPT_BACKUP=true`
2. **Access Control**: Restrict backup directory permissions
   ```bash
   chmod 700 backups/
   ```
3. **Off-Site Storage**: Store backups on separate physical machine
4. **Key Management**: Never store `BACKUP_KEY` or `DB_ENCRYPTION_KEY` in git
5. **Audit Logs**: Monitor `logs/backup.log` for unauthorized access

## Integration with CI/CD

```yaml
# .github/workflows/backup.yml
name: Database Backup
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:  # Manual trigger

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run backup
        env:
          MAX_BACKUPS: 100
          COMPRESSION: true
        run: ./scripts/backup-db.sh
      - name: Upload to S3
        run: aws s3 sync backups/ s3://my-backups/marketplace/
```

## Support

For issues or questions:
- Check logs: `tail -f logs/backup.log`
- Verify script permissions: `ls -l scripts/backup-db.sh`
- Test manually: `bash -x scripts/backup-db.sh` (debug mode)
