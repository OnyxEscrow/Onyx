#!/bin/bash
# Create Arbiter User Script for Phase 7 MVP
# Creates the sole arbiter user for dispute resolution

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Monero Marketplace - Arbiter User Setup${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if DATABASE_URL is set
DB_FILE="${DATABASE_URL:-marketplace.db}"

if [[ ! -f "$DB_FILE" ]]; then
    echo -e "${RED}❌ Database not found: $DB_FILE${NC}"
    echo "Run migrations first: diesel migration run"
    exit 1
fi

# Check if arbiter already exists
EXISTING_ARBITER=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM users WHERE role='arbiter';" 2>/dev/null || echo "0")

if [[ "$EXISTING_ARBITER" -gt 0 ]]; then
    echo -e "${YELLOW}⚠️  Arbiter user already exists${NC}"
    echo ""
    sqlite3 "$DB_FILE" "SELECT id, username, email, role FROM users WHERE role='arbiter';" -header -column
    echo ""
    read -p "Create another arbiter? (y/N): " confirm
    if [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]]; then
        echo "Setup cancelled"
        exit 0
    fi
fi

# Get arbiter details
echo -e "${GREEN}Creating new arbiter user${NC}"
echo ""

read -p "Username (default: arbiter): " username
username=${username:-arbiter}

read -p "Email: " email
if [[ -z "$email" ]]; then
    echo -e "${RED}❌ Email is required${NC}"
    exit 1
fi

read -sp "Password: " password
echo ""
read -sp "Confirm password: " password_confirm
echo ""

if [[ "$password" != "$password_confirm" ]]; then
    echo -e "${RED}❌ Passwords do not match${NC}"
    exit 1
fi

if [[ ${#password} -lt 8 ]]; then
    echo -e "${RED}❌ Password must be at least 8 characters${NC}"
    exit 1
fi

# Optional: Wallet address for payouts
echo ""
read -p "Monero wallet address (optional, for arbiter fees): " wallet_address

# Generate UUID
ARBITER_ID=$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')

# Hash password with bcrypt (using Python)
PASSWORD_HASH=$(python3 << EOF
import bcrypt
password = "$password".encode('utf-8')
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
print(hashed.decode('utf-8'))
EOF
)

# Insert into database
sqlite3 "$DB_FILE" << SQL
INSERT INTO users (id, username, email, password_hash, role, wallet_address, created_at)
VALUES (
    '$ARBITER_ID',
    '$username',
    '$email',
    '$PASSWORD_HASH',
    'arbiter',
    $(if [[ -n "$wallet_address" ]]; then echo "'$wallet_address'"; else echo "NULL"; fi),
    datetime('now')
);
SQL

if [[ $? -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ Arbiter user created successfully${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "User ID:   $ARBITER_ID"
    echo "Username:  $username"
    echo "Email:     $email"
    echo "Role:      arbiter"
    if [[ -n "$wallet_address" ]]; then
        echo "Wallet:    $wallet_address"
    fi
    echo ""
    echo -e "${YELLOW}IMPORTANT:${NC}"
    echo "1. This user can resolve disputes and release funds"
    echo "2. Keep credentials secure (server admin level access)"
    echo "3. Arbiter sees ALL escrow details and messages"
    echo "4. Login at: http://localhost:8080/login"
    echo ""
else
    echo -e "${RED}❌ Failed to create arbiter user${NC}"
    exit 1
fi

# Show all arbiters
echo "Current arbiters in system:"
sqlite3 "$DB_FILE" "SELECT id, username, email, created_at FROM users WHERE role='arbiter';" -header -column
echo ""

exit 0
