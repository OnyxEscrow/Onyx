#!/bin/bash
# Monero Marketplace - Startup Script
# Ensures clean startup with all prerequisites checked

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🚀 Monero Marketplace Startup"
echo "=============================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
error() {
    echo -e "${RED}❌ ERROR:${NC} $1"
}

success() {
    echo -e "${GREEN}✅${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠️  WARNING:${NC} $1"
}

info() {
    echo "ℹ️  $1"
}

# 1. Kill old servers
echo "1. Cleaning up old server processes..."
if ps aux | grep -q "[t]arget/release/server"; then
    killall -9 server 2>/dev/null || true
    pkill -9 -f "target/release/server" 2>/dev/null || true
    sleep 2
    success "Old servers killed"
else
    info "No old servers found"
fi

# 2. Verify IPFS daemon
echo ""
echo "2. Checking IPFS daemon..."
if ! ps aux | grep -q "[i]pfs daemon"; then
    error "IPFS daemon not running"
    echo "   Start with: ipfs daemon &"
    exit 1
fi
success "IPFS daemon running"

# Check IPFS gateway port
IPFS_GATEWAY=$(ipfs config Addresses.Gateway 2>/dev/null || echo "unknown")
if [[ "$IPFS_GATEWAY" != *"8083"* ]] && [[ "$IPFS_GATEWAY" != *"8081"* ]]; then
    warning "IPFS gateway not on expected port (found: $IPFS_GATEWAY)"
    echo "   Expected: /ip4/127.0.0.1/tcp/8083 or /ip4/127.0.0.1/tcp/8081"
fi

# 3. Verify database
echo ""
echo "3. Checking database..."
if [ ! -f marketplace.db ]; then
    error "Database not found: marketplace.db"
    echo "   Create with: cargo run --release --bin init_db"
    exit 1
fi

DB_SIZE=$(stat -c%s marketplace.db)
if [ "$DB_SIZE" -lt 100000 ]; then
    warning "Database seems empty or corrupted (${DB_SIZE} bytes)"
    echo "   Expected: ~188KB+"
    read -p "   Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    success "Database exists ($(numfmt --to=iec-i --suffix=B $DB_SIZE))"
fi

# 4. Verify DATABASE_URL configuration
echo ""
echo "4. Checking configuration..."
if [ ! -f .env ]; then
    error ".env file not found"
    exit 1
fi

DATABASE_URL=$(grep "^DATABASE_URL=" .env | cut -d'=' -f2)
if [[ "$DATABASE_URL" == sqlite:* ]]; then
    error "DATABASE_URL has wrong format in .env"
    echo "   Found: $DATABASE_URL"
    echo "   Expected: /absolute/path/to/marketplace.db"
    echo "   This will create a file named 'sqlite:marketplace.db' instead!"
    exit 1
fi

if [[ ! "$DATABASE_URL" = /* ]]; then
    warning "DATABASE_URL is not an absolute path: $DATABASE_URL"
    echo "   Recommended: Use absolute path for clarity"
fi

success "DATABASE_URL configured correctly"

# 5. Verify IPFS gateway port in code
echo ""
echo "5. Verifying IPFS gateway configuration..."
if grep -q "8080/ipfs" server/src/ipfs/client.rs; then
    error "IPFS gateway uses wrong port (8080) in code"
    echo "   File: server/src/ipfs/client.rs"
    echo "   Fix: Change to http://127.0.0.1:8083/ipfs"
    echo "   Then recompile: cargo build --release --package server"
    exit 1
fi

if grep -q "8083/ipfs\|8081/ipfs" server/src/ipfs/client.rs; then
    success "IPFS gateway port correct (8083 or 8081)"
else
    warning "Could not verify IPFS gateway port"
fi

# 6. Check server binary exists and is recent
echo ""
echo "6. Checking server binary..."
if [ ! -f target/release/server ]; then
    error "Server binary not found"
    echo "   Compile with: cargo build --release --package server"
    exit 1
fi

BINARY_AGE=$(stat -c %Y target/release/server)
NOW=$(date +%s)
AGE_HOURS=$(( ($NOW - $BINARY_AGE) / 3600 ))

if [ $AGE_HOURS -gt 24 ]; then
    warning "Server binary is $AGE_HOURS hours old"
    echo "   Consider recompiling: cargo build --release --package server"
    read -p "   Continue with old binary? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    success "Server binary recent (${AGE_HOURS}h old)"
fi

# 7. Check ports availability
echo ""
echo "7. Checking port availability..."
if lsof -i :8080 >/dev/null 2>&1; then
    OCCUPANT=$(lsof -i :8080 | grep -v COMMAND | awk '{print $1}' | head -1)
    error "Port 8080 already in use by: $OCCUPANT"
    echo "   Kill with: killall -9 $OCCUPANT"
    exit 1
fi
success "Port 8080 available"

# 8. Start server
echo ""
echo "8. Starting server..."
env -u DATABASE_URL ./target/release/server > server.log 2>&1 &
SERVER_PID=$!
echo "   Server PID: $SERVER_PID"

# 9. Wait for startup
echo ""
echo "9. Waiting for server startup..."
sleep 5

# 10. Verify server is running
if ! ps -p $SERVER_PID > /dev/null; then
    error "Server process died"
    echo "   Check logs:"
    echo "   tail -50 server.log"
    exit 1
fi
success "Server process running"

# 11. Health check
echo ""
echo "10. Running health check..."
if curl -s --max-time 5 http://127.0.0.1:8080/api/health | grep -q "ok"; then
    success "Server is healthy"
else
    error "Server health check failed"
    echo "   Server is running but not responding correctly"
    echo "   Check logs: tail -50 server.log"
    exit 1
fi

# 12. Test listings endpoint
echo ""
echo "11. Testing listings endpoint..."
LISTINGS_COUNT=$(curl -s http://127.0.0.1:8080/api/listings | jq length 2>/dev/null || echo "error")
if [ "$LISTINGS_COUNT" = "error" ]; then
    warning "Listings endpoint failed"
else
    success "Listings endpoint works (${LISTINGS_COUNT} listings)"
fi

# Summary
echo ""
echo "=============================="
echo -e "${GREEN}✅ Marketplace started successfully!${NC}"
echo ""
echo "Access at:"
echo "  • Web:    http://127.0.0.1:8080"
echo "  • API:    http://127.0.0.1:8080/api"
echo "  • Health: http://127.0.0.1:8080/api/health"
echo ""
echo "Logs:"
echo "  • tail -f server.log"
echo ""
echo "Stop:"
echo "  • killall -9 server"
echo ""

# Optional: Show recent logs
read -p "Show recent logs? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Recent logs:"
    echo "=============================="
    tail -20 server.log
fi
