#!/bin/bash
# Start All NEXUS Services Script
# Usage: ./scripts/start-all-services.sh [testnet|stagenet]

NETWORK=${1:-testnet}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

log_info "Starting NEXUS Marketplace services..."
log_info "Project root: $PROJECT_ROOT"

# ═══════════════════════════════════════════════════════════════════════
# 1. START TOR DAEMON
# ═══════════════════════════════════════════════════════════════════════
log_info "Checking Tor daemon..."

if ! systemctl is-active --quiet tor; then
    log_warning "Tor daemon not running, starting..."

    # Try to start with systemd
    if command -v systemctl &> /dev/null; then
        sudo systemctl start tor
        sleep 2

        if systemctl is-active --quiet tor; then
            log_success "Tor daemon started via systemd"
        else
            log_error "Failed to start Tor via systemd"
            exit 1
        fi
    else
        log_error "systemctl not available, cannot start Tor automatically"
        log_info "Please start Tor manually: sudo systemctl start tor"
        exit 1
    fi
else
    log_success "Tor daemon already running"
fi

# Verify Tor SOCKS proxy is accessible
if curl --socks5-hostname 127.0.0.1:9050 --max-time 5 https://check.torproject.org &>/dev/null; then
    log_success "Tor SOCKS proxy accessible on 127.0.0.1:9050"
else
    log_warning "Tor SOCKS proxy not accessible (might still be starting)"
fi

# ═══════════════════════════════════════════════════════════════════════
# 2. START MONERO WALLET RPC (TESTNET)
# ═══════════════════════════════════════════════════════════════════════
log_info "Checking Monero wallet RPC..."

# Check if wallet RPC is already running
if curl -s http://127.0.0.1:18083/json_rpc -H 'Content-Type: application/json' \
   -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' &>/dev/null; then
    log_success "Monero wallet RPC already running on port 18083"
else
    log_warning "Monero wallet RPC not running, starting..."

    # Check if monero-wallet-rpc is installed
    if ! command -v monero-wallet-rpc &> /dev/null; then
        log_error "monero-wallet-rpc not found in PATH"
        log_info "Please install Monero CLI: https://www.getmonero.org/downloads/"
        exit 1
    fi

    # Create wallet directory if it doesn't exist
    mkdir -p "$PROJECT_ROOT/.monero-wallets"

    # Start wallet RPC in background
    log_info "Starting monero-wallet-rpc on port 18083..."
    nohup monero-wallet-rpc \
        --testnet \
        --rpc-bind-port 18083 \
        --rpc-bind-ip 127.0.0.1 \
        --disable-rpc-login \
        --wallet-dir "$PROJECT_ROOT/.monero-wallets" \
        --log-file "$PROJECT_ROOT/.monero-wallets/wallet-rpc.log" \
        > /dev/null 2>&1 &

    WALLET_RPC_PID=$!
    echo $WALLET_RPC_PID > "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid"

    # Wait for wallet RPC to be ready
    log_info "Waiting for wallet RPC to be ready..."
    for i in {1..30}; do
        if curl -s http://127.0.0.1:18083/json_rpc -H 'Content-Type: application/json' \
           -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' &>/dev/null; then
            log_success "Monero wallet RPC started successfully (PID: $WALLET_RPC_PID)"
            break
        fi

        if [ $i -eq 30 ]; then
            log_error "Timeout waiting for wallet RPC to start"
            exit 1
        fi

        sleep 1
    done
fi

# ═══════════════════════════════════════════════════════════════════════
# 3. START IPFS DAEMON
# ═══════════════════════════════════════════════════════════════════════
log_info "Checking IPFS daemon..."

# Check if IPFS is already running
if curl -s http://127.0.0.1:5001/api/v0/version &>/dev/null; then
    log_success "IPFS daemon already running on port 5001"
else
    log_warning "IPFS daemon not running, starting..."

    # Check if ipfs is installed
    if ! command -v ipfs &> /dev/null; then
        log_error "IPFS not found in PATH"
        log_info "Please install IPFS: https://docs.ipfs.tech/install/"
        log_warning "Continuing without IPFS (reputation export will be unavailable)"
    else
        # Initialize IPFS if not already initialized
        if [ ! -d "$HOME/.ipfs" ]; then
            log_info "Initializing IPFS..."
            ipfs init
        fi

        # Start IPFS daemon in background
        log_info "Starting IPFS daemon..."
        nohup ipfs daemon > "$PROJECT_ROOT/ipfs-daemon.log" 2>&1 &
        IPFS_PID=$!
        echo $IPFS_PID > "$PROJECT_ROOT/.ipfs-daemon.pid"

        # Wait for IPFS to be ready
        log_info "Waiting for IPFS daemon to be ready..."
        for i in {1..30}; do
            if curl -s http://127.0.0.1:5001/api/v0/version &>/dev/null; then
                log_success "IPFS daemon started successfully (PID: $IPFS_PID)"
                break
            fi

            if [ $i -eq 30 ]; then
                log_warning "Timeout waiting for IPFS daemon (continuing without IPFS)"
            fi

            sleep 1
        done
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# 4. VERIFY DATABASE AND MIGRATIONS
# ═══════════════════════════════════════════════════════════════════════
log_info "Checking database..."

if [ ! -f "$PROJECT_ROOT/marketplace.db" ]; then
    log_warning "Database not found, creating..."

    # Check if diesel CLI is installed
    if ! command -v diesel &> /dev/null; then
        log_error "Diesel CLI not installed"
        log_info "Install with: cargo install diesel_cli --no-default-features --features sqlite"
        exit 1
    fi

    # Run migrations
    cd "$PROJECT_ROOT"
    DATABASE_URL=marketplace.db diesel migration run
    log_success "Database created and migrations applied"
else
    log_success "Database exists"

    # Check if there are pending migrations
    if command -v diesel &> /dev/null; then
        PENDING=$(DATABASE_URL=marketplace.db diesel migration list | grep -c "\[ \]" || true)
        if [ "$PENDING" -gt 0 ]; then
            log_warning "$PENDING pending migration(s) detected, applying..."
            DATABASE_URL=marketplace.db diesel migration run
            log_success "Migrations applied"
        else
            log_success "All migrations applied"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# 5. BUILD SERVER (IF NOT ALREADY BUILT)
# ═══════════════════════════════════════════════════════════════════════
log_info "Checking server binary..."

SERVER_BIN="$PROJECT_ROOT/target/release/server"

if [ ! -f "$SERVER_BIN" ]; then
    log_warning "Server binary not found, building..."
    cargo build --release --package server
    log_success "Server built successfully"
else
    # Check if source code is newer than binary
    if [ "$(find server/src -type f -newer "$SERVER_BIN" | wc -l)" -gt 0 ]; then
        log_warning "Source code newer than binary, rebuilding..."
        cargo build --release --package server
        log_success "Server rebuilt successfully"
    else
        log_success "Server binary up to date"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# 6. START NEXUS SERVER
# ═══════════════════════════════════════════════════════════════════════
log_info "Starting NEXUS server..."

# Kill any existing server processes
if [ -f "$PROJECT_ROOT/.server.pid" ]; then
    OLD_PID=$(cat "$PROJECT_ROOT/.server.pid")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        log_warning "Stopping existing server (PID: $OLD_PID)..."
        kill -9 "$OLD_PID" || true
        sleep 1
    fi
fi

# Additional cleanup
pkill -9 -f "target/release/server" || true
sleep 1

# Start server in background
cd "$PROJECT_ROOT"
nohup "$SERVER_BIN" > "$PROJECT_ROOT/server.log" 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > "$PROJECT_ROOT/.server.pid"

# Wait for server to be ready
log_info "Waiting for server to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/health &>/dev/null; then
        log_success "NEXUS server started successfully (PID: $SERVER_PID)"
        break
    fi

    if [ $i -eq 30 ]; then
        log_error "Timeout waiting for server to start"
        log_info "Check server.log for errors"
        exit 1
    fi

    sleep 1
done

# ═══════════════════════════════════════════════════════════════════════
# 7. DISPLAY STATUS SUMMARY
# ═══════════════════════════════════════════════════════════════════════
echo ""
log_success "════════════════════════════════════════════════════════════"
log_success "   NEXUS MARKETPLACE - ALL SERVICES STARTED"
log_success "════════════════════════════════════════════════════════════"
echo ""

# Tor status
if systemctl is-active --quiet tor; then
    echo -e "✅ ${GREEN}Tor Daemon${NC}         : Running (SOCKS proxy: 127.0.0.1:9050)"
else
    echo -e "❌ ${RED}Tor Daemon${NC}         : Not running"
fi

# Monero wallet RPC status
if curl -s http://127.0.0.1:18083/json_rpc -H 'Content-Type: application/json' \
   -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' &>/dev/null; then
    if [ -f "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid" ]; then
        WALLET_PID=$(cat "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid")
        echo -e "✅ ${GREEN}Monero Wallet RPC${NC}  : Running on port 18083 (PID: $WALLET_PID)"
    else
        echo -e "✅ ${GREEN}Monero Wallet RPC${NC}  : Running on port 18083"
    fi
else
    echo -e "❌ ${RED}Monero Wallet RPC${NC}  : Not running"
fi

# IPFS status
if curl -s http://127.0.0.1:5001/api/v0/version &>/dev/null; then
    if [ -f "$PROJECT_ROOT/.ipfs-daemon.pid" ]; then
        IPFS_PID=$(cat "$PROJECT_ROOT/.ipfs-daemon.pid")
        echo -e "✅ ${GREEN}IPFS Daemon${NC}        : Running on port 5001 (PID: $IPFS_PID)"
    else
        echo -e "✅ ${GREEN}IPFS Daemon${NC}        : Running on port 5001"
    fi
else
    echo -e "⚠️  ${YELLOW}IPFS Daemon${NC}        : Not running (optional)"
fi

# Server status
if curl -s http://127.0.0.1:8080/health &>/dev/null; then
    echo -e "✅ ${GREEN}NEXUS Server${NC}       : Running on http://127.0.0.1:8080 (PID: $SERVER_PID)"
else
    echo -e "❌ ${RED}NEXUS Server${NC}       : Not running"
fi

echo ""
echo -e "${BLUE}Background Services:${NC}"
echo -e "  • TimeoutMonitor         : Monitoring escrow timeouts"
echo -e "  • BlockchainMonitor      : Polling blockchain every 30s"
echo -e "  • MultisigAutoCoordinator: Automatic multisig setup (5s interval)"
echo ""

echo -e "${BLUE}Logs:${NC}"
echo -e "  • Server               : tail -f $PROJECT_ROOT/server.log"
echo -e "  • Monero Wallet RPC    : tail -f $PROJECT_ROOT/.monero-wallets/wallet-rpc.log"
if [ -f "$PROJECT_ROOT/ipfs-daemon.log" ]; then
    echo -e "  • IPFS Daemon          : tail -f $PROJECT_ROOT/ipfs-daemon.log"
fi
echo ""

echo -e "${BLUE}Access:${NC}"
echo -e "  • Web Interface        : http://127.0.0.1:8080"
echo -e "  • Health Check         : http://127.0.0.1:8080/health"
echo -e "  • API Documentation    : http://127.0.0.1:8080/api/docs (if enabled)"
echo ""

echo -e "${YELLOW}To stop all services:${NC}"
echo -e "  ./scripts/stop-all-services.sh"
echo ""

log_success "All services started successfully! 🚀"
