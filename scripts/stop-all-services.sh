#!/bin/bash
# Stop All NEXUS Services Script
# This script gracefully stops all NEXUS services:
# 1. NEXUS server
# 2. Monero wallet RPC
# 3. IPFS daemon
# 4. Optionally Tor daemon (if started by script)

set -e  # Exit on error

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

log_info "Stopping NEXUS Marketplace services..."

# ═══════════════════════════════════════════════════════════════════════
# 1. STOP NEXUS SERVER
# ═══════════════════════════════════════════════════════════════════════
log_info "Stopping NEXUS server..."

if [ -f "$PROJECT_ROOT/.server.pid" ]; then
    SERVER_PID=$(cat "$PROJECT_ROOT/.server.pid")

    if kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Sending SIGTERM to server (PID: $SERVER_PID)..."
        kill -15 "$SERVER_PID" || true

        # Wait up to 10 seconds for graceful shutdown
        for i in {1..10}; do
            if ! kill -0 "$SERVER_PID" 2>/dev/null; then
                log_success "Server stopped gracefully"
                break
            fi

            if [ $i -eq 10 ]; then
                log_warning "Server did not stop gracefully, forcing..."
                kill -9 "$SERVER_PID" || true
                log_success "Server killed forcefully"
            fi

            sleep 1
        done

        rm -f "$PROJECT_ROOT/.server.pid"
    else
        log_warning "Server PID file exists but process not running"
        rm -f "$PROJECT_ROOT/.server.pid"
    fi
else
    log_warning "Server PID file not found"
fi

# Additional cleanup for any lingering server processes
pkill -9 -f "target/release/server" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════
# 2. STOP MONERO WALLET RPC
# ═══════════════════════════════════════════════════════════════════════
log_info "Stopping Monero wallet RPC..."

if [ -f "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid" ]; then
    WALLET_PID=$(cat "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid")

    if kill -0 "$WALLET_PID" 2>/dev/null; then
        log_info "Sending SIGTERM to wallet RPC (PID: $WALLET_PID)..."
        kill -15 "$WALLET_PID" || true

        # Wait up to 10 seconds for graceful shutdown
        for i in {1..10}; do
            if ! kill -0 "$WALLET_PID" 2>/dev/null; then
                log_success "Wallet RPC stopped gracefully"
                break
            fi

            if [ $i -eq 10 ]; then
                log_warning "Wallet RPC did not stop gracefully, forcing..."
                kill -9 "$WALLET_PID" || true
                log_success "Wallet RPC killed forcefully"
            fi

            sleep 1
        done

        rm -f "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid"
    else
        log_warning "Wallet RPC PID file exists but process not running"
        rm -f "$PROJECT_ROOT/.monero-wallets/wallet-rpc.pid"
    fi
else
    log_warning "Wallet RPC PID file not found"
fi

# Additional cleanup for any lingering wallet RPC processes
pkill -9 -f "monero-wallet-rpc.*--testnet" 2>/dev/null || true
fuser -k 18083/tcp 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════
# 3. STOP IPFS DAEMON
# ═══════════════════════════════════════════════════════════════════════
log_info "Stopping IPFS daemon..."

if [ -f "$PROJECT_ROOT/.ipfs-daemon.pid" ]; then
    IPFS_PID=$(cat "$PROJECT_ROOT/.ipfs-daemon.pid")

    if kill -0 "$IPFS_PID" 2>/dev/null; then
        log_info "Sending SIGTERM to IPFS daemon (PID: $IPFS_PID)..."
        kill -15 "$IPFS_PID" || true

        # Wait up to 10 seconds for graceful shutdown
        for i in {1..10}; do
            if ! kill -0 "$IPFS_PID" 2>/dev/null; then
                log_success "IPFS daemon stopped gracefully"
                break
            fi

            if [ $i -eq 10 ]; then
                log_warning "IPFS daemon did not stop gracefully, forcing..."
                kill -9 "$IPFS_PID" || true
                log_success "IPFS daemon killed forcefully"
            fi

            sleep 1
        done

        rm -f "$PROJECT_ROOT/.ipfs-daemon.pid"
    else
        log_warning "IPFS daemon PID file exists but process not running"
        rm -f "$PROJECT_ROOT/.ipfs-daemon.pid"
    fi
else
    log_warning "IPFS daemon PID file not found"
fi

# Additional cleanup for any lingering IPFS processes
pkill -9 -f "ipfs daemon" 2>/dev/null || true
fuser -k 5001/tcp 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════
# 4. TOR DAEMON (OPTIONAL)
# ═══════════════════════════════════════════════════════════════════════
# Note: We don't stop Tor by default because it's a system service
# and might be used by other applications

if [ "$1" == "--stop-tor" ]; then
    log_info "Stopping Tor daemon (as requested)..."

    if systemctl is-active --quiet tor; then
        sudo systemctl stop tor
        log_success "Tor daemon stopped"
    else
        log_warning "Tor daemon not running"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# 5. CLEANUP LOGS (OPTIONAL)
# ═══════════════════════════════════════════════════════════════════════
if [ "$1" == "--clean-logs" ] || [ "$2" == "--clean-logs" ]; then
    log_info "Cleaning up log files..."

    rm -f "$PROJECT_ROOT/server.log"
    rm -f "$PROJECT_ROOT/ipfs-daemon.log"
    rm -f "$PROJECT_ROOT/.monero-wallets/wallet-rpc.log"

    log_success "Log files cleaned"
fi

# ═══════════════════════════════════════════════════════════════════════
# 6. DISPLAY STATUS
# ═══════════════════════════════════════════════════════════════════════
echo ""
log_success "════════════════════════════════════════════════════════════"
log_success "   NEXUS MARKETPLACE - ALL SERVICES STOPPED"
log_success "════════════════════════════════════════════════════════════"
echo ""

# Verify services are stopped
SERVICES_STOPPED=true

# Check NEXUS server
if pgrep -f "target/release/server" &>/dev/null; then
    echo -e "❌ ${RED}NEXUS Server${NC}       : Still running (manual cleanup required)"
    SERVICES_STOPPED=false
else
    echo -e "✅ ${GREEN}NEXUS Server${NC}       : Stopped"
fi

# Check Monero wallet RPC
if pgrep -f "monero-wallet-rpc" &>/dev/null; then
    echo -e "❌ ${RED}Monero Wallet RPC${NC}  : Still running (manual cleanup required)"
    SERVICES_STOPPED=false
else
    echo -e "✅ ${GREEN}Monero Wallet RPC${NC}  : Stopped"
fi

# Check IPFS daemon
if pgrep -f "ipfs daemon" &>/dev/null; then
    echo -e "❌ ${RED}IPFS Daemon${NC}        : Still running (manual cleanup required)"
    SERVICES_STOPPED=false
else
    echo -e "✅ ${GREEN}IPFS Daemon${NC}        : Stopped"
fi

# Check Tor daemon
if systemctl is-active --quiet tor; then
    echo -e "ℹ️  ${BLUE}Tor Daemon${NC}         : Still running (system service, use --stop-tor to stop)"
else
    echo -e "✅ ${GREEN}Tor Daemon${NC}         : Stopped"
fi

echo ""

if [ "$SERVICES_STOPPED" = true ]; then
    log_success "All services stopped successfully! ✅"
else
    log_warning "Some services are still running. Run again or kill manually:"
    echo -e "  ${YELLOW}pkill -9 -f 'target/release/server'${NC}"
    echo -e "  ${YELLOW}pkill -9 -f 'monero-wallet-rpc'${NC}"
    echo -e "  ${YELLOW}pkill -9 -f 'ipfs daemon'${NC}"
fi

echo ""
echo -e "${BLUE}Options:${NC}"
echo -e "  --stop-tor    : Also stop Tor daemon (system service)"
echo -e "  --clean-logs  : Clean all log files"
echo ""
echo -e "${YELLOW}To start services again:${NC}"
echo -e "  ./scripts/start-all-services.sh"
echo ""
