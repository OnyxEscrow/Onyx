#!/bin/bash
# =============================================================================
# Start Monero Wallet RPC instances for MAINNET
# =============================================================================
#
# CRITICAL: This script starts MAINNET wallet RPCs handling REAL FUNDS.
# Ensure all security measures are in place before running.
#
# Architecture:
# - Port 18082: Buyer wallets
# - Port 18083: Vendor wallets
# - Port 18084: Arbiter wallets
# - Port 18086: Monitor wallet (read-only)
#
# Prerequisites:
# - monerod running and FULLY SYNCED on mainnet (port 18081)
# - Tor daemon running (for hidden service)
# - Fresh secrets generated (see .env.mainnet.template)
# =============================================================================

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
WALLET_DIR="${MAINNET_WALLET_DIR:-./mainnet-wallets}"
DAEMON_URL="${DAEMON_URL:-http://127.0.0.1:18081}"
LOG_DIR="${LOG_DIR:-./logs}"

# Ports (mainnet defaults)
BUYER_PORT=18082
VENDOR_PORT=18083
ARBITER_PORT=18084
MONITOR_PORT=18086

echo -e "${YELLOW}==============================================================================${NC}"
echo -e "${YELLOW} MONERO MARKETPLACE - MAINNET WALLET RPC STARTUP${NC}"
echo -e "${YELLOW}==============================================================================${NC}"
echo ""

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

echo -e "${YELLOW}[1/6] Pre-flight checks...${NC}"

# Check if running as root (bad idea)
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}ERROR: Do not run as root! Use a dedicated user account.${NC}"
    exit 1
fi

# Check if daemon is running and synced
echo "  Checking monerod status..."
DAEMON_STATUS=$(curl -s -X POST "$DAEMON_URL/json_rpc" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' 2>/dev/null || echo '{"error":"unreachable"}')

if echo "$DAEMON_STATUS" | grep -q '"error"'; then
    echo -e "${RED}ERROR: Cannot connect to monerod at $DAEMON_URL${NC}"
    echo "  Please ensure monerod is running: monerod --data-dir /path/to/mainnet-data"
    exit 1
fi

# Check if synced
SYNC_STATUS=$(echo "$DAEMON_STATUS" | grep -o '"synchronized":[^,]*' | cut -d':' -f2 || echo "false")
if [ "$SYNC_STATUS" != "true" ]; then
    echo -e "${RED}ERROR: monerod is not fully synchronized!${NC}"
    echo "  Wait for blockchain sync to complete before starting wallets."
    exit 1
fi

# Check network type (must be mainnet)
NETTYPE=$(echo "$DAEMON_STATUS" | grep -o '"nettype":"[^"]*' | cut -d'"' -f4 || echo "unknown")
if [ "$NETTYPE" != "mainnet" ]; then
    echo -e "${RED}ERROR: Daemon is running on $NETTYPE, expected mainnet!${NC}"
    exit 1
fi

echo -e "${GREEN}  ✓ monerod is running and fully synced on mainnet${NC}"

# Check for Tor
echo "  Checking Tor status..."
if ! pgrep -x "tor" > /dev/null 2>&1; then
    echo -e "${YELLOW}  WARNING: Tor is not running. Hidden service will not work.${NC}"
else
    echo -e "${GREEN}  ✓ Tor daemon is running${NC}"
fi

# =============================================================================
# SETUP DIRECTORIES
# =============================================================================

echo -e "${YELLOW}[2/6] Setting up directories...${NC}"

mkdir -p "$WALLET_DIR"
mkdir -p "$LOG_DIR"

# Secure permissions (owner only)
chmod 700 "$WALLET_DIR"

echo -e "${GREEN}  ✓ Wallet directory: $WALLET_DIR${NC}"
echo -e "${GREEN}  ✓ Log directory: $LOG_DIR${NC}"

# =============================================================================
# KILL EXISTING PROCESSES
# =============================================================================

echo -e "${YELLOW}[3/6] Stopping existing wallet RPC processes...${NC}"

# Kill only specific ports to avoid killing unrelated instances
for port in $BUYER_PORT $VENDOR_PORT $ARBITER_PORT $MONITOR_PORT; do
    PID=$(lsof -t -i:$port 2>/dev/null || true)
    if [ -n "$PID" ]; then
        echo "  Killing process on port $port (PID: $PID)"
        kill -9 $PID 2>/dev/null || true
    fi
done

sleep 2
echo -e "${GREEN}  ✓ Cleared ports${NC}"

# =============================================================================
# START WALLET RPC INSTANCES
# =============================================================================

echo -e "${YELLOW}[4/6] Starting wallet RPC instances...${NC}"

# Common flags for mainnet
# NOTE: No --testnet or --stagenet flag = mainnet
COMMON_FLAGS="--disable-rpc-login --wallet-dir $WALLET_DIR --daemon-address $DAEMON_URL --log-level 1 --rpc-bind-ip 127.0.0.1"

# Start Buyer RPC
echo "  Starting BUYER wallet RPC on port $BUYER_PORT..."
monero-wallet-rpc $COMMON_FLAGS --rpc-bind-port $BUYER_PORT \
    > "$LOG_DIR/wallet-rpc-buyer-$BUYER_PORT.log" 2>&1 &
echo $! > "$LOG_DIR/.wallet-rpc-buyer.pid"
sleep 1

# Start Vendor RPC
echo "  Starting VENDOR wallet RPC on port $VENDOR_PORT..."
monero-wallet-rpc $COMMON_FLAGS --rpc-bind-port $VENDOR_PORT \
    > "$LOG_DIR/wallet-rpc-vendor-$VENDOR_PORT.log" 2>&1 &
echo $! > "$LOG_DIR/.wallet-rpc-vendor.pid"
sleep 1

# Start Arbiter RPC
echo "  Starting ARBITER wallet RPC on port $ARBITER_PORT..."
monero-wallet-rpc $COMMON_FLAGS --rpc-bind-port $ARBITER_PORT \
    > "$LOG_DIR/wallet-rpc-arbiter-$ARBITER_PORT.log" 2>&1 &
echo $! > "$LOG_DIR/.wallet-rpc-arbiter.pid"
sleep 1

# Start Monitor RPC (for blockchain monitoring)
echo "  Starting MONITOR wallet RPC on port $MONITOR_PORT..."
monero-wallet-rpc $COMMON_FLAGS --rpc-bind-port $MONITOR_PORT \
    > "$LOG_DIR/wallet-rpc-monitor-$MONITOR_PORT.log" 2>&1 &
echo $! > "$LOG_DIR/.wallet-rpc-monitor.pid"
sleep 2

echo -e "${GREEN}  ✓ All wallet RPCs starting...${NC}"

# =============================================================================
# VERIFY INSTANCES
# =============================================================================

echo -e "${YELLOW}[5/6] Verifying wallet RPC instances...${NC}"

FAILED=0
for port in $BUYER_PORT $VENDOR_PORT $ARBITER_PORT $MONITOR_PORT; do
    # Give it a moment to start
    sleep 1

    # Check if responding
    RESPONSE=$(curl -s -X POST "http://127.0.0.1:$port/json_rpc" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null || echo '{"error":"failed"}')

    if echo "$RESPONSE" | grep -q '"result"'; then
        echo -e "${GREEN}  ✓ Port $port responding${NC}"
    else
        echo -e "${RED}  ✗ Port $port not responding${NC}"
        FAILED=1
    fi
done

if [ $FAILED -eq 1 ]; then
    echo -e "${RED}ERROR: Some wallet RPCs failed to start. Check logs in $LOG_DIR${NC}"
    exit 1
fi

# =============================================================================
# SECURITY VERIFICATION
# =============================================================================

echo -e "${YELLOW}[6/6] Security verification...${NC}"

# Check no public binding
for port in $BUYER_PORT $VENDOR_PORT $ARBITER_PORT $MONITOR_PORT; do
    BIND=$(netstat -tlnp 2>/dev/null | grep ":$port" | grep -v "127.0.0.1" || true)
    if [ -n "$BIND" ]; then
        echo -e "${RED}CRITICAL: Port $port bound to public interface!${NC}"
        echo -e "${RED}This is a security risk. Shutting down...${NC}"
        killall -9 monero-wallet-rpc 2>/dev/null || true
        exit 1
    fi
done

echo -e "${GREEN}  ✓ All RPCs bound to localhost only${NC}"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo -e "${GREEN}==============================================================================${NC}"
echo -e "${GREEN} MAINNET WALLET RPC INSTANCES READY${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo ""
echo "  Network:  MAINNET"
echo "  Daemon:   $DAEMON_URL"
echo "  Wallets:  $WALLET_DIR"
echo ""
echo "  Instances:"
echo "    - Buyer:    http://127.0.0.1:$BUYER_PORT  → $LOG_DIR/wallet-rpc-buyer-$BUYER_PORT.log"
echo "    - Vendor:   http://127.0.0.1:$VENDOR_PORT  → $LOG_DIR/wallet-rpc-vendor-$VENDOR_PORT.log"
echo "    - Arbiter:  http://127.0.0.1:$ARBITER_PORT  → $LOG_DIR/wallet-rpc-arbiter-$ARBITER_PORT.log"
echo "    - Monitor:  http://127.0.0.1:$MONITOR_PORT  → $LOG_DIR/wallet-rpc-monitor-$MONITOR_PORT.log"
echo ""
echo "  PID files:"
echo "    $LOG_DIR/.wallet-rpc-*.pid"
echo ""
echo -e "${YELLOW}  REMINDER: Source your mainnet environment before starting the server:${NC}"
echo "    source .env.mainnet && ./target/release/server"
echo ""
echo -e "${GREEN}==============================================================================${NC}"
