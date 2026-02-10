#!/bin/bash
# Start 3 Monero Wallet RPC instances for production-ready role-based assignment
#
# Architecture:
# - Port 18082: Buyer wallets
# - Port 18083: Vendor wallets
# - Port 18084: Arbiter wallets

set -e

WALLET_DIR="/var/monero/wallets"
DAEMON_URL="http://127.0.0.1:18081"
LOG_DIR="/home/malix/Desktop/monero.marketplace"

echo "🚀 Starting 3 Monero Wallet RPC instances..."

# Kill any existing instances
echo "🔪 Killing existing wallet RPC processes..."
killall -9 monero-wallet-rpc 2>/dev/null || true
sleep 2

# Start Buyer RPC (port 18082)
echo "▶️  Starting BUYER wallet RPC on port 18082..."
monero-wallet-rpc \
    --rpc-bind-port 18082 \
    --disable-rpc-login \
    --wallet-dir "$WALLET_DIR" \
    --daemon-address "$DAEMON_URL" \
    --testnet \
    --log-level 2 \
    > "$LOG_DIR/monero-wallet-rpc-18082.log" 2>&1 &

sleep 1

# Start Vendor RPC (port 18083)
echo "▶️  Starting VENDOR wallet RPC on port 18083..."
monero-wallet-rpc \
    --rpc-bind-port 18083 \
    --disable-rpc-login \
    --wallet-dir "$WALLET_DIR" \
    --daemon-address "$DAEMON_URL" \
    --testnet \
    --log-level 2 \
    > "$LOG_DIR/monero-wallet-rpc-18083.log" 2>&1 &

sleep 1

# Start Arbiter RPC (port 18084)
echo "▶️  Starting ARBITER wallet RPC on port 18084..."
monero-wallet-rpc \
    --rpc-bind-port 18084 \
    --disable-rpc-login \
    --wallet-dir "$WALLET_DIR" \
    --daemon-address "$DAEMON_URL" \
    --testnet \
    --log-level 2 \
    > "$LOG_DIR/monero-wallet-rpc-18084.log" 2>&1 &

sleep 2

# Verify all instances are running
echo ""
echo "✅ Verification:"
ps aux | grep monero-wallet-rpc | grep -v grep | grep -E "18082|18083|18084" || {
    echo "❌ ERROR: Not all RPC instances started"
    exit 1
}

echo ""
echo "✅ All 3 Wallet RPC instances running:"
echo "   - Port 18082 (Buyer)   → $LOG_DIR/monero-wallet-rpc-18082.log"
echo "   - Port 18083 (Vendor)  → $LOG_DIR/monero-wallet-rpc-18083.log"
echo "   - Port 18084 (Arbiter) → $LOG_DIR/monero-wallet-rpc-18084.log"
echo ""
echo "🎯 Ready for production-ready role-based wallet assignment!"
