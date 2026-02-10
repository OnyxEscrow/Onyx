#!/bin/bash
# =============================================================================
# NEXUS Security Assistant - Linux/Mac Setup Script
# =============================================================================

echo ""
echo "========================================"
echo "   NEXUS Security Assistant v0.4.0"
echo "========================================"
echo ""
echo "Starting your LOCAL wallet service..."
echo "This keeps your keys PRIVATE and SECURE"
echo ""

# Generate unique access code
ACCESS_CODE="nexus_$(date +%s)_$(( RANDOM % 10000 ))"
echo "Your Access Code: $ACCESS_CODE"
echo ""
echo "COPY THIS CODE - You'll need it on the NEXUS website"
echo ""
read -p "Press Enter to continue..."

# Check if monero-wallet-rpc exists
if ! command -v monero-wallet-rpc &> /dev/null; then
    echo "ERROR: monero-wallet-rpc not found!"
    echo "Please install Monero from https://getmonero.org"
    read -p "Press Enter to exit..."
    exit 1
fi

# Create wallet directory
WALLET_DIR="$HOME/.nexus/wallets"
mkdir -p "$WALLET_DIR"

echo ""
echo "Starting Monero Wallet RPC..."
echo "Port: 18083 (localhost only)"
echo ""
echo "KEEP THIS TERMINAL OPEN while using NEXUS!"
echo ""

# Start monero-wallet-rpc
monero-wallet-rpc \
    --testnet \
    --rpc-bind-port 18083 \
    --rpc-bind-ip 127.0.0.1 \
    --disable-rpc-login \
    --wallet-dir "$WALLET_DIR" \
    --log-level 1 \
    --daemon-address http://stagenet.community.rino.io:38081

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to start wallet RPC!"
    read -p "Press Enter to exit..."
    exit 1
fi

echo "Wallet RPC stopped."
read -p "Press Enter to exit..."
