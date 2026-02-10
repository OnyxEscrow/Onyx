#!/bin/bash
# Test script for multisig wallet synchronization
# Tests the new sync_multisig_wallets() implementation with real testnet escrow

set -euo pipefail

ESCROW_ID="32eff079-b7d0-4b8a-9bc0-095e0e2ebdab"

echo "=========================================="
echo "Multisig Wallet Sync Test"
echo "=========================================="
echo ""
echo "Escrow ID: $ESCROW_ID"
echo "Expected balance: 0.005 XMR (5000000000000 atomic units)"
echo ""

# Check if wallet RPCs are running
echo "Checking wallet RPC status..."
for port in 18082 18083 18084; do
    if ! curl -s --fail http://127.0.0.1:$port/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' > /dev/null 2>&1; then
        echo "❌ ERROR: Wallet RPC on port $port is not running!"
        exit 1
    fi
    echo "✅ Wallet RPC on port $port is running"
done

echo ""
echo "All RPC instances are running. Ready to test sync."
echo ""
echo "To test the sync function, we need to add a CLI command or API endpoint."
echo "The sync_multisig_wallets() method is now implemented in WalletManager."
echo ""
echo "Next steps:"
echo "1. Add API endpoint: POST /api/escrows/{id}/check_balance"
echo "2. Test via HTTP request to trigger sync"
echo "3. Verify balance is visible (5000000000000 atomic units)"
