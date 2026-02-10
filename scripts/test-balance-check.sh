#!/bin/bash
# Test the check_escrow_balance API endpoint
# This tests the complete lazy sync flow with real testnet XMR

set -euo pipefail

ESCROW_ID="32eff079-b7d0-4b8a-9bc0-095e0e2ebdab"
SERVER_URL="http://127.0.0.1:8080"

echo "=========================================="
echo "Testing Escrow Balance Check API"
echo "=========================================="
echo ""
echo "Escrow ID: $ESCROW_ID"
echo "Expected balance: 0.005 XMR (5000000000000 atomic units)"
echo ""

# Check if server is running
if ! curl -s --fail "${SERVER_URL}/health" > /dev/null 2>&1; then
    echo "❌ ERROR: Server is not running on ${SERVER_URL}"
    echo "Start server with: ./target/release/server"
    exit 1
fi

echo "✅ Server is running"
echo ""

# Check if wallet RPCs are running
echo "Checking wallet RPC status..."
for port in 18082 18083 18084; do
    if ! curl -s --fail http://127.0.0.1:$port/json_rpc \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' > /dev/null 2>&1; then
        echo "❌ ERROR: Wallet RPC on port $port is not running!"
        exit 1
    fi
    echo "✅ Wallet RPC on port $port is running"
done

echo ""
echo "=== Calling check-balance API ==="
echo "POST ${SERVER_URL}/api/escrow/${ESCROW_ID}/check-balance"
echo ""

# Make API request (this will trigger multisig sync)
response=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -b "session=test_session" \
    "${SERVER_URL}/api/escrow/${ESCROW_ID}/check-balance" 2>&1)

http_code=$(echo "$response" | tail -1)
body=$(echo "$response" | head -n -1)

echo "HTTP Status: $http_code"
echo ""

if [ "$http_code" -eq 200 ]; then
    echo "✅ SUCCESS: Balance check completed"
    echo ""
    echo "Response:"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    echo ""

    # Extract balance
    balance_xmr=$(echo "$body" | jq -r '.balance_xmr' 2>/dev/null || echo "unknown")
    unlocked_xmr=$(echo "$body" | jq -r '.unlocked_balance_xmr' 2>/dev/null || echo "unknown")

    echo "Balance: $balance_xmr XMR"
    echo "Unlocked: $unlocked_xmr XMR"

    if [ "$balance_xmr" != "unknown" ] && [ "$balance_xmr" != "0.000000000000" ]; then
        echo ""
        echo "🎉 BALANCE VISIBLE! The multisig sync worked!"
    else
        echo ""
        echo "⚠️  Balance is still 0. Check server logs for details."
    fi
elif [ "$http_code" -eq 401 ]; then
    echo "❌ AUTHENTICATION REQUIRED"
    echo ""
    echo "You need to be logged in to check escrow balance."
    echo "This is expected behavior for the API endpoint."
    echo ""
    echo "To test with authentication:"
    echo "1. Log in via the web UI at http://127.0.0.1:8080"
    echo "2. Use your browser's session cookie"
    echo "3. Or create a test session in the database"
else
    echo "❌ ERROR: Unexpected response"
    echo ""
    echo "$body"
fi

echo ""
echo "Check server logs for detailed sync information:"
echo "tail -f server.log | grep -E '(sync|balance|multisig)'"
