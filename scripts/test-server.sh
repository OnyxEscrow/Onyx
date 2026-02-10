#!/bin/bash
# Test Monero Marketplace Server
# Usage: ./scripts/test-server.sh

set -e

cd "$(dirname "$0")/.."

echo "🧪 Testing Monero Marketplace Server"
echo "====================================="
echo ""

# Source cargo environment
if [ -f ~/.cargo/env ]; then
    source ~/.cargo/env
fi

# Check if server is already running
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "⚠️  Server already running on port 8080"
    echo ""
else
    echo "🚀 Starting server in background..."
    cargo run --bin server > /tmp/monero-server.log 2>&1 &
    SERVER_PID=$!
    echo "   Server PID: $SERVER_PID"
    echo "   Waiting 3 seconds for server to start..."
    sleep 3

    # Check if server is still running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "❌ Server failed to start. Check logs:"
        cat /tmp/monero-server.log
        exit 1
    fi
    echo "✅ Server started successfully"
    echo ""
fi

echo "📡 Testing Endpoints"
echo "-------------------"
echo ""

# Test 1: Health endpoint
echo "Test 1: GET /api/health"
HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" http://127.0.0.1:8080/api/health 2>/dev/null || echo "FAILED")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
BODY=$(echo "$HEALTH_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Status: $HTTP_CODE OK"
    echo "   Response: $BODY"
else
    echo "❌ Status: $HTTP_CODE (expected 200)"
    echo "   Response: $BODY"
fi
echo ""

# Test 2: Root endpoint
echo "Test 2: GET /"
ROOT_RESPONSE=$(curl -s -w "\n%{http_code}" http://127.0.0.1:8080/ 2>/dev/null || echo "FAILED")
HTTP_CODE=$(echo "$ROOT_RESPONSE" | tail -n1)
BODY=$(echo "$ROOT_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Status: $HTTP_CODE OK"
    echo "   Response: $BODY"
else
    echo "❌ Status: $HTTP_CODE (expected 200)"
    echo "   Response: $BODY"
fi
echo ""

# Test 3: 404 endpoint
echo "Test 3: GET /nonexistent (should return 404)"
NOT_FOUND_RESPONSE=$(curl -s -w "\n%{http_code}" http://127.0.0.1:8080/nonexistent 2>/dev/null || echo "FAILED")
HTTP_CODE=$(echo "$NOT_FOUND_RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "404" ]; then
    echo "✅ Status: $HTTP_CODE (correctly returns 404)"
else
    echo "❌ Status: $HTTP_CODE (expected 404)"
fi
echo ""

echo "=========================================="
echo "🎉 Server Tests Complete!"
echo "=========================================="
echo ""

if [ -n "$SERVER_PID" ]; then
    echo "Server is still running with PID: $SERVER_PID"
    echo ""
    echo "To stop the server:"
    echo "  kill $SERVER_PID"
    echo ""
    echo "To view logs:"
    echo "  tail -f /tmp/monero-server.log"
else
    echo "Server was already running before tests"
    echo ""
    echo "To stop the server:"
    echo "  pkill -f 'cargo run --bin server'"
    echo "  # or"
    echo "  lsof -ti:8080 | xargs kill"
fi
echo ""
