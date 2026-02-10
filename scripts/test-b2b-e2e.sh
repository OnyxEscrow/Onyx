#!/bin/bash
# ============================================================================
# B2B E2E Test: API Key → Escrow Create → Webhook Fire
# ============================================================================
# Prerequisites:
#   1. Backend running on http://127.0.0.1:8080
#   2. Database with migrations applied
#   3. At least one user account (uses debug test-login if available)
# ============================================================================

set -euo pipefail

BASE_URL="http://127.0.0.1:8080"
COOKIE_JAR="/tmp/nexus-b2b-test-cookies.txt"
WEBHOOK_LOG="/tmp/nexus-webhook-test.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✅ $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}📋 $1${NC}"; }

cleanup() {
    rm -f "$COOKIE_JAR"
    # Kill webhook listener if running
    if [ -n "${WEBHOOK_PID:-}" ]; then
        kill "$WEBHOOK_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "============================================"
echo "  NEXUS B2B E2E Test Suite"
echo "============================================"
echo ""

# ── Step 0: Check server is running ──────────────────────────────────────
info "Step 0: Checking server connectivity..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" != "200" ]; then
    fail "Server not reachable at $BASE_URL (HTTP $HTTP_CODE). Start it first."
fi
pass "Server is running"

# ── Step 1: Authenticate (create session) ────────────────────────────────
info "Step 1: Authenticating..."

# Try debug test-login first (dev mode)
AUTH_RESPONSE=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/debug/test-login" \
    -H "Content-Type: application/json" \
    -d '{
        "user_id": "b2b-test-user-00000000-0000-0000-0000-000000000001",
        "username": "b2b_test_partner",
        "role": "vendor"
    }' 2>/dev/null || echo '{"error":"not available"}')

if echo "$AUTH_RESPONSE" | grep -q '"success":true'; then
    pass "Authenticated via debug test-login"
else
    # Fall back to regular login
    info "Debug login not available, trying regular auth..."
    AUTH_RESPONSE=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "$BASE_URL/api/auth/login-json" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "arbiter_system",
            "password": "'"${ARBITER_PASSWORD:-admin123}"'"
        }' 2>/dev/null || echo '{"error":"auth failed"}')

    if echo "$AUTH_RESPONSE" | grep -q '"success"'; then
        pass "Authenticated via regular login"
    else
        fail "Cannot authenticate. Set ARBITER_PASSWORD or enable debug-endpoints feature.\nResponse: $AUTH_RESPONSE"
    fi
fi

# Verify session works
WHOAMI=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/auth/whoami" 2>/dev/null)
if echo "$WHOAMI" | grep -q "user_id"; then
    USER_ID=$(echo "$WHOAMI" | python3 -c "import sys,json; print(json.load(sys.stdin).get('user_id',''))" 2>/dev/null || echo "unknown")
    pass "Session valid (user: $USER_ID)"
else
    fail "Session invalid. Whoami response: $WHOAMI"
fi

# ── Step 2: Create API Key ───────────────────────────────────────────────
info "Step 2: Creating API key..."

# Get CSRF token from session
CSRF_TOKEN=$(echo "$WHOAMI" | python3 -c "import sys,json; print(json.load(sys.stdin).get('csrf_token',''))" 2>/dev/null || echo "")

# If no CSRF token in whoami, try without it (some endpoints may not require it)
API_KEY_RESPONSE=$(curl -s -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/api-keys" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "B2B Test Partner Key",
        "csrf_token": "'"${CSRF_TOKEN}"'",
        "metadata": "{\"partner\": \"e2e-test\"}"
    }' 2>/dev/null)

echo "  API Key Response: $API_KEY_RESPONSE"

# Extract the raw API key (only shown once)
RAW_KEY=$(echo "$API_KEY_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # Try different response shapes
    key = data.get('raw_key') or data.get('api_key') or data.get('key') or ''
    print(key)
except:
    print('')
" 2>/dev/null || echo "")

if [ -z "$RAW_KEY" ]; then
    fail "Failed to create API key. Response: $API_KEY_RESPONSE"
fi
pass "API key created: ${RAW_KEY:0:12}..."

# ── Step 3: Start webhook listener ──────────────────────────────────────
info "Step 3: Starting webhook listener on port 9999..."

# Start a simple HTTP server to capture webhook deliveries
> "$WEBHOOK_LOG"
python3 -c "
import http.server, json, sys, threading

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        sig = self.headers.get('X-Nexus-Signature', 'none')
        event = self.headers.get('X-Nexus-Event', 'unknown')
        with open('$WEBHOOK_LOG', 'a') as f:
            f.write(json.dumps({
                'event': event,
                'signature': sig,
                'body': json.loads(body) if body else {},
                'timestamp': __import__('datetime').datetime.utcnow().isoformat()
            }) + '\n')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"ok\":true}')
    def log_message(self, format, *args):
        pass  # Suppress logs

server = http.server.HTTPServer(('127.0.0.1', 9999), WebhookHandler)
server.handle_request()  # Handle exactly 1 request then exit
server.handle_request()  # Handle 2nd (in case of retry)
" &
WEBHOOK_PID=$!
sleep 0.5
pass "Webhook listener running (PID: $WEBHOOK_PID)"

# ── Step 4: Register webhook via API key ─────────────────────────────────
info "Step 4: Registering webhook..."

WEBHOOK_RESPONSE=$(curl -s \
    -X POST "$BASE_URL/api/v1/webhooks" \
    -H "Authorization: Bearer $RAW_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "url": "http://127.0.0.1:9999/webhook",
        "events": ["escrow.created", "escrow.funded", "escrow.shipped", "escrow.released"],
        "description": "B2B E2E test webhook"
    }' 2>/dev/null)

echo "  Webhook Response: $WEBHOOK_RESPONSE"

WEBHOOK_ID=$(echo "$WEBHOOK_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('id') or data.get('webhook_id') or data.get('webhook', {}).get('id', ''))
except:
    print('')
" 2>/dev/null || echo "")

if [ -z "$WEBHOOK_ID" ]; then
    info "Webhook registration may have failed (non-critical). Continuing..."
else
    pass "Webhook registered: $WEBHOOK_ID"
fi

# ── Step 5: Create escrow via B2B API ────────────────────────────────────
info "Step 5: Creating escrow via /api/v1/escrows/create..."

ESCROW_RESPONSE=$(curl -s \
    -X POST "$BASE_URL/api/v1/escrows/create" \
    -H "Authorization: Bearer $RAW_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "amount": 500000000000,
        "role": "buyer",
        "external_reference": "B2B-TEST-001",
        "description": "B2B E2E test escrow"
    }' 2>/dev/null)

echo "  Escrow Response: $ESCROW_RESPONSE"

ESCROW_ID=$(echo "$ESCROW_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('escrow_id') or data.get('id') or '')
except:
    print('')
" 2>/dev/null || echo "")

if [ -z "$ESCROW_ID" ]; then
    fail "Failed to create escrow via B2B API. Response: $ESCROW_RESPONSE"
fi
pass "Escrow created: $ESCROW_ID"

# ── Step 6: Verify escrow via B2B API ────────────────────────────────────
info "Step 6: Fetching escrow via /api/v1/escrows/$ESCROW_ID..."

ESCROW_DETAIL=$(curl -s \
    -H "Authorization: Bearer $RAW_KEY" \
    "$BASE_URL/api/v1/escrows/$ESCROW_ID" 2>/dev/null)

echo "  Escrow Detail: $(echo "$ESCROW_DETAIL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({k:d[k] for k in ['id','status','amount','external_reference'] if k in d}, indent=2))" 2>/dev/null || echo "$ESCROW_DETAIL")"

if echo "$ESCROW_DETAIL" | grep -q "$ESCROW_ID"; then
    pass "Escrow retrievable via B2B API"
else
    info "Escrow fetch returned unexpected response (non-critical)"
fi

# ── Step 7: Check webhook delivery ───────────────────────────────────────
info "Step 7: Checking webhook delivery..."
sleep 2  # Wait for async webhook delivery

if [ -s "$WEBHOOK_LOG" ]; then
    pass "Webhook fired!"
    echo "  Webhook payload:"
    cat "$WEBHOOK_LOG" | python3 -c "
import sys, json
for line in sys.stdin:
    data = json.loads(line.strip())
    print(f\"    Event: {data['event']}\")
    print(f\"    Signature: {data['signature'][:20]}...\")
    print(f\"    Escrow ID: {data['body'].get('escrow_id', 'N/A')}\")
" 2>/dev/null || cat "$WEBHOOK_LOG"
else
    info "No webhook received (webhook delivery is async — may need retry worker cycle)"
    info "Check server logs for webhook dispatch activity"
fi

# ── Step 8: Test fee estimation endpoint ─────────────────────────────────
info "Step 8: Testing fee estimation..."

FEE_RESPONSE=$(curl -s \
    -H "Authorization: Bearer $RAW_KEY" \
    "$BASE_URL/api/v1/client/fees/estimate?amount_atomic=1000000000000&is_refund=false" 2>/dev/null)

echo "  Fee Response: $FEE_RESPONSE"

if echo "$FEE_RESPONSE" | grep -q "fee_bps"; then
    pass "Fee estimation endpoint working"
else
    info "Fee endpoint returned unexpected response (may need session auth)"
fi

# ── Step 9: Test analytics endpoint ──────────────────────────────────────
info "Step 9: Testing analytics..."

ANALYTICS_RESPONSE=$(curl -s \
    -H "Authorization: Bearer $RAW_KEY" \
    "$BASE_URL/api/v1/analytics/usage?period=30d" 2>/dev/null)

echo "  Analytics Response: $ANALYTICS_RESPONSE"

if echo "$ANALYTICS_RESPONSE" | grep -q "total_escrows"; then
    pass "Analytics endpoint working"
else
    info "Analytics endpoint returned unexpected response"
fi

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  B2B E2E Test Complete"
echo "============================================"
echo ""
echo "  API Key:    ${RAW_KEY:0:12}..."
echo "  Escrow ID:  ${ESCROW_ID}"
echo "  Webhook ID: ${WEBHOOK_ID:-N/A}"
echo "  Webhook Log: $WEBHOOK_LOG"
echo ""
echo "  Next steps:"
echo "    1. Add CORS_ALLOWED_ORIGINS in .env for partner domains"
echo "    2. Upgrade API key tier: POST /admin/api-keys/{id}/tier"
echo "    3. Monitor webhooks: GET /api/v1/webhooks/{id}/deliveries"
echo ""
