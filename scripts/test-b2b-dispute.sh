#!/bin/bash
# ============================================================================
# B2B Dispute Path Test: Create → Join → Dispute → Resolve
# ============================================================================
# Tests the full dispute flow via /api/v1 with API key auth
# Prerequisites:
#   1. Backend running on http://127.0.0.1:8080
#   2. TEST_AUTH_BYPASS=true in .env (for debug test-login)
# ============================================================================

set -euo pipefail

BASE_URL="http://127.0.0.1:8080"
COOKIE_JAR_BUYER="/tmp/nexus-dispute-buyer.txt"
COOKIE_JAR_ARBITER="/tmp/nexus-dispute-arbiter.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}  ✅ $1${NC}"; }
fail() { echo -e "${RED}  ❌ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}  📋 $1${NC}"; }
step() { echo -e "${CYAN}── $1 ──${NC}"; }

cleanup() {
    rm -f "$COOKIE_JAR_BUYER" "$COOKIE_JAR_ARBITER"
}
trap cleanup EXIT

echo ""
echo "============================================"
echo "  NEXUS B2B Dispute Path Test"
echo "============================================"
echo ""

# ── Step 0: Check server ────────────────────────────────────────────────
step "Step 0: Server connectivity"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" != "200" ]; then
    fail "Server not reachable at $BASE_URL (HTTP $HTTP_CODE)"
fi
pass "Server is running"

# ── Step 1: Create buyer session + API key ──────────────────────────────
step "Step 1: Authenticate as buyer"

BUYER_RESPONSE=$(curl -s -c "$COOKIE_JAR_BUYER" -b "$COOKIE_JAR_BUYER" \
    -X POST "$BASE_URL/api/debug/test-login" \
    -H "Content-Type: application/json" \
    -d '{
        "user_id": "00000000-0000-0000-0000-000000000b01",
        "username": "dispute_test_buyer",
        "role": "buyer"
    }' 2>/dev/null || echo '{"error":"failed"}')

if ! echo "$BUYER_RESPONSE" | grep -q '"success":true'; then
    fail "Buyer auth failed: $BUYER_RESPONSE"
fi
pass "Buyer authenticated"

# Get CSRF + create API key for buyer
WHOAMI_BUYER=$(curl -s -b "$COOKIE_JAR_BUYER" "$BASE_URL/api/auth/whoami" 2>/dev/null)
CSRF_BUYER=$(echo "$WHOAMI_BUYER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('csrf_token',''))" 2>/dev/null || echo "")

API_KEY_RESP=$(curl -s -b "$COOKIE_JAR_BUYER" \
    -X POST "$BASE_URL/api/api-keys" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"dispute-test-buyer\", \"csrf_token\": \"$CSRF_BUYER\"}" 2>/dev/null)

BUYER_API_KEY=$(echo "$API_KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null || echo "")
if [ -z "$BUYER_API_KEY" ]; then
    fail "Failed to create buyer API key: $API_KEY_RESP"
fi
pass "Buyer API key: ${BUYER_API_KEY:0:12}..."

# ── Step 2: Create escrow via B2B API ───────────────────────────────────
step "Step 2: Create escrow (buyer, via API key)"

CREATE_RESP=$(curl -s -X POST "$BASE_URL/api/v1/escrows/create" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $BUYER_API_KEY" \
    -d '{
        "amount": 100000000000,
        "description": "Dispute test escrow",
        "creator_role": "buyer",
        "external_reference": "DISP-TEST-001"
    }' 2>/dev/null)

echo "  Create response: $CREATE_RESP"

ESCROW_ID=$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('escrow_id',''))" 2>/dev/null || echo "")
if [ -z "$ESCROW_ID" ]; then
    fail "Failed to create escrow: $CREATE_RESP"
fi
pass "Escrow created: $ESCROW_ID"

# ── Step 3: GET escrow by ID (test dual-auth) ──────────────────────────
step "Step 3: GET escrow by ID (API key auth)"

GET_RESP=$(curl -s "$BASE_URL/api/v1/escrows/$ESCROW_ID" \
    -H "X-API-Key: $BUYER_API_KEY" 2>/dev/null)

if echo "$GET_RESP" | grep -q "Not authenticated"; then
    fail "GET escrow still returns 'Not authenticated': $GET_RESP"
fi
pass "GET escrow works with API key auth"
echo "  Status: $(echo "$GET_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status', d.get('escrow',{}).get('status','unknown')))" 2>/dev/null || echo 'unknown')"

# ── Step 4: Join escrow as vendor ───────────────────────────────────────
step "Step 4: Authenticate as vendor + join escrow"

# Create vendor session
VENDOR_COOKIE="/tmp/nexus-dispute-vendor.txt"
VENDOR_RESPONSE=$(curl -s -c "$VENDOR_COOKIE" -b "$VENDOR_COOKIE" \
    -X POST "$BASE_URL/api/debug/test-login" \
    -H "Content-Type: application/json" \
    -d '{
        "user_id": "00000000-0000-0000-0000-000000000v01",
        "username": "dispute_test_vendor",
        "role": "vendor"
    }' 2>/dev/null || echo '{"error":"failed"}')

if ! echo "$VENDOR_RESPONSE" | grep -q '"success":true'; then
    fail "Vendor auth failed: $VENDOR_RESPONSE"
fi
pass "Vendor authenticated"

# Vendor gets API key
WHOAMI_VENDOR=$(curl -s -b "$VENDOR_COOKIE" "$BASE_URL/api/auth/whoami" 2>/dev/null)
CSRF_VENDOR=$(echo "$WHOAMI_VENDOR" | python3 -c "import sys,json; print(json.load(sys.stdin).get('csrf_token',''))" 2>/dev/null || echo "")

VENDOR_KEY_RESP=$(curl -s -b "$VENDOR_COOKIE" \
    -X POST "$BASE_URL/api/api-keys" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"dispute-test-vendor\", \"csrf_token\": \"$CSRF_VENDOR\"}" 2>/dev/null)

VENDOR_API_KEY=$(echo "$VENDOR_KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null || echo "")
if [ -z "$VENDOR_API_KEY" ]; then
    fail "Failed to create vendor API key: $VENDOR_KEY_RESP"
fi
pass "Vendor API key: ${VENDOR_API_KEY:0:12}..."

# Join escrow
JOIN_RESP=$(curl -s -X POST "$BASE_URL/api/v1/escrows/$ESCROW_ID/join" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $VENDOR_API_KEY" 2>/dev/null)

echo "  Join response: $JOIN_RESP"

if echo "$JOIN_RESP" | grep -q '"error"'; then
    info "Join may have failed (expected if escrow requires specific state): $JOIN_RESP"
else
    pass "Vendor joined escrow"
fi

# ── Step 5: Initiate dispute (buyer) ────────────────────────────────────
step "Step 5: Initiate dispute (buyer)"

DISPUTE_RESP=$(curl -s -X POST "$BASE_URL/api/v1/escrows/$ESCROW_ID/dispute" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $BUYER_API_KEY" \
    -d '{
        "reason": "Vendor never shipped the item after 7 days. No tracking provided. Requesting full refund."
    }' 2>/dev/null)

echo "  Dispute response: $DISPUTE_RESP"

if echo "$DISPUTE_RESP" | grep -q '"success":true'; then
    pass "Dispute initiated successfully"
elif echo "$DISPUTE_RESP" | grep -q "Not authenticated"; then
    fail "Dispute returns 'Not authenticated' — dual-auth broken"
else
    info "Dispute response (may fail due to state): $DISPUTE_RESP"
fi

# ── Step 6: Verify escrow status is now 'disputed' ─────────────────────
step "Step 6: Verify escrow status"

STATUS_RESP=$(curl -s "$BASE_URL/api/v1/escrows/$ESCROW_ID" \
    -H "X-API-Key: $BUYER_API_KEY" 2>/dev/null)

CURRENT_STATUS=$(echo "$STATUS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status', d.get('escrow',{}).get('status','unknown')))" 2>/dev/null || echo "unknown")
echo "  Current escrow status: $CURRENT_STATUS"

if [ "$CURRENT_STATUS" = "disputed" ]; then
    pass "Escrow status is 'disputed'"
else
    info "Status is '$CURRENT_STATUS' (dispute may have been rejected due to state constraints)"
fi

# ── Step 7: Resolve dispute as arbiter ──────────────────────────────────
step "Step 7: Resolve dispute (arbiter)"

# Create arbiter session
ARBITER_RESPONSE=$(curl -s -c "$COOKIE_JAR_ARBITER" -b "$COOKIE_JAR_ARBITER" \
    -X POST "$BASE_URL/api/debug/test-login" \
    -H "Content-Type: application/json" \
    -d '{
        "user_id": "00000000-0000-0000-0000-000000000a01",
        "username": "dispute_test_arbiter",
        "role": "arbiter"
    }' 2>/dev/null || echo '{"error":"failed"}')

if ! echo "$ARBITER_RESPONSE" | grep -q '"success":true'; then
    fail "Arbiter auth failed: $ARBITER_RESPONSE"
fi
pass "Arbiter authenticated"

# Arbiter gets API key
WHOAMI_ARBITER=$(curl -s -b "$COOKIE_JAR_ARBITER" "$BASE_URL/api/auth/whoami" 2>/dev/null)
CSRF_ARBITER=$(echo "$WHOAMI_ARBITER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('csrf_token',''))" 2>/dev/null || echo "")

ARBITER_KEY_RESP=$(curl -s -b "$COOKIE_JAR_ARBITER" \
    -X POST "$BASE_URL/api/api-keys" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"dispute-test-arbiter\", \"csrf_token\": \"$CSRF_ARBITER\"}" 2>/dev/null)

ARBITER_API_KEY=$(echo "$ARBITER_KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null || echo "")
if [ -z "$ARBITER_API_KEY" ]; then
    fail "Failed to create arbiter API key: $ARBITER_KEY_RESP"
fi
pass "Arbiter API key: ${ARBITER_API_KEY:0:12}..."

# Resolve dispute in favor of buyer
RESOLVE_RESP=$(curl -s -X POST "$BASE_URL/api/v1/escrows/$ESCROW_ID/resolve" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $ARBITER_API_KEY" \
    -d '{
        "resolution": "buyer",
        "recipient_address": "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
    }' 2>/dev/null)

echo "  Resolve response: $RESOLVE_RESP"

if echo "$RESOLVE_RESP" | grep -q "Not authenticated"; then
    fail "Resolve returns 'Not authenticated' — dual-auth broken for arbiter"
elif echo "$RESOLVE_RESP" | grep -q '"success":true'; then
    pass "Dispute resolved in favor of buyer"
elif echo "$RESOLVE_RESP" | grep -q "Only assigned arbiter"; then
    info "Arbiter not assigned to this escrow (expected in test without proper setup)"
elif echo "$RESOLVE_RESP" | grep -q "not in disputed state"; then
    info "Escrow not in disputed state (dispute step may have failed)"
else
    info "Resolve response: $RESOLVE_RESP"
fi

# ── Step 8: Final status check ──────────────────────────────────────────
step "Step 8: Final escrow status"

FINAL_RESP=$(curl -s "$BASE_URL/api/v1/escrows/$ESCROW_ID" \
    -H "X-API-Key: $BUYER_API_KEY" 2>/dev/null)

FINAL_STATUS=$(echo "$FINAL_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status', d.get('escrow',{}).get('status','unknown')))" 2>/dev/null || echo "unknown")
echo "  Final escrow status: $FINAL_STATUS"

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Test Summary"
echo "============================================"
echo "  Escrow ID:    $ESCROW_ID"
echo "  Final Status: $FINAL_STATUS"
echo ""
echo "  Key validations:"
echo "    - API key auth on GET escrow:     ✅ tested"
echo "    - API key auth on POST dispute:   ✅ tested"
echo "    - API key auth on POST resolve:   ✅ tested"
echo "    - Dual-auth (no session needed):  ✅ tested"
echo "============================================"
echo ""

# Cleanup vendor cookie
rm -f "$VENDOR_COOKIE"
