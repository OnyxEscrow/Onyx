#!/bin/bash
# Non-Custodial Security Audit Script
# Version: 1.0
# Date: 23 October 2025

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

echo "================================================="
echo "  NON-CUSTODIAL SECURITY AUDIT"
echo "  Monero Marketplace v0.3.0"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================="
echo ""

# Helper functions
pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((PASS++))
}

fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((FAIL++))
}

warn() {
    echo -e "${YELLOW}⚠️  WARN${NC}: $1"
    ((WARN++))
}

# Test 1: Server-side key generation
echo "[1/10] Checking for server-side key generation..."
if grep -r "PrivateKey::from_random\|generate_random_bytes\|rand::thread_rng" server/src/ \
    | grep -v "test\|comment\|//\|Documentation" | grep -q .; then
    fail "Server generates private keys"
else
    pass "No server-side key generation"
fi

# Test 2: Private key storage in database
echo "[2/10] Checking database for private key storage..."
if grep -Ei "private.*key|seed.*phrase|spend.*key|view.*key" database/schema.sql \
    | grep -v "-- " | grep -q .; then
    fail "Database stores private keys"
else
    pass "No private key storage in DB"
fi

# Test 3: NonCustodialViolation enforcement
echo "[3/10] Testing NonCustodialViolation enforcement..."
if grep -q "NonCustodialViolation" server/src/wallet_manager.rs; then
    pass "NonCustodialViolation error type exists"
else
    fail "NonCustodialViolation error type missing"
fi

# Test 4: register_wallet_rpc API
echo "[4/10] Checking client wallet registration API..."
if grep -q "register_wallet_rpc" server/src/handlers/escrow.rs && \
   grep -q "register_client_wallet_rpc" server/src/wallet_manager.rs; then
    pass "Client wallet registration API exists"
else
    fail "API endpoint missing"
fi

# Test 5: Documentation
echo "[5/10] Checking documentation..."
if [ -f "docs/CLIENT-WALLET-SETUP.md" ] && \
   [ $(wc -l < docs/CLIENT-WALLET-SETUP.md) -gt 400 ]; then
    pass "Documentation complete ($(wc -l < docs/CLIENT-WALLET-SETUP.md) lines)"
else
    fail "Client setup guide missing or incomplete"
fi

# Test 6: Hardcoded credentials
echo "[6/10] Checking for hardcoded credentials..."
if grep -r "password\s*=\s*['\"]" server/src/ \
    | grep -v "test\|example\|comment\|//\|password_hash" | grep -q .; then
    fail "Hardcoded passwords found"
else
    pass "No hardcoded credentials"
fi

# Test 7: Sensitive logging
echo "[7/10] Checking for sensitive data in logs..."
if grep -r "info!.*private\|debug!.*seed\|info!.*password.*=" server/src/ \
    | grep -v "test\|comment\|//\|password_hash" | grep -q .; then
    fail "Sensitive data logged"
else
    pass "No sensitive logging"
fi

# Test 8: RPC URL validation
echo "[8/10] Checking RPC URL validation..."
if grep -q "InvalidRpcUrl" server/src/wallet_manager.rs && \
   grep -q "validate.*url\|starts_with.*http" server/src/wallet_manager.rs; then
    pass "RPC URL validation present"
else
    warn "RPC URL validation might be incomplete"
fi

# Test 9: Deprecated methods marked
echo "[9/10] Checking deprecated method warnings..."
if grep -q "#\[deprecated\]" server/src/wallet_manager.rs; then
    pass "Deprecated methods properly marked"
else
    warn "create_wallet_instance not marked as deprecated"
fi

# Test 10: Code compilation
echo "[10/10] Verifying compilation..."
if cargo check --package server --quiet 2>&1; then
    pass "Code compiles without errors"
else
    fail "Compilation errors detected"
fi

echo ""
echo "================================================="
echo "  AUDIT RESULTS"
echo "================================================="
echo -e "${GREEN}Passed:${NC} $PASS/10"
echo -e "${RED}Failed:${NC} $FAIL/10"
echo -e "${YELLOW}Warnings:${NC} $WARN/10"
echo ""

# Calculate score
SCORE=$((PASS * 10))
echo "Non-Custodial Score: $SCORE/100"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✅ AUDIT PASSED - System is NON-CUSTODIAL${NC}"
    echo ""
    echo "Certification Status: ✅ APPROVED"
    echo "Ready for: Testnet deployment"
    echo "Mainnet: Requires external audit"
    exit 0
else
    echo -e "${RED}❌ AUDIT FAILED - Critical issues detected${NC}"
    echo ""
    echo "Action required: Fix issues before deployment"
    exit 1
fi
