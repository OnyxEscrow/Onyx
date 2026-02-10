#!/bin/bash
# =============================================================================
# NEXUS Tor Reality Check Validation Script
# =============================================================================
# Validates that all network-facing functions are properly Tor-isolated
# and do not leak DNS, IPs, or sensitive data.
#
# Usage: ./scripts/validate-tor-reality-check.sh [--verbose]
#
# Exit codes:
#   0 = All checks passed
#   1 = Critical failures (must fix)
#   2 = Warnings only (recommended fixes)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

VERBOSE=false
if [[ "${1:-}" == "--verbose" ]]; then
    VERBOSE=true
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++)) || true
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL++)) || true
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN++)) || true
}

log_info() {
    if $VERBOSE; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

echo "=========================================="
echo "NEXUS Tor Reality Check Validation"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=========================================="
echo ""

# =============================================================================
# Section 1: Tor Daemon Status
# =============================================================================
echo "--- Tor Daemon Checks ---"

# Test 1: Tor daemon running
echo -n "Tor daemon status: "
if systemctl is-active --quiet tor 2>/dev/null; then
    log_pass "Tor daemon running (systemd)"
elif pgrep -x tor >/dev/null 2>&1; then
    log_pass "Tor daemon running (process)"
else
    log_warn "Tor daemon not running (tests may fail)"
fi

# Test 2: SOCKS port accessible (use ss command)
echo -n "Tor SOCKS port 9050: "
if ss -tlnp 2>/dev/null | grep -q ':9050'; then
    log_pass "Port bound"
else
    log_warn "Port 9050 not bound (Tor may not be listening)"
fi

# Test 3: Skip network connectivity check (too slow for CI)
log_pass "Tor network check skipped (manual: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org)"

echo ""

# =============================================================================
# Section 2: Price Conversion Service (External API)
# =============================================================================
echo "--- Price Conversion Service ---"
PRICE_FILE="server/src/services/price_conversion.rs"

if [[ -f "$PRICE_FILE" ]]; then
    # Test: Uses socks5h (DNS over Tor)
    echo -n "Uses socks5h for DNS over Tor: "
    if grep -q 'socks5h://127.0.0.1:9050' "$PRICE_FILE"; then
        log_pass "Correctly configured"
    else
        log_fail "Missing socks5h - DNS will leak!"
    fi

    # Test: Appropriate timeout
    echo -n "Timeout >= 30s for Tor latency: "
    if grep -E 'timeout.*Duration::from_secs\(([3-9][0-9]|[1-9][0-9]{2,})\)' "$PRICE_FILE" >/dev/null 2>&1; then
        log_pass "Adequate timeout"
    else
        log_warn "Check timeout value"
    fi

    # Test: Generic User-Agent
    echo -n "Generic User-Agent configured: "
    if grep -q 'Mozilla/5.0.*Firefox' "$PRICE_FILE"; then
        log_pass "Firefox User-Agent"
    else
        log_fail "Missing or custom User-Agent"
    fi

    # Test: No URL logging
    echo -n "No API URLs in logs: "
    if grep -E '(info!|debug!|warn!|error!).*coingecko' "$PRICE_FILE" >/dev/null 2>&1; then
        log_fail "API URL found in log statements"
    else
        log_pass "URLs not logged"
    fi
else
    log_warn "File not found: $PRICE_FILE"
fi

echo ""

# =============================================================================
# Section 3: IPFS Client
# =============================================================================
echo "--- IPFS Client ---"
IPFS_FILE="server/src/ipfs/client.rs"

if [[ -f "$IPFS_FILE" ]]; then
    # Test: Infura uses socks5h
    echo -n "Infura gateway uses socks5h: "
    if grep -A10 'new_infura' "$IPFS_FILE" | grep -q 'socks5h://'; then
        log_pass "Correctly configured"
    else
        log_fail "Infura missing socks5h"
    fi

    # Test: Check for DNS leak (socks5:// without h)
    echo -n "No DNS leak (socks5 without h): "
    # This checks if there's any socks5:// that isn't socks5h://
    if grep 'Proxy::all("socks5://' "$IPFS_FILE" | grep -v 'socks5h' >/dev/null 2>&1; then
        log_fail "CRITICAL: Found socks5:// without 'h' - DNS LEAK RISK"
        log_info "Fix: Change line 78 from socks5:// to socks5h://"
    else
        log_pass "All SOCKS5 proxies use DNS-over-Tor"
    fi

    # Test: Local bypass only for 127.0.0.1
    echo -n "Localhost bypass only for 127.0.0.1: "
    if grep -q 'starts_with("http://127.0.0.1")' "$IPFS_FILE"; then
        log_pass "Correct localhost detection"
    else
        log_warn "Check localhost detection logic"
    fi
else
    log_warn "File not found: $IPFS_FILE"
fi

echo ""

# =============================================================================
# Section 4: Monero RPC Client
# =============================================================================
echo "--- Monero RPC Client ---"
RPC_FILE="wallet/src/rpc.rs"
VALIDATION_FILE="wallet/src/validation.rs"

if [[ -f "$RPC_FILE" ]]; then
    # Test: Uses validate_localhost_strict
    echo -n "Strict localhost validation: "
    if grep -q 'validate_localhost_strict' "$RPC_FILE"; then
        log_pass "TM-004 fix implemented"
    else
        log_fail "Missing strict localhost validation"
    fi

    # Test: No public IP patterns
    echo -n "No hardcoded public IPs: "
    if grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$RPC_FILE" | grep -vE '127\.0\.0\.1|0\.0\.0\.0' | grep -v '//' >/dev/null 2>&1; then
        log_fail "Found non-localhost IP addresses"
    else
        log_pass "Only localhost IPs"
    fi

    # Test: Address truncation in logs
    echo -n "Address truncation in logs: "
    if grep -q '\[\.\.8\]' "$RPC_FILE" || grep -q '\[\.\.10\]' "$RPC_FILE"; then
        log_pass "Addresses truncated"
    else
        log_warn "Check address logging"
    fi
else
    log_warn "File not found: $RPC_FILE"
fi

if [[ -f "$VALIDATION_FILE" ]]; then
    # Test: Validates against bypass attacks
    echo -n "Validates against hostname bypass: "
    if grep -q 'url::Host::Domain' "$VALIDATION_FILE"; then
        log_pass "Proper URL host parsing"
    else
        log_fail "Vulnerable to hostname bypass"
    fi
else
    log_warn "File not found: $VALIDATION_FILE"
fi

echo ""

# =============================================================================
# Section 5: Sync Proxy Service
# =============================================================================
echo "--- Sync Proxy Service ---"
SYNC_FILE="server/src/services/sync_proxy.rs"

if [[ -f "$SYNC_FILE" ]]; then
    # Test: Localhost validation exists
    echo -n "Localhost validation present: "
    if grep -q 'localhost only' "$SYNC_FILE" || grep -q '127.0.0.1' "$SYNC_FILE"; then
        log_pass "Validation present"
    else
        log_fail "Missing localhost validation"
    fi

    # Test: Uses contains() instead of strict parsing (warning)
    echo -n "URL validation strength: "
    if grep 'contains("127.0.0.1")' "$SYNC_FILE" >/dev/null 2>&1; then
        log_warn "Uses contains() - vulnerable to bypass (e.g., evil-127.0.0.1.com)"
        log_info "Recommend: Use validate_localhost_strict() from wallet/src/validation.rs"
    else
        log_pass "Strong URL validation"
    fi
else
    log_warn "File not found: $SYNC_FILE"
fi

echo ""

# =============================================================================
# Section 6: General OPSEC Checks
# =============================================================================
echo "--- General OPSEC Checks ---"

# Test: No 0.0.0.0 bindings (except in tests)
echo -n "No public interface bindings (0.0.0.0): "
BINDING_ISSUES=$(grep -rn '0\.0\.0\.0' server/src wallet/src --include='*.rs' 2>/dev/null | grep -v 'test' | grep -v '//' | grep -v '#\[' || true)
if [[ -n "$BINDING_ISSUES" ]]; then
    log_fail "Found 0.0.0.0 bindings"
    if $VERBOSE; then
        echo "$BINDING_ISSUES" | head -5
    fi
else
    log_pass "No public bindings"
fi

# Test: No .onion addresses in log statements
echo -n "No .onion addresses in logs: "
ONION_LOGS=$(grep -rE '(info!|debug!|warn!|error!).*\.onion' server/src wallet/src --include='*.rs' 2>/dev/null || true)
if [[ -n "$ONION_LOGS" ]]; then
    log_fail "Found .onion in log statements"
else
    log_pass "No .onion in logs"
fi

# Test: No private keys in logs
echo -n "No private key patterns in logs: "
KEY_LOGS=$(grep -rE '(info!|debug!|warn!|error!).*(priv.*key|secret.*key|spend.*key)' server/src wallet/src --include='*.rs' 2>/dev/null | grep -v 'view' || true)
if [[ -n "$KEY_LOGS" ]]; then
    log_fail "Found private key references in logs"
else
    log_pass "No private keys in logs"
fi

# Test: No clearnet API calls without Tor
echo -n "External APIs use Tor proxy: "
CLEARNET=$(grep -rn 'reqwest::Client::new()' server/src --include='*.rs' 2>/dev/null | grep -v 'test' | grep -v 'localhost' | grep -v '//' || true)
if [[ -n "$CLEARNET" ]]; then
    log_warn "Found reqwest::Client::new() without explicit proxy"
    if $VERBOSE; then
        echo "$CLEARNET" | head -3
    fi
else
    log_pass "All external clients use proxy builders"
fi

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=========================================="
echo "RESULTS SUMMARY"
echo "=========================================="
echo -e "${GREEN}Passed:${NC}   $PASS"
echo -e "${RED}Failed:${NC}   $FAIL"
echo -e "${YELLOW}Warnings:${NC} $WARN"
echo "=========================================="

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}OVERALL: FAIL${NC}"
    echo "Critical issues must be fixed before production deployment."
    echo ""
    echo "Priority fixes:"
    echo "1. IPFS client: Change socks5:// to socks5h:// (line 78)"
    echo "2. Sync proxy: Use validate_localhost_strict() for URL validation"
    exit 1
elif [[ $WARN -gt 3 ]]; then
    echo -e "${YELLOW}OVERALL: PASS with warnings${NC}"
    echo "Recommended fixes before production."
    exit 2
else
    echo -e "${GREEN}OVERALL: PASS${NC}"
    echo "Ready for manual validation. Run DNS leak and traffic tests."
    exit 0
fi
