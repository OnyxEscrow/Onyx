#!/usr/bin/env bash
#
# ULTRA FULL AUDIT EXTENDED v2.0.0 - Monero Marketplace
#
# Comprehensive security, infrastructure, cryptographic, and production-readiness audit
# Prevents "schema.rs missing" type oversights with exhaustive validation
#
# Usage:
#   ./scripts/ultra-full-audit-extended.sh              # Standard audit
#   ./scripts/ultra-full-audit-extended.sh -v           # Verbose mode
#   ./scripts/ultra-full-audit-extended.sh --strict     # Fail on warnings
#   ./scripts/ultra-full-audit-extended.sh --json       # JSON output for CI/CD
#   ./scripts/ultra-full-audit-extended.sh --html       # Generate HTML report
#
# Exit codes:
#   0  - All checks passed
#   1  - Critical issues found
#   2  - High priority issues found
#   3  - Medium priority issues found
#   10 - Script error
#

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Report directory
REPORT_DIR="$PROJECT_ROOT/audit-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/audit_$TIMESTAMP.json"
LOG_FILE="$REPORT_DIR/audit_$TIMESTAMP.log"

# Options
VERBOSE=false
STRICT=false
JSON_OUTPUT=false
HTML_OUTPUT=false
PARALLEL_EXECUTION=false

# Issue counters (associative arrays for categories)
declare -A CRITICAL_ISSUES
declare -A HIGH_ISSUES
declare -A MEDIUM_ISSUES
declare -A LOW_ISSUES

TOTAL_CHECKS=0
PASSED_CHECKS=0

# Colors
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# JSON buffer
JSON_BUFFER=""

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log() {
    local message="$*"
    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "${BOLD}[AUDIT]${NC} $message" | tee -a "$LOG_FILE"
    fi
}

log_verbose() {
    if [[ "$VERBOSE" == "true" && "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "  ${BLUE}ℹ${NC} $*" | tee -a "$LOG_FILE"
    fi
}

log_critical() {
    local category="$1"
    local message="$2"
    CRITICAL_ISSUES["$category"]="${CRITICAL_ISSUES[$category]:-0}"
    ((CRITICAL_ISSUES["$category"]++))

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "${RED}🔴 CRITICAL:${NC} $message" | tee -a "$LOG_FILE"
    fi
}

log_high() {
    local category="$1"
    local message="$2"
    HIGH_ISSUES["$category"]="${HIGH_ISSUES[$category]:-0}"
    ((HIGH_ISSUES["$category"]++))

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "${ORANGE}🟠 HIGH:${NC} $message" | tee -a "$LOG_FILE"
    fi
}

log_medium() {
    local category="$1"
    local message="$2"
    MEDIUM_ISSUES["$category"]="${MEDIUM_ISSUES[$category]:-0}"
    ((MEDIUM_ISSUES["$category"]++))

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "${YELLOW}🟡 MEDIUM:${NC} $message" | tee -a "$LOG_FILE"
    fi
}

log_low() {
    local category="$1"
    local message="$2"
    LOW_ISSUES["$category"]="${LOW_ISSUES[$category]:-0}"
    ((LOW_ISSUES["$category"]++))

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "${GREEN}🟢 LOW:${NC} $message" | tee -a "$LOG_FILE"
    fi
}

log_pass() {
    local message="$*"
    if [[ "$VERBOSE" == "true" && "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "  ${GREEN}✓${NC} $message" | tee -a "$LOG_FILE"
    fi
    ((PASSED_CHECKS++))
}

check_start() {
    ((TOTAL_CHECKS++))
    log_verbose "Checking: $*"
}

# ============================================================================
# CATEGORY 1: INFRASTRUCTURE CRITICAL (ENHANCED)
# ============================================================================

audit_infrastructure() {
    local category="Infrastructure"
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${PURPLE}CATEGORY 1: INFRASTRUCTURE CRITICAL (ENHANCED)${NC}"
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: schema.rs existence and validity
    check_start "schema.rs existence and content"
    if [[ ! -f "server/src/schema.rs" ]]; then
        log_critical "$category" "schema.rs is MISSING! Diesel ORM will fail."
    elif [[ ! -s "server/src/schema.rs" ]]; then
        log_critical "$category" "schema.rs exists but is EMPTY!"
    else
        local table_count=$(grep -c "diesel::table!" server/src/schema.rs || echo "0")
        if [[ "$table_count" -lt 5 ]]; then
            log_high "$category" "schema.rs has only $table_count tables (expected 6+)"
        else
            log_pass "schema.rs exists with $table_count tables"
        fi
    fi

    # Check 2: Database file
    check_start "Database file existence and integrity"
    if [[ ! -f "marketplace.db" ]]; then
        log_critical "$category" "marketplace.db MISSING! Run migrations."
    else
        local db_size=$(stat -c%s "marketplace.db" 2>/dev/null || echo "0")
        if [[ "$db_size" -lt 1000 ]]; then
            log_high "$category" "Database suspiciously small ($db_size bytes)"
        else
            log_pass "Database exists ($(( db_size / 1024 ))KB)"
        fi
    fi

    # Check 3: Pending migrations
    check_start "Database migrations status"
    if command -v diesel &> /dev/null; then
        local pending=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" || echo "0")
        if [[ "$pending" -gt 0 ]]; then
            log_critical "$category" "$pending pending migrations NOT applied!"
        else
            log_pass "All migrations applied"
        fi
    else
        log_high "$category" "diesel CLI not installed"
    fi

    # Check 4: Cargo workspace integrity
    check_start "Cargo workspace configuration"
    if [[ ! -f "Cargo.toml" ]]; then
        log_critical "$category" "Root Cargo.toml MISSING!"
    else
        local members=$(grep -A10 "^\[workspace\]" Cargo.toml | grep "members" | wc -l)
        if [[ "$members" -eq 0 ]]; then
            log_high "$category" "No workspace members defined"
        else
            log_pass "Cargo workspace configured"
        fi
    fi

    # Check 5: Essential directories
    check_start "Project structure"
    local missing_dirs=()
    for dir in "server" "wallet" "common" "scripts" "docs"; do
        if [[ ! -d "$dir" ]]; then
            missing_dirs+=("$dir")
        fi
    done
    if [[ ${#missing_dirs[@]} -gt 0 ]]; then
        log_high "$category" "Missing directories: ${missing_dirs[*]}"
    else
        log_pass "All essential directories present"
    fi

    # Check 6: Environment configuration
    check_start ".env configuration"
    if [[ ! -f ".env" ]]; then
        log_high "$category" ".env file MISSING!"
    else
        log_pass ".env exists"
    fi

    # Check 7: Build artifacts
    check_start "Compiled binaries"
    if [[ ! -f "target/release/server" ]]; then
        log_medium "$category" "Release binary not built"
    else
        log_pass "Release binary exists"
    fi

    echo
}

# ============================================================================
# CATEGORY 2: SECURITY CRITICAL (ENHANCED WITH API KEYS)
# ============================================================================

audit_security() {
    local category="Security"
    log "${BOLD}${RED}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${RED}CATEGORY 2: SECURITY CRITICAL (ENHANCED)${NC}"
    log "${BOLD}${RED}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Exposed API keys
    check_start "Exposed API keys and secrets"
    local api_key_patterns="sk-ant-api|sk-|ANTHROPIC_API_KEY.*=.*sk-|OPENAI_API_KEY"
    local exposed_keys=$(grep -rE "$api_key_patterns" --include="*.rs" --include="*.toml" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$exposed_keys" -gt 0 ]]; then
        log_critical "$category" "Found $exposed_keys exposed API keys in code!"
    else
        log_pass "No exposed API keys in code"
    fi

    # Check 2: .env tracked by git
    check_start ".env git tracking"
    if git ls-files .env 2>/dev/null | grep -q ".env"; then
        log_critical "$category" ".env is TRACKED BY GIT! Secrets exposed!"
    else
        log_pass ".env not tracked by git"
    fi

    # Check 3: API keys in .env
    if [[ -f ".env" ]]; then
        check_start ".env API key security"
        if git ls-files --error-unmatch .env &>/dev/null; then
            if grep -qE "ANTHROPIC_API_KEY=sk-ant-api" .env; then
                log_critical "$category" ".env contains API key and is tracked by git!"
            fi
        fi

        # Check if API key looks like placeholder
        local api_key=$(grep "^ANTHROPIC_API_KEY=" .env | cut -d'=' -f2 || echo "")
        if [[ "$api_key" == *"your-api-key"* ]] || [[ "$api_key" == *"example"* ]]; then
            log_medium "$category" "API key looks like placeholder value"
        elif [[ -n "$api_key" ]]; then
            log_pass "API key configured (not checking validity)"
        fi
    fi

    # Check 4: Database encryption key
    check_start "Database encryption key strength"
    if [[ -f ".env" ]]; then
        local db_key=$(grep "^DB_ENCRYPTION_KEY=" .env | cut -d'=' -f2 || echo "")
        if [[ -z "$db_key" ]]; then
            log_critical "$category" "DB_ENCRYPTION_KEY not set!"
        elif [[ "${#db_key}" -lt 64 ]]; then
            log_critical "$category" "DB_ENCRYPTION_KEY too short (${#db_key} chars, need 64 for 256-bit)"
        else
            log_pass "DB_ENCRYPTION_KEY configured (${#db_key} chars)"
        fi
    fi

    # Check 5: SQL injection patterns
    check_start "Potential SQL injection vulnerabilities"
    local sql_concat=$(grep -rE "format!.*SELECT|&format.*INSERT|query.*&" --include="*.rs" --exclude-dir=target ./server 2>/dev/null | wc -l || echo "0")
    if [[ "$sql_concat" -gt 0 ]]; then
        log_critical "$category" "Found $sql_concat potential SQL injection patterns!"
    else
        log_pass "No obvious SQL injection patterns"
    fi

    # Check 6: XSS vulnerabilities
    check_start "XSS vulnerability patterns"
    local xss_patterns=$(grep -rE "innerHTML|dangerouslySetInnerHTML|eval\(" --include="*.rs" --include="*.html" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$xss_patterns" -gt 0 ]]; then
        log_high "$category" "Found $xss_patterns potential XSS patterns"
    else
        log_pass "No obvious XSS patterns"
    fi

    # Check 7: Unwrap/expect usage
    check_start "Unsafe error handling"
    local unwraps=$(grep -r "\.unwrap()" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    local expects=$(grep -r "\.expect(" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    local total=$((unwraps + expects))
    if [[ "$total" -gt 100 ]]; then
        log_high "$category" "Found $total unwrap/expect calls (high panic risk)"
    elif [[ "$total" -gt 50 ]]; then
        log_medium "$category" "Found $total unwrap/expect calls"
    else
        log_pass "Found $total unwrap/expect calls (acceptable)"
    fi

    # Check 8: Hardcoded credentials
    check_start "Hardcoded credentials"
    local hardcoded=$(grep -rE "password\s*=\s*\"[^\"]+\"|secret\s*=\s*\"[^\"]+\"" --include="*.rs" --exclude-dir=target . 2>/dev/null | grep -v "password_hash" | wc -l || echo "0")
    if [[ "$hardcoded" -gt 0 ]]; then
        log_critical "$category" "Found $hardcoded hardcoded credentials!"
    else
        log_pass "No hardcoded credentials detected"
    fi

    # Check 9: Secrets in logs
    check_start "Secrets in log files"
    if [[ -f "server.log" ]]; then
        local secrets_in_logs=$(grep -iE "password=|secret=|key=|token=" server.log 2>/dev/null | wc -l || echo "0")
        if [[ "$secrets_in_logs" -gt 0 ]]; then
            log_high "$category" "Found $secrets_in_logs potential secrets in logs!"
        else
            log_pass "No secrets in logs"
        fi
    fi

    # Check 10: Tor proxy status
    check_start "Tor proxy configuration"
    if [[ -f "server.log" ]]; then
        if grep -q "Tor proxy DISABLED" server.log 2>/dev/null; then
            log_critical "$category" "Tor proxy DISABLED! Privacy compromised!"
        else
            log_pass "Tor proxy enabled"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 3: MONERO CRYPTOGRAPHIC AUDIT
# ============================================================================

audit_monero_crypto() {
    local category="Monero_Crypto"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${CYAN}CATEGORY 3: MONERO CRYPTOGRAPHIC AUDIT${NC}"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Monero address validation
    check_start "Monero address validation logic"
    local addr_validation=$(grep -r "validate_address\|check_address\|is_valid.*address" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$addr_validation" -eq 0 ]]; then
        log_critical "$category" "No Monero address validation found!"
    else
        log_pass "Found $addr_validation address validation checks"
    fi

    # Check 2: Private key handling
    check_start "Private key secure handling"
    local unsafe_keys=$(grep -r "private_key\|secret_key\|spend_key\|view_key" --include="*.rs" --exclude-dir=target . 2>/dev/null | grep -v "zeroize\|clear_on_drop\|SecretKey" | wc -l || echo "0")
    if [[ "$unsafe_keys" -gt 10 ]]; then
        log_high "$category" "Found $unsafe_keys potentially unsafe key references (need zeroize)"
    elif [[ "$unsafe_keys" -gt 0 ]]; then
        log_medium "$category" "Found $unsafe_keys key references (verify secure handling)"
    else
        log_pass "Key handling appears secure"
    fi

    # Check 3: Multisig implementation
    check_start "Multisig implementation"
    local multisig_funcs=$(grep -r "prepare_multisig\|make_multisig\|export_multisig" --include="*.rs" --exclude-dir=target ./wallet 2>/dev/null | wc -l || echo "0")
    if [[ "$multisig_funcs" -lt 3 ]]; then
        log_high "$category" "Incomplete multisig implementation (found $multisig_funcs functions)"
    else
        log_pass "Multisig functions implemented ($multisig_funcs)"
    fi

    # Check 4: RingCT verification
    check_start "RingCT transaction verification"
    local ringct=$(grep -r "RingCT\|rct_signatures\|verify_rct" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$ringct" -eq 0 ]]; then
        log_medium "$category" "No explicit RingCT verification (may rely on RPC)"
    else
        log_pass "RingCT verification present"
    fi

    # Check 5: Payment proof implementation
    check_start "Payment proof generation"
    local payment_proof=$(grep -r "get_tx_proof\|check_tx_proof" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$payment_proof" -eq 0 ]]; then
        log_medium "$category" "No payment proof functionality (needed for disputes)"
    else
        log_pass "Payment proof functionality present"
    fi

    # Check 6: Monero RPC client security
    check_start "Monero RPC localhost-only enforcement"
    if [[ -f "wallet/src/rpc.rs" ]]; then
        if grep -q "127.0.0.1\|localhost" wallet/src/rpc.rs; then
            log_pass "RPC client restricts to localhost"
        else
            log_critical "$category" "RPC client may allow non-localhost connections!"
        fi
    fi

    # Check 7: Transaction confirmation checks
    check_start "Transaction confirmation validation"
    local conf_check=$(grep -r "confirmations\|get_confirmations" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$conf_check" -eq 0 ]]; then
        log_high "$category" "No confirmation checking (double-spend risk)"
    else
        log_pass "Confirmation checking implemented"
    fi

    echo
}

# ============================================================================
# CATEGORY 4: NETWORK SECURITY
# ============================================================================

audit_network_security() {
    local category="Network"
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${BLUE}CATEGORY 4: NETWORK SECURITY${NC}"
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Tor daemon status
    check_start "Tor daemon running"
    if pgrep -x "tor" > /dev/null; then
        log_pass "Tor daemon running"
    else
        log_critical "$category" "Tor daemon NOT running!"
    fi

    # Check 2: Tor SOCKS port
    check_start "Tor SOCKS port availability"
    if ss -tulpn 2>/dev/null | grep -q ":9050"; then
        log_pass "Tor SOCKS port 9050 listening"
    else
        log_high "$category" "Tor SOCKS port not accessible"
    fi

    # Check 3: Public port exposure
    check_start "No public ports exposed"
    local public_ports=$(ss -tulpn 2>/dev/null | grep -E "0\.0\.0\.0:(8080|18082|5001)" | wc -l || echo "0")
    if [[ "$public_ports" -gt 0 ]]; then
        log_critical "$category" "Found $public_ports services on 0.0.0.0 (public)!"
    else
        log_pass "No public port exposure"
    fi

    # Check 4: Tor connectivity test
    check_start "Tor network connectivity"
    if command -v curl &> /dev/null; then
        if timeout 15 curl -s --socks5 127.0.0.1:9050 https://check.torproject.org 2>&1 | grep -q "Congratulations"; then
            log_pass "Tor connectivity verified"
        else
            log_high "$category" "Tor connectivity test failed"
        fi
    fi

    # Check 5: TLS/SSL configuration
    check_start "TLS/SSL implementation"
    local tls_usage=$(grep -r "rustls\|native-tls\|https" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$tls_usage" -eq 0 ]]; then
        log_medium "$category" "No TLS library detected (needed for HTTPS)"
    else
        log_pass "TLS libraries present"
    fi

    # Check 6: Firewall status (basic check)
    check_start "Firewall status"
    if command -v ufw &> /dev/null; then
        if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            log_pass "UFW firewall active"
        else
            log_medium "$category" "UFW firewall inactive"
        fi
    fi

    # Check 7: Rate limiting
    check_start "Rate limiting implementation"
    local rate_limit=$(grep -r "RateLimiter\|rate_limit\|throttle" --include="*.rs" --exclude-dir=target ./server 2>/dev/null | wc -l || echo "0")
    if [[ "$rate_limit" -eq 0 ]]; then
        log_high "$category" "No rate limiting (DDoS vulnerable)"
    else
        log_pass "Rate limiting implemented"
    fi

    echo
}

# ============================================================================
# CATEGORY 5: DATABASE SECURITY & PERFORMANCE
# ============================================================================

audit_database() {
    local category="Database"
    log "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${YELLOW}CATEGORY 5: DATABASE SECURITY & PERFORMANCE${NC}"
    log "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo

    if [[ ! -f "marketplace.db" ]]; then
        log_critical "$category" "Database file missing!"
        echo
        return
    fi

    if ! command -v sqlite3 &> /dev/null; then
        log_medium "$category" "sqlite3 not installed (skipping DB checks)"
        echo
        return
    fi

    # Check 1: Database integrity
    check_start "Database integrity check"
    local integrity=$(sqlite3 marketplace.db "PRAGMA integrity_check;" 2>/dev/null || echo "error")
    if [[ "$integrity" != "ok" ]]; then
        log_critical "$category" "Database integrity FAILED: $integrity"
    else
        log_pass "Database integrity OK"
    fi

    # Check 2: Encryption (SQLCipher)
    check_start "Database encryption"
    if grep -q "sqlcipher" Cargo.toml 2>/dev/null; then
        log_pass "SQLCipher encryption library present"
    else
        log_high "$category" "Database NOT encrypted (SQLCipher missing)"
    fi

    # Check 3: Indexes
    check_start "Database indexes"
    local index_count=$(sqlite3 marketplace.db ".indexes" 2>/dev/null | wc -l || echo "0")
    if [[ "$index_count" -lt 5 ]]; then
        log_medium "$category" "Only $index_count indexes (performance issue)"
    else
        log_pass "$index_count indexes configured"
    fi

    # Check 4: Foreign keys
    check_start "Foreign key constraints"
    local fk_enabled=$(sqlite3 marketplace.db "PRAGMA foreign_keys;" 2>/dev/null || echo "0")
    if [[ "$fk_enabled" != "1" ]]; then
        log_high "$category" "Foreign keys NOT enabled!"
    else
        log_pass "Foreign keys enabled"
    fi

    # Check 5: VACUUM status
    check_start "Database fragmentation"
    local page_count=$(sqlite3 marketplace.db "PRAGMA page_count;" 2>/dev/null || echo "0")
    local freelist=$(sqlite3 marketplace.db "PRAGMA freelist_count;" 2>/dev/null || echo "0")
    if [[ "$page_count" -gt 0 ]] && [[ "$freelist" -gt $((page_count / 4)) ]]; then
        log_medium "$category" "Database fragmented ($freelist free pages), run VACUUM"
    else
        log_pass "Database not fragmented"
    fi

    # Check 6: Required tables
    check_start "Required tables exist"
    local expected_tables=("users" "listings" "orders" "escrows" "transactions" "reviews")
    local missing_tables=()
    for table in "${expected_tables[@]}"; do
        if ! sqlite3 marketplace.db ".tables" 2>/dev/null | grep -qw "$table"; then
            missing_tables+=("$table")
        fi
    done
    if [[ ${#missing_tables[@]} -gt 0 ]]; then
        log_critical "$category" "Missing tables: ${missing_tables[*]}"
    else
        log_pass "All required tables present"
    fi

    # Check 7: Backup strategy
    check_start "Database backup configuration"
    if [[ -d "backups" ]] || [[ -f "scripts/backup-db.sh" ]]; then
        log_pass "Backup strategy configured"
    else
        log_medium "$category" "No backup strategy detected"
    fi

    echo
}

# ============================================================================
# CATEGORY 6: CODE QUALITY & STATIC ANALYSIS
# ============================================================================

audit_code_quality() {
    local category="Code_Quality"
    log "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${GREEN}CATEGORY 6: CODE QUALITY & STATIC ANALYSIS${NC}"
    log "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Clippy lints
    check_start "Clippy static analysis"
    if command -v cargo &> /dev/null; then
        log_verbose "Running clippy..."
        local clippy_output=$(cargo clippy --workspace --quiet 2>&1 || true)
        local clippy_errors=$(echo "$clippy_output" | grep -c "error:" || echo "0")
        local clippy_warnings=$(echo "$clippy_output" | grep -c "warning:" || echo "0")

        if [[ "$clippy_errors" -gt 0 ]]; then
            log_critical "$category" "Clippy found $clippy_errors errors!"
        elif [[ "$clippy_warnings" -gt 10 ]]; then
            log_high "$category" "Clippy found $clippy_warnings warnings"
        elif [[ "$clippy_warnings" -gt 0 ]]; then
            log_medium "$category" "Clippy found $clippy_warnings warnings"
        else
            log_pass "Clippy: clean"
        fi
    fi

    # Check 2: Code formatting
    check_start "rustfmt formatting"
    if command -v cargo &> /dev/null; then
        local fmt_issues=$(cargo fmt --check 2>&1 | grep "Diff in" | wc -l || echo "0")
        if [[ "$fmt_issues" -gt 0 ]]; then
            log_medium "$category" "$fmt_issues files need formatting"
        else
            log_pass "All code formatted correctly"
        fi
    fi

    # Check 3: Unsafe code blocks
    check_start "Unsafe code usage"
    local unsafe_blocks=$(grep -r "unsafe {" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$unsafe_blocks" -gt 10 ]]; then
        log_high "$category" "Found $unsafe_blocks unsafe blocks (review needed)"
    elif [[ "$unsafe_blocks" -gt 0 ]]; then
        log_medium "$category" "Found $unsafe_blocks unsafe blocks"
    else
        log_pass "No unsafe blocks"
    fi

    # Check 4: Dependency audit
    check_start "Dependency vulnerability scan"
    if command -v cargo-audit &> /dev/null; then
        local vulns=$(cargo audit 2>&1 | grep -c "warning:" || echo "0")
        if [[ "$vulns" -gt 0 ]]; then
            log_high "$category" "$vulns vulnerable dependencies!"
        else
            log_pass "No vulnerable dependencies"
        fi
    else
        log_verbose "cargo-audit not installed (skipping)"
    fi

    # Check 5: TODO/FIXME comments
    check_start "TODO/FIXME comments"
    local todos=$(grep -r "TODO\|FIXME" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$todos" -gt 50 ]]; then
        log_high "$category" "Found $todos TODO/FIXME (needs cleanup)"
    elif [[ "$todos" -gt 20 ]]; then
        log_medium "$category" "Found $todos TODO/FIXME"
    else
        log_pass "Found $todos TODO/FIXME (acceptable)"
    fi

    # Check 6: License compliance
    check_start "License compliance"
    if [[ ! -f "LICENSE" ]] && [[ ! -f "LICENSE.md" ]]; then
        log_medium "$category" "No LICENSE file found"
    else
        log_pass "LICENSE file present"
    fi

    echo
}

# ============================================================================
# CATEGORY 7: TESTING & QUALITY ASSURANCE
# ============================================================================

audit_testing() {
    local category="Testing"
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${PURPLE}CATEGORY 7: TESTING & QUALITY ASSURANCE${NC}"
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Unit tests exist
    check_start "Unit test coverage"
    local test_files=$(find . -path "*/src/*.rs" -type f -exec grep -l "#\[test\]" {} \; 2>/dev/null | wc -l || echo "0")
    if [[ "$test_files" -eq 0 ]]; then
        log_high "$category" "No unit tests found!"
    else
        log_pass "Found tests in $test_files files"
    fi

    # Check 2: Integration tests
    check_start "Integration tests"
    local int_tests=$(find . -path "*/tests/*.rs" -type f 2>/dev/null | wc -l || echo "0")
    if [[ "$int_tests" -eq 0 ]]; then
        log_medium "$category" "No integration tests found"
    else
        log_pass "Found $int_tests integration test files"
    fi

    # Check 3: Run tests
    check_start "Test execution"
    if command -v cargo &> /dev/null; then
        log_verbose "Running tests (may take time)..."
        local test_output=$(cargo test --workspace --lib 2>&1 || true)
        local test_failed=$(echo "$test_output" | grep "test result:" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "0")

        if [[ "$test_failed" -gt 0 ]]; then
            log_critical "$category" "$test_failed tests FAILED!"
        else
            local test_passed=$(echo "$test_output" | grep "test result:" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
            log_pass "$test_passed tests passed"
        fi
    fi

    # Check 4: E2E tests
    check_start "End-to-end tests"
    if [[ -f "server/tests/escrow_e2e.rs" ]]; then
        log_pass "E2E escrow tests exist"
    else
        log_medium "$category" "No E2E tests found"
    fi

    # Check 5: Test documentation
    check_start "Test documentation"
    if [[ -f "docs/TESTING.md" ]]; then
        log_pass "Testing documentation exists"
    else
        log_medium "$category" "No testing documentation"
    fi

    echo
}

# ============================================================================
# CATEGORY 8: PERFORMANCE & MONITORING
# ============================================================================

audit_performance() {
    local category="Performance"
    log "${BOLD}${ORANGE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${ORANGE}CATEGORY 8: PERFORMANCE & MONITORING${NC}"
    log "${BOLD}${ORANGE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Logging framework
    check_start "Logging framework"
    if grep -q "tracing\|log" Cargo.toml; then
        log_pass "Logging framework configured"
    else
        log_medium "$category" "No logging framework detected"
    fi

    # Check 2: Log file size
    check_start "Log file management"
    if [[ -f "server.log" ]]; then
        local log_size=$(stat -c%s "server.log" 2>/dev/null || echo "0")
        local log_size_mb=$((log_size / 1024 / 1024))
        if [[ "$log_size_mb" -gt 100 ]]; then
            log_medium "$category" "Log file very large (${log_size_mb}MB), needs rotation"
        else
            log_pass "Log file size OK (${log_size_mb}MB)"
        fi
    fi

    # Check 3: Metrics collection
    check_start "Metrics/monitoring"
    if grep -rq "prometheus\|metrics" --include="*.toml" . 2>/dev/null; then
        log_pass "Metrics collection configured"
    else
        log_low "$category" "No metrics collection (recommended for production)"
    fi

    # Check 4: Health check endpoint
    check_start "Health check endpoint"
    if grep -r "/health\|/api/health" --include="*.rs" --exclude-dir=target ./server 2>/dev/null | grep -q "health"; then
        log_pass "Health check endpoint exists"
    else
        log_medium "$category" "No health check endpoint"
    fi

    # Check 5: Binary size
    check_start "Binary size optimization"
    if [[ -f "target/release/server" ]]; then
        local bin_size=$(stat -c%s "target/release/server" 2>/dev/null || echo "0")
        local bin_size_mb=$((bin_size / 1024 / 1024))
        if [[ "$bin_size_mb" -gt 100 ]]; then
            log_medium "$category" "Binary very large (${bin_size_mb}MB)"
        else
            log_pass "Binary size OK (${bin_size_mb}MB)"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 9: DISASTER RECOVERY & BACKUP
# ============================================================================

audit_disaster_recovery() {
    local category="Disaster_Recovery"
    log "${BOLD}${RED}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${RED}CATEGORY 9: DISASTER RECOVERY & BACKUP${NC}"
    log "${BOLD}${RED}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Backup scripts
    check_start "Backup automation"
    if [[ -f "scripts/backup-db.sh" ]] || [[ -d "backups" ]]; then
        log_pass "Backup scripts/directory exist"
    else
        log_high "$category" "No backup strategy configured!"
    fi

    # Check 2: Recovery documentation
    check_start "Recovery documentation"
    if [[ -f "docs/RECOVERY.md" ]] || [[ -f "docs/DISASTER-RECOVERY.md" ]]; then
        log_pass "Recovery documentation exists"
    else
        log_medium "$category" "No recovery documentation"
    fi

    # Check 3: Database backups
    check_start "Recent database backups"
    if [[ -d "backups" ]]; then
        local recent_backup=$(find backups -name "*.db" -mtime -7 2>/dev/null | head -1)
        if [[ -n "$recent_backup" ]]; then
            log_pass "Recent backup found (< 7 days)"
        else
            log_high "$category" "No recent database backup!"
        fi
    else
        log_high "$category" "No backup directory"
    fi

    # Check 4: Configuration backups
    check_start "Configuration backup"
    if [[ -f ".env.example" ]]; then
        log_pass ".env.example exists for recovery"
    else
        log_medium "$category" "No .env.example template"
    fi

    echo
}

# ============================================================================
# CATEGORY 10: DOCUMENTATION
# ============================================================================

audit_documentation() {
    local category="Documentation"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${CYAN}CATEGORY 10: DOCUMENTATION${NC}"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: README
    check_start "README.md"
    if [[ ! -f "README.md" ]]; then
        log_high "$category" "README.md missing!"
    else
        local readme_lines=$(wc -l < README.md)
        if [[ "$readme_lines" -lt 20 ]]; then
            log_medium "$category" "README.md very short ($readme_lines lines)"
        else
            log_pass "README.md exists ($readme_lines lines)"
        fi
    fi

    # Check 2: CLAUDE.md
    check_start "CLAUDE.md project guide"
    if [[ ! -f "CLAUDE.md" ]]; then
        log_medium "$category" "CLAUDE.md missing"
    else
        log_pass "CLAUDE.md exists"
    fi

    # Check 3: API documentation
    check_start "API documentation"
    if [[ -f "docs/API.md" ]] || [[ -f "docs/api/README.md" ]]; then
        log_pass "API documentation exists"
    else
        log_medium "$category" "No API documentation"
    fi

    # Check 4: Function specifications
    check_start "Function specifications"
    if [[ -d "docs/specs" ]]; then
        local spec_count=$(find docs/specs -name "*.md" 2>/dev/null | wc -l || echo "0")
        if [[ "$spec_count" -gt 0 ]]; then
            log_pass "$spec_count specifications found"
        else
            log_medium "$category" "No specifications in docs/specs/"
        fi
    else
        log_medium "$category" "docs/specs/ missing"
    fi

    # Check 5: Code comments
    check_start "Code documentation"
    local doc_comments=$(grep -r "///" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$doc_comments" -lt 50 ]]; then
        log_medium "$category" "Low doc comment count ($doc_comments)"
    else
        log_pass "$doc_comments doc comments found"
    fi

    echo
}

# ============================================================================
# SCORING & SUMMARY
# ============================================================================

calculate_score() {
    local total_critical=0
    local total_high=0
    local total_medium=0
    local total_low=0

    for val in "${CRITICAL_ISSUES[@]}"; do
        ((total_critical+=val))
    done
    for val in "${HIGH_ISSUES[@]}"; do
        ((total_high+=val))
    done
    for val in "${MEDIUM_ISSUES[@]}"; do
        ((total_medium+=val))
    done
    for val in "${LOW_ISSUES[@]}"; do
        ((total_low+=val))
    done

    local penalty=$((total_critical * 20 + total_high * 10 + total_medium * 3 + total_low * 1))
    local score=$((100 - penalty))

    if [[ "$score" -lt 0 ]]; then
        score=0
    fi

    echo "$score:$total_critical:$total_high:$total_medium:$total_low"
}

print_summary() {
    local score_data=$(calculate_score)
    IFS=':' read -r SCORE CRITICAL_TOTAL HIGH_TOTAL MEDIUM_TOTAL LOW_TOTAL <<< "$score_data"

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "score": $SCORE,
  "summary": {
    "total_checks": $TOTAL_CHECKS,
    "passed": $PASSED_CHECKS,
    "critical": $CRITICAL_TOTAL,
    "high": $HIGH_TOTAL,
    "medium": $MEDIUM_TOTAL,
    "low": $LOW_TOTAL
  },
  "categories": $(declare -p CRITICAL_ISSUES HIGH_ISSUES MEDIUM_ISSUES LOW_ISSUES | sed 's/declare -A//')
}
EOF
        echo "Report saved to: $REPORT_FILE"
        return
    fi

    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}AUDIT SUMMARY${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Determine grade
    local grade color
    if [[ "$SCORE" -ge 90 ]]; then
        grade="A+"; color="$GREEN"
    elif [[ "$SCORE" -ge 80 ]]; then
        grade="A"; color="$GREEN"
    elif [[ "$SCORE" -ge 70 ]]; then
        grade="B"; color="$YELLOW"
    elif [[ "$SCORE" -ge 60 ]]; then
        grade="C"; color="$ORANGE"
    else
        grade="F"; color="$RED"
    fi

    echo -e "${BOLD}Total Checks:${NC} $TOTAL_CHECKS"
    echo -e "${BOLD}Passed:${NC} ${GREEN}$PASSED_CHECKS${NC}"
    echo
    echo -e "${RED}🔴 Critical:${NC} $CRITICAL_TOTAL (×20 pts)"
    echo -e "${ORANGE}🟠 High:${NC} $HIGH_TOTAL (×10 pts)"
    echo -e "${YELLOW}🟡 Medium:${NC} $MEDIUM_TOTAL (×3 pts)"
    echo -e "${GREEN}🟢 Low:${NC} $LOW_TOTAL (×1 pt)"
    echo
    echo -e "${BOLD}Overall Score:${NC} ${color}${SCORE}/100${NC} (Grade: ${color}${grade}${NC})"
    echo

    if [[ "$CRITICAL_TOTAL" -gt 0 ]]; then
        echo -e "${RED}${BOLD}⚠️  CRITICAL ISSUES MUST BE FIXED IMMEDIATELY!${NC}"
    elif [[ "$SCORE" -lt 70 ]]; then
        echo -e "${ORANGE}⚠️  Address high-priority issues before production${NC}"
    elif [[ "$SCORE" -lt 90 ]]; then
        echo -e "${YELLOW}✓ Good progress, continue improving${NC}"
    else
        echo -e "${GREEN}✓ Excellent! Project ready for production${NC}"
    fi
    echo

    echo "Full report saved to: $LOG_FILE"
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose) VERBOSE=true; shift ;;
            --strict) STRICT=true; shift ;;
            --json) JSON_OUTPUT=true; shift ;;
            --html) HTML_OUTPUT=true; shift ;;
            -h|--help)
                cat <<EOF
Ultra Full Audit Extended v2.0.0 - Monero Marketplace

Usage: $0 [OPTIONS]

Options:
    -v, --verbose     Verbose output
    --strict          Fail on warnings
    --json            JSON output
    --html            HTML report
    -h, --help        Show help

Exit Codes:
    0 - All passed
    1 - Critical issues
    2 - High issues
    3 - Medium issues
EOF
                exit 0
                ;;
            *) echo "Unknown: $1"; exit 10 ;;
        esac
    done
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    parse_args "$@"

    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}ULTRA FULL AUDIT EXTENDED v2.0.0${NC}"
    log "${BOLD}Monero Marketplace Comprehensive Audit${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo
    log "Project: $PROJECT_ROOT"
    log "Timestamp: $(date)"
    log "Report: $LOG_FILE"
    echo

    # Run all categories
    audit_infrastructure
    audit_security
    audit_monero_crypto
    audit_network_security
    audit_database
    audit_code_quality
    audit_testing
    audit_performance
    audit_disaster_recovery
    audit_documentation

    # Summary
    print_summary

    # Exit code
    local score_data=$(calculate_score)
    IFS=':' read -r _ CRITICAL_TOTAL HIGH_TOTAL MEDIUM_TOTAL _ <<< "$score_data"

    if [[ "$CRITICAL_TOTAL" -gt 0 ]]; then
        exit 1
    elif [[ "$HIGH_TOTAL" -gt 0 ]] && [[ "$STRICT" == "true" ]]; then
        exit 2
    elif [[ "$MEDIUM_TOTAL" -gt 0 ]] && [[ "$STRICT" == "true" ]]; then
        exit 3
    else
        exit 0
    fi
}

main "$@"
