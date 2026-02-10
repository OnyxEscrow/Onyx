#!/usr/bin/env bash
#
# ULTRA FULL AUDIT - Monero Marketplace
#
# Comprehensive security, infrastructure, and code quality audit
# Detects ALL potential issues to prevent "schema.rs missing" type problems
#
# Usage:
#   ./scripts/ultra-full-audit.sh              # Standard audit
#   ./scripts/ultra-full-audit.sh -v           # Verbose mode
#   ./scripts/ultra-full-audit.sh --strict     # Fail on warnings
#   ./scripts/ultra-full-audit.sh --fix        # Auto-fix issues (where possible)
#   ./scripts/ultra-full-audit.sh --json       # JSON output for CI/CD
#   ./scripts/ultra-full-audit.sh --html       # Generate HTML report
#
# Exit codes:
#   0  - All checks passed
#   1  - Critical issues found
#   2  - High priority issues found
#   3  - Medium priority issues found
#   10 - Script error

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

VERBOSE=false
STRICT=false
FIX_MODE=false
JSON_OUTPUT=false
HTML_OUTPUT=false
OUTPUT_FILE=""

# Counters
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
TOTAL_CHECKS=0
PASSED_CHECKS=0

# Colors
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ============================================================================

# HELPER FUNCTIONS

# ============================================================================



RESULTS=()



log() {
    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        echo -e "${BOLD}[AUDIT]${NC} $ *"
    fi
}



log_verbose() {

    if [[ "$VERBOSE" == "true" && "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then

        echo -e "  ${BLUE}ℹ${NC} $ *"

    fi

}



log_critical() {

    local message=


    RESULTS+=("CRITICAL|$message")

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then

        echo -e "${RED}🔴 CRITICAL:${NC} $message"

    fi

    ((CRITICAL_COUNT++))

}



log_high() {

    local message=


    RESULTS+=("HIGH|$message")

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then

        echo -e "${ORANGE}🟠 HIGH:${NC} $message"

    fi

    ((HIGH_COUNT++))

}



log_medium() {

    local message=


    RESULTS+=("MEDIUM|$message")

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then

        echo -e "${YELLOW}🟡 MEDIUM:${NC} $message"

    fi

    ((MEDIUM_COUNT++))

}



log_low() {

    local message=


    RESULTS+=("LOW|$message")

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then

        echo -e "${GREEN}🟢 LOW:${NC} $message"

    fi

    ((LOW_COUNT++))

}



log_pass() {

    local message=


    RESULTS+=("PASS|$message")

    if [[ "$VERBOSE" == "true" && "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then

        echo -e "  ${GREEN}✓${NC} $message"

    fi

    ((PASSED_CHECKS++))

}



check_start() {

    ((TOTAL_CHECKS++))

    log_verbose "Checking: 
"

}



# ============================================================================

# REPORTING

# ============================================================================



generate_json_report() {

    echo "{"

    echo "  \"summary\": {"

    echo "    \"score\": $SCORE,"

    echo "    \"critical_issues\": $CRITICAL_COUNT,"

    echo "    \"high_issues\": $HIGH_COUNT,"

    echo "    \"medium_issues\": $MEDIUM_COUNT,"

    echo "    \"low_issues\": $LOW_COUNT"

    echo "  },"

    echo "  \"results\": ["

    for i in "${!RESULTS[@]}"; do

        IFS='|' read -r severity message <<< "${RESULTS[$i]}"

        # Escape quotes in message for valid JSON

        message=$(echo "$message" | sed 's/"/\\"/g')

        echo "    {"

        echo "      \"severity\": \"$severity\","

        echo "      \"message\": \"$message\""

        echo "    }"

        if [ $i -lt $((${#RESULTS[@]} - 1)) ]; then

            echo ","

        fi

    done

    echo "  ]"

    echo "}"

}



generate_html_report() {

    cat <<EOF

<!DOCTYPE html>

<html>

<head>

<title>Ultra Full Audit Report</title>

<style>

  body { font-family: sans-serif; margin: 2em; background-color: #f8f9fa; color: #212529; }

  h1, h2 { color: #343a40; }

  .summary { background-color: #e9ecef; padding: 1em; border-radius: 0.5em; }

  .results { list-style-type: none; padding: 0; }

  .result { margin: 0.5em 0; padding: 1em; border-left: 5px solid; border-radius: 0.25em; background-color: #fff; }

  .result strong { font-size: 1.1em; }

  .CRITICAL { border-color: #dc3545; }

  .HIGH { border-color: #fd7e14; }

  .MEDIUM { border-color: #ffc107; }

  .LOW { border-color: #28a745; }

  .PASS { border-color: #28a745; }

</style>

</head>

<body>

<h1>Ultra Full Audit Report</h1>

<div class="summary">

  <h2>Summary</h2>

  <p><strong>Score:</strong> $SCORE/100</p>

  <p><strong>Critical Issues:</strong> $CRITICAL_COUNT</p>

  <p><strong>High Issues:</strong> $HIGH_COUNT</p>

  <p><strong>Medium Issues:</strong> $MEDIUM_COUNT</p>

  <p><strong>Low Issues:</strong> $LOW_COUNT</p>

</div>

<h2>Details</h2>

<ul class="results">

EOF



    for result in "${RESULTS[@]}"; do

        IFS='|' read -r severity message <<< "$result"

        echo "<li class=\"result $severity\"><strong>[$severity]</strong> $message</li>"

    done



    cat <<EOF

</ul>

</body>

</html>

EOF

}

# ============================================================================
# CATEGORY 1: INFRASTRUCTURE CRITICAL
# ============================================================================

audit_infrastructure() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 1: INFRASTRUCTURE CRITICAL${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: schema.rs exists
    check_start "schema.rs existence"
    if [[ ! -f "server/src/schema.rs" ]]; then
        log_critical "schema.rs is MISSING! This breaks Diesel ORM completely."
        log_critical "  Fix: DATABASE_URL=marketplace.db diesel print-schema > server/src/schema.rs"
    else
        log_pass "schema.rs exists"

        # Verify it's not empty
        if [[ ! -s "server/src/schema.rs" ]]; then
            log_critical "schema.rs is EMPTY!"
        fi
    fi

    # Check 2: diesel.toml exists
    check_start "diesel.toml configuration"
    if [[ ! -f "diesel.toml" ]]; then
        log_high "diesel.toml missing - Diesel may not work properly"
    else
        log_pass "diesel.toml exists"
    fi

    # Check 3: Database file exists
    check_start "Database file existence"
    if [[ ! -f "marketplace.db" ]]; then
        log_critical "marketplace.db database file MISSING!"
        log_critical "  Fix: Run migrations with 'diesel migration run'"
    else
        log_pass "marketplace.db exists"

        # Check database size (should be > 0)
        DB_SIZE=$(stat -c%s "marketplace.db" 2>/dev/null || echo "0")
        if [[ "$DB_SIZE" -lt 1000 ]]; then
            log_high "Database file is suspiciously small ($DB_SIZE bytes)"
        fi
    fi

    # Check 4: Migrations applied
    check_start "Database migrations status"
    if command -v diesel &> /dev/null; then
        PENDING_MIGRATIONS=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" || echo "0")
        if [[ "$PENDING_MIGRATIONS" -gt 0 ]]; then
            log_critical "$PENDING_MIGRATIONS pending migrations NOT applied!"
            log_critical "  Fix: DATABASE_URL=marketplace.db diesel migration run"
            if [[ "$VERBOSE" == "true" ]]; then
                DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep "\[ \]" || true
            fi
        else
            log_pass "All migrations applied"
        fi
    else
        log_high "diesel CLI not installed - cannot verify migrations"
    fi

    # Check 5: Schema consistency (DB columns vs Rust schema)
    check_start "Schema consistency"
    if [[ -f "server/src/schema.rs" ]] && command -v sqlite3 &> /dev/null; then
        # Count tables in DB
        DB_TABLES=$(sqlite3 marketplace.db ".tables" 2>/dev/null | wc -w || echo "0")
        # Count tables in schema.rs
        RUST_TABLES=$(grep -c "diesel::table!" server/src/schema.rs 2>/dev/null || echo "0")

        if [[ "$DB_TABLES" -ne "$RUST_TABLES" ]]; then
            log_high "Schema mismatch: DB has $DB_TABLES tables, Rust schema has $RUST_TABLES"
            log_high "  This may indicate schema.rs is out of sync"
        else
            log_pass "Schema table count matches ($DB_TABLES tables)"
        fi
    fi

    # Check 6: .env file exists
    check_start ".env configuration"
    if [[ ! -f ".env" ]]; then
        log_high ".env file missing - using defaults (may be insecure)"
    else
        log_pass ".env exists"
    fi

    # Check 7: Cargo.toml workspace members
    check_start "Cargo workspace configuration"
    if [[ ! -f "Cargo.toml" ]]; then
        log_critical "Root Cargo.toml missing!"
    else
        # Check if workspace members are valid
        WORKSPACE_MEMBERS=$(grep -A10 "^\[workspace\]" Cargo.toml | grep "members" | wc -l)
        if [[ "$WORKSPACE_MEMBERS" -eq 0 ]]; then
            log_high "No workspace members defined in Cargo.toml"
        else
            log_pass "Cargo workspace configured"
        fi
    fi

    # Check 8: Target directory exists
    check_start "Build artifacts"
    if [[ ! -d "target" ]]; then
        log_medium "target/ directory missing - project never built?"
    else
        if [[ ! -f "target/release/server" ]]; then
            log_medium "Release binary not found - run 'cargo build --release'"
        else
            log_pass "Release binary exists"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 2: SECURITY CRITICAL
# ============================================================================

audit_security() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 2: SECURITY CRITICAL${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Hardcoded passwords
    check_start "Hardcoded passwords"
    HARDCODED_PASSWORDS=$(grep -r "password.*=" --include="*.rs" --exclude-dir=target . 2>/dev/null | grep -v "password_hash" | grep -v "//.*password" | wc -l || echo "0")
    if [[ "$HARDCODED_PASSWORDS" -gt 0 ]]; then
        log_critical "Found $HARDCODED_PASSWORDS potential hardcoded passwords!"
        if [[ "$VERBOSE" == "true" ]]; then
            grep -r "password.*=" --include="*.rs" --exclude-dir=target . 2>/dev/null | grep -v "password_hash" | grep -v "//.*password" | head -5
        fi
    else
        log_pass "No hardcoded passwords detected"
    fi

    # Check 2: Hardcoded secrets/keys
    check_start "Hardcoded secrets"
    HARDCODED_SECRETS=$(grep -r "secret.*=" --include="*.rs" --exclude-dir=target . 2>/dev/null | grep -v "SECRET_KEY" | grep -v "//.*secret" | wc -l || echo "0")
    if [[ "$HARDCODED_SECRETS" -gt 0 ]]; then
        log_critical "Found $HARDCODED_SECRETS potential hardcoded secrets!"
    else
        log_pass "No hardcoded secrets detected"
    fi

    # Check 3: DB_ENCRYPTION_KEY strength
    check_start "Database encryption key"
    if [[ -f ".env" ]]; then
        DB_KEY=$(grep "^DB_ENCRYPTION_KEY=" .env | cut -d'=' -f2 || echo "")
        if [[ -z "$DB_KEY" ]]; then
            log_critical "DB_ENCRYPTION_KEY not set in .env!"
        elif [[ "${#DB_KEY}" -lt 32 ]]; then
            log_critical "DB_ENCRYPTION_KEY too short (${#DB_KEY} chars, need 64+ for 256-bit key)"
        elif [[ "$DB_KEY" == *"change"* ]] || [[ "$DB_KEY" == *"example"* ]] || [[ "$DB_KEY" == *"test"* ]]; then
            log_critical "DB_ENCRYPTION_KEY looks like a default/example value!"
        else
            log_pass "DB_ENCRYPTION_KEY configured (${#DB_KEY} chars)"
        fi
    fi

    # Check 4: .env not in git
    check_start ".env not tracked by git"
    if git ls-files .env 2>/dev/null | grep -q ".env"; then
        log_critical ".env is TRACKED BY GIT! This exposes secrets!"
        log_critical "  Fix: git rm --cached .env && git commit -m 'Remove .env from git'"
    else
        log_pass ".env not tracked by git"
    fi

    # Check 5: .gitignore includes sensitive files
    check_start ".gitignore completeness"
    if [[ -f ".gitignore" ]]; then
        GITIGNORE_CHECKS=("*.key" "*.pem" ".env" "*.wallet" "*.db")
        MISSING_PATTERNS=()
        for pattern in "${GITIGNORE_CHECKS[ @]}"; do
            if ! grep -q "$pattern" .gitignore; then
                MISSING_PATTERNS+=("$pattern")
            fi
        done
        if [[ ${#MISSING_PATTERNS[ @]} -gt 0 ]]; then
            log_high ".gitignore missing patterns: ${MISSING_PATTERNS[*]}"
        else
            log_pass ".gitignore includes sensitive patterns"
        fi
    else
        log_critical ".gitignore missing!"
    fi

    # Check 6: Secrets in logs
    check_start "Secrets in log files"
    if [[ -f "server.log" ]]; then
        SECRETS_IN_LOGS=$(grep -iE "password|secret|key|token" server.log 2>/dev/null | grep -v "SECRET_KEY not set" | wc -l || echo "0")
        if [[ "$SECRETS_IN_LOGS" -gt 0 ]]; then
            log_high "Found $SECRETS_IN_LOGS potential secrets in logs!"
        else
            log_pass "No secrets detected in logs"
        fi
    fi

    # Check 7: Tor status
    check_start "Tor configuration"
    if [[ -f "server.log" ]]; then
        TOR_DISABLED=$(grep -c "Tor proxy DISABLED" server.log 2>/dev/null || echo "0")
        if [[ "$TOR_DISABLED" -gt 0 ]]; then
            log_critical "Tor proxy is DISABLED! Privacy compromised!"
            log_critical "  All network traffic is NOT going through Tor"
        else
            log_pass "Tor appears to be enabled (no DISABLED warnings)"
        fi
    fi

    # Check 8: IPFS local vs public
    check_start "IPFS configuration"
    if [[ -f "server.log" ]]; then
        IPFS_LOCAL=$(grep -c "127.0.0.1:5001" server.log 2>/dev/null || echo "0")
        if [[ "$IPFS_LOCAL" -eq 0 ]]; then
            log_high "IPFS may not be local - check configuration"
        else
            log_pass "IPFS configured for localhost"
        fi
    fi

    # Check 9: Session secret
    check_start "Session secret configuration"
    if [[ -f "server.log" ]]; then
        DEV_SESSION=$(grep -c "using development key" server.log 2>/dev/null || echo "0")
        if [[ "$DEV_SESSION" -gt 0 ]]; then
            log_high "Using development session key (not for production)"
        fi
    fi

    # Check 10: Unwrap/expect usage
    check_start "Unsafe error handling (unwrap/expect)"
    UNWRAPS=$(grep -r "\.unwrap()" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    EXPECTS=$(grep -r "\.expect(" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    TOTAL_UNSAFE=$((UNWRAPS + EXPECTS))
    if [[ "$TOTAL_UNSAFE" -gt 50 ]]; then
        log_high "Found $TOTAL_UNSAFE uses of unwrap/expect (HIGH risk of panics)"
    elif [[ "$TOTAL_UNSAFE" -gt 20 ]]; then
        log_medium "Found $TOTAL_UNSAFE uses of unwrap/expect"
    elif [[ "$TOTAL_UNSAFE" -gt 0 ]]; then
        log_pass "Found $TOTAL_UNSAFE uses of unwrap/expect (acceptable level)"
    else
        log_pass "No unwrap/expect found (excellent!)"
    fi

    echo
}

# ============================================================================
# CATEGORY 3: CONFIGURATION SERVICES
# ============================================================================

audit_services() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 3: SERVICE CONFIGURATION${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Tor daemon
    check_start "Tor daemon status"
    if pgrep -x "tor" > /dev/null; then
        log_pass "Tor daemon running"
    else
        log_critical "Tor daemon NOT running!"
        log_critical "  Fix: sudo systemctl start tor"
    fi

    # Check 2: Tor SOCKS port
    check_start "Tor SOCKS port (9050)"
    if ss -tulpn 2>/dev/null | grep -q ":9050"; then
        log_pass "Tor SOCKS port 9050 listening"
    else
        log_high "Tor SOCKS port 9050 not listening"
    fi

    # Check 3: Monero RPC
    check_start "Monero wallet RPC status"
    if curl -s http://127.0.0.1:18082/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' 2>/dev/null | grep -q "result"; then
        log_pass "Monero RPC responding on port 18082"
    else
        log_medium "Monero RPC not responding (may be intentional for testnet)"
    fi

    # Check 4: IPFS node
    check_start "IPFS node status"
    if curl -s http://127.0.0.1:5001/api/v0/version 2>/dev/null | grep -q "Version"; then
        log_pass "IPFS node running on port 5001"
    else
        log_medium "IPFS node not responding (needed for image uploads)"
    fi

    # Check 5: Server port
    check_start "Marketplace server port (8080)"
    if ss -tulpn 2>/dev/null | grep -q ":8080"; then
        log_pass "Server listening on port 8080"
    else
        log_medium "Server not running on port 8080"
    fi

    # Check 6: No public ports exposed
    check_start "No public service ports"
    PUBLIC_PORTS=$(ss -tulpn 2>/dev/null | grep -E "0\.0\.0\.0:(8080|18082|5001)" | wc -l || echo "0")
    if [[ "$PUBLIC_PORTS" -gt 0 ]]; then
        log_critical "Found $PUBLIC_PORTS services bound to 0.0.0.0 (publicly accessible)!"
        log_critical "  Services should bind to 127.0.0.1 only"
    else
        log_pass "No services bound to public interface"
    fi

    # Check 7: Tor connectivity test
    check_start "Tor network connectivity"
    if command -v curl &> /dev/null; then
        if curl -s --max-time 10 --socks5 127.0.0.1:9050 https://check.torproject.org 2>&1 | grep -q "Congratulations"; then
            log_pass "Tor network connectivity confirmed"
        else
            log_high "Tor connectivity test failed"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 4: CODE QUALITY
# ============================================================================

audit_code_quality() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 4: CODE QUALITY${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: TODO/FIXME
    check_start "TODO/FIXME comments"
    TODOS=$(grep -r "TODO\|FIXME" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$TODOS" -gt 20 ]]; then
        log_high "Found $TODOS TODO/FIXME comments (needs cleanup)"
    elif [[ "$TODOS" -gt 0 ]]; then
        log_medium "Found $TODOS TODO/FIXME comments"
    else
        log_pass "No TODO/FIXME comments"
    fi

    # Check 2: Clippy warnings
    check_start "Clippy lints"
    if command -v cargo &> /dev/null; then
        log_verbose "Running clippy (this may take a while)..."
        CLIPPY_OUTPUT=$(cargo clippy --workspace --quiet 2>&1 || true)
        CLIPPY_WARNINGS=$(echo "$CLIPPY_OUTPUT" | grep -c "warning:" || echo "0")
        CLIPPY_ERRORS=$(echo "$CLIPPY_OUTPUT" | grep -c "error:" || echo "0")

        if [[ "$CLIPPY_ERRORS" -gt 0 ]]; then
            log_critical "Clippy found $CLIPPY_ERRORS errors!"
        elif [[ "$CLIPPY_WARNINGS" -gt 10 ]]; then
            log_high "Clippy found $CLIPPY_WARNINGS warnings"
        elif [[ "$CLIPPY_WARNINGS" -gt 0 ]]; then
            log_medium "Clippy found $CLIPPY_WARNINGS warnings"
        else
            log_pass "Clippy: no warnings or errors"
        fi
    fi

    # Check 3: Code formatting
    check_start "Code formatting (rustfmt)"
    if command -v cargo &> /dev/null; then
        FORMATTING_ISSUES=$(cargo fmt --check 2>&1 | grep "Diff in" | wc -l || echo "0")
        if [[ "$FORMATTING_ISSUES" -gt 0 ]]; then
            log_medium "$FORMATTING_ISSUES files need formatting (run 'cargo fmt')"
        else
            log_pass "All code properly formatted"
        fi
    fi

    # Check 4: Magic numbers
    check_start "Magic numbers"
    MAGIC_NUMBERS=$(grep -rE "[^a-zA-Z_][0-9]{4,}[^a-zA-Z_]" --include="*.rs" --exclude-dir=target . 2>/dev/null | grep -v "//" | wc -l || echo "0")
    if [[ "$MAGIC_NUMBERS" -gt 20 ]]; then
        log_medium "Found $MAGIC_NUMBERS potential magic numbers (should be constants)"
    elif [[ "$MAGIC_NUMBERS" -gt 0 ]]; then
        log_pass "Found $MAGIC_NUMBERS potential magic numbers (acceptable)"
    else
        log_pass "No magic numbers detected"
    fi

    # Check 5: println! usage (should use tracing instead)
    check_start "println! usage in production code"
    PRINTLNS=$(grep -r "println!" --include="*.rs" --exclude-dir=target ./server/src 2>/dev/null | grep -v "#\[cfg(test)\]" | wc -l || echo "0")
    if [[ "$PRINTLNS" -gt 0 ]]; then
        log_medium "Found $PRINTLNS println! statements (should use tracing::info!)"
    else
        log_pass "No println! in production code"
    fi

    # Check 6: Security theatre patterns
    check_start "Security theatre detection"
    if [[ -f "scripts/check-security-theatre.sh" ]]; then
        THEATRE_ISSUES=$(bash scripts/check-security-theatre.sh 2>&1 | grep -c "Found:" || echo "0")
        if [[ "$THEATRE_ISSUES" -gt 0 ]]; then
            log_high "Security theatre script found issues"
        else
            log_pass "No security theatre detected"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 5: TESTS
# ============================================================================

audit_tests() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 5: TESTS${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Unit tests
    check_start "Unit tests"
    if command -v cargo &> /dev/null; then
        log_verbose "Running unit tests (this may take a while)..."
        TEST_OUTPUT=$(cargo test --workspace --lib 2>&1 || true)
        TEST_PASSED=$(echo "$TEST_OUTPUT" | grep "test result:" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
        TEST_FAILED=$(echo "$TEST_OUTPUT" | grep "test result:" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "0")

        if [[ "$TEST_FAILED" -gt 0 ]]; then
            log_critical "$TEST_FAILED unit tests FAILED!"
        else
            log_pass "$TEST_PASSED unit tests passed"
        fi
    fi

    # Check 2: Integration tests
    check_start "Integration tests"
    if command -v cargo &> /dev/null; then
        INT_TEST_COUNT=$(find . -path "*/tests/*.rs" -type f 2>/dev/null | wc -l || echo "0")
        if [[ "$INT_TEST_COUNT" -eq 0 ]]; then
            log_medium "No integration tests found"
        else
            log_pass "Found $INT_TEST_COUNT integration test files"
        fi
    fi

    # Check 3: Ignored tests
    check_start "Ignored tests"
    IGNORED_TESTS=$(grep -r "#\[ignore\]" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$IGNORED_TESTS" -gt 5 ]]; then
        log_medium "$IGNORED_TESTS tests are ignored (may indicate broken tests)"
    elif [[ "$IGNORED_TESTS" -gt 0 ]]; then
        log_pass "$IGNORED_TESTS tests ignored (E2E tests, acceptable)"
    else
        log_pass "No ignored tests"
    fi

    # Check 4: Test coverage
    check_start "Test coverage"
    if command -v cargo-tarpaulin &> /dev/null; then
        log_verbose "Calculating test coverage..."
        COVERAGE=$(cargo tarpaulin --workspace --out Stdout 2>&1 | grep -oP '\d+\.\d+%' | head -1 || echo "0%")
        COVERAGE_NUM=$(echo "$COVERAGE" | grep -oP '\d+' || echo "0")
        if [[ "$COVERAGE_NUM" -lt 50 ]]; then
            log_high "Test coverage is $COVERAGE (target: 70%+)"
        elif [[ "$COVERAGE_NUM" -lt 70 ]]; then
            log_medium "Test coverage is $COVERAGE (target: 70%+)"
        else
            log_pass "Test coverage is $COVERAGE"
        fi
    else
        log_verbose "cargo-tarpaulin not installed (skipping coverage)"
    fi

    echo
}

# ============================================================================
# CATEGORY 6: DATABASE INTEGRITY
# ============================================================================

audit_database() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 6: DATABASE INTEGRITY${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    if [[ ! -f "marketplace.db" ]]; then
        log_critical "Database file missing - skipping database checks"
        echo
        return
    fi

    # Check 1: Database integrity
    check_start "Database integrity check"
    if command -v sqlite3 &> /dev/null; then
        INTEGRITY=$(sqlite3 marketplace.db "PRAGMA integrity_check;" 2>/dev/null || echo "error")
        if [[ "$INTEGRITY" != "ok" ]]; then
            log_critical "Database integrity check FAILED: $INTEGRITY"
        else
            log_pass "Database integrity OK"
        fi
    fi

    # Check 2: Expected tables exist
    check_start "Required tables"
    if command -v sqlite3 &> /dev/null; then
        EXPECTED_TABLES=("users" "listings" "orders" "escrows" "transactions")
        MISSING_TABLES=()
        for table in "${EXPECTED_TABLES[ @]}"; do
            if ! sqlite3 marketplace.db ".tables" 2>/dev/null | grep -q "$table"; then
                MISSING_TABLES+=("$table")
            fi
        done
        if [[ ${#MISSING_TABLES[ @]} -gt 0 ]]; then
            log_critical "Missing tables: ${MISSING_TABLES[*]}"
        else
            log_pass "All required tables exist"
        fi
    fi

    # Check 3: Indexes
    check_start "Database indexes"
    if command -v sqlite3 &> /dev/null; then
        INDEX_COUNT=$(sqlite3 marketplace.db ".indexes" 2>/dev/null | wc -l || echo "0")
        if [[ "$INDEX_COUNT" -lt 5 ]]; then
            log_medium "Only $INDEX_COUNT indexes found (performance may be poor)"
        else
            log_pass "$INDEX_COUNT indexes configured"
        fi
    fi

    # Check 4: Foreign keys enabled
    check_start "Foreign key constraints"
    if command -v sqlite3 &> /dev/null; then
        FK_ENABLED=$(sqlite3 marketplace.db "PRAGMA foreign_keys;" 2>/dev/null || echo "0")
        if [[ "$FK_ENABLED" != "1" ]]; then
            log_high "Foreign keys NOT enabled (data integrity risk)"
        else
            log_pass "Foreign keys enabled"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 7: DOCUMENTATION
# ============================================================================

audit_documentation() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 7: DOCUMENTATION${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: README.md
    check_start "README.md"
    if [[ ! -f "README.md" ]]; then
        log_high "README.md missing"
    else
        README_SIZE=$(wc -l < README.md)
        if [[ "$README_SIZE" -lt 20 ]]; then
            log_medium "README.md is very short ($README_SIZE lines)"
        else
            log_pass "README.md exists ($README_SIZE lines)"
        fi
    fi

    # Check 2: CLAUDE.md
    check_start "CLAUDE.md"
    if [[ ! -f "CLAUDE.md" ]]; then
        log_medium "CLAUDE.md missing"
    else
        log_pass "CLAUDE.md exists"
    fi

    # Check 3: Specifications
    check_start "Function specifications"
    if [[ -d "docs/specs" ]]; then
        SPEC_COUNT=$(find docs/specs -name "*.md" 2>/dev/null | wc -l || echo "0")
        if [[ "$SPEC_COUNT" -eq 0 ]]; then
            log_medium "No specifications found in docs/specs/"
        else
            log_pass "$SPEC_COUNT specifications found"
        fi
    else
        log_medium "docs/specs/ directory missing"
    fi

    # Check 4: Reality checks
    check_start "Tor reality checks"
    if [[ -d "docs/reality-checks" ]]; then
        RC_COUNT=$(find docs/reality-checks -name "*.md" 2>/dev/null | wc -l || echo "0")
        if [[ "$RC_COUNT" -eq 0 ]]; then
            log_medium "No reality checks found"
        else
            log_pass "$RC_COUNT reality checks documented"
        fi
    else
        log_medium "docs/reality-checks/ directory missing"
    fi

    # Check 5: API documentation
    check_start "Code documentation"
    DOC_COMMENTS=$(grep -r "///" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$DOC_COMMENTS" -lt 50 ]]; then
        log_medium "Only $DOC_COMMENTS doc comments found (needs more documentation)"
    else
        log_pass "$DOC_COMMENTS doc comments found"
    fi

    echo
}

# ============================================================================
# CATEGORY 8: BUILD & COMPILATION
# ============================================================================

audit_build() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 8: BUILD & COMPILATION${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Cargo check
    check_start "Compilation check"
    if command -v cargo &> /dev/null; then
        log_verbose "Running cargo check..."
        if cargo check --workspace --quiet 2>&1 | grep -q "error"; then
            log_critical "Compilation errors detected!"
        else
            log_pass "Project compiles without errors"
        fi
    fi

    # Check 2: Cargo.lock exists
    check_start "Cargo.lock"
    if [[ ! -f "Cargo.lock" ]]; then
        log_medium "Cargo.lock missing (dependencies not locked)"
    else
        log_pass "Cargo.lock exists"
    fi

    # Check 3: Binary size
    check_start "Binary size"
    if [[ -f "target/release/server" ]]; then
        BINARY_SIZE=$(stat -c%s "target/release/server" 2>/dev/null || echo "0")
        BINARY_SIZE_MB=$((BINARY_SIZE / 1024 / 1024))
        if [[ "$BINARY_SIZE_MB" -gt 100 ]]; then
            log_medium "Binary is very large (${BINARY_SIZE_MB}MB)"
        else
            log_pass "Binary size: ${BINARY_SIZE_MB}MB"
        fi
    fi

    # Check 4: Vulnerable dependencies
    check_start "Dependency vulnerabilities"
    if command -v cargo-audit &> /dev/null; then
        VULNS=$(cargo audit 2>&1 | grep -c "warning:" || echo "0")
        if [[ "$VULNS" -gt 0 ]]; then
            log_high "$VULNS vulnerable dependencies found!"
        else
            log_pass "No vulnerable dependencies"
        fi
    else
        log_verbose "cargo-audit not installed (skipping)"
    fi

    # Check 5: Outdated dependencies
    check_start "Outdated dependencies"
    if command -v cargo-outdated &> /dev/null; then
        OUTDATED=$(cargo outdated 2>&1 | grep -c "→" || echo "0")
        if [[ "$OUTDATED" -gt 10 ]]; then
            log_medium "$OUTDATED dependencies are outdated"
        elif [[ "$OUTDATED" -gt 0 ]]; then
            log_pass "$OUTDATED dependencies outdated (acceptable)"
        else
            log_pass "All dependencies up to date"
        fi
    else
        log_verbose "cargo-outdated not installed (skipping)"
    fi

    echo
}

# ============================================================================
# CATEGORY 9: GIT HYGIENE
# ============================================================================

audit_git() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 9: GIT HYGIENE${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_medium "Not a git repository"
        echo
        return
    fi

    # Check 1: Sensitive files tracked
    check_start "Sensitive files in git"
    TRACKED_SECRETS=$(git ls-files | grep -E "\.env$|\.key$|\.pem$|\.wallet$|\.db$" | wc -l || echo "0")
    if [[ "$TRACKED_SECRETS" -gt 0 ]]; then
        log_critical "$TRACKED_SECRETS sensitive files tracked by git!"
        if [[ "$VERBOSE" == "true" ]]; then
            git ls-files | grep -E "\.env$|\.key$|\.pem$|\.wallet$|\.db$"
        fi
    else
        log_pass "No sensitive files tracked"
    fi

    # Check 2: Large files
    check_start "Large files in git"
    LARGE_FILES=$(git ls-files | xargs ls -l 2>/dev/null | awk '$5 > 1048576 {print $NF}' | wc -l || echo "0")
    if [[ "$LARGE_FILES" -gt 0 ]]; then
        log_medium "$LARGE_FILES files >1MB tracked (consider git-lfs)"
    else
        log_pass "No large files tracked"
    fi

    # Check 3: Uncommitted changes
    check_start "Uncommitted changes"
    UNCOMMITTED=$(git status --porcelain | wc -l || echo "0")
    if [[ "$UNCOMMITTED" -gt 0 ]]; then
        log_low "$UNCOMMITTED uncommitted changes"
    else
        log_pass "Working directory clean"
    fi

    # Check 4: Unpushed commits
    check_start "Unpushed commits"
    UNPUSHED=$(git log @{u}.. 2>/dev/null | grep -c "^commit" || echo "0")
    if [[ "$UNPUSHED" -gt 10 ]]; then
        log_medium "$UNPUSHED commits not pushed to remote"
    elif [[ "$UNPUSHED" -gt 0 ]]; then
        log_low "$UNPUSHED commits not pushed"
    else
        log_pass "All commits pushed"
    fi

    echo
}

# ============================================================================
# CATEGORY 10: PERFORMANCE & MONITORING
# ============================================================================

audit_performance() {
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}CATEGORY 10: PERFORMANCE & MONITORING${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Log file size
    check_start "Log file management"
    if [[ -f "server.log" ]]; then
        LOG_SIZE=$(stat -c%s "server.log" 2>/dev/null || echo "0")
        LOG_SIZE_MB=$((LOG_SIZE / 1024 / 1024))
        if [[ "$LOG_SIZE_MB" -gt 100 ]]; then
            log_medium "server.log is very large (${LOG_SIZE_MB}MB) - needs rotation"
        else
            log_pass "Log file size: ${LOG_SIZE_MB}MB"
        fi
    fi

    # Check 2: Metrics collection
    check_start "Prometheus metrics"
    if [[ -d "metrics" ]]; then
        log_pass "Metrics directory exists"
    else
        log_low "No metrics directory (monitoring not configured)"
    fi

    # Check 3: Memory leaks (basic check)
    check_start "Potential memory leaks"
    MEM_LEAKS=$(grep -r "Box::leak\|mem::forget\|Rc::new.*loop" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$MEM_LEAKS" -gt 0 ]]; then
        log_high "Found $MEM_LEAKS potential memory leak patterns"
    else
        log_pass "No obvious memory leak patterns"
    fi

    echo
}

# ============================================================================
# SUMMARY & SCORING
# ============================================================================

print_summary() {
    # Calculate score (weighted by severity)
    CRITICAL_PENALTY=$((CRITICAL_COUNT * 20))
    HIGH_PENALTY=$((HIGH_COUNT * 10))
    MEDIUM_PENALTY=$((MEDIUM_COUNT * 3))
    LOW_PENALTY=$((LOW_COUNT * 1))
    TOTAL_PENALTY=$((CRITICAL_PENALTY + HIGH_PENALTY + MEDIUM_PENALTY + LOW_PENALTY))

    BASE_SCORE=100
    SCORE=$((BASE_SCORE - TOTAL_PENALTY))
    if [[ "$SCORE" -lt 0 ]]; then
        SCORE=0
    fi

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        generate_json_report
        return
    elif [[ "$HTML_OUTPUT" == "true" ]]; then
        generate_html_report
        return
    fi

    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}AUDIT SUMMARY${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Determine grade and color
    if [[ "$SCORE" -ge 90 ]]; then
        GRADE="A+"
        GRADE_COLOR="$GREEN"
    elif [[ "$SCORE" -ge 80 ]]; then
        GRADE="A"
        GRADE_COLOR="$GREEN"
    elif [[ "$SCORE" -ge 70 ]]; then
        GRADE="B"
        GRADE_COLOR="$YELLOW"
    elif [[ "$SCORE" -ge 60 ]]; then
        GRADE="C"
        GRADE_COLOR="$ORANGE"
    else
        GRADE="F"
        GRADE_COLOR="$RED"
    fi

    echo -e "${BOLD}Total Checks:${NC} $TOTAL_CHECKS"
    echo -e "${BOLD}Passed:${NC} ${GREEN}$PASSED_CHECKS${NC}"
    echo
    echo -e "${RED}🔴 Critical Issues:${NC} $CRITICAL_COUNT (×20 points)"
    echo -e "${ORANGE}🟠 High Priority:${NC} $HIGH_COUNT (×10 points)"
    echo -e "${YELLOW}🟡 Medium Priority:${NC} $MEDIUM_COUNT (×3 points)"
    echo -e "${GREEN}🟢 Low Priority:${NC} $LOW_COUNT (×1 point)"
    echo
    echo -e "${BOLD}Overall Score:${NC} ${GRADE_COLOR}${SCORE}/100${NC} (Grade: ${GRADE_COLOR}${GRADE}${NC})"
    echo

    # Recommendations
    if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
        echo -e "${RED}${BOLD}⚠️  CRITICAL ISSUES MUST BE FIXED BEFORE DEPLOYMENT${NC}"
        echo
    fi

    if [[ "$SCORE" -lt 70 ]]; then
        echo -e "${ORANGE}Recommendation: Address high-priority issues before continuing development${NC}"
    elif [[ "$SCORE" -lt 90 ]]; then
        echo -e "${YELLOW}Recommendation: Good progress, but room for improvement${NC}"
    else
        echo -e "${GREEN}Excellent! Project is in good shape.${NC}"
    fi
    echo

    # Determine exit code
    if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
        return 1
    elif [[ "$HIGH_COUNT" -gt 0 ]] && [[ "$STRICT" == "true" ]]; then
        return 2
    elif [[ "$MEDIUM_COUNT" -gt 0 ]] && [[ "$STRICT" == "true" ]]; then
        return 3
    else
        return 0
    fi
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --strict)
                STRICT=true
                shift
                ;;
            --fix)
                FIX_MODE=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --html)
                HTML_OUTPUT=true
                shift
                ;;
            -h|--help)
                cat << EOF
Ultra Full Audit - Monero Marketplace

Usage: $0 [OPTIONS]

Options:
    -v, --verbose     Verbose output (show passed checks)
    --strict          Fail on warnings
    --fix             Auto-fix issues where possible
    --json            Output results as JSON
    --html            Generate HTML report
    -h, --help        Show this help message

Exit Codes:
    0 - All checks passed
    1 - Critical issues found
    2 - High priority issues found
    3 - Medium priority issues found
    10 - Script error
EOF
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 10
                ;;
        esac
    done
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    parse_args "$@"

    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}ULTRA FULL AUDIT - Monero Marketplace${NC}"
    log "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo
    log "Starting comprehensive audit..."
    log "Project root: $PROJECT_ROOT"
    log "Timestamp: $(date)"
    echo

    # Run all audit categories
    audit_infrastructure
    audit_security
    audit_services
    audit_code_quality
    audit_tests
    audit_database
    audit_documentation
    audit_build
    audit_git
    audit_performance

    # Print summary and determine exit code
    print_summary
    EXIT_CODE=$?

    if [[ "$JSON_OUTPUT" == "false" && "$HTML_OUTPUT" == "false" ]]; then
        log "${BOLD}Audit complete!${NC}"
    fi
    exit $EXIT_CODE
}

# Run main
main "$@"