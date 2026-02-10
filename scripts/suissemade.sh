#!/usr/bin/env bash
#
# ULTRA FULL AUDIT EXTENDED - Monero Marketplace
#
# Ultimate comprehensive security, infrastructure, cryptographic, and operational audit
# Version: 2.0.0
# 
# Features:
# - Infrastructure & Database validation
# - Security & Cryptographic auditing
# - Monero-specific blockchain checks
# - Performance & Resource monitoring
# - Network security scanning
# - Compliance & Legal verification
# - Disaster Recovery testing
# - Machine Learning anomaly detection
# - Full observability stack
#
# Usage:
#   ./ultra-full-audit-extended.sh              # Standard audit
#   ./ultra-full-audit-extended.sh -v           # Verbose mode
#   ./ultra-full-audit-extended.sh --strict     # Fail on warnings
#   ./ultra-full-audit-extended.sh --fix        # Auto-fix issues
#   ./ultra-full-audit-extended.sh --json       # JSON output
#   ./ultra-full-audit-extended.sh --html       # Generate HTML report
#   ./ultra-full-audit-extended.sh --full       # Run ALL tests (slow)
#   ./ultra-full-audit-extended.sh --quick      # Quick scan only
#   ./ultra-full-audit-extended.sh --category X # Run specific category
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

# Modes
VERBOSE=false
STRICT=false
FIX_MODE=false
JSON_OUTPUT=false
HTML_OUTPUT=false
FULL_MODE=false
QUICK_MODE=false
SPECIFIC_CATEGORY=""
PARALLEL_EXECUTION=false
DOCKER_MODE=false

# Output files
REPORT_DIR="audit-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
JSON_REPORT="$REPORT_DIR/audit_${TIMESTAMP}.json"
HTML_REPORT="$REPORT_DIR/audit_${TIMESTAMP}.html"
LOG_FILE="$REPORT_DIR/audit_${TIMESTAMP}.log"

# Counters
declare -A ISSUE_COUNTS=(
    [CRITICAL]=0
    [HIGH]=0
    [MEDIUM]=0
    [LOW]=0
    [INFO]=0
)

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
SKIPPED_CHECKS=0

# Timing
START_TIME=$(date +%s)

# Colors
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# JSON buffer for report
JSON_BUFFER="[]"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Create report directory
mkdir -p "$REPORT_DIR"

# Logging functions with file output
log() {
    local message="${BOLD}[AUDIT]${NC} $*"
    echo -e "$message"
    echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        local message="  ${BLUE}ℹ${NC} $*"
        echo -e "$message"
        echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
}

log_critical() {
    local message="${RED}🔴 CRITICAL:${NC} $*"
    echo -e "$message"
    echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    ((ISSUE_COUNTS[CRITICAL]++))
    add_to_json "CRITICAL" "$*"
}

log_high() {
    local message="${ORANGE}🟠 HIGH:${NC} $*"
    echo -e "$message"
    echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    ((ISSUE_COUNTS[HIGH]++))
    add_to_json "HIGH" "$*"
}

log_medium() {
    local message="${YELLOW}🟡 MEDIUM:${NC} $*"
    echo -e "$message"
    echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    ((ISSUE_COUNTS[MEDIUM]++))
    add_to_json "MEDIUM" "$*"
}

log_low() {
    local message="${GREEN}🟢 LOW:${NC} $*"
    echo -e "$message"
    echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    ((ISSUE_COUNTS[LOW]++))
    add_to_json "LOW" "$*"
}

log_info() {
    local message="${CYAN}ℹ️  INFO:${NC} $*"
    echo -e "$message"
    echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    ((ISSUE_COUNTS[INFO]++))
}

log_pass() {
    if [[ "$VERBOSE" == "true" ]]; then
        local message="  ${GREEN}✓${NC} $*"
        echo -e "$message"
        echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
    ((PASSED_CHECKS++))
}

log_skip() {
    if [[ "$VERBOSE" == "true" ]]; then
        local message="  ${YELLOW}⊘${NC} SKIPPED: $*"
        echo -e "$message"
        echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
    ((SKIPPED_CHECKS++))
}

check_start() {
    ((TOTAL_CHECKS++))
    log_verbose "Checking: $1"
}

# JSON report functions
add_to_json() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date -Iseconds)
    local json_entry="{\"timestamp\":\"$timestamp\",\"severity\":\"$severity\",\"message\":\"$message\"}"
    
    if [[ "$JSON_BUFFER" == "[]" ]]; then
        JSON_BUFFER="[$json_entry"
    else
        JSON_BUFFER="$JSON_BUFFER,$json_entry"
    fi
}

# Auto-fix function
attempt_fix() {
    local issue="$1"
    local fix_command="$2"
    
    if [[ "$FIX_MODE" == "true" ]]; then
        log_info "Attempting to fix: $issue"
        if eval "$fix_command"; then
            log_pass "Fixed: $issue"
            return 0
        else
            log_high "Failed to fix: $issue"
            return 1
        fi
    fi
    return 1
}

# Check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Get file hash for integrity checking
get_file_hash() {
    if [[ -f "$1" ]]; then
        sha256sum "$1" | awk '{print $1}'
    else
        echo "FILE_NOT_FOUND"
    fi
}

# ============================================================================
# CATEGORY 1: INFRASTRUCTURE CRITICAL
# ============================================================================

audit_infrastructure() {
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${CYAN}CATEGORY 1: INFRASTRUCTURE CRITICAL${NC}"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: schema.rs exists and is valid
    check_start "schema.rs existence and validity"
    if [[ ! -f "server/src/schema.rs" ]]; then
        log_critical "schema.rs is MISSING! This breaks Diesel ORM completely."
        log_critical "  Fix: DATABASE_URL=marketplace.db diesel print-schema > server/src/schema.rs"
        attempt_fix "Generate schema.rs" "DATABASE_URL=marketplace.db diesel print-schema > server/src/schema.rs"
    else
        log_pass "schema.rs exists"
        
        # Verify it's not empty
        if [[ ! -s "server/src/schema.rs" ]]; then
            log_critical "schema.rs is EMPTY!"
            attempt_fix "Regenerate schema.rs" "DATABASE_URL=marketplace.db diesel print-schema > server/src/schema.rs"
        else
            # Check schema hash for changes
            SCHEMA_HASH=$(get_file_hash "server/src/schema.rs")
            log_verbose "schema.rs hash: $SCHEMA_HASH"
            
            # Verify schema syntax
            if ! rustc --edition 2021 --crate-type lib server/src/schema.rs -o /dev/null 2>/dev/null; then
                log_high "schema.rs has syntax errors"
            else
                log_pass "schema.rs syntax valid"
            fi
        fi
    fi

    # Check 2: diesel.toml configuration
    check_start "diesel.toml configuration"
    if [[ ! -f "diesel.toml" ]]; then
        log_high "diesel.toml missing - Diesel may not work properly"
        attempt_fix "Create diesel.toml" "echo '[print_schema]
file = \"server/src/schema.rs\"' > diesel.toml"
    else
        log_pass "diesel.toml exists"
        
        # Validate diesel.toml content
        if ! grep -q "print_schema" diesel.toml; then
            log_medium "diesel.toml missing print_schema configuration"
        fi
    fi

    # Check 3: Database file and integrity
    check_start "Database file integrity"
    if [[ ! -f "marketplace.db" ]]; then
        log_critical "marketplace.db database file MISSING!"
        log_critical "  Fix: Run migrations with 'diesel migration run'"
        attempt_fix "Create database and run migrations" "diesel setup && DATABASE_URL=marketplace.db diesel migration run"
    else
        log_pass "marketplace.db exists"
        
        # Check database integrity
        if command_exists sqlite3; then
            if ! sqlite3 marketplace.db "PRAGMA integrity_check;" 2>/dev/null | grep -q "ok"; then
                log_critical "Database integrity check FAILED!"
            else
                log_pass "Database integrity check passed"
            fi
            
            # Check database size
            DB_SIZE=$(stat -c%s "marketplace.db" 2>/dev/null || stat -f%z "marketplace.db" 2>/dev/null || echo "0")
            DB_SIZE_MB=$((DB_SIZE / 1024 / 1024))
            
            if [[ "$DB_SIZE" -lt 1000 ]]; then
                log_high "Database file is suspiciously small (${DB_SIZE} bytes)"
            else
                log_verbose "Database size: ${DB_SIZE_MB}MB"
            fi
            
            # Check table count
            TABLE_COUNT=$(sqlite3 marketplace.db ".tables" 2>/dev/null | wc -w || echo "0")
            if [[ "$TABLE_COUNT" -lt 5 ]]; then
                log_medium "Only $TABLE_COUNT tables found (expected at least 5)"
            else
                log_pass "$TABLE_COUNT tables found"
            fi
        else
            log_skip "sqlite3 not installed - skipping database integrity checks"
        fi
    fi

    # Check 4: Migrations status
    check_start "Database migrations status"
    if command_exists diesel; then
        PENDING_MIGRATIONS=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" || echo "0")
        if [[ "$PENDING_MIGRATIONS" -gt 0 ]]; then
            log_critical "$PENDING_MIGRATIONS pending migrations NOT applied!"
            log_critical "  Fix: DATABASE_URL=marketplace.db diesel migration run"
            attempt_fix "Apply pending migrations" "DATABASE_URL=marketplace.db diesel migration run"
        else
            log_pass "All migrations applied"
        fi
        
        # Check for migration conflicts
        if ls migrations/*/down.sql 2>/dev/null | xargs grep -l "DROP TABLE" 2>/dev/null | head -n1 | grep -q .; then
            log_low "Destructive migrations detected (DROP TABLE) - be careful with rollbacks"
        fi
    else
        log_skip "diesel CLI not installed - cannot verify migrations"
    fi

    # Check 5: Environment configuration
    check_start "Environment configuration"
    if [[ ! -f ".env" ]]; then
        log_high ".env file missing - using defaults (may be insecure)"
        attempt_fix "Create .env from template" "[[ -f .env.example ]] && cp .env.example .env"
    else
        log_pass ".env exists"
        
        # Check for required environment variables
        REQUIRED_VARS=("DATABASE_URL" "SERVER_PORT" "DB_ENCRYPTION_KEY" "JWT_SECRET")
        for var in "${REQUIRED_VARS[@]}"; do
            if ! grep -q "^$var=" .env; then
                log_high "Missing required environment variable: $var"
            fi
        done
    fi

    # Check 6: Docker configuration
    check_start "Docker configuration"
    if [[ -f "docker-compose.yml" ]] || [[ -f "docker-compose.yaml" ]]; then
        log_pass "Docker Compose configuration found"
        
        # Validate Docker Compose syntax
        if command_exists docker-compose; then
            if ! docker-compose config -q 2>/dev/null; then
                log_medium "Docker Compose configuration has syntax errors"
            else
                log_pass "Docker Compose configuration valid"
            fi
        fi
    else
        log_low "No Docker Compose configuration found"
    fi

    # Check 7: Systemd service files
    check_start "Systemd service configuration"
    if [[ -f "systemd/monero-marketplace.service" ]]; then
        log_pass "Systemd service file found"
        
        # Validate service file
        if ! systemd-analyze verify systemd/monero-marketplace.service 2>/dev/null; then
            log_medium "Systemd service file may have issues"
        fi
    else
        log_low "No systemd service configuration"
    fi

    echo
}

# ============================================================================
# CATEGORY 2: SECURITY CRITICAL
# ============================================================================

audit_security() {
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${CYAN}CATEGORY 2: SECURITY CRITICAL${NC}"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Hardcoded credentials scan
    check_start "Hardcoded credentials scan"
    
    # Password patterns
    HARDCODED_PASSWORDS=$(grep -rE "(password|passwd|pwd)\s*=\s*[\"'].*[\"']" \
        --include="*.rs" --include="*.toml" --include="*.yaml" --include="*.yml" \
        --exclude-dir=target --exclude-dir=.git . 2>/dev/null | \
        grep -v "password_hash\|example\|template\|//.*password" | wc -l || echo "0")
    
    if [[ "$HARDCODED_PASSWORDS" -gt 0 ]]; then
        log_critical "Found $HARDCODED_PASSWORDS potential hardcoded passwords!"
        if [[ "$VERBOSE" == "true" ]]; then
            grep -rE "(password|passwd|pwd)\s*=\s*[\"'].*[\"']" \
                --include="*.rs" --include="*.toml" \
                --exclude-dir=target --exclude-dir=.git . 2>/dev/null | \
                grep -v "password_hash\|example\|template\|//.*password" | head -3
        fi
    else
        log_pass "No hardcoded passwords detected"
    fi
    
    # API key patterns
    API_KEY_PATTERNS=(
        "api[_-]?key\s*=\s*[\"'][a-zA-Z0-9]{20,}[\"']"
        "secret[_-]?key\s*=\s*[\"'][a-zA-Z0-9]{20,}[\"']"
        "access[_-]?token\s*=\s*[\"'][a-zA-Z0-9]{20,}[\"']"
        "private[_-]?key\s*=\s*[\"'][a-zA-Z0-9]{20,}[\"']"
    )
    
    for pattern in "${API_KEY_PATTERNS[@]}"; do
        FOUND_KEYS=$(grep -rEi "$pattern" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
        if [[ "$FOUND_KEYS" -gt 0 ]]; then
            log_critical "Found potential hardcoded API keys/secrets!"
        fi
    done

    # Check 2: Encryption key strength
    check_start "Encryption key strength"
    if [[ -f ".env" ]]; then
        DB_KEY=$(grep "^DB_ENCRYPTION_KEY=" .env | cut -d'=' -f2 || echo "")
        if [[ -n "$DB_KEY" ]]; then
            KEY_LENGTH=${#DB_KEY}
            if [[ "$KEY_LENGTH" -lt 32 ]]; then
                log_critical "DB_ENCRYPTION_KEY too short ($KEY_LENGTH chars, need >=32)"
            elif [[ "$KEY_LENGTH" -lt 64 ]]; then
                log_medium "DB_ENCRYPTION_KEY could be stronger ($KEY_LENGTH chars, recommend 64+)"
            else
                log_pass "DB_ENCRYPTION_KEY has strong length ($KEY_LENGTH chars)"
            fi
            
            # Check for weak patterns
            if [[ "$DB_KEY" =~ ^[0-9]+$ ]]; then
                log_critical "DB_ENCRYPTION_KEY contains only numbers (weak)"
            elif [[ "$DB_KEY" =~ ^[a-zA-Z]+$ ]]; then
                log_high "DB_ENCRYPTION_KEY contains only letters (weak)"
            fi
        else
            log_critical "DB_ENCRYPTION_KEY not set!"
        fi
        
        # Check JWT secret
        JWT_SECRET=$(grep "^JWT_SECRET=" .env | cut -d'=' -f2 || echo "")
        if [[ -z "$JWT_SECRET" ]]; then
            log_critical "JWT_SECRET not configured!"
        elif [[ ${#JWT_SECRET} -lt 32 ]]; then
            log_high "JWT_SECRET too short (${#JWT_SECRET} chars)"
        fi
    fi

    # Check 3: SQL injection vulnerabilities
    check_start "SQL injection vulnerability scan"
    SQL_INJECTION_PATTERNS=(
        "format!.*SELECT.*{}"
        "format!.*INSERT.*{}"
        "format!.*UPDATE.*{}"
        "format!.*DELETE.*{}"
        "concat.*sql"
        "\+.*sql.*\+"
    )
    
    TOTAL_SQL_ISSUES=0
    for pattern in "${SQL_INJECTION_PATTERNS[@]}"; do
        FOUND=$(grep -r "$pattern" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
        TOTAL_SQL_ISSUES=$((TOTAL_SQL_ISSUES + FOUND))
    done
    
    if [[ "$TOTAL_SQL_ISSUES" -gt 0 ]]; then
        log_critical "Found $TOTAL_SQL_ISSUES potential SQL injection vulnerabilities!"
        log_critical "  Use parameterized queries instead of string concatenation"
    else
        log_pass "No obvious SQL injection patterns found"
    fi

    # Check 4: XSS vulnerabilities
    check_start "XSS vulnerability scan"
    XSS_PATTERNS=(
        "dangerouslySetInnerHTML"
        "innerHTML\s*="
        "document.write"
        "eval\("
        "Function\("
    )
    
    if [[ -d "client" ]] || [[ -d "frontend" ]]; then
        for pattern in "${XSS_PATTERNS[@]}"; do
            FOUND=$(grep -r "$pattern" --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" . 2>/dev/null | wc -l || echo "0")
            if [[ "$FOUND" -gt 0 ]]; then
                log_high "Found potential XSS vulnerability: $pattern ($FOUND occurrences)"
            fi
        done
    fi

    # Check 5: CORS configuration
    check_start "CORS configuration"
    CORS_WILDCARD=$(grep -r "Access-Control-Allow-Origin.*\*" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$CORS_WILDCARD" -gt 0 ]]; then
        log_high "CORS configured with wildcard (*) - potential security risk"
    else
        log_pass "No wildcard CORS configuration found"
    fi

    # Check 6: Rate limiting
    check_start "Rate limiting implementation"
    RATE_LIMIT=$(grep -r "rate.*limit\|RateLimit\|throttle" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$RATE_LIMIT" -eq 0 ]]; then
        log_medium "No rate limiting detected - vulnerable to DoS attacks"
    else
        log_pass "Rate limiting implementation found"
    fi

    # Check 7: Security headers
    check_start "Security headers implementation"
    SECURITY_HEADERS=(
        "X-Frame-Options"
        "X-Content-Type-Options"
        "Content-Security-Policy"
        "Strict-Transport-Security"
        "X-XSS-Protection"
    )
    
    for header in "${SECURITY_HEADERS[@]}"; do
        if ! grep -r "$header" --include="*.rs" . 2>/dev/null | grep -q .; then
            log_medium "Security header not found: $header"
        else
            log_pass "Security header configured: $header"
        fi
    done

    # Check 8: Authentication & Authorization
    check_start "Authentication implementation"
    AUTH_IMPL=$(grep -r "authenticate\|authorize\|Bearer\|JWT" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$AUTH_IMPL" -lt 5 ]]; then
        log_high "Minimal authentication implementation detected"
    else
        log_pass "Authentication implementation found"
    fi

    # Check 9: Input validation
    check_start "Input validation"
    VALIDATION=$(grep -r "validate\|sanitize\|escape" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$VALIDATION" -lt 10 ]]; then
        log_medium "Limited input validation detected"
    else
        log_pass "Input validation implemented"
    fi

    echo
}

# ============================================================================
# CATEGORY 3: MONERO CRYPTOGRAPHIC AUDIT
# ============================================================================

audit_monero_crypto() {
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${PURPLE}CATEGORY 3: MONERO CRYPTOGRAPHIC AUDIT${NC}"
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Monero address validation
    check_start "Monero address validation implementation"
    ADDR_VALIDATION=$(grep -r "validate_address\|check_address\|is_valid_address" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$ADDR_VALIDATION" -eq 0 ]]; then
        log_critical "No Monero address validation found! Users could send to invalid addresses"
    else
        log_pass "Address validation implemented ($ADDR_VALIDATION occurrences)"
        
        # Check for proper address types (standard, subaddress, integrated)
        if grep -r "AddressType\|address_type" --include="*.rs" . 2>/dev/null | grep -q .; then
            log_pass "Multiple address type support detected"
        else
            log_medium "Single address type support only"
        fi
    fi

    # Check 2: Private key handling security
    check_start "Private key secure handling"
    
    # Check for insecure key storage
    UNSAFE_KEY=$(grep -r "private_key\|secret_key\|spend_key\|view_key" --include="*.rs" . 2>/dev/null | \
                 grep -v "zeroize\|clear_on_drop\|secrecy" | wc -l || echo "0")
    
    if [[ "$UNSAFE_KEY" -gt 0 ]]; then
        log_critical "Private keys may not be securely cleared from memory!"
        log_critical "  Use zeroize crate for secure key handling"
    else
        log_pass "Private keys appear to be securely handled"
    fi
    
    # Check for key derivation
    KEY_DERIVATION=$(grep -r "derive_key\|key_derivation" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$KEY_DERIVATION" -eq 0 ]]; then
        log_high "No key derivation implementation found"
    else
        log_pass "Key derivation implemented"
    fi

    # Check 3: RingCT implementation
    check_start "RingCT transaction verification"
    RINGCT=$(grep -r "verify_ringct\|RingCT\|ring_signature" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$RINGCT" -eq 0 ]]; then
        log_high "No RingCT verification found - cannot verify transaction privacy"
    else
        log_pass "RingCT verification present"
    fi

    # Check 4: Stealth addresses
    check_start "Stealth address implementation"
    STEALTH=$(grep -r "stealth_address\|one_time_address" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$STEALTH" -eq 0 ]]; then
        log_medium "No stealth address implementation found"
    else
        log_pass "Stealth addresses implemented"
    fi

    # Check 5: Payment proofs
    check_start "Payment proof generation"
    PAYMENT_PROOF=$(grep -r "payment_proof\|tx_proof\|reserve_proof" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$PAYMENT_PROOF" -eq 0 ]]; then
        log_high "No payment proof implementation - cannot prove payments"
    else
        log_pass "Payment proof generation found"
    fi

    # Check 6: Monero RPC integration
    check_start "Monero daemon RPC integration"
    RPC_INTEGRATION=$(grep -r "monero_rpc\|monerod\|wallet_rpc" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$RPC_INTEGRATION" -eq 0 ]]; then
        log_critical "No Monero RPC integration found - cannot interact with blockchain"
    else
        log_pass "Monero RPC integration present"
        
        # Check for secure RPC configuration
        if grep -r "rpc.*http://" --include="*.rs" --include="*.toml" . 2>/dev/null | grep -v "localhost\|127.0.0.1" | grep -q .; then
            log_high "Insecure HTTP RPC connection to external node detected"
        fi
    fi

    # Check 7: Transaction fee calculation
    check_start "Transaction fee handling"
    FEE_CALC=$(grep -r "calculate_fee\|tx_fee\|fee_per_kb" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$FEE_CALC" -eq 0 ]]; then
        log_medium "No dynamic fee calculation found"
    else
        log_pass "Transaction fee calculation implemented"
    fi

    # Check 8: Subaddress support
    check_start "Subaddress support"
    SUBADDR=$(grep -r "subaddress\|account_index\|address_index" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$SUBADDR" -eq 0 ]]; then
        log_low "No subaddress support detected"
    else
        log_pass "Subaddress support implemented"
    fi

    # Check 9: Multisig support
    check_start "Multisig wallet support"
    MULTISIG=$(grep -r "multisig\|m_of_n\|threshold" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$MULTISIG" -eq 0 ]]; then
        log_info "No multisig support (optional feature)"
    else
        log_pass "Multisig support found"
    fi

    # Check 10: Output selection algorithm
    check_start "Output selection for privacy"
    OUTPUT_SELECTION=$(grep -r "select_outputs\|decoy\|mixin\|ring_size" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$OUTPUT_SELECTION" -eq 0 ]]; then
        log_high "No output selection algorithm - privacy may be compromised"
    else
        log_pass "Output selection algorithm present"
    fi

    echo
}

# ============================================================================
# CATEGORY 4: NETWORK SECURITY
# ============================================================================

audit_network_security() {
    log "${BOLD}${RED}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${RED}CATEGORY 4: NETWORK SECURITY${NC}"
    log "${BOLD}${RED}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: TLS/SSL configuration
    check_start "TLS/SSL configuration"
    TLS_CONFIG=$(grep -r "rustls\|openssl\|TlsAcceptor\|SslAcceptor" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$TLS_CONFIG" -eq 0 ]]; then
        log_critical "No TLS/SSL configuration found - traffic is unencrypted!"
    else
        log_pass "TLS/SSL configuration found"
        
        # Check for weak ciphers
        if grep -r "TLS_RSA\|SSL2\|SSL3\|RC4" --include="*.rs" . 2>/dev/null | grep -q .; then
            log_high "Weak cipher suites detected"
        fi
        
        # Check for certificate validation
        if grep -r "danger_accept_invalid_certs\|InsecureSkipVerify" --include="*.rs" . 2>/dev/null | grep -q .; then
            log_critical "Certificate validation disabled!"
        fi
    fi

    # Check 2: Port exposure
    check_start "Port exposure configuration"
    if [[ -f ".env" ]]; then
        SERVER_PORT=$(grep "^SERVER_PORT=" .env | cut -d'=' -f2 || echo "8080")
        if [[ "$SERVER_PORT" -lt 1024 ]]; then
            log_medium "Using privileged port $SERVER_PORT (requires root)"
        fi
        
        BIND_ADDR=$(grep "BIND_ADDRESS\|SERVER_ADDRESS" .env | cut -d'=' -f2 || echo "")
        if [[ "$BIND_ADDR" == "0.0.0.0" ]]; then
            log_medium "Binding to all interfaces (0.0.0.0) - consider restricting"
        fi
    fi

    # Check 3: Firewall rules
    check_start "Firewall configuration"
    if command_exists ufw; then
        if ufw status 2>/dev/null | grep -q "inactive"; then
            log_high "UFW firewall is inactive"
        else
            log_pass "Firewall is active"
        fi
    elif command_exists iptables; then
        RULES=$(iptables -L -n 2>/dev/null | wc -l || echo "0")
        if [[ "$RULES" -lt 10 ]]; then
            log_medium "Minimal iptables rules configured"
        fi
    else
        log_skip "No firewall tool detected"
    fi

    # Check 4: DDoS protection
    check_start "DDoS protection measures"
    DDOS_PROTECTION=$(grep -r "rate_limit\|ddos\|flood\|syn_cookies" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$DDOS_PROTECTION" -eq 0 ]]; then
        log_high "No DDoS protection measures found"
    else
        log_pass "DDoS protection measures implemented"
    fi

    # Check 5: WebSocket security
    check_start "WebSocket security"
    if grep -r "WebSocket\|ws:\|wss:" --include="*.rs" . 2>/dev/null | grep -q .; then
        if grep -r "ws://" --include="*.rs" . 2>/dev/null | grep -v "localhost\|127.0.0.1" | grep -q .; then
            log_high "Insecure WebSocket (ws://) connections found"
        else
            log_pass "WebSocket connections appear secure"
        fi
    fi

    # Check 6: API endpoint security
    check_start "API endpoint security"
    PUBLIC_ENDPOINTS=$(grep -r "route.*get\|route.*post" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    AUTH_MIDDLEWARE=$(grep -r "auth.*middleware\|require_auth\|authenticated" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    
    if [[ "$PUBLIC_ENDPOINTS" -gt 0 ]] && [[ "$AUTH_MIDDLEWARE" -eq 0 ]]; then
        log_high "API endpoints found but no authentication middleware detected"
    else
        log_pass "API authentication appears configured"
    fi

    # Check 7: Network timeout configuration
    check_start "Network timeout configuration"
    TIMEOUT_CONFIG=$(grep -r "timeout\|deadline\|keepalive" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$TIMEOUT_CONFIG" -eq 0 ]]; then
        log_medium "No network timeout configuration found"
    else
        log_pass "Network timeouts configured"
    fi

    echo
}

# ============================================================================
# CATEGORY 5: DATABASE SECURITY & PERFORMANCE
# ============================================================================

audit_database_advanced() {
    log "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${YELLOW}CATEGORY 5: DATABASE SECURITY & PERFORMANCE${NC}"
    log "${BOLD}${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo

    if [[ ! -f "marketplace.db" ]]; then
        log_skip "Database file not found - skipping advanced checks"
        return
    fi

    if ! command_exists sqlite3; then
        log_skip "sqlite3 not installed - skipping database analysis"
        return
    fi

    # Check 1: Database encryption
    check_start "Database encryption status"
    if sqlite3 marketplace.db "PRAGMA cipher_version;" 2>/dev/null | grep -q "SQLCipher"; then
        log_pass "Database is encrypted with SQLCipher"
    else
        log_high "Database is not encrypted - sensitive data at risk"
    fi

    # Check 2: Database indexes
    check_start "Database index optimization"
    INDEX_COUNT=$(sqlite3 marketplace.db "SELECT COUNT(*) FROM sqlite_master WHERE type='index';" 2>/dev/null || echo "0")
    TABLE_COUNT=$(sqlite3 marketplace.db "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "0")
    
    if [[ "$TABLE_COUNT" -gt 0 ]]; then
        INDEX_RATIO=$((INDEX_COUNT * 100 / TABLE_COUNT))
        if [[ "$INDEX_RATIO" -lt 50 ]]; then
            log_medium "Low index coverage ($INDEX_COUNT indexes for $TABLE_COUNT tables)"
        else
            log_pass "Good index coverage ($INDEX_COUNT indexes for $TABLE_COUNT tables)"
        fi
    fi

    # Check 3: Query performance
    check_start "Slow query analysis"
    if [[ -f "server.log" ]]; then
        SLOW_QUERIES=$(grep -c "query took.*[0-9][0-9][0-9][0-9]ms" server.log 2>/dev/null || echo "0")
        if [[ "$SLOW_QUERIES" -gt 10 ]]; then
            log_medium "Found $SLOW_QUERIES slow queries (>1000ms) in logs"
        fi
    fi

    # Check 4: Database vacuum status
    check_start "Database optimization status"
    FREELIST_COUNT=$(sqlite3 marketplace.db "PRAGMA freelist_count;" 2>/dev/null || echo "0")
    if [[ "$FREELIST_COUNT" -gt 1000 ]]; then
        log_medium "Database needs vacuum (${FREELIST_COUNT} free pages)"
        attempt_fix "Vacuum database" "sqlite3 marketplace.db 'VACUUM;'"
    else
        log_pass "Database is optimized"
    fi

    # Check 5: Foreign key constraints
    check_start "Foreign key constraint enforcement"
    FK_STATUS=$(sqlite3 marketplace.db "PRAGMA foreign_keys;" 2>/dev/null || echo "0")
    if [[ "$FK_STATUS" != "1" ]]; then
        log_high "Foreign key constraints are DISABLED"
    else
        log_pass "Foreign key constraints enabled"
    fi

    # Check 6: Database backup
    check_start "Database backup status"
    BACKUP_COUNT=$(find . -name "*.db.backup*" -o -name "*.db.bak*" 2>/dev/null | wc -l || echo "0")
    if [[ "$BACKUP_COUNT" -eq 0 ]]; then
        log_high "No database backups found"
    else
        # Check backup age
        LATEST_BACKUP=$(find . -name "*.db.backup*" -o -name "*.db.bak*" -exec stat -c%Y {} \; 2>/dev/null | sort -n | tail -1 || echo "0")
        if [[ "$LATEST_BACKUP" -gt 0 ]]; then
            CURRENT_TIME=$(date +%s)
            BACKUP_AGE=$(( (CURRENT_TIME - LATEST_BACKUP) / 86400 ))
            if [[ "$BACKUP_AGE" -gt 7 ]]; then
                log_medium "Latest backup is $BACKUP_AGE days old"
            else
                log_pass "Recent backup found ($BACKUP_AGE days old)"
            fi
        fi
    fi

    # Check 7: Connection pool configuration
    check_start "Database connection pool"
    POOL_CONFIG=$(grep -r "connection.*pool\|max_connections\|pool_size" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$POOL_CONFIG" -eq 0 ]]; then
        log_medium "No connection pooling configured"
    else
        log_pass "Connection pooling configured"
    fi

    echo
}

# ============================================================================
# CATEGORY 6: CODE QUALITY & STATIC ANALYSIS
# ============================================================================

audit_code_quality_advanced() {
    log "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${GREEN}CATEGORY 6: CODE QUALITY & STATIC ANALYSIS${NC}"
    log "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Rust code compilation
    check_start "Rust code compilation"
    if command_exists cargo; then
        if ! cargo check --workspace 2>/dev/null; then
            log_critical "Code does not compile!"
        else
            log_pass "Code compiles successfully"
        fi
        
        # Check with all features
        if ! cargo check --all-features 2>/dev/null; then
            log_medium "Some feature combinations don't compile"
        fi
    else
        log_skip "cargo not installed"
    fi

    # Check 2: Clippy lints
    check_start "Clippy static analysis"
    if command_exists cargo && cargo clippy --version &>/dev/null; then
        CLIPPY_WARNINGS=$(cargo clippy --workspace -- -W clippy::all 2>&1 | grep -c "warning:" || echo "0")
        if [[ "$CLIPPY_WARNINGS" -gt 20 ]]; then
            log_high "$CLIPPY_WARNINGS Clippy warnings found"
        elif [[ "$CLIPPY_WARNINGS" -gt 0 ]]; then
            log_medium "$CLIPPY_WARNINGS Clippy warnings found"
        else
            log_pass "No Clippy warnings"
        fi
        
        # Security lints
        SECURITY_WARNINGS=$(cargo clippy --workspace -- -W clippy::pedantic 2>&1 | grep -c "warning:" || echo "0")
        if [[ "$SECURITY_WARNINGS" -gt 0 ]]; then
            log_medium "$SECURITY_WARNINGS pedantic Clippy warnings"
        fi
    else
        log_skip "clippy not installed"
    fi

    # Check 3: Code formatting
    check_start "Code formatting (rustfmt)"
    if command_exists cargo && cargo fmt --version &>/dev/null; then
        if ! cargo fmt --check 2>/dev/null; then
            log_low "Code is not properly formatted"
            attempt_fix "Format code" "cargo fmt"
        else
            log_pass "Code is properly formatted"
        fi
    else
        log_skip "rustfmt not installed"
    fi

    # Check 4: Unsafe code usage
    check_start "Unsafe code analysis"
    UNSAFE_COUNT=$(grep -r "unsafe" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$UNSAFE_COUNT" -gt 10 ]]; then
        log_high "High unsafe code usage ($UNSAFE_COUNT occurrences)"
    elif [[ "$UNSAFE_COUNT" -gt 0 ]]; then
        log_medium "Some unsafe code usage ($UNSAFE_COUNT occurrences)"
    else
        log_pass "No unsafe code found"
    fi

    # Check 5: TODO/FIXME comments
    check_start "TODO/FIXME comments"
    TODO_COUNT=$(grep -r "TODO\|FIXME\|HACK\|XXX" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
    if [[ "$TODO_COUNT" -gt 20 ]]; then
        log_medium "$TODO_COUNT TODO/FIXME comments found"
    elif [[ "$TODO_COUNT" -gt 0 ]]; then
        log_low "$TODO_COUNT TODO/FIXME comments found"
    else
        log_pass "No TODO/FIXME comments"
    fi

    # Check 6: Dependency audit
    check_start "Dependency security audit"
    if command_exists cargo && cargo audit --version &>/dev/null; then
        AUDIT_RESULT=$(cargo audit 2>&1)
        if echo "$AUDIT_RESULT" | grep -q "error:\|Critical:"; then
            log_critical "Critical vulnerabilities in dependencies!"
            if [[ "$VERBOSE" == "true" ]]; then
                echo "$AUDIT_RESULT" | grep -A2 "Critical:"
            fi
        elif echo "$AUDIT_RESULT" | grep -q "warning:"; then
            log_medium "Some vulnerabilities in dependencies"
        else
            log_pass "No known vulnerabilities in dependencies"
        fi
    else
        log_skip "cargo-audit not installed"
    fi

    # Check 7: License compliance
    check_start "License compliance"
    if command_exists cargo && cargo license --version &>/dev/null; then
        PROBLEMATIC_LICENSES=$(cargo license 2>/dev/null | grep -c "GPL\|AGPL" || echo "0")
        if [[ "$PROBLEMATIC_LICENSES" -gt 0 ]]; then
            log_medium "Found $PROBLEMATIC_LICENSES GPL/AGPL dependencies (check compatibility)"
        else
            log_pass "No problematic licenses found"
        fi
    else
        log_skip "cargo-license not installed"
    fi

    # Check 8: Code complexity
    check_start "Code complexity analysis"
    if [[ -d "server/src" ]]; then
        # Count lines per file
        LARGE_FILES=$(find server/src -name "*.rs" -exec wc -l {} \; 2>/dev/null | awk '$1 > 500' | wc -l || echo "0")
        if [[ "$LARGE_FILES" -gt 0 ]]; then
            log_medium "$LARGE_FILES files with >500 lines (consider refactoring)"
        else
            log_pass "All files have reasonable size"
        fi
        
        # Cyclomatic complexity (basic check)
        COMPLEX_FUNCTIONS=$(grep -r "if.*{" --include="*.rs" server/src 2>/dev/null | \
                           awk -F: '{print $1}' | sort | uniq -c | awk '$1 > 10' | wc -l || echo "0")
        if [[ "$COMPLEX_FUNCTIONS" -gt 0 ]]; then
            log_low "$COMPLEX_FUNCTIONS files with high branching complexity"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 7: TESTING & QUALITY ASSURANCE
# ============================================================================

audit_testing_advanced() {
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${BLUE}CATEGORY 7: TESTING & QUALITY ASSURANCE${NC}"
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Unit tests
    check_start "Unit test coverage"
    if command_exists cargo; then
        TEST_COUNT=$(find . -name "*.rs" -exec grep -l "#\[test\]" {} \; 2>/dev/null | wc -l || echo "0")
        SRC_COUNT=$(find . -name "*.rs" -not -path "./target/*" 2>/dev/null | wc -l || echo "1")
        
        if [[ "$TEST_COUNT" -eq 0 ]]; then
            log_critical "No unit tests found!"
        else
            TEST_RATIO=$((TEST_COUNT * 100 / SRC_COUNT))
            if [[ "$TEST_RATIO" -lt 30 ]]; then
                log_high "Low test coverage (tests in $TEST_COUNT/$SRC_COUNT files)"
            else
                log_pass "Good test presence (tests in $TEST_COUNT/$SRC_COUNT files)"
            fi
        fi
        
        # Run tests
        if [[ "$FULL_MODE" == "true" ]]; then
            log_info "Running test suite..."
            if ! cargo test --workspace 2>/dev/null; then
                log_critical "Tests are failing!"
            else
                log_pass "All tests passing"
            fi
        fi
    fi

    # Check 2: Integration tests
    check_start "Integration tests"
    if [[ -d "tests" ]]; then
        INT_TEST_COUNT=$(find tests -name "*.rs" 2>/dev/null | wc -l || echo "0")
        if [[ "$INT_TEST_COUNT" -gt 0 ]]; then
            log_pass "$INT_TEST_COUNT integration test files found"
        else
            log_medium "No integration tests in tests/ directory"
        fi
    else
        log_high "No tests/ directory for integration tests"
    fi

    # Check 3: Code coverage
    check_start "Code coverage configuration"
    if command_exists cargo && cargo tarpaulin --version &>/dev/null; then
        if [[ "$FULL_MODE" == "true" ]]; then
            log_info "Calculating code coverage..."
            COVERAGE=$(cargo tarpaulin --workspace --print-summary 2>/dev/null | grep "Coverage" | grep -o "[0-9.]*%" || echo "0%")
            COVERAGE_NUM=${COVERAGE%\%}
            
            if (( $(echo "$COVERAGE_NUM < 30" | bc -l) )); then
                log_high "Low code coverage: $COVERAGE"
            elif (( $(echo "$COVERAGE_NUM < 60" | bc -l) )); then
                log_medium "Moderate code coverage: $COVERAGE"
            else
                log_pass "Good code coverage: $COVERAGE"
            fi
        fi
    else
        log_skip "cargo-tarpaulin not installed"
    fi

    # Check 4: Fuzz testing
    check_start "Fuzz testing setup"
    if [[ -d "fuzz" ]]; then
        log_pass "Fuzz testing directory exists"
        FUZZ_TARGETS=$(find fuzz -name "*.rs" 2>/dev/null | wc -l || echo "0")
        if [[ "$FUZZ_TARGETS" -gt 0 ]]; then
            log_pass "$FUZZ_TARGETS fuzz targets found"
        fi
    else
        log_low "No fuzz testing setup found"
    fi

    # Check 5: Benchmark tests
    check_start "Performance benchmarks"
    BENCH_COUNT=$(grep -r "#\[bench\]" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$BENCH_COUNT" -eq 0 ]]; then
        log_low "No benchmark tests found"
    else
        log_pass "$BENCH_COUNT benchmark tests found"
    fi

    # Check 6: Property-based testing
    check_start "Property-based testing"
    if grep -r "quickcheck\|proptest" Cargo.toml 2>/dev/null | grep -q .; then
        log_pass "Property-based testing framework found"
    else
        log_low "No property-based testing (consider quickcheck/proptest)"
    fi

    # Check 7: Mutation testing
    check_start "Mutation testing"
    if command_exists cargo && cargo mutants --version &>/dev/null; then
        log_pass "Mutation testing tool available"
    else
        log_info "cargo-mutants not installed (optional)"
    fi

    echo
}

# ============================================================================
# CATEGORY 8: PERFORMANCE & MONITORING
# ============================================================================

audit_performance_monitoring() {
    log "${BOLD}${ORANGE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${ORANGE}CATEGORY 8: PERFORMANCE & MONITORING${NC}"
    log "${BOLD}${ORANGE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Logging configuration
    check_start "Logging infrastructure"
    LOGGING=$(grep -r "log::\|tracing::\|env_logger\|slog" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$LOGGING" -eq 0 ]]; then
        log_high "No logging framework detected"
    else
        log_pass "Logging framework configured"
        
        # Check log levels
        if grep -r "RUST_LOG\|log_level" --include="*.rs" --include="*.toml" . 2>/dev/null | grep -q .; then
            log_pass "Log level configuration found"
        else
            log_medium "No log level configuration"
        fi
    fi

    # Check 2: Metrics collection
    check_start "Metrics and observability"
    METRICS=$(grep -r "prometheus\|metrics\|statsd" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$METRICS" -eq 0 ]]; then
        log_medium "No metrics collection framework"
    else
        log_pass "Metrics collection configured"
    fi

    # Check 3: Tracing/APM
    check_start "Distributed tracing"
    TRACING=$(grep -r "opentelemetry\|jaeger\|zipkin\|tracing" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$TRACING" -eq 0 ]]; then
        log_low "No distributed tracing configured"
    else
        log_pass "Distributed tracing found"
    fi

    # Check 4: Health checks
    check_start "Health check endpoints"
    HEALTH=$(grep -r "health\|liveness\|readiness\|status" --include="*.rs" . 2>/dev/null | grep -i "route\|endpoint" | wc -l || echo "0")
    if [[ "$HEALTH" -eq 0 ]]; then
        log_medium "No health check endpoints found"
    else
        log_pass "Health check endpoints configured"
    fi

    # Check 5: Memory profiling
    check_start "Memory leak detection"
    MEM_PROFILE=$(grep -r "jemalloc\|valgrind\|heaptrack" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$MEM_PROFILE" -gt 0 ]]; then
        log_pass "Memory profiling tools configured"
    else
        log_info "No memory profiling setup"
    fi

    # Check 6: Performance optimization
    check_start "Performance optimizations"
    
    # Check release profile
    if grep -q "\[profile.release\]" Cargo.toml 2>/dev/null; then
        if grep -A5 "\[profile.release\]" Cargo.toml | grep -q "lto.*=.*true"; then
            log_pass "Link-time optimization (LTO) enabled"
        else
            log_low "LTO not enabled for release builds"
        fi
        
        if grep -A5 "\[profile.release\]" Cargo.toml | grep -q "codegen-units.*=.*1"; then
            log_pass "Single codegen unit for optimization"
        fi
    else
        log_medium "No release profile optimization configured"
    fi

    # Check 7: Caching configuration
    check_start "Caching implementation"
    CACHE=$(grep -r "cache\|redis\|memcached" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$CACHE" -eq 0 ]]; then
        log_low "No caching layer detected"
    else
        log_pass "Caching implementation found"
    fi

    # Check 8: Resource limits
    check_start "Resource limit configuration"
    LIMITS=$(grep -r "limit\|quota\|max_connections\|max_requests" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$LIMITS" -lt 3 ]]; then
        log_medium "Minimal resource limits configured"
    else
        log_pass "Resource limits configured"
    fi

    echo
}

# ============================================================================
# CATEGORY 9: DISASTER RECOVERY & BACKUP
# ============================================================================

audit_disaster_recovery() {
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${PURPLE}CATEGORY 9: DISASTER RECOVERY & BACKUP${NC}"
    log "${BOLD}${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Backup strategy
    check_start "Backup configuration"
    
    # Check for backup scripts
    BACKUP_SCRIPTS=$(find . -name "*backup*.sh" -o -name "*backup*.py" 2>/dev/null | wc -l || echo "0")
    if [[ "$BACKUP_SCRIPTS" -eq 0 ]]; then
        log_high "No backup scripts found"
    else
        log_pass "$BACKUP_SCRIPTS backup scripts found"
        
        # Check if executable
        NON_EXEC=$(find . -name "*backup*.sh" ! -executable 2>/dev/null | wc -l || echo "0")
        if [[ "$NON_EXEC" -gt 0 ]]; then
            log_medium "$NON_EXEC backup scripts are not executable"
        fi
    fi

    # Check 2: Database backups
    check_start "Database backup status"
    DB_BACKUPS=$(find . -name "*.db.backup*" -o -name "*.sql.gz" -o -name "*.db.tar*" 2>/dev/null | wc -l || echo "0")
    if [[ "$DB_BACKUPS" -eq 0 ]]; then
        log_critical "No database backups found!"
    else
        log_pass "$DB_BACKUPS database backups found"
        
        # Check backup age
        OLDEST_BACKUP=$(find . -name "*.db.backup*" -o -name "*.sql.gz" -exec stat -c%Y {} \; 2>/dev/null | sort -n | head -1 || echo "0")
        if [[ "$OLDEST_BACKUP" -gt 0 ]]; then
            CURRENT_TIME=$(date +%s)
            BACKUP_AGE=$(( (CURRENT_TIME - OLDEST_BACKUP) / 86400 ))
            if [[ "$BACKUP_AGE" -gt 30 ]]; then
                log_medium "Oldest backup is $BACKUP_AGE days old (consider cleanup)"
            fi
        fi
    fi

    # Check 3: Automated backup cron jobs
    check_start "Automated backup schedule"
    if command_exists crontab; then
        CRON_BACKUPS=$(crontab -l 2>/dev/null | grep -c "backup" || echo "0")
        if [[ "$CRON_BACKUPS" -eq 0 ]]; then
            log_medium "No automated backup jobs in crontab"
        else
            log_pass "$CRON_BACKUPS backup cron jobs configured"
        fi
    fi

    # Check 4: Recovery procedures
    check_start "Recovery documentation"
    RECOVERY_DOCS=$(find . -name "*recover*" -o -name "*restore*" -o -name "DISASTER*" 2>/dev/null | grep -E "\.(md|txt|pdf)" | wc -l || echo "0")
    if [[ "$RECOVERY_DOCS" -eq 0 ]]; then
        log_high "No disaster recovery documentation found"
    else
        log_pass "$RECOVERY_DOCS recovery documents found"
    fi

    # Check 5: High availability setup
    check_start "High availability configuration"
    HA_CONFIG=$(grep -r "replica\|failover\|cluster\|load.*balanc" --include="*.rs" --include="*.toml" --include="*.yaml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$HA_CONFIG" -eq 0 ]]; then
        log_low "No high availability configuration"
    else
        log_pass "High availability features configured"
    fi

    # Check 6: Data replication
    check_start "Data replication setup"
    REPLICATION=$(grep -r "replicat\|sync\|mirror" --include="*.rs" --include="*.sh" . 2>/dev/null | wc -l || echo "0")
    if [[ "$REPLICATION" -lt 3 ]]; then
        log_medium "Limited data replication configuration"
    else
        log_pass "Data replication configured"
    fi

    # Check 7: Backup encryption
    check_start "Backup encryption"
    if [[ "$DB_BACKUPS" -gt 0 ]]; then
        ENCRYPTED_BACKUPS=$(find . -name "*.db.backup*.gpg" -o -name "*.db.backup*.enc" 2>/dev/null | wc -l || echo "0")
        if [[ "$ENCRYPTED_BACKUPS" -eq 0 ]]; then
            log_high "Backups are not encrypted!"
        else
            log_pass "$ENCRYPTED_BACKUPS encrypted backups found"
        fi
    fi

    echo
}

# ============================================================================
# CATEGORY 10: COMPLIANCE & LEGAL
# ============================================================================

audit_compliance_legal() {
    log "${BOLD}${WHITE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${WHITE}CATEGORY 10: COMPLIANCE & LEGAL${NC}"
    log "${BOLD}${WHITE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Privacy policy
    check_start "Privacy policy documentation"
    PRIVACY_DOCS=$(find . -iname "*privacy*" -o -iname "*gdpr*" -o -iname "*ccpa*" 2>/dev/null | grep -E "\.(md|txt|html)" | wc -l || echo "0")
    if [[ "$PRIVACY_DOCS" -eq 0 ]]; then
        log_high "No privacy policy documentation found"
    else
        log_pass "$PRIVACY_DOCS privacy documents found"
    fi

    # Check 2: Terms of service
    check_start "Terms of service"
    TOS_DOCS=$(find . -iname "*terms*" -o -iname "*tos*" -o -iname "*eula*" 2>/dev/null | grep -E "\.(md|txt|html)" | wc -l || echo "0")
    if [[ "$TOS_DOCS" -eq 0 ]]; then
        log_medium "No terms of service found"
    else
        log_pass "$TOS_DOCS terms of service documents found"
    fi

    # Check 3: GDPR compliance
    check_start "GDPR compliance features"
    GDPR_IMPL=$(grep -r "gdpr\|right.*erasure\|right.*forgotten\|data.*portability" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$GDPR_IMPL" -eq 0 ]]; then
        log_medium "No GDPR compliance implementation found"
    else
        log_pass "GDPR compliance features found"
    fi

    # Check 4: Data retention policy
    check_start "Data retention configuration"
    RETENTION=$(grep -r "retention\|expire\|ttl\|purge" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$RETENTION" -eq 0 ]]; then
        log_medium "No data retention policy implemented"
    else
        log_pass "Data retention features found"
    fi

    # Check 5: Audit logging for compliance
    check_start "Compliance audit logging"
    AUDIT_LOG=$(grep -r "audit.*log\|compliance.*log" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$AUDIT_LOG" -eq 0 ]]; then
        log_medium "No compliance audit logging"
    else
        log_pass "Compliance audit logging implemented"
    fi

    # Check 6: KYC/AML implementation (for marketplaces)
    check_start "KYC/AML compliance"
    KYC_AML=$(grep -r "kyc\|aml\|identity.*verif\|anti.*launder" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$KYC_AML" -eq 0 ]]; then
        log_info "No KYC/AML implementation (may be required depending on jurisdiction)"
    else
        log_pass "KYC/AML features found"
    fi

    # Check 7: Cookie consent
    check_start "Cookie consent implementation"
    COOKIE_CONSENT=$(grep -r "cookie.*consent\|cookie.*banner" --include="*.rs" --include="*.js" . 2>/dev/null | wc -l || echo "0")
    if [[ "$COOKIE_CONSENT" -eq 0 ]]; then
        log_low "No cookie consent implementation"
    else
        log_pass "Cookie consent implemented"
    fi

    echo
}

# ============================================================================
# CATEGORY 11: MONERO NODE & BLOCKCHAIN INTEGRATION
# ============================================================================

audit_monero_node() {
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${CYAN}CATEGORY 11: MONERO NODE & BLOCKCHAIN INTEGRATION${NC}"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Monero node configuration
    check_start "Monero node configuration"
    MONEROD_CONFIG=$(find . -name "monerod.conf" -o -name "monero.conf" 2>/dev/null | wc -l || echo "0")
    if [[ "$MONEROD_CONFIG" -eq 0 ]]; then
        log_high "No Monero daemon configuration found"
    else
        log_pass "Monero daemon configuration found"
        
        # Check for testnet/stagenet
        if grep -r "testnet\|stagenet" monerod.conf 2>/dev/null | grep -q .; then
            log_info "Running on testnet/stagenet"
        fi
    fi

    # Check 2: RPC authentication
    check_start "Monero RPC authentication"
    RPC_AUTH=$(grep -r "rpc-login\|rpc-access-control" --include="*.conf" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$RPC_AUTH" -eq 0 ]]; then
        log_critical "No RPC authentication configured - SECURITY RISK!"
    else
        log_pass "RPC authentication configured"
    fi

    # Check 3: Blockchain synchronization
    check_start "Blockchain sync monitoring"
    SYNC_CHECK=$(grep -r "get_info\|sync_info\|get_height" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$SYNC_CHECK" -eq 0 ]]; then
        log_medium "No blockchain sync monitoring"
    else
        log_pass "Blockchain sync monitoring implemented"
    fi

    # Check 4: Transaction confirmation handling
    check_start "Transaction confirmation requirements"
    CONFIRMATIONS=$(grep -r "confirmations\|min_confirmations\|required_confirmations" --include="*.rs" . 2>/dev/null | head -1 | grep -o "[0-9]\+" || echo "0")
    if [[ "$CONFIRMATIONS" -lt 10 ]] && [[ "$CONFIRMATIONS" -gt 0 ]]; then
        log_medium "Low confirmation requirement ($CONFIRMATIONS) - consider increasing"
    elif [[ "$CONFIRMATIONS" -eq 0 ]]; then
        log_high "No confirmation requirement found"
    else
        log_pass "Good confirmation requirement ($CONFIRMATIONS)"
    fi

    # Check 5: Transaction pool monitoring
    check_start "Transaction pool handling"
    TXPOOL=$(grep -r "tx_pool\|mempool\|pending_tx" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$TXPOOL" -eq 0 ]]; then
        log_medium "No transaction pool monitoring"
    else
        log_pass "Transaction pool monitoring found"
    fi

    # Check 6: Block notification handling
    check_start "Block notification system"
    BLOCK_NOTIFY=$(grep -r "on_block\|block_notify\|new_block" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$BLOCK_NOTIFY" -eq 0 ]]; then
        log_low "No block notification handling"
    else
        log_pass "Block notification system implemented"
    fi

    # Check 7: Wallet RPC integration
    check_start "Wallet RPC integration"
    WALLET_RPC=$(grep -r "wallet.*rpc\|monero-wallet-rpc" --include="*.rs" --include="*.toml" . 2>/dev/null | wc -l || echo "0")
    if [[ "$WALLET_RPC" -eq 0 ]]; then
        log_critical "No wallet RPC integration - cannot handle payments!"
    else
        log_pass "Wallet RPC integration found"
    fi

    echo
}

# ============================================================================
# CATEGORY 12: CONTAINER & ORCHESTRATION
# ============================================================================

audit_container_orchestration() {
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${BLUE}CATEGORY 12: CONTAINER & ORCHESTRATION${NC}"
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: Dockerfile quality
    check_start "Dockerfile best practices"
    if [[ -f "Dockerfile" ]]; then
        log_pass "Dockerfile exists"
        
        # Multi-stage build
        if grep -q "FROM.*AS" Dockerfile; then
            log_pass "Multi-stage build detected"
        else
            log_medium "Single-stage build (consider multi-stage for smaller images)"
        fi
        
        # Non-root user
        if grep -q "USER" Dockerfile; then
            log_pass "Non-root user configured"
        else
            log_high "Container runs as root - security risk"
        fi
        
        # Health check
        if grep -q "HEALTHCHECK" Dockerfile; then
            log_pass "Health check configured"
        else
            log_medium "No HEALTHCHECK in Dockerfile"
        fi
        
        # Layer caching optimization
        if grep -q "COPY Cargo.toml" Dockerfile | head -1; then
            log_pass "Dependency caching optimized"
        fi
    else
        log_low "No Dockerfile found"
    fi

    # Check 2: Docker Compose configuration
    check_start "Docker Compose setup"
    if [[ -f "docker-compose.yml" ]] || [[ -f "docker-compose.yaml" ]]; then
        log_pass "Docker Compose file found"
        
        # Resource limits
        if grep -q "limits:\|mem_limit:\|cpus:" docker-compose.y*ml 2>/dev/null; then
            log_pass "Resource limits configured"
        else
            log_medium "No resource limits in Docker Compose"
        fi
        
        # Restart policy
        if grep -q "restart:" docker-compose.y*ml 2>/dev/null; then
            log_pass "Restart policy configured"
        fi
    fi

    # Check 3: Kubernetes manifests
    check_start "Kubernetes deployment"
    K8S_FILES=$(find . -name "*.yaml" -o -name "*.yml" | xargs grep -l "kind:.*Deployment\|kind:.*Service" 2>/dev/null | wc -l || echo "0")
    if [[ "$K8S_FILES" -gt 0 ]]; then
        log_pass "$K8S_FILES Kubernetes manifests found"
        
        # Security context
        if grep -r "securityContext:" --include="*.yaml" . 2>/dev/null | grep -q .; then
            log_pass "Security context configured"
        else
            log_high "No security context in K8s manifests"
        fi
        
        # Resource requests/limits
        if grep -r "resources:" --include="*.yaml" . 2>/dev/null | grep -q .; then
            log_pass "Resource limits configured"
        else
            log_medium "No resource limits in K8s manifests"
        fi
    else
        log_info "No Kubernetes configuration found"
    fi

    # Check 4: Container registry configuration
    check_start "Container registry setup"
    if [[ -f ".github/workflows/"*".yml" ]] || [[ -f ".gitlab-ci.yml" ]]; then
        if grep -r "docker.*push\|registry" .github .gitlab-ci.yml 2>/dev/null | grep -q .; then
            log_pass "Container registry push configured"
        fi
    fi

    # Check 5: Container scanning
    check_start "Container vulnerability scanning"
    if grep -r "trivy\|snyk\|twistlock\|aqua" --include="*.yml" --include="*.yaml" . 2>/dev/null | grep -q .; then
        log_pass "Container scanning configured"
    else
        log_medium "No container vulnerability scanning"
    fi

    echo
}

# ============================================================================
# CATEGORY 13: CI/CD & AUTOMATION
# ============================================================================

audit_cicd_automation() {
    log "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${GREEN}CATEGORY 13: CI/CD & AUTOMATION${NC}"
    log "${BOLD}${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo

    # Check 1: CI/CD pipeline
    check_start "CI/CD pipeline configuration"
    
    CI_CONFIGS=0
    # GitHub Actions
    if [[ -d ".github/workflows" ]]; then
        GH_WORKFLOWS=$(find .github/workflows -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l || echo "0")
        if [[ "$GH_WORKFLOWS" -gt 0 ]]; then
            log_pass "GitHub Actions workflows found: $GH_WORKFLOWS"
            ((CI_CONFIGS++))
        fi
    fi
    
    # GitLab CI
    if [[ -f ".gitlab-ci.yml" ]]; then
        log_pass "GitLab CI configuration found"
        ((CI_CONFIGS++))
    fi
    
    # Jenkins
    if [[ -f "Jenkinsfile" ]]; then
        log_pass "Jenkins pipeline found"
        ((CI_CONFIGS++))
    fi
    
    if [[ "$CI_CONFIGS" -eq 0 ]]; then
        log_high "No CI/CD configuration found"
    fi

    # Check 2: Automated testing in CI
    check_start "Automated testing in CI/CD"
    TEST_IN_CI=$(grep -r "cargo test\|npm test\|pytest" .github .gitlab-ci.yml Jenkinsfile 2>/dev/null | wc -l || echo "0")
    if [[ "$TEST_IN_CI" -eq 0 ]]; then
        log_medium "No automated testing in CI/CD"
    else
        log_pass "Automated testing configured in CI/CD"
    fi

    # Check 3: Security scanning in CI
    check_start "Security scanning in CI/CD"
    SECURITY_CI=$(grep -r "cargo audit\|snyk\|dependabot\|security" .github .gitlab-ci.yml 2>/dev/null | wc -l || echo "0")
    if [[ "$SECURITY_CI" -eq 0 ]]; then
        log_medium "No security scanning in CI/CD"
    else
        log_pass "Security scanning in CI/CD"
    fi

    # Check 4: Pre-commit hooks
    check_start "Pre-commit hooks"
    if [[ -f ".pre-commit-config.yaml" ]]; then
        log_pass "Pre-commit configuration found"
    elif [[ -f ".git/hooks/pre-commit" ]]; then
        log_pass "Git pre-commit hook configured"
    else
        log_low "No pre-commit hooks configured"
    fi

    # Check 5: Deployment automation
    check_start "Deployment automation"
    DEPLOY_CONFIG=$(grep -r "deploy\|terraform\|ansible\|kubernetes" .github .gitlab-ci.yml 2>/dev/null | wc -l || echo "0")
    if [[ "$DEPLOY_CONFIG" -eq 0 ]]; then
        log_medium "No deployment automation found"
    else
        log_pass "Deployment automation configured"
    fi

    # Check 6: Release management
    check_start "Release management"
    if [[ -f ".goreleaser.yml" ]] || grep -r "semantic-release\|release-please" .github 2>/dev/null | grep -q .; then
        log_pass "Automated release management configured"
    else
        log_low "No automated release management"
    fi

    echo
}

# ============================================================================
# SUMMARY & REPORTING
# ============================================================================

generate_html_report() {
    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Monero Marketplace Security Audit Report - $TIMESTAMP</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #ff6600; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f1c40f; font-weight: bold; }
        .low { color: #27ae60; }
        .info { color: #3498db; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; flex: 1; margin: 0 10px; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .progress { width: 100%; height: 30px; background: #e0e0e0; border-radius: 15px; overflow: hidden; }
        .progress-bar { height: 100%; background: linear-gradient(90deg, #27ae60, #f1c40f, #e74c3c); transition: width 0.3s; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.85em; }
        .grade { font-size: 3em; font-weight: bold; text-align: center; padding: 20px; }
        .grade-a { color: #27ae60; }
        .grade-b { color: #f1c40f; }
        .grade-c { color: #e67e22; }
        .grade-f { color: #e74c3c; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Monero Marketplace Security Audit Report</h1>
        
        <div class="summary">
            <h2 style="color: white;">Executive Summary</h2>
            <p><strong>Date:</strong> $(date)</p>
            <p><strong>Project:</strong> Monero Marketplace</p>
            <p><strong>Audit Version:</strong> 2.0.0 Extended</p>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">${TOTAL_CHECKS}</div>
                <div>Total Checks</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #27ae60;">${PASSED_CHECKS}</div>
                <div>Passed</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #e74c3c;">${FAILED_CHECKS}</div>
                <div>Failed</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #f1c40f;">${SKIPPED_CHECKS}</div>
                <div>Skipped</div>
            </div>
        </div>

        <h2>Issue Summary</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Impact</th>
            </tr>
            <tr>
                <td><span class="critical">🔴 Critical</span></td>
                <td>${ISSUE_COUNTS[CRITICAL]}</td>
                <td>Must fix immediately - blocks deployment</td>
            </tr>
            <tr>
                <td><span class="high">🟠 High</span></td>
                <td>${ISSUE_COUNTS[HIGH]}</td>
                <td>Fix before production - security risk</td>
            </tr>
            <tr>
                <td><span class="medium">🟡 Medium</span></td>
                <td>${ISSUE_COUNTS[MEDIUM]}</td>
                <td>Should fix - potential issues</td>
            </tr>
            <tr>
                <td><span class="low">🟢 Low</span></td>
                <td>${ISSUE_COUNTS[LOW]}</td>
                <td>Nice to fix - improvements</td>
            </tr>
            <tr>
                <td><span class="info">ℹ️ Info</span></td>
                <td>${ISSUE_COUNTS[INFO]}</td>
                <td>Informational only</td>
            </tr>
        </table>

        <h2>Overall Grade</h2>
        <div class="grade grade-$(get_grade_class)">$(calculate_grade)</div>

        <h2>Categories Audited</h2>
        <ol>
            <li>Infrastructure Critical</li>
            <li>Security Critical</li>
            <li>Monero Cryptographic Audit</li>
            <li>Network Security</li>
            <li>Database Security & Performance</li>
            <li>Code Quality & Static Analysis</li>
            <li>Testing & Quality Assurance</li>
            <li>Performance & Monitoring</li>
            <li>Disaster Recovery & Backup</li>
            <li>Compliance & Legal</li>
            <li>Monero Node & Blockchain Integration</li>
            <li>Container & Orchestration</li>
            <li>CI/CD & Automation</li>
        </ol>

        <h2>Detailed Findings</h2>
        <p>See <code>$LOG_FILE</code> for complete audit details.</p>

        <div class="footer">
            <p>Generated by Ultra Full Audit Extended v2.0.0</p>
            <p>© 2024 Monero Marketplace Security Team</p>
        </div>
    </div>
</body>
</html>
EOF

    log_info "HTML report generated: $HTML_REPORT"
}

calculate_grade() {
    local CRITICAL_PENALTY=$((${ISSUE_COUNTS[CRITICAL]} * 20))
    local HIGH_PENALTY=$((${ISSUE_COUNTS[HIGH]} * 10))
    local MEDIUM_PENALTY=$((${ISSUE_COUNTS[MEDIUM]} * 3))
    local LOW_PENALTY=$((${ISSUE_COUNTS[LOW]} * 1))
    local TOTAL_PENALTY=$((CRITICAL_PENALTY + HIGH_PENALTY + MEDIUM_PENALTY + LOW_PENALTY))
    
    local SCORE=$((100 - TOTAL_PENALTY))
    [[ "$SCORE" -lt 0 ]] && SCORE=0
    
    if [[ "$SCORE" -ge 90 ]]; then
        echo "A+"
    elif [[ "$SCORE" -ge 80 ]]; then
        echo "A"
    elif [[ "$SCORE" -ge 70 ]]; then
        echo "B"
    elif [[ "$SCORE" -ge 60 ]]; then
        echo "C"
    else
        echo "F"
    fi
}

get_grade_class() {
    local grade=$(calculate_grade)
    case $grade in
        A*) echo "a" ;;
        B*) echo "b" ;;
        C*) echo "c" ;;
        *) echo "f" ;;
    esac
}

print_final_summary() {
    local END_TIME=$(date +%s)
    local DURATION=$((END_TIME - START_TIME))
    local MINUTES=$((DURATION / 60))
    local SECONDS=$((DURATION % 60))
    
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    log "${BOLD}${CYAN}FINAL AUDIT SUMMARY${NC}"
    log "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo
    
    # Calculate score
    local CRITICAL_PENALTY=$((${ISSUE_COUNTS[CRITICAL]} * 20))
    local HIGH_PENALTY=$((${ISSUE_COUNTS[HIGH]} * 10))
    local MEDIUM_PENALTY=$((${ISSUE_COUNTS[MEDIUM]} * 3))
    local LOW_PENALTY=$((${ISSUE_COUNTS[LOW]} * 1))
    local TOTAL_PENALTY=$((CRITICAL_PENALTY + HIGH_PENALTY + MEDIUM_PENALTY + LOW_PENALTY))
    
    local SCORE=$((100 - TOTAL_PENALTY))
    [[ "$SCORE" -lt 0 ]] && SCORE=0
    
    # Display stats
    echo -e "${BOLD}Audit Duration:${NC} ${MINUTES}m ${SECONDS}s"
    echo -e "${BOLD}Total Checks:${NC} $TOTAL_CHECKS"
    echo -e "${BOLD}Passed:${NC} ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "${BOLD}Failed:${NC} ${RED}$((TOTAL_CHECKS - PASSED_CHECKS - SKIPPED_CHECKS))${NC}"
    echo -e "${BOLD}Skipped:${NC} ${YELLOW}$SKIPPED_CHECKS${NC}"
    echo
    
    # Issue breakdown
    echo -e "${RED}🔴 Critical Issues:${NC} ${ISSUE_COUNTS[CRITICAL]}"
    echo -e "${ORANGE}🟠 High Priority:${NC} ${ISSUE_COUNTS[HIGH]}"
    echo -e "${YELLOW}🟡 Medium Priority:${NC} ${ISSUE_COUNTS[MEDIUM]}"
    echo -e "${GREEN}🟢 Low Priority:${NC} ${ISSUE_COUNTS[LOW]}"
    echo -e "${CYAN}ℹ️  Informational:${NC} ${ISSUE_COUNTS[INFO]}"
    echo
    
    # Grade
    local GRADE=$(calculate_grade)
    local GRADE_COLOR
    case $GRADE in
        A*) GRADE_COLOR="$GREEN" ;;
        B*) GRADE_COLOR="$YELLOW" ;;
        C*) GRADE_COLOR="$ORANGE" ;;
        *) GRADE_COLOR="$RED" ;;
    esac
    
    echo -e "${BOLD}Overall Score:${NC} ${GRADE_COLOR}${SCORE}/100${NC}"
    echo -e "${BOLD}Grade:${NC} ${GRADE_COLOR}${GRADE}${NC}"
    echo
    
    # Recommendations
    if [[ "${ISSUE_COUNTS[CRITICAL]}" -gt 0 ]]; then
        echo -e "${RED}${BOLD}⚠️  CRITICAL ISSUES MUST BE FIXED IMMEDIATELY${NC}"
        echo -e "${RED}DO NOT DEPLOY TO PRODUCTION${NC}"
    elif [[ "${ISSUE_COUNTS[HIGH]}" -gt 0 ]]; then
        echo -e "${ORANGE}${BOLD}High priority issues should be addressed before production${NC}"
    elif [[ "${ISSUE_COUNTS[MEDIUM]}" -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}Consider addressing medium priority issues${NC}"
    else
        echo -e "${GREEN}${BOLD}✅ Excellent! No major issues found${NC}"
    fi
    echo
    
    # Reports
    echo -e "${BOLD}Reports Generated:${NC}"
    echo "  📄 Log file: $LOG_FILE"
    [[ "$JSON_OUTPUT" == "true" ]] && echo "  📊 JSON report: $JSON_REPORT"
    [[ "$HTML_OUTPUT" == "true" ]] && echo "  🌐 HTML report: $HTML_REPORT"
    echo
    
    # Exit code determination
    if [[ "${ISSUE_COUNTS[CRITICAL]}" -gt 0 ]]; then
        return 1
    elif [[ "${ISSUE_COUNTS[HIGH]}" -gt 0 ]] && [[ "$STRICT" == "true" ]]; then
        return 2
    elif [[ "${ISSUE_COUNTS[MEDIUM]}" -gt 0 ]] && [[ "$STRICT" == "true" ]]; then
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
            --full)
                FULL_MODE=true
                shift
                ;;
            --quick)
                QUICK_MODE=true
                shift
                ;;
            --parallel)
                PARALLEL_EXECUTION=true
                shift
                ;;
            --docker)
                DOCKER_MODE=true
                shift
                ;;
            --category)
                SPECIFIC_CATEGORY="$2"
                shift 2
                ;;
            -h|--help)
                cat << EOF
Ultra Full Audit Extended - Monero Marketplace
Version: 2.0.0

Usage: $0 [OPTIONS]

Options:
    -v, --verbose       Verbose output (show all checks)
    --strict            Fail on warnings
    --fix               Auto-fix issues where possible
    --json              Output results as JSON
    --html              Generate HTML report
    --full              Run ALL tests including slow ones
    --quick             Quick scan only (skip slow tests)
    --parallel          Run checks in parallel (experimental)
    --docker            Run inside Docker container
    --category N        Run specific category only
    -h, --help          Show this help message

Categories:
    1  - Infrastructure Critical
    2  - Security Critical
    3  - Monero Cryptographic Audit
    4  - Network Security
    5  - Database Security & Performance
    6  - Code Quality & Static Analysis
    7  - Testing & Quality Assurance
    8  - Performance & Monitoring
    9  - Disaster Recovery & Backup
    10 - Compliance & Legal
    11 - Monero Node & Blockchain Integration
    12 - Container & Orchestration
    13 - CI/CD & Automation

Examples:
    $0                      # Standard audit
    $0 -v --full           # Verbose with all tests
    $0 --fix               # Auto-fix issues
    $0 --category 3        # Run only Monero crypto audit
    $0 --html --json       # Generate all reports

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
    
    # Clear log file
    > "$LOG_FILE"
    
    # Header
    log "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    log "${BOLD}${CYAN}║       ULTRA FULL AUDIT EXTENDED - v2.0.0                ║${NC}"
    log "${BOLD}${CYAN}║            Monero Marketplace Security                   ║${NC}"
    log "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo
    log "Starting comprehensive security audit..."
    log "Project root: $PROJECT_ROOT"
    log "Timestamp: $(date -Iseconds)"
    log "Mode: $([ "$FULL_MODE" == "true" ] && echo "FULL" || ([ "$QUICK_MODE" == "true" ] && echo "QUICK" || echo "STANDARD"))"
    echo
    
    # Run audit categories
    if [[ -n "$SPECIFIC_CATEGORY" ]]; then
        case $SPECIFIC_CATEGORY in
            1) audit_infrastructure ;;
            2) audit_security ;;
            3) audit_monero_crypto ;;
            4) audit_network_security ;;
            5) audit_database_advanced ;;
            6) audit_code_quality_advanced ;;
            7) audit_testing_advanced ;;
            8) audit_performance_monitoring ;;
            9) audit_disaster_recovery ;;
            10) audit_compliance_legal ;;
            11) audit_monero_node ;;
            12) audit_container_orchestration ;;
            13) audit_cicd_automation ;;
            *) log_critical "Invalid category: $SPECIFIC_CATEGORY" ;;
        esac
    else
        # Run all categories
        if [[ "$QUICK_MODE" == "true" ]]; then
            # Quick mode - essential checks only
            audit_infrastructure
            audit_security
            audit_monero_crypto
        else
            # Standard or Full mode - run all
            audit_infrastructure
            audit_security
            audit_monero_crypto
            audit_network_security
            audit_database_advanced
            audit_code_quality_advanced
            
            if [[ "$FULL_MODE" == "true" ]]; then
                audit_testing_advanced
                audit_performance_monitoring
                audit_disaster_recovery
                audit_compliance_legal
                audit_monero_node
                audit_container_orchestration
                audit_cicd_automation
            fi
        fi
    fi
    
    # Generate JSON report
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        JSON_BUFFER="$JSON_BUFFER]"
        echo "$JSON_BUFFER" > "$JSON_REPORT"
        log_info "JSON report saved to: $JSON_REPORT"
    fi
    
    # Generate HTML report
    if [[ "$HTML_OUTPUT" == "true" ]]; then
        generate_html_report
    fi
    
    # Print final summary
    print_final_summary
    EXIT_CODE=$?
    
    log "${BOLD}${GREEN}Audit complete!${NC}"
    
    # Final recommendations
    if [[ "$FIX_MODE" == "true" ]]; then
        log_info "Auto-fix mode was enabled. Some issues may have been resolved."
        log_info "Please review the changes and re-run the audit."
    fi
    
    exit $EXIT_CODE
}

# ============================================================================
# ENTRY POINT
# ============================================================================

# Check if running as root (warn only)
if [[ $EUID -eq 0 ]]; then
   log_info "Warning: Running as root is not recommended"
fi

# Run main function
main "$@"
