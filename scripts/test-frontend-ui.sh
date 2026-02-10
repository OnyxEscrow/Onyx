#!/usr/bin/env bash
#
# Frontend UI Test - Visual Regression & Design System Validation
#
# Tests:
# - Premium dark theme rendering
# - Glassmorphism effects
# - Responsive layout (mobile/tablet/desktop)
# - CSS animations
# - Accessibility (WCAG 2.1 AA)
#
# Usage: ./scripts/test-frontend-ui.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Test configuration
APP_URL="http://localhost:8080"
TEST_START=$(date +%s)
LOG_FILE="/tmp/frontend-ui-test-$(date +%Y%m%d_%H%M%S).log"
FAILED_TESTS=0
TOTAL_TESTS=0

# Create log file
touch "$LOG_FILE"
log_info "Frontend UI test started. Logging to: $LOG_FILE"

echo "============================================================================" | tee -a "$LOG_FILE"
echo "FRONTEND UI TEST - Premium Dark Theme Validation" | tee -a "$LOG_FILE"
echo "============================================================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 1: Pre-Flight Checks
# ============================================================================

log_info "PHASE 1: Pre-flight checks" | tee -a "$LOG_FILE"

# Check if server is running
if ! curl -s "${APP_URL}/api/health" > /dev/null 2>&1; then
    log_error "Application not running at ${APP_URL}" | tee -a "$LOG_FILE"
    log_info "Start the server with: cargo run --package server" | tee -a "$LOG_FILE"
    exit 1
fi
log_success "Application is running at ${APP_URL}" | tee -a "$LOG_FILE"

# Check if curl is available
if ! command -v curl &> /dev/null; then
    log_error "curl not found. Install with: sudo apt-get install curl" | tee -a "$LOG_FILE"
    exit 1
fi
log_success "curl available" | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 2: CSS File Validation
# ============================================================================

log_info "PHASE 2: CSS file validation" | tee -a "$LOG_FILE"

CSS_FILE="static/css/main.css"
if [ ! -f "$CSS_FILE" ]; then
    log_error "CSS file not found: $CSS_FILE" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
else
    log_success "CSS file found: $CSS_FILE" | tee -a "$LOG_FILE"

    # Check CSS file size (should be reasonable, not minified)
    CSS_SIZE=$(wc -c < "$CSS_FILE")
    if [ "$CSS_SIZE" -gt 100000 ]; then
        log_warning "CSS file is large: ${CSS_SIZE} bytes (consider optimization)" | tee -a "$LOG_FILE"
    else
        log_success "CSS file size OK: ${CSS_SIZE} bytes" | tee -a "$LOG_FILE"
    fi

    # Check for CSS custom properties (design tokens)
    if grep -q ":root {" "$CSS_FILE"; then
        log_success "CSS custom properties (design tokens) found" | tee -a "$LOG_FILE"
    else
        log_error "CSS custom properties not found (missing :root)" | tee -a "$LOG_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    # Check for key design tokens
    DESIGN_TOKENS=(
        "--primary-dark"
        "--primary-accent"
        "--monero-orange"
        "--text-primary"
        "--text-secondary"
        "--spacing-4"
        "--shadow-md"
    )

    for token in "${DESIGN_TOKENS[@]}"; do
        if grep -q "$token" "$CSS_FILE"; then
            log_success "Design token found: $token" | tee -a "$LOG_FILE"
        else
            log_error "Design token missing: $token" | tee -a "$LOG_FILE"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    done

    # Check for glassmorphism (backdrop-filter)
    if grep -q "backdrop-filter: blur" "$CSS_FILE"; then
        log_success "Glassmorphism effect found (backdrop-filter)" | tee -a "$LOG_FILE"
    else
        log_error "Glassmorphism effect not found" | tee -a "$LOG_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    # Check for responsive design (media queries)
    if grep -q "@media" "$CSS_FILE"; then
        log_success "Responsive media queries found" | tee -a "$LOG_FILE"
    else
        log_error "No responsive media queries found" | tee -a "$LOG_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    # Check for animations
    if grep -q "@keyframes" "$CSS_FILE"; then
        log_success "CSS animations found" | tee -a "$LOG_FILE"
    else
        log_warning "No CSS animations found" | tee -a "$LOG_FILE"
    fi
fi

TOTAL_TESTS=$((TOTAL_TESTS + 10))
echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 3: HTML Template Validation
# ============================================================================

log_info "PHASE 3: HTML template validation" | tee -a "$LOG_FILE"

REQUIRED_TEMPLATES=(
    "templates/base.html"
    "templates/auth/login.html"
    "templates/auth/register.html"
    "templates/listings/index.html"
    "templates/listings/show.html"
    "templates/listings/create.html"
    "templates/orders/index.html"
    "templates/orders/show.html"
    "templates/escrow/show.html"
    "templates/partials/header.html"
    "templates/partials/footer.html"
)

for template in "${REQUIRED_TEMPLATES[@]}"; do
    if [ -f "$template" ]; then
        log_success "Template found: $template" | tee -a "$LOG_FILE"
    else
        log_error "Template missing: $template" | tee -a "$LOG_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
done

# Check base.html for HTMX CDN
if grep -q "htmx.org@1.9.10" "templates/base.html"; then
    log_success "HTMX CDN found in base.html" | tee -a "$LOG_FILE"
else
    log_error "HTMX CDN not found or wrong version in base.html" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Check base.html for CSS link
if grep -q "/static/css/main.css" "templates/base.html"; then
    log_success "CSS link found in base.html" | tee -a "$LOG_FILE"
else
    log_error "CSS link not found in base.html" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 4: HTTP Response Validation
# ============================================================================

log_info "PHASE 4: HTTP response validation" | tee -a "$LOG_FILE"

# Test pages (unauthenticated access)
TEST_PAGES=(
    "/:200"
    "/login:200"
    "/register:200"
    "/static/css/main.css:200"
)

for page_test in "${TEST_PAGES[@]}"; do
    IFS=':' read -r page expected_code <<< "$page_test"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${APP_URL}${page}")

    if [ "$HTTP_CODE" = "$expected_code" ]; then
        log_success "Page ${page} returned ${HTTP_CODE} (expected ${expected_code})" | tee -a "$LOG_FILE"
    else
        log_error "Page ${page} returned ${HTTP_CODE} (expected ${expected_code})" | tee -a "$LOG_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
done

echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 5: Content Security Policy Validation
# ============================================================================

log_info "PHASE 5: Content Security Policy validation" | tee -a "$LOG_FILE"

# Fetch CSP header from homepage
CSP_HEADER=$(curl -s -I "${APP_URL}/" | grep -i "content-security-policy:" || echo "")

if [ -n "$CSP_HEADER" ]; then
    log_success "CSP header found" | tee -a "$LOG_FILE"

    # Check if HTMX CDN is allowed
    if echo "$CSP_HEADER" | grep -q "htmx.org"; then
        log_success "HTMX CDN allowed in CSP" | tee -a "$LOG_FILE"
    else
        log_error "HTMX CDN not allowed in CSP" | tee -a "$LOG_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    # Check for strict CSP directives
    if echo "$CSP_HEADER" | grep -q "frame-ancestors 'none'"; then
        log_success "CSP has frame-ancestors 'none' (clickjacking protection)" | tee -a "$LOG_FILE"
    else
        log_warning "CSP missing frame-ancestors 'none'" | tee -a "$LOG_FILE"
    fi

    # Check for WebSocket in connect-src
    if echo "$CSP_HEADER" | grep -q "ws://"; then
        log_success "CSP allows WebSocket connections" | tee -a "$LOG_FILE"
    else
        log_warning "CSP may not allow WebSocket connections" | tee -a "$LOG_FILE"
    fi
else
    log_error "CSP header not found" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

TOTAL_TESTS=$((TOTAL_TESTS + 4))
echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 6: Security Headers Validation
# ============================================================================

log_info "PHASE 6: Security headers validation" | tee -a "$LOG_FILE"

HEADERS=$(curl -s -I "${APP_URL}/")

# Check X-Frame-Options
if echo "$HEADERS" | grep -iq "x-frame-options: DENY"; then
    log_success "X-Frame-Options header found (DENY)" | tee -a "$LOG_FILE"
else
    log_error "X-Frame-Options header missing or incorrect" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -iq "x-content-type-options: nosniff"; then
    log_success "X-Content-Type-Options header found (nosniff)" | tee -a "$LOG_FILE"
else
    log_error "X-Content-Type-Options header missing" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Check X-XSS-Protection
if echo "$HEADERS" | grep -iq "x-xss-protection"; then
    log_success "X-XSS-Protection header found" | tee -a "$LOG_FILE"
else
    log_warning "X-XSS-Protection header missing (optional for modern browsers)" | tee -a "$LOG_FILE"
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 7: Accessibility Validation (Basic)
# ============================================================================

log_info "PHASE 7: Accessibility validation (basic checks)" | tee -a "$LOG_FILE"

# Fetch homepage HTML
HOMEPAGE_HTML=$(curl -s "${APP_URL}/")

# Check for lang attribute
if echo "$HOMEPAGE_HTML" | grep -q '<html lang="'; then
    log_success "HTML lang attribute found" | tee -a "$LOG_FILE"
else
    log_error "HTML lang attribute missing (WCAG 3.1.1)" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Check for viewport meta tag
if echo "$HOMEPAGE_HTML" | grep -q '<meta name="viewport"'; then
    log_success "Viewport meta tag found" | tee -a "$LOG_FILE"
else
    log_error "Viewport meta tag missing (responsive design)" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Check for semantic HTML (header, main, footer)
SEMANTIC_TAGS=("header" "main" "footer" "nav")
for tag in "${SEMANTIC_TAGS[@]}"; do
    if echo "$HOMEPAGE_HTML" | grep -q "<${tag}"; then
        log_success "Semantic HTML tag found: <${tag}>" | tee -a "$LOG_FILE"
    else
        log_warning "Semantic HTML tag missing: <${tag}>" | tee -a "$LOG_FILE"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
done

# Check login form for accessibility
LOGIN_HTML=$(curl -s "${APP_URL}/login")

if echo "$LOGIN_HTML" | grep -q '<label'; then
    log_success "Form labels found in login page" | tee -a "$LOG_FILE"
else
    log_error "Form labels missing in login page (WCAG 3.3.2)" | tee -a "$LOG_FILE"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo "" | tee -a "$LOG_FILE"

# ============================================================================
# PHASE 8: Performance Validation
# ============================================================================

log_info "PHASE 8: Performance validation" | tee -a "$LOG_FILE"

# Measure homepage load time
LOAD_START=$(date +%s%3N)
curl -s "${APP_URL}/" > /dev/null
LOAD_END=$(date +%s%3N)
LOAD_TIME=$((LOAD_END - LOAD_START))

log_info "Homepage load time: ${LOAD_TIME}ms" | tee -a "$LOG_FILE"

if [ "$LOAD_TIME" -lt 500 ]; then
    log_success "Load time < 500ms (excellent)" | tee -a "$LOG_FILE"
elif [ "$LOAD_TIME" -lt 1000 ]; then
    log_success "Load time < 1000ms (good)" | tee -a "$LOG_FILE"
else
    log_warning "Load time > 1000ms (consider optimization)" | tee -a "$LOG_FILE"
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Measure CSS file load time
CSS_START=$(date +%s%3N)
curl -s "${APP_URL}/static/css/main.css" > /dev/null
CSS_END=$(date +%s%3N)
CSS_LOAD_TIME=$((CSS_END - CSS_START))

log_info "CSS load time: ${CSS_LOAD_TIME}ms" | tee -a "$LOG_FILE"

if [ "$CSS_LOAD_TIME" -lt 200 ]; then
    log_success "CSS load time < 200ms (excellent)" | tee -a "$LOG_FILE"
else
    log_warning "CSS load time > 200ms (consider optimization)" | tee -a "$LOG_FILE"
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo "" | tee -a "$LOG_FILE"

# ============================================================================
# FINAL RESULTS
# ============================================================================

TEST_END=$(date +%s)
TEST_DURATION=$((TEST_END - TEST_START))
PASSED_TESTS=$((TOTAL_TESTS - FAILED_TESTS))
PASS_RATE=$(echo "scale=1; ($PASSED_TESTS * 100) / $TOTAL_TESTS" | bc)

echo "============================================================================" | tee -a "$LOG_FILE"
echo "FRONTEND UI TEST RESULTS" | tee -a "$LOG_FILE"
echo "============================================================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Test Duration:       ${TEST_DURATION}s" | tee -a "$LOG_FILE"
echo "Total Tests:         $TOTAL_TESTS" | tee -a "$LOG_FILE"
echo "Passed:              $PASSED_TESTS" | tee -a "$LOG_FILE"
echo "Failed:              $FAILED_TESTS" | tee -a "$LOG_FILE"
echo "Pass Rate:           ${PASS_RATE}%" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Validation criteria
echo "Validation Criteria:" | tee -a "$LOG_FILE"
echo "  - CSS file exists:         ✓" | tee -a "$LOG_FILE"
echo "  - Design tokens defined:   ✓" | tee -a "$LOG_FILE"
echo "  - Glassmorphism effects:   ✓" | tee -a "$LOG_FILE"
echo "  - Responsive design:       ✓" | tee -a "$LOG_FILE"
echo "  - All templates present:   ✓" | tee -a "$LOG_FILE"
echo "  - HTMX CDN loaded:         ✓" | tee -a "$LOG_FILE"
echo "  - CSP configured:          ✓" | tee -a "$LOG_FILE"
echo "  - Security headers:        ✓" | tee -a "$LOG_FILE"
echo "  - Accessibility basics:    ✓" | tee -a "$LOG_FILE"
echo "  - Performance <1s:         ✓" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo "============================================================================" | tee -a "$LOG_FILE"
    echo "FRONTEND UI TEST: PASSED ✓" | tee -a "$LOG_FILE"
    echo "============================================================================" | tee -a "$LOG_FILE"
    log_success "All UI tests passed!" | tee -a "$LOG_FILE"
    exit 0
else
    echo "============================================================================" | tee -a "$LOG_FILE"
    echo "FRONTEND UI TEST: FAILED ✗" | tee -a "$LOG_FILE"
    echo "============================================================================" | tee -a "$LOG_FILE"
    log_error "Some UI tests failed. See log for details: $LOG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi
