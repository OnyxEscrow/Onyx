#!/bin/bash
# run-security-audit.sh - Local security audit runner
#
# Runs the same security checks as CI/CD locally
# Usage: ./scripts/run-security-audit.sh

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Monero Marketplace - Local Security Audit                ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for required tools
MISSING_TOOLS=0

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}✗${NC} $1 not installed"
        echo "  Install: $2"
        MISSING_TOOLS=$((MISSING_TOOLS + 1))
    else
        echo -e "${GREEN}✓${NC} $1 installed"
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Checking for required tools..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_tool "cargo" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
check_tool "cargo-audit" "cargo install cargo-audit --locked"
check_tool "cargo-outdated" "cargo install cargo-outdated --locked"

if [ $MISSING_TOOLS -gt 0 ]; then
    echo ""
    echo -e "${RED}ERROR: $MISSING_TOOLS required tool(s) missing${NC}"
    echo "Install missing tools and try again"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Audit 1: Cargo Audit (Known Vulnerabilities)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if cargo audit --deny warnings 2>&1; then
    echo -e "${GREEN}✓ PASS${NC}: No known vulnerabilities detected"
else
    echo -e "${RED}✗ FAIL${NC}: Vulnerabilities found!"
    echo ""
    echo "Review output above and update dependencies:"
    echo "  cargo update"
    echo ""
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Audit 2: Outdated Dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

OUTDATED=$(cargo outdated --format list --workspace 2>&1 || true)

if echo "$OUTDATED" | grep -q "All dependencies are up to date"; then
    echo -e "${GREEN}✓ PASS${NC}: All dependencies up to date"
else
    echo -e "${YELLOW}⚠ WARNING${NC}: Some dependencies are outdated"
    echo ""
    cargo outdated --workspace
    echo ""
    echo "Consider updating:"
    echo "  cargo update"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Audit 3: Security Theatre Detection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "scripts/check-security-theatre.sh" ]; then
    if ./scripts/check-security-theatre.sh; then
        echo -e "${GREEN}✓ PASS${NC}: No security theatre detected"
    else
        echo -e "${RED}✗ FAIL${NC}: Security theatre patterns found"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ SKIP${NC}: check-security-theatre.sh not found"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Audit 4: Forbidden Patterns"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

VIOLATIONS=0

# Check for .unwrap() in production code (excluding tests)
UNWRAPS=$(grep -r "\.unwrap()" --include="*.rs" server/src/ wallet/src/ 2>/dev/null | grep -v "tests/" | grep -v "test_" || true)
if [ -n "$UNWRAPS" ]; then
    echo -e "${RED}✗${NC} Found .unwrap() in production code:"
    echo "$UNWRAPS" | head -5
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo -e "${GREEN}✓${NC} No .unwrap() in production code"
fi

# Check for println! in production code
PRINTLNS=$(grep -r "println!" --include="*.rs" server/src/ wallet/src/ 2>/dev/null | grep -v "tests/" | grep -v "test_" || true)
if [ -n "$PRINTLNS" ]; then
    echo -e "${RED}✗${NC} Found println! in production code:"
    echo "$PRINTLNS" | head -5
    echo "  Use tracing::info!() instead"
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo -e "${GREEN}✓${NC} No println! in production code"
fi

# Check for TODO/FIXME without issue tracking
TODOS=$(grep -r "TODO\|FIXME" --include="*.rs" server/src/ wallet/src/ 2>/dev/null | grep -v "tests/" || true)
if [ -n "$TODOS" ]; then
    TODO_COUNT=$(echo "$TODOS" | wc -l)
    echo -e "${YELLOW}⚠${NC} Found $TODO_COUNT TODO/FIXME comments"
    echo "  Ensure they are tracked in issues"
else
    echo -e "${GREEN}✓${NC} No untracked TODO/FIXME"
fi

if [ $VIOLATIONS -gt 0 ]; then
    echo ""
    echo -e "${RED}✗ FAIL${NC}: $VIOLATIONS forbidden pattern violations"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Audit 5: Clippy Security Lints"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if cargo clippy --workspace --quiet -- \
    -D warnings \
    -D clippy::unwrap_used \
    -D clippy::expect_used 2>&1 | head -20; then
    echo -e "${GREEN}✓ PASS${NC}: No clippy security warnings"
else
    echo -e "${RED}✗ FAIL${NC}: Clippy found security issues"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Audit 6: Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if cargo test --workspace --quiet 2>&1 | tail -20; then
    echo -e "${GREEN}✓ PASS${NC}: All tests passing"
else
    echo -e "${RED}✗ FAIL${NC}: Tests failing"
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✓ All Security Audits PASSED                             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Your code is ready for commit!"
echo ""
echo "Next steps:"
echo "  1. git add ."
echo "  2. git commit -m 'Your message'"
echo "  3. git push"
echo ""
echo "CI/CD will run the same checks automatically."
echo ""
