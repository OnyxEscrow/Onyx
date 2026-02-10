#!/bin/bash
# Dependency Security Audit Script
# Checks for vulnerabilities, outdated packages, and license compliance

set -e

echo "=================================================="
echo "Dependency Security Audit"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
ISSUES_FOUND=0
WARNINGS=0

# ============================================================================
# Function: Check if command exists
# ============================================================================
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ============================================================================
# Function: Install missing tools
# ============================================================================
install_tools() {
    echo -e "${BLUE}[SETUP]${NC} Checking for required tools..."

    if ! command_exists cargo-audit; then
        echo "  Installing cargo-audit..."
        cargo install cargo-audit --locked
    fi

    if ! command_exists cargo-deny; then
        echo "  Installing cargo-deny..."
        cargo install cargo-deny --locked
    fi

    if ! command_exists cargo-outdated; then
        echo "  Installing cargo-outdated..."
        cargo install cargo-outdated --locked
    fi

    if ! command_exists cargo-license; then
        echo "  Installing cargo-license..."
        cargo install cargo-license --locked
    fi

    echo -e "${GREEN}✅ All tools installed${NC}"
    echo ""
}

# ============================================================================
# Check 1: Cargo Audit (Known Vulnerabilities)
# ============================================================================
check_vulnerabilities() {
    echo "=================================================="
    echo "Check 1: Known Vulnerabilities (cargo audit)"
    echo "=================================================="
    echo ""

    # Update advisory database
    echo "Updating RustSec advisory database..."
    cargo audit fetch

    # Run audit with JSON output
    if cargo audit --json > /tmp/audit-report.json 2>&1; then
        echo -e "${GREEN}✅ No known vulnerabilities found${NC}"
    else
        VULNS=$(jq '.vulnerabilities.found' /tmp/audit-report.json 2>/dev/null || echo "0")

        if [ "$VULNS" -gt 0 ]; then
            echo -e "${RED}❌ Found $VULNS vulnerabilities:${NC}"
            echo ""
            cargo audit --color always

            # Show details
            jq -r '.vulnerabilities.list[] | "  - \(.advisory.id): \(.advisory.title) (\(.package.name):\(.package.version))"' /tmp/audit-report.json 2>/dev/null || true

            ((ISSUES_FOUND += VULNS))
        fi
    fi

    echo ""
}

# ============================================================================
# Check 2: Outdated Dependencies
# ============================================================================
check_outdated() {
    echo "=================================================="
    echo "Check 2: Outdated Dependencies (cargo outdated)"
    echo "=================================================="
    echo ""

    if cargo outdated --format json > /tmp/outdated-report.json 2>&1; then
        OUTDATED=$(jq '.dependencies | length' /tmp/outdated-report.json 2>/dev/null || echo "0")

        if [ "$OUTDATED" -eq 0 ]; then
            echo -e "${GREEN}✅ All dependencies are up to date${NC}"
        else
            echo -e "${YELLOW}⚠️  Found $OUTDATED outdated dependencies:${NC}"
            echo ""
            cargo outdated --color always | head -20

            ((WARNINGS += OUTDATED))
        fi
    else
        echo -e "${RED}❌ Failed to check outdated dependencies${NC}"
    fi

    echo ""
}

# ============================================================================
# Check 3: License Compliance
# ============================================================================
check_licenses() {
    echo "=================================================="
    echo "Check 3: License Compliance (cargo license)"
    echo "=================================================="
    echo ""

    cargo license --json > /tmp/licenses.json 2>&1

    # Check for incompatible licenses
    INCOMPATIBLE=$(jq -r '.[] | select(.license | contains("GPL-3.0") or contains("AGPL-3.0")) | .name' /tmp/licenses.json 2>/dev/null || true)

    if [ -z "$INCOMPATIBLE" ]; then
        echo -e "${GREEN}✅ All licenses compatible with MIT${NC}"
    else
        echo -e "${RED}❌ Found incompatible licenses:${NC}"
        echo "$INCOMPATIBLE" | while read -r crate; do
            echo "  - $crate"
        done

        ((ISSUES_FOUND++))
    fi

    echo ""
}

# ============================================================================
# Check 4: Supply Chain Security (cargo deny)
# ============================================================================
check_supply_chain() {
    echo "=================================================="
    echo "Check 4: Supply Chain Security (cargo deny)"
    echo "=================================================="
    echo ""

    # Check if deny.toml exists
    if [ ! -f deny.toml ]; then
        echo -e "${YELLOW}⚠️  deny.toml not found, creating default...${NC}"
        cargo deny init
    fi

    # Run all checks
    if cargo deny check all --format json > /tmp/deny-report.json 2>&1; then
        echo -e "${GREEN}✅ Supply chain checks passed${NC}"
    else
        echo -e "${RED}❌ Supply chain issues detected:${NC}"
        echo ""
        cargo deny check all --color always

        ((ISSUES_FOUND++))
    fi

    echo ""
}

# ============================================================================
# Check 5: Yanked Crates
# ============================================================================
check_yanked() {
    echo "=================================================="
    echo "Check 5: Yanked Crates"
    echo "=================================================="
    echo ""

    # cargo audit also checks for yanked crates
    YANKED=$(jq '.vulnerabilities.list[] | select(.advisory.id | startswith("RUSTSEC")) | .package.name' /tmp/audit-report.json 2>/dev/null || true)

    if [ -z "$YANKED" ]; then
        echo -e "${GREEN}✅ No yanked crates in use${NC}"
    else
        echo -e "${RED}❌ Found yanked crates:${NC}"
        echo "$YANKED" | while read -r crate; do
            echo "  - $crate"
        done

        ((ISSUES_FOUND++))
    fi

    echo ""
}

# ============================================================================
# Check 6: Duplicate Dependencies (bloat check)
# ============================================================================
check_duplicates() {
    echo "=================================================="
    echo "Check 6: Duplicate Dependencies"
    echo "=================================================="
    echo ""

    # Find duplicate versions
    DUPLICATES=$(cargo tree --duplicates 2>/dev/null | grep -v "^$" || true)

    if [ -z "$DUPLICATES" ]; then
        echo -e "${GREEN}✅ No duplicate dependencies${NC}"
    else
        echo -e "${YELLOW}⚠️  Found duplicate dependencies (may increase binary size):${NC}"
        echo ""
        echo "$DUPLICATES" | head -20

        ((WARNINGS++))
    fi

    echo ""
}

# ============================================================================
# Generate Report
# ============================================================================
generate_report() {
    echo "=================================================="
    echo "Audit Summary Report"
    echo "=================================================="
    echo ""

    local REPORT_FILE="target/dependency-audit-report.md"
    mkdir -p target

    cat > "$REPORT_FILE" <<EOF
# Dependency Security Audit Report

**Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Project:** Monero Marketplace

---

## Summary

- **Critical Issues:** $ISSUES_FOUND
- **Warnings:** $WARNINGS

---

## Detailed Results

### 1. Known Vulnerabilities

$(if [ -f /tmp/audit-report.json ]; then
    jq -r '.vulnerabilities.list[] | "- **\(.advisory.id)**: \(.advisory.title)\n  - Package: `\(.package.name):\(.package.version)`\n  - Severity: \(.advisory.severity)\n  - Fix: \(.advisory.patched_versions // "None")\n  - URL: \(.advisory.url)\n"' /tmp/audit-report.json 2>/dev/null || echo "No vulnerabilities found"
else
    echo "No audit data available"
fi)

### 2. Outdated Dependencies

$(if [ -f /tmp/outdated-report.json ]; then
    jq -r '.dependencies[] | "- `\(.name)`: \(.project) → \(.latest)"' /tmp/outdated-report.json 2>/dev/null | head -10 || echo "All up to date"
else
    echo "No outdated check performed"
fi)

### 3. License Compliance

$(cargo license --color never 2>/dev/null | head -20 || echo "License check failed")

### 4. Action Items

$(if [ "$ISSUES_FOUND" -gt 0 ]; then
    echo "**CRITICAL:** Fix $ISSUES_FOUND critical issues immediately"
    echo "1. Review vulnerability details above"
    echo "2. Update affected dependencies"
    echo "3. Test thoroughly before deploying"
    echo "4. Re-run this audit after fixes"
else
    echo "✅ No critical issues - continue monitoring"
fi)

$(if [ "$WARNINGS" -gt 0 ]; then
    echo ""
    echo "**Recommended:**"
    echo "1. Update $WARNINGS outdated dependencies"
    echo "2. Review duplicate dependencies"
    echo "3. Schedule next audit"
fi)

---

**Generated by:** \`scripts/audit-dependencies.sh\`
EOF

    echo -e "${BLUE}📄 Report saved to:${NC} $REPORT_FILE"
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    echo "Starting dependency security audit..."
    echo ""

    # Install tools if needed
    if [ "${SKIP_INSTALL:-}" != "true" ]; then
        install_tools
    fi

    # Run all checks
    check_vulnerabilities
    check_outdated
    check_licenses
    check_supply_chain
    check_yanked
    check_duplicates

    # Generate report
    generate_report

    # Final summary
    echo "=================================================="
    echo "Audit Complete"
    echo "=================================================="
    echo ""

    if [ "$ISSUES_FOUND" -eq 0 ]; then
        echo -e "${GREEN}✅ No critical issues found${NC}"

        if [ "$WARNINGS" -gt 0 ]; then
            echo -e "${YELLOW}⚠️  $WARNINGS warnings (recommended fixes)${NC}"
            exit 0
        else
            echo -e "${GREEN}✅ All checks passed!${NC}"
            exit 0
        fi
    else
        echo -e "${RED}❌ Found $ISSUES_FOUND critical issues${NC}"
        echo -e "${RED}⚠️  Action required before production deployment${NC}"
        echo ""
        echo "View full report: target/dependency-audit-report.md"
        exit 1
    fi
}

# Run main
main "$@"
