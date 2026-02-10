#!/bin/bash

# Script: test-automation-setup.sh
# Description: Validate Phase 1 Ultra-Automation installation
# Usage: ./scripts/test-automation-setup.sh

# --- Couleurs ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║ ${NC} Testing Phase 1: Claude AI Ultra-Automation Setup${CYAN} ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
echo

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name=$1
    local test_command=$2

    echo -n "Testing: $test_name... "

    if eval "$test_command" &> /dev/null; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# --- Test 1: Python Version ---
run_test "Python 3.11+" "python3 --version | grep -E 'Python 3\.(11|12|13)'"

# --- Test 2: Scripts Exist ---
run_test "claude_security_analyzer.py exists" "test -f scripts/ai/claude_security_analyzer.py"
run_test "claude_quick_scan.py exists" "test -f scripts/ai/claude_quick_scan.py"
run_test "audit-master.sh exists" "test -f scripts/audit-master.sh"

# --- Test 3: Scripts Executable ---
run_test "claude_security_analyzer.py executable" "test -x scripts/ai/claude_security_analyzer.py"
run_test "claude_quick_scan.py executable" "test -x scripts/ai/claude_quick_scan.py"
run_test "audit-master.sh executable" "test -x scripts/audit-master.sh"

# --- Test 4: Python Syntax ---
run_test "claude_security_analyzer.py syntax" "python3 -m py_compile scripts/ai/claude_security_analyzer.py"
run_test "claude_quick_scan.py syntax" "python3 -m py_compile scripts/ai/claude_quick_scan.py"

# --- Test 5: Dependencies (Optional) ---
echo -n "Testing: anthropic package... "
if python3 -c "import anthropic" 2>/dev/null; then
    echo -e "${GREEN}✅ INSTALLED${NC}"
    ((TESTS_PASSED++))

    # Test API key if anthropic is installed
    echo -n "Testing: ANTHROPIC_API_KEY... "
    if [ -n "$ANTHROPIC_API_KEY" ]; then
        echo -e "${GREEN}✅ SET${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${YELLOW}⚠️  NOT SET (optional for testing)${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  NOT INSTALLED${NC}"
    echo -e "${YELLOW}   Install with: pip install -r requirements.txt${NC}"
fi

# --- Test 6: GitHub Workflows ---
run_test "claude-security-review.yml exists" "test -f .github/workflows/claude-security-review.yml"
run_test "claude-daily-scan.yml exists" "test -f .github/workflows/claude-daily-scan.yml"

# --- Test 7: Documentation ---
run_test "ULTRA-AUTOMATION-GUIDE.md exists" "test -f docs/ULTRA-AUTOMATION-GUIDE.md"
run_test "scripts/ai/README.md exists" "test -f scripts/ai/README.md"
run_test "requirements.txt exists" "test -f requirements.txt"

# --- Test 8: Directory Structure ---
run_test "docs/security-reports/ directory" "test -d docs/security-reports || mkdir -p docs/security-reports"

# --- Test 9: Help Commands ---
run_test "claude_security_analyzer --help" "python3 scripts/ai/claude_security_analyzer.py --help | grep -q 'usage:'"
run_test "claude_quick_scan --help" "python3 scripts/ai/claude_quick_scan.py --help | grep -q 'usage:'"

# --- Test 10: Bash Syntax ---
run_test "audit-master.sh syntax" "bash -n scripts/audit-master.sh"

# --- Summary ---
echo
echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                    TEST SUMMARY                       ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ✅ ALL TESTS PASSED - Phase 1 Ready for Use!      ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}Next steps:${NC}"
    echo -e "  1. Set ANTHROPIC_API_KEY: ${YELLOW}export ANTHROPIC_API_KEY='sk-ant-...'${NC}"
    echo -e "  2. Install Python deps: ${YELLOW}pip install -r requirements.txt${NC}"
    echo -e "  3. Run first audit: ${YELLOW}./scripts/audit-master.sh --full${NC}"
    echo
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${NC}  ❌ SOME TESTS FAILED - Please fix issues above      ${RED}║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════╝${NC}"
    echo
    exit 1
fi
