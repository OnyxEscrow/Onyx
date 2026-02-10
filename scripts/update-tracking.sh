#!/bin/bash
# NEXUS Session Tracking Auto-Update Script
# Purpose: Update features.json and progress.md after significant changes
# Usage: ./scripts/update-tracking.sh [--test-results TEST_LOG]

set -e

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments
TEST_RESULTS_FILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --test-results)
            TEST_RESULTS_FILE="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--test-results TEST_LOG]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}        Updating Session Tracking Files${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

# 1. Update last_updated timestamps
echo -e "${BLUE}[1/4] Updating timestamps...${NC}"

CURRENT_DATE=$(date +%Y-%m-%d)

if [ -f "features.json" ]; then
    # Update last_updated in features.json (requires jq)
    if command -v jq >/dev/null 2>&1; then
        jq ".last_updated = \"$CURRENT_DATE\"" features.json > features.json.tmp
        mv features.json.tmp features.json
        echo -e "${GREEN}✓${NC} Updated features.json timestamp"
    else
        echo -e "${YELLOW}⚠${NC} jq not installed, skipping features.json timestamp update"
    fi
fi

if [ -f "progress.md" ]; then
    # Update timestamp in progress.md
    sed -i "s/\*\*Last Updated:\*\* .*/\*\*Last Updated:\*\* $CURRENT_DATE/" progress.md
    echo -e "${GREEN}✓${NC} Updated progress.md timestamp"
fi

echo ""

# 2. Update test results if provided
if [ -n "$TEST_RESULTS_FILE" ] && [ -f "$TEST_RESULTS_FILE" ]; then
    echo -e "${BLUE}[2/4] Parsing test results...${NC}"

    # Extract test counts from cargo test output
    PASSED_TESTS=$(grep -oP '\d+ passed' "$TEST_RESULTS_FILE" | awk '{sum+=$1} END {print sum}')
    FAILED_TESTS=$(grep -oP '\d+ failed' "$TEST_RESULTS_FILE" | awk '{sum+=$1} END {print sum}')

    if [ -n "$PASSED_TESTS" ]; then
        echo -e "${GREEN}✓${NC} Found $PASSED_TESTS passing tests"

        # Update features.json with test counts
        if command -v jq >/dev/null 2>&1 && [ -f "features.json" ]; then
            jq ".test_summary.total_tests = $PASSED_TESTS" features.json > features.json.tmp
            mv features.json.tmp features.json
            echo -e "${GREEN}✓${NC} Updated features.json test count"
        fi
    fi

    if [ -n "$FAILED_TESTS" ] && [ "$FAILED_TESTS" -gt 0 ]; then
        echo -e "${YELLOW}⚠${NC} Found $FAILED_TESTS failing tests"
    fi
else
    echo -e "${BLUE}[2/4] No test results provided, skipping...${NC}"
fi

echo ""

# 3. Update git commit summary in progress.md
echo -e "${BLUE}[3/4] Updating git commit history...${NC}"

if [ -f "progress.md" ]; then
    # Get last 20 commits
    RECENT_COMMITS=$(git log --oneline -20 | sed 's/^/    /')

    # Create a temporary file with updated commits
    awk -v commits="$RECENT_COMMITS" '
    /^```$/ && flag == 0 {
        flag = 1
        print
        print commits
        next
    }
    /^```$/ && flag == 1 {
        flag = 2
        print
        next
    }
    flag != 1 || /^### Recent Work/ { print }
    ' progress.md > progress.md.tmp

    mv progress.md.tmp progress.md
    echo -e "${GREEN}✓${NC} Updated commit history in progress.md"
fi

echo ""

# 4. Check for modified files and update status
echo -e "${BLUE}[4/4] Checking repository status...${NC}"

MODIFIED_COUNT=$(git status --porcelain | grep -c "^.M" || echo 0)
UNTRACKED_COUNT=$(git status --porcelain | grep -c "^??" || echo 0)

echo -e "${GREEN}✓${NC} $MODIFIED_COUNT modified files"
echo -e "${GREEN}✓${NC} $UNTRACKED_COUNT untracked files"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}        Tracking Files Updated${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

# Display summary
echo -e "${BLUE}Updated Files:${NC}"
[ -f "features.json" ] && echo "  ✓ features.json"
[ -f "progress.md" ] && echo "  ✓ progress.md"
echo ""

echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Review changes: git diff features.json progress.md"
echo "  2. Commit changes: git add features.json progress.md && git commit -m 'chore: update tracking files'"
echo "  3. Continue development"
echo ""
