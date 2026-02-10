#!/bin/bash
# Property-based testing runner
# Executes property-based tests with various configurations

set -e

echo "=================================================="
echo "Property-Based Testing Suite"
echo "=================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
PROPTEST_CASES=${PROPTEST_CASES:-100}  # Number of test cases per property
PROPTEST_MAX_SHRINK_ITERS=${PROPTEST_MAX_SHRINK_ITERS:-10000}  # Max shrink attempts

echo -e "${BLUE}Configuration:${NC}"
echo "  Test cases per property: $PROPTEST_CASES"
echo "  Max shrink iterations: $PROPTEST_MAX_SHRINK_ITERS"
echo ""

# Function to run tests with specific configuration
run_property_tests() {
    local mode=$1
    local cases=$2
    local description=$3

    echo -e "${YELLOW}[$mode]${NC} $description"
    echo "  Running with $cases test cases..."

    PROPTEST_CASES=$cases \
    PROPTEST_MAX_SHRINK_ITERS=$PROPTEST_MAX_SHRINK_ITERS \
    cargo test --package monero-marketplace-wallet \
        --test property_based_multisig \
        -- --nocapture 2>&1 | \
        grep -E "(test.*ok|test.*FAILED|running|test result)" || true

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
    else
        echo -e "${RED}❌ FAILED${NC}"
        return 1
    fi
    echo ""
}

# Parse command-line arguments
MODE=${1:-quick}

case $MODE in
    quick)
        echo "=================================================="
        echo "Quick Mode (100 cases per property)"
        echo "=================================================="
        echo ""
        run_property_tests "QUICK" 100 "Fast validation of properties"
        ;;

    standard)
        echo "=================================================="
        echo "Standard Mode (1,000 cases per property)"
        echo "=================================================="
        echo ""
        run_property_tests "STANDARD" 1000 "Standard property validation"
        ;;

    thorough)
        echo "=================================================="
        echo "Thorough Mode (10,000 cases per property)"
        echo "=================================================="
        echo ""
        run_property_tests "THOROUGH" 10000 "Extensive property validation"
        ;;

    stress)
        echo "=================================================="
        echo "Stress Mode (100,000 cases per property)"
        echo "=================================================="
        echo ""
        echo -e "${RED}WARNING:${NC} This may take several minutes..."
        echo ""
        run_property_tests "STRESS" 100000 "Stress testing with extreme cases"
        ;;

    regression)
        echo "=================================================="
        echo "Regression Tests Only"
        echo "=================================================="
        echo ""
        cargo test --package monero-marketplace-wallet \
            --test property_based_multisig \
            regression_ \
            -- --nocapture
        ;;

    performance)
        echo "=================================================="
        echo "Performance Tests Only"
        echo "=================================================="
        echo ""
        cargo test --package monero-marketplace-wallet \
            --test property_based_multisig \
            perf_ \
            -- --nocapture --test-threads=1
        ;;

    all)
        echo "=================================================="
        echo "Running All Test Suites"
        echo "=================================================="
        echo ""

        run_property_tests "QUICK" 100 "Quick smoke test"
        run_property_tests "STANDARD" 1000 "Standard validation"

        echo "Running regression tests..."
        cargo test --package monero-marketplace-wallet \
            --test property_based_multisig \
            regression_ \
            -- --nocapture

        echo ""
        echo "Running performance tests..."
        cargo test --package monero-marketplace-wallet \
            --test property_based_multisig \
            perf_ \
            -- --nocapture --test-threads=1
        ;;

    *)
        echo "Usage: $0 [mode]"
        echo ""
        echo "Modes:"
        echo "  quick       - 100 cases per property (~5 seconds)"
        echo "  standard    - 1,000 cases per property (~30 seconds)"
        echo "  thorough    - 10,000 cases per property (~5 minutes)"
        echo "  stress      - 100,000 cases per property (~30 minutes)"
        echo "  regression  - Run regression tests only"
        echo "  performance - Run performance tests only"
        echo "  all         - Run all test suites"
        echo ""
        echo "Examples:"
        echo "  $0 quick              # Fast validation"
        echo "  $0 thorough           # Comprehensive testing"
        echo "  $0 regression         # Only regression tests"
        echo ""
        echo "Environment variables:"
        echo "  PROPTEST_CASES              - Number of test cases (default: 100)"
        echo "  PROPTEST_MAX_SHRINK_ITERS   - Max shrink attempts (default: 10000)"
        exit 1
        ;;
esac

echo "=================================================="
echo "Property-Based Testing Complete"
echo "=================================================="
echo ""
echo "For more information, see:"
echo "  - DOX/security/PROPERTY-BASED-TESTING.md"
echo "  - wallet/tests/property_based_multisig.rs"
