#!/bin/bash
# =============================================================================
# NEXUS Production Build Script
# =============================================================================
#
# Builds only the production server binary, excluding development binaries
# that should never be deployed to production (debug_*, verify_*, test_*).
#
# Usage:
#   ./scripts/build-release.sh
#
# Output:
#   target/release/server
#
# =============================================================================

set -e

echo "========================================"
echo "NEXUS Production Build"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Verify environment
echo -e "\n${YELLOW}[1/4] Checking environment...${NC}"

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}ERROR: cargo not found. Install Rust first.${NC}"
    exit 1
fi

echo -e "${GREEN}  cargo: $(cargo --version)${NC}"

# Step 2: Clean previous builds (optional)
if [ "$1" == "--clean" ]; then
    echo -e "\n${YELLOW}[2/4] Cleaning previous builds...${NC}"
    cargo clean
else
    echo -e "\n${YELLOW}[2/4] Skipping clean (use --clean to clean)${NC}"
fi

# Step 3: Build ONLY the main server binary
echo -e "\n${YELLOW}[3/4] Building production server binary...${NC}"
echo "  Command: cargo build --release --bin server"
echo ""

cargo build --release --bin server

# Step 4: Verify output
echo -e "\n${YELLOW}[4/4] Verifying build output...${NC}"

BINARY_PATH="target/release/server"

if [ -f "$BINARY_PATH" ]; then
    SIZE=$(ls -lh "$BINARY_PATH" | awk '{print $5}')
    echo -e "${GREEN}  Binary: $BINARY_PATH ($SIZE)${NC}"
    echo -e "${GREEN}  Build timestamp: $(stat -c '%y' $BINARY_PATH)${NC}"
else
    echo -e "${RED}ERROR: Build failed - binary not found${NC}"
    exit 1
fi

echo ""
echo "========================================"
echo -e "${GREEN}Production build complete!${NC}"
echo "========================================"
echo ""
echo "Deployment checklist:"
echo "  [ ] Copy target/release/server to production"
echo "  [ ] Ensure marketplace.db is backed up"
echo "  [ ] Set DB_ENCRYPTION_KEY environment variable"
echo "  [ ] Verify Tor daemon is running"
echo "  [ ] Start server: ./server"
echo ""
echo "IMPORTANT: Do NOT deploy the following binaries:"
echo "  - debug_*"
echo "  - verify_*"
echo "  - test_*"
echo "  - clsag_test_vectors"
echo "  - Any binary containing sensitive test data"
echo ""
