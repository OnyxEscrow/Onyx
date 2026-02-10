#!/bin/bash
# Test Shamir 3-of-5 key splitting and reconstruction (TM-002)
#
# This script validates the TM-002 mitigation implementation:
# 1. Generate a test encryption key
# 2. Split into 5 shares (3 required)
# 3. Reconstruct from 3 shares
# 4. Verify reconstruction matches original

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  TM-002 Shamir Secret Sharing - Integration Test          ║"
echo "║  Testing 3-of-5 key splitting and reconstruction          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Generate test key (32 bytes = 64 hex chars)
echo "[1/5] Generating test 256-bit encryption key..."
TEST_KEY=$(openssl rand -hex 32)
echo "      Key: ${TEST_KEY:0:16}...${TEST_KEY: -16}"
echo ""

# Step 2: Split key into 5 shares
echo "[2/5] Splitting key into 5 shares (threshold: 3)..."
SHARES_OUTPUT=$(echo "$TEST_KEY" | cargo run --quiet --bin split_key 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "❌ FAILED: split_key binary failed"
    echo "$SHARES_OUTPUT"
    exit 1
fi

# Extract shares from output
SHARE1=$(echo "$SHARES_OUTPUT" | grep "Share 1 -" | awk '{print $NF}')
SHARE2=$(echo "$SHARES_OUTPUT" | grep "Share 2 -" | awk '{print $NF}')
SHARE3=$(echo "$SHARES_OUTPUT" | grep "Share 3 -" | awk '{print $NF}')
SHARE4=$(echo "$SHARES_OUTPUT" | grep "Share 4 -" | awk '{print $NF}')
SHARE5=$(echo "$SHARES_OUTPUT" | grep "Share 5 -" | awk '{print $NF}')

if [ -z "$SHARE1" ] || [ -z "$SHARE2" ] || [ -z "$SHARE3" ]; then
    echo "❌ FAILED: Could not extract shares from split_key output"
    echo "$SHARES_OUTPUT"
    exit 1
fi

echo "      ✅ Successfully generated 5 shares"
echo ""

# Step 3: Test reconstruction with shares 1, 2, 3
echo "[3/5] Reconstructing key with shares 1, 2, 3..."
RECONSTRUCTED=$(printf "%s\n%s\n%s\n" "$SHARE1" "$SHARE2" "$SHARE3" | \
    cargo run --quiet --bin reconstruct_key 2>/dev/null | \
    grep -A 1 "Reconstructed Key (hex):" | tail -1 | tr -d ' ')

if [ -z "$RECONSTRUCTED" ]; then
    echo "❌ FAILED: Could not reconstruct key"
    exit 1
fi

echo "      Reconstructed: ${RECONSTRUCTED:0:16}...${RECONSTRUCTED: -16}"
echo ""

# Step 4: Verify reconstruction matches original
echo "[4/5] Verifying reconstructed key matches original..."
if [ "$RECONSTRUCTED" == "$TEST_KEY" ]; then
    echo "      ✅ PASS: Reconstruction successful"
else
    echo "      ❌ FAIL: Keys don't match!"
    echo "      Original:      $TEST_KEY"
    echo "      Reconstructed: $RECONSTRUCTED"
    exit 1
fi
echo ""

# Step 5: Test reconstruction with different combination (shares 2, 4, 5)
echo "[5/5] Testing with different share combination (2, 4, 5)..."
RECONSTRUCTED2=$(printf "%s\n%s\n%s\n" "$SHARE2" "$SHARE4" "$SHARE5" | \
    cargo run --quiet --bin reconstruct_key 2>/dev/null | \
    grep -A 1 "Reconstructed Key (hex):" | tail -1 | tr -d ' ')

if [ "$RECONSTRUCTED2" == "$TEST_KEY" ]; then
    echo "      ✅ PASS: Alternative reconstruction successful"
else
    echo "      ❌ FAIL: Alternative reconstruction failed!"
    exit 1
fi
echo ""

# Final summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ TM-002 MITIGATION VALIDATED                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Summary:"
echo "  • Original key:          ${TEST_KEY:0:20}..."
echo "  • Shares generated:      5"
echo "  • Threshold:             3"
echo "  • Reconstruction test 1: ✅ PASS (shares 1,2,3)"
echo "  • Reconstruction test 2: ✅ PASS (shares 2,4,5)"
echo ""
echo "🔒 Shamir 3-of-5 secret sharing is working correctly!"
echo ""
echo "Next steps for production deployment:"
echo "  1. Generate production DB encryption key: openssl rand -hex 32"
echo "  2. Split into 5 shares: cargo run --bin split_key"
echo "  3. Store shares in separate secure locations (see TM-002 spec)"
echo "  4. Delete original key: shred -uvz -n 5 db_key.txt"
echo "  5. Unset DB_ENCRYPTION_KEY from .env to enable Shamir mode"
echo "  6. Start server - will prompt for 3 shares interactively"
echo ""
