#!/bin/bash
# Quick Audit - Simplified version
set -e

echo "════════════════════════════════════════════"
echo "QUICK AUDIT - Monero Marketplace"
echo "════════════════════════════════════════════"
echo

CRITICAL=0
HIGH=0
MEDIUM=0

# Check 1: schema.rs
echo "Checking infrastructure..."
if [ ! -f "server/src/schema.rs" ]; then
    echo "🔴 CRITICAL: schema.rs MISSING!"
    echo "   Fix: DATABASE_URL=marketplace.db diesel print-schema > server/src/schema.rs"
    ((CRITICAL++))
else
    echo "✓ schema.rs exists"
fi

# Check 2: Migrations
if command -v diesel &> /dev/null; then
    PENDING=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" || echo "0")
    if [ "$PENDING" -gt 0 ]; then
        echo "🔴 CRITICAL: $PENDING migrations NOT applied!"
        echo "   Fix: DATABASE_URL=marketplace.db diesel migration run"
        ((CRITICAL++))
    else
        echo "✓ All migrations applied"
    fi
fi

# Check 3: Database exists
if [ ! -f "marketplace.db" ]; then
    echo "🔴 CRITICAL: marketplace.db MISSING!"
    ((CRITICAL++))
else
    echo "✓ marketplace.db exists"
fi

# Check 4: Tor
if ! pgrep -x "tor" > /dev/null; then
    echo "🔴 CRITICAL: Tor daemon NOT running!"
    ((CRITICAL++))
else
    echo "✓ Tor daemon running"
fi

# Check 5: .env in git
if git ls-files .env 2>/dev/null | grep -q ".env"; then
    echo "🔴 CRITICAL: .env tracked by git (exposes secrets)!"
    ((CRITICAL++))
else
    echo "✓ .env not in git"
fi

# Check 6: Unwraps
UNWRAPS=$(grep -r "\.unwrap()" --include="*.rs" --exclude-dir=target . 2>/dev/null | wc -l || echo "0")
if [ "$UNWRAPS" -gt 50 ]; then
    echo "🟠 HIGH: $UNWRAPS uses of unwrap/expect (risk of panics)"
    ((HIGH++))
else
    echo "✓ Acceptable unwrap usage ($UNWRAPS)"
fi

# Check 7: Compilation
echo
echo "Checking compilation..."
if cargo check --workspace --quiet 2>&1 | grep -q "error"; then
    echo "🔴 CRITICAL: Compilation errors!"
    ((CRITICAL++))
else
    echo "✓ Project compiles"
fi

echo
echo "════════════════════════════════════════════"
echo "RESULTS:"
echo "🔴 Critical: $CRITICAL"
echo "🟠 High: $HIGH"
echo "🟡 Medium: $MEDIUM"
echo

if [ "$CRITICAL" -gt 0 ]; then
    echo "⚠️  FIX CRITICAL ISSUES IMMEDIATELY"
    exit 1
else
    echo "✅ No critical issues"
    exit 0
fi
