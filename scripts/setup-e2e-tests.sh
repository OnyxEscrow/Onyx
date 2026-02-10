#!/bin/bash
set -euo pipefail

# ============================================================================
# Setup script for E2E tests
# ============================================================================

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVER_DIR="$PROJECT_ROOT/server"

cd "$SERVER_DIR"

echo "🧪 Setting up E2E test environment..."
echo ""

# Step 1: Create test database
echo "📦 Step 1/4: Creating test database..."
if [ -f "test_marketplace.db" ]; then
    echo "  ⚠️  test_marketplace.db already exists"
    read -p "  Delete and recreate? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f test_marketplace.db test_marketplace.db-shm test_marketplace.db-wal
        echo "  ✅ Deleted existing database"
    else
        echo "  ℹ️  Keeping existing database"
    fi
fi

if [ ! -f "test_marketplace.db" ]; then
    touch test_marketplace.db
    echo "  ✅ Created test_marketplace.db"
fi

# Step 2: Check diesel CLI
echo ""
echo "🔧 Step 2/4: Checking diesel CLI..."
if ! command -v diesel &> /dev/null; then
    echo "  ❌ diesel CLI not found"
    echo "  Install with: cargo install diesel_cli --no-default-features --features sqlite"
    exit 1
fi
echo "  ✅ diesel CLI found: $(diesel --version)"

# Step 3: Apply migrations
echo ""
echo "🗄️  Step 3/4: Applying migrations..."
DATABASE_URL=test_marketplace.db diesel migration run
echo "  ✅ Migrations applied"

# Step 4: Create .env.test
echo ""
echo "📝 Step 4/4: Creating .env.test..."
cat > .env.test << 'EOF'
# E2E Test Environment Configuration
DATABASE_URL=test_marketplace.db
DB_ENCRYPTION_KEY=test_encryption_key_32_bytes!!!!!!!

# Monero RPC (optional for E2E tests, used by orchestrator tests)
MONERO_RPC_URL=http://127.0.0.1:18082/json_rpc
EOF
echo "  ✅ Created .env.test"

# Verification
echo ""
echo "✅ Setup complete!"
echo ""
echo "📊 Database schema:"
sqlite3 test_marketplace.db ".tables"

echo ""
echo "🚀 Run E2E tests with:"
echo "   cargo test --package server --test escrow_e2e -- --ignored"
echo ""
echo "   Or a specific test:"
echo "   cargo test --package server --test escrow_e2e test_complete_escrow_flow -- --ignored --nocapture"
echo ""
