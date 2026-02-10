#!/bin/bash
# Start Monero Marketplace Server
# Usage: ./scripts/start-server.sh

set -e

cd "$(dirname "$0")/.."

echo "🚀 Starting Monero Marketplace Server..."
echo "========================================"

# Source cargo environment
if [ -f ~/.cargo/env ]; then
    source ~/.cargo/env
fi

# Run server
cargo run --bin server
