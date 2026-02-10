#!/bin/bash
set -e

echo "🔧 Building WASM Wallet Module..."

# Navigate to WASM directory
cd "$(dirname "$0")"

# Run clippy first
echo "📋 Running clippy..."
cargo clippy -- -D warnings

# Build WASM
echo "🌐 Building WASM..."
wasm-pack build --target web --out-dir ../../static/wasm

# Verify output
echo "✅ Build complete!"
ls -lh ../../static/wasm/wallet_wasm*

echo ""
echo "📦 WASM files generated:"
echo "  - wallet_wasm.js (JavaScript glue)"
echo "  - wallet_wasm_bg.wasm (WebAssembly binary)"
echo "  - wallet_wasm.d.ts (TypeScript definitions)"
echo ""
echo "🚀 Ready to use in Web UI at /wallet/setup"
