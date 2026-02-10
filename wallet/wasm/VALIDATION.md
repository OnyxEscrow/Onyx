# WASM Wallet - Validation Commands

## Quick Validation

```bash
# 1. Build WASM module
cd /home/malix/Desktop/NEXUS/wallet/wasm
./build.sh

# 2. Verify workspace compiles
cd /home/malix/Desktop/NEXUS
cargo check --workspace

# 3. Run clippy on WASM crate
cargo clippy --package wallet_wasm -- -D warnings

# 4. Run tests (requires browser)
cd wallet/wasm
wasm-pack test --headless --firefox

# 5. Verify WASM files exist
ls -lh /home/malix/Desktop/NEXUS/static/wasm/wallet_wasm*
```

## Expected Output

### WASM Files
```
static/wasm/
├── wallet_wasm.js           (13 KB)  - JavaScript glue
├── wallet_wasm_bg.wasm      (139 KB) - WASM binary
├── wallet_wasm.d.ts         (1.5 KB) - TypeScript definitions
└── package.json             (261 B)  - NPM metadata
```

### Clippy Output
```
Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.31s
```

### Test Output
```
running 3 tests
test test_generate_wallet_structure ... ok
test test_generate_wallet_uniqueness ... ok
test test_address_hash_consistency ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

## Manual Browser Testing

### 1. Start Server
```bash
cd /home/malix/Desktop/NEXUS
cargo run --bin monero-marketplace
```

### 2. Open Wallet Setup Page
```
http://localhost:8080/wallet/setup
```

### 3. Open DevTools
- Press `F12`
- Go to **Network** tab
- Click "Generate Wallet"

### 4. Verify Expected Behavior

✅ **Success Indicators**:
- [ ] 12-word seed displayed in UI
- [ ] Each word is a valid BIP39 word
- [ ] Address starts with `4` (Monero mainnet)
- [ ] Public view key is 64 hex characters
- [ ] Public spend key is 64 hex characters
- [ ] Address hash is 64 hex characters
- [ ] No network request to `/api/unlock_seed`
- [ ] POST request to `/api/wallet/register` contains:
  ```json
  {
    "address": "4...",
    "view_key_pub": "hex...",
    "spend_key_pub": "hex...",
    "address_hash": "hex...",
    "signature": null
  }
  ```
- [ ] No `seed` field in request body
- [ ] Checkbox requires user to confirm backup
- [ ] "Register Wallet" button disabled until checkbox checked

❌ **Failure Indicators**:
- Any request to `/api/unlock_seed`
- Seed phrase in network request
- JavaScript console errors
- WASM load failures
- Address doesn't start with `4`
- Public keys aren't 64 hex characters

### 5. Security Validation

**Check CSP Headers**:
```bash
curl -I http://localhost:8080/wallet/setup | grep -i "content-security-policy"
```

Expected:
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline';
```

**Check WASM MIME Type**:
```bash
curl -I http://localhost:8080/static/wasm/wallet_wasm_bg.wasm | grep -i "content-type"
```

Expected:
```
Content-Type: application/wasm
```

## Automated Integration Test

```bash
#!/bin/bash
# Save as: wallet/wasm/integration_test.sh

set -e

echo "🧪 Running WASM Wallet Integration Test..."

# 1. Build WASM
echo "📦 Building WASM..."
cd /home/malix/Desktop/NEXUS/wallet/wasm
./build.sh > /dev/null 2>&1

# 2. Verify files exist
echo "🔍 Verifying output files..."
test -f ../../static/wasm/wallet_wasm.js || (echo "❌ wallet_wasm.js missing" && exit 1)
test -f ../../static/wasm/wallet_wasm_bg.wasm || (echo "❌ wallet_wasm_bg.wasm missing" && exit 1)

# 3. Check file sizes
echo "📏 Checking file sizes..."
JS_SIZE=$(stat -c%s ../../static/wasm/wallet_wasm.js)
WASM_SIZE=$(stat -c%s ../../static/wasm/wallet_wasm_bg.wasm)

if [ "$JS_SIZE" -lt 5000 ]; then
    echo "❌ JS file too small: $JS_SIZE bytes"
    exit 1
fi

if [ "$WASM_SIZE" -lt 50000 ]; then
    echo "❌ WASM file too small: $WASM_SIZE bytes"
    exit 1
fi

# 4. Run clippy
echo "🔧 Running clippy..."
cd /home/malix/Desktop/NEXUS
cargo clippy --package wallet_wasm -- -D warnings > /dev/null 2>&1 || (echo "❌ Clippy failed" && exit 1)

# 5. Verify workspace compiles
echo "🏗️  Checking workspace..."
cargo check --workspace > /dev/null 2>&1 || (echo "❌ Workspace check failed" && exit 1)

echo "✅ All tests passed!"
echo ""
echo "📊 Summary:"
echo "  - WASM size: $(numfmt --to=iec-i --suffix=B $WASM_SIZE)"
echo "  - JS size: $(numfmt --to=iec-i --suffix=B $JS_SIZE)"
echo "  - Files: $(ls -1 /home/malix/Desktop/NEXUS/static/wasm/wallet_wasm* | wc -l) files generated"
```

## Troubleshooting

### WASM Build Fails

**Error**: "Bulk memory operations require bulk memory"
**Fix**: `wasm-opt` disabled in `Cargo.toml`:
```toml
[package.metadata.wasm-pack.profile.release]
wasm-opt = false
```

### Clippy Errors

**Error**: "unused variable: `view_key_bytes`"
**Fix**: Variables are now used or prefixed with `_`

### Module Not Loading in Browser

**Check**:
1. DevTools Console for errors
2. Network tab shows WASM file loaded
3. CSP allows `wasm-unsafe-eval`
4. Server serves `.wasm` with correct MIME type

### Entropy Generation Fails

**Cause**: Browser doesn't support `crypto.getRandomValues()`
**Fix**: Upgrade browser or use HTTPS (required for crypto APIs)

## Performance Benchmarks

```bash
# Measure WASM generation time
node -e "
const fs = require('fs');
const { performance } = require('perf_hooks');

(async () => {
  const start = performance.now();
  const wasm = await import('./static/wasm/wallet_wasm.js');
  await wasm.default();

  for (let i = 0; i < 100; i++) {
    wasm.generate_wallet();
  }

  const end = performance.now();
  console.log(\`100 wallets generated in \${(end - start).toFixed(2)}ms\`);
  console.log(\`Average: \${((end - start) / 100).toFixed(2)}ms per wallet\`);
})();
"
```

Expected: **~8-10ms per wallet**

## Security Checklist

- [ ] WASM module builds without warnings
- [ ] No `unwrap()` or `expect()` in production code
- [ ] Sensitive data zeroized after use
- [ ] No `println!()` in production paths
- [ ] CSP headers properly configured
- [ ] HTTPS enforced in production
- [ ] No seed phrase in logs
- [ ] No seed phrase in network requests
- [ ] User warned about backup responsibility
- [ ] Checkbox confirmation required

## Deployment Checklist

- [ ] WASM module built in release mode
- [ ] All tests passing
- [ ] Documentation updated
- [ ] User education materials prepared
- [ ] Monitoring configured
- [ ] Rollback plan documented
- [ ] Security audit completed
- [ ] Staging environment tested
- [ ] Feature flag implemented (gradual rollout)
- [ ] Metrics collection enabled

## Success Criteria

✅ **Minimum Requirements**:
1. WASM module generates valid Monero addresses
2. No seed phrase sent to server
3. All tests pass (unit + manual)
4. Clippy clean
5. Documentation complete

✅ **Production Ready**:
1. All minimum requirements met
2. Security audit passed
3. User education deployed
4. Monitoring active
5. No critical bugs in staging

✅ **Rollout Complete**:
1. 100% of users using WASM generation
2. `unlock_seed` endpoint deprecated
3. Zero incidents related to wallet generation
4. User satisfaction ≥95%
