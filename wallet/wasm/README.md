# Client-Side Wallet Generation (WASM)

## Overview

This WebAssembly module provides **true client-side Monero wallet generation** for the Web UI, implementing Zero Trust architecture where the server **never sees the private seed**.

## Security Model

### Before (Custodial)
```
Browser → POST /api/unlock_seed → Server generates seed → Returns seed to browser
❌ Server has access to private seed momentarily
```

### After (Zero Trust)
```
Browser WASM → Generate seed locally → POST /api/wallet/register (public keys only)
✅ Server NEVER sees private seed
```

## Architecture

```
User clicks "Generate Wallet"
  ↓
WASM: getrandom() → crypto.getRandomValues() [16 bytes entropy]
  ↓
WASM: BIP39 mnemonic (12 words)
  ↓
WASM: Derive Monero keys (curve25519-dalek)
  ↓
WASM: Generate Monero address (Base58 + Keccak256 checksum)
  ↓
Browser: Display seed to user (MUST BACKUP!)
  ↓
Browser: POST /api/wallet/register { address, view_key_pub, spend_key_pub, address_hash }
  ↓
Server: Store public keys only
```

## Build Instructions

### Prerequisites
```bash
# Install wasm-pack (if not already installed)
cargo install wasm-pack
```

### Build WASM Module
```bash
cd wallet/wasm
wasm-pack build --target web --out-dir ../../static/wasm
```

Output files in `static/wasm/`:
- `wallet_wasm.js` - JavaScript glue code
- `wallet_wasm_bg.wasm` - WebAssembly binary
- `wallet_wasm.d.ts` - TypeScript definitions

### Development Workflow
```bash
# Make changes to src/lib.rs
vim src/lib.rs

# Rebuild WASM
wasm-pack build --target web --out-dir ../../static/wasm

# Run clippy
cargo clippy -- -D warnings

# Run tests (requires browser)
wasm-pack test --headless --firefox
```

## Usage

### Frontend Integration

```javascript
// Import WASM module
import { initWasm, generateWallet } from './wasm-loader.js';

// Initialize WASM
await initWasm();

// Generate wallet
const wallet = await generateWallet();

// wallet = {
//   seed: "word1 word2 ... word12",
//   address: "4...",
//   viewKeyPub: "hex...",
//   spendKeyPub: "hex...",
//   addressHash: "hex..."
// }

// Display seed to user for backup
displaySeed(wallet.seed);

// Register with server (PUBLIC DATA ONLY)
await fetch('/api/wallet/register', {
    method: 'POST',
    body: JSON.stringify({
        address: wallet.address,
        view_key_pub: wallet.viewKeyPub,
        spend_key_pub: wallet.spendKeyPub,
        address_hash: wallet.addressHash,
        signature: null  // Optional for Phase 1
    })
});
```

## Cryptographic Implementation

### Key Derivation

1. **Entropy Generation** (128 bits)
   ```
   getrandom() → [u8; 16]
   ```

2. **BIP39 Mnemonic** (12 words)
   ```
   Mnemonic::from_entropy(entropy) → "word1 word2 ... word12"
   ```

3. **Spend Key Derivation**
   ```
   entropy_extended = SHA256(entropy || "monero_spend_key")
   spend_scalar = Scalar::from_bytes_mod_order(entropy_extended)
   spend_pub = spend_scalar * G (Ed25519 base point)
   ```

4. **View Key Derivation** (Monero standard)
   ```
   view_key_hash = Keccak256(spend_scalar.to_bytes())
   view_scalar = Scalar::from_bytes_mod_order(view_key_hash)
   view_pub = view_scalar * G
   ```

5. **Address Generation** (Monero standard)
   ```
   address_data = network_byte || spend_pub || view_pub
   checksum = Keccak256(address_data)[0..4]
   address = Base58(address_data || checksum)
   ```

### Security Features

- **Secure Entropy**: `getrandom` with `js` feature → `crypto.getRandomValues()`
- **Memory Zeroization**: Sensitive data cleared with `zeroize` crate
- **No Server Trust**: Private keys never leave browser
- **Standard Compliance**: Monero address format matches official implementation

## Testing

### Unit Tests (Headless Browser)
```bash
cd wallet/wasm
wasm-pack test --headless --firefox
```

Tests verify:
- ✅ Seed format (12 words)
- ✅ Address format (starts with '4' for mainnet)
- ✅ Public key lengths (64 hex chars)
- ✅ Address hash consistency (SHA256)
- ✅ Uniqueness (two generations produce different wallets)

### Manual Testing

1. **Open Wallet Setup Page**
   ```
   http://localhost:8080/wallet/setup
   ```

2. **Open Browser DevTools** (Network tab)

3. **Click "Generate Wallet"**

4. **Verify**:
   - ❌ No request to `/api/unlock_seed`
   - ✅ 12-word seed displayed in UI
   - ✅ POST `/api/wallet/register` with public keys only
   - ✅ Wallet created in database

## Dependencies

```toml
wasm-bindgen = "0.2"          # Rust-JS bindings
getrandom = "0.2" (js)        # Secure random (crypto.getRandomValues)
curve25519-dalek = "4.1"      # Ed25519 curve operations
bip39 = "2.0"                 # BIP39 mnemonic generation
sha2 = "0.10"                 # SHA256 hashing
sha3 = "0.10"                 # Keccak256 hashing (Monero standard)
hex = "0.4"                   # Hex encoding
zeroize = "1.7"               # Secure memory clearing
base58-monero = "2.0"         # Monero Base58 encoding
serde = "1.0"                 # Serialization
serde-wasm-bindgen = "0.6"    # Rust ↔ JS serialization
```

## File Structure

```
wallet/wasm/
├── Cargo.toml               # Crate manifest
├── src/
│   └── lib.rs              # Wallet generation logic (230 lines)
└── README.md               # This file

static/
├── js/
│   ├── wasm-loader.js      # WASM initialization
│   └── wallet-setup.js     # UI handler
└── wasm/                   # Build output (generated)
    ├── wallet_wasm.js
    ├── wallet_wasm_bg.wasm
    └── wallet_wasm.d.ts

templates/wallet/
└── wallet-setup.html       # User interface
```

## Limitations & Future Work

### Current Limitations

1. **Mainnet Only**: Hardcoded to mainnet (network byte 18)
   - TODO: Add network selection (testnet/stagenet)

2. **No Seed Recovery**: If user loses seed, funds are unrecoverable
   - This is intentional for Zero Trust model
   - User MUST backup seed phrase

3. **No Signature**: `signature` field is `null` for Phase 1
   - TODO: Sign address hash with spend key for verification

### Future Enhancements

- [ ] Network selection (mainnet/testnet/stagenet)
- [ ] Seed phrase verification UI (re-enter words)
- [ ] QR code export for seed backup
- [ ] Hardware wallet integration (Ledger/Trezor)
- [ ] Mnemonic passphrase (BIP39 extension)
- [ ] Address signature for server verification

## Troubleshooting

### Build Fails: "Bulk memory operations require bulk memory"

**Solution**: Disable wasm-opt
```toml
[package.metadata.wasm-pack.profile.release]
wasm-opt = false
```

### WASM Module Not Loading in Browser

**Check**:
1. CSP header allows `wasm-unsafe-eval`
2. WASM files exist in `/static/wasm/`
3. Server serves `.wasm` with correct MIME type (`application/wasm`)

### Entropy Source Fails in Browser

**Check**:
1. Browser supports `crypto.getRandomValues()`
2. Page served over HTTPS (localhost OK for development)
3. `getrandom` crate has `js` feature enabled

## Security Considerations

### ✅ What This Protects Against

- **Server Compromise**: Server breach does NOT expose private seeds
- **Man-in-the-Middle**: HTTPS ensures seed never transmitted
- **Database Leak**: Only public keys stored in database

### ⚠️ What This Does NOT Protect Against

- **Client Malware**: If user's browser is compromised, seed can be stolen
- **Phishing**: User may enter seed into fake website
- **Social Engineering**: User may backup seed insecurely

### Best Practices

1. **HTTPS Only**: Never serve wallet generation over HTTP
2. **CSP Headers**: Strict Content-Security-Policy to prevent XSS
3. **User Education**: Emphasize seed backup importance
4. **No Screenshots**: Warn users against screenshotting seed
5. **Offline Backup**: Recommend writing seed on paper, not digital storage

## License

MIT (same as parent project)

## References

- [Monero Address Format](https://monerodocs.org/cryptography/address/)
- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [wasm-bindgen Guide](https://rustwasm.github.io/docs/wasm-bindgen/)
- [Curve25519 Dalek](https://docs.rs/curve25519-dalek/)
