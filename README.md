# Onyx-Escrow

Non-custodial Monero escrow using FROST threshold signatures (RFC 9591).

## Overview

Onyx-Escrow implements 2-of-3 threshold escrow for Monero, where all signing
operations execute client-side in a WASM module. The server acts as a blind
relay: it coordinates signature rounds and holds a view key for transaction
monitoring, but it is mathematically unable to spend funds unilaterally.

The core protocol -- CMD (Commitment Mask Derivation) -- enables browser-native
FROST DKG and CLSAG threshold signing without requiring users to install
desktop software or run their own wallet RPC.

See [PROTOCOL.md](PROTOCOL.md) for the full cryptographic specification.

## Architecture

```
 Browser (WASM)                Relay Server               Monero Network
+-------------------+     +--------------------+     +------------------+
| onyx-crypto-core |     | server (Actix-web) |     | monerod          |
| - FROST DKG       | <-> | - REST API         | <-> | - mainnet/testnet|
| - CMD masks       |     | - FROST coord      |     |                  |
| - CLSAG signing   |     | - view key only    |     |                  |
+-------------------+     +--------------------+     +------------------+
   Client holds              Cannot spend.             Full node.
   spend key share.          Coordinates only.
```

**Key crates:**

| Crate | Purpose |
|-------|---------|
| `onyx-crypto-core` | FROST DKG, CMD protocol, Lagrange interpolation, CLSAG |
| `onyx-crypto-core/wasm` | WASM bindings for browser execution |
| `wallet` | Monero RPC client, multisig operations |
| `wallet/wasm` | WASM wallet bindings |
| `server` | Actix-web REST API, FROST coordinator, transaction builder |
| `common` | Shared types, error types, constants |

## Build

**Prerequisites:** Rust 1.75+, Linux, monerod (synced).

```bash
# Build all workspace members
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint (strict -- all warnings are errors)
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --workspace
```

Server release build:

```bash
cargo build --release --package server
```

WASM module:

```bash
cd wallet/wasm
wasm-pack build --target web --release
```

## Configuration

Copy `.env.example` and fill in the required values:

```bash
cp .env.example .env
```

Required variables:

| Variable | Description |
|----------|-------------|
| `MONERO_NETWORK` | `mainnet` or `testnet` |
| `MONERO_DAEMON_URL` | URL of your monerod instance (default `http://127.0.0.1:18081`) |
| `PLATFORM_FEE_WALLET` | Mainnet address starting with `4`, validated on startup |
| `DB_ENCRYPTION_KEY` | 64 hex chars, e.g. from `openssl rand -hex 32` |
| `SESSION_SECRET_KEY` | 64 bytes base64, e.g. from `openssl rand -base64 48 \| head -c 64` |
| `WALLET_ENCRYPTION_PASSWORD` | 32+ chars for wallet file encryption |

The server validates all critical configuration on startup and will refuse to
start if address checksums, network matching, or encryption keys are invalid.

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for the complete cryptographic specification
covering:

- FROST Distributed Key Generation (DKG) per RFC 9591
- CMD (Commitment Mask Derivation) for view-key-derived masks
- CLSAG threshold signing flow
- Escrow lifecycle: creation, funding, release, dispute, refund
- Threat model and security proofs

## SDK

Client libraries for integrating Onyx-Escrow into third-party applications:

| SDK | Package | Install |
|-----|---------|---------|
| JavaScript/TypeScript | `packages/onyx-sdk-js` | `npm install @onyx-escrow/sdk` |
| Python | `packages/onyx-sdk-python` | `pip install onyx-escrow` |

Both SDKs provide typed wrappers around the REST API for escrow creation,
status polling, webhook verification, and dispute management.

## Security

**Non-custodial by design.** The server holds a shared view key for payment
detection but zero signing shares. It cannot produce a valid signature.
Spending requires cooperation of at least two of the three parties (buyer,
vendor, arbiter). This is not a policy decision -- it is a mathematical
constraint of the FROST threshold scheme (RFC 9591).

- All signing operations execute client-side in WASM
- Signing data relayed via X25519 + ChaCha20-Poly1305 encrypted channels
- Address validation with full Base58-Monero checksum verification before any transfer
- Wallet RPC bound to 127.0.0.1 only; public binding is blocked at the code level
- No sensitive data (keys, addresses, passwords) written to logs

**Responsible disclosure:** security@onyx-escrow.io

## License

MIT. See [LICENSE](LICENSE).

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure all checks pass:
   ```bash
   cargo fmt --workspace -- --check
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
4. Open a pull request against `main`

All PRs must pass the full CI pipeline before merge.
