# nexus-crypto-core

[![Crates.io](https://img.shields.io/crates/v/nexus-crypto-core.svg)](https://crates.io/crates/nexus-crypto-core)
[![Documentation](https://docs.rs/nexus-crypto-core/badge.svg)](https://docs.rs/nexus-crypto-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Core cryptographic library for NEXUS Escrow-as-a-Service (EaaS).**

Provides production-ready cryptographic primitives for non-custodial Monero escrow, including FROST threshold signatures, key image generation, and CLSAG verification.

## Features

- **FROST DKG (RFC 9591)** — Distributed Key Generation for 2-of-3 threshold signatures
- **Key Image Generation** — Partial and aggregated key images for spend detection
- **CLSAG Verification** — Linkable ring signature verification matching Monero
- **MuSig2-style Nonces** — Commitment-based nonce aggregation for secure signing
- **Address Validation** — Full Monero address checksum verification (mainnet/stagenet/testnet)
- **Encrypted Relay** — X25519 ECDH + ChaCha20Poly1305 for secure data transport

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
nexus-crypto-core = "0.1"
```

### Generate FROST Key Shares (2-of-3 Multisig)

```rust
use nexus_crypto_core::{dkg_part1, dkg_part2, dkg_part3, extract_secret_share};

// Each participant runs DKG Part 1
let (round1_result_buyer, _) = dkg_part1(1, 2, 3)?;   // Participant 1 (Buyer)
let (round1_result_seller, _) = dkg_part2(2, 2, 3)?;  // Participant 2 (Seller)
let (round1_result_arbiter, _) = dkg_part1(3, 2, 3)?; // Participant 3 (Arbiter)

// Exchange Round 1 packages...
// Each participant completes Round 2 and Round 3 with received packages

// Final result contains group public key and individual key package
let final_result = dkg_part3(
    round2_packages,
    round1_packages,
    round1_secret,
)?;

// Extract secret share for signing
let secret_share = extract_secret_share(&final_result.key_package)?;
```

### Compute Partial Key Images

```rust
use nexus_crypto_core::{compute_partial_key_image, aggregate_partial_key_images};

// Each signer computes their partial key image
let partial_ki_buyer = compute_partial_key_image(
    &buyer_secret_share,
    &output_public_key,
)?;

let partial_ki_seller = compute_partial_key_image(
    &seller_secret_share,
    &output_public_key,
)?;

// Aggregate partial key images (any 2 of 3)
let full_key_image = aggregate_partial_key_images(&[
    partial_ki_buyer.partial_key_image,
    partial_ki_seller.partial_key_image,
])?;
```

### Validate Monero Address

```rust
use nexus_crypto_core::keys::{validate_address_for_network, MoneroNetwork};

// Validate mainnet address
let result = validate_address_for_network(
    "4...",  // 95-character Monero address
    MoneroNetwork::Mainnet,
)?;

assert!(result.is_valid);
println!("Spend pubkey: {}", result.spend_public_key);
println!("View pubkey: {}", result.view_public_key);
```

### Encrypt Data for Relay

```rust
use nexus_crypto_core::{
    generate_ephemeral_keypair, derive_shared_key, encrypt_data, decrypt_data
};

// Sender generates ephemeral keypair
let sender_keypair = generate_ephemeral_keypair()?;

// Derive shared key with recipient's public key
let shared_key = derive_shared_key(
    &sender_keypair.secret_key,
    &recipient_public_key,
)?;

// Encrypt data
let encrypted = encrypt_data(&shared_key, &plaintext_data)?;

// Recipient decrypts with their secret key
let decrypted = decrypt_data(&shared_key, &encrypted.ciphertext, &encrypted.nonce)?;
```

## Module Reference

### `frost` — FROST Threshold Signatures (RFC 9591)

Implements Flexible Round-Optimized Schnorr Threshold signatures for 2-of-3 multisig.

| Function | Description |
|----------|-------------|
| `dkg_part1()` | Generate Round 1 commitment package |
| `dkg_part2()` | Compute secret shares from Round 1 packages |
| `dkg_part3()` | Finalize DKG and produce KeyPackage |
| `extract_secret_share()` | Extract scalar secret for signing |
| `compute_lagrange_coefficient()` | Compute λ_i for threshold reconstruction |

### `keys` — Key Derivation & Validation

Address validation and key image generation for Monero.

| Function | Description |
|----------|-------------|
| `validate_address()` | Full address checksum validation |
| `validate_address_for_network()` | Network-specific validation |
| `quick_network_check()` | Fast prefix check (mainnet='4', stagenet='5') |
| `extract_public_keys()` | Decode address to (spend_pub, view_pub) |
| `is_subaddress()` | Check if address is subaddress |
| `compute_key_image()` | Generate full key image KI = x·Hp(P) |
| `compute_partial_key_image()` | Generate partial KI for threshold signing |
| `aggregate_partial_key_images()` | Combine partial KIs into full KI |

### `nonce` — MuSig2-style Nonce Commitments

Secure nonce handling for threshold signatures.

| Function | Description |
|----------|-------------|
| `generate_nonce_commitment()` | Generate R, R_hash, binding factor |
| `compute_nonce_commitment_hash()` | Keccak256(R) for commitment |
| `verify_nonce_commitment()` | Verify R matches committed hash |
| `aggregate_nonces()` | Combine nonces: R = R₁ + R₂ |
| `verify_nonce_aggregation()` | Verify aggregated nonce is correct |

### `clsag` — Ring Signature Verification

CLSAG (Compact Linkable Spontaneous Anonymous Group) signature verification.

| Function | Description |
|----------|-------------|
| `verify_clsag()` | Full CLSAG verification |
| `compute_mixing_coefficients()` | Compute μ_P, μ_C coefficients |
| `compute_round_hash()` | Hash round values (c_i computation) |

### `encryption` — Secure Data Transport

X25519 ECDH key exchange with ChaCha20Poly1305 AEAD encryption.

| Function | Description |
|----------|-------------|
| `generate_ephemeral_keypair()` | Generate X25519 keypair |
| `derive_shared_key()` | ECDH shared secret derivation |
| `encrypt_data()` | ChaCha20Poly1305 encryption |
| `decrypt_data()` | ChaCha20Poly1305 decryption |

### `cmd` — Output Identification

View-key-based output identification for Monero transactions.

| Function | Description |
|----------|-------------|
| `derive_commitment_mask()` | Derive mask for output commitment |
| `find_our_output_and_derive_mask()` | Identify owned outputs in transaction |
| `decode_encrypted_amount()` | Decode ecdhInfo encrypted amount |
| `extract_tx_pub_key_from_extra()` | Parse tx_pub_key from tx extra field |

## Build Instructions

### Standard Build

```bash
cargo build --release
```

### WASM Build

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for web
wasm-pack build --target web --features wasm
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `std` (default) | Standard library support |
| `wasm` | WebAssembly support with wasm-bindgen |
| `test-helpers` | Deterministic functions for testing |

### Run Tests

```bash
# All tests
cargo test

# With verbose output
cargo test -- --nocapture

# Specific module
cargo test frost::
cargo test keys::
```

## Security Considerations

This crate handles cryptographic secrets. Follow these guidelines:

1. **Never log secrets** — No `println!` or `tracing::info!` for secret keys
2. **Use zeroize** — All sensitive types implement `Zeroize` and `ZeroizeOnDrop`
3. **Constant-time operations** — Uses `subtle` crate for timing-safe comparisons
4. **Memory protection** — Consider OS-level memory locking for production

### Audit Status

- [ ] Internal code review
- [ ] External audit (planned Q2 2026)
- [ ] Formal verification (roadmap)

## Architecture

```
nexus-crypto-core/
├── src/
│   ├── lib.rs          # Crate root and re-exports
│   ├── types/          # Core types and errors
│   │   ├── address.rs  # MoneroNetwork, AddressType
│   │   ├── escrow.rs   # EscrowRole, SigningPair
│   │   ├── transaction.rs  # KeyImage, ClsagSignature
│   │   └── errors.rs   # CryptoError, CryptoResult
│   ├── frost/          # FROST DKG (RFC 9591)
│   │   ├── dkg.rs      # dkg_part1/2/3
│   │   ├── lagrange.rs # Coefficient computation
│   │   └── types.rs    # DkgRound1Result, etc.
│   ├── keys/           # Key operations
│   │   ├── validate.rs # Address validation
│   │   ├── derive.rs   # Key derivation
│   │   └── image.rs    # Key image generation
│   ├── cmd/            # Output identification
│   │   ├── derivation.rs
│   │   └── masks.rs
│   ├── nonce/          # Nonce commitments
│   │   ├── generate.rs
│   │   └── aggregate.rs
│   ├── clsag/          # Ring signatures
│   │   ├── verify.rs
│   │   └── hash.rs
│   └── encryption/     # AEAD encryption
│       ├── ecdh.rs
│       └── symmetric.rs
└── Cargo.toml
```

## Minimum Supported Rust Version

MSRV: **1.70.0**

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome. Please:

1. Run `cargo fmt` and `cargo clippy` before submitting
2. Add tests for new functionality
3. Update documentation for public API changes
4. Sign commits with GPG

## Related Projects

- [NEXUS Escrow](https://github.com/nexus-escrow/nexus) — Full escrow platform
- [monero-rs](https://github.com/monero-rs/monero-rs) — Monero library for Rust
- [frost-ed25519](https://docs.rs/frost-ed25519) — FROST implementation
