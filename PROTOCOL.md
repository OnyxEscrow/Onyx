# Onyx-Escrow Protocol Specification

FROST Threshold Escrow for Monero

**Version:** 1.0.0
**Status:** Implementation Reference
**Last Updated:** 2026-02-09

---

## 1. Notation

| Symbol | Description |
|--------|-------------|
| `G` | Ed25519 basepoint |
| `H` | Pedersen commitment generator (Monero-specific, NOT `Hp(G)`) |
| `Hs(x)` | `Keccak256(x)` reduced to scalar mod `l` |
| `Hp(P)` | Hash-to-point (`ge_fromfe_frombytes_vartime`) |
| `a` | View private key (scalar) |
| `b_i` | Participant `i`'s signing share (scalar) |
| `B` | Group public spend key (point, `GroupVerifyingKey`) |
| `R` | Transaction public key (point, from `tx_extra`) |
| `l` | Ed25519 group order `2^252 + 27742317777372353535851937790883648493` |
| `varint(n)` | Monero variable-length integer encoding |
| `\|\|` | Byte concatenation |

---

## 2. Architecture

Onyx-Escrow provides non-custodial 2-of-3 threshold escrow for Monero. Three parties participate:

| Role | Index | Description |
|------|-------|-------------|
| Buyer | 1 | Funds the escrow, releases on receipt of goods |
| Vendor | 2 | Receives funds upon buyer confirmation or dispute resolution |
| Arbiter | 3 | Resolves disputes; does not participate in normal flow |

Any 2 of the 3 parties can authorize fund release. No single party — including the relay server — can spend unilaterally.

### Execution Boundary

All private key operations execute client-side in WebAssembly (WASM). The server functions as a **blind relay**: it stores and forwards public data between participants but never holds signing shares or private spend keys.

```
 Buyer Browser          Relay Server          Vendor Browser
 ┌──────────┐          ┌──────────┐          ┌──────────┐
 │  WASM    │◄────────►│  REST    │◄────────►│  WASM    │
 │  Engine  │  public  │  API     │  public  │  Engine  │
 │          │  data    │          │  data    │          │
 │ [b_1]    │  only    │ [view    │  only    │ [b_2]    │
 │ secret   │          │  key a]  │          │ secret   │
 └──────────┘          └────┬─────┘          └──────────┘
                            │
                     ┌──────▼──────┐
                     │   monerod   │
                     │  (mainnet)  │
                     └─────────────┘
```

The relay holds the shared view key `a` (derived deterministically; see Section 4) to detect incoming payments. Possession of `a` alone is insufficient to spend — a valid CLSAG signature requires at least 2 signing shares.

---

## 3. FROST Distributed Key Generation (RFC 9591)

Key generation follows the three-round DKG protocol defined in RFC 9591, instantiated over Ed25519 via `frost-ed25519`.

### 3.1 Round 1 — Commitment

Each participant `i` generates a commitment polynomial of degree `t-1 = 1`:

```
(round1_package_i, round1_secret_i) = frost_ed25519::keys::dkg::part1(
    identifier_i,
    max_signers = 3,
    min_signers = 2,
    rng
)
```

- `round1_package_i` is broadcast to all participants (relayed by server).
- `round1_secret_i` is retained locally and encrypted at rest.
- The server sees `round1_package_i` but cannot derive any private share from it.

### 3.2 Round 2 — Share Distribution

Each participant computes per-recipient secret shares:

```
(round2_packages_i, round2_secret_i) = frost_ed25519::keys::dkg::part2(
    round1_secret_i,
    {round1_package_1, round1_package_2, round1_package_3}
)
```

- `round2_packages_i` is a map: one encrypted share per recipient.
- Each participant receives only their own share from each other participant.
- The server relays these shares but cannot decrypt them (they are point evaluations of the commitment polynomial, not raw secrets).

### 3.3 Round 3 — Key Package Finalization

Each participant finalizes their key package:

```
(key_package_i, group_pubkey, verifying_share_i) = frost_ed25519::keys::dkg::part3(
    round2_secret_i,
    {round1_package_1, round1_package_2, round1_package_3},
    {round2_package_from_j, round2_package_from_k}    // j,k ≠ i
)
```

**Outputs:**

| Output | Visibility | Description |
|--------|------------|-------------|
| `key_package_i` | Private (client `i` only) | Contains `SigningShare b_i` |
| `group_pubkey` | Public (identical for all) | `GroupVerifyingKey B` — becomes the spend key |
| `verifying_share_i` | Public | `b_i * G` — verifiable without revealing `b_i` |

**Invariant:** All three participants must derive the same `group_pubkey`. The client verifies this before proceeding.

### 3.4 Server Knowledge After DKG

The server observes:
- Round 1 packages (public commitments)
- Round 2 packages (encrypted polynomial evaluations routed between participants)
- `group_pubkey B` (public)
- `verifying_share_i` for each participant (public)

The server **cannot** reconstruct any `SigningShare b_i`. Shamir's Secret Sharing guarantees that `t = 2` shares are required for reconstruction; the server holds zero shares.

---

## 4. Multisig Address Derivation

After DKG, all participants independently derive a deterministic Monero address.

### 4.1 Shared View Key

```
view_priv = Hs("frost_escrow_view_key" || escrow_id || B.compress())
view_pub  = view_priv * G
```

- `escrow_id`: UTF-8 encoded session identifier
- `B.compress()`: 32-byte compressed group public key
- Domain separator `"frost_escrow_view_key"` prevents cross-context collisions

All three participants compute the same `view_priv` from public inputs. This shared view key is communicated to the relay server to enable payment detection.

### 4.2 Address Construction

```
address = base58_monero(network_byte || B.compress() || view_pub.compress() || checksum)
```

- `network_byte`: `0x12` (mainnet), `0x35` (testnet), `0x18` (stagenet)
- `checksum`: first 4 bytes of `Keccak256(network_byte || B || view_pub)`

The resulting address is a standard Monero address. Senders cannot distinguish it from a single-signer address.

---

## 5. Commitment Mask Derivation (CMD)

CMD enables the relay server to detect incoming payments and derive the commitment mask required for CLSAG signing — using only the shared view key, without any spend key.

### 5.1 ECDH Derivation

```
derivation = 8 * a * R
```

- `a`: view private key (scalar)
- `R`: transaction public key from `tx_extra`
- Cofactor `8` applied via `mul_by_cofactor()` per Monero convention

### 5.2 Output-Specific Shared Secret

```
shared_secret = Hs(derivation.compress() || varint(output_index))
```

- `derivation.compress()`: 32-byte compressed Edwards point
- `output_index`: zero-indexed, **varint encoded** (not fixed-width)

### 5.3 Commitment Mask

```
mask = Hs("commitment_mask" || shared_secret)
```

- Domain separator: literal bytes `"commitment_mask"` (15 bytes)
- Result: scalar mod `l`

### 5.4 Output Ownership Verification

To identify which transaction output belongs to the escrow address:

```
P_expected = Hs(derivation.compress() || varint(i)) * G + B
```

For each output index `i`, compare `P_expected` with the on-chain one-time output key. A match identifies the escrow's output.

**View tag optimization:** The first byte of `shared_secret` serves as a view tag for fast rejection of non-matching outputs, avoiding full point computation for most ring members.

### 5.5 Non-Custodial Property

The relay server derives `mask` from the view key. This value is needed to construct the pseudo-output commitment during signing, but it does **not** enable spending. Spending requires a valid CLSAG signature, which requires at least 2 signing shares `b_i`. The server holds zero signing shares.

---

## 6. CLSAG Threshold Signing

Fund release uses Monero's CLSAG ring signature scheme, adapted for 2-of-3 threshold signing with a sequential (round-robin) protocol.

### 6.1 Lagrange Coefficients

For 2-of-3 with participating signers `{i, j}`:

```
lambda_i = j / (j - i)    (mod l)
```

Precomputed values:

| Signers | lambda_1 | lambda_2 | lambda_3 |
|---------|----------|----------|----------|
| {1, 2} | 2 | -1 (mod l) | -- |
| {1, 3} | 3/2 (mod l) | -- | -1/2 (mod l) |
| {2, 3} | -- | 3 | -2 (mod l) |

These coefficients satisfy `lambda_i + lambda_j = 1` at evaluation point `x = 0`, enabling Lagrange interpolation of the group secret.

### 6.2 Key Image

The key image prevents double-spending:

```
d = Hs(derivation.compress() || varint(output_index))
x_total = d + lambda_i * b_i + lambda_j * b_j
P = d * G + B                   // one-time output public key
I = x_total * Hp(P)             // key image
```

Each signer computes their partial key image independently:

```
pKI_i = lambda_i * b_i * Hp(P)
```

The relay aggregates:

```
I = pKI_i + pKI_j + d * Hp(P)
```

where `d` is the output derivation scalar, computable from the view key.

### 6.3 CLSAG Structure

A CLSAG signature over a ring of size `n = 16` consists of:

| Field | Size | Description |
|-------|------|-------------|
| `D` | 32 bytes | Commitment linking point |
| `s[0..15]` | 16 x 32 bytes | Response scalars |
| `c_1` | 32 bytes | Initial challenge |

**Auxiliary point D:**

```
mask_delta = z_input - z_pseudo_out
D = mask_delta * Hp(P_real) * 8^(-1)
```

- `z_input`: commitment mask of the real input (derived via CMD)
- `z_pseudo_out`: mask of the pseudo-output commitment
- `8^(-1)`: multiplicative inverse of cofactor mod `l`

**Mixing coefficients:**

```
mu_P = Hs("CLSAG_agg_0\x00..." || P[0..n] || C[0..n] || I || D*8^(-1) || pseudo_out)
mu_C = Hs("CLSAG_agg_1\x00..." || P[0..n] || C[0..n] || I || D*8^(-1) || pseudo_out)
```

Domain tags are null-padded to 32 bytes.

### 6.4 Round-Robin Signing Protocol

Parallel CLSAG aggregation is incorrect for threshold signing due to nonce double-counting. Onyx-Escrow uses a sequential round-robin protocol:

**Step 1: Signer 1 creates partial signature**

Signer 1 (WASM, client-side):
1. Samples random nonce `alpha`
2. Computes all `s[j]` for decoy indices `j != l` (where `l` is the real index)
3. Computes partial `s[l]` incorporating their weighted share `lambda_1 * b_1`
4. Encrypts `{alpha, partial_s_l, c_1, D, ...}` for Signer 2 (see Section 6.5)
5. Submits encrypted blob to relay

**Step 2: Signer 2 completes signature**

Signer 2 (WASM, client-side):
1. Decrypts Signer 1's partial data
2. Recovers `alpha` and `partial_s_l`
3. Adds their weighted share: `s[l] = partial_s_l + alpha - c_l * lambda_2 * b_2`
4. Returns completed `{s[0..15], c_1, D}` — a valid CLSAG signature

The relay broadcasts the resulting transaction via `sendrawtransaction`.

### 6.5 Encrypted Relay (E2E Signing Channel)

Partial signature data is encrypted end-to-end between the two signing parties. The relay handles only opaque ciphertext.

**Key exchange:** X25519 ECDH

```
shared_secret = X25519(signer1_private, signer2_public)
symmetric_key = SHA3-256(shared_secret)
```

**Encryption:** ChaCha20-Poly1305 (AEAD)

```
nonce = random(12 bytes)
ciphertext = ChaCha20Poly1305.encrypt(symmetric_key, nonce, partial_sig_json)
```

Each signing session uses ephemeral X25519 keypairs generated in WASM, providing forward secrecy.

### 6.6 Verification Equations

For completeness, the CLSAG verification equations (checked by monerod before accepting the transaction):

```
L[j] = s[j] * G + (mu_P * c_j) * P[j] + (mu_C * c_j) * (C[j] - pseudo_out)
R[j] = s[j] * Hp(P[j]) + (mu_P * c_j) * I + (mu_C * c_j) * D
c_{j+1} = Hs("CLSAG_round\x00..." || ... || L[j] || R[j])
```

Ring indices are processed in order `l+1, l+2, ..., n-1, 0, 1, ..., l` (real index last). The signature is valid iff the final computed `c_1` matches the stored `c_1`.

---

## 7. Transaction Construction

Onyx-Escrow constructs standard Monero transactions (RCT type 6, BulletproofPlus).

### 7.1 Format

```
TX {
    version: 2
    unlock_time: 0
    vin:  [TxinToKey { key_image, key_offsets }]
    vout: [TxOut { amount: 0, tagged_key { key, view_tag } }]
    extra: [tx_pubkey]
    rct_signatures: {
        type: 6 (RCTTypeBulletproofPlus)
        txnFee: varint
        ecdhInfo: [8 bytes per output]
        outPk: [32 bytes per output]
        prunable: {
            bulletproofPlus: [range_proof]
            CLSAGs: [clsag_signature]
            pseudo_outs: [32 bytes per input]
        }
    }
}
```

### 7.2 Transaction Hash

The transaction hash is computed as:

```
tx_hash = Keccak256(tx_prefix_hash || rct_base_hash || rct_prunable_hash)
```

This is a three-part hash, **not** `Keccak256(full_serialized_tx)`.

### 7.3 Ring Selection

Decoy outputs are selected using a gamma distribution matching Monero's wallet2 implementation:

- Ring size: 16 (15 decoys + 1 real input)
- Distribution shape matches empirical transaction patterns
- Outputs fetched via `get_outs` RPC from monerod

### 7.4 Fee Splitting

The platform fee is applied at the application layer before transaction construction:

```
vendor_amount = escrow_amount - platform_fee
platform_fee  = escrow_amount * fee_bps / 10000
```

The transaction has two outputs: one to the vendor (or buyer in refund case), one to the platform fee address.

---

## 8. Escrow Lifecycle

```
                          ┌─────────────────────────┐
                          │   pending_counterparty   │
                          └───────────┬─────────────┘
                                      │ counterparty joins
                          ┌───────────▼─────────────┐
                          │      DKG (3 rounds)      │
                          └───────────┬─────────────┘
                                      │ group key established
                          ┌───────────▼─────────────┐
                          │    pending_funding       │
                          └───────────┬─────────────┘
                               ┌──────┤
                               │      │ funded
                    underfunded│  ┌───▼──────────┐
                               │  │    active     │
                               │  └──┬────┬──────┘
                               │     │    │
                               │ ship│    │dispute
                          ┌────▼──┐  │  ┌─▼───────────┐
                          │grace  │  │  │   dispute    │
                          │period │  │  └──┬───────────┘
                          └───┬───┘  │     │ resolved
                              │      │  ┌──▼───────────┐
                         cancel│     │  │  resolved     │
                              │      │  └──────────────┘
                              │  ┌───▼──────────────┐
                              │  │ release_signing   │
                              │  └───────┬──────────┘
                              │          │ tx broadcast
                              │  ┌───────▼──────────┐
                              └──│    completed      │
                                 └──────────────────┘
```

**Normal flow:** `pending_counterparty` -> DKG -> `pending_funding` -> `active` -> `release_signing` -> `completed`

**Dispute flow:** `active` -> `dispute` -> arbiter resolves -> `release_signing` -> `completed`

**Timeout flow:** `pending_funding` -> `underfunded` -> `grace_period` (48h) -> `cancelled_recoverable`

**Shipping (optional):** `active` -> `shipped` -> buyer confirms -> `release_signing`. If buyer does not confirm within the deadline, an auto-release is triggered.

---

## 9. Security Properties

### 9.1 Non-Custodial Guarantee

The relay server holds:
- Shared view key `a` (derived from public inputs)
- Public group key `B`
- Public verifying shares `b_i * G`

The relay server does **not** hold:
- Any signing share `b_i`
- Any ephemeral signing nonces
- Any partial signature plaintext (encrypted in transit)

**Consequence:** The server cannot construct a valid CLSAG signature. Even if the server is fully compromised, funds remain safe — an attacker would still need to compromise at least 2 of the 3 client-side key stores.

### 9.2 Threshold Security

FROST (RFC 9591) provides `(t, n)` threshold security with `t = 2, n = 3`:
- Any 2 participants can reconstruct a valid signature
- Any 1 participant alone cannot
- No trusted dealer is involved (DKG is decentralized)

### 9.3 Forward Secrecy

Each signing session uses ephemeral X25519 keypairs for the encrypted relay channel. Compromise of long-term signing shares does not reveal the content of past encrypted relay messages.

### 9.4 Replay Protection

Monero's key image mechanism (`I = x * Hp(P)`) ensures each output can be spent exactly once. The network rejects transactions with duplicate key images.

### 9.5 View Key Scope

The shared view key enables:
- Detecting incoming payments
- Deriving commitment masks for signing
- Confirming transaction amounts

The shared view key does **not** enable:
- Spending funds
- Deriving spend keys (Hs is a one-way function)
- Identifying the sender of a payment

---

## 10. Dependencies and Standards

| Component | Library | Version | Standard |
|-----------|---------|---------|----------|
| Threshold DKG | `frost-ed25519` (ZcashFoundation) | 2.1.0+ | RFC 9591 |
| Elliptic curves | `curve25519-dalek` | 4.1 | RFC 8032 |
| Key exchange | `x25519-dalek` | 2.0 | RFC 7748 |
| AEAD encryption | `chacha20poly1305` | 0.10 | RFC 8439 |
| Hash functions | `sha3` (Keccak256) | 0.10 | FIPS 202 |
| Monero generators | `monero-serai` | 0.4+ | CryptoNote (Cuprate-compatible) |
| WASM target | `wasm-bindgen` | 0.2 | W3C WebAssembly |

The WASM module compiles to `wasm32-unknown-unknown` with `opt-level = "z"` and LTO enabled. Randomness is sourced from `crypto.getRandomValues()` via the `getrandom` crate with the `js` feature.

---

## 11. Comparison: FROST Threshold vs Native Monero Multisig

Native Monero 2-of-3 multisig uses `exchange_multisig_keys` and requires multiple synchronization rounds between all participants. It also suffers from a parallel aggregation problem:

```
Native parallel aggregation (INCORRECT):
  Signer A signs: partial_A = f(k_A, k_B)
  Signer B signs: partial_B = f(k_B, k_C)
  Aggregate: partial_A + partial_B contains k_B TWICE
```

FROST avoids this entirely through Lagrange interpolation:

```
FROST reconstruction:
  x_total = d + lambda_i * b_i + lambda_j * b_j
  Each share b_i appears EXACTLY ONCE with its correct coefficient
```

Additional advantages:
- No wallet synchronization rounds required between signing sessions
- Standard DKG (RFC 9591) vs. Monero-specific multisig protocol
- Client-side WASM execution vs. desktop wallet requirement

---

## Appendix A: Varint Encoding

Monero uses variable-length integer encoding throughout the transaction format. Incorrect encoding (e.g., using fixed-width `u64`) produces invalid commitment masks.

```
value < 0x80:       [value]
value < 0x4000:     [0x80 | (value & 0x7F), value >> 7]
value < 0x200000:   [0x80 | (value & 0x7F), 0x80 | ((value >> 7) & 0x7F), value >> 14]
...
```

## Appendix B: Domain Separators

| Context | Domain Separator | Length |
|---------|-----------------|--------|
| View key derivation | `"frost_escrow_view_key"` | 22 bytes |
| Commitment mask | `"commitment_mask"` | 15 bytes |
| CLSAG aggregation 0 | `"CLSAG_agg_0\x00..."` | 32 bytes (null-padded) |
| CLSAG aggregation 1 | `"CLSAG_agg_1\x00..."` | 32 bytes (null-padded) |
| CLSAG round hash | `"CLSAG_round\x00..."` | 32 bytes (null-padded) |

---

## References

1. RFC 9591 — Two-Round Threshold Schnorr Signatures with FROST (Komlo, Goldberg, 2024)
2. CryptoNote v2.0 — van Saberhagen (2013)
3. Ring Confidential Transactions — Noether, Mackenzie (2016)
4. CLSAG — Goodell, Noether et al. (2019)
5. Bulletproofs+ — Chung et al. (2020)
6. Monero Source — github.com/monero-project/monero
