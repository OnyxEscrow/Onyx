# FCMP++ Implementation Notes

Onyx-Escrow's Pre-Hard-Fork Integration with Full-Chain Membership Proofs

**Version:** 0.1.1-draft
**Status:** Speculative — blocked on Monero hard fork
**Last Updated:** 2026-02-17

---

## Disclaimer

Everything in this document describes an implementation built against the **pre-release** `monero-fcmp-plus-plus` crate from kayabaNerve (Serai-DEX). The Monero hard fork that activates FCMP++ has no confirmed date. Until it ships:

- Wire format constants (TX version, RCT type, input type byte) are **guesses based on current crate state**.
- The consensus parameter `layers` (Curve Trees depth) is undefined.
- No testnet exists to validate v3 transactions end-to-end.
- Our code compiles against vendored crate APIs that may change before mainnet activation.

We built this now because the cryptographic primitives are stable enough to architect around. The hard fork will change byte-level constants, not the protocol structure. When it lands, we adapt constants — we don't rewrite.

---

## 1. Integration Findings

We integrated `monero-fcmp-plus-plus` (vendored from kayabaNerve's `develop` branch, 208 files, ~28K LOC) into a 2-of-3 threshold escrow system with WASM client-side signing. SA+L DKG, rerandomization, signing, and batch verification all pass. TX v3 serialization produces structurally correct blobs. ~740 tests across the workspace. What follows are the non-obvious things we discovered — the kind of integration feedback that doesn't appear in API docs.

**1. `Fcmp::read()` is not self-delimiting.** The proof format requires the caller to precompute `proof_size(inputs, layers) - 64` to know where proof bytes end and the 64-byte `root_blind_pok` begins. A wrong `layers` value silently splits the blob at the wrong offset. Both halves look like valid byte arrays. Both are garbage. No magic number, no length prefix, no checksum. We added explicit `expected_proof_len` validation at two pipeline stages (`submit_membership_proof()` and `attach_fcmp_proof()`). See Section 6.5.

**2. Only `s_y` is FROST-aggregated.** We initially assumed the entire SA+L proof required threshold aggregation. Wrong. Reading `SalAlgorithm::sign()` reveals that 10 of 12 proof values are fully deterministic from the transcript seed, public inputs, and spend key `x`. Only `s_y` — the scalar tied to the `T`-component share — goes through FROST. The 12th value `s_r_p` is derived post-aggregation as `s_r_p_pre - s_y`. FROST overhead is one scalar aggregation. See Section 4.1.

**3. Aggregation must happen client-side.** `SignatureMachine::complete()` needs the `partial` state from `sign()` — the intermediate SA+L values (P, A, B, R_O, R_P, R_L and pre-scalars) that live in WASM memory. The server never has this state and cannot reconstruct it. This is strictly better for non-custodial properties than our CLSAG flow, where the server transiently holds `x_total`. With SA+L, the server literally cannot produce a valid proof. See Section 4.2.

**4. Ed25519T is not Ed25519 with a different name.** The SA+L ciphersuite uses generator `T` instead of `G`. FROST DKG produces `ThresholdKeys<Ed25519T>`, not `ThresholdKeys<Ed25519>`. Reusing an existing Ed25519 DKG gives valid-looking but wrong key packages. We built a separate DKG flow (`sal_dkg_part1/2/3`). Type safety > code reuse for cryptographic parameters.

**5. Pseudo-outs binding moved.** In CLSAG, pseudo-outs are in the prunable hash (component 3). The vendor's `FcmpPlusPlus::verify()` states that `signable_tx_hash` must bind to "the transaction prefix, the RingCT base, and the pseudo-outs." The crate takes the hash as an opaque `[u8; 32]` — it doesn't enforce a component structure. We bind pseudo-outs in component 2 (base hash). Computing the hash the CLSAG way for an FCMP++ TX makes the SA+L proof sign a different message than verifiers expect. See Section 6.4.

**6. The crate is research-grade, not integration-grade.** Internal types lack `Serialize`/`Deserialize`. `prove()` and `verify()` take 10+ parameters, some of which are intermediate values from other functions with no documentation on how to obtain them. Test vectors validate primitives, not the integration surface. We vendored a known-good commit and wrapped it with our own typed API (`OnyxSalSigner`, `verify_sal_proof()`).

**What we'd do differently:** start with the wire format (not the signing protocol) — it's the network contract and constrains everything upstream. Read `verify()` before `prove()` — the former is a spec, the latter is an implementation. Build a mock `Fcmp::read()` round-trip test on day one to catch the non-self-delimiting issue early.

---

## 2. What FCMP++ Replaces

Currently (Monero v0.18.x), spending an output requires proving you own it by producing a **CLSAG ring signature** over a ring of 16 outputs (1 real + 15 decoys). The anonymity set is 16.

FCMP++ replaces this with two things:

1. **Spend Authorization and Linkability (SA+L)** — proves you can spend the output and links it to a key image (prevents double-spend). This is the spiritual successor to CLSAG but operates on a re-randomized representation of the output.

2. **Full-Chain Membership Proof (FCMP)** — proves the output exists somewhere in the entire UTXO set using a Curve Trees accumulator. The anonymity set becomes the entire chain.

The practical effect: no more rings, no more decoy selection, no more timing analysis based on ring composition. The tradeoff is larger proofs and more complex cryptography.

---

## 3. Architecture Overview

### What changes in the transaction format

| Field | CLSAG (current) | FCMP++ (post-fork) |
|-------|-----------------|-------------------|
| TX version | 2 | 3 (assumed) |
| RCT type | 6 (BulletproofPlus) | 7 (assumed) |
| Ring members | 16 per input | 0 — no rings |
| Per-input proof | CLSAG (32 + 16×32 + 32 = 576B) | SA+L (384B) + re-randomized tuple (96B) |
| Global proof | None | FCMP membership proof (variable, ~2-10KB depending on tree depth) |
| Pseudo-outs | In prunable section | Same position, bound differently in signable hash |

### What stays the same

- Bulletproofs+ for range proofs (output amounts)
- Key images in the TX prefix
- `sendrawtransaction` RPC for broadcast
- View key derivation and output scanning
- FROST DKG for threshold key generation

### Our implementation boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT (WASM)                         │
│                                                         │
│  sal_dkg_part1/2/3()     — threshold keygen (Ed25519T)  │
│  sal_rerandomize()       — output re-randomization       │
│  sal_preprocess()        — FROST Round 1 (nonces)        │
│  sal_sign()              — FROST Round 2 (shares)        │
│  sal_complete()          — FROST aggregation → SA+L      │
│                                                         │
│  [Membership proof generation — NOT YET IMPLEMENTED]     │
│                                                         │
└──────────────────────┬──────────────────────────────────┘
                       │ public data only
┌──────────────────────▼──────────────────────────────────┐
│                    SERVER (blind relay)                   │
│                                                         │
│  SalSigningCoordinator   — state machine, collects data  │
│  assemble_fcmp_prunable()— builds FcmpPrunableData       │
│  MoneroTransactionBuilder— serializes v3 TX blob         │
│  broadcast via monerod   — sendrawtransaction            │
│                                                         │
│  Server NEVER holds keys, nonces, or FROST state.        │
│  Server CANNOT produce a valid SA+L proof.               │
└─────────────────────────────────────────────────────────┘
```

---

## 4. The SA+L Signing Protocol

SA+L uses `modular-frost` (from the `monero-fcmp-plus-plus` crate) instantiated over `Ed25519T` — a custom ciphersuite where the generator is `T` (the re-randomization base) instead of `G`. This is because only the `y` component of the output key `O = xG + yT` is threshold-shared. The `x` (spend key) is provided directly.

### 4.1 Key Insight: What Gets Threshold-Signed

In the SA+L proof, 12 values are produced:

| Value | Type | How computed |
|-------|------|-------------|
| P, A, B, R_L | Points (4 × 32B) | Deterministically from transcript seed + `x` + `r_i` |
| R_O, R_P | Points (2 × 32B) | Deterministic nonces + FROST nonce commitment sum (`R_y`) |
| s_alpha, s_beta, s_delta, s_z | Scalars (4 × 32B) | Deterministically from transcript seed + `x` + `r_i` |
| **s_y** | **Scalar (32B)** | **FROST-aggregated from threshold shares** |
| s_r_p | Scalar (32B) | Derived post-aggregation: `s_r_p_pre - s_y` |

Only `s_y` requires the threshold protocol. 10 of 12 values are fully deterministic, computed identically by each signer from a deterministic transcript seed. `R_O` and `R_P` additionally incorporate the FROST nonce commitment sum. The FROST protocol aggregates `s_y = Σ(share_i)` and then `s_r_p` is derived as `s_r_p_pre - s_y`.

This means:
- The 2-round FROST protocol only aggregates a single scalar.
- The partial SA+L data (P, A, B, etc.) lives in the `SalAlgorithm` state inside each signer's WASM.
- The server never sees or needs any of it.

### 4.2 Three-Round Flow

```
Round 1 — Preprocess (both signers, parallel):
  WASM: sal_preprocess(keys, tx_hash, rerand, x, indices)
        → { sessionId, preprocessHex }
  Send preprocessHex to server.

Round 2 — Sign (both signers, parallel, after server distributes all preprocesses):
  WASM: sal_sign(sessionId, allPreprocessesJson, messageHex)
        → { shareHex }
  Send shareHex to server.

Round 3 — Complete (ONE signer, the "aggregator"):
  Server sends all shares to the aggregating signer.
  WASM: sal_complete(sessionId, allSharesJson)
        → { salProofHex }   // 384 bytes
  Send salProofHex to server.
```

The aggregation MUST happen client-side because `SignatureMachine::complete()` needs the `SalAlgorithm`'s internal `partial` state (set during `sign()`). The server doesn't have this state and can't reconstruct it without keys.

### 4.3 Identifiable Abort

If a signer submits an invalid share, `complete()` returns `FrostError::InvalidShare(participant)`. The server can identify and blame the misbehaving signer.

**A full protocol restart IS required after any abort.** All nonces from the aborted round must be destroyed before retrying — even if the retry uses the same honest signers. Reusing a nonce `r` across two rounds with different challenges `c₁, c₂` leaks the private key via algebraic extraction:

    s₁ = r + c₁·x
    s₂ = r + c₂·x
    x  = (s₁ - s₂) / (c₁ - c₂)

This applies to both the CLSAG and SA+L signing paths. Our implementation enforces this structurally: `reset_signing_session()` atomically burns all nonce state and issues a fresh `round_id` UUID. Stale submissions against an old `round_id` are rejected. Signer set changes (e.g., swapping in the arbiter) trigger automatic nonce invalidation via `signer_set_hash` comparison in `init_signing()`.

---

## 5. Re-randomization

Before SA+L proving, each output must be re-randomized to break the link between the on-chain output and the proof. This produces:

```
O~ = O + r_o * T
I~ = I + r_i * U
R  = r_i * V + r_r_i * T
C~ = C + r_c * G
```

Where `T`, `U`, `V` are the FCMP++ generators (distinct from `G` and `H`). The randomizers `r_o, r_i, r_r_i, r_c` are sampled client-side and never leave WASM.

The re-randomized tuple `(O~, I~, R)` is 96 bytes and appears in the TX body. `C~` (the re-randomized commitment) is the pseudo-output.

---

## 6. Transaction Serialization (v3)

Our TX builder supports dual-path serialization. When `FcmpPrunableData` is attached, it emits a v3 transaction:

### 6.1 Prefix

```
version: 3 (varint)
unlock_time: 0 (varint)
num_inputs: N (varint)
for each input:
    type: 0x02 (TxinToKey)
    amount: 0 (varint)
    num_key_offsets: 0 (varint)    ← no ring members
    key_image: 32 bytes
num_outputs: M (varint)
for each output:
    amount: 0 (varint)
    tagged_key: { key: 32B, view_tag: 1B }
extra: [tx_pubkey, ...]
```

The critical difference from v2: `num_key_offsets = 0` for each input. There are no ring members — membership is proved globally by the FCMP.

### 6.2 RCT Base

```
rct_type: 7 (single byte)
txnFee: varint
ecdhInfo: 8 bytes per output
outPk: 32 bytes per output
```

### 6.3 RCT Prunable (FCMP++)

```
bulletproofPlus: [range_proof]    ← unchanged from v2

for each input:
    O~: 32 bytes
    I~: 32 bytes
    R:  32 bytes
    SA+L proof: 384 bytes (P|A|B|R_O|R_P|R_L|s_alpha|...|s_r_p)

FCMP membership proof: variable bytes (NOT self-delimiting)
root_blind_pok: 64 bytes

pseudo_outs: 32 bytes per input
```

### 6.4 Signable Transaction Hash

```
signable_hash = Keccak256(prefix_hash || component2 || bp_hash)

where:
  prefix_hash = Keccak256(serialized_prefix)
  component2  = Keccak256(rct_base_blob || pseudo_outs)    ← note: pseudo-outs in component 2
  bp_hash     = Keccak256(serialized_bulletproofs)
```

In CLSAG, pseudo-outs appear in the prunable hash (component 3). The vendor's `FcmpPlusPlus::verify()` (`lib.rs:312-313`) documents that `signable_tx_hash` "must be binding to the transaction prefix, the RingCT base, and the pseudo-outs." The crate takes the hash as an opaque `[u8; 32]` at `lib.rs:328` and passes it through to `SpendAuthAndLinkability::verify()` at `lib.rs:337` — it does not compute or enforce a specific hash structure. We chose to bind pseudo-outs in component 2 (the base hash) to satisfy this requirement. The exact component placement may change when the hard fork spec is finalized.

### 6.5 Membership Proof Size Validation

The FCMP proof format is **not self-delimiting**. `Fcmp::read(inputs, layers)` computes the exact proof size from:

```rust
proof_size = (32 * proof_elements) + 64  // proof_elements depends on inputs, layers, curve params
proof_bytes_len = proof_size - 64        // last 64 bytes are root_blind_pok
```

The reader must know `inputs` (from TX prefix) and `layers` (consensus constant, the Curve Trees depth) to split the blob correctly. A wrong-length proof silently corrupts deserialization — the reader takes N bytes as proof and 64 bytes as PoK, but if N is wrong, both halves are garbage.

We validate at two points:
1. `submit_membership_proof()` — checks `proof_bytes.len() == expected_proof_len` and `% 32 == 0`
2. `attach_fcmp_proof()` — same validation before serialization

The `expected_proof_len` is provided by the client (which has access to the curve type parameters needed to compute `proof_size()`). If the client lies, the proof fails network verification anyway. But accidental mismatches are caught before serialization.

---

## 7. What's Implemented (with file references)

### Crypto Layer (onyx-crypto-core)

| Module | LOC | What it does |
|--------|-----|-------------|
| `src/gsp/multisig.rs` | 188 | `OnyxSalSigner` wrapper, `verify_sal_proof()`, scalar/point conversion |
| `src/gsp/verify.rs` | ~60 | Standalone SA+L batch verification |
| `src/rerandomize/` | ~200 | Output re-randomization (wraps vendor `RerandomizedOutput`) |
| `src/fcmp/tree.rs` | ~100 | Curve Trees data types |
| `vendor/fcmp-plus-plus/` | ~15K | kayabaNerve's full crate (vendored) |

### WASM (wallet/wasm)

| Module | LOC | Exports |
|--------|-----|---------|
| `sal_signing.rs` | 460 | `sal_preprocess`, `sal_sign`, `sal_complete`, `sal_cleanup` |
| `sal_dkg.rs` | 385 | `sal_dkg_part1`, `sal_dkg_part2`, `sal_dkg_part3` |
| `sal_rerandomize.rs` | 213 | `sal_rerandomize`, `sal_generators` |

### Server

| Module | LOC | What it does |
|--------|-----|-------------|
| `services/transaction_builder.rs` | 2960 | Dual-path v2/v3 TX serialization |
| `services/sal_signing_coordinator.rs` | 1055 | SA+L signing state machine + assembly |
| `handlers/sal_signing.rs` | 571 | HTTP API for SA+L signing rounds |
| `handlers/sal_dkg.rs` | 619 | HTTP API for SA+L DKG |

### Tests

| Test | Result |
|------|--------|
| SA+L multisig integration (20 tests) | Pass |
| E2E DKG → rerandomize → sign → verify | Pass |
| Server lib tests (301) | Pass |
| WASM lib tests with fcmp feature (18) | Pass |

---

## 8. What's NOT Implemented (Blockers)

### 8.1 Membership Proof Generation (Blocked — requires chain state)

The FCMP membership proof (`Fcmp::prove()`) requires:
- The full Curve Trees accumulator (built from the entire UTXO set)
- The path from the output's leaf to the root
- The tree depth (`layers` — consensus constant, undefined)

This is fundamentally a **node-side operation**. Either monerod provides an RPC to generate the proof, or the client builds the tree locally from chain data. Neither exists yet.

**Our code accepts the proof as an opaque blob from the client.** When the infrastructure exists, the client generates it and submits it via `submit_membership_proof()`.

### 8.2 Consensus Constants (Blocked — hard fork spec not frozen)

| Constant | Our guess | Source of guess | Final value | Impact if wrong |
|----------|-----------|----------------|-------------|-----------------|
| TX version | 3 | Monero v2→v3 convention; no constant in vendor crate (it doesn't build TXs) | TBD | 1-line change in `serialize_prefix()` |
| RCT type | 7 | Next after RCTTypeBulletproofPlus (6); vendor `FcmpPlusPlus::verify()` at `lib.rs:320` takes `signable_tx_hash` opaquely — no RCT type parsing | TBD | 1-line change in `serialize_rct_base()` |
| Input type byte | 0x02 | Existing `txin_to_key` type byte; vendor doesn't serialize TX inputs — only consumes `Input` structs via `read()` at `lib.rs:288` | TBD | 1-line change in `serialize_prefix()` |
| Tree depth (`layers`) | Unknown | `FcmpPlusPlus::verify()` takes `layers: usize` at `lib.rs:327` — consensus must define this | Consensus param | Affects `proof_size()` validation |
| Key image location | TX prefix | Current Monero convention; vendor `verify()` takes `key_images: Vec<G>` at `lib.rs:329` separately from the proof struct | May move to proof body | ~20-line refactor |

### 8.3 Frontend Integration (Blocked — needs working aggregation E2E)

No JavaScript calls the WASM `sal_*` functions yet. The frontend work follows naturally once we can test the full flow on a testnet with FCMP++ activated.

### 8.4 monerod RPC Changes (Blocked — hard fork)

- `get_outs` is irrelevant (no ring selection needed)
- Curve Trees RPC (for membership proof generation) doesn't exist yet
- `sendrawtransaction` should accept v3 TXs after the fork (same RPC, different validation)

---

## 9. What Works Today (Without the Hard Fork)

Despite the blockers above, the following is fully functional and tested:

1. **SA+L threshold keygen**: Three parties run DKG, produce `ThresholdKeys<Ed25519T>`. Tested.
2. **Output re-randomization**: Given an output `(O, I, C)`, produce `(O~, I~, R, C~)`. Tested.
3. **SA+L 2-of-3 signing**: Two parties produce a valid `SpendAuthAndLinkability` proof. Tested against `verify_sal_proof()` with batch verification.
4. **TX v3 serialization**: The TX builder produces a byte blob matching `FcmpPlusPlus::write()` format. Structural tests pass (correct byte offsets, field sizes).
5. **Server coordination**: The full state machine (init → round1 → round2 → aggregate → assemble) works with mock data.

What we **cannot** test today: submitting a v3 TX to monerod and having it accepted by the network. That requires the hard fork.

---

## 10. Migration Path (When the Fork Happens)

### Phase 1: Constants update (day 1)

Read the final consensus rules. Update:
- `TX_VERSION_FCMP` (currently 3)
- `RCT_TYPE_FCMP` (currently 7)
- `INPUT_TYPE_FCMP` (currently 0x02)
- `TREE_LAYERS` (currently unknown)

These are all constants in `transaction_builder.rs`. Total: ~5 lines changed.

### Phase 2: Membership proof pipeline (week 1)

Implement or integrate the Curve Trees proof generation:
- If monerod exposes an RPC: call it from the client, submit proof hex to server.
- If not: build the tree client-side from `get_output_distribution` data.

Wire into `submit_membership_proof()` which already validates and stores it.

### Phase 3: Testnet validation (week 1-2)

- Generate a v3 TX with real inputs from testnet
- Submit via `sendrawtransaction`
- Verify acceptance by monerod
- Fix any byte-level serialization issues discovered

### Phase 4: Frontend (week 2-3)

Wire the JS to call `sal_dkg_part1/2/3`, `sal_preprocess`, `sal_sign`, `sal_complete` in sequence. The HTTP endpoints already exist (`handlers/sal_signing.rs`, `handlers/sal_dkg.rs`).

---

## 11. Dependencies

| Component | Crate | Version | Source | Pinned |
|-----------|-------|---------|--------|--------|
| SA+L Algorithm | `monero-fcmp-plus-plus` | 0.1.0 | [kayabaNerve/fcmp-plus-plus](https://github.com/kayabaNerve/fcmp-plus-plus) `develop` branch | Vendored 2026-02-11, 208 files, 27,788 LOC |
| FROST Protocol | `modular-frost` | 0.8.1 | [serai-dex/serai](https://github.com/serai-dex/serai) | Via fcmp++ vendor tree |
| Ciphersuite | `ciphersuite` (Ed25519T) | — | kayabaNerve | Via fcmp++ vendor tree |
| Transcript | `flexible-transcript` | 0.3.2 | kayabaNerve | Via fcmp++ vendor tree |
| Curve arithmetic | `dalek-ff-group` | — | kayabaNerve | Via fcmp++ vendor tree |
| Bulletproofs | `generalized-bulletproofs` | — | kayabaNerve | Via fcmp++ vendor tree |
| WASM bindings | `wasm-bindgen` | 0.2.x | Official | crates.io |

The entire `fcmp-plus-plus` dependency tree (208 files) is vendored at `onyx-crypto-core/vendor/fcmp-plus-plus/` to avoid upstream breakage. No upstream commit hash was recorded at vendoring time — the upstream repo (`kayabaNerve/fcmp-plus-plus`) does not tag releases, and the `develop` branch moves frequently. The crate versions above (`monero-fcmp-plus-plus` 0.1.0, `modular-frost` 0.8.1) serve as the pinning reference. When the final release ships post-hard-fork, we'll update the vendor tree and run the full test suite.

---

## 12. Differences from CLSAG Threshold Signing

For readers familiar with our CLSAG implementation (see `PROTOCOL.md`):

| Aspect | CLSAG (current) | SA+L (FCMP++) |
|--------|-----------------|---------------|
| What's threshold-shared | `b_i` (spend key share) | `y_i` (T-component share) |
| Signing rounds | 2 (sequential round-robin) | 2 (parallel FROST) + 1 (aggregation) |
| Ring selection | 16 decoys from `get_outs` | None — full-chain proof |
| Proof size per input | 576 bytes | 480 bytes (96B tuple + 384B SA+L) |
| Global proof | None | FCMP (variable, ~2-10KB) |
| Aggregation location | Server (reconstructs `x_total`) | Client WASM (`SignatureMachine::complete()`) |
| Ciphersuite | Ed25519 (generator G) | Ed25519T (generator T) |
| Nonce reuse risk | State-machine enforced: `reset_signing_session()` + `round_id` binding + `signer_set_hash` auto-invalidation | Same enforcement via SA+L coordinator `rollback()` — nonces burned on any abort/retry |

The biggest architectural change is that **aggregation moved client-side**. In our CLSAG flow, the server reconstructs `x_total` from FROST shares and Lagrange interpolation, then builds the full CLSAG. In SA+L, the server can't do this because `complete()` needs the partial proof state from `sign()`. This is actually better for the non-custodial property — the server never touches anything resembling a private key, even transiently.

---

## References

1. kayabaNerve, "Full-Chain Membership Proofs" — https://github.com/serai-dex/serai/tree/develop/networks/monero
2. Rucknium et al., "FCMP++ Design Document" — Monero Research Lab
3. Goodell, Noether, "Concise Linkable Ring Signatures (CLSAG)" — 2019
4. RFC 9591 — Two-Round Threshold Schnorr Signatures with FROST
5. Cypher Stack, "Review of the FCMP++ Composition" — 2024
6. Onyx-Escrow CLSAG Protocol — `PROTOCOL.md` in this repository
