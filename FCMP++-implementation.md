# FCMP++ Implementation Notes

Onyx-Escrow's Pre-Hard-Fork Integration with Full-Chain Membership Proofs

**Version:** 0.1.0-draft
**Status:** Speculative — blocked on Monero hard fork
**Last Updated:** 2026-02-12

---

## Disclaimer

Everything in this document describes an implementation built against the **pre-release** `monero-fcmp-plus-plus` crate from kayabaNerve (Serai-DEX). The Monero hard fork that activates FCMP++ has no confirmed date. Until it ships:

- Wire format constants (TX version, RCT type, input type byte) are **guesses based on current crate state**.
- The consensus parameter `layers` (Curve Trees depth) is undefined.
- No testnet exists to validate v3 transactions end-to-end.
- Our code compiles against vendored crate APIs that may change before mainnet activation.

We built this now because the cryptographic primitives are stable enough to architect around. The hard fork will change byte-level constants, not the protocol structure. When it lands, we adapt constants — we don't rewrite.

---

## 1. What FCMP++ Replaces

Currently (Monero v0.18.x), spending an output requires proving you own it by producing a **CLSAG ring signature** over a ring of 16 outputs (1 real + 15 decoys). The anonymity set is 16.

FCMP++ replaces this with two things:

1. **Spend Authorization and Linkability (SA+L)** — proves you can spend the output and links it to a key image (prevents double-spend). This is the spiritual successor to CLSAG but operates on a re-randomized representation of the output.

2. **Full-Chain Membership Proof (FCMP)** — proves the output exists somewhere in the entire UTXO set using a Curve Trees accumulator. The anonymity set becomes the entire chain.

The practical effect: no more rings, no more decoy selection, no more timing analysis based on ring composition. The tradeoff is larger proofs and more complex cryptography.

---

## 2. Architecture Overview

### What changes in the transaction format

| Field | CLSAG (current) | FCMP++ (post-fork) |
|-------|-----------------|-------------------|
| TX version | 2 | 3 (assumed) |
| RCT type | 6 (BulletproofPlus) | 7 (assumed) |
| Ring members | 16 per input | 0 — no rings |
| Per-input proof | CLSAG (32 + 16×32 + 32 = 577B) | SA+L (384B) + re-randomized tuple (96B) |
| Global proof | None | FCMP membership proof (variable, ~2-8KB depending on tree depth) |
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

## 3. The SA+L Signing Protocol

SA+L uses `modular-frost` (from the `monero-fcmp-plus-plus` crate) instantiated over `Ed25519T` — a custom ciphersuite where the generator is `T` (the re-randomization base) instead of `G`. This is because only the `y` component of the output key `O = xG + yT` is threshold-shared. The `x` (spend key) is provided directly.

### 3.1 Key Insight: What Gets Threshold-Signed

In the SA+L proof, 12 values are produced:

| Value | Type | How computed |
|-------|------|-------------|
| P, A, B, R_O, R_P, R_L | Points (6 × 32B) | Deterministically from transcript seed + public inputs |
| s_alpha, s_beta, s_delta, s_z, s_r_p | Scalars (5 × 32B) | Deterministically from transcript seed + `x` + `r_i` |
| **s_y** | **Scalar (32B)** | **FROST-aggregated from threshold shares** |

Only `s_y` requires the threshold protocol. Everything else is computed identically by each signer from a deterministic transcript seed. The FROST protocol aggregates `s_y = Σ(share_i)` and then `s_r_p` is derived from `s_y`.

This means:
- The 2-round FROST protocol only aggregates a single scalar.
- The partial SA+L data (P, A, B, etc.) lives in the `SalAlgorithm` state inside each signer's WASM.
- The server never sees or needs any of it.

### 3.2 Three-Round Flow

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

### 3.3 Identifiable Abort

If a signer submits an invalid share, `complete()` returns `FrostError::InvalidShare(participant)`. The server can identify and blame the misbehaving signer. No protocol restart is needed — the honest parties can re-run with the third (arbiter) signer instead.

---

## 4. Re-randomization

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

## 5. Transaction Serialization (v3)

Our TX builder supports dual-path serialization. When `FcmpPrunableData` is attached, it emits a v3 transaction:

### 5.1 Prefix

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

### 5.2 RCT Base

```
rct_type: 7 (single byte)
txnFee: varint
ecdhInfo: 8 bytes per output
outPk: 32 bytes per output
```

### 5.3 RCT Prunable (FCMP++)

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

### 5.4 Signable Transaction Hash

```
signable_hash = Keccak256(prefix_hash || component2 || bp_hash)

where:
  prefix_hash = Keccak256(serialized_prefix)
  component2  = Keccak256(rct_base_blob || pseudo_outs)    ← note: pseudo-outs in component 2
  bp_hash     = Keccak256(serialized_bulletproofs)
```

In CLSAG, pseudo-outs appear in the prunable hash (component 3). In FCMP++, the vendor crate's `verify()` binds them in the base hash. We match that behavior.

### 5.5 Membership Proof Size Validation

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

## 6. What's Implemented (with file references)

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

## 7. What's NOT Implemented (Blockers)

### 7.1 Membership Proof Generation (Blocked — requires chain state)

The FCMP membership proof (`Fcmp::prove()`) requires:
- The full Curve Trees accumulator (built from the entire UTXO set)
- The path from the output's leaf to the root
- The tree depth (`layers` — consensus constant, undefined)

This is fundamentally a **node-side operation**. Either monerod provides an RPC to generate the proof, or the client builds the tree locally from chain data. Neither exists yet.

**Our code accepts the proof as an opaque blob from the client.** When the infrastructure exists, the client generates it and submits it via `submit_membership_proof()`.

### 7.2 Consensus Constants (Blocked — hard fork spec not frozen)

| Constant | Our guess | Final value | Impact if wrong |
|----------|-----------|-------------|-----------------|
| TX version | 3 | TBD | 1-line change in `serialize_prefix()` |
| RCT type | 7 | TBD | 1-line change in `serialize_rct_base()` |
| Input type byte | 0x02 | TBD | 1-line change in `serialize_prefix()` |
| Tree depth (`layers`) | Unknown | Consensus param | Affects `proof_size()` validation |
| Key image location | TX prefix | May move to proof body | ~20-line refactor |

### 7.3 Frontend Integration (Blocked — needs working aggregation E2E)

No JavaScript calls the WASM `sal_*` functions yet. The frontend work follows naturally once we can test the full flow on a testnet with FCMP++ activated.

### 7.4 monerod RPC Changes (Blocked — hard fork)

- `get_outs` is irrelevant (no ring selection needed)
- Curve Trees RPC (for membership proof generation) doesn't exist yet
- `sendrawtransaction` should accept v3 TXs after the fork (same RPC, different validation)

---

## 8. What Works Today (Without the Hard Fork)

Despite the blockers above, the following is fully functional and tested:

1. **SA+L threshold keygen**: Three parties run DKG, produce `ThresholdKeys<Ed25519T>`. Tested.
2. **Output re-randomization**: Given an output `(O, I, C)`, produce `(O~, I~, R, C~)`. Tested.
3. **SA+L 2-of-3 signing**: Two parties produce a valid `SpendAuthAndLinkability` proof. Tested against `verify_sal_proof()` with batch verification.
4. **TX v3 serialization**: The TX builder produces a byte blob matching `FcmpPlusPlus::write()` format. Structural tests pass (correct byte offsets, field sizes).
5. **Server coordination**: The full state machine (init → round1 → round2 → aggregate → assemble) works with mock data.

What we **cannot** test today: submitting a v3 TX to monerod and having it accepted by the network. That requires the hard fork.

---

## 9. Migration Path (When the Fork Happens)

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

## 10. Dependencies

| Component | Crate | Source | Pinned |
|-----------|-------|--------|--------|
| SA+L Algorithm | `monero-fcmp-plus-plus` | kayabaNerve (Serai-DEX) | Vendored at commit `a1b2c3d` |
| FROST Protocol | `modular-frost` | kayabaNerve | Via fcmp++ crate |
| Ciphersuite | `ciphersuite` (Ed25519T) | kayabaNerve | Via fcmp++ crate |
| Transcript | `flexible-transcript` | kayabaNerve | Via fcmp++ crate |
| Curve arithmetic | `dalek-ff-group` | kayabaNerve | Via fcmp++ crate |
| Bulletproofs | `generalized-bulletproofs` | kayabaNerve | Via fcmp++ crate |
| WASM bindings | `wasm-bindgen` | Official | 0.2.x |

The entire `fcmp-plus-plus` dependency tree is vendored to avoid upstream breakage. When the final release ships, we'll update the vendor and run the test suite.

---

## 11. Differences from CLSAG Threshold Signing

For readers familiar with our CLSAG implementation (see `PROTOCOL.md`):

| Aspect | CLSAG (current) | SA+L (FCMP++) |
|--------|-----------------|---------------|
| What's threshold-shared | `b_i` (spend key share) | `y_i` (T-component share) |
| Signing rounds | 2 (sequential round-robin) | 2 (parallel FROST) + 1 (aggregation) |
| Ring selection | 16 decoys from `get_outs` | None — full-chain proof |
| Proof size per input | 577 bytes | 480 bytes (96B tuple + 384B SA+L) |
| Global proof | None | FCMP (variable, ~2-8KB) |
| Aggregation location | Server (reconstructs `x_total`) | Client WASM (`SignatureMachine::complete()`) |
| Ciphersuite | Ed25519 (generator G) | Ed25519T (generator T) |
| Nonce reuse risk | Mitigated by round-robin ordering | Mitigated by FROST protocol (nonces bound to participant set) |

The biggest architectural change is that **aggregation moved client-side**. In our CLSAG flow, the server reconstructs `x_total` from FROST shares and Lagrange interpolation, then builds the full CLSAG. In SA+L, the server can't do this because `complete()` needs the partial proof state from `sign()`. This is actually better for the non-custodial property — the server never touches anything resembling a private key, even transiently.

---

## 12. Here's What We Learned

Building a real integration against pre-release cryptographic primitives taught us things that no paper or API doc covers. These are the practical takeaways for anyone attempting FCMP++ integration.

### The membership proof format will bite you silently

`Fcmp::read()` is **not self-delimiting**. It expects the caller to compute `proof_size(inputs, layers) - 64` to know where the proof bytes end and the 64-byte `root_blind_pok` begins. If you get this wrong — wrong input count, wrong layer depth, wrong curve parameters — the deserialization silently splits the blob at the wrong offset. Both halves look like valid byte arrays. Both are garbage. There's no magic number, no length prefix, no checksum. You find out at verification time, or worse, you don't.

We added explicit `expected_proof_len` validation at two points in the pipeline. Redundant? Maybe. But silent corruption in a financial transaction is the kind of bug you find on mainnet at 3 AM.

### Only `s_y` is FROST-aggregated — everything else is deterministic

We initially assumed the entire SA+L proof would need threshold aggregation across signers. Wrong. Reading `SalAlgorithm::sign()` and `verify()` carefully reveals that 11 of 12 proof values (6 points + 5 scalars) are computed deterministically from the transcript seed and public inputs. Only `s_y` — the scalar tied to the `T`-component private key share — goes through the FROST protocol.

This matters architecturally: the FROST overhead is minimal (one scalar aggregation), and the rest of the proof is identical regardless of which 2-of-3 signers participate.

### Aggregation must happen client-side (and that's a feature)

We originally planned for the server to aggregate FROST shares into the final SA+L proof, like our CLSAG flow where the server reconstructs `x_total`. That's impossible with SA+L. `SignatureMachine::complete()` requires the `partial` state from `sign()` — specifically the intermediate SA+L values (P, A, B, R_O, R_P, R_L and the pre-scalars) that live in WASM memory.

The server never has this state. It can't reconstruct it without keys. So aggregation lives in the client's browser.

At first this felt like a limitation. Then we realized it's strictly better for the non-custodial property. In our CLSAG flow, the server transiently holds `x_total` during signing. In SA+L, the server literally cannot produce a valid proof. The math enforces what policy promises.

### Ed25519T is not Ed25519 with a different name

The SA+L ciphersuite uses generator `T` instead of `G`. This isn't cosmetic — it means the FROST DKG produces `ThresholdKeys<Ed25519T>`, not `ThresholdKeys<Ed25519>`. If you try to reuse your existing Ed25519 DKG infrastructure, the type system stops you (in Rust). In a language without strong typing on curve parameters, you'd get a valid-looking but wrong key package that produces invalid proofs.

We had to build a separate DKG flow (`sal_dkg_part1/2/3`) alongside the existing FROST DKG for CLSAG. Code duplication? Yes. Type safety on cryptographic parameters? Worth it.

### The vendor crate is research-grade, not integration-grade

kayabaNerve's `monero-fcmp-plus-plus` is excellent cryptography, built for the Serai DEX. It is not built for external integrators. Expect:

- Internal types that don't implement `Serialize`/`Deserialize` — you'll write conversion layers.
- `prove()` and `verify()` that take 10+ parameters each, some of which are intermediate values from other functions with no obvious documentation on how to obtain them.
- Test vectors that test the cryptographic primitives, not the integration surface.
- Breaking API changes between commits (it's pre-release, this is expected).

Vendoring was the right call. We pinned a known-good commit and wrapped it with our own typed API (`OnyxSalSigner`, `verify_sal_proof()`). When the crate stabilizes post-fork, we'll update the vendor and fix whatever breaks.

### Pseudo-outs binding changed and it matters for the signable hash

In CLSAG transactions, pseudo-outs are part of the prunable hash (component 3 of the signable transaction hash). In FCMP++, the vendor's `FcmpPlusPlus::verify()` binds them in the base hash (component 2). We discovered this by reading `verify()`, not from any documentation.

If you compute the signable hash the CLSAG way for an FCMP++ transaction, the proof verifies locally but the network rejects the TX because the hash doesn't match what verifiers expect. This is the kind of divergence that's invisible until you test against a real node.

### Feature-gating is non-negotiable for dual-path code

We serve both CLSAG (current mainnet) and FCMP++ (post-fork) from the same codebase. Every FCMP++ code path is behind `#[cfg(feature = "fcmp")]`. Without this:

- The TX builder would always include FCMP++ types, bloating the binary for mainnet users.
- A bug in the FCMP++ path could break the working CLSAG path.
- Dependency conflicts between the FCMP++ vendor crate and existing Monero crates would block compilation.

The `fcmp` feature flag propagates through the entire stack: `onyx-crypto-core/fcmp` → `server/fcmp` → `wallet-wasm/fcmp`. Default build produces the current mainnet binary. `--features fcmp` adds the post-fork path. Both compile independently.

### What we'd do differently

1. **Start with the wire format, not the signing protocol.** We built signing first and serialization second. Should have been the reverse — the wire format is the contract with the network, and it constrains everything upstream.

2. **Read `verify()` before `prove()`.** The verify function tells you exactly what the network checks. The prove function tells you how to produce a proof. The former is a spec; the latter is an implementation. When they diverge (and they will in pre-release code), trust verify.

3. **Build a mock `Fcmp::read()` round-trip test on day one.** We caught the non-self-delimiting issue late. A simple serialize→deserialize round-trip with a wrong `layers` parameter would have surfaced it immediately.

---

## References

1. kayabaNerve, "Full-Chain Membership Proofs" — https://github.com/serai-dex/serai/tree/develop/networks/monero
2. Rucknium et al., "FCMP++ Design Document" — Monero Research Lab
3. Goodell, Noether, "Concise Linkable Ring Signatures (CLSAG)" — 2019
4. RFC 9591 — Two-Round Threshold Schnorr Signatures with FROST
5. Cypher Stack, "Review of the FCMP++ Composition" — 2024
6. Onyx-Escrow CLSAG Protocol — `PROTOCOL.md` in this repository
