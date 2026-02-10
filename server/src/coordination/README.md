# Non-Custodial Escrow Coordination

**Status:** Phase 1 Implementation (Dual Mode)
**Date:** 2025-11-08
**Architecture:** Inspired by Haveno DEX

## Overview

This module implements a **pure coordinator** for non-custodial multisig escrow, where the server NEVER creates or manages wallets. Clients run their own `monero-wallet-rpc` instances and the server only coordinates the exchange of public multisig info.

### Key Principle

**Before (Custodial):**
```
Server creates wallet → Server executes prepare_multisig → Server manages keys
```

**After (Non-Custodial):**
```
Client local wallet → Client executes prepare_multisig → Server coordinates exchange ONLY
```

## Architecture

### Components

1. **EscrowCoordinator** (`escrow_coordinator.rs`)
   - Stores RPC URLs only (NOT wallets)
   - Validates localhost strict
   - Coordinates multisig info exchange
   - Validates formats and thresholds

2. **Handlers** (`server/src/handlers/noncustodial.rs`)
   - API endpoints for client wallet registration
   - Multisig coordination endpoints
   - Status checking endpoints

3. **Routes** (`server/src/main.rs`)
   - `/api/v2/escrow/register-wallet`
   - `/api/v2/escrow/coordinate-exchange`
   - `/api/v2/escrow/coordination-status/{escrow_id}`

## Flow Diagram

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│  BUYER (Client)     │     │  SELLER (Client)    │     │  ARBITER (Client)   │
│                     │     │                     │     │                     │
│ monero-wallet-rpc   │     │ monero-wallet-rpc   │     │ monero-wallet-rpc   │
│ Port: 18083 LOCAL   │     │ Port: 18084 LOCAL   │     │ Port: 18085 LOCAL   │
│                     │     │                     │     │                     │
│ 1. create_wallet    │     │ 1. create_wallet    │     │ 1. create_wallet    │
│ 2. prepare_multisig │     │ 2. prepare_multisig │     │ 2. prepare_multisig │
│    ↓ info_B         │     │    ↓ info_S         │     │    ↓ info_A         │
└──────────┬──────────┘     └──────────┬──────────┘     └──────────┬──────────┘
           │                           │                           │
           │  POST /v2/escrow/register-wallet                     │
           │  {"escrow_id": "esc_123", "role": "buyer",           │
           │   "rpc_url": "http://127.0.0.1:18083"}              │
           └───────────────────────────┼───────────────────────────┘
                                       ↓
                        ┌──────────────────────────────┐
                        │   SERVER (Coordinator)       │
                        │                              │
                        │ EscrowCoordinator            │
                        │ ✅ Validates localhost       │
                        │ ✅ Checks RPC connectivity   │
                        │ ✅ Stores URLs (NOT wallets) │
                        │ ✅ Waits for all 3           │
                        └──────────────────────────────┘
                                       ↓
           ┌───────────────────────────┼───────────────────────────┐
           │ POST /v2/escrow/coordinate-exchange                    │
           │ {"escrow_id": "esc_123"}                              │
           ↓                           ↓                           ↓
           │                           │                           │
           │ Server requests:          │                           │
           │ prepare_multisig()        │                           │
           │ from each wallet          │                           │
           │                           │                           │
           │ Server validates:         │                           │
           │ - Format (MultisigV1)     │                           │
           │ - Length (100-5000)       │                           │
           │                           │                           │
           │ Server exchanges:         │                           │
           │ buyer ← [info_S, info_A]  │                           │
           │ seller ← [info_B, info_A] │                           │
           │ arbiter ← [info_B, info_S]│                           │
           ↓                           ↓                           ↓
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│  BUYER              │     │  SELLER             │     │  ARBITER            │
│                     │     │                     │     │                     │
│ 3. make_multisig    │     │ 3. make_multisig    │     │ 3. make_multisig    │
│    ([info_S,info_A])│     │    ([info_B,info_A])│     │    ([info_B,info_S])│
│                     │     │                     │     │                     │
│ 4. export_multisig  │     │ 4. export_multisig  │     │ 4. export_multisig  │
│ 5. import_multisig  │     │ 5. import_multisig  │     │ 5. import_multisig  │
│ 6. export (round 2) │     │ 6. export (round 2) │     │ 6. export (round 2) │
│ 7. import (round 2) │     │ 7. import (round 2) │     │ 7. import (round 2) │
│                     │     │                     │     │                     │
│ ✅ READY FOR TX     │     │ ✅ READY FOR TX     │     │ ✅ READY FOR TX     │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
```

## API Endpoints

### 1. Register Client Wallet

**POST** `/api/v2/escrow/register-wallet`

Register a client's local wallet RPC for escrow participation.

**Request:**
```json
{
  "escrow_id": "escrow_abc123",
  "role": "buyer",
  "rpc_url": "http://127.0.0.1:18083"
}
```

**Response:**
```json
{
  "success": true,
  "message": "✅ Buyer wallet registered. Waiting for: [\"seller\", \"arbiter\"]",
  "escrow_id": "escrow_abc123",
  "role": "buyer",
  "coordination_state": "AwaitingRegistrations",
  "awaiting": ["seller", "arbiter"]
}
```

**Security:**
- ✅ RPC URL MUST be localhost (127.0.0.1, localhost, ::1)
- ✅ Server checks RPC connectivity before accepting
- ✅ Server stores URL only (NOT the wallet)

### 2. Coordinate Multisig Exchange

**POST** `/api/v2/escrow/coordinate-exchange`

Coordinate the exchange of multisig info between all participants.

**Prerequisites:**
- All 3 wallets registered (buyer, seller, arbiter)
- Each wallet prepared (executed `prepare_multisig` locally)

**Request:**
```json
{
  "escrow_id": "escrow_abc123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "✅ Multisig info exchange coordinated successfully",
  "escrow_id": "escrow_abc123",
  "exchange_result": {
    "buyer_receives": [
      "MultisigV1AAAABBBBCCCCDDDD...",
      "MultisigV1EEEEFFFF..."
    ],
    "seller_receives": [
      "MultisigV1GGGGHHHHIIII...",
      "MultisigV1JJJJKKKK..."
    ],
    "arbiter_receives": [
      "MultisigV1LLLLMMMM...",
      "MultisigV1NNNNOOOO..."
    ]
  }
}
```

**Server Actions:**
- ✅ Requests `prepare_multisig` from each client wallet
- ✅ Validates format (starts with MultisigV1)
- ✅ Validates length (100-5000 bytes)
- ✅ Exchanges infos (each receives 2 others)

### 3. Get Coordination Status

**GET** `/api/v2/escrow/coordination-status/{escrow_id}`

Check current coordination state for an escrow.

**Response:**
```json
{
  "success": true,
  "escrow_id": "escrow_abc123",
  "state": "AllRegistered",
  "buyer_registered": true,
  "seller_registered": true,
  "arbiter_registered": true,
  "ready_for_exchange": true
}
```

## Coordination States

```
AwaitingRegistrations  → Waiting for all 3 wallets to register
         ↓
AllRegistered          → All 3 wallets registered, ready to prepare
         ↓
Prepared               → prepare_multisig executed, infos collected
         ↓
ReadyForMakeMultisig   → Infos exchanged, clients can make_multisig
         ↓
MadeMultisig           → make_multisig completed (verified via export)
         ↓
SyncRound1Complete     → First export/import round done
         ↓
SyncRound2Complete     → Second export/import round done
         ↓
Ready                  → Fully synchronized, ready for transactions
```

## Security Guarantees

### What the Server CAN Do ✅
- Store RPC URLs (localhost only)
- Request `prepare_multisig` from client wallets
- Validate multisig_info formats
- Exchange public multisig_info strings
- Coordinate sync rounds

### What the Server CANNOT Do ❌
- Create wallets
- Access private keys
- Execute `make_multisig`
- Sign transactions
- Access wallet files
- See seed phrases

## Comparison to Old System

| Aspect | Old (Custodial) | New (Non-Custodial) |
|--------|-----------------|---------------------|
| **Wallet Creation** | Server creates | Client creates locally |
| **prepare_multisig** | Server executes | Client executes locally |
| **Private Keys** | Temporarily on server | NEVER leave client |
| **make_multisig** | Server executes | Client executes locally |
| **Server Role** | Wallet manager | Pure coordinator |
| **Routes** | `/api/escrow/*` | `/api/v2/escrow/*` |

## Testing

### Unit Tests

```bash
# Test coordination logic
cargo test --package server coordination

# Test handlers
cargo test --package server noncustodial
```

### Integration Tests

See `server/tests/noncustodial/` for E2E tests that:
1. Start 3 local `monero-wallet-rpc` instances
2. Register each with coordinator
3. Coordinate exchange
4. Verify multisig created locally (not on server)

### Manual Testing

```bash
# 1. Start 3 wallet RPCs
monero-wallet-rpc --testnet --rpc-bind-port 18083 --disable-rpc-login &
monero-wallet-rpc --testnet --rpc-bind-port 18084 --disable-rpc-login &
monero-wallet-rpc --testnet --rpc-bind-port 18085 --disable-rpc-login &

# 2. Start server
cargo run --release --bin server

# 3. Register buyer
curl -X POST http://localhost:8080/api/v2/escrow/register-wallet \
  -H "Content-Type: application/json" \
  -d '{
    "escrow_id": "test_esc_123",
    "role": "buyer",
    "rpc_url": "http://127.0.0.1:18083"
  }'

# 4. Register seller
curl -X POST http://localhost:8080/api/v2/escrow/register-wallet \
  -H "Content-Type: application/json" \
  -d '{
    "escrow_id": "test_esc_123",
    "role": "seller",
    "rpc_url": "http://127.0.0.1:18084"
  }'

# 5. Register arbiter
curl -X POST http://localhost:8080/api/v2/escrow/register-wallet \
  -H "Content-Type: application/json" \
  -d '{
    "escrow_id": "test_esc_123",
    "role": "arbiter",
    "rpc_url": "http://127.0.0.1:18085"
  }'

# 6. Check status
curl http://localhost:8080/api/v2/escrow/coordination-status/test_esc_123

# 7. Coordinate exchange
curl -X POST http://localhost:8080/api/v2/escrow/coordinate-exchange \
  -H "Content-Type: application/json" \
  -d '{"escrow_id": "test_esc_123"}'
```

## Migration Path

This is **Phase 1** of the migration plan (see `DOX/guides/MIGRATION-NON-CUSTODIAL-PLAN.md`).

**Current State:**
- ✅ Dual mode: Old custodial system still works
- ✅ New non-custodial endpoints available (`/api/v2/escrow/*`)
- ✅ Feature flag ready (can be environment-controlled)

**Next Phases:**
- Phase 2: User CLI and migration guide
- Phase 3: Deprecate custodial mode
- Phase 4: Remove custodial code entirely

## References

- **Haveno DEX:** https://github.com/haveno-dex/haveno
  - Inspiration for pure coordinator architecture
  - Similar pattern: clients run local wallets, server coordinates
- **Migration Plan:** `/DOX/guides/MIGRATION-NON-CUSTODIAL-PLAN.md`
- **Audit Report:** Previous non-custodial audits (now outdated)

---

**Next Steps:**
1. Implement CLI for clients (`cli/src/noncustodial_client.rs`)
2. Create E2E tests with 3 wallet instances
3. Document user workflow
4. Add health checks and monitoring
