# NEXUS Escrow Python SDK

Official Python SDK for the NEXUS Escrow-as-a-Service API. Create non-custodial Monero escrows with browser-based FROST multisig.

## Installation

```bash
pip install nexus-escrow
```

## Quick Start

```python
import asyncio
from nexus_escrow import NexusClient, EscrowStatus

async def main():
    async with NexusClient(api_key="nxs_your_api_key") as client:
        # Create an escrow
        escrow = await client.create_escrow(
            buyer_address="4...",   # Monero address
            seller_address="4...",  # Monero address
            amount=1_000_000_000_000,  # 1 XMR in piconero
            description="Payment for services",
        )
        print(f"Escrow created: {escrow.id}")
        print(f"Fund address: {escrow.escrow_address}")

        # Check escrow status
        escrow = await client.get_escrow(escrow.id)
        print(f"Status: {escrow.status}")

asyncio.run(main())
```

## Features

- Async/await support with `httpx`
- Full type hints with Pydantic v2 models
- Automatic retries for transient errors
- FROST DKG and threshold signing
- E2EE escrow chat (X25519 + ChaCha20Poly1305)
- Webhook signature verification
- Fee estimation (network + platform)
- API key management
- Context manager for resource cleanup

## Managers

All functionality is organized into managers accessible from the client:

| Manager | Access | Description |
|---------|--------|-------------|
| `EscrowManager` | `client.escrows` | Escrow CRUD and lifecycle |
| `DkgManager` | `client.dkg` | FROST Distributed Key Generation |
| `SigningManager` | `client.signing` | FROST threshold CLSAG signing |
| `WebhookManager` | `client.webhooks` | Webhook CRUD and verification |
| `FeeManager` | `client.fees` | Network and platform fee estimation |
| `AnalyticsManager` | `client.analytics` | Usage analytics |
| `ChatManager` | `client.chat` | E2EE escrow messaging |
| `ApiKeyManager` | `client.api_keys` | API key lifecycle |

## Usage

### Creating Escrows

```python
from nexus_escrow import NexusClient

async with NexusClient(api_key="nxs_...") as client:
    escrow = await client.escrows.create(
        buyer_address="4...",
        seller_address="4...",
        amount=5_000_000_000_000,  # 5 XMR
        description="Freelance project payment",
        metadata={"project_id": "proj_123"},
        expires_in_hours=72,
    )
```

### Escrow Lifecycle (Shipping Flow)

```python
# Vendor: confirm shipment
await client.escrows.confirm_shipped(
    escrow_id,
    tracking_info="USPS 1234567890",
    estimated_delivery_days=7,
)

# Buyer: confirm receipt and trigger release
await client.escrows.confirm_receipt(
    escrow_id,
    consent_confirmed=True,
    feedback="Excellent service",
)
```

### FROST DKG (Distributed Key Generation)

```python
# Initialize DKG for an escrow
await client.dkg.init(escrow_id)

# Each participant submits Round 1 package
await client.dkg.submit_round1(escrow_id, role="buyer", package=hex_round1)

# Get all Round 1 packages
packages = await client.dkg.get_round1_packages(escrow_id)

# Each participant submits Round 2 packages
await client.dkg.submit_round2(
    escrow_id, role="buyer", packages={"1": hex_pkg1, "2": hex_pkg2}
)

# Complete DKG with group public key
await client.dkg.complete(
    escrow_id,
    group_pubkey=hex_group_key,
    multisig_address="4...",
    multisig_view_key=hex_view_key,
)
```

### FROST Signing

```python
# Initialize signing session
tx_data = await client.signing.init(escrow_id)

# Each signer submits nonces
await client.signing.submit_nonces(
    escrow_id,
    role="buyer",
    r_public=hex_r,
    r_prime_public=hex_r_prime,
    commitment_hash=hex_commit,
)

# Each signer submits partial signature
await client.signing.submit_partial_signature(
    escrow_id,
    role="buyer",
    partial_signature=json_sig,
    partial_key_image=hex_ki,
)

# Aggregate and broadcast
result = await client.signing.complete(escrow_id)
print(f"TX broadcast: {result['tx_hash']}")
```

### Fee Estimation

```python
# Network fee estimate
estimate = await client.fees.estimate(priority="normal")
print(f"Fee for 2-output TX: {estimate.fee_xmr} XMR")

# All priority levels
all_fees = await client.fees.estimate_all()
print(f"Recommended: {all_fees.recommended}")

# Platform fee for a specific amount
platform_fee = await client.fees.estimate_client_fee(1_000_000_000_000)
print(f"Platform fee: {platform_fee.fee_percent}%")
print(f"Net amount: {platform_fee.net_amount_atomic} piconero")

# Daemon health
health = await client.fees.daemon_health()
print(f"Healthy daemons: {health.healthy}/{health.total}")
```

### Analytics

```python
stats = await client.analytics.usage(period="30d")
print(f"Total escrows: {stats.total_escrows}")
print(f"Volume: {stats.total_volume_atomic} piconero")
```

### E2EE Chat

```python
# Register X25519 keypair for encrypted messaging
await client.chat.register_keypair(escrow_id, public_key=hex_x25519_pub)

# Get all participants' public keys
keypairs = await client.chat.get_keypairs(escrow_id)

# Send encrypted message (encrypted 3x: buyer, vendor, arbiter)
await client.chat.send_message(
    escrow_id,
    encrypted_content_buyer=base64_buyer,
    encrypted_content_vendor=base64_vendor,
    encrypted_content_arbiter=base64_arbiter,
    sender_ephemeral_pubkey=hex_ephemeral,
    nonce=hex_nonce,
)

# Get messages
result = await client.chat.get_messages(escrow_id, limit=50)
```

### API Keys

```python
# Create a new API key
key = await client.api_keys.create("Production Key")
print(f"Key: {key['raw_key']}")  # Only shown once

# List all keys
keys = await client.api_keys.list()

# Revoke a key
await client.api_keys.revoke("key_id")
```

### Webhooks

#### Register a Webhook

```python
from nexus_escrow import WebhookEventType

webhook = await client.webhooks.register(
    url="https://your-app.com/webhooks/nexus",
    events=[
        WebhookEventType.ESCROW_FUNDED,
        WebhookEventType.ESCROW_RELEASED,
        WebhookEventType.ESCROW_SHIPPED,
        WebhookEventType.ESCROW_DISPUTED,
    ],
)
# Store webhook.secret securely for verification
```

#### Verify Webhook Signatures

```python
from nexus_escrow import WebhookManager, NexusWebhookVerificationError

@app.post("/webhooks/nexus")
async def handle_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("X-Nexus-Signature", "")
    timestamp = request.headers.get("X-Nexus-Timestamp")

    try:
        WebhookManager.verify_signature(
            payload=payload,
            signature=signature,
            secret=WEBHOOK_SECRET,
            timestamp=timestamp,
        )
    except NexusWebhookVerificationError:
        raise HTTPException(401, "Invalid signature")

    event = WebhookManager.parse_event(payload)

    if event.type == WebhookEventType.ESCROW_FUNDED:
        print(f"Escrow {event.escrow_id} was funded!")
```

#### Webhook Delivery Management

```python
# Get delivery history
deliveries = await client.webhooks.get_deliveries("whk_...", limit=50)

# Retry a failed delivery
await client.webhooks.retry_delivery("whk_...", "dlv_...")

# Get delivery statistics
stats = await client.webhooks.get_stats("whk_...")
```

### Handling Disputes

```python
# Open a dispute
escrow = await client.escrows.dispute(
    escrow_id="esc_...",
    reason="Seller did not deliver as agreed",
    evidence_urls=["https://example.com/screenshot.png"],
)

# Resolve dispute (arbitrator only)
from nexus_escrow import DisputeResolution

escrow = await client.escrows.resolve(
    escrow_id="esc_...",
    resolution=DisputeResolution.BUYER_WINS,
    reason="Seller failed to provide proof of delivery",
)
```

## Error Handling

```python
from nexus_escrow import (
    NexusApiError,
    NexusAuthenticationError,
    NexusNotFoundError,
    NexusValidationError,
    NexusRateLimitError,
)

try:
    escrow = await client.get_escrow("esc_invalid")
except NexusNotFoundError:
    print("Escrow not found")
except NexusAuthenticationError:
    print("Invalid API key")
except NexusValidationError as e:
    print(f"Validation error: {e.message}")
    print(f"Details: {e.details}")
except NexusRateLimitError as e:
    print(f"Rate limited, retry after {e.retry_after} seconds")
except NexusApiError as e:
    print(f"API error [{e.status_code}]: {e.message}")
```

## Configuration

```python
client = NexusClient(
    api_key="nxs_...",
    base_url="https://api.nexus.io",  # Default
    timeout=30.0,  # Request timeout in seconds
    max_retries=3,  # Retries for 5xx errors
)
```

## API Reference

### EscrowManager (`client.escrows`)

| Method | Description |
|--------|-------------|
| `create(...)` | Create a new escrow |
| `get(id)` | Get escrow by ID |
| `list(...)` | List escrows with filters |
| `get_funding_instructions(id)` | Get funding address/amount |
| `check_funding(id)` | Check if escrow is funded |
| `join(id)` | Join escrow as counterparty |
| `notify_funding(id)` | Notify platform of funding |
| `mark_delivered(id)` | Mark goods as delivered (vendor) |
| `confirm_delivery(id)` | Confirm delivery receipt (buyer) |
| `release(id, signature)` | Release funds to seller |
| `refund(id)` | Refund funds to buyer |
| `dispute(id, reason)` | Open a dispute |
| `resolve(id, resolution)` | Resolve a dispute |
| `cancel(id)` | Cancel unfunded escrow |
| `confirm_shipped(id)` | Confirm shipment (vendor) |
| `confirm_receipt(id)` | Confirm receipt and trigger release (buyer) |
| `set_payout_address(id, address)` | Set vendor payout address |
| `set_refund_address(id, address)` | Set buyer refund address |

### DkgManager (`client.dkg`)

| Method | Description |
|--------|-------------|
| `init(id)` | Initialize FROST DKG |
| `submit_round1(id, role, package)` | Submit Round 1 package |
| `get_round1_packages(id)` | Get all Round 1 packages |
| `submit_round2(id, role, packages)` | Submit Round 2 packages |
| `get_round2_packages(id, role)` | Get Round 2 packages for role |
| `complete(id, group_pubkey, ...)` | Complete DKG |
| `get_status(id)` | Get DKG status |
| `get_lagrange_coefficients(...)` | Get Lagrange coefficients |

### SigningManager (`client.signing`)

| Method | Description |
|--------|-------------|
| `init(id)` | Initialize signing session |
| `submit_nonces(id, ...)` | Submit nonce commitment |
| `get_nonces(id)` | Get all nonces |
| `submit_partial_signature(id, ...)` | Submit partial CLSAG sig |
| `get_status(id)` | Get signing status |
| `complete(id)` | Aggregate and broadcast TX |
| `get_tx_data(id)` | Get TX data for signing |
| `get_first_signer_data(id)` | Get first signer data |

### WebhookManager (`client.webhooks`)

| Method | Description |
|--------|-------------|
| `register(url, events)` | Register a new webhook |
| `get(id)` | Get webhook by ID |
| `list()` | List all webhooks |
| `update(id, ...)` | Update webhook config |
| `delete(id)` | Delete a webhook |
| `activate(id)` | Activate a webhook |
| `deactivate(id)` | Deactivate a webhook |
| `rotate_secret(id)` | Rotate signing secret |
| `test(id)` | Send test event |
| `get_deliveries(id)` | Get delivery history |
| `retry_delivery(id, delivery_id)` | Retry failed delivery |
| `get_stats(id)` | Get delivery statistics |
| `verify_signature(...)` | Verify webhook signature (static) |
| `parse_event(payload)` | Parse webhook payload (static) |

### FeeManager (`client.fees`)

| Method | Description |
|--------|-------------|
| `estimate(priority)` | Get fee estimate |
| `estimate_all()` | Get all priority estimates |
| `daemon_health()` | Get daemon health status |
| `get_client_fees()` | Get client fee config |
| `estimate_client_fee(amount)` | Estimate platform fee |

### AnalyticsManager (`client.analytics`)

| Method | Description |
|--------|-------------|
| `usage(period)` | Get usage analytics |

### ChatManager (`client.chat`)

| Method | Description |
|--------|-------------|
| `register_keypair(id, public_key)` | Register X25519 keypair |
| `get_keypairs(id)` | Get all participants' keys |
| `send_message(id, ...)` | Send E2EE message |
| `get_messages(id)` | Get message history |
| `mark_read(id, message_id)` | Mark message as read |
| `export_for_dispute(id)` | Export chat for disputes |

### ApiKeyManager (`client.api_keys`)

| Method | Description |
|--------|-------------|
| `create(name)` | Create new API key |
| `list()` | List all API keys |
| `get(id)` | Get API key details |
| `revoke(id)` | Revoke an API key |
| `delete(id)` | Permanently delete key |

## Types

### Enums

- `EscrowStatus`: `CREATED`, `FUNDED`, `SHIPPED`, `RELEASING`, `RELEASED`, `DISPUTED`, `RESOLVED`, `CANCELLED`, `EXPIRED`
- `DisputeResolution`: `BUYER_WINS`, `SELLER_WINS`, `SPLIT`
- `WebhookEventType`: `ESCROW_CREATED`, `ESCROW_FUNDED`, `ESCROW_SHIPPED`, `ESCROW_RELEASED`, etc.
- `FrostRole`: `BUYER`, `VENDOR`, `ARBITER`
- `FeePriority`: `UNIMPORTANT`, `NORMAL`, `ELEVATED`, `PRIORITY`
- `ApiKeyTier`: `FREE`, `PRO`, `ENTERPRISE`

### Models

- `Escrow`: Escrow resource with all fields
- `EscrowList`: Paginated escrow list
- `FundingInstructions`: Address and amount for funding
- `DkgStatus`, `DkgParticipants`: DKG state tracking
- `LagrangeCoefficients`: Lagrange coefficients for signing
- `SigningStatus`, `TxSigningData`: Signing session state
- `FeeEstimate`, `AllFeeEstimates`: Network fee estimates
- `ClientFeeConfig`, `ClientFeeEstimate`: Platform fee info
- `DaemonHealth`, `DaemonHealthSummary`: Daemon status
- `UsageAnalytics`: Usage analytics
- `Webhook`, `WebhookList`, `WebhookEvent`: Webhook types
- `WebhookDelivery`, `WebhookDeliveryStats`: Delivery tracking
- `ChatKeypairResponse`, `ChatKeypairsDto`: Chat key exchange
- `ChatMessage`, `ChatMessageList`: Encrypted messages
- `ApiKeyInfo`, `ApiKeyCreationResponse`: API key types
- `UsageStats`: Account usage stats

## Requirements

- Python 3.10+
- httpx >= 0.24.0
- pydantic >= 2.0.0

## License

MIT
