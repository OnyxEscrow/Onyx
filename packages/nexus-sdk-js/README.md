# @nexus-escrow/sdk

TypeScript SDK for the NEXUS Escrow-as-a-Service (EaaS) API. Non-custodial Monero escrow with FROST 2-of-3 threshold signing.

## Features

- Full TypeScript support with comprehensive type definitions
- Zero external dependencies (uses native `fetch`)
- Works in Browser and Node.js (18+)
- Tree-shakeable ESM exports
- Automatic retry handling for rate limits
- Webhook signature verification (HMAC-SHA256)
- Complete FROST DKG + signing flow
- E2EE escrow chat (X25519 + ChaCha20Poly1305)
- Fee estimation and daemon health monitoring

## Installation

```bash
npm install @nexus-escrow/sdk
# or
yarn add @nexus-escrow/sdk
# or
pnpm add @nexus-escrow/sdk
```

## Quick Start

```typescript
import { NexusClient, xmrToPiconero } from '@nexus-escrow/sdk';

const client = new NexusClient({
  apiKey: process.env.NEXUS_API_KEY!,
  baseUrl: 'https://your-nexus-instance.com',
});

// Create an escrow
const escrow = await client.escrow.create({
  buyer_address: '4BuyerMoneroAddress...',
  seller_address: '4SellerMoneroAddress...',
  amount: xmrToPiconero(1.5), // 1.5 XMR
  description: 'Purchase of item #123',
});

console.log(`Escrow ID: ${escrow.id}`);
console.log(`Deposit to: ${escrow.deposit_address}`);
```

## API Reference

### NexusClient

Main client with all resource accessors.

```typescript
const client = new NexusClient({
  apiKey: 'nxs_live_...', // Required
  baseUrl: 'https://api.nexus-escrow.com', // Optional
  timeout: 30000, // Optional, ms
});

// Resource accessors:
client.escrow    // Escrow lifecycle
client.frost     // FROST DKG + signing
client.webhooks  // Webhook management
client.fees      // Fee estimation
client.analytics // Usage analytics
client.apiKeys   // API key management
client.chat      // E2EE escrow chat
```

### Escrow Operations

```typescript
// Create
const escrow = await client.escrow.create({
  buyer_address: '4...',
  seller_address: '4...',
  amount: 1_000_000_000_000n,
});

// Get
const escrow = await client.escrow.get('escrow-id');

// List with filters
const { escrows } = await client.escrow.list({ status: 'funded', limit: 20 });

// Join (counterparty)
await client.escrow.join('escrow-id');

// Lifecycle
await client.escrow.notifyFunding('escrow-id', { tx_hash: '...' });
await client.escrow.markDelivered('escrow-id');
await client.escrow.confirmDelivery('escrow-id');
await client.escrow.release({ escrow_id: '...', recipient_address: '4...' });
await client.escrow.refund('escrow-id');
await client.escrow.dispute({ escrow_id: '...', reason: '...', raised_by: 'buyer' });
await client.escrow.resolve({ escrow_id: '...', winner: 'buyer' });

// Addresses
await client.escrow.setPayoutAddress('escrow-id', { payout_address: '4...' });
await client.escrow.setRefundAddress('escrow-id', { refund_address: '4...' });
await client.escrow.getMultisigAddress('escrow-id');
```

### FROST DKG + Signing

Complete threshold signature flow for 2-of-3 multisig.

```typescript
// Initialize DKG
const status = await client.frost.initDkg('escrow-id');

// DKG Round 1
await client.frost.submitRound1('escrow-id', {
  role: 'buyer',
  package: 'hex-encoded-round1-package',
});
const round1 = await client.frost.getRound1Packages('escrow-id');

// DKG Round 2
await client.frost.submitRound2('escrow-id', {
  role: 'buyer',
  packages: { '1': 'hex-for-vendor', '2': 'hex-for-arbiter' },
});
const round2 = await client.frost.getRound2Packages('escrow-id', 'buyer');

// Complete DKG
await client.frost.completeDkg('escrow-id', {
  group_pubkey: '64-hex-chars',
  multisig_address: '95-char-monero-address',
  multisig_view_key: '64-hex-chars',
});

// Get Lagrange coefficients
const lagrange = await client.frost.getLagrangeCoefficients('buyer', 'vendor');

// Signing
await client.frost.initSigning('escrow-id', {
  action: 'release',
  destination_address: '4...',
});
await client.frost.submitNonceCommitment('escrow-id', {
  role: 'buyer',
  hiding_nonce_commitment: '...',
  binding_nonce_commitment: '...',
});
await client.frost.submitPartialSignature('escrow-id', {
  role: 'buyer',
  partial_signature: '...',
});
const { tx_hash } = await client.frost.completeAndBroadcast('escrow-id');

// Shield backup
await client.frost.registerShield('escrow-id', { backup_id: '...', role: 'buyer' });
await client.frost.verifyShield('escrow-id', { backup_id: '...' });

// Shipping flow
await client.frost.confirmShipped('escrow-id', {
  tracking_info: 'Shipped via DHL',
  estimated_delivery_days: 7,
});
await client.frost.confirmReceipt('escrow-id', {
  consent_confirmed: true,
});
```

### Webhooks

```typescript
// Create (returns HMAC secret once)
const { webhook, secret } = await client.webhooks.create({
  url: 'https://example.com/webhooks/nexus',
  events: ['escrow.funded', 'escrow.released'],
});

// CRUD
const { webhooks } = await client.webhooks.list();
const wh = await client.webhooks.get('webhook-id');
await client.webhooks.update('webhook-id', { events: ['*'] });
await client.webhooks.delete('webhook-id');

// Control
await client.webhooks.activate('webhook-id');
await client.webhooks.deactivate('webhook-id');
const { secret: newSecret } = await client.webhooks.rotateSecret('webhook-id');

// Deliveries
const { deliveries } = await client.webhooks.getDeliveries('webhook-id');
await client.webhooks.retryDelivery('delivery-id');
const stats = await client.webhooks.getStats('webhook-id');
```

### Webhook Signature Verification

```typescript
import { verifyWebhookSignature, parseWebhookPayload } from '@nexus-escrow/sdk';

app.post('/webhooks/nexus', async (req, res) => {
  const isValid = await verifyWebhookSignature(
    req.body,
    req.headers['x-nexus-signature'],
    req.headers['x-nexus-timestamp'],
    process.env.WEBHOOK_SECRET!
  );

  if (!isValid) return res.status(401).send('Invalid signature');

  const event = parseWebhookPayload(req.body);
  switch (event.event_type) {
    case 'escrow.funded':
      // Handle funding...
      break;
    case 'escrow.released':
      // Handle release...
      break;
  }

  res.status(200).send('OK');
});
```

### Fee Estimation

```typescript
// Single priority estimate
const fee = await client.fees.estimate('normal');
console.log(`Fee: ${fee.fee_xmr} (${fee.live ? 'live' : 'cached'})`);

// All priorities
const all = await client.fees.allEstimates();
for (const est of all.estimates) {
  console.log(`${est.priority}: ${est.fee_xmr}`);
}

// Daemon health
const health = await client.fees.daemonHealth();
console.log(`${health.healthy}/${health.total} endpoints healthy`);

// Client fee config (B2B)
const config = await client.fees.getClientFeeConfig();
const estimate = await client.fees.estimateClientFees(1_000_000_000_000);
console.log(`Fee: ${estimate.fee_atomic} piconero (${estimate.fee_percent}%)`);
```

### Analytics

```typescript
const usage = await client.analytics.getUsage('30d');
console.log(`Escrows: ${usage.total_escrows}`);
console.log(`Active: ${usage.active_escrows}`);
console.log(`Volume: ${usage.total_volume_atomic} piconero`);
console.log(`API requests: ${usage.total_api_requests}`);
```

### API Keys

```typescript
// Create (raw key only shown once)
const { key } = await client.apiKeys.create({
  name: 'Production Key',
  csrf_token: csrfToken,
});
console.log(`Save this: ${key.raw_key}`);

// List
const { keys, total } = await client.apiKeys.list();

// Revoke / Delete
await client.apiKeys.revoke('key-id');
await client.apiKeys.delete('key-id');
```

### E2EE Escrow Chat

```typescript
// Register keypair
await client.chat.registerKeypair('escrow-id', {
  public_key: 'x25519-pubkey-hex',
});

// Get all participants' keys
const keypairs = await client.chat.getKeypairs('escrow-id');
if (keypairs.all_registered) {
  // Send encrypted message (encrypted separately for each participant)
  await client.chat.sendMessage('escrow-id', {
    encrypted_content_buyer: '...',
    encrypted_content_vendor: '...',
    encrypted_content_arbiter: '...',
    sender_ephemeral_pubkey: '...',
    nonce: '...',
  });
}

// Get messages
const { messages, has_more } = await client.chat.getMessages('escrow-id', {
  limit: 50,
});

// Mark as read
await client.chat.markRead('escrow-id', 'message-id');

// Export for dispute evidence
const evidence = await client.chat.exportForDispute('escrow-id');
```

## Utility Functions

```typescript
import { xmrToPiconero, piconeroToXmr, formatXmr, isValidMainnetAddress } from '@nexus-escrow/sdk';

xmrToPiconero(1.5);          // 1_500_000_000_000n
piconeroToXmr(1_500_000_000_000n); // 1.5
formatXmr(1_500_000_000_000n, 4);  // "1.5000 XMR"
isValidMainnetAddress('4...');      // true/false
```

## Error Handling

```typescript
import {
  NexusApiError,
  AuthenticationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  NetworkError,
  TimeoutError,
} from '@nexus-escrow/sdk';

try {
  await client.escrow.get('nonexistent');
} catch (error) {
  if (error instanceof NotFoundError) {
    console.log('Escrow not found');
  } else if (error instanceof RateLimitError) {
    console.log(`Retry after ${error.retryAfter}s`);
  } else if (error instanceof NexusApiError) {
    console.log(`${error.code}: ${error.message} (req: ${error.requestId})`);
  }
}
```

## Tree-Shaking

Import only what you need:

```typescript
import { EscrowResource, xmrToPiconero } from '@nexus-escrow/sdk/escrow';
import { verifyWebhookSignature } from '@nexus-escrow/sdk/webhooks';
import { FrostResource } from '@nexus-escrow/sdk/frost';
import { FeeResource } from '@nexus-escrow/sdk/fees';
import { AnalyticsResource } from '@nexus-escrow/sdk/analytics';
import { ChatResource } from '@nexus-escrow/sdk/chat';
```

## Environment Support

- **Node.js**: 18.0.0+
- **Browser**: All modern browsers with `fetch` support
- **Edge Runtime**: Cloudflare Workers, Vercel Edge Functions, Deno

## License

MIT
