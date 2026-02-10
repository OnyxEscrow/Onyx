/**
 * NEXUS SDK Webhook Operations
 */

import type {
  CreateWebhookParams,
  CreateWebhookResponse,
  Webhook,
  UpdateWebhookParams,
  WebhookDelivery,
  WebhookPayload,
} from './types.js';

type RequestFn = <T>(method: string, path: string, body?: unknown) => Promise<T>;

/**
 * Webhook resource operations
 */
export class WebhookResource {
  private readonly request: RequestFn;

  constructor(request: RequestFn) {
    this.request = request;
  }

  /**
   * Create a new webhook. Returns the HMAC secret (only shown once).
   *
   * POST /api/webhooks
   */
  async create(params: CreateWebhookParams): Promise<CreateWebhookResponse> {
    return this.request<CreateWebhookResponse>('POST', '/webhooks', params);
  }

  /**
   * Get a webhook by ID
   *
   * GET /api/webhooks/{id}
   */
  async get(webhookId: string): Promise<Webhook> {
    return this.request<Webhook>('GET', `/webhooks/${webhookId}`);
  }

  /**
   * List all webhooks for the authenticated API key
   *
   * GET /api/webhooks
   */
  async list(): Promise<{ webhooks: Webhook[]; count: number }> {
    return this.request('GET', '/webhooks');
  }

  /**
   * Update a webhook
   *
   * PATCH /api/webhooks/{id}
   */
  async update(webhookId: string, params: UpdateWebhookParams): Promise<Webhook> {
    return this.request<Webhook>('PATCH', `/webhooks/${webhookId}`, params);
  }

  /**
   * Delete a webhook
   *
   * DELETE /api/webhooks/{id}
   */
  async delete(webhookId: string): Promise<{ success: boolean; message: string }> {
    return this.request('DELETE', `/webhooks/${webhookId}`);
  }

  /**
   * Activate a webhook
   *
   * POST /api/webhooks/{id}/activate
   */
  async activate(webhookId: string): Promise<{ success: boolean; message: string }> {
    return this.request('POST', `/webhooks/${webhookId}/activate`);
  }

  /**
   * Deactivate a webhook
   *
   * POST /api/webhooks/{id}/deactivate
   */
  async deactivate(webhookId: string): Promise<{ success: boolean; message: string }> {
    return this.request('POST', `/webhooks/${webhookId}/deactivate`);
  }

  /**
   * Rotate the webhook HMAC secret. Returns new secret (only shown once).
   *
   * POST /api/webhooks/{id}/rotate-secret
   */
  async rotateSecret(webhookId: string): Promise<{
    webhook_id: string;
    secret: string;
    message: string;
  }> {
    return this.request('POST', `/webhooks/${webhookId}/rotate-secret`);
  }

  /**
   * Get delivery history for a webhook
   *
   * GET /api/webhooks/{id}/deliveries
   */
  async getDeliveries(
    webhookId: string,
    params?: { limit?: number }
  ): Promise<{ deliveries: WebhookDelivery[]; count: number }> {
    const searchParams = new URLSearchParams();
    if (params?.limit !== undefined) {
      searchParams.set('limit', String(params.limit));
    }
    const query = searchParams.toString();
    const path = query
      ? `/webhooks/${webhookId}/deliveries?${query}`
      : `/webhooks/${webhookId}/deliveries`;
    return this.request('GET', path);
  }

  /**
   * Retry a failed webhook delivery
   *
   * POST /api/webhooks/{webhookId}/deliveries/{deliveryId}/retry
   */
  async retryDelivery(webhookId: string, deliveryId: string): Promise<{ success: boolean; message: string }> {
    return this.request('POST', `/webhooks/${webhookId}/deliveries/${deliveryId}/retry`);
  }

  /**
   * Get delivery statistics for a webhook
   *
   * GET /api/webhooks/{id}/stats
   */
  async getStats(webhookId: string): Promise<{
    total: number;
    success: number;
    failed: number;
    pending: number;
  }> {
    return this.request('GET', `/webhooks/${webhookId}/stats`);
  }
}

// ============================================================================
// Webhook Signature Verification
// ============================================================================

/**
 * Verify webhook signature.
 * Use this to verify that incoming webhook requests are authentic.
 *
 * @example
 * ```typescript
 * import { verifyWebhookSignature } from '@nexus-escrow/sdk';
 *
 * app.post('/webhooks/nexus', async (req, res) => {
 *   const signature = req.headers['x-nexus-signature'];
 *   const timestamp = req.headers['x-nexus-timestamp'];
 *
 *   const isValid = await verifyWebhookSignature(
 *     req.body,
 *     signature,
 *     timestamp,
 *     process.env.WEBHOOK_SECRET
 *   );
 *
 *   if (!isValid) {
 *     return res.status(401).send('Invalid signature');
 *   }
 *
 *   // Process the webhook...
 * });
 * ```
 */
export async function verifyWebhookSignature(
  payload: string | Record<string, unknown>,
  signature: string,
  timestamp: string,
  secret: string,
  options?: { tolerance?: number }
): Promise<boolean> {
  const tolerance = options?.tolerance ?? 300; // 5 minutes default

  // Check timestamp freshness
  const timestampNum = parseInt(timestamp, 10);
  const now = Math.floor(Date.now() / 1000);

  if (isNaN(timestampNum) || Math.abs(now - timestampNum) > tolerance) {
    return false;
  }

  // Compute expected signature
  const payloadString =
    typeof payload === 'string' ? payload : JSON.stringify(payload);
  const signedPayload = `${timestamp}.${payloadString}`;

  const expectedSignature = await computeHmacSha256(signedPayload, secret);

  // Constant-time comparison
  return timingSafeEqual(signature, expectedSignature);
}

/**
 * Parse and validate webhook payload
 *
 * @example
 * ```typescript
 * const event = parseWebhookPayload(req.body);
 * if (event.event_type === 'escrow.funded') {
 *   console.log(`Escrow ${event.data.escrow.id} is now funded`);
 * }
 * ```
 */
export function parseWebhookPayload(payload: unknown): WebhookPayload {
  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload);
    } catch {
      throw new Error('Invalid webhook payload: not valid JSON');
    }
  }

  if (typeof payload !== 'object' || payload === null) {
    throw new Error('Invalid webhook payload: expected object');
  }

  const p = payload as Record<string, unknown>;

  if (typeof p['event_id'] !== 'string') {
    throw new Error('Invalid webhook payload: missing event_id');
  }
  if (typeof p['event_type'] !== 'string') {
    throw new Error('Invalid webhook payload: missing event_type');
  }
  if (typeof p['timestamp'] !== 'string') {
    throw new Error('Invalid webhook payload: missing timestamp');
  }
  if (typeof p['data'] !== 'object' || p['data'] === null) {
    throw new Error('Invalid webhook payload: missing data');
  }

  return p as unknown as WebhookPayload;
}

// ============================================================================
// Internal Helpers
// ============================================================================

async function computeHmacSha256(message: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, messageData);
  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}
