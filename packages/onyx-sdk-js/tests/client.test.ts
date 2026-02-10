/**
 * Onyx SDK Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  OnyxClient,
  OnyxApiError,
  AuthenticationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  TimeoutError,
  NetworkError,
  xmrToPiconero,
  piconeroToXmr,
  formatXmr,
  isValidMainnetAddress,
  verifyWebhookSignature,
  parseWebhookPayload,
} from '../src/index.js';

// ============================================================================
// Mock Fetch
// ============================================================================

/**
 * Mock fetch that matches on URL pathname.
 * Keys must include the full pathname as seen by `new URL(url).pathname`.
 * With default baseUrl 'https://onyx-escrow.com/api', an SDK path of
 * '/v1/escrows/create' produces pathname '/api/v1/escrows/create'.
 */
function createMockFetch(responses: Map<string, { status: number; body: unknown }>) {
  return vi.fn(async (url: string, options?: RequestInit) => {
    const path = new URL(url).pathname;
    const key = `${options?.method ?? 'GET'}:${path}`;
    const response = responses.get(key);

    if (!response) {
      return {
        ok: false,
        status: 404,
        statusText: 'Not Found',
        headers: new Headers(),
        text: async () =>
          JSON.stringify({
            success: false,
            error: { code: 'NOT_FOUND', message: 'Endpoint not found' },
          }),
      };
    }

    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      statusText: 'OK',
      headers: new Headers(),
      text: async () => JSON.stringify(response.body),
    };
  });
}

// ============================================================================
// Client Tests
// ============================================================================

describe('OnyxClient', () => {
  it('should throw if no API key provided', () => {
    expect(() => new OnyxClient({ apiKey: '' })).toThrow('API key is required');
  });

  it('should throw if API key has invalid format', () => {
    expect(() => new OnyxClient({ apiKey: 'invalid_key' })).toThrow(
      'Invalid API key format'
    );
  });

  it('should create client with valid API key', () => {
    const client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      fetch: vi.fn(),
    });
    expect(client).toBeInstanceOf(OnyxClient);
  });

  it('should use custom base URL', async () => {
    const mockFetch = createMockFetch(
      new Map([['GET:/custom/health', { status: 200, body: { status: 'ok' } }]])
    );

    const client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      baseUrl: 'https://custom.api.com/custom',
      fetch: mockFetch as unknown as typeof fetch,
    });

    await client.health();

    expect(mockFetch).toHaveBeenCalledWith(
      'https://custom.api.com/custom/health',
      expect.any(Object)
    );
  });
});

// ============================================================================
// Escrow Resource Tests
// ============================================================================

describe('EscrowResource', () => {
  let client: OnyxClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  const mockEscrow = {
    id: 'esc_abc123',
    status: 'pending_funding',
    buyer_address: '4Buyer...',
    seller_address: '4Seller...',
    amount: '1000000000000',
    fee: '10000000000',
    deposit_address: '4Deposit...',
    description: null,
    external_id: null,
    metadata: null,
    created_at: '2024-01-15T10:00:00Z',
    updated_at: '2024-01-15T10:00:00Z',
    expires_at: '2024-01-16T10:00:00Z',
    funded_at: null,
    released_at: null,
    release_txid: null,
  };

  const mockCreateResponse = {
    escrow_id: 'esc_abc123',
    status: 'pending_counterparty',
    creator_role: 'buyer',
    join_link: '/join/esc_abc123',
  };

  beforeEach(() => {
    // SDK paths: /v1/escrows/create, /v1/escrows/{id}, /v1/user/escrows, /v1/escrows/{id}/release
    // With default baseUrl https://onyx-escrow.com/api → pathname prefix is /api
    mockFetch = createMockFetch(
      new Map([
        [
          'POST:/api/v1/escrows/create',
          { status: 201, body: mockCreateResponse },
        ],
        [
          'GET:/api/v1/escrows/esc_abc123',
          { status: 200, body: { success: true, data: mockEscrow } },
        ],
        [
          'GET:/api/v1/user/escrows',
          {
            status: 200,
            body: {
              success: true,
              data: {
                escrows: [mockEscrow],
                next_cursor: null,
                total_count: 1,
              },
            },
          },
        ],
        [
          'POST:/api/v1/escrows/esc_abc123/release',
          {
            status: 200,
            body: {
              success: true,
              data: {
                escrow: { ...mockEscrow, status: 'released' },
                txid: 'tx_123abc',
              },
            },
          },
        ],
      ])
    );

    client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      fetch: mockFetch as unknown as typeof fetch,
    });
  });

  it('should create escrow', async () => {
    const result = await client.escrow.create({
      amount: 1_000_000_000_000n,
      creator_role: 'buyer',
      description: 'Test escrow',
    });

    expect(result.escrow_id).toBe('esc_abc123');
    expect(result.status).toBe('pending_counterparty');
    expect(result.join_link).toBe('/join/esc_abc123');
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/v1/escrows/create'),
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('"amount":1000000000000'),
      })
    );
  });

  it('should get escrow by ID', async () => {
    const escrow = await client.escrow.get('esc_abc123');
    expect(escrow.id).toBe('esc_abc123');
  });

  it('should list escrows', async () => {
    const response = await client.escrow.list();
    expect(response.escrows).toHaveLength(1);
    expect(response.total_count).toBe(1);
  });

  it('should release escrow', async () => {
    const response = await client.escrow.release({
      escrow_id: 'esc_abc123',
      recipient_address: '4Seller...',
    });

    expect(response.escrow.status).toBe('released');
    expect(response.txid).toBe('tx_123abc');
  });
});

// ============================================================================
// Webhook Resource Tests
// ============================================================================

describe('WebhookResource', () => {
  let client: OnyxClient;

  const mockWebhook = {
    id: 'wh_abc123',
    url: 'https://example.com/webhooks',
    events: ['escrow.funded', 'escrow.released'],
    active: true,
    created_at: '2024-01-15T10:00:00Z',
    updated_at: '2024-01-15T10:00:00Z',
    last_delivery_status: null,
    last_delivery_at: null,
  };

  beforeEach(() => {
    // Webhook SDK paths: /webhooks, /webhooks/{id}
    // With default baseUrl https://onyx-escrow.com/api → pathname prefix is /api
    const mockFetch = createMockFetch(
      new Map([
        [
          'POST:/api/webhooks',
          { status: 201, body: { success: true, data: mockWebhook } },
        ],
        [
          'GET:/api/webhooks/wh_abc123',
          { status: 200, body: { success: true, data: mockWebhook } },
        ],
        [
          'GET:/api/webhooks',
          { status: 200, body: { success: true, data: { webhooks: [mockWebhook], count: 1 } } },
        ],
        [
          'PATCH:/api/webhooks/wh_abc123',
          {
            status: 200,
            body: { success: true, data: { ...mockWebhook, active: false } },
          },
        ],
        ['DELETE:/api/webhooks/wh_abc123', { status: 204, body: null }],
      ])
    );

    client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      fetch: mockFetch as unknown as typeof fetch,
    });
  });

  it('should create webhook', async () => {
    const webhook = await client.webhooks.create({
      url: 'https://example.com/webhooks',
      events: ['escrow.funded', 'escrow.released'],
    });

    expect(webhook.id).toBe('wh_abc123');
  });

  it('should get webhook by ID', async () => {
    const webhook = await client.webhooks.get('wh_abc123');
    expect(webhook.id).toBe('wh_abc123');
  });

  it('should list webhooks', async () => {
    const response = await client.webhooks.list();
    expect(response.webhooks).toHaveLength(1);
  });

  it('should update webhook', async () => {
    const webhook = await client.webhooks.update('wh_abc123', { active: false });
    expect(webhook.active).toBe(false);
  });

  it('should delete webhook', async () => {
    await expect(client.webhooks.delete('wh_abc123')).resolves.toBeUndefined();
  });
});

// ============================================================================
// Error Handling Tests
// ============================================================================

describe('Error Handling', () => {
  it('should handle 401 authentication errors', async () => {
    const mockFetch = createMockFetch(
      new Map([
        [
          'GET:/api/health',
          {
            status: 401,
            body: {
              success: false,
              error: { code: 'INVALID_API_KEY', message: 'Invalid API key' },
            },
          },
        ],
      ])
    );

    const client = new OnyxClient({
      apiKey: 'nxs_test_invalid',
      fetch: mockFetch as unknown as typeof fetch,
    });

    await expect(client.health()).rejects.toThrow(AuthenticationError);
  });

  it('should handle 404 not found errors', async () => {
    const mockFetch = createMockFetch(
      new Map([
        [
          'GET:/api/v1/escrows/esc_notfound',
          {
            status: 404,
            body: {
              success: false,
              error: { code: 'NOT_FOUND', message: 'Escrow not found' },
            },
          },
        ],
      ])
    );

    const client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      fetch: mockFetch as unknown as typeof fetch,
    });

    await expect(client.escrow.get('esc_notfound')).rejects.toThrow(NotFoundError);
  });

  it('should handle 400 validation errors', async () => {
    const mockFetch = createMockFetch(
      new Map([
        [
          'POST:/api/v1/escrows/create',
          {
            status: 400,
            body: {
              success: false,
              error: {
                code: 'VALIDATION_ERROR',
                message: 'Invalid address',
                details: { field: 'buyer_address' },
              },
            },
          },
        ],
      ])
    );

    const client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      fetch: mockFetch as unknown as typeof fetch,
    });

    await expect(
      client.escrow.create({
        amount: 1000n,
        creator_role: 'buyer',
      })
    ).rejects.toThrow(ValidationError);
  });

  it('should handle 429 rate limit errors', async () => {
    const mockFetch = vi.fn(async () => ({
      ok: false,
      status: 429,
      statusText: 'Too Many Requests',
      headers: new Headers({ 'Retry-After': '120' }),
      text: async () =>
        JSON.stringify({
          success: false,
          error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Rate limit exceeded' },
        }),
    }));

    const client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      fetch: mockFetch as unknown as typeof fetch,
    });

    try {
      await client.health();
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(RateLimitError);
      expect((error as RateLimitError).retryAfter).toBe(120);
    }
  });

  it('should handle timeout errors', async () => {
    const mockFetch = vi.fn(
      () =>
        new Promise((_, reject) => {
          setTimeout(() => {
            const abortError = new Error('Aborted');
            abortError.name = 'AbortError';
            reject(abortError);
          }, 10);
        })
    );

    const client = new OnyxClient({
      apiKey: 'nxs_test_abc123',
      timeout: 5,
      fetch: mockFetch as unknown as typeof fetch,
    });

    await expect(client.health()).rejects.toThrow(TimeoutError);
  });

  it('should identify retryable errors', () => {
    const rateLimitError = new RateLimitError('Rate limit', 60);
    expect(rateLimitError.isRetryable()).toBe(true);

    const validationError = new ValidationError('Invalid input');
    expect(validationError.isRetryable()).toBe(false);
  });

  it('should serialize errors to JSON', () => {
    const error = new OnyxApiError(
      'Test error',
      'VALIDATION_ERROR',
      400,
      'req_123',
      { field: 'test' }
    );

    const json = error.toJSON();
    expect(json).toEqual({
      name: 'OnyxApiError',
      message: 'Test error',
      code: 'VALIDATION_ERROR',
      statusCode: 400,
      requestId: 'req_123',
      details: { field: 'test' },
    });
  });
});

// ============================================================================
// Utility Function Tests
// ============================================================================

describe('Utility Functions', () => {
  describe('xmrToPiconero', () => {
    it('should convert whole numbers', () => {
      expect(xmrToPiconero(1)).toBe(1_000_000_000_000n);
      expect(xmrToPiconero(10)).toBe(10_000_000_000_000n);
    });

    it('should convert decimals', () => {
      expect(xmrToPiconero(1.5)).toBe(1_500_000_000_000n);
      expect(xmrToPiconero(0.001)).toBe(1_000_000_000n);
    });

    it('should handle small amounts', () => {
      // 0.000001 XMR = 1,000,000 piconero
      expect(xmrToPiconero(0.000001)).toBe(1_000_000n);
    });
  });

  describe('piconeroToXmr', () => {
    it('should convert to XMR', () => {
      expect(piconeroToXmr(1_000_000_000_000n)).toBe(1);
      expect(piconeroToXmr(1_500_000_000_000n)).toBe(1.5);
    });

    it('should handle string input', () => {
      expect(piconeroToXmr('1000000000000')).toBe(1);
    });
  });

  describe('formatXmr', () => {
    it('should format with default decimals', () => {
      expect(formatXmr(1_500_000_000_000n)).toBe('1.500000000000 XMR');
    });

    it('should format with custom decimals', () => {
      expect(formatXmr(1_500_000_000_000n, 4)).toBe('1.5000 XMR');
    });
  });

  describe('isValidMainnetAddress', () => {
    it('should validate standard addresses', () => {
      const validAddress = '4' + 'A'.repeat(94);
      expect(isValidMainnetAddress(validAddress)).toBe(true);
    });

    it('should validate integrated addresses', () => {
      const validIntegrated = '4' + 'A'.repeat(105);
      expect(isValidMainnetAddress(validIntegrated)).toBe(true);
    });

    it('should validate subaddresses', () => {
      const validSubaddress = '8' + 'A'.repeat(94);
      expect(isValidMainnetAddress(validSubaddress)).toBe(true);
    });

    it('should reject invalid addresses', () => {
      expect(isValidMainnetAddress('invalid')).toBe(false);
      expect(isValidMainnetAddress('5' + 'A'.repeat(94))).toBe(false);
      expect(isValidMainnetAddress('')).toBe(false);
    });

    it('should reject non-string input', () => {
      // @ts-expect-error Testing invalid input
      expect(isValidMainnetAddress(null)).toBe(false);
      // @ts-expect-error Testing invalid input
      expect(isValidMainnetAddress(123)).toBe(false);
    });
  });
});

// ============================================================================
// Webhook Signature Verification Tests
// ============================================================================

describe('Webhook Signature Verification', () => {
  const secret = 'whsec_test_secret_123';
  const payload = { event_type: 'escrow.funded', data: { id: 'esc_123' } };

  it('should verify valid signature', async () => {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const payloadString = JSON.stringify(payload);
    const signedPayload = `${timestamp}.${payloadString}`;

    // Compute signature manually
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signatureBuffer = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(signedPayload)
    );
    const signature = Array.from(new Uint8Array(signatureBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    const isValid = await verifyWebhookSignature(
      payload,
      signature,
      timestamp,
      secret
    );

    expect(isValid).toBe(true);
  });

  it('should reject invalid signature', async () => {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const isValid = await verifyWebhookSignature(
      payload,
      'invalid_signature',
      timestamp,
      secret
    );

    expect(isValid).toBe(false);
  });

  it('should reject expired timestamp', async () => {
    const oldTimestamp = String(Math.floor(Date.now() / 1000) - 600); // 10 minutes ago
    const isValid = await verifyWebhookSignature(
      payload,
      'any_signature',
      oldTimestamp,
      secret
    );

    expect(isValid).toBe(false);
  });
});

describe('parseWebhookPayload', () => {
  it('should parse valid payload', () => {
    const payload = {
      event_id: 'evt_123',
      event_type: 'escrow.funded',
      timestamp: '2024-01-15T10:00:00Z',
      api_version: '2024-01',
      data: {
        escrow: { id: 'esc_123', status: 'funded' },
      },
    };

    const parsed = parseWebhookPayload(payload);
    expect(parsed.event_id).toBe('evt_123');
    expect(parsed.event_type).toBe('escrow.funded');
  });

  it('should parse JSON string payload', () => {
    const payloadStr = JSON.stringify({
      event_id: 'evt_123',
      event_type: 'escrow.funded',
      timestamp: '2024-01-15T10:00:00Z',
      api_version: '2024-01',
      data: { escrow: {} },
    });

    const parsed = parseWebhookPayload(payloadStr);
    expect(parsed.event_id).toBe('evt_123');
  });

  it('should throw on invalid payload', () => {
    expect(() => parseWebhookPayload({})).toThrow('missing event_id');
    expect(() => parseWebhookPayload({ event_id: 'evt_123' })).toThrow(
      'missing event_type'
    );
    expect(() => parseWebhookPayload('invalid json')).toThrow('not valid JSON');
  });
});
