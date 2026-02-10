/**
 * NEXUS SDK Client
 *
 * Main entry point for the NEXUS Escrow-as-a-Service API.
 * Provides access to all API resources: escrow, FROST DKG/signing,
 * webhooks, API keys, fees, analytics, and E2EE chat.
 */

import type { NexusClientConfig, ApiErrorResponse } from './types.js';
import { EscrowResource } from './escrow.js';
import { WebhookResource } from './webhooks.js';
import { FrostResource } from './frost.js';
import { FeeResource } from './fees.js';
import { AnalyticsResource } from './analytics.js';
import { ApiKeyResource } from './apikeys.js';
import { ChatResource } from './chat.js';
import {
  NexusApiError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  NetworkError,
  TimeoutError,
} from './errors.js';

const DEFAULT_BASE_URL = 'https://onyx-escrow.com/api';
const DEFAULT_TIMEOUT = 30_000;
const API_VERSION = '2025-01';

/**
 * NEXUS API Client
 *
 * @example
 * ```typescript
 * import { NexusClient } from '@nexus-escrow/sdk';
 *
 * const client = new NexusClient({
 *   apiKey: 'nxs_live_...',
 * });
 *
 * // Create an escrow
 * const escrow = await client.escrow.create({
 *   buyer_address: '4...',
 *   seller_address: '4...',
 *   amount: 1_000_000_000_000n,
 * });
 *
 * // FROST DKG
 * await client.frost.initDkg(escrow.id);
 *
 * // Fee estimation
 * const fee = await client.fees.estimate('normal');
 *
 * // Analytics
 * const usage = await client.analytics.getUsage('30d');
 * ```
 */
export class NexusClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly fetchFn: typeof fetch;

  /** Escrow lifecycle operations (create, fund, release, dispute, etc.) */
  public readonly escrow: EscrowResource;
  /** Webhook CRUD and delivery management */
  public readonly webhooks: WebhookResource;
  /** FROST DKG + threshold signing operations */
  public readonly frost: FrostResource;
  /** Fee estimation and daemon health */
  public readonly fees: FeeResource;
  /** API usage analytics */
  public readonly analytics: AnalyticsResource;
  /** API key management */
  public readonly apiKeys: ApiKeyResource;
  /** E2EE escrow chat */
  public readonly chat: ChatResource;

  constructor(config: NexusClientConfig) {
    if (!config.apiKey) {
      throw new Error('API key is required');
    }

    if (!config.apiKey.startsWith('nxs_')) {
      throw new Error('Invalid API key format: must start with "nxs_"');
    }

    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
    this.fetchFn = config.fetch ?? globalThis.fetch;

    if (!this.fetchFn) {
      throw new Error(
        'fetch is not available. Please provide a fetch implementation.'
      );
    }

    // Initialize resources
    const requestFn = this.request.bind(this);
    this.escrow = new EscrowResource(requestFn);
    this.webhooks = new WebhookResource(requestFn);
    this.frost = new FrostResource(requestFn);
    this.fees = new FeeResource(requestFn);
    this.analytics = new AnalyticsResource(requestFn);
    this.apiKeys = new ApiKeyResource(requestFn);
    this.chat = new ChatResource(requestFn);
  }

  /**
   * Make an authenticated API request
   */
  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const headers: Record<string, string> = {
      'X-API-Key': this.apiKey,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-Nexus-Version': API_VERSION,
    };

    // B2B API requires Idempotency-Key for mutation requests
    if (method !== 'GET' && path.startsWith('/v1/')) {
      headers['Idempotency-Key'] = crypto.randomUUID();
    }

    try {
      const requestInit: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      if (body !== undefined) {
        requestInit.body = JSON.stringify(body);
      }

      const response = await this.fetchFn(url, requestInit);

      clearTimeout(timeoutId);

      // Handle empty responses (204 No Content)
      if (response.status === 204) {
        return undefined as T;
      }

      const responseText = await response.text();
      let data: unknown;

      try {
        data = responseText ? JSON.parse(responseText) : undefined;
      } catch {
        throw new NetworkError(`Invalid JSON response: ${responseText.slice(0, 100)}`);
      }

      if (!response.ok) {
        throw this.handleErrorResponse(response, data as ApiErrorResponse);
      }

      // Extract data from wrapped response if present
      if (
        typeof data === 'object' &&
        data !== null &&
        'success' in data &&
        'data' in data
      ) {
        return (data as { success: boolean; data: T }).data;
      }

      return data as T;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof NexusApiError) {
        throw error;
      }

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new TimeoutError(this.timeout);
        }
        throw new NetworkError(error.message, error);
      }

      throw new NetworkError('Unknown error occurred');
    }
  }

  /**
   * Convert HTTP error response to appropriate error class
   */
  private handleErrorResponse(
    response: Response,
    data: ApiErrorResponse | undefined
  ): NexusApiError {
    const requestId = data?.meta?.request_id;

    // Handle standard API error response
    if (data?.error) {
      const { message, details } = data.error;

      switch (response.status) {
        case 401:
          return new AuthenticationError(message, requestId);
        case 403:
          return new AuthorizationError(message, requestId);
        case 404:
          return new NotFoundError(message, requestId);
        case 400:
          return new ValidationError(message, details, requestId);
        case 429: {
          const retryAfter = parseInt(
            response.headers.get('Retry-After') ?? '60',
            10
          );
          return new RateLimitError(message, retryAfter, requestId);
        }
        default:
          return NexusApiError.fromResponse(data, response.status);
      }
    }

    // Handle non-standard error responses
    return new NexusApiError(
      `HTTP ${response.status}: ${response.statusText}`,
      'INTERNAL_ERROR',
      response.status,
      requestId
    );
  }

  /**
   * Get API health status
   */
  async health(): Promise<{ status: string }> {
    return this.request('GET', '/health');
  }
}
