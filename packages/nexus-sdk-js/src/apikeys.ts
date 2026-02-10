/**
 * NEXUS SDK API Key Management
 *
 * Session-authenticated endpoints for managing B2B API keys.
 */

import type { ApiKey, CreateApiKeyParams, ApiKeyCreationResponse } from './types.js';

type RequestFn = <T>(method: string, path: string, body?: unknown) => Promise<T>;

/**
 * API Key management resource
 *
 * @example
 * ```typescript
 * // Create a new API key
 * const result = await client.apiKeys.create({
 *   name: 'Production Key',
 *   csrf_token: csrfToken,
 * });
 * console.log(`Key: ${result.raw_key}`); // Only shown once
 *
 * // List all keys
 * const { keys } = await client.apiKeys.list();
 * ```
 */
export class ApiKeyResource {
  private readonly request: RequestFn;

  constructor(request: RequestFn) {
    this.request = request;
  }

  /**
   * Create a new API key
   *
   * POST /api/api-keys
   *
   * The raw key is only returned once at creation time.
   */
  async create(params: CreateApiKeyParams): Promise<{
    message: string;
    key: ApiKeyCreationResponse;
  }> {
    return this.request('POST', '/api-keys', params);
  }

  /**
   * List all API keys for the authenticated user
   *
   * GET /api/api-keys
   */
  async list(): Promise<{ keys: ApiKey[]; total: number }> {
    return this.request('GET', '/api-keys');
  }

  /**
   * Get details of a specific API key
   *
   * GET /api/api-keys/{id}
   */
  async get(keyId: string): Promise<ApiKey> {
    return this.request<ApiKey>('GET', `/api/api-keys/${keyId}`);
  }

  /**
   * Revoke (deactivate) an API key
   *
   * DELETE /api/api-keys/{id}
   */
  async revoke(keyId: string): Promise<{ message: string; key_id: string }> {
    return this.request('DELETE', `/api/api-keys/${keyId}`);
  }

  /**
   * Permanently delete an API key
   *
   * DELETE /api/api-keys/{id}/permanent
   */
  async delete(keyId: string): Promise<{ message: string; key_id: string }> {
    return this.request('DELETE', `/api/api-keys/${keyId}/permanent`);
  }
}
