/**
 * NEXUS SDK Analytics Operations
 *
 * Provides access to API usage analytics for B2B clients.
 */

import type { UsageAnalytics, AnalyticsPeriod } from './types.js';

type RequestFn = <T>(method: string, path: string, body?: unknown) => Promise<T>;

/**
 * Analytics resource operations
 *
 * @example
 * ```typescript
 * // Get usage analytics for the last 30 days
 * const usage = await client.analytics.getUsage('30d');
 * console.log(`Total escrows: ${usage.total_escrows}`);
 * console.log(`Volume: ${usage.total_volume_atomic} piconero`);
 * ```
 */
export class AnalyticsResource {
  private readonly request: RequestFn;

  constructor(request: RequestFn) {
    this.request = request;
  }

  /**
   * Get usage analytics for the authenticated client
   *
   * GET /api/v1/analytics/usage
   *
   * @param period - Time period: '24h', '7d', '30d', or 'all' (default: '30d')
   */
  async getUsage(period?: AnalyticsPeriod): Promise<UsageAnalytics> {
    const params = new URLSearchParams();
    if (period) {
      params.set('period', period);
    }
    const query = params.toString();
    const path = query ? `/v1/analytics/usage?${query}` : '/v1/analytics/usage';
    return this.request<UsageAnalytics>('GET', path);
  }
}
