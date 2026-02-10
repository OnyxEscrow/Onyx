/**
 * Onyx SDK Fee Estimation Operations
 *
 * Provides access to Monero network fee estimates and daemon health.
 */

import type {
  FeeEstimate,
  AllFeeEstimates,
  DaemonHealth,
  FeePriority,
  ClientFeeConfig,
  ClientFeeEstimate,
} from './types.js';

type RequestFn = <T>(method: string, path: string, body?: unknown) => Promise<T>;

/**
 * Fee estimation and daemon health resource
 *
 * @example
 * ```typescript
 * // Get fee estimate for a normal-priority transaction
 * const fee = await client.fees.estimate('normal');
 * console.log(`Fee: ${fee.fee_xmr}`);
 *
 * // Get all priority levels
 * const all = await client.fees.allEstimates();
 * for (const est of all.estimates) {
 *   console.log(`${est.priority}: ${est.fee_xmr}`);
 * }
 * ```
 */
export class FeeResource {
  private readonly request: RequestFn;

  constructor(request: RequestFn) {
    this.request = request;
  }

  /**
   * Get fee estimate for a Monero transaction
   *
   * GET /api/v1/fees/estimate
   *
   * @param priority - Fee priority level (default: 'normal')
   * @param txSize - Optional custom transaction size in bytes
   */
  async estimate(priority?: FeePriority, txSize?: number): Promise<FeeEstimate> {
    const params = new URLSearchParams();
    if (priority) {
      params.set('priority', priority);
    }
    if (txSize !== undefined) {
      params.set('tx_size', String(txSize));
    }
    const query = params.toString();
    const path = query ? `/v1/fees/estimate?${query}` : '/v1/fees/estimate';
    return this.request<FeeEstimate>('GET', path);
  }

  /**
   * Get fee estimates for all priority levels
   *
   * GET /api/v1/fees/all
   */
  async allEstimates(): Promise<AllFeeEstimates> {
    return this.request<AllFeeEstimates>('GET', '/v1/fees/all');
  }

  /**
   * Get daemon pool health status
   *
   * GET /api/v1/daemon/health
   */
  async daemonHealth(): Promise<DaemonHealth> {
    return this.request<DaemonHealth>('GET', '/v1/daemon/health');
  }

  /**
   * Get current fee configuration for the authenticated client (B2B)
   *
   * GET /api/v1/client/fees
   */
  async getClientFeeConfig(): Promise<ClientFeeConfig> {
    return this.request<ClientFeeConfig>('GET', '/v1/client/fees');
  }

  /**
   * Estimate fees for a specific amount (B2B)
   *
   * GET /api/v1/client/fees/estimate
   *
   * @param amountAtomic - Amount in piconero
   * @param isRefund - Whether this is a refund transaction
   */
  async estimateClientFees(
    amountAtomic: number,
    isRefund: boolean = false
  ): Promise<ClientFeeEstimate> {
    const params = new URLSearchParams();
    params.set('amount_atomic', String(amountAtomic));
    if (isRefund) {
      params.set('is_refund', 'true');
    }
    return this.request<ClientFeeEstimate>(
      'GET',
      `/v1/client/fees/estimate?${params.toString()}`
    );
  }
}
