/**
 * Onyx SDK Escrow Operations
 */

import type {
  CreateEscrowParams,
  CreateEscrowResponse,
  Escrow,
  EscrowListParams,
  EscrowListResponse,
  ReleaseEscrowParams,
  ReleaseEscrowResponse,
  DisputeEscrowParams,
  ResolveDisputeParams,
  JoinEscrowParams,
  FundingNotificationParams,
  SetPayoutAddressParams,
  SetRefundAddressParams,
} from './types.js';

type RequestFn = <T>(method: string, path: string, body?: unknown) => Promise<T>;

/**
 * Escrow resource operations
 */
export class EscrowResource {
  private readonly request: RequestFn;

  constructor(request: RequestFn) {
    this.request = request;
  }

  /**
   * Create a new escrow
   *
   * POST /api/v1/escrows/create
   *
   * EaaS flow: Creator specifies amount and role. Counterparty joins
   * later via the returned join_link.
   */
  async create(params: CreateEscrowParams): Promise<CreateEscrowResponse> {
    const body = {
      amount: Number(params.amount),
      creator_role: params.creator_role ?? 'buyer',
      description: params.description,
      external_reference: params.external_reference,
    };
    return this.request<CreateEscrowResponse>('POST', '/v1/escrows/create', body);
  }

  /**
   * Get an escrow by ID
   *
   * GET /api/v1/escrows/{id}
   */
  async get(escrowId: string): Promise<Escrow> {
    return this.request<Escrow>('GET', `/v1/escrows/${escrowId}`);
  }

  /**
   * List escrows for the authenticated user
   *
   * GET /api/v1/user/escrows
   */
  async list(params?: EscrowListParams): Promise<EscrowListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.status) {
      searchParams.set('status', params.status);
    }
    if (params?.external_id) {
      searchParams.set('external_id', params.external_id);
    }
    if (params?.limit !== undefined) {
      searchParams.set('limit', String(params.limit));
    }
    if (params?.cursor) {
      searchParams.set('cursor', params.cursor);
    }
    if (params?.order) {
      searchParams.set('order', params.order);
    }
    const query = searchParams.toString();
    const path = query ? `/v1/user/escrows?${query}` : '/v1/user/escrows';
    return this.request<EscrowListResponse>('GET', path);
  }

  /**
   * Join an existing escrow (as buyer/vendor)
   *
   * POST /api/v1/escrows/{id}/join
   */
  async join(escrowId: string, params?: JoinEscrowParams): Promise<Escrow> {
    return this.request<Escrow>(
      'POST',
      `/v1/escrows/${escrowId}/join`,
      params
    );
  }

  /**
   * Get public escrow info (for join page, no auth required)
   *
   * GET /api/escrows/{id}/public
   */
  async getPublic(escrowId: string): Promise<Escrow> {
    return this.request<Escrow>('GET', `/escrows/${escrowId}/public`);
  }

  /**
   * Get lobby status (who has joined, DKG readiness)
   *
   * GET /api/escrows/{id}/lobby-status
   */
  async getLobbyStatus(escrowId: string): Promise<unknown> {
    return this.request('GET', `/escrows/${escrowId}/lobby-status`);
  }

  /**
   * Start DKG process for an escrow (all parties must have joined)
   *
   * POST /api/escrows/{id}/start-dkg
   */
  async startDkg(escrowId: string): Promise<unknown> {
    return this.request('POST', `/escrows/${escrowId}/start-dkg`);
  }

  /**
   * Mark goods/services as delivered (vendor action)
   *
   * POST /api/v1/escrows/{id}/deliver
   */
  async markDelivered(escrowId: string): Promise<Escrow> {
    return this.request<Escrow>('POST', `/v1/escrows/${escrowId}/deliver`);
  }

  /**
   * Confirm delivery (buyer action)
   *
   * POST /api/v1/escrows/{id}/confirm
   */
  async confirmDelivery(escrowId: string): Promise<Escrow> {
    return this.request<Escrow>('POST', `/v1/escrows/${escrowId}/confirm`);
  }

  /**
   * Notify the server of an incoming funding transaction
   *
   * POST /api/v1/escrows/{id}/funding-notification
   */
  async notifyFunding(
    escrowId: string,
    params?: FundingNotificationParams
  ): Promise<unknown> {
    return this.request(
      'POST',
      `/v1/escrows/${escrowId}/funding-notification`,
      params
    );
  }

  /**
   * Release funds from an escrow to the vendor
   *
   * POST /api/v1/escrows/{id}/release
   */
  async release(params: ReleaseEscrowParams): Promise<ReleaseEscrowResponse> {
    return this.request<ReleaseEscrowResponse>(
      'POST',
      `/v1/escrows/${params.escrow_id}/release`,
      { recipient_address: params.recipient_address }
    );
  }

  /**
   * Refund an escrow back to the buyer
   *
   * POST /api/v1/escrows/{id}/refund
   */
  async refund(escrowId: string): Promise<unknown> {
    return this.request('POST', `/v1/escrows/${escrowId}/refund`);
  }

  /**
   * Raise a dispute on an escrow
   *
   * POST /api/v1/escrows/{id}/dispute
   */
  async dispute(params: DisputeEscrowParams): Promise<Escrow> {
    return this.request<Escrow>(
      'POST',
      `/v1/escrows/${params.escrow_id}/dispute`,
      { reason: params.reason, raised_by: params.raised_by }
    );
  }

  /**
   * Resolve a disputed escrow (requires arbitrator permissions)
   *
   * POST /api/v1/escrows/{id}/resolve
   */
  async resolve(params: ResolveDisputeParams): Promise<Escrow> {
    return this.request<Escrow>(
      'POST',
      `/v1/escrows/${params.escrow_id}/resolve`,
      {
        winner: params.winner,
        resolution_notes: params.resolution_notes,
      }
    );
  }

  /**
   * Get the funding status of an escrow (balance check)
   *
   * GET /api/escrow/{id}/balance
   */
  async getFundingStatus(escrowId: string): Promise<{
    escrow_id: string;
    expected_amount: string;
    received_amount: string;
    confirmations: number;
    required_confirmations: number;
    is_funded: boolean;
  }> {
    return this.request('GET', `/escrow/${escrowId}/balance`);
  }

  /**
   * Get the multisig deposit address for an escrow
   *
   * GET /api/escrow/{id}/multisig-address
   */
  async getMultisigAddress(escrowId: string): Promise<{ address: string }> {
    return this.request('GET', `/escrow/${escrowId}/multisig-address`);
  }

  /**
   * Set vendor payout address (before shipping)
   *
   * POST /api/v2/escrow/{id}/set-payout-address
   */
  async setPayoutAddress(
    escrowId: string,
    params: SetPayoutAddressParams
  ): Promise<unknown> {
    return this.request(
      'POST',
      `/v2/escrow/${escrowId}/set-payout-address`,
      params
    );
  }

  /**
   * Set buyer refund address (for dispute refunds)
   *
   * POST /api/v2/escrow/{id}/set-refund-address
   */
  async setRefundAddress(
    escrowId: string,
    params: SetRefundAddressParams
  ): Promise<unknown> {
    return this.request(
      'POST',
      `/v2/escrow/${escrowId}/set-refund-address`,
      params
    );
  }

  /**
   * Get escrow details (v2 endpoint with extended info)
   *
   * GET /api/v2/escrow/{id}
   */
  async getDetails(escrowId: string): Promise<unknown> {
    return this.request('GET', `/v2/escrow/${escrowId}`);
  }

  /**
   * Get user's dashboard view of all escrows
   *
   * GET /api/user/escrows/dashboard
   */
  async getDashboard(): Promise<unknown> {
    return this.request('GET', '/user/escrows/dashboard');
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert XMR to piconero
 *
 * @example
 * ```typescript
 * const piconero = xmrToPiconero(1.5); // 1_500_000_000_000n
 * ```
 */
export function xmrToPiconero(xmr: number): bigint {
  const PICONERO_PER_XMR = 1_000_000_000_000n;
  const parts = xmr.toString().split('.');
  const whole = parts[0] ?? '0';
  const decimal = parts[1] ?? '';
  const paddedDecimal = decimal.padEnd(12, '0').slice(0, 12);
  return BigInt(whole) * PICONERO_PER_XMR + BigInt(paddedDecimal);
}

/**
 * Convert piconero to XMR
 *
 * @example
 * ```typescript
 * const xmr = piconeroToXmr(1_500_000_000_000n); // 1.5
 * ```
 */
export function piconeroToXmr(piconero: bigint | string): number {
  const PICONERO_PER_XMR = 1_000_000_000_000n;
  const value = typeof piconero === 'string' ? BigInt(piconero) : piconero;
  const whole = value / PICONERO_PER_XMR;
  const decimal = value % PICONERO_PER_XMR;
  return Number(whole) + Number(decimal) / Number(PICONERO_PER_XMR);
}

/**
 * Format piconero amount as human-readable XMR string
 *
 * @example
 * ```typescript
 * formatXmr(1_500_000_000_000n); // "1.500000000000 XMR"
 * formatXmr(1_500_000_000_000n, 4); // "1.5000 XMR"
 * ```
 */
export function formatXmr(
  piconero: bigint | string,
  decimals: number = 12
): string {
  const xmr = piconeroToXmr(piconero);
  return `${xmr.toFixed(decimals)} XMR`;
}

/**
 * Validate a Monero mainnet address (basic format check).
 * For full validation with checksum, use the server-side validate_address endpoint.
 *
 * @example
 * ```typescript
 * if (!isValidMainnetAddress('4...')) {
 *   throw new Error('Invalid address');
 * }
 * ```
 */
export function isValidMainnetAddress(address: string): boolean {
  if (typeof address !== 'string') {
    return false;
  }

  const length = address.length;

  if (address.startsWith('4')) {
    return length === 95 || length === 106;
  }

  if (address.startsWith('8')) {
    return length === 95;
  }

  return false;
}
