/**
 * Onyx SDK FROST DKG + Signing Operations
 *
 * Handles the full FROST 2-of-3 threshold CLSAG lifecycle:
 * - DKG (Distributed Key Generation) rounds
 * - Signing session management
 * - Shield backup management
 * - Shipped/receipt tracking
 */

import type {
  DkgStatus,
  Round1SubmitParams,
  Round2SubmitParams,
  CompleteDkgParams,
  LagrangeCoefficients,
  FrostRole,
  SigningInitParams,
  NonceCommitmentParams,
  PartialSignatureParams,
  SigningStatus,
  RegisterShieldParams,
  VerifyShieldParams,
  ConfirmShippedParams,
  ConfirmReceiptParams,
} from './types.js';

type RequestFn = <T>(method: string, path: string, body?: unknown) => Promise<T>;

/**
 * FROST DKG + Signing resource operations
 *
 * @example
 * ```typescript
 * // Initialize DKG
 * const status = await client.frost.initDkg('escrow-id');
 *
 * // Submit Round 1 package
 * await client.frost.submitRound1('escrow-id', {
 *   role: 'buyer',
 *   package: 'hex-encoded-round1-package',
 * });
 * ```
 */
export class FrostResource {
  private readonly request: RequestFn;

  constructor(request: RequestFn) {
    this.request = request;
  }

  // ===========================================================================
  // DKG Operations
  // ===========================================================================

  /**
   * Initialize FROST DKG for an escrow
   *
   * POST /api/escrow/frost/{id}/init
   */
  async initDkg(escrowId: string): Promise<DkgStatus> {
    return this.request<DkgStatus>('POST', `/escrow/frost/${escrowId}/init`);
  }

  /**
   * Submit Round 1 package
   *
   * POST /api/escrow/frost/{id}/dkg/round1
   */
  async submitRound1(escrowId: string, params: Round1SubmitParams): Promise<DkgStatus> {
    return this.request<DkgStatus>(
      'POST',
      `/escrow/frost/${escrowId}/dkg/round1`,
      params
    );
  }

  /**
   * Get all Round 1 packages from other participants
   *
   * GET /api/escrow/frost/{id}/dkg/round1
   */
  async getRound1Packages(escrowId: string): Promise<Record<string, string>> {
    return this.request<Record<string, string>>(
      'GET',
      `/escrow/frost/${escrowId}/dkg/round1`
    );
  }

  /**
   * Submit Round 2 packages for other participants
   *
   * POST /api/escrow/frost/{id}/dkg/round2
   */
  async submitRound2(escrowId: string, params: Round2SubmitParams): Promise<DkgStatus> {
    return this.request<DkgStatus>(
      'POST',
      `/escrow/frost/${escrowId}/dkg/round2`,
      params
    );
  }

  /**
   * Get Round 2 packages addressed to the specified role
   *
   * GET /api/escrow/frost/{id}/dkg/round2?role={role}
   */
  async getRound2Packages(escrowId: string, role: FrostRole): Promise<Record<string, string>> {
    return this.request<Record<string, string>>(
      'GET',
      `/escrow/frost/${escrowId}/dkg/round2?role=${role}`
    );
  }

  /**
   * Complete DKG with group public key and derived multisig address
   *
   * POST /api/escrow/frost/{id}/dkg/complete
   */
  async completeDkg(escrowId: string, params: CompleteDkgParams): Promise<DkgStatus> {
    return this.request<DkgStatus>(
      'POST',
      `/escrow/frost/${escrowId}/dkg/complete`,
      params
    );
  }

  /**
   * Get current DKG status
   *
   * GET /api/escrow/frost/{id}/status
   */
  async getDkgStatus(escrowId: string): Promise<DkgStatus> {
    return this.request<DkgStatus>('GET', `/escrow/frost/${escrowId}/status`);
  }

  /**
   * Get Lagrange coefficients for a signing pair
   *
   * GET /api/escrow/frost/lagrange?signer1={signer1}&signer2={signer2}
   */
  async getLagrangeCoefficients(
    signer1: FrostRole,
    signer2: FrostRole
  ): Promise<LagrangeCoefficients> {
    return this.request<LagrangeCoefficients>(
      'GET',
      `/escrow/frost/lagrange?signer1=${signer1}&signer2=${signer2}`
    );
  }

  // ===========================================================================
  // Signing Operations
  // ===========================================================================

  /**
   * Initialize a FROST signing session
   *
   * POST /api/escrow/frost/{id}/sign/init
   */
  async initSigning(escrowId: string, params: SigningInitParams): Promise<SigningStatus> {
    return this.request<SigningStatus>(
      'POST',
      `/escrow/frost/${escrowId}/sign/init`,
      params
    );
  }

  /**
   * Submit nonce commitment for signing
   *
   * POST /api/escrow/frost/{id}/sign/nonces
   */
  async submitNonceCommitment(
    escrowId: string,
    params: NonceCommitmentParams
  ): Promise<SigningStatus> {
    return this.request<SigningStatus>(
      'POST',
      `/escrow/frost/${escrowId}/sign/nonces`,
      params
    );
  }

  /**
   * Get aggregated nonce commitments from all signers
   *
   * GET /api/escrow/frost/{id}/sign/nonces
   */
  async getNonceCommitments(escrowId: string): Promise<unknown> {
    return this.request('GET', `/escrow/frost/${escrowId}/sign/nonces`);
  }

  /**
   * Submit partial signature
   *
   * POST /api/escrow/frost/{id}/sign/partial
   */
  async submitPartialSignature(
    escrowId: string,
    params: PartialSignatureParams
  ): Promise<SigningStatus> {
    return this.request<SigningStatus>(
      'POST',
      `/escrow/frost/${escrowId}/sign/partial`,
      params
    );
  }

  /**
   * Get signing session status
   *
   * GET /api/escrow/frost/{id}/sign/status
   */
  async getSigningStatus(escrowId: string): Promise<SigningStatus> {
    return this.request<SigningStatus>(
      'GET',
      `/escrow/frost/${escrowId}/sign/status`
    );
  }

  /**
   * Aggregate partial signatures and broadcast the transaction
   *
   * POST /api/escrow/frost/{id}/sign/complete
   */
  async completeAndBroadcast(escrowId: string): Promise<{ tx_hash: string }> {
    return this.request<{ tx_hash: string }>(
      'POST',
      `/escrow/frost/${escrowId}/sign/complete`
    );
  }

  /**
   * Get transaction data needed for signing
   *
   * GET /api/escrow/frost/{id}/sign/tx-data
   */
  async getTxData(escrowId: string): Promise<unknown> {
    return this.request('GET', `/escrow/frost/${escrowId}/sign/tx-data`);
  }

  /**
   * Get first signer data for round-robin signing
   *
   * GET /api/escrow/frost/{id}/sign/first-signer-data
   */
  async getFirstSignerData(escrowId: string): Promise<unknown> {
    return this.request('GET', `/escrow/frost/${escrowId}/sign/first-signer-data`);
  }

  // ===========================================================================
  // Shield Backup Operations
  // ===========================================================================

  /**
   * Register a shield backup for key recovery
   *
   * POST /api/escrow/frost/{id}/shield/register
   */
  async registerShield(
    escrowId: string,
    params: RegisterShieldParams
  ): Promise<{ id: string; backup_id: string; created_at: string }> {
    return this.request(
      'POST',
      `/escrow/frost/${escrowId}/shield/register`,
      params
    );
  }

  /**
   * Verify a shield backup exists
   *
   * POST /api/escrow/frost/{id}/shield/verify
   */
  async verifyShield(
    escrowId: string,
    params: VerifyShieldParams
  ): Promise<{ valid: boolean; backup_id?: string }> {
    return this.request(
      'POST',
      `/escrow/frost/${escrowId}/shield/verify`,
      params
    );
  }

  /**
   * Get shield backup status for the current user
   *
   * GET /api/escrow/frost/{id}/shield/status
   */
  async getShieldStatus(escrowId: string): Promise<unknown> {
    return this.request('GET', `/escrow/frost/${escrowId}/shield/status`);
  }

  // ===========================================================================
  // Shipped Tracking Operations
  // ===========================================================================

  /**
   * Confirm shipment (vendor only). Changes status from "funded" to "shipped".
   *
   * POST /api/escrow/frost/{id}/ship
   */
  async confirmShipped(
    escrowId: string,
    params: ConfirmShippedParams
  ): Promise<{ success: boolean; status: string; auto_release_at: string; message: string }> {
    return this.request(
      'POST',
      `/escrow/frost/${escrowId}/ship`,
      params
    );
  }

  /**
   * Confirm receipt and trigger fund release (buyer only).
   * Sets buyer_release_requested to trigger Arbiter Watchdog auto-signing.
   *
   * POST /api/escrow/frost/{id}/confirm-receipt
   */
  async confirmReceipt(
    escrowId: string,
    params: ConfirmReceiptParams
  ): Promise<{ success: boolean; status: string; message: string }> {
    return this.request(
      'POST',
      `/escrow/frost/${escrowId}/confirm-receipt`,
      params
    );
  }
}
