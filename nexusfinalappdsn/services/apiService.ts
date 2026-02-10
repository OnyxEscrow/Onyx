/**
 * API Service - FROST DKG and Escrow API calls
 *
 * Wraps all server API endpoints with proper types and error handling.
 * All requests include credentials for session-based authentication.
 */

// ============================================================================
// Configuration
// ============================================================================

const API_BASE = '/api';

// ============================================================================
// Types
// ============================================================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface DkgParticipants {
  buyer_round1_ready: boolean;
  vendor_round1_ready: boolean;
  arbiter_round1_ready: boolean;
  buyer_round2_ready: boolean;
  vendor_round2_ready: boolean;
  arbiter_round2_ready: boolean;
}

export interface DkgStatus {
  escrow_id: string;
  round1_complete: boolean;
  round2_complete: boolean;
  dkg_complete: boolean;
  participants: DkgParticipants;
}

export interface LagrangeResponse {
  signer1_lambda: string;
  signer2_lambda: string;
}

export interface Round1Request {
  role: string;
  package: string;
}

export interface Round2Request {
  role: string;
  packages: Record<string, string>;
}

export interface CompleteDkgRequest {
  group_pubkey: string;
  multisig_address: string;
  multisig_view_key: string;
}

export interface EscrowDetails {
  id: string;
  buyer_id: string;
  vendor_id: string;
  arbiter_id: string;
  status: string;
  amount: number;           // Amount in atomic units
  amount_atomic: number;    // Alias for amount (deprecated)
  balance_received: number; // Funds received (atomic units)
  confirmations: number;    // Blockchain confirmations
  multisig_address?: string;
  multisig_view_key?: string;
  funding_tx_hash?: string;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// HTTP Helpers
// ============================================================================

async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const url = `${API_BASE}${endpoint}`;

  // Generate idempotency key for mutating requests
  const method = options.method?.toUpperCase() || 'GET';
  const needsIdempotencyKey = ['POST', 'PUT', 'PATCH'].includes(method);
  const idempotencyKey = needsIdempotencyKey ? crypto.randomUUID() : undefined;

  const response = await fetch(url, {
    ...options,
    credentials: 'include', // Include session cookies
    headers: {
      'Content-Type': 'application/json',
      ...(idempotencyKey && { 'Idempotency-Key': idempotencyKey }),
      ...options.headers,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    return {
      success: false,
      error: data.error || `HTTP ${response.status}: ${response.statusText}`,
    };
  }

  // Handle both wrapped responses { success, data } and raw responses
  if (typeof data === 'object' && 'success' in data) {
    // Response is already wrapped in ApiResponse format
    return {
      success: data.success,
      data: data.data || data, // Some endpoints put data at top-level
      error: data.error,
    };
  }

  // Raw response - wrap it
  return {
    success: true,
    data: data as T,
  };
}

// ============================================================================
// FROST DKG API
// ============================================================================

/**
 * Initialize FROST DKG for an escrow
 *
 * POST /api/escrow/frost/{id}/init
 */
export async function initFrostDkg(escrowId: string): Promise<ApiResponse<DkgStatus>> {
  return fetchApi<DkgStatus>(`/escrow/frost/${escrowId}/init`, {
    method: 'POST',
  });
}

/**
 * Submit Round 1 package
 *
 * POST /api/escrow/frost/{id}/dkg/round1
 */
export async function submitRound1(
  escrowId: string,
  role: string,
  packageHex: string
): Promise<ApiResponse<DkgStatus>> {
  const body: Round1Request = {
    role,
    package: packageHex,
  };

  return fetchApi<DkgStatus>(`/escrow/frost/${escrowId}/dkg/round1`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * Get all Round 1 packages
 *
 * GET /api/escrow/frost/{id}/dkg/round1
 */
export async function getRound1Packages(
  escrowId: string
): Promise<ApiResponse<Record<string, string>>> {
  return fetchApi<Record<string, string>>(`/escrow/frost/${escrowId}/dkg/round1`);
}

/**
 * Submit Round 2 packages
 *
 * POST /api/escrow/frost/{id}/dkg/round2
 */
export async function submitRound2(
  escrowId: string,
  role: string,
  packages: Record<string, string>
): Promise<ApiResponse<DkgStatus>> {
  const body: Round2Request = {
    role,
    packages,
  };

  return fetchApi<DkgStatus>(`/escrow/frost/${escrowId}/dkg/round2`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * Get Round 2 packages for a specific role
 *
 * GET /api/escrow/frost/{id}/dkg/round2?role={role}
 */
export async function getRound2Packages(
  escrowId: string,
  role: string
): Promise<ApiResponse<Record<string, string>>> {
  return fetchApi<Record<string, string>>(`/escrow/frost/${escrowId}/dkg/round2?role=${role}`);
}

/**
 * Complete DKG with group public key and derived address
 *
 * POST /api/escrow/frost/{id}/dkg/complete
 */
export async function completeDkg(
  escrowId: string,
  groupPubkey: string,
  multisigAddress: string,
  multisigViewKey: string
): Promise<ApiResponse<DkgStatus>> {
  const body: CompleteDkgRequest = {
    group_pubkey: groupPubkey,
    multisig_address: multisigAddress,
    multisig_view_key: multisigViewKey,
  };

  return fetchApi<DkgStatus>(`/escrow/frost/${escrowId}/dkg/complete`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * Get DKG status
 *
 * GET /api/escrow/frost/{id}/status
 */
export async function getDkgStatus(escrowId: string): Promise<ApiResponse<DkgStatus>> {
  return fetchApi<DkgStatus>(`/escrow/frost/${escrowId}/status`);
}

/**
 * Get Lagrange coefficients for a signing pair
 *
 * GET /api/escrow/frost/lagrange?signer1={signer1}&signer2={signer2}
 */
export async function getLagrangeCoefficients(
  signer1: string,
  signer2: string
): Promise<ApiResponse<LagrangeResponse>> {
  return fetchApi<LagrangeResponse>(`/escrow/frost/lagrange?signer1=${signer1}&signer2=${signer2}`);
}

// ============================================================================
// Escrow API
// ============================================================================

/**
 * Get escrow details
 *
 * GET /api/escrow/{id}
 */
export async function getEscrow(escrowId: string): Promise<ApiResponse<EscrowDetails>> {
  return fetchApi<EscrowDetails>(`/escrow/${escrowId}`);
}

/**
 * Create a new escrow
 *
 * POST /api/escrow
 */
export async function createEscrow(data: {
  vendor_id: string;
  amount_atomic: number;
  description?: string;
}): Promise<ApiResponse<EscrowDetails>> {
  return fetchApi<EscrowDetails>('/escrow', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

// ============================================================================
// EaaS Lobby API (Escrow Creation & Join)
// ============================================================================

export interface CreateEscrowResponse {
  escrow_id: string;
  status: string;
  creator_role: string;
  join_link: string;
}

export interface JoinEscrowResponse {
  success: boolean;
  role: string;
  escrow_id: string;
  status: string;
}

export interface LobbyStatus {
  escrow_id: string;
  status: string;
  amount: number;
  buyer_joined: boolean;
  vendor_joined: boolean;
  arbiter_assigned: boolean;
  all_ready: boolean;
}

/**
 * Create a new escrow lobby
 *
 * POST /api/escrows/create
 */
export async function createEscrowLobby(
  amount: number,
  creatorRole: 'buyer' | 'vendor',
  description?: string
): Promise<ApiResponse<CreateEscrowResponse>> {
  return fetchApi<CreateEscrowResponse>('/escrows/create', {
    method: 'POST',
    body: JSON.stringify({
      amount,
      creator_role: creatorRole,
      description,
    }),
  });
}

/**
 * Join an existing escrow as counterparty
 *
 * POST /api/escrows/{id}/join
 */
export async function joinEscrow(escrowId: string): Promise<ApiResponse<JoinEscrowResponse>> {
  return fetchApi<JoinEscrowResponse>(`/escrows/${escrowId}/join`, {
    method: 'POST',
  });
}

/**
 * Get escrow lobby status (participant readiness)
 *
 * GET /api/escrows/{id}/lobby-status
 */
export async function getLobbyStatus(escrowId: string): Promise<ApiResponse<LobbyStatus>> {
  return fetchApi<LobbyStatus>(`/escrows/${escrowId}/lobby-status`);
}

/**
 * Get escrow public info (for join page, no auth required)
 *
 * GET /api/escrows/{id}/public
 */
export async function getEscrowPublic(escrowId: string): Promise<ApiResponse<{
  escrow_id: string;
  amount: number;
  status: string;
  creator_role: string;
}>> {
  return fetchApi(`/escrows/${escrowId}/public`);
}

// ============================================================================
// Authentication API
// ============================================================================

export interface AuthUser {
  id: string;
  username: string;
  role?: string;
  csrf_token?: string;
}

/**
 * Get current user from session
 *
 * GET /api/auth/whoami
 */
export async function getCurrentUser(): Promise<ApiResponse<AuthUser>> {
  return fetchApi<AuthUser>('/auth/whoami');
}

/**
 * Login (JSON API)
 *
 * POST /api/auth/login-json
 */
export async function login(
  username: string,
  password: string
): Promise<ApiResponse<AuthUser>> {
  return fetchApi<AuthUser>('/auth/login-json', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

/**
 * Logout
 *
 * POST /api/auth/logout
 */
export async function logout(): Promise<ApiResponse<void>> {
  return fetchApi<void>('/auth/logout', {
    method: 'POST',
  });
}

/**
 * Register new user (JSON API)
 *
 * POST /api/auth/register-json
 */
export async function register(
  username: string,
  password: string,
  role: string
): Promise<ApiResponse<AuthUser>> {
  return fetchApi<AuthUser>('/auth/register-json', {
    method: 'POST',
    body: JSON.stringify({ username, password, role }),
  });
}

// ============================================================================
// Signing API (FROST CLSAG)
// ============================================================================

export interface PrepareSignInput {
  input_index: number;
  ring_member_indices: number[];
  signer_index: number;
  ring_public_keys: string[];
  ring_commitments: string[];
  real_global_index: number;
  key_offset: string;
  pseudo_out_mask: string;
}

export interface PrepareSignResponse {
  escrow_id: string;
  tx_prefix_hash: string;
  inputs: PrepareSignInput[];
  amount: number;
  destination: string;

  // Multisig signing data
  multisig_spend_pub_key?: string;      // Group public key (P_multisig)
  key_image?: string;                    // Aggregated key image
  first_signer_c1?: string;             // First signer's c1 (for second signer)
  first_signer_d?: string;              // First signer's D point
  first_signer_s?: string[];            // First signer's s values
  first_signer_pseudo_out?: string;     // First signer's pseudo-out

  // MuSig2 nonce aggregation
  peer_nonce_public?: string;           // Other signer's R point
  peer_nonce_prime_public?: string;     // Other signer's R' point
  r_agg?: string;                       // Aggregated nonce R_agg
  first_signer_used_r_agg?: boolean;    // Whether first signer used R_agg
  my_nonce_r_public?: string;           // This signer's submitted nonce

  // MuSig2 coefficients
  mu_P?: string;                        // mu_P for CLSAG
  mu_C?: string;                        // mu_C for CLSAG

  // FROST-specific
  frost_enabled?: boolean;
  my_role?: string;
  lagrange_coefficient?: string;
  other_signer_role?: string;

  // Full CLSAG message (not just tx_prefix_hash)
  clsag_message?: string;

  // Legacy fields (deprecated)
  ring_data?: {
    ring_member_indices: number[];
    signer_index: number;
    ring_public_keys: string[];
    ring_commitments: string[];
    real_global_index: number;
  };
  stealth_address?: string;
  commitment_mask?: string;
  amount_atomic?: number;
  status?: string;
}

export interface SubmitSignatureRequest {
  role: string;
  clsag_signature: string; // Full CLSAG signature JSON
  partial_key_image?: string;
}

export interface SubmitSignatureResponse {
  success: boolean;
  signatures_collected: number;
  signatures_required: number;
  ready_to_broadcast: boolean;
  tx_hash?: string;
}

export interface SigningSession {
  escrow_id: string;
  action: string;
  status: string;
  signatures_collected: number;
  signatures_required: number;
  partial_signatures: Array<{
    signer_role: string;
    partial_signature: string;
    partial_key_image: string;
    nonce_commitment: string;
  }>;
  transaction_hex?: string;
  tx_hash?: string;

  // Signing data from server (populated during signing flow)
  group_public_key?: string;           // The multisig address public key
  tx_prefix_hash?: string;             // Hash of transaction prefix
  tx_pub_key?: string;                 // R from funding transaction
  view_key_shared?: string;            // Shared view key for output derivation
  output_index?: number;               // Output index in funding tx
  one_time_pubkey?: string;            // One-time output public key P
  aggregated_key_image?: string;       // Pre-computed aggregated key image
  mask_share?: string;                 // This signer's mask share
  co_signer_pubkey?: string;           // Co-signer's X25519 pubkey for encryption
  input_data?: Record<string, unknown>; // Ring data for CLSAG signing
  first_signer_data?: {                // Data from first signer (for second signer)
    encrypted_alpha: string;
    partial_s: string[];
    c1: string;
    D: string;
    key_image: string;
    pseudo_out: string;
    ring: string[][];
    tx_prefix_hash: string;
    signer_index: number;
    mu_P: string;
    mu_C: string;
  };
}

/**
 * Prepare signing data (ring selection, tx prefix, etc.)
 *
 * GET /api/v2/escrow/{id}/prepare-sign
 */
export async function prepareSign(escrowId: string): Promise<ApiResponse<PrepareSignResponse>> {
  return fetchApi<PrepareSignResponse>(`/v2/escrow/${escrowId}/prepare-sign`);
}

/**
 * Submit CLSAG signature
 *
 * POST /api/v2/escrow/{id}/submit-signature
 */
export async function submitSignature(
  escrowId: string,
  role: string,
  clsagSignature: string,
  partialKeyImage?: string
): Promise<ApiResponse<SubmitSignatureResponse>> {
  const body: SubmitSignatureRequest = {
    role,
    clsag_signature: clsagSignature,
    partial_key_image: partialKeyImage,
  };

  return fetchApi<SubmitSignatureResponse>(`/v2/escrow/${escrowId}/submit-signature`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * Get escrow signing status
 *
 * GET /api/v2/escrow/{id}
 */
export async function getSigningStatus(escrowId: string): Promise<ApiResponse<SigningSession>> {
  return fetchApi<SigningSession>(`/v2/escrow/${escrowId}`);
}

/**
 * Broadcast completed transaction
 *
 * POST /api/v2/escrow/{id}/broadcast-tx
 */
export async function broadcastTransaction(escrowId: string): Promise<ApiResponse<{ tx_hash: string }>> {
  return fetchApi<{ tx_hash: string }>(`/v2/escrow/${escrowId}/broadcast-tx`, {
    method: 'POST',
  });
}

// ============================================================================
// Round-Robin Signing API (100% Non-Custodial - requires local wallet RPC)
// ============================================================================

export interface RoundRobinInitRequest {
  destination_address: string;
  role: 'buyer' | 'vendor';
}

export interface RoundRobinStatus {
  phase: string;
  current_signer: string | null;
  round: number;
  is_complete: boolean;
  tx_hash: string | null;
  data_to_sign: string | null;
  destination_address: string | null;
  amount: number | null;
}

/**
 * Initiate round-robin signing (non-custodial)
 *
 * POST /api/escrow/{id}/initiate-round-robin-signing
 *
 * This starts the signing process. The first signer must then create
 * a multisig_txset on their LOCAL wallet using monero-wallet-rpc.
 */
export async function initiateRoundRobinSigning(
  escrowId: string,
  destinationAddress: string,
  role: 'buyer' | 'vendor'
): Promise<ApiResponse<{ next_step: string }>> {
  return fetchApi<{ next_step: string }>(`/escrow/${escrowId}/initiate-round-robin-signing`, {
    method: 'POST',
    body: JSON.stringify({
      destination_address: destinationAddress,
      role,
    }),
  });
}

/**
 * Submit multisig txset from first signer's local wallet
 *
 * POST /api/escrow/{id}/submit-multisig-txset
 *
 * After creating the txset on local wallet via `transfer` RPC call,
 * submit the unsigned multisig_txset here.
 */
export async function submitMultisigTxset(
  escrowId: string,
  multisigTxset: string
): Promise<ApiResponse<{ next_signer_id: string }>> {
  return fetchApi<{ next_signer_id: string }>(`/escrow/${escrowId}/submit-multisig-txset`, {
    method: 'POST',
    body: JSON.stringify({
      multisig_txset: multisigTxset,
    }),
  });
}

/**
 * Submit partial signature from second signer's local wallet
 *
 * POST /api/escrow/{id}/submit-round-robin-signature
 *
 * After signing the txset on local wallet via `sign_multisig` RPC call,
 * submit the partial_signed_txset here.
 */
export async function submitRoundRobinSignature(
  escrowId: string,
  partialSignedTxset: string
): Promise<ApiResponse<{ next_signer_id: string }>> {
  return fetchApi<{ next_signer_id: string }>(`/escrow/${escrowId}/submit-round-robin-signature`, {
    method: 'POST',
    body: JSON.stringify({
      partial_signed_txset: partialSignedTxset,
    }),
  });
}

/**
 * Confirm round-robin broadcast with tx_hash
 *
 * POST /api/escrow/{id}/confirm-round-robin-broadcast
 *
 * After the first signer completes signing and broadcasts via local wallet,
 * they confirm the broadcast here with the tx_hash.
 */
export async function confirmRoundRobinBroadcast(
  escrowId: string,
  txHash: string
): Promise<ApiResponse<{ status: string }>> {
  return fetchApi<{ status: string }>(`/escrow/${escrowId}/confirm-round-robin-broadcast`, {
    method: 'POST',
    body: JSON.stringify({
      tx_hash: txHash,
    }),
  });
}

/**
 * Get round-robin signing status
 *
 * GET /api/escrow/{id}/round-robin-status
 */
export async function getRoundRobinStatus(
  escrowId: string
): Promise<ApiResponse<RoundRobinStatus>> {
  return fetchApi<RoundRobinStatus>(`/escrow/${escrowId}/round-robin-status`);
}

// ============================================================================
// Escrow Status Update API
// ============================================================================

/**
 * Mark escrow as delivered (vendor action)
 *
 * POST /api/escrow/{id}/deliver
 *
 * Stores the vendor's payout address for the release transaction.
 * The release TX will have 2 outputs: vendor_address + platform_fee_wallet
 */
export async function markDelivered(
  escrowId: string,
  vendorPayoutAddress: string
): Promise<ApiResponse<{ status: string; vendor_payout_address: string }>> {
  return fetchApi<{ status: string; vendor_payout_address: string }>(
    `/escrow/${escrowId}/deliver`,
    {
      method: 'POST',
      body: JSON.stringify({
        vendor_payout_address: vendorPayoutAddress,
      }),
    }
  );
}

/**
 * Confirm shipment (vendor action) - v0.75.0
 *
 * POST /api/escrow/frost/{id}/ship
 *
 * Called AFTER markDelivered to transition status from "funded" to "shipped".
 * Requires vendor_payout_address to already be set via markDelivered.
 */
export async function confirmShipped(
  escrowId: string,
  trackingInfo?: string,
  estimatedDeliveryDays?: number
): Promise<ApiResponse<{ success: boolean; status: string }>> {
  return fetchApi<{ success: boolean; status: string }>(
    `/escrow/frost/${escrowId}/ship`,
    {
      method: 'POST',
      body: JSON.stringify({
        tracking_info: trackingInfo,
        estimated_delivery_days: estimatedDeliveryDays || 14,
      }),
    }
  );
}

/**
 * Confirm receipt (buyer action) - v0.75.0
 *
 * POST /api/escrow/frost/{id}/confirm-receipt
 *
 * Buyer confirms goods received. Transitions status from "shipped" to "releasing".
 * Triggers Arbiter Watchdog auto-signing within 30 seconds.
 */
export async function confirmReceipt(
  escrowId: string
): Promise<ApiResponse<{ success: boolean; status: string; message: string }>> {
  return fetchApi<{ success: boolean; status: string; message: string }>(
    `/escrow/frost/${escrowId}/confirm-receipt`,
    {
      method: 'POST',
      body: JSON.stringify({ consent_confirmed: true }),
    }
  );
}

/**
 * Confirm delivery (buyer action) - DEPRECATED: use confirmReceipt
 *
 * POST /api/escrow/{id}/confirm
 *
 * Buyer confirms receipt of goods/services.
 * Sets status to "signing_initiated" which triggers release flow.
 * Transaction will use vendor_payout_address stored during mark-delivered.
 */
export async function confirmDelivery(
  escrowId: string
): Promise<ApiResponse<{ status: string; message: string }>> {
  return fetchApi<{ status: string; message: string }>(
    `/escrow/${escrowId}/confirm`,
    {
      method: 'POST',
    }
  );
}

/**
 * Release escrow funds (buyer action)
 *
 * POST /api/escrow/{id}/release
 *
 * Uses the vendor_payout_address stored during mark-delivered.
 * Transaction has 2 outputs:
 * - Output 0: Vendor payout (escrow_amount - platform_fee - tx_fee)
 * - Output 1: Platform fee
 */
export async function releaseFunds(
  escrowId: string,
  vendorAddress: string
): Promise<ApiResponse<{ tx_hash: string }>> {
  return fetchApi<{ tx_hash: string }>(`/escrow/${escrowId}/release`, {
    method: 'POST',
    body: JSON.stringify({
      vendor_address: vendorAddress,
    }),
  });
}

// ============================================================================
// Legacy Signing API (kept for backwards compatibility with WASM signing)
// ============================================================================

// Note: These endpoints don't exist on the backend. They are placeholders
// for future WASM-based CLSAG signing when implemented.

export interface SigningRequest {
  escrow_id: string;
  action: 'release' | 'refund' | 'dispute_resolution';
  recipient_address?: string;
}

/**
 * @deprecated Use initiateRoundRobinSigning() instead
 * This endpoint does not exist - kept for API compatibility
 */
export async function initiateSigningSession(
  escrowId: string,
  action: 'release' | 'refund' | 'dispute_resolution',
  recipientAddress?: string
): Promise<ApiResponse<SigningSession>> {
  // Redirect to round-robin signing
  console.warn('[API] initiateSigningSession is deprecated. Use initiateRoundRobinSigning instead.');

  const role = action === 'release' ? 'vendor' : 'buyer';
  const result = await initiateRoundRobinSigning(
    escrowId,
    recipientAddress || '',
    role as 'buyer' | 'vendor'
  );

  // Transform response to match old interface
  return {
    success: result.success,
    data: result.success ? {
      escrow_id: escrowId,
      action,
      status: 'round_robin_signing',
      signatures_collected: 0,
      signatures_required: 2,
      partial_signatures: [],
    } : undefined,
    error: result.error,
  };
}

/**
 * @deprecated Use submitRoundRobinSignature() instead
 * This endpoint does not exist - kept for API compatibility
 */
export async function submitPartialSignature(
  escrowId: string,
  _signerRole: string,
  _partialSignature: string,
  _partialKeyImage: string,
  _nonceCommitment: string
): Promise<ApiResponse<SigningSession>> {
  console.warn('[API] submitPartialSignature is deprecated. Use submitRoundRobinSignature instead.');

  return {
    success: false,
    error: 'Use round-robin signing flow: initiateRoundRobinSigning → submitMultisigTxset → submitRoundRobinSignature → confirmRoundRobinBroadcast',
  };
}

// ============================================================================
// WebSocket Helper
// ============================================================================

export interface WebSocketMessage {
  type: string;
  escrow_id?: string;
  data?: unknown;
}

/**
 * Create WebSocket connection for real-time updates
 */
export function createWebSocket(onMessage: (message: WebSocketMessage) => void): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

  ws.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data) as WebSocketMessage;
      onMessage(message);
    } catch (error) {
      console.error('[WebSocket] Failed to parse message:', error);
    }
  };

  ws.onerror = (error) => {
    console.error('[WebSocket] Error:', error);
  };

  ws.onclose = (event) => {
    console.log('[WebSocket] Closed:', event.code, event.reason);
  };

  return ws;
}

// ============================================================================
// Utility Types
// ============================================================================

export type FrostRole = 'buyer' | 'vendor' | 'arbiter';

export function isValidRole(role: string): role is FrostRole {
  return ['buyer', 'vendor', 'arbiter'].includes(role.toLowerCase());
}

// ============================================================================
// Partial Key Image API (for FROST Signing)
// ============================================================================

export interface EscrowDetailsV2 {
  id: string;
  status: string;
  amount: number;
  frost_group_pubkey?: string;
  multisig_address?: string;
  multisig_view_key?: string;
  funding_tx_hash?: string;
  funding_output_pubkey?: string;  // one_time_pubkey (P) for Hp(P)
  funding_tx_pubkey?: string;      // TX pubkey (R) for derivation
  funding_output_index?: number;   // Output index for derivation
  buyer_partial_key_image?: string;
  vendor_partial_key_image?: string;
  aggregated_key_image?: string;
  signing_phase?: string;
}

export interface SubmitPartialKeyImageRequest {
  role: string;
  partial_key_image: string;
}

export interface SubmitPartialKeyImageResponse {
  success: boolean;
  role: string;
  partial_key_images_count: number;
  aggregated_key_image?: string;  // Set when both PKIs submitted
  message: string;
}

/**
 * Get escrow details V2 (includes signing prerequisites)
 * Returns data needed for partial key image computation.
 *
 * GET /api/v2/escrow/{id}
 */
export async function getEscrowDetailsV2(escrowId: string): Promise<ApiResponse<EscrowDetailsV2>> {
  return fetchApi<EscrowDetailsV2>(`/v2/escrow/${escrowId}`);
}

/**
 * Submit partial key image for FROST signing
 *
 * Partial key image: pKI = (d + λ*b) * Hp(P)
 * where:
 *   d = derivation scalar (from view_key, tx_pubkey, output_index)
 *   λ = Lagrange coefficient for this signer
 *   b = spend share (from FROST key package)
 *   P = one_time_pubkey (funding_output_pubkey)
 *
 * When both buyer and vendor submit PKIs, server aggregates:
 *   KI = pKI_buyer + pKI_vendor
 *
 * POST /api/v2/escrow/{id}/submit-partial-key-image
 */
export async function submitPartialKeyImage(
  escrowId: string,
  role: string,
  partialKeyImage: string
): Promise<ApiResponse<SubmitPartialKeyImageResponse>> {
  const body: SubmitPartialKeyImageRequest = {
    role,
    partial_key_image: partialKeyImage,
  };

  return fetchApi<SubmitPartialKeyImageResponse>(`/v2/escrow/${escrowId}/submit-partial-key-image`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

// ============================================================================
// Arbiter Dispute Management
// ============================================================================

export interface ArbiterDispute {
  id: string;
  escrow_id: string;
  status: string;
  reason: string | null;
  buyer_username: string;
  vendor_username: string;
  amount: number;
  created_at: string;
  dispute_created_at: string | null;
}

/**
 * Get all disputes assigned to the authenticated arbiter
 *
 * GET /api/arbiter/disputes
 */
export async function getArbiterDisputes(): Promise<ApiResponse<{ disputes: ArbiterDispute[]; total: number }>> {
  return fetchApi<{ disputes: ArbiterDispute[]; total: number }>('/arbiter/disputes');
}

/**
 * Get single dispute details
 *
 * GET /api/arbiter/disputes/{id}
 */
export async function getArbiterDisputeDetail(disputeId: string): Promise<ApiResponse<ArbiterDispute>> {
  return fetchApi<ArbiterDispute>(`/arbiter/disputes/${disputeId}`);
}

/**
 * Initiate a dispute on an escrow (buyer or vendor)
 *
 * POST /api/escrow/{id}/dispute
 */
export async function initiateDispute(
  escrowId: string,
  reason: string
): Promise<ApiResponse<{ success: boolean; message: string }>> {
  return fetchApi<{ success: boolean; message: string }>(`/escrow/${escrowId}/dispute`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

/**
 * Resolve a dispute (arbiter only)
 *
 * POST /api/escrow/{id}/resolve
 * resolution: "buyer" or "vendor"
 * recipient_address: Monero address (95 chars, starts with '4')
 */
export async function resolveDispute(
  escrowId: string,
  resolution: 'buyer' | 'vendor',
  recipientAddress: string
): Promise<ApiResponse<{ success: boolean; message: string; tx_hash?: string }>> {
  return fetchApi<{ success: boolean; message: string; tx_hash?: string }>(`/escrow/${escrowId}/resolve`, {
    method: 'POST',
    body: JSON.stringify({ resolution, recipient_address: recipientAddress }),
  });
}

/**
 * Submit winning party's FROST share for dispute broadcast
 * POST /api/escrow/{id}/submit-dispute-share
 */
export async function submitDisputeShare(
  escrowId: string,
  frostShare: string,
  userRole: string
): Promise<ApiResponse<{ status: string; success?: boolean; tx_hash?: string; message?: string; has_arbiter_share?: boolean; has_winner_share?: boolean }>> {
  return fetchApi<{ status: string; success?: boolean; tx_hash?: string; message?: string; has_arbiter_share?: boolean; has_winner_share?: boolean }>(`/escrow/${escrowId}/submit-dispute-share`, {
    method: 'POST',
    body: JSON.stringify({ frost_share: frostShare, user_role: userRole }),
  });
}

// ============================================================================
// API Key Management (B2B EaaS)
// ============================================================================

export interface ApiKeyInfo {
  id: string;
  name: string;
  key_prefix: string;
  tier: string;
  is_active: boolean;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  total_requests: number;
}

export interface ApiKeyCreationResponse {
  id: string;
  raw_key: string;
  key_prefix: string;
  name: string;
  tier: string;
}

/**
 * List all API keys for the authenticated user
 *
 * GET /api/api-keys
 */
export async function listApiKeys(): Promise<ApiResponse<{ keys: ApiKeyInfo[]; total: number }>> {
  return fetchApi<{ keys: ApiKeyInfo[]; total: number }>('/api-keys');
}

/**
 * Create a new API key
 *
 * POST /api/api-keys
 */
export async function createApiKey(
  name: string,
  csrfToken: string,
  metadata?: string
): Promise<ApiResponse<{ message: string; key: ApiKeyCreationResponse }>> {
  return fetchApi<{ message: string; key: ApiKeyCreationResponse }>('/api-keys', {
    method: 'POST',
    body: JSON.stringify({
      name,
      csrf_token: csrfToken,
      metadata,
    }),
  });
}

/**
 * Revoke (deactivate) an API key
 *
 * DELETE /api/api-keys/{id}
 */
export async function revokeApiKey(keyId: string): Promise<ApiResponse<{ message: string }>> {
  return fetchApi<{ message: string }>(`/api-keys/${keyId}`, {
    method: 'DELETE',
  });
}

/**
 * Permanently delete an API key
 *
 * DELETE /api/api-keys/{id}/permanent
 */
export async function deleteApiKey(keyId: string): Promise<ApiResponse<{ message: string }>> {
  return fetchApi<{ message: string }>(`/api-keys/${keyId}/permanent`, {
    method: 'DELETE',
  });
}
