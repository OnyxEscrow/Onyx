/**
 * NEXUS SDK Type Definitions
 * All types for the NEXUS Escrow-as-a-Service API
 */

// ============================================================================
// Configuration Types
// ============================================================================

export interface NexusClientConfig {
  /** API key for authentication (format: nxs_...) */
  apiKey: string;
  /** Base URL for the NEXUS API (default: https://api.nexus-escrow.com) */
  baseUrl?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom fetch implementation (for testing or special environments) */
  fetch?: typeof fetch;
}

// ============================================================================
// Escrow Types
// ============================================================================

export type EscrowStatus =
  | 'created'
  | 'pending_funding'
  | 'funded'
  | 'shipped'
  | 'in_progress'
  | 'signing'
  | 'releasing'
  | 'awaiting_release'
  | 'released'
  | 'completed'
  | 'disputed'
  | 'resolved'
  | 'refunded'
  | 'cancelled'
  | 'expired';

export type EscrowRole = 'buyer' | 'seller' | 'vendor' | 'arbitrator' | 'arbiter';

export interface CreateEscrowParams {
  /** Amount in piconero (1 XMR = 1_000_000_000_000 piconero) */
  amount: bigint | number;
  /** Role of the creator: 'buyer' or 'seller' (default: 'buyer') */
  creator_role?: 'buyer' | 'seller' | 'vendor';
  /** Optional description for the escrow */
  description?: string;
  /** Optional external reference ID from your system */
  external_reference?: string;
}

export interface CreateEscrowResponse {
  /** Unique escrow identifier */
  escrow_id: string;
  /** Initial status (pending_counterparty) */
  status: string;
  /** Role of the creator */
  creator_role: string;
  /** Link for counterparty to join */
  join_link: string;
}

export interface Escrow {
  /** Unique escrow identifier */
  id: string;
  /** Current status of the escrow */
  status: EscrowStatus;
  /** Buyer's Monero address */
  buyer_address: string;
  /** Seller's Monero address */
  seller_address: string;
  /** Escrow amount in piconero */
  amount: string;
  /** Platform fee in piconero */
  fee: string;
  /** Deposit address for funding (2-of-3 multisig) */
  deposit_address: string;
  /** Description if provided */
  description: string | null;
  /** External ID if provided */
  external_id: string | null;
  /** Custom metadata */
  metadata: Record<string, unknown> | null;
  /** ISO 8601 creation timestamp */
  created_at: string;
  /** ISO 8601 last update timestamp */
  updated_at: string;
  /** ISO 8601 expiration timestamp */
  expires_at: string;
  /** ISO 8601 funding confirmation timestamp */
  funded_at: string | null;
  /** ISO 8601 release timestamp */
  released_at: string | null;
  /** Transaction ID of the release transaction */
  release_txid: string | null;
  /** Buyer user ID */
  buyer_id?: string;
  /** Vendor user ID */
  vendor_id?: string;
  /** Arbiter user ID */
  arbiter_id?: string;
  /** Vendor payout address */
  vendor_payout_address?: string | null;
  /** Buyer refund address */
  buyer_refund_address?: string | null;
}

export interface EscrowListParams {
  /** Filter by status */
  status?: EscrowStatus;
  /** Filter by external ID */
  external_id?: string;
  /** Maximum number of results (default: 20, max: 100) */
  limit?: number;
  /** Pagination cursor */
  cursor?: string;
  /** Sort order (default: desc) */
  order?: 'asc' | 'desc';
}

export interface EscrowListResponse {
  escrows: Escrow[];
  /** Cursor for next page, null if no more results */
  next_cursor: string | null;
  /** Total count of matching escrows */
  total_count: number;
}

export interface ReleaseEscrowParams {
  /** Escrow ID to release */
  escrow_id: string;
  /** Recipient address (must match buyer or seller) */
  recipient_address: string;
}

export interface ReleaseEscrowResponse {
  escrow: Escrow;
  /** Transaction ID of the release */
  txid: string;
}

export interface DisputeEscrowParams {
  /** Escrow ID to dispute */
  escrow_id: string;
  /** Reason for the dispute */
  reason: string;
  /** Role of the party raising the dispute */
  raised_by: EscrowRole;
}

export interface ResolveDisputeParams {
  /** Escrow ID to resolve */
  escrow_id: string;
  /** Winner of the dispute */
  winner: 'buyer' | 'seller';
  /** Resolution notes */
  resolution_notes?: string;
}

export interface JoinEscrowParams {
  /** Role to join as */
  role?: string;
}

export interface FundingNotificationParams {
  /** Transaction hash of the funding TX */
  tx_hash?: string;
  /** Amount sent in piconero */
  amount?: string;
}

export interface SetPayoutAddressParams {
  /** Monero payout address for vendor */
  payout_address: string;
}

export interface SetRefundAddressParams {
  /** Monero refund address for buyer */
  refund_address: string;
}

// ============================================================================
// FROST DKG Types
// ============================================================================

export type FrostRole = 'buyer' | 'vendor' | 'arbiter';

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

export interface Round1SubmitParams {
  /** Participant role */
  role: FrostRole;
  /** Hex-encoded Round 1 package */
  package: string;
}

export interface Round2SubmitParams {
  /** Sender role */
  role: FrostRole;
  /** Map of recipient index to hex-encoded package */
  packages: Record<string, string>;
}

export interface CompleteDkgParams {
  /** Hex-encoded group public key (64 hex chars) */
  group_pubkey: string;
  /** Monero multisig address (95 chars) */
  multisig_address: string;
  /** Hex-encoded multisig view key (64 hex chars) */
  multisig_view_key: string;
}

export interface LagrangeCoefficients {
  signer1_lambda: string;
  signer2_lambda: string;
}

// ============================================================================
// FROST Signing Types
// ============================================================================

export interface SigningInitParams {
  /** Action: 'release' or 'refund' or 'dispute' */
  action: string;
  /** Destination address */
  destination_address?: string;
  /** Signer 1 role */
  signer1_role?: string;
  /** Signer 2 role */
  signer2_role?: string;
}

export interface NonceCommitmentParams {
  /** Participant role */
  role: FrostRole;
  /** Hex-encoded nonce commitment */
  hiding_nonce_commitment: string;
  /** Hex-encoded binding nonce commitment */
  binding_nonce_commitment: string;
}

export interface PartialSignatureParams {
  /** Participant role */
  role: FrostRole;
  /** Hex-encoded partial signature */
  partial_signature: string;
}

export interface SigningStatus {
  escrow_id: string;
  phase: string;
  nonces_submitted: string[];
  partial_sigs_submitted: string[];
  complete: boolean;
  tx_hash?: string;
}

// ============================================================================
// Shield Backup Types
// ============================================================================

export interface RegisterShieldParams {
  /** Hex-encoded backup identifier (min 32 chars) */
  backup_id: string;
  /** Participant role */
  role: FrostRole;
}

export interface VerifyShieldParams {
  /** Hex-encoded backup identifier to verify */
  backup_id: string;
}

// ============================================================================
// Shipping Types
// ============================================================================

export interface ConfirmShippedParams {
  /** Optional tracking information */
  tracking_info?: string;
  /** Estimated delivery days (default: 14) */
  estimated_delivery_days?: number;
}

export interface ConfirmReceiptParams {
  /** REQUIRED: Explicit consent to release funds */
  consent_confirmed: boolean;
  /** Optional feedback */
  feedback?: string;
}

// ============================================================================
// Webhook Types
// ============================================================================

export type WebhookEventType =
  | 'escrow.created'
  | 'escrow.funded'
  | 'escrow.shipped'
  | 'escrow.released'
  | 'escrow.disputed'
  | 'escrow.resolved'
  | 'escrow.cancelled'
  | 'escrow.expired'
  | '*';

export interface CreateWebhookParams {
  /** URL to receive webhook events (must be HTTPS) */
  url: string;
  /** Events to subscribe to */
  events: string[];
  /** Optional description */
  description?: string;
}

export interface Webhook {
  /** Unique webhook identifier */
  id: string;
  /** Webhook endpoint URL */
  url: string;
  /** Subscribed events */
  events: string;
  /** Whether the webhook is active */
  active: boolean;
  /** Secret for signature verification (only shown on creation) */
  secret?: string;
  /** Optional description */
  description?: string | null;
  /** ISO 8601 creation timestamp */
  created_at: string;
  /** ISO 8601 last update timestamp */
  updated_at: string;
}

export interface CreateWebhookResponse {
  webhook: Webhook;
  /** HMAC secret - only shown once at creation */
  secret: string;
}

export interface UpdateWebhookParams {
  /** New URL (optional) */
  url?: string;
  /** New events list (optional) */
  events?: string[];
  /** New description (optional) */
  description?: string;
}

export interface WebhookDelivery {
  /** Delivery attempt ID */
  id: string;
  /** Webhook ID */
  webhook_id: string;
  /** Event type that triggered the delivery */
  event_type: string;
  /** Request payload sent */
  payload: Record<string, unknown>;
  /** HTTP response status code */
  response_status: number | null;
  /** Response body (truncated) */
  response_body: string | null;
  /** Delivery status */
  status: 'pending' | 'success' | 'failed';
  /** Number of retry attempts */
  attempt_count: number;
  /** ISO 8601 timestamp */
  created_at: string;
  /** ISO 8601 timestamp of last attempt */
  attempted_at: string | null;
}

export interface WebhookPayload {
  /** Unique event ID */
  event_id: string;
  /** Event type */
  event_type: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** API version */
  api_version: string;
  /** Event data */
  data: {
    escrow: Escrow;
  };
}

// ============================================================================
// API Key Types
// ============================================================================

export type ApiKeyTier = 'free' | 'pro' | 'enterprise';

export interface ApiKey {
  /** API key ID */
  id: string;
  /** Key name/label */
  name: string;
  /** Key prefix (first 8 characters) */
  key_prefix: string;
  /** Tier level */
  tier: ApiKeyTier;
  /** Whether the key is active */
  is_active: boolean;
  /** Total API requests made */
  total_requests: number;
  /** ISO 8601 creation timestamp */
  created_at: string;
  /** ISO 8601 last used timestamp */
  last_used_at: string | null;
  /** ISO 8601 expiration timestamp */
  expires_at: string | null;
  /** Optional metadata */
  metadata: string | null;
}

export interface CreateApiKeyParams {
  /** Human-readable name for the key */
  name: string;
  /** Optional expiration date (YYYY-MM-DD HH:MM:SS) */
  expires_at?: string;
  /** Optional metadata (JSON string) */
  metadata?: string;
  /** CSRF token */
  csrf_token: string;
}

export interface ApiKeyCreationResponse {
  id: string;
  /** The raw API key (only shown once) */
  raw_key: string;
  key_prefix: string;
  tier: ApiKeyTier;
}

export type ApiKeyPermission =
  | 'escrow:read'
  | 'escrow:write'
  | 'webhook:read'
  | 'webhook:write';

// ============================================================================
// Fee Types
// ============================================================================

export type FeePriority = 'unimportant' | 'normal' | 'elevated' | 'priority';

export interface FeeEstimate {
  /** Fee per byte in piconero */
  fee_per_byte: number;
  /** Quantization mask */
  quantization_mask: number;
  /** Estimated fee for 2-output transaction */
  estimated_fee_2_outputs: number;
  /** Estimated fee for 3-output transaction (with platform fee) */
  estimated_fee_3_outputs: number;
  /** Estimated fee for custom size (if tx_size provided) */
  estimated_fee_custom?: number;
  /** Priority level used */
  priority: string;
  /** Whether estimate is from live daemon */
  live: boolean;
  /** Fee in XMR string for display */
  fee_xmr: string;
}

export interface AllFeeEstimates {
  estimates: FeeEstimate[];
  recommended: string;
  daemon_height: number | null;
  daemon_url: string | null;
}

export interface DaemonHealth {
  total: number;
  healthy: number;
  unhealthy: number;
  avg_response_time_ms: number;
  max_height: number | null;
  endpoints: Array<{
    url: string;
    healthy: boolean;
    height?: number;
    last_response_ms?: number;
  }>;
}

export interface ClientFeeConfig {
  fee_bps: number;
  fee_percent: number;
  source: string;
  client_id: string | null;
}

export interface ClientFeeEstimate {
  amount_atomic: number;
  fee_bps: number;
  fee_atomic: number;
  net_amount_atomic: number;
  fee_percent: number;
  source: string;
}

// ============================================================================
// Analytics Types
// ============================================================================

export type AnalyticsPeriod = '24h' | '7d' | '30d' | 'all';

export interface UsageAnalytics {
  period: string;
  total_escrows: number;
  active_escrows: number;
  completed_escrows: number;
  disputed_escrows: number;
  total_volume_atomic: number;
  api_keys_count: number;
  total_api_requests: number;
}

// ============================================================================
// Escrow Chat Types (E2EE)
// ============================================================================

export interface RegisterChatKeypairParams {
  /** X25519 public key (64 hex chars) */
  public_key: string;
}

export interface ChatKeypairsDto {
  buyer_pubkey: string | null;
  vendor_pubkey: string | null;
  arbiter_pubkey: string | null;
  all_registered: boolean;
}

export interface SendChatMessageParams {
  /** Ciphertext for buyer (base64) */
  encrypted_content_buyer: string;
  /** Ciphertext for vendor (base64) */
  encrypted_content_vendor: string;
  /** Ciphertext for arbiter (base64) */
  encrypted_content_arbiter: string;
  /** X25519 ephemeral public key (hex) */
  sender_ephemeral_pubkey: string;
  /** 12-byte nonce (hex) */
  nonce: string;
  /** Optional FROST signature for non-repudiation */
  frost_signature?: string;
}

export interface ChatMessage {
  id: string;
  escrow_id: string;
  sender_id: string;
  sender_role: string;
  encrypted_content: string;
  sender_ephemeral_pubkey: string;
  nonce: string;
  frost_signature: string | null;
  is_own: boolean;
  is_read: boolean;
  created_at: string;
}

export interface ChatMessagesResponse {
  messages: ChatMessage[];
  total: number;
  has_more: boolean;
}

// ============================================================================
// Response Types
// ============================================================================

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  meta?: {
    request_id: string;
    timestamp: string;
  };
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
    next_cursor: string | null;
  };
}

// ============================================================================
// Error Types
// ============================================================================

export interface ApiErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  meta?: {
    request_id: string;
    timestamp: string;
  };
}

export type NexusErrorCode =
  | 'INVALID_API_KEY'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'VALIDATION_ERROR'
  | 'INVALID_ADDRESS'
  | 'INSUFFICIENT_FUNDS'
  | 'ESCROW_NOT_FUNDED'
  | 'ESCROW_ALREADY_RELEASED'
  | 'ESCROW_EXPIRED'
  | 'DISPUTE_ALREADY_RAISED'
  | 'WEBHOOK_DELIVERY_FAILED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'INTERNAL_ERROR';
