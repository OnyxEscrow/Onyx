/**
 * NEXUS SDK - TypeScript SDK for NEXUS Escrow-as-a-Service
 *
 * @example
 * ```typescript
 * import { NexusClient, xmrToPiconero } from '@nexus-escrow/sdk';
 *
 * const client = new NexusClient({
 *   apiKey: process.env.NEXUS_API_KEY!,
 * });
 *
 * // Create an escrow
 * const escrow = await client.escrow.create({
 *   buyer_address: '4...',
 *   seller_address: '4...',
 *   amount: xmrToPiconero(1.5),
 * });
 *
 * // Run FROST DKG
 * await client.frost.initDkg(escrow.id);
 *
 * // Estimate fees
 * const fee = await client.fees.estimate('normal');
 *
 * // Register webhook
 * const wh = await client.webhooks.create({
 *   url: 'https://example.com/webhooks',
 *   events: ['escrow.funded', 'escrow.released'],
 * });
 * ```
 *
 * @packageDocumentation
 */

// Main client
export { NexusClient } from './client.js';

// Resources
export { EscrowResource, xmrToPiconero, piconeroToXmr, formatXmr, isValidMainnetAddress } from './escrow.js';
export { WebhookResource, verifyWebhookSignature, parseWebhookPayload } from './webhooks.js';
export { FrostResource } from './frost.js';
export { FeeResource } from './fees.js';
export { AnalyticsResource } from './analytics.js';
export { ApiKeyResource } from './apikeys.js';
export { ChatResource } from './chat.js';

// Errors
export {
  NexusApiError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  InvalidAddressError,
  EscrowError,
  NetworkError,
  TimeoutError,
} from './errors.js';

// Types
export type {
  // Config
  NexusClientConfig,

  // Escrow
  CreateEscrowParams,
  Escrow,
  EscrowStatus,
  EscrowRole,
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

  // FROST DKG
  FrostRole,
  DkgStatus,
  DkgParticipants,
  Round1SubmitParams,
  Round2SubmitParams,
  CompleteDkgParams,
  LagrangeCoefficients,

  // FROST Signing
  SigningInitParams,
  NonceCommitmentParams,
  PartialSignatureParams,
  SigningStatus,

  // Shield Backup
  RegisterShieldParams,
  VerifyShieldParams,

  // Shipping
  ConfirmShippedParams,
  ConfirmReceiptParams,

  // Webhooks
  CreateWebhookParams,
  CreateWebhookResponse,
  Webhook,
  UpdateWebhookParams,
  WebhookDelivery,
  WebhookPayload,
  WebhookEventType,

  // API Keys
  ApiKey,
  ApiKeyTier,
  CreateApiKeyParams,
  ApiKeyCreationResponse,
  ApiKeyPermission,

  // Fees
  FeePriority,
  FeeEstimate,
  AllFeeEstimates,
  DaemonHealth,
  ClientFeeConfig,
  ClientFeeEstimate,

  // Analytics
  AnalyticsPeriod,
  UsageAnalytics,

  // Chat (E2EE)
  RegisterChatKeypairParams,
  ChatKeypairsDto,
  SendChatMessageParams,
  ChatMessage,
  ChatMessagesResponse,

  // Responses
  ApiResponse,
  PaginatedResponse,
  ApiErrorResponse,
  NexusErrorCode,
} from './types.js';

// Re-export version
export const VERSION = '1.1.0';
