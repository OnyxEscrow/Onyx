"""NEXUS SDK Data Types.

Pydantic models for NEXUS Escrow API request and response data.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# =============================================================================
# Enums
# =============================================================================


class EscrowStatus(str, Enum):
    """Escrow lifecycle states."""

    CREATED = "created"
    PENDING_COUNTERPARTY = "pending_counterparty"
    PENDING_FUNDING = "pending_funding"
    FUNDED = "funded"
    ACTIVE = "active"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    RELEASING = "releasing"
    RELEASED = "released"
    COMPLETED = "completed"
    DISPUTED = "disputed"
    RESOLVED = "resolved"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class DisputeResolution(str, Enum):
    """Dispute resolution outcomes."""

    BUYER_WINS = "buyer_wins"
    SELLER_WINS = "seller_wins"
    SPLIT = "split"


class WebhookEventType(str, Enum):
    """Types of webhook events."""

    ESCROW_CREATED = "escrow.created"
    ESCROW_FUNDED = "escrow.funded"
    ESCROW_SHIPPED = "escrow.shipped"
    ESCROW_RELEASED = "escrow.released"
    ESCROW_DISPUTED = "escrow.disputed"
    ESCROW_RESOLVED = "escrow.resolved"
    ESCROW_CANCELLED = "escrow.cancelled"
    ESCROW_EXPIRED = "escrow.expired"


class FrostRole(str, Enum):
    """FROST DKG participant roles."""

    BUYER = "buyer"
    VENDOR = "vendor"
    ARBITER = "arbiter"


class FeePriority(str, Enum):
    """Monero transaction fee priority levels."""

    UNIMPORTANT = "unimportant"
    NORMAL = "normal"
    ELEVATED = "elevated"
    PRIORITY = "priority"


class ApiKeyTier(str, Enum):
    """API key tier levels."""

    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# =============================================================================
# Base model
# =============================================================================


class NexusModel(BaseModel):
    """Base model with common configuration."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        populate_by_name=True,
        use_enum_values=True,
    )


# =============================================================================
# Escrow Request/Response models
# =============================================================================


class CreateEscrowRequest(NexusModel):
    """Request to create a new escrow (EaaS flow).

    Creator specifies amount and role. Counterparty joins later via join_link.
    """

    amount: int = Field(
        ...,
        description="Escrow amount in atomic units (piconero)",
        gt=0,
    )
    creator_role: str = Field(
        "buyer",
        description="Role of the creator: 'buyer' or 'seller'",
    )
    description: str | None = Field(
        None,
        description="Optional description for the escrow",
        max_length=500,
    )
    external_reference: str | None = Field(
        None,
        description="Optional external reference ID from your system",
    )


class CreateEscrowResponse(NexusModel):
    """Response from creating an escrow."""

    escrow_id: str = Field(..., description="Unique escrow identifier")
    status: str = Field(..., description="Initial status (pending_counterparty)")
    creator_role: str = Field(..., description="Role of the creator")
    join_link: str = Field(..., description="Link for counterparty to join")


class ReleaseEscrowRequest(NexusModel):
    """Request to release escrow funds to seller."""

    buyer_signature: str = Field(
        ...,
        description="Buyer's FROST signature share",
    )


class DisputeEscrowRequest(NexusModel):
    """Request to open a dispute on an escrow."""

    reason: str = Field(
        ...,
        description="Reason for the dispute",
        min_length=10,
        max_length=2000,
    )
    evidence_urls: list[str] | None = Field(
        None,
        description="Optional URLs to evidence",
        max_length=10,
    )


class ResolveDisputeRequest(NexusModel):
    """Request to resolve a dispute (platform/arbitrator only)."""

    resolution: DisputeResolution = Field(
        ...,
        description="Dispute resolution outcome",
    )
    buyer_amount: int | None = Field(
        None,
        description="Amount to send to buyer (for split resolution)",
    )
    seller_amount: int | None = Field(
        None,
        description="Amount to send to seller (for split resolution)",
    )
    reason: str | None = Field(
        None,
        description="Reason for the resolution",
        max_length=2000,
    )


class RegisterWebhookRequest(NexusModel):
    """Request to register a new webhook endpoint."""

    url: str = Field(
        ...,
        description="HTTPS URL to receive webhook events",
    )
    events: list[WebhookEventType] = Field(
        ...,
        description="List of event types to subscribe to",
        min_length=1,
    )
    secret: str | None = Field(
        None,
        description="Optional secret for signing webhooks (auto-generated if not provided)",
        min_length=32,
    )


class Escrow(NexusModel):
    """Escrow resource returned by the API.

    Uses model_config extra='allow' to accept any additional fields
    from the server without breaking.
    """

    model_config = {"extra": "allow"}

    id: str = Field(..., description="Unique escrow identifier")
    amount: int = Field(..., description="Escrow amount in atomic units")
    status: str = Field(..., description="Current escrow status")
    description: str | None = Field(None, description="Escrow description")
    created_at: str | None = Field(None, description="Creation timestamp")
    order_id: str | None = Field(None, description="Order ID (same as escrow ID for EaaS)")
    buyer_id: str | None = Field(None, description="Buyer user ID")
    vendor_id: str | None = Field(None, description="Vendor user ID")
    arbiter_id: str | None = Field(None, description="Arbiter user ID")
    multisig_address: str | None = Field(None, description="Multisig escrow address")
    multisig_phase: str | None = Field(None, description="Current multisig phase")
    frost_enabled: bool | None = Field(None, description="Whether FROST is enabled")
    frost_dkg_complete: bool | None = Field(None, description="Whether FROST DKG is complete")
    external_reference: str | None = Field(None, description="External reference ID")
    broadcast_tx_hash: str | None = Field(None, description="Broadcast transaction hash")
    vendor_payout_address: str | None = Field(None, description="Vendor payout address")
    buyer_refund_address: str | None = Field(None, description="Buyer refund address")


class EscrowList(NexusModel):
    """List of escrows (from /v1/user/escrows)."""

    model_config = {"extra": "allow"}


class FundingInstructions(NexusModel):
    """Instructions for funding an escrow."""

    escrow_id: str = Field(..., description="Escrow ID")
    escrow_address: str = Field(..., description="Multisig address to send funds to")
    amount: int = Field(..., description="Amount to send in atomic units")
    amount_xmr: str = Field(..., description="Amount in XMR (formatted string)")
    qr_code_uri: str | None = Field(None, description="URI for QR code generation")
    expires_at: datetime = Field(..., description="Deadline to fund the escrow")


# =============================================================================
# Webhook models
# =============================================================================


class Webhook(NexusModel):
    """Webhook configuration returned by the API."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Unique webhook identifier")
    url: str = Field(..., description="Webhook endpoint URL")
    events: list[str] = Field(..., description="Subscribed event types")
    secret: str | None = Field(None, description="Webhook signing secret (only on create)")
    is_active: bool = Field(True, description="Whether webhook is active")
    created_at: str | None = Field(None, description="Creation timestamp")
    updated_at: str | None = Field(None, description="Last update timestamp")
    consecutive_failures: int = Field(0, description="Consecutive failure count")
    last_failure_reason: str | None = Field(None, description="Last failure reason")
    description: str | None = Field(None, description="Webhook description")


class WebhookList(NexusModel):
    """List of webhooks."""

    model_config = ConfigDict(extra="allow")

    webhooks: list[Webhook] = Field(..., description="List of webhooks")
    count: int | None = Field(None, description="Total webhook count")


class WebhookEvent(NexusModel):
    """Webhook event payload."""

    id: str = Field(..., description="Unique event identifier")
    type: WebhookEventType = Field(..., description="Event type")
    escrow_id: str = Field(..., description="Related escrow ID")
    escrow: Escrow = Field(..., description="Escrow state at time of event")
    timestamp: datetime = Field(..., description="Event timestamp")
    metadata: dict[str, Any] | None = Field(None, description="Additional event metadata")


class WebhookDelivery(NexusModel):
    """Webhook delivery record."""

    id: str = Field(..., description="Delivery ID")
    webhook_id: str = Field(..., description="Webhook ID")
    event_type: str = Field(..., description="Event type")
    status_code: int | None = Field(None, description="HTTP response status")
    success: bool = Field(..., description="Whether delivery succeeded")
    attempt: int = Field(..., description="Delivery attempt number")
    created_at: datetime = Field(..., description="Delivery timestamp")
    response_time_ms: int | None = Field(None, description="Response time in ms")


class WebhookDeliveryStats(NexusModel):
    """Webhook delivery statistics."""

    total_deliveries: int = Field(0, description="Total delivery attempts")
    successful: int = Field(0, description="Successful deliveries")
    failed: int = Field(0, description="Failed deliveries")
    avg_response_time_ms: float | None = Field(None, description="Average response time")


# =============================================================================
# API Key models
# =============================================================================


class ApiKeyInfo(NexusModel):
    """API key information."""

    key_id: str = Field(..., description="API key identifier (nxs_...)")
    name: str = Field(..., description="Human-readable key name")
    permissions: list[str] = Field(default_factory=list, description="Granted permissions")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_used_at: datetime | None = Field(None, description="Last usage timestamp")
    expires_at: datetime | None = Field(None, description="Expiration timestamp")


class ApiKeyCreationResponse(NexusModel):
    """Response from creating an API key (includes raw key)."""

    id: str = Field(..., description="Key ID")
    key_prefix: str = Field(..., description="Key prefix for display")
    raw_key: str | None = Field(None, description="Raw API key (only shown once)")
    name: str = Field(..., description="Key name")
    tier: str = Field(..., description="Key tier")
    created_at: str | None = Field(None, description="Creation timestamp")


class UsageStats(NexusModel):
    """API usage statistics."""

    period_start: datetime = Field(..., description="Period start timestamp")
    period_end: datetime = Field(..., description="Period end timestamp")
    escrows_created: int = Field(..., description="Number of escrows created")
    escrows_completed: int = Field(..., description="Number of escrows completed")
    total_volume: int = Field(..., description="Total volume in atomic units")
    api_calls: int = Field(..., description="Total API calls made")


# =============================================================================
# FROST DKG models
# =============================================================================


class DkgParticipants(NexusModel):
    """DKG round readiness per participant."""

    buyer_round1_ready: bool = False
    vendor_round1_ready: bool = False
    arbiter_round1_ready: bool = False
    buyer_round2_ready: bool = False
    vendor_round2_ready: bool = False
    arbiter_round2_ready: bool = False


class DkgStatus(NexusModel):
    """FROST DKG status for an escrow."""

    escrow_id: str = Field(..., description="Escrow ID")
    round1_complete: bool = Field(False, description="All Round 1 packages submitted")
    round2_complete: bool = Field(False, description="All Round 2 packages submitted")
    dkg_complete: bool = Field(False, description="DKG finalized with group pubkey")
    participants: DkgParticipants = Field(
        default_factory=DkgParticipants,
        description="Per-participant readiness",
    )


class LagrangeCoefficients(NexusModel):
    """Lagrange coefficients for a signing pair."""

    signer1_lambda: str = Field(..., description="Lambda for signer 1")
    signer2_lambda: str = Field(..., description="Lambda for signer 2")


# =============================================================================
# FROST Signing models
# =============================================================================


class SigningStatus(NexusModel):
    """FROST signing session status."""

    escrow_id: str = Field(..., description="Escrow ID")
    nonces_complete: bool = Field(False, description="All nonces submitted")
    signatures_complete: bool = Field(False, description="All partial sigs submitted")
    tx_hash: str | None = Field(None, description="Broadcast TX hash")


class TxSigningData(NexusModel):
    """Transaction data needed for FROST signing."""

    tx_prefix_hash: str = Field(..., description="TX prefix hash (hex)")
    clsag_message_hash: str = Field(..., description="CLSAG message hash (hex)")
    ring_data_json: str = Field(..., description="Ring member data (JSON)")
    pseudo_out: str | None = Field(None, description="Pseudo output commitment")
    recipient_address: str = Field(..., description="Recipient Monero address")
    amount_atomic: str = Field(..., description="Amount in atomic units")
    multisig_pubkey: str | None = Field(None, description="Group public key")
    pseudo_out_mask: str | None = Field(None, description="Pseudo output mask")
    funding_commitment_mask: str | None = Field(None, description="Funding commitment mask")
    multisig_view_key: str | None = Field(None, description="Multisig view key")
    funding_tx_pubkey: str | None = Field(None, description="Funding TX public key")
    funding_output_index: int | None = Field(None, description="Funding output index")


# =============================================================================
# Fee models
# =============================================================================


class FeeEstimate(NexusModel):
    """Monero transaction fee estimate."""

    fee_per_byte: int = Field(..., description="Fee per byte in piconero")
    quantization_mask: int = Field(..., description="Quantization mask")
    estimated_fee_2_outputs: int = Field(
        ..., description="Estimated fee for 2-output TX"
    )
    estimated_fee_3_outputs: int = Field(
        ..., description="Estimated fee for 3-output TX"
    )
    estimated_fee_custom: int | None = Field(
        None, description="Fee for custom TX size"
    )
    priority: str = Field(..., description="Priority level used")
    live: bool = Field(..., description="Whether estimate is from live daemon")
    fee_xmr: str = Field(..., description="Fee in XMR display format")


class AllFeeEstimates(NexusModel):
    """Fee estimates for all priority levels."""

    estimates: list[FeeEstimate] = Field(..., description="Estimates per priority")
    recommended: str = Field(..., description="Recommended priority level")
    daemon_height: int | None = Field(None, description="Current daemon height")
    daemon_url: str | None = Field(None, description="Serving daemon URL")


class ClientFeeConfig(NexusModel):
    """Client fee configuration."""

    fee_bps: int = Field(..., description="Fee in basis points")
    fee_percent: float = Field(..., description="Fee as percentage")
    source: str = Field(..., description="Fee source (global_default or client_override)")
    client_id: str | None = Field(None, description="Client ID for overrides")


class ClientFeeEstimate(NexusModel):
    """Client fee estimate for a specific amount."""

    amount_atomic: int = Field(..., description="Input amount in piconero")
    fee_bps: int = Field(..., description="Fee in basis points")
    fee_atomic: int = Field(..., description="Fee amount in piconero")
    net_amount_atomic: int = Field(..., description="Amount after fee deduction")
    fee_percent: float = Field(..., description="Fee as percentage")
    source: str = Field(..., description="Fee source")


class DaemonHealth(NexusModel):
    """Daemon endpoint health status."""

    url: str | None = Field(None, description="Daemon URL")
    healthy: bool = Field(..., description="Whether daemon is healthy")
    height: int | None = Field(None, description="Current block height")
    last_response_ms: int | None = Field(None, description="Last response time in ms")


class DaemonHealthSummary(NexusModel):
    """Overall daemon health summary."""

    total: int = Field(..., description="Total endpoint count")
    healthy: int = Field(..., description="Healthy endpoint count")
    unhealthy: int = Field(..., description="Unhealthy endpoint count")
    avg_response_time_ms: int = Field(0, description="Average response time in ms")
    max_height: int | None = Field(None, description="Max block height")
    endpoints: list[DaemonHealth] = Field(
        default_factory=list, description="Individual endpoint health"
    )


# =============================================================================
# Analytics models
# =============================================================================


class UsageAnalytics(NexusModel):
    """Usage analytics response."""

    period: str = Field(..., description="Analytics period")
    total_escrows: int = Field(0, description="Total escrows")
    active_escrows: int = Field(0, description="Active escrows")
    completed_escrows: int = Field(0, description="Completed escrows")
    disputed_escrows: int = Field(0, description="Disputed escrows")
    total_volume_atomic: int = Field(0, description="Total volume in piconero")
    api_keys_count: int = Field(0, description="Number of API keys")
    total_api_requests: int = Field(0, description="Total API requests")


# =============================================================================
# Chat models
# =============================================================================


class ChatKeypairResponse(NexusModel):
    """Chat keypair registration response."""

    id: str | None = Field(None, description="Keypair record ID")
    escrow_id: str | None = Field(None, description="Escrow ID")
    user_id: str | None = Field(None, description="User ID")
    role: str | None = Field(None, description="User role in escrow")
    public_key: str | None = Field(None, description="X25519 public key (hex)")


class ChatKeypairsDto(NexusModel):
    """All participants' chat keypairs for an escrow."""

    buyer_pubkey: str | None = Field(None, description="Buyer public key")
    vendor_pubkey: str | None = Field(None, description="Vendor public key")
    arbiter_pubkey: str | None = Field(None, description="Arbiter public key")
    all_registered: bool = Field(False, description="Whether all 3 keypairs registered")


class ChatMessage(NexusModel):
    """Encrypted chat message."""

    id: str = Field(..., description="Message ID")
    escrow_id: str = Field(..., description="Escrow ID")
    sender_id: str = Field(..., description="Sender user ID")
    sender_role: str = Field(..., description="Sender role")
    encrypted_content: str | None = Field(None, description="Encrypted content for viewer")
    sender_ephemeral_pubkey: str = Field(..., description="Sender ephemeral X25519 pubkey")
    nonce: str = Field(..., description="Encryption nonce (hex)")
    is_own: bool = Field(False, description="Whether message is from current user")
    is_read: bool = Field(False, description="Whether message has been read")
    created_at: str = Field(..., description="Creation timestamp")


class ChatMessageList(NexusModel):
    """Paginated chat message list."""

    messages: list[ChatMessage] = Field(default_factory=list, description="Messages")
    total: int = Field(0, description="Total message count")
    has_more: bool = Field(False, description="Whether more messages exist")
