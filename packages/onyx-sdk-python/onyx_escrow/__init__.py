"""Onyx Escrow Python SDK.

A Python client library for the Onyx Escrow-as-a-Service API.
Enables non-custodial Monero escrow with browser-based FROST multisig.

Quick Start:
    >>> from onyx_escrow import OnyxClient
    >>> async with OnyxClient(api_key="nxs_...") as client:
    ...     escrow = await client.create_escrow(
    ...         buyer_address="4...",
    ...         seller_address="4...",
    ...         amount=1_000_000_000_000,  # 1 XMR in piconero
    ...     )
    ...     print(f"Created escrow: {escrow.id}")

For more information, see https://docs.onyx-escrow.com/sdk/python
"""

from .analytics import AnalyticsManager
from .api_keys import ApiKeyManager
from .chat import ChatManager
from .client import OnyxClient
from .dkg import DkgManager
from .escrow import EscrowManager
from .exceptions import (
    OnyxApiError,
    OnyxAuthenticationError,
    OnyxAuthorizationError,
    OnyxConnectionError,
    OnyxError,
    OnyxNotFoundError,
    OnyxRateLimitError,
    OnyxServerError,
    OnyxTimeoutError,
    OnyxValidationError,
    OnyxWebhookVerificationError,
)
from .fees import FeeManager
from .signing import SigningManager
from .types import (
    AllFeeEstimates,
    ApiKeyCreationResponse,
    ApiKeyInfo,
    ApiKeyTier,
    ChatKeypairResponse,
    ChatKeypairsDto,
    ChatMessage,
    ChatMessageList,
    ClientFeeConfig,
    ClientFeeEstimate,
    CreateEscrowRequest,
    CreateEscrowResponse,
    DaemonHealth,
    DaemonHealthSummary,
    DisputeEscrowRequest,
    DisputeResolution,
    DkgParticipants,
    DkgStatus,
    Escrow,
    EscrowList,
    EscrowStatus,
    FeeEstimate,
    FeePriority,
    FrostRole,
    FundingInstructions,
    LagrangeCoefficients,
    RegisterWebhookRequest,
    ReleaseEscrowRequest,
    ResolveDisputeRequest,
    SigningStatus,
    TxSigningData,
    UsageAnalytics,
    UsageStats,
    Webhook,
    WebhookDelivery,
    WebhookDeliveryStats,
    WebhookEvent,
    WebhookEventType,
    WebhookList,
)
from .webhooks import WebhookManager

__version__ = "0.3.0"
__all__ = [
    # Client
    "OnyxClient",
    # Managers
    "EscrowManager",
    "DkgManager",
    "SigningManager",
    "WebhookManager",
    "FeeManager",
    "AnalyticsManager",
    "ChatManager",
    "ApiKeyManager",
    # Types - Enums
    "EscrowStatus",
    "DisputeResolution",
    "WebhookEventType",
    "FrostRole",
    "FeePriority",
    "ApiKeyTier",
    # Types - Request models
    "CreateEscrowRequest",
    "ReleaseEscrowRequest",
    "DisputeEscrowRequest",
    "ResolveDisputeRequest",
    "RegisterWebhookRequest",
    # Types - Response models (Escrow)
    "CreateEscrowResponse",
    "Escrow",
    "EscrowList",
    "FundingInstructions",
    # Types - Response models (DKG/Signing)
    "DkgParticipants",
    "DkgStatus",
    "LagrangeCoefficients",
    "SigningStatus",
    "TxSigningData",
    # Types - Response models (Fees)
    "FeeEstimate",
    "AllFeeEstimates",
    "ClientFeeConfig",
    "ClientFeeEstimate",
    "DaemonHealth",
    "DaemonHealthSummary",
    # Types - Response models (Analytics)
    "UsageAnalytics",
    # Types - Response models (Webhooks)
    "Webhook",
    "WebhookList",
    "WebhookEvent",
    "WebhookDelivery",
    "WebhookDeliveryStats",
    # Types - Response models (Chat)
    "ChatKeypairResponse",
    "ChatKeypairsDto",
    "ChatMessage",
    "ChatMessageList",
    # Types - Response models (API Keys)
    "ApiKeyInfo",
    "ApiKeyCreationResponse",
    # Types - Response models (Account)
    "UsageStats",
    # Exceptions
    "OnyxError",
    "OnyxApiError",
    "OnyxAuthenticationError",
    "OnyxAuthorizationError",
    "OnyxNotFoundError",
    "OnyxValidationError",
    "OnyxRateLimitError",
    "OnyxServerError",
    "OnyxConnectionError",
    "OnyxTimeoutError",
    "OnyxWebhookVerificationError",
    # Version
    "__version__",
]


async def create_escrow(
    api_key: str,
    amount: int,
    *,
    creator_role: str = "buyer",
    **kwargs: object,
) -> CreateEscrowResponse:
    """Quick helper to create an escrow.

    Creates a temporary client and closes it after use.
    For multiple operations, use OnyxClient as a context manager instead.

    Args:
        api_key: Your Onyx API key.
        amount: Escrow amount in atomic units (piconero).
        creator_role: Role of the creator ('buyer' or 'seller').
        **kwargs: Additional arguments (description, external_reference).

    Returns:
        CreateEscrowResponse with escrow_id, status, and join_link.
    """
    async with OnyxClient(api_key=api_key) as client:
        return await client.create_escrow(
            amount=amount,
            creator_role=creator_role,
            **kwargs,
        )
