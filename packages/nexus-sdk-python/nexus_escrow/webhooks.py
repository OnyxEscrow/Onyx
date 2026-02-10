"""Webhook management for NEXUS SDK.

This module provides webhook registration, signature verification, and delivery management.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, Any

from .exceptions import NexusWebhookVerificationError
from .types import (
    RegisterWebhookRequest,
    Webhook,
    WebhookEvent,
    WebhookEventType,
    WebhookList,
)

if TYPE_CHECKING:
    from .client import NexusClient


class WebhookManager:
    """Manages webhook operations.

    Accessed via ``client.webhooks``.

    Example::

        async with NexusClient(api_key="nxs_...") as client:
            webhook = await client.webhooks.register(
                url="https://example.com/webhooks/nexus",
                events=[WebhookEventType.ESCROW_FUNDED],
            )
    """

    def __init__(self, client: NexusClient) -> None:
        self._client = client

    # =========================================================================
    # CRUD
    # =========================================================================

    async def register(
        self,
        url: str,
        events: list[WebhookEventType],
        *,
        secret: str | None = None,
    ) -> Webhook:
        """Register a new webhook endpoint.

        Args:
            url: HTTPS URL to receive webhook events.
            events: List of event types to subscribe to.
            secret: Optional signing secret (auto-generated if not provided).

        Returns:
            The registered Webhook object with secret.
        """
        request = RegisterWebhookRequest(
            url=url,
            events=events,
            secret=secret,
        )
        response = await self._client._request(
            "POST",
            "/api/v1/webhooks",
            json=request.model_dump(exclude_none=True),
        )
        # Server wraps: {"webhook": {...}, "secret": "..."}
        if isinstance(response, dict) and "webhook" in response:
            wh_data = response["webhook"]
            wh_data["secret"] = response.get("secret")
            return Webhook.model_validate(wh_data)
        return Webhook.model_validate(response)

    async def get(self, webhook_id: str) -> Webhook:
        """Get a webhook by ID.

        Args:
            webhook_id: The webhook identifier.

        Returns:
            The Webhook object.
        """
        response = await self._client._request("GET", f"/api/v1/webhooks/{webhook_id}")
        return Webhook.model_validate(response)

    async def list(self) -> WebhookList:
        """List all registered webhooks.

        Returns:
            List of registered webhooks.
        """
        response = await self._client._request("GET", "/api/v1/webhooks")
        return WebhookList.model_validate(response)

    async def update(
        self,
        webhook_id: str,
        *,
        url: str | None = None,
        events: list[WebhookEventType] | None = None,
        active: bool | None = None,
    ) -> Webhook:
        """Update a webhook configuration.

        Args:
            webhook_id: The webhook identifier.
            url: New webhook URL.
            events: New list of subscribed events.
            active: Enable/disable the webhook.

        Returns:
            Updated Webhook object.
        """
        data: dict[str, object] = {}
        if url is not None:
            data["url"] = url
        if events is not None:
            data["events"] = [e.value if isinstance(e, WebhookEventType) else e for e in events]
        if active is not None:
            data["active"] = active

        response = await self._client._request(
            "PATCH",
            f"/api/v1/webhooks/{webhook_id}",
            json=data,
        )
        return Webhook.model_validate(response)

    async def delete(self, webhook_id: str) -> None:
        """Delete a webhook.

        Args:
            webhook_id: The webhook identifier.
        """
        await self._client._request("DELETE", f"/api/v1/webhooks/{webhook_id}")

    # =========================================================================
    # Lifecycle
    # =========================================================================

    async def activate(self, webhook_id: str) -> dict[str, Any]:
        """Activate a webhook.

        Args:
            webhook_id: The webhook identifier.

        Returns:
            Activation confirmation.
        """
        return await self._client._request(
            "POST", f"/api/v1/webhooks/{webhook_id}/activate"
        )

    async def deactivate(self, webhook_id: str) -> dict[str, Any]:
        """Deactivate a webhook.

        Args:
            webhook_id: The webhook identifier.

        Returns:
            Deactivation confirmation.
        """
        return await self._client._request(
            "POST", f"/api/v1/webhooks/{webhook_id}/deactivate"
        )

    async def rotate_secret(self, webhook_id: str) -> Webhook:
        """Rotate the signing secret for a webhook.

        Generates a new secret and invalidates the old one.

        Args:
            webhook_id: The webhook identifier.

        Returns:
            Updated Webhook object with new secret.
        """
        response = await self._client._request(
            "POST", f"/api/v1/webhooks/{webhook_id}/rotate-secret"
        )
        return Webhook.model_validate(response)

    # =========================================================================
    # Delivery management
    # =========================================================================

    async def get_deliveries(
        self,
        webhook_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Get delivery history for a webhook.

        Args:
            webhook_id: The webhook identifier.
            limit: Maximum deliveries to return.
            offset: Pagination offset.

        Returns:
            Dict with deliveries list and pagination info.
        """
        return await self._client._request(
            "GET",
            f"/api/v1/webhooks/{webhook_id}/deliveries",
            params={"limit": limit, "offset": offset},
        )

    async def retry_delivery(
        self, webhook_id: str, delivery_id: str
    ) -> dict[str, Any]:
        """Retry a failed webhook delivery.

        Args:
            webhook_id: The webhook identifier.
            delivery_id: The delivery identifier to retry.

        Returns:
            Retry result.
        """
        return await self._client._request(
            "POST",
            f"/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/retry",
        )

    async def get_stats(self, webhook_id: str) -> dict[str, Any]:
        """Get delivery statistics for a webhook.

        Args:
            webhook_id: The webhook identifier.

        Returns:
            Delivery statistics (total, success, fail, avg response time).
        """
        return await self._client._request(
            "GET", f"/api/v1/webhooks/{webhook_id}/stats"
        )

    # =========================================================================
    # Static verification helpers
    # =========================================================================

    @staticmethod
    def verify_signature(
        payload: bytes,
        signature: str,
        secret: str,
        *,
        timestamp: str | None = None,
        tolerance_seconds: int = 300,
    ) -> bool:
        """Verify a webhook signature.

        This is a static method that can be used without a client instance.
        It verifies that a webhook payload was signed by NEXUS.

        Args:
            payload: The raw request body bytes.
            signature: The X-Nexus-Signature header value.
            secret: Your webhook signing secret.
            timestamp: The X-Nexus-Timestamp header (optional).
            tolerance_seconds: Max age of request in seconds (default 5 min).

        Returns:
            True if signature is valid.

        Raises:
            NexusWebhookVerificationError: If verification fails.
        """
        import time

        # Verify timestamp if provided (replay attack protection)
        if timestamp:
            try:
                ts = int(timestamp)
                now = int(time.time())
                if abs(now - ts) > tolerance_seconds:
                    raise NexusWebhookVerificationError(
                        f"Timestamp too old (>{tolerance_seconds}s)"
                    )
            except ValueError as err:
                raise NexusWebhookVerificationError("Invalid timestamp format") from err

        # Build signed payload: timestamp.payload if timestamp provided
        if timestamp:
            signed_payload = f"{timestamp}.".encode() + payload
        else:
            signed_payload = payload

        # Compute expected signature
        expected = hmac.new(
            secret.encode(),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()

        # Parse signature header (format: "sha256=HEXDIGEST")
        if signature.startswith("sha256="):
            provided = signature[7:]
        else:
            provided = signature

        # Constant-time comparison
        if not hmac.compare_digest(expected, provided):
            raise NexusWebhookVerificationError("Signature mismatch")

        return True

    @staticmethod
    def parse_event(payload: bytes) -> WebhookEvent:
        """Parse a webhook event from the request payload.

        Args:
            payload: The raw request body bytes.

        Returns:
            Parsed WebhookEvent object.
        """
        return WebhookEvent.model_validate_json(payload)
