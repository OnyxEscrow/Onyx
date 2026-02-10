"""Escrow operations for NEXUS SDK.

This module provides the EscrowManager class for managing escrow operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .types import (
    CreateEscrowRequest,
    CreateEscrowResponse,
    DisputeEscrowRequest,
    DisputeResolution,
    Escrow,
    EscrowStatus,
    ReleaseEscrowRequest,
    ResolveDisputeRequest,
)

if TYPE_CHECKING:
    from .client import NexusClient


class EscrowManager:
    """Manages escrow operations.

    Accessed via ``client.escrows``.

    Example::

        async with NexusClient(api_key="nxs_...") as client:
            escrow = await client.escrows.create(
                buyer_address="4...",
                seller_address="4...",
                amount=1_000_000_000_000,
            )
    """

    def __init__(self, client: NexusClient) -> None:
        self._client = client

    # =========================================================================
    # CRUD
    # =========================================================================

    async def create(
        self,
        amount: int,
        *,
        creator_role: str = "buyer",
        description: str | None = None,
        external_reference: str | None = None,
    ) -> CreateEscrowResponse:
        """Create a new escrow (EaaS flow).

        Creator specifies amount and role. Counterparty joins later
        via the returned join_link.

        Args:
            amount: Escrow amount in atomic units (piconero).
            creator_role: Role of the creator ('buyer' or 'seller').
            description: Optional description for the escrow.
            external_reference: Optional external reference from your system.

        Returns:
            CreateEscrowResponse with escrow_id, status, and join_link.
        """
        request = CreateEscrowRequest(
            amount=amount,
            creator_role=creator_role,
            description=description,
            external_reference=external_reference,
        )
        response = await self._client._request(
            "POST",
            "/api/v1/escrows/create",
            json=request.model_dump(exclude_none=True),
        )
        return CreateEscrowResponse.model_validate(response)

    async def get(self, escrow_id: str) -> Escrow:
        """Get an escrow by ID.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            The Escrow object.
        """
        response = await self._client._request("GET", f"/api/v1/escrows/{escrow_id}")
        return Escrow.model_validate(response)

    async def list(
        self,
        *,
        status: str | None = None,
    ) -> list[Escrow]:
        """List escrows for the authenticated user.

        Args:
            status: Filter by escrow status (optional).

        Returns:
            List of Escrow objects.
        """
        params: dict[str, Any] = {}
        if status is not None:
            params["status"] = status.value if isinstance(status, EscrowStatus) else status
        response = await self._client._request("GET", "/api/v1/user/escrows", params=params)
        if isinstance(response, list):
            return [Escrow.model_validate(e) for e in response]
        return [Escrow.model_validate(response)]

    # =========================================================================
    # Lifecycle transitions
    # =========================================================================

    async def join(self, escrow_id: str) -> dict[str, Any]:
        """Join an escrow as the counterparty.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Join confirmation.
        """
        return await self._client._request(
            "POST", f"/api/v1/escrows/{escrow_id}/join"
        )

    async def notify_funding(
        self, escrow_id: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Notify the platform that funding has been sent.

        Args:
            escrow_id: The escrow identifier.
            **kwargs: Additional funding notification data (tx_hash, commitment, etc.).

        Returns:
            Funding notification acknowledgment.
        """
        return await self._client._request(
            "POST",
            f"/api/v1/escrows/{escrow_id}/funding-notification",
            json=kwargs if kwargs else None,
        )

    async def mark_delivered(self, escrow_id: str) -> dict[str, Any]:
        """Mark escrow goods/services as delivered (vendor action).

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Delivery confirmation.
        """
        return await self._client._request(
            "POST", f"/api/v1/escrows/{escrow_id}/deliver"
        )

    async def confirm_delivery(self, escrow_id: str) -> dict[str, Any]:
        """Confirm delivery receipt (buyer action).

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Delivery confirmation.
        """
        return await self._client._request(
            "POST", f"/api/v1/escrows/{escrow_id}/confirm"
        )

    async def release(self, escrow_id: str, buyer_signature: str) -> Escrow:
        """Release escrow funds to the seller.

        Args:
            escrow_id: The escrow identifier.
            buyer_signature: Buyer's FROST signature share.

        Returns:
            Updated Escrow object with release transaction hash.
        """
        request = ReleaseEscrowRequest(buyer_signature=buyer_signature)
        response = await self._client._request(
            "POST",
            f"/api/v1/escrows/{escrow_id}/release",
            json=request.model_dump(),
        )
        return Escrow.model_validate(response)

    async def refund(self, escrow_id: str) -> dict[str, Any]:
        """Refund escrow funds to the buyer.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Refund response.
        """
        return await self._client._request(
            "POST", f"/api/v1/escrows/{escrow_id}/refund"
        )

    async def dispute(
        self,
        escrow_id: str,
        reason: str,
        *,
        evidence_urls: list[str] | None = None,
    ) -> dict[str, Any]:
        """Open a dispute on an escrow.

        Args:
            escrow_id: The escrow identifier.
            reason: Reason for the dispute (min 10 chars).
            evidence_urls: Optional URLs to evidence.

        Returns:
            Dispute confirmation with success status and message.
        """
        request = DisputeEscrowRequest(
            reason=reason,
            evidence_urls=evidence_urls,
        )
        return await self._client._request(
            "POST",
            f"/api/v1/escrows/{escrow_id}/dispute",
            json=request.model_dump(exclude_none=True),
        )

    async def resolve(
        self,
        escrow_id: str,
        resolution: DisputeResolution,
        *,
        buyer_amount: int | None = None,
        seller_amount: int | None = None,
        reason: str | None = None,
    ) -> Escrow:
        """Resolve a disputed escrow.

        Args:
            escrow_id: The escrow identifier.
            resolution: The dispute resolution outcome.
            buyer_amount: Amount to buyer (required for split resolution).
            seller_amount: Amount to seller (required for split resolution).
            reason: Optional explanation for the resolution.

        Returns:
            Updated Escrow object in resolved state.
        """
        request = ResolveDisputeRequest(
            resolution=resolution,
            buyer_amount=buyer_amount,
            seller_amount=seller_amount,
            reason=reason,
        )
        response = await self._client._request(
            "POST",
            f"/api/v1/escrows/{escrow_id}/resolve",
            json=request.model_dump(exclude_none=True),
        )
        return Escrow.model_validate(response)

    # =========================================================================
    # Shipping flow (v0.75.0)
    # =========================================================================

    async def confirm_shipped(
        self,
        escrow_id: str,
        *,
        tracking_info: str | None = None,
        estimated_delivery_days: int | None = None,
    ) -> dict[str, Any]:
        """Confirm shipment (vendor only).

        Changes status from "funded" to "shipped" and sets an auto-release
        timer for buyer timeout.

        Args:
            escrow_id: The escrow identifier.
            tracking_info: Optional tracking info (carrier, tracking number).
            estimated_delivery_days: Days until auto-release (default: 14).

        Returns:
            Shipment confirmation with auto_release_at timestamp.
        """
        payload: dict[str, Any] = {}
        if tracking_info is not None:
            payload["tracking_info"] = tracking_info
        if estimated_delivery_days is not None:
            payload["estimated_delivery_days"] = estimated_delivery_days

        return await self._client._request(
            "POST",
            f"/api/v1/escrow/frost/{escrow_id}/ship",
            json=payload,
        )

    async def confirm_receipt(
        self,
        escrow_id: str,
        *,
        consent_confirmed: bool = True,
        feedback: str | None = None,
    ) -> dict[str, Any]:
        """Confirm receipt and trigger fund release (buyer only).

        Sets buyer_release_requested to trigger Arbiter Watchdog auto-signing.

        Args:
            escrow_id: The escrow identifier.
            consent_confirmed: Explicit consent to release funds (required True).
            feedback: Optional feedback about the transaction.

        Returns:
            Release trigger confirmation.
        """
        payload: dict[str, Any] = {"consent_confirmed": consent_confirmed}
        if feedback is not None:
            payload["feedback"] = feedback

        return await self._client._request(
            "POST",
            f"/api/v1/escrow/frost/{escrow_id}/confirm-receipt",
            json=payload,
        )

    # =========================================================================
    # Address management
    # =========================================================================

    async def set_payout_address(
        self, escrow_id: str, *, address: str
    ) -> dict[str, Any]:
        """Set vendor payout address (before shipping).

        Args:
            escrow_id: The escrow identifier.
            address: Monero address for vendor payout.

        Returns:
            Confirmation.
        """
        return await self._client._request(
            "POST",
            f"/api/v2/escrow/{escrow_id}/set-payout-address",
            json={"address": address},
        )

    async def set_refund_address(
        self, escrow_id: str, *, address: str
    ) -> dict[str, Any]:
        """Set buyer refund address (for dispute refunds).

        Args:
            escrow_id: The escrow identifier.
            address: Monero address for buyer refund.

        Returns:
            Confirmation.
        """
        return await self._client._request(
            "POST",
            f"/api/v2/escrow/{escrow_id}/set-refund-address",
            json={"address": address},
        )
