"""Fee estimation and management for Onyx SDK.

Provides access to Monero transaction fee estimates and client fee configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .types import (
    ClientFeeConfig,
    ClientFeeEstimate,
)

if TYPE_CHECKING:
    from .client import OnyxClient


class FeeManager:
    """Manages fee estimation and configuration.

    Accessed via ``client.fees``.

    Example::

        async with OnyxClient(api_key="nxs_...") as client:
            estimate = await client.fees.estimate(priority="normal")
            print(f"Fee for 2-output TX: {estimate.fee_xmr} XMR")
    """

    def __init__(self, client: OnyxClient) -> None:
        self._client = client

    async def get_client_fees(self) -> ClientFeeConfig:
        """Get current fee configuration for the authenticated client.

        Returns:
            Client fee configuration (basis points, source).
        """
        response = await self._client._request("GET", "/api/v1/client/fees")
        return ClientFeeConfig.model_validate(response)

    async def estimate_client_fee(
        self,
        amount_atomic: int,
        *,
        is_refund: bool = False,
    ) -> ClientFeeEstimate:
        """Estimate platform fee for a given amount.

        Args:
            amount_atomic: Transaction amount in piconero.
            is_refund: Whether this is a refund (may have different fee).

        Returns:
            Fee breakdown including net amount after deduction.
        """
        params: dict[str, Any] = {"amount_atomic": amount_atomic}
        if is_refund:
            params["is_refund"] = "true"
        response = await self._client._request(
            "GET", "/api/v1/client/fees/estimate", params=params
        )
        return ClientFeeEstimate.model_validate(response)
