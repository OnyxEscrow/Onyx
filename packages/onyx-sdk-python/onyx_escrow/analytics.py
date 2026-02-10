"""Analytics operations for Onyx SDK.

Provides API usage analytics and statistics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import UsageAnalytics

if TYPE_CHECKING:
    from .client import OnyxClient


class AnalyticsManager:
    """Manages analytics and usage reporting.

    Accessed via ``client.analytics``.

    Example::

        async with OnyxClient(api_key="nxs_...") as client:
            stats = await client.analytics.usage(period="30d")
            print(f"Total escrows: {stats.total_escrows}")
    """

    def __init__(self, client: OnyxClient) -> None:
        self._client = client

    async def usage(self, *, period: str = "30d") -> UsageAnalytics:
        """Get API usage analytics.

        Args:
            period: Time period filter ("24h", "7d", "30d", "all").

        Returns:
            Usage analytics for the specified period.
        """
        response = await self._client._request(
            "GET",
            "/api/v1/analytics/usage",
            params={"period": period},
        )
        return UsageAnalytics.model_validate(response)
