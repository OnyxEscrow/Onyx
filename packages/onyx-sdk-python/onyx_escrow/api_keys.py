"""API key management for Onyx SDK.

Provides CRUD operations for B2B API keys.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import OnyxClient


class ApiKeyManager:
    """Manages API key lifecycle.

    Accessed via ``client.api_keys``.

    Example::

        async with OnyxClient(api_key="nxs_...") as client:
            keys = await client.api_keys.list()
            print(f"Active keys: {keys['total']}")
    """

    def __init__(self, client: OnyxClient) -> None:
        self._client = client

    async def create(
        self,
        name: str,
        *,
        expires_at: str | None = None,
        metadata: str | None = None,
        csrf_token: str = "",
    ) -> dict[str, Any]:
        """Create a new API key.

        The raw key is only returned once at creation time.

        Args:
            name: Human-readable name for the key.
            expires_at: Optional expiration (ISO 8601: YYYY-MM-DD HH:MM:SS).
            metadata: Optional JSON metadata string.
            csrf_token: CSRF token (required for session-authenticated requests).

        Returns:
            Creation response including the raw API key.
        """
        payload: dict[str, Any] = {"name": name, "csrf_token": csrf_token}
        if expires_at is not None:
            payload["expires_at"] = expires_at
        if metadata is not None:
            payload["metadata"] = metadata

        return await self._client._request(
            "POST", "/api/api-keys", json=payload
        )

    async def list(self) -> dict[str, Any]:
        """List all API keys for the authenticated user.

        Returns:
            Dict with ``keys`` list and ``total`` count.
        """
        return await self._client._request("GET", "/api/api-keys")

    async def get(self, key_id: str) -> dict[str, Any]:
        """Get details of a specific API key.

        Args:
            key_id: The API key identifier.

        Returns:
            API key info.
        """
        return await self._client._request("GET", f"/api/api-keys/{key_id}")

    async def revoke(self, key_id: str) -> dict[str, Any]:
        """Revoke (deactivate) an API key.

        The key will no longer be usable for authentication.

        Args:
            key_id: The API key identifier.

        Returns:
            Revocation confirmation.
        """
        return await self._client._request("DELETE", f"/api/api-keys/{key_id}")

    async def delete(self, key_id: str) -> dict[str, Any]:
        """Permanently delete an API key.

        Args:
            key_id: The API key identifier.

        Returns:
            Deletion confirmation.
        """
        return await self._client._request(
            "DELETE", f"/api/api-keys/{key_id}/permanent"
        )
