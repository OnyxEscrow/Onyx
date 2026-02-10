"""FROST signing operations for Onyx SDK.

Manages FROST 2-of-3 threshold CLSAG signing sessions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import OnyxClient


class SigningManager:
    """Manages FROST signing operations for escrows.

    Accessed via ``client.signing``.

    Example::

        async with OnyxClient(api_key="nxs_...") as client:
            tx_data = await client.signing.init(escrow_id)
            await client.signing.submit_nonces(
                escrow_id, role="buyer",
                r_public="...", r_prime_public="...", commitment_hash="...",
            )
    """

    def __init__(self, client: OnyxClient) -> None:
        self._client = client

    async def init(self, escrow_id: str) -> dict[str, Any]:
        """Initialize a FROST signing session.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Transaction signing data.
        """
        return await self._client._request(
            "POST", f"/api/v1/escrow/frost/{escrow_id}/sign/init"
        )

    async def submit_nonces(
        self,
        escrow_id: str,
        *,
        role: str,
        r_public: str,
        r_prime_public: str,
        commitment_hash: str,
    ) -> dict[str, Any]:
        """Submit nonce commitment for signing.

        Args:
            escrow_id: The escrow identifier.
            role: Signer role ("buyer", "vendor", "arbiter").
            r_public: Public nonce R (hex).
            r_prime_public: Public nonce R' (hex).
            commitment_hash: Commitment hash (hex).

        Returns:
            Nonce submission status.
        """
        return await self._client._request(
            "POST",
            f"/api/v1/escrow/frost/{escrow_id}/sign/nonces",
            json={
                "role": role,
                "r_public": r_public,
                "r_prime_public": r_prime_public,
                "commitment_hash": commitment_hash,
            },
        )

    async def get_nonces(self, escrow_id: str) -> dict[str, Any]:
        """Get nonce commitments for a signing session.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Nonce data for buyer, vendor, and aggregated.
        """
        return await self._client._request(
            "GET", f"/api/v1/escrow/frost/{escrow_id}/sign/nonces"
        )

    async def submit_partial_signature(
        self,
        escrow_id: str,
        *,
        role: str,
        partial_signature: str,
        partial_key_image: str,
    ) -> dict[str, Any]:
        """Submit partial CLSAG signature.

        Args:
            escrow_id: The escrow identifier.
            role: Signer role.
            partial_signature: JSON-encoded partial CLSAG signature.
            partial_key_image: Partial key image (hex).

        Returns:
            Signature submission status.
        """
        return await self._client._request(
            "POST",
            f"/api/v1/escrow/frost/{escrow_id}/sign/partial",
            json={
                "role": role,
                "partial_signature": partial_signature,
                "partial_key_image": partial_key_image,
            },
        )

    async def get_status(self, escrow_id: str) -> dict[str, Any]:
        """Get signing session status.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Current signing status.
        """
        return await self._client._request(
            "GET", f"/api/v1/escrow/frost/{escrow_id}/sign/status"
        )

    async def complete(self, escrow_id: str) -> dict[str, Any]:
        """Aggregate signatures and broadcast transaction.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Broadcast result with tx_hash.
        """
        return await self._client._request(
            "POST", f"/api/v1/escrow/frost/{escrow_id}/sign/complete"
        )

    async def get_tx_data(self, escrow_id: str) -> dict[str, Any]:
        """Get transaction data needed for client-side signing.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Transaction signing data (ring, hashes, etc.).
        """
        return await self._client._request(
            "GET", f"/api/v1/escrow/frost/{escrow_id}/sign/tx-data"
        )

    async def get_first_signer_data(self, escrow_id: str) -> dict[str, Any]:
        """Get first signer data for Round-Robin CLSAG.

        Returns buyer's c1, s_values, D, mu_p, mu_c, pseudo_out so
        vendor can sign as second signer reusing the same decoys.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            First signer data dict, or empty dict if not yet available.
        """
        return await self._client._request(
            "GET", f"/api/v1/escrow/frost/{escrow_id}/sign/first-signer-data"
        )
