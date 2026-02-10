"""FROST DKG operations for Onyx SDK.

Manages Distributed Key Generation for 2-of-3 FROST threshold signing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import OnyxClient


class DkgManager:
    """Manages FROST DKG operations for escrows.

    Accessed via ``client.dkg``.

    Example::

        async with OnyxClient(api_key="nxs_...") as client:
            status = await client.dkg.init(escrow_id)
            await client.dkg.submit_round1(escrow_id, role="buyer", package=hex_pkg)
    """

    def __init__(self, client: OnyxClient) -> None:
        self._client = client

    async def init(self, escrow_id: str) -> dict[str, Any]:
        """Initialize FROST DKG for an escrow.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            DKG initialization status.
        """
        response = await self._client._request(
            "POST", f"/api/v1/escrow/frost/{escrow_id}/init"
        )
        return response

    async def submit_round1(
        self, escrow_id: str, *, role: str, package: str
    ) -> dict[str, Any]:
        """Submit Round 1 DKG package.

        Args:
            escrow_id: The escrow identifier.
            role: Participant role ("buyer", "vendor", "arbiter").
            package: Hex-encoded Round 1 package.

        Returns:
            Updated DKG status.
        """
        response = await self._client._request(
            "POST",
            f"/api/v1/escrow/frost/{escrow_id}/dkg/round1",
            json={"role": role, "package": package},
        )
        return response

    async def get_round1_packages(self, escrow_id: str) -> dict[str, Any]:
        """Get all Round 1 packages for an escrow.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Dict mapping roles to their Round 1 packages.
        """
        return await self._client._request(
            "GET", f"/api/v1/escrow/frost/{escrow_id}/dkg/round1"
        )

    async def submit_round2(
        self,
        escrow_id: str,
        *,
        role: str,
        packages: dict[str, str],
    ) -> dict[str, Any]:
        """Submit Round 2 DKG packages.

        Args:
            escrow_id: The escrow identifier.
            role: Sender's role.
            packages: Dict mapping recipient index to hex-encoded package.

        Returns:
            Updated DKG status.
        """
        response = await self._client._request(
            "POST",
            f"/api/v1/escrow/frost/{escrow_id}/dkg/round2",
            json={"role": role, "packages": packages},
        )
        return response

    async def get_round2_packages(
        self, escrow_id: str, *, role: str
    ) -> dict[str, Any]:
        """Get Round 2 packages addressed to a specific role.

        Args:
            escrow_id: The escrow identifier.
            role: Recipient role to fetch packages for.

        Returns:
            Dict of Round 2 packages for the specified role.
        """
        return await self._client._request(
            "GET",
            f"/api/v1/escrow/frost/{escrow_id}/dkg/round2",
            params={"role": role},
        )

    async def complete(
        self,
        escrow_id: str,
        *,
        group_pubkey: str,
        multisig_address: str,
        multisig_view_key: str,
    ) -> dict[str, Any]:
        """Complete DKG with group public key and derived address.

        Args:
            escrow_id: The escrow identifier.
            group_pubkey: Hex-encoded group public key (64 hex chars).
            multisig_address: Monero address (95 chars).
            multisig_view_key: Hex-encoded view key (64 hex chars).

        Returns:
            Final DKG status.
        """
        response = await self._client._request(
            "POST",
            f"/api/v1/escrow/frost/{escrow_id}/dkg/complete",
            json={
                "group_pubkey": group_pubkey,
                "multisig_address": multisig_address,
                "multisig_view_key": multisig_view_key,
            },
        )
        return response

    async def get_status(self, escrow_id: str) -> dict[str, Any]:
        """Get DKG status for an escrow.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Current DKG status.
        """
        return await self._client._request(
            "GET", f"/api/v1/escrow/frost/{escrow_id}/status"
        )

    async def get_lagrange_coefficients(
        self, *, signer1: str, signer2: str
    ) -> dict[str, Any]:
        """Get Lagrange coefficients for a signing pair.

        Args:
            signer1: First signer role.
            signer2: Second signer role.

        Returns:
            Lagrange coefficients for both signers.
        """
        return await self._client._request(
            "GET",
            "/api/v1/escrow/frost/lagrange",
            params={"signer1": signer1, "signer2": signer2},
        )
