"""Escrow E2EE chat operations for NEXUS SDK.

End-to-end encrypted group messaging within escrows using
X25519 ECDH + ChaCha20Poly1305.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import NexusClient


class ChatManager:
    """Manages escrow end-to-end encrypted chat.

    Accessed via ``client.chat``.

    Example::

        async with NexusClient(api_key="nxs_...") as client:
            await client.chat.register_keypair(escrow_id, public_key="aabb...")
            keypairs = await client.chat.get_keypairs(escrow_id)
    """

    def __init__(self, client: NexusClient) -> None:
        self._client = client

    async def register_keypair(
        self, escrow_id: str, *, public_key: str
    ) -> dict[str, Any]:
        """Register X25519 messaging keypair for an escrow.

        Args:
            escrow_id: The escrow identifier.
            public_key: X25519 public key (64 hex chars).

        Returns:
            Registered keypair details.
        """
        response = await self._client._request(
            "POST",
            f"/api/v2/escrow/{escrow_id}/chat/keypair",
            json={"public_key": public_key},
        )
        return response

    async def get_keypairs(self, escrow_id: str) -> dict[str, Any]:
        """Get all participants' chat public keys.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Keypair DTO with buyer/vendor/arbiter pubkeys and all_registered flag.
        """
        return await self._client._request(
            "GET", f"/api/v2/escrow/{escrow_id}/chat/keypairs"
        )

    async def send_message(
        self,
        escrow_id: str,
        *,
        encrypted_content_buyer: str,
        encrypted_content_vendor: str,
        encrypted_content_arbiter: str,
        sender_ephemeral_pubkey: str,
        nonce: str,
        frost_signature: str | None = None,
    ) -> dict[str, Any]:
        """Send an E2EE message to all escrow participants.

        Each message is encrypted 3 times (once per participant).

        Args:
            escrow_id: The escrow identifier.
            encrypted_content_buyer: Ciphertext for buyer (base64).
            encrypted_content_vendor: Ciphertext for vendor (base64).
            encrypted_content_arbiter: Ciphertext for arbiter (base64).
            sender_ephemeral_pubkey: Sender's ephemeral X25519 pubkey (hex).
            nonce: 12-byte nonce (hex).
            frost_signature: Optional FROST signature for non-repudiation.

        Returns:
            Message creation response with id and created_at.
        """
        payload: dict[str, Any] = {
            "encrypted_content_buyer": encrypted_content_buyer,
            "encrypted_content_vendor": encrypted_content_vendor,
            "encrypted_content_arbiter": encrypted_content_arbiter,
            "sender_ephemeral_pubkey": sender_ephemeral_pubkey,
            "nonce": nonce,
        }
        if frost_signature is not None:
            payload["frost_signature"] = frost_signature

        return await self._client._request(
            "POST",
            f"/api/v2/escrow/{escrow_id}/chat/send",
            json=payload,
        )

    async def get_messages(
        self,
        escrow_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Get chat message history for an escrow.

        Args:
            escrow_id: The escrow identifier.
            limit: Maximum messages to return (max 50).
            offset: Pagination offset.

        Returns:
            Messages list with total count and has_more flag.
        """
        return await self._client._request(
            "GET",
            f"/api/v2/escrow/{escrow_id}/chat/messages",
            params={"limit": limit, "offset": offset},
        )

    async def mark_read(self, escrow_id: str, message_id: str) -> dict[str, Any]:
        """Mark a chat message as read.

        Args:
            escrow_id: The escrow identifier.
            message_id: The message identifier.

        Returns:
            Acknowledgment response.
        """
        return await self._client._request(
            "POST", f"/api/v2/escrow/{escrow_id}/chat/{message_id}/read"
        )

    async def export_for_dispute(self, escrow_id: str) -> dict[str, Any]:
        """Export chat history as signed evidence for disputes.

        Only available for disputed escrows or by arbiters.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            Exported message data for dispute evidence.
        """
        return await self._client._request(
            "GET", f"/api/v2/escrow/{escrow_id}/chat/export"
        )
