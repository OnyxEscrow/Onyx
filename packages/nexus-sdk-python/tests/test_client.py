"""Tests for NexusClient."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from nexus_escrow import (
    Escrow,
    EscrowStatus,
    NexusApiError,
    NexusAuthenticationError,
    NexusAuthorizationError,
    NexusClient,
    NexusConnectionError,
    NexusNotFoundError,
    NexusRateLimitError,
    NexusValidationError,
    WebhookEventType,
)
from nexus_escrow.webhooks import WebhookManager

# Test constants
TEST_API_KEY = "nxs_test_1234567890abcdef"
TEST_BASE_URL = "https://api.test.nexus.io"
TEST_BUYER_ADDRESS = "4" + "A" * 94
TEST_SELLER_ADDRESS = "4" + "B" * 94
TEST_ESCROW_ID = "esc_test123456"


@pytest.fixture
def mock_escrow_response() -> dict[str, Any]:
    """Return a mock escrow response."""
    return {
        "id": TEST_ESCROW_ID,
        "buyer_address": TEST_BUYER_ADDRESS,
        "seller_address": TEST_SELLER_ADDRESS,
        "amount": 1_000_000_000_000,
        "status": "created",
        "escrow_address": "4" + "E" * 94,
        "description": "Test escrow",
        "metadata": {"order_id": "12345"},
        "created_at": "2025-01-15T10:00:00Z",
        "funded_at": None,
        "released_at": None,
        "expires_at": "2025-01-18T10:00:00Z",
        "tx_hash": None,
    }


# =========================================================================
# Client initialization
# =========================================================================


class TestNexusClientInit:
    """Tests for client initialization."""

    def test_init_valid_api_key(self) -> None:
        """Client initializes with valid API key."""
        client = NexusClient(api_key=TEST_API_KEY)
        assert client._api_key == TEST_API_KEY

    def test_init_empty_api_key_raises(self) -> None:
        """Client raises ValueError for empty API key."""
        with pytest.raises(ValueError, match="api_key is required"):
            NexusClient(api_key="")

    def test_init_invalid_api_key_format(self) -> None:
        """Client raises ValueError for invalid API key format."""
        with pytest.raises(ValueError, match="Invalid API key format"):
            NexusClient(api_key="invalid_key_123")

    def test_init_custom_base_url(self) -> None:
        """Client accepts custom base URL."""
        client = NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL)
        assert client._base_url == TEST_BASE_URL

    def test_init_strips_trailing_slash(self) -> None:
        """Client strips trailing slash from base URL."""
        client = NexusClient(api_key=TEST_API_KEY, base_url=f"{TEST_BASE_URL}/")
        assert client._base_url == TEST_BASE_URL

    def test_init_has_all_managers(self) -> None:
        """Client initializes all manager instances."""
        client = NexusClient(api_key=TEST_API_KEY)
        assert hasattr(client, "escrows")
        assert hasattr(client, "dkg")
        assert hasattr(client, "signing")
        assert hasattr(client, "webhooks")
        assert hasattr(client, "fees")
        assert hasattr(client, "analytics")
        assert hasattr(client, "chat")
        assert hasattr(client, "api_keys")

    def test_init_sends_x_api_key_header(self) -> None:
        """Client sets X-API-Key header."""
        client = NexusClient(api_key=TEST_API_KEY)
        assert client._client.headers["X-API-Key"] == TEST_API_KEY


class TestNexusClientContextManager:
    """Tests for async context manager."""

    @pytest.mark.asyncio
    async def test_context_manager_closes_client(self) -> None:
        """Client closes HTTP connection when exiting context."""
        async with NexusClient(api_key=TEST_API_KEY) as client:
            assert client._client is not None
        assert client._client.is_closed


# =========================================================================
# Escrow operations
# =========================================================================


class TestEscrowOperations:
    """Tests for escrow operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_escrow_success(self) -> None:
        """Successfully create an escrow."""
        create_response = {
            "escrow_id": "esc_abc123",
            "status": "pending_counterparty",
            "creator_role": "buyer",
            "join_link": "/join/esc_abc123",
        }
        respx.post(f"{TEST_BASE_URL}/api/v1/escrows/create").mock(
            return_value=httpx.Response(200, json=create_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            from nexus_escrow.types import CreateEscrowResponse

            result = await client.escrows.create(
                amount=1_000_000_000_000,
                description="Test escrow",
            )

        assert isinstance(result, CreateEscrowResponse)
        assert result.escrow_id == "esc_abc123"
        assert result.status == "pending_counterparty"
        assert result.join_link == "/join/esc_abc123"

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_escrow_convenience_method(self) -> None:
        """Convenience method create_escrow works."""
        create_response = {
            "escrow_id": "esc_abc123",
            "status": "pending_counterparty",
            "creator_role": "buyer",
            "join_link": "/join/esc_abc123",
        }
        respx.post(f"{TEST_BASE_URL}/api/v1/escrows/create").mock(
            return_value=httpx.Response(200, json=create_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.create_escrow(amount=1_000_000_000_000)

        assert result.escrow_id == "esc_abc123"

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_escrow_success(
        self, mock_escrow_response: dict[str, Any]
    ) -> None:
        """Successfully get an escrow by ID."""
        respx.get(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}").mock(
            return_value=httpx.Response(200, json=mock_escrow_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            escrow = await client.escrows.get(TEST_ESCROW_ID)

        assert escrow.id == TEST_ESCROW_ID

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_escrow_not_found(self) -> None:
        """Get escrow raises NotFoundError for missing escrow."""
        respx.get(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}").mock(
            return_value=httpx.Response(
                404,
                json={"error": {"code": "ESCROW_NOT_FOUND", "message": "Not found"}},
            )
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            with pytest.raises(NexusNotFoundError):
                await client.escrows.get(TEST_ESCROW_ID)

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_escrows_success(
        self, mock_escrow_response: dict[str, Any]
    ) -> None:
        """Successfully list escrows."""
        respx.get(f"{TEST_BASE_URL}/api/v1/user/escrows").mock(
            return_value=httpx.Response(200, json=[mock_escrow_response])
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.escrows.list()

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].id == TEST_ESCROW_ID

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_escrows_with_status_filter(
        self, mock_escrow_response: dict[str, Any]
    ) -> None:
        """List escrows with status filter."""
        mock_escrow_response["status"] = "funded"
        route = respx.get(f"{TEST_BASE_URL}/api/v1/user/escrows").mock(
            return_value=httpx.Response(200, json=[mock_escrow_response])
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.escrows.list(status=EscrowStatus.FUNDED)

        assert route.called
        assert "status=funded" in str(route.calls[0].request.url)

    @pytest.mark.asyncio
    @respx.mock
    async def test_release_escrow_success(
        self, mock_escrow_response: dict[str, Any]
    ) -> None:
        """Successfully release an escrow."""
        mock_escrow_response["status"] = "released"
        mock_escrow_response["tx_hash"] = "abc123def456"
        mock_escrow_response["released_at"] = "2025-01-16T10:00:00Z"

        respx.post(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}/release").mock(
            return_value=httpx.Response(200, json=mock_escrow_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            escrow = await client.escrows.release(
                escrow_id=TEST_ESCROW_ID,
                buyer_signature="signature_data_here",
            )

        assert escrow.status == "released"
        assert escrow.tx_hash == "abc123def456"

    @pytest.mark.asyncio
    @respx.mock
    async def test_dispute_escrow_success(self) -> None:
        """Successfully open a dispute."""
        dispute_response = {
            "success": True,
            "message": "Dispute initiated successfully. Arbiter has been notified.",
        }

        respx.post(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}/dispute").mock(
            return_value=httpx.Response(200, json=dispute_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.escrows.dispute(
                escrow_id=TEST_ESCROW_ID,
                reason="Seller did not deliver the goods as promised.",
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_join_escrow_success(self) -> None:
        """Successfully join an escrow."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}/join").mock(
            return_value=httpx.Response(200, json={"status": "joined"})
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.escrows.join(TEST_ESCROW_ID)

        assert result["status"] == "joined"

    @pytest.mark.asyncio
    @respx.mock
    async def test_confirm_shipped_success(self) -> None:
        """Successfully confirm shipment."""
        respx.post(
            f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/ship"
        ).mock(
            return_value=httpx.Response(
                200, json={"status": "shipped", "auto_release_at": "2025-02-01T00:00:00Z"}
            )
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.escrows.confirm_shipped(
                TEST_ESCROW_ID,
                tracking_info="USPS 1234567890",
            )

        assert result["status"] == "shipped"

    @pytest.mark.asyncio
    @respx.mock
    async def test_confirm_receipt_success(self) -> None:
        """Successfully confirm receipt."""
        respx.post(
            f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/confirm-receipt"
        ).mock(
            return_value=httpx.Response(200, json={"status": "releasing"})
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.escrows.confirm_receipt(TEST_ESCROW_ID)

        assert result["status"] == "releasing"


# =========================================================================
# Error handling
# =========================================================================


class TestErrorHandling:
    """Tests for error handling."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_authentication_error(self) -> None:
        """401 response raises NexusAuthenticationError."""
        respx.get(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}").mock(
            return_value=httpx.Response(
                401,
                json={"error": {"code": "AUTH_FAILED", "message": "Invalid API key"}},
            )
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            with pytest.raises(NexusAuthenticationError) as exc_info:
                await client.escrows.get(TEST_ESCROW_ID)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    @respx.mock
    async def test_authorization_error(self) -> None:
        """403 response raises NexusAuthorizationError."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}/resolve").mock(
            return_value=httpx.Response(
                403,
                json={
                    "error": {"code": "FORBIDDEN", "message": "Insufficient permissions"}
                },
            )
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            with pytest.raises(NexusAuthorizationError):
                from nexus_escrow import DisputeResolution

                await client.escrows.resolve(
                    TEST_ESCROW_ID, resolution=DisputeResolution.BUYER_WINS
                )

    @pytest.mark.asyncio
    @respx.mock
    async def test_validation_error(self) -> None:
        """422 response raises NexusValidationError."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrows/create").mock(
            return_value=httpx.Response(
                422,
                json={
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Invalid buyer address",
                        "details": {"field": "buyer_address"},
                    }
                },
            )
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            with pytest.raises(NexusValidationError) as exc_info:
                await client.escrows.create(
                    amount=1_000_000_000_000,
                )

        assert "Invalid buyer address" in str(exc_info.value)

    @pytest.mark.asyncio
    @respx.mock
    async def test_rate_limit_error(self) -> None:
        """429 response raises NexusRateLimitError."""
        respx.get(f"{TEST_BASE_URL}/api/v1/user/escrows").mock(
            return_value=httpx.Response(
                429,
                headers={"Retry-After": "60"},
                json={"error": {"code": "RATE_LIMITED", "message": "Too many requests"}},
            )
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            with pytest.raises(NexusRateLimitError) as exc_info:
                await client.escrows.list()

        assert exc_info.value.retry_after == 60

    @pytest.mark.asyncio
    @respx.mock
    async def test_server_error_with_retry(self) -> None:
        """500 errors are retried before failing."""
        respx.get(f"{TEST_BASE_URL}/api/v1/escrows/{TEST_ESCROW_ID}").mock(
            return_value=httpx.Response(500, json={"error": {"message": "Server error"}})
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=3
        ) as client:
            with pytest.raises(NexusApiError) as exc_info:
                await client.escrows.get(TEST_ESCROW_ID)

        assert exc_info.value.status_code == 500


# =========================================================================
# Webhook operations
# =========================================================================


class TestWebhookOperations:
    """Tests for webhook operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_register_webhook_success(self) -> None:
        """Successfully register a webhook."""
        webhook_response = {
            "webhook": {
                "id": "whk_test123",
                "url": "https://example.com/webhook",
                "events": ["escrow.funded", "escrow.released"],
                "is_active": True,
                "consecutive_failures": 0,
                "last_failure_reason": None,
                "description": None,
                "created_at": "2025-01-15T10:00:00Z",
                "updated_at": "2025-01-15T10:00:00Z",
            },
            "secret": "whsec_abcdef123456",
        }
        respx.post(f"{TEST_BASE_URL}/api/v1/webhooks").mock(
            return_value=httpx.Response(200, json=webhook_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            webhook = await client.webhooks.register(
                url="https://example.com/webhook",
                events=[WebhookEventType.ESCROW_FUNDED, WebhookEventType.ESCROW_RELEASED],
            )

        assert webhook.id == "whk_test123"
        assert webhook.is_active is True
        assert webhook.secret == "whsec_abcdef123456"

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_webhooks_success(self) -> None:
        """Successfully list webhooks."""
        webhooks_response = {
            "webhooks": [
                {
                    "id": "whk_test123",
                    "url": "https://example.com/webhook",
                    "events": ["escrow.funded"],
                    "is_active": True,
                    "consecutive_failures": 0,
                    "last_failure_reason": None,
                    "description": None,
                    "created_at": "2025-01-15T10:00:00Z",
                    "updated_at": "2025-01-15T10:00:00Z",
                }
            ],
            "count": 1,
        }
        respx.get(f"{TEST_BASE_URL}/api/v1/webhooks").mock(
            return_value=httpx.Response(200, json=webhooks_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.webhooks.list()

        assert len(result.webhooks) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_delete_webhook_success(self) -> None:
        """Successfully delete a webhook."""
        respx.delete(f"{TEST_BASE_URL}/api/v1/webhooks/whk_test123").mock(
            return_value=httpx.Response(204)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            await client.webhooks.delete("whk_test123")

    @pytest.mark.asyncio
    @respx.mock
    async def test_activate_webhook_success(self) -> None:
        """Successfully activate a webhook."""
        respx.post(f"{TEST_BASE_URL}/api/v1/webhooks/whk_test123/activate").mock(
            return_value=httpx.Response(200, json={"status": "active"})
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.webhooks.activate("whk_test123")

        assert result["status"] == "active"

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_webhook_deliveries(self) -> None:
        """Successfully get webhook deliveries."""
        deliveries_response = {
            "deliveries": [
                {
                    "id": "dlv_001",
                    "webhook_id": "whk_test123",
                    "event_type": "escrow.funded",
                    "status_code": 200,
                    "success": True,
                    "attempt": 1,
                    "created_at": "2025-01-15T10:00:00Z",
                    "response_time_ms": 150,
                }
            ],
            "total": 1,
        }
        respx.get(f"{TEST_BASE_URL}/api/v1/webhooks/whk_test123/deliveries").mock(
            return_value=httpx.Response(200, json=deliveries_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.webhooks.get_deliveries("whk_test123")

        assert result["total"] == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_webhook_stats(self) -> None:
        """Successfully get webhook stats."""
        stats_response = {
            "total_deliveries": 100,
            "successful": 95,
            "failed": 5,
            "avg_response_time_ms": 200.5,
        }
        respx.get(f"{TEST_BASE_URL}/api/v1/webhooks/whk_test123/stats").mock(
            return_value=httpx.Response(200, json=stats_response)
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.webhooks.get_stats("whk_test123")

        assert result["total_deliveries"] == 100


# =========================================================================
# Webhook signature verification
# =========================================================================


class TestWebhookSignatureVerification:
    """Tests for webhook signature verification."""

    def test_verify_signature_valid(self) -> None:
        """Valid signature verification succeeds."""
        import hashlib
        import hmac
        import time

        payload = b'{"type": "escrow.funded", "escrow_id": "esc_123"}'
        secret = "test_secret_123"
        timestamp = str(int(time.time()))

        signed_payload = f"{timestamp}.".encode() + payload
        expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
        signature = f"sha256={expected}"

        result = WebhookManager.verify_signature(
            payload=payload,
            signature=signature,
            secret=secret,
            timestamp=timestamp,
            tolerance_seconds=300,
        )
        assert result is True

    def test_verify_signature_invalid(self) -> None:
        """Invalid signature raises error."""
        from nexus_escrow import NexusWebhookVerificationError

        payload = b'{"type": "escrow.funded"}'

        with pytest.raises(NexusWebhookVerificationError, match="Signature mismatch"):
            WebhookManager.verify_signature(
                payload=payload,
                signature="sha256=invalid_signature",
                secret="secret",
            )

    def test_verify_signature_old_timestamp(self) -> None:
        """Old timestamp raises error."""
        from nexus_escrow import NexusWebhookVerificationError

        payload = b'{"type": "escrow.funded"}'

        with pytest.raises(NexusWebhookVerificationError, match="Timestamp too old"):
            WebhookManager.verify_signature(
                payload=payload,
                signature="sha256=whatever",
                secret="secret",
                timestamp="1",
                tolerance_seconds=300,
            )


# =========================================================================
# DKG operations
# =========================================================================


class TestDkgOperations:
    """Tests for FROST DKG operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_dkg_init(self) -> None:
        """Successfully initialize DKG."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/init").mock(
            return_value=httpx.Response(200, json={"escrow_id": TEST_ESCROW_ID, "status": "initialized"})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.dkg.init(TEST_ESCROW_ID)

        assert result["status"] == "initialized"

    @pytest.mark.asyncio
    @respx.mock
    async def test_dkg_submit_round1(self) -> None:
        """Successfully submit DKG round 1 package."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/dkg/round1").mock(
            return_value=httpx.Response(200, json={"round1_complete": False})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.dkg.submit_round1(
                TEST_ESCROW_ID, role="buyer", package="aabbccdd"
            )

        assert result["round1_complete"] is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_dkg_get_round1_packages(self) -> None:
        """Successfully get DKG round 1 packages."""
        respx.get(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/dkg/round1").mock(
            return_value=httpx.Response(200, json={"buyer": "aabb", "vendor": "ccdd"})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.dkg.get_round1_packages(TEST_ESCROW_ID)

        assert "buyer" in result

    @pytest.mark.asyncio
    @respx.mock
    async def test_dkg_complete(self) -> None:
        """Successfully complete DKG."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/dkg/complete").mock(
            return_value=httpx.Response(200, json={"dkg_complete": True})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.dkg.complete(
                TEST_ESCROW_ID,
                group_pubkey="aa" * 32,
                multisig_address="4" + "A" * 94,
                multisig_view_key="bb" * 32,
            )

        assert result["dkg_complete"] is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_dkg_get_lagrange(self) -> None:
        """Successfully get Lagrange coefficients."""
        respx.get(f"{TEST_BASE_URL}/api/v1/escrow/frost/lagrange").mock(
            return_value=httpx.Response(
                200, json={"signer1_lambda": "aabb", "signer2_lambda": "ccdd"}
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.dkg.get_lagrange_coefficients(
                signer1="buyer", signer2="arbiter"
            )

        assert "signer1_lambda" in result


# =========================================================================
# Signing operations
# =========================================================================


class TestSigningOperations:
    """Tests for FROST signing operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_signing_init(self) -> None:
        """Successfully initialize signing session."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/sign/init").mock(
            return_value=httpx.Response(
                200, json={"tx_prefix_hash": "aabb", "clsag_message_hash": "ccdd"}
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.signing.init(TEST_ESCROW_ID)

        assert "tx_prefix_hash" in result

    @pytest.mark.asyncio
    @respx.mock
    async def test_signing_submit_nonces(self) -> None:
        """Successfully submit nonces."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/sign/nonces").mock(
            return_value=httpx.Response(200, json={"nonces_submitted": True})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.signing.submit_nonces(
                TEST_ESCROW_ID,
                role="buyer",
                r_public="aa" * 32,
                r_prime_public="bb" * 32,
                commitment_hash="cc" * 32,
            )

        assert result["nonces_submitted"] is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_signing_submit_partial(self) -> None:
        """Successfully submit partial signature."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/sign/partial").mock(
            return_value=httpx.Response(200, json={"partial_submitted": True})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.signing.submit_partial_signature(
                TEST_ESCROW_ID,
                role="buyer",
                partial_signature='{"s": "aabb"}',
                partial_key_image="dd" * 32,
            )

        assert result["partial_submitted"] is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_signing_complete(self) -> None:
        """Successfully complete signing and broadcast."""
        respx.post(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/sign/complete").mock(
            return_value=httpx.Response(200, json={"tx_hash": "deadbeef" * 8})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.signing.complete(TEST_ESCROW_ID)

        assert "tx_hash" in result

    @pytest.mark.asyncio
    @respx.mock
    async def test_signing_get_tx_data(self) -> None:
        """Successfully get TX signing data."""
        respx.get(f"{TEST_BASE_URL}/api/v1/escrow/frost/{TEST_ESCROW_ID}/sign/tx-data").mock(
            return_value=httpx.Response(
                200,
                json={
                    "tx_prefix_hash": "aa" * 32,
                    "clsag_message_hash": "bb" * 32,
                    "ring_data_json": "[]",
                    "recipient_address": "4" + "C" * 94,
                    "amount_atomic": "1000000000000",
                },
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.signing.get_tx_data(TEST_ESCROW_ID)

        assert "tx_prefix_hash" in result


# =========================================================================
# Fee operations
# =========================================================================


class TestFeeOperations:
    """Tests for fee operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_client_fee_config(self) -> None:
        """Successfully get client fee config."""
        response = {
            "fee_bps": 100,
            "fee_percent": 1.0,
            "source": "global_default",
        }
        respx.get(f"{TEST_BASE_URL}/api/v1/client/fees").mock(
            return_value=httpx.Response(200, json=response)
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            config = await client.fees.get_client_fees()

        assert config.fee_bps == 100
        assert config.source == "global_default"

    @pytest.mark.asyncio
    @respx.mock
    async def test_client_fee_estimate(self) -> None:
        """Successfully estimate client fee for amount."""
        response = {
            "amount_atomic": 1_000_000_000_000,
            "fee_bps": 100,
            "fee_atomic": 10_000_000_000,
            "net_amount_atomic": 990_000_000_000,
            "fee_percent": 1.0,
            "source": "global_default",
        }
        respx.get(f"{TEST_BASE_URL}/api/v1/client/fees/estimate").mock(
            return_value=httpx.Response(200, json=response)
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            estimate = await client.fees.estimate_client_fee(1_000_000_000_000)

        assert estimate.fee_atomic == 10_000_000_000
        assert estimate.net_amount_atomic == 990_000_000_000



# =========================================================================
# Analytics operations
# =========================================================================


class TestAnalyticsOperations:
    """Tests for analytics operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_usage_analytics(self) -> None:
        """Successfully get usage analytics."""
        response = {
            "period": "30d",
            "total_escrows": 150,
            "active_escrows": 25,
            "completed_escrows": 120,
            "disputed_escrows": 5,
            "total_volume_atomic": 500_000_000_000_000,
            "api_keys_count": 3,
            "total_api_requests": 10000,
        }
        respx.get(f"{TEST_BASE_URL}/api/v1/analytics/usage").mock(
            return_value=httpx.Response(200, json=response)
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            analytics = await client.analytics.usage(period="30d")

        assert analytics.total_escrows == 150
        assert analytics.period == "30d"


# =========================================================================
# Chat operations
# =========================================================================


class TestChatOperations:
    """Tests for E2EE chat operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_register_keypair(self) -> None:
        """Successfully register chat keypair."""
        respx.post(
            f"{TEST_BASE_URL}/api/v2/escrow/{TEST_ESCROW_ID}/chat/keypair"
        ).mock(
            return_value=httpx.Response(
                200, json={"id": "kp_001", "public_key": "aa" * 32}
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.chat.register_keypair(
                TEST_ESCROW_ID, public_key="aa" * 32
            )

        assert result["public_key"] == "aa" * 32

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_keypairs(self) -> None:
        """Successfully get chat keypairs."""
        respx.get(
            f"{TEST_BASE_URL}/api/v2/escrow/{TEST_ESCROW_ID}/chat/keypairs"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "buyer_pubkey": "aa" * 32,
                    "vendor_pubkey": "bb" * 32,
                    "arbiter_pubkey": None,
                    "all_registered": False,
                },
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.chat.get_keypairs(TEST_ESCROW_ID)

        assert result["all_registered"] is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_send_message(self) -> None:
        """Successfully send encrypted message."""
        respx.post(
            f"{TEST_BASE_URL}/api/v2/escrow/{TEST_ESCROW_ID}/chat/send"
        ).mock(
            return_value=httpx.Response(
                200, json={"id": "msg_001", "created_at": "2025-01-15T10:00:00Z"}
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.chat.send_message(
                TEST_ESCROW_ID,
                encrypted_content_buyer="enc_buyer",
                encrypted_content_vendor="enc_vendor",
                encrypted_content_arbiter="enc_arbiter",
                sender_ephemeral_pubkey="cc" * 32,
                nonce="dd" * 12,
            )

        assert result["id"] == "msg_001"

    @pytest.mark.asyncio
    @respx.mock
    async def test_get_messages(self) -> None:
        """Successfully get chat messages."""
        respx.get(
            f"{TEST_BASE_URL}/api/v2/escrow/{TEST_ESCROW_ID}/chat/messages"
        ).mock(
            return_value=httpx.Response(
                200, json={"messages": [], "total": 0, "has_more": False}
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.chat.get_messages(TEST_ESCROW_ID)

        assert result["total"] == 0


# =========================================================================
# API key operations
# =========================================================================


class TestApiKeyOperations:
    """Tests for API key operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_api_key(self) -> None:
        """Successfully create an API key."""
        respx.post(f"{TEST_BASE_URL}/api/api-keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "key_001",
                    "key_prefix": "nxs_abc",
                    "raw_key": "nxs_abcdef123456",
                    "name": "Test Key",
                    "tier": "free",
                },
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.api_keys.create("Test Key")

        assert result["raw_key"] == "nxs_abcdef123456"

    @pytest.mark.asyncio
    @respx.mock
    async def test_list_api_keys(self) -> None:
        """Successfully list API keys."""
        respx.get(f"{TEST_BASE_URL}/api/api-keys").mock(
            return_value=httpx.Response(
                200, json={"keys": [{"id": "key_001", "name": "Test"}], "total": 1}
            )
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.api_keys.list()

        assert result["total"] == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_revoke_api_key(self) -> None:
        """Successfully revoke an API key."""
        respx.delete(f"{TEST_BASE_URL}/api/api-keys/key_001").mock(
            return_value=httpx.Response(200, json={"status": "revoked"})
        )

        async with NexusClient(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.api_keys.revoke("key_001")

        assert result["status"] == "revoked"


# =========================================================================
# Account operations
# =========================================================================


class TestAccountOperations:
    """Tests for account operations."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_health_check_success(self) -> None:
        """Health check returns True when API is healthy."""
        respx.get(f"{TEST_BASE_URL}/api/health").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            result = await client.health_check()

        assert result is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_health_check_failure(self) -> None:
        """Health check raises error on connection failure."""
        respx.get(f"{TEST_BASE_URL}/api/health").mock(side_effect=httpx.ConnectError("Failed"))

        async with NexusClient(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL
        ) as client:
            with pytest.raises(NexusConnectionError):
                await client.health_check()
