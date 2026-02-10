"""Onyx Escrow API Client.

Main client for interacting with the Onyx Escrow-as-a-Service API.
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from .types import CreateEscrowResponse, Escrow

from .analytics import AnalyticsManager
from .api_keys import ApiKeyManager
from .chat import ChatManager
from .dkg import DkgManager
from .escrow import EscrowManager
from .exceptions import (
    OnyxApiError,
    OnyxAuthenticationError,
    OnyxAuthorizationError,
    OnyxConnectionError,
    OnyxNotFoundError,
    OnyxRateLimitError,
    OnyxServerError,
    OnyxTimeoutError,
    OnyxValidationError,
)
from .fees import FeeManager
from .signing import SigningManager
from .webhooks import WebhookManager

__all__ = ["OnyxClient"]

DEFAULT_BASE_URL = "https://onyx-escrow.com"
DEFAULT_TIMEOUT = 30.0
SDK_VERSION = "0.2.0"


class OnyxClient:
    """Async client for the Onyx Escrow-as-a-Service API.

    Provides access to all Onyx API endpoints including escrow management,
    FROST DKG/signing, webhooks, fees, analytics, chat, and API keys.

    The client should be used as an async context manager:

        async with OnyxClient(api_key="nxs_...") as client:
            escrow = await client.escrows.create(...)

    Alternatively, manage the lifecycle manually:

        client = OnyxClient(api_key="nxs_...")
        try:
            escrow = await client.escrows.create(...)
        finally:
            await client.close()

    Attributes:
        escrows: Manager for escrow operations.
        dkg: Manager for FROST DKG operations.
        signing: Manager for FROST signing operations.
        webhooks: Manager for webhook operations.
        fees: Manager for fee estimation and configuration.
        analytics: Manager for usage analytics.
        chat: Manager for escrow E2EE chat.
        api_keys: Manager for API key lifecycle.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = 3,
    ) -> None:
        """Initialize the Onyx client.

        Args:
            api_key: Your Onyx API key (starts with "nxs_").
            base_url: Base URL for the API (default: https://api.onyx-escrow.com).
            timeout: Request timeout in seconds (default: 30).
            max_retries: Maximum number of retries for transient errors.

        Raises:
            ValueError: If api_key is empty or invalid.
        """
        if not api_key:
            raise ValueError("api_key is required")
        if not api_key.startswith("nxs_"):
            raise ValueError("Invalid API key format (should start with 'nxs_')")

        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries

        # Initialize HTTP client with both Bearer and X-API-Key headers
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout),
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-API-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"onyx-python-sdk/{SDK_VERSION}",
            },
        )

        # Initialize managers
        self.escrows = EscrowManager(self)
        self.dkg = DkgManager(self)
        self.signing = SigningManager(self)
        self.webhooks = WebhookManager(self)
        self.fees = FeeManager(self)
        self.analytics = AnalyticsManager(self)
        self.chat = ChatManager(self)
        self.api_keys = ApiKeyManager(self)

    async def __aenter__(self) -> OnyxClient:
        """Enter async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit async context manager."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an API request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: API endpoint path.
            params: Query parameters.
            json: JSON request body.

        Returns:
            Parsed JSON response.

        Raises:
            OnyxApiError: On API error.
            OnyxConnectionError: On connection failure.
            OnyxTimeoutError: On request timeout.
        """
        last_error: Exception | None = None

        # B2B API requires Idempotency-Key for mutation requests
        headers = {}
        if method != "GET" and "/api/v1/" in path:
            import uuid
            headers["Idempotency-Key"] = str(uuid.uuid4())

        for attempt in range(self._max_retries):
            try:
                response = await self._client.request(
                    method,
                    path,
                    params=params,
                    json=json,
                    headers=headers,
                )
                return self._handle_response(response)

            except httpx.ConnectError as e:
                last_error = OnyxConnectionError(f"Connection failed: {e}")
                raise last_error from e

            except httpx.TimeoutException as e:
                last_error = OnyxTimeoutError(f"Request timed out: {e}")
                if attempt == self._max_retries - 1:
                    raise last_error from e
                continue

            except OnyxServerError as e:
                last_error = e
                if attempt == self._max_retries - 1:
                    raise
                continue

            except OnyxApiError:
                raise

        if last_error:
            raise last_error
        raise OnyxConnectionError("Request failed after retries")

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        """Handle API response and raise appropriate exceptions.

        Args:
            response: The HTTP response.

        Returns:
            Parsed JSON response body.

        Raises:
            OnyxApiError: On error response.
        """
        request_id = response.headers.get("X-Request-Id")

        if response.is_success:
            if response.status_code == 204:
                return {}
            return response.json()

        try:
            error_data = response.json()
            error_code = error_data.get("error", {}).get("code")
            message = error_data.get("error", {}).get("message", "Unknown error")
            details = error_data.get("error", {}).get("details")
        except Exception:
            error_code = None
            message = response.text or f"HTTP {response.status_code}"
            details = None

        status = response.status_code

        if status == 401:
            raise OnyxAuthenticationError(message=message, request_id=request_id)

        if status == 403:
            raise OnyxAuthorizationError(message=message, request_id=request_id)

        if status == 404:
            raise OnyxNotFoundError(
                resource="Resource",
                request_id=request_id,
            )

        if status == 422 or status == 400:
            raise OnyxValidationError(
                message=message,
                details=details,
                request_id=request_id,
            )

        if status == 429:
            retry_after = response.headers.get("Retry-After")
            raise OnyxRateLimitError(
                retry_after=int(retry_after) if retry_after else None,
                request_id=request_id,
            )

        if status >= 500:
            raise OnyxServerError(
                status_code=status,
                message=message,
                request_id=request_id,
            )

        raise OnyxApiError(
            message=message,
            status_code=status,
            error_code=error_code,
            request_id=request_id,
            details=details,
        )

    # =========================================================================
    # Convenience methods
    # =========================================================================

    async def create_escrow(
        self,
        amount: int,
        *,
        creator_role: str = "buyer",
        **kwargs: Any,
    ) -> CreateEscrowResponse:
        """Convenience method to create an escrow.

        Equivalent to ``client.escrows.create(...)``.

        Args:
            amount: Escrow amount in atomic units.
            creator_role: Role of the creator ('buyer' or 'seller').
            **kwargs: Additional arguments (description, external_reference).

        Returns:
            CreateEscrowResponse with escrow_id, status, and join_link.
        """

        return await self.escrows.create(
            amount=amount,
            creator_role=creator_role,
            **kwargs,
        )

    async def get_escrow(self, escrow_id: str) -> Escrow:
        """Convenience method to get an escrow by ID.

        Args:
            escrow_id: The escrow identifier.

        Returns:
            The Escrow object.
        """

        return await self.escrows.get(escrow_id)

    async def health_check(self) -> bool:
        """Check if the Onyx API is healthy.

        Returns:
            True if the API is operational.

        Raises:
            OnyxConnectionError: If cannot connect to API.
        """
        try:
            response = await self._client.get("/api/health")
            return response.is_success
        except httpx.HTTPError as e:
            raise OnyxConnectionError(f"Health check failed: {e}") from e
