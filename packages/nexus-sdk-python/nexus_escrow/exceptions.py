"""NEXUS SDK Exceptions.

Custom exceptions for the NEXUS Escrow API client.
"""

from __future__ import annotations

from typing import Any


class NexusError(Exception):
    """Base exception for all NEXUS SDK errors."""

    pass


class NexusApiError(NexusError):
    """Exception raised when the NEXUS API returns an error.

    Attributes:
        status_code: HTTP status code from the API response.
        error_code: NEXUS-specific error code (e.g., "ESCROW_NOT_FOUND").
        message: Human-readable error message.
        request_id: Request ID for debugging/support.
        details: Additional error details from the API.
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        error_code: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.request_id = request_id
        self.details = details or {}

    def __str__(self) -> str:
        parts = [f"[{self.status_code}]"]
        if self.error_code:
            parts.append(f"({self.error_code})")
        parts.append(self.message)
        if self.request_id:
            parts.append(f"(request_id: {self.request_id})")
        return " ".join(parts)

    def __repr__(self) -> str:
        return (
            f"NexusApiError(message={self.message!r}, status_code={self.status_code}, "
            f"error_code={self.error_code!r}, request_id={self.request_id!r})"
        )


class NexusAuthenticationError(NexusApiError):
    """Raised when API authentication fails (401)."""

    def __init__(
        self,
        message: str = "Invalid or missing API key",
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=401,
            error_code="AUTHENTICATION_FAILED",
            request_id=request_id,
        )


class NexusAuthorizationError(NexusApiError):
    """Raised when the API key lacks permission for an action (403)."""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=403,
            error_code="AUTHORIZATION_FAILED",
            request_id=request_id,
        )


class NexusNotFoundError(NexusApiError):
    """Raised when a requested resource is not found (404)."""

    def __init__(
        self,
        resource: str = "Resource",
        resource_id: str | None = None,
        request_id: str | None = None,
    ) -> None:
        message = f"{resource} not found"
        if resource_id:
            message = f"{resource} '{resource_id}' not found"
        super().__init__(
            message=message,
            status_code=404,
            error_code=f"{resource.upper()}_NOT_FOUND",
            request_id=request_id,
        )


class NexusValidationError(NexusApiError):
    """Raised when request validation fails (400/422)."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=422,
            error_code="VALIDATION_ERROR",
            request_id=request_id,
            details=details,
        )


class NexusRateLimitError(NexusApiError):
    """Raised when rate limit is exceeded (429)."""

    def __init__(
        self,
        retry_after: int | None = None,
        request_id: str | None = None,
    ) -> None:
        message = "Rate limit exceeded"
        if retry_after:
            message += f", retry after {retry_after} seconds"
        super().__init__(
            message=message,
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            request_id=request_id,
            details={"retry_after": retry_after} if retry_after else {},
        )
        self.retry_after = retry_after


class NexusServerError(NexusApiError):
    """Raised when the server returns a 5xx error."""

    def __init__(
        self,
        status_code: int = 500,
        message: str = "Internal server error",
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="SERVER_ERROR",
            request_id=request_id,
        )


class NexusConnectionError(NexusError):
    """Raised when connection to the NEXUS API fails."""

    def __init__(self, message: str = "Failed to connect to NEXUS API") -> None:
        super().__init__(message)
        self.message = message


class NexusTimeoutError(NexusError):
    """Raised when a request to the NEXUS API times out."""

    def __init__(self, message: str = "Request timed out") -> None:
        super().__init__(message)
        self.message = message


class NexusWebhookVerificationError(NexusError):
    """Raised when webhook signature verification fails."""

    def __init__(self, message: str = "Invalid webhook signature") -> None:
        super().__init__(message)
        self.message = message
