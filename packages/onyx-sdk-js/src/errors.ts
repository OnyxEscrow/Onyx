/**
 * Onyx SDK Error Classes
 */

import type { OnyxErrorCode, ApiErrorResponse } from './types.js';

/**
 * Base error class for all Onyx API errors
 */
export class OnyxApiError extends Error {
  /** Error code from the API */
  public readonly code: OnyxErrorCode;
  /** HTTP status code */
  public readonly statusCode: number;
  /** Request ID for debugging */
  public readonly requestId: string | undefined;
  /** Additional error details */
  public readonly details: Record<string, unknown> | undefined;

  constructor(
    message: string,
    code: OnyxErrorCode,
    statusCode: number,
    requestId?: string,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'OnyxApiError';
    this.code = code;
    this.statusCode = statusCode;
    this.requestId = requestId;
    this.details = details;

    // Maintains proper stack trace for where error was thrown (V8 engines)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, OnyxApiError);
    }
  }

  /**
   * Create error from API response
   */
  static fromResponse(response: ApiErrorResponse, statusCode: number): OnyxApiError {
    return new OnyxApiError(
      response.error.message,
      response.error.code as OnyxErrorCode,
      statusCode,
      response.meta?.request_id,
      response.error.details
    );
  }

  /**
   * Check if error is of a specific type
   */
  isCode(code: OnyxErrorCode): boolean {
    return this.code === code;
  }

  /**
   * Check if error is retryable
   */
  isRetryable(): boolean {
    return (
      this.code === 'RATE_LIMIT_EXCEEDED' ||
      this.code === 'INTERNAL_ERROR' ||
      this.statusCode >= 500
    );
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      requestId: this.requestId,
      details: this.details,
    };
  }
}

/**
 * Error thrown when authentication fails
 */
export class AuthenticationError extends OnyxApiError {
  constructor(message: string, requestId?: string) {
    super(message, 'INVALID_API_KEY', 401, requestId);
    this.name = 'AuthenticationError';
  }
}

/**
 * Error thrown when authorization fails
 */
export class AuthorizationError extends OnyxApiError {
  constructor(message: string, requestId?: string) {
    super(message, 'FORBIDDEN', 403, requestId);
    this.name = 'AuthorizationError';
  }
}

/**
 * Error thrown when a resource is not found
 */
export class NotFoundError extends OnyxApiError {
  constructor(message: string, requestId?: string) {
    super(message, 'NOT_FOUND', 404, requestId);
    this.name = 'NotFoundError';
  }
}

/**
 * Error thrown when request validation fails
 */
export class ValidationError extends OnyxApiError {
  constructor(message: string, details?: Record<string, unknown>, requestId?: string) {
    super(message, 'VALIDATION_ERROR', 400, requestId, details);
    this.name = 'ValidationError';
  }
}

/**
 * Error thrown when rate limit is exceeded
 */
export class RateLimitError extends OnyxApiError {
  /** Seconds until rate limit resets */
  public readonly retryAfter: number;

  constructor(message: string, retryAfter: number, requestId?: string) {
    super(message, 'RATE_LIMIT_EXCEEDED', 429, requestId);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Error thrown when a Monero address is invalid
 */
export class InvalidAddressError extends OnyxApiError {
  /** The invalid address */
  public readonly address: string;

  constructor(message: string, address: string, requestId?: string) {
    super(message, 'INVALID_ADDRESS', 400, requestId, { address });
    this.name = 'InvalidAddressError';
    this.address = address;
  }
}

/**
 * Error thrown for escrow-specific errors
 */
export class EscrowError extends OnyxApiError {
  /** The escrow ID */
  public readonly escrowId: string;

  constructor(
    message: string,
    code: OnyxErrorCode,
    escrowId: string,
    requestId?: string
  ) {
    super(message, code, 400, requestId, { escrow_id: escrowId });
    this.name = 'EscrowError';
    this.escrowId = escrowId;
  }
}

/**
 * Error thrown when network request fails
 */
export class NetworkError extends Error {
  public readonly cause: Error | undefined;

  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'NetworkError';
    this.cause = cause;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NetworkError);
    }
  }
}

/**
 * Error thrown when request times out
 */
export class TimeoutError extends Error {
  public readonly timeout: number;

  constructor(timeout: number) {
    super(`Request timed out after ${timeout}ms`);
    this.name = 'TimeoutError';
    this.timeout = timeout;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TimeoutError);
    }
  }
}
