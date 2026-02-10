//! Middleware for the Monero Marketplace API
//!
//! Provides production-grade middleware:
//! - Rate limiting (DDoS protection, brute-force prevention)
//! - Authentication (RequireAuth for protected endpoints)
//! - Admin authentication (AdminAuth for /admin/* endpoints)
//! - API Key authentication (RequireApiKey for B2B endpoints)
//! - Request ID tracing (X-Request-ID per request)
//! - Scope guard (fine-grained API key permission checks)
//! - Security headers (CSP, X-Frame-Options, etc.)
//! - CSRF protection (token-based validation)
//! - WebSocket connection limiting (DoS protection)

pub mod admin_auth;
pub mod api_key_auth;
pub mod auth;
pub mod csp_nonce;
pub mod csrf;
pub mod idempotency;
pub mod rate_limit;
pub mod registration_rate_limit;
pub mod request_id;
pub mod scope_guard;
pub mod security_headers;
pub mod traits;
pub mod ws_limiter;

pub use api_key_auth::{
    new_api_key_rate_limit_storage, ApiKeyContext, ApiKeyRateLimitStorage, OptionalApiKey,
    RequireApiKey,
};
pub use csp_nonce::CspNonce;
pub use registration_rate_limit::{
    check_registration_rate_limit, new_registration_rate_limit_storage,
    record_registration_attempt, RegistrationRateLimitStorage,
};
pub use request_id::{RequestId, RequestIdMiddleware};
pub use scope_guard::RequireScope;
pub use security_headers::{get_csp_nonce, CspNonceMiddleware, SecurityHeadersMiddleware};
pub use traits::ConnectionLimiter;
pub use ws_limiter::ConnectionManager;
