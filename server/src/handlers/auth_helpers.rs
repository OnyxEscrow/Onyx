//! Dual authentication identity system for B2B EaaS
//!
//! Supports both API key authentication (B2B clients) and session-based
//! authentication (web UI users). Handlers use `AuthIdentity` to operate
//! on whichever auth method was provided, without caring about the transport.

use actix_session::Session;
use actix_web::{HttpMessage, HttpRequest};

use crate::error::ApiError;
use crate::middleware::api_key_auth::ApiKeyContext;

/// Unified authentication identity across API key and session auth.
#[derive(Debug, Clone)]
pub enum AuthIdentity {
    /// Authenticated via API key (B2B path).
    ApiKey {
        key_id: String,
        user_id: String,
        tier: String,
        scopes: Vec<String>,
    },
    /// Authenticated via browser session cookie.
    Session {
        user_id: String,
    },
}

impl AuthIdentity {
    /// Return the user_id regardless of auth method.
    pub fn user_id(&self) -> &str {
        match self {
            AuthIdentity::ApiKey { user_id, .. } => user_id,
            AuthIdentity::Session { user_id } => user_id,
        }
    }

    /// Return true if this identity was established via API key.
    pub fn is_api_key(&self) -> bool {
        matches!(self, AuthIdentity::ApiKey { .. })
    }
}

/// Resolve the authenticated identity from the request.
///
/// Priority:
/// 1. `ApiKeyContext` in request extensions (set by `RequireApiKey` / `OptionalApiKey` middleware)
/// 2. `user_id` in session cookie
///
/// Returns `Err(ApiError::Unauthorized)` if neither is present.
pub fn get_authenticated_identity(
    req: &HttpRequest,
    session: &Session,
) -> Result<AuthIdentity, ApiError> {
    // 1. Check API key context first (higher priority for B2B routes).
    if let Some(ctx) = req.extensions().get::<ApiKeyContext>() {
        return Ok(AuthIdentity::ApiKey {
            key_id: ctx.key_id.clone(),
            user_id: ctx.user_id.clone(),
            tier: ctx.tier.clone(),
            scopes: ctx.scopes.clone(),
        });
    }

    // 2. Fall back to session.
    if let Ok(Some(user_id)) = session.get::<String>("user_id") {
        return Ok(AuthIdentity::Session { user_id });
    }

    Err(ApiError::Unauthorized(
        "Authentication required. Provide API key or log in.".to_string(),
    ))
}

/// Verify that the authenticated identity has access to a specific escrow.
///
/// For API key auth: checks that `auth.user_id` matches either
/// `buyer_id` or `vendor_id` on the escrow.
///
/// For session auth: same check against session user.
///
/// Returns `Err(ApiError::Forbidden)` if the user is not a participant.
pub fn verify_escrow_access(
    auth: &AuthIdentity,
    buyer_id: &str,
    vendor_id: &str,
) -> Result<(), ApiError> {
    let uid = auth.user_id();
    if uid == buyer_id || uid == vendor_id {
        return Ok(());
    }
    Err(ApiError::Forbidden(
        "You are not a participant in this escrow".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_identity_user_id() {
        let api = AuthIdentity::ApiKey {
            key_id: "k1".into(),
            user_id: "u1".into(),
            tier: "pro".into(),
            scopes: vec!["*".into()],
        };
        assert_eq!(api.user_id(), "u1");
        assert!(api.is_api_key());

        let sess = AuthIdentity::Session {
            user_id: "u2".into(),
        };
        assert_eq!(sess.user_id(), "u2");
        assert!(!sess.is_api_key());
    }

    #[test]
    fn test_verify_escrow_access_buyer() {
        let auth = AuthIdentity::Session {
            user_id: "buyer_1".into(),
        };
        assert!(verify_escrow_access(&auth, "buyer_1", "vendor_1").is_ok());
    }

    #[test]
    fn test_verify_escrow_access_vendor() {
        let auth = AuthIdentity::ApiKey {
            key_id: "k".into(),
            user_id: "vendor_1".into(),
            tier: "enterprise".into(),
            scopes: vec!["escrow:read".into()],
        };
        assert!(verify_escrow_access(&auth, "buyer_1", "vendor_1").is_ok());
    }

    #[test]
    fn test_verify_escrow_access_denied() {
        let auth = AuthIdentity::Session {
            user_id: "outsider".into(),
        };
        assert!(verify_escrow_access(&auth, "buyer_1", "vendor_1").is_err());
    }
}
