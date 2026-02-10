// CSRF Token Management
// Simple CSRF protection using session-based tokens

use actix_session::Session;
use uuid::Uuid;

/// Generate or retrieve a CSRF token from the session
///
/// If a token already exists in the session, return it.
/// Otherwise, generate a new UUID token and store it in the session.
pub fn get_csrf_token(session: &Session) -> String {
    if let Ok(Some(token)) = session.get::<String>("csrf_token") {
        token
    } else {
        let new_token = Uuid::new_v4().to_string();
        let _ = session.insert("csrf_token", &new_token);
        new_token
    }
}

/// Validate a CSRF token against the session
///
/// Returns true if the provided token matches the one stored in the session.
/// Returns false if there is no token in the session or if the tokens don't match.
///
/// # Test Mode
/// For integration tests, a special bypass token can be used. This is ONLY enabled
/// in debug builds to ensure production builds never have this bypass.
pub fn validate_csrf_token(session: &Session, token: &str) -> bool {
    // Test bypass: allow integration tests to skip CSRF validation in debug builds
    #[cfg(debug_assertions)]
    {
        if token == "test-csrf-token-skip" {
            return true;
        }
    }

    session
        .get::<String>("csrf_token")
        .ok()
        .flatten()
        .map(|stored| stored == token)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_session::SessionExt;
    use actix_web::test;

    #[actix_web::test]
    async fn test_get_csrf_token_generates_new() {
        let req = test::TestRequest::default().to_http_request();
        let session = req.get_session();

        let token1 = get_csrf_token(&session);
        let token2 = get_csrf_token(&session);

        // Should return the same token on subsequent calls
        assert_eq!(token1, token2);
        assert!(!token1.is_empty());
    }

    #[actix_web::test]
    async fn test_validate_csrf_token() {
        let req = test::TestRequest::default().to_http_request();
        let session = req.get_session();

        let token = get_csrf_token(&session);

        // Valid token should pass
        assert!(validate_csrf_token(&session, &token));

        // Invalid token should fail
        assert!(!validate_csrf_token(&session, "invalid-token"));
    }
}
