//! Admin authentication middleware
//!
//! Protects /admin/* endpoints by verifying the authenticated user has admin role.
//! Returns 401 Unauthorized if not logged in, 403 Forbidden if not admin.

use actix_session::SessionExt;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorForbidden,
    error::ErrorUnauthorized,
    Error,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::DbPool;
use crate::models::user::User;

/// Admin authentication middleware
///
/// Usage:
/// ```rust
/// .service(
///     web::scope("/admin")
///         .wrap(AdminAuth)
///         .service(monitoring::get_escrow_health)
/// )
/// ```
pub struct AdminAuth;

impl<S, B> Transform<S, ServiceRequest> for AdminAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AdminAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AdminAuthMiddleware { service }))
    }
}

pub struct AdminAuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AdminAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract session using SessionExt
        let session = req.get_session();

        let pool = req.app_data::<actix_web::web::Data<DbPool>>().cloned();

        // Get user_id from session
        let user_id = match session.get::<String>("user_id") {
            Ok(Some(id)) => id,
            Ok(None) => {
                warn!(
                    "Admin endpoint accessed without authentication: {}",
                    req.path()
                );
                return Box::pin(async move {
                    Err(ErrorUnauthorized(serde_json::json!({
                        "error": "Authentication required"
                    })))
                });
            }
            Err(e) => {
                warn!("Session error on admin endpoint: {}", e);
                return Box::pin(async move {
                    Err(ErrorUnauthorized(serde_json::json!({
                        "error": "Invalid session"
                    })))
                });
            }
        };

        // Parse UUID
        let user_uuid = match Uuid::parse_str(&user_id) {
            Ok(uuid) => uuid,
            Err(e) => {
                warn!("Invalid user_id UUID in session: {} - {}", user_id, e);
                return Box::pin(async move {
                    Err(ErrorUnauthorized(serde_json::json!({
                        "error": "Invalid session"
                    })))
                });
            }
        };

        // Check if pool is available
        let pool = match pool {
            Some(p) => p,
            None => {
                warn!("Database pool not available in admin middleware");
                return Box::pin(async move {
                    Err(actix_web::error::ErrorInternalServerError(
                        "Internal server error",
                    ))
                });
            }
        };

        // Verify user has admin role
        let fut = self.service.call(req);

        Box::pin(async move {
            // Query database for user role
            let mut conn = pool.get().map_err(|e| {
                warn!("Failed to get DB connection in admin middleware: {}", e);
                actix_web::error::ErrorInternalServerError("Database error")
            })?;

            let user = tokio::task::spawn_blocking(move || {
                User::find_by_id(&mut conn, user_uuid.to_string())
            })
            .await
            .map_err(|e| {
                warn!("Task join error in admin middleware: {}", e);
                actix_web::error::ErrorInternalServerError("Internal error")
            })?
            .map_err(|e| {
                warn!("User not found in admin middleware: {}", e);
                ErrorUnauthorized(serde_json::json!({
                    "error": "User not found"
                }))
            })?;

            // Check admin role
            if user.role != "admin" {
                warn!(
                    "Non-admin user {} attempted to access admin endpoint",
                    user_uuid
                );
                return Err(ErrorForbidden(serde_json::json!({
                    "error": "Admin privileges required",
                    "message": "You do not have permission to access this resource"
                })));
            }

            info!(
                "Admin access granted to user {} ({})",
                user.username, user_uuid
            );

            // User is admin - proceed with request
            fut.await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_auth_struct_creation() {
        let _auth = AdminAuth;
        // Just verify we can create the struct
        assert!(true);
    }
}
