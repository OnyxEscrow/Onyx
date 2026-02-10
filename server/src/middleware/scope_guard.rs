//! Scope guard middleware for API key permissions
//!
//! Checks that the authenticated API key has the required scope before
//! allowing the request through. If the key lacks the scope, returns 403 Forbidden.
//!
//! The wildcard scope `"*"` grants access to all endpoints.
//!
//! ## Usage
//! ```rust,ignore
//! use server::middleware::scope_guard::RequireScope;
//!
//! web::resource("/escrow")
//!     .wrap(RequireScope::new("escrow:write"))
//!     .route(web::post().to(create_escrow))
//! ```

use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;

use crate::middleware::api_key_auth::ApiKeyContext;

/// Middleware factory that requires a specific scope on the API key.
pub struct RequireScope {
    scope: String,
}

impl RequireScope {
    pub fn new(scope: &str) -> Self {
        Self {
            scope: scope.to_string(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireScope
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = RequireScopeService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireScopeService {
            service: Rc::new(service),
            scope: self.scope.clone(),
        }))
    }
}

pub struct RequireScopeService<S> {
    service: Rc<S>,
    scope: String,
}

impl<S, B> Service<ServiceRequest> for RequireScopeService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let required_scope = self.scope.clone();

        Box::pin(async move {
            // Extract ApiKeyContext from extensions (set by RequireApiKey middleware).
            let has_scope = {
                let extensions = req.extensions();
                match extensions.get::<ApiKeyContext>() {
                    Some(ctx) => {
                        ctx.scopes.iter().any(|s| s == "*" || s == &required_scope)
                    }
                    None => {
                        // No API key context means no authentication was applied upstream.
                        // This is a configuration error; deny by default.
                        false
                    }
                }
            };

            if !has_scope {
                tracing::warn!(
                    scope = %required_scope,
                    "API key missing required scope"
                );
                return Ok(req
                    .into_response(
                        HttpResponse::Forbidden().json(serde_json::json!({
                            "error": "Insufficient permissions",
                            "message": format!("API key requires scope '{}'", required_scope)
                        })),
                    )
                    .map_into_right_body());
            }

            let res = svc.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
