//! Request ID middleware for B2B request tracing
//!
//! Assigns a unique UUID to each incoming request and propagates it via:
//! - Request extensions (for handler access)
//! - `X-Request-ID` response header (for client correlation)
//! - Tracing span field (for log correlation)
//!
//! If the client sends an `X-Request-ID` header, it is reused (validated as UUID).
//! Otherwise, a new UUID v4 is generated.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;
use uuid::Uuid;

/// Wrapper type stored in request extensions for handler access.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Middleware factory that attaches a unique request ID to every request.
pub struct RequestIdMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestIdMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestIdService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestIdService {
            service: Rc::new(service),
        }))
    }
}

pub struct RequestIdService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestIdService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            // Reuse client-supplied X-Request-ID if it is a valid UUID, otherwise generate.
            let request_id = req
                .headers()
                .get("X-Request-ID")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| Uuid::parse_str(v).ok())
                .map(|u| u.to_string())
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            // Store in extensions so handlers can access it.
            req.extensions_mut().insert(RequestId(request_id.clone()));

            let span = tracing::info_span!("request", request_id = %request_id);
            let _guard = span.enter();

            let mut res = svc.call(req).await?;

            // Attach header to response.
            res.headers_mut().insert(
                actix_web::http::header::HeaderName::from_static("x-request-id"),
                actix_web::http::header::HeaderValue::from_str(&request_id)
                    .unwrap_or_else(|_| actix_web::http::header::HeaderValue::from_static("unknown")),
            );

            Ok(res)
        })
    }
}
