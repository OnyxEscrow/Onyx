//! HTTP Metrics Middleware
//!
//! Automatically records Prometheus metrics for all HTTP requests:
//! - Request duration (histogram)
//! - Request count (counter)
//! - Request size (histogram)
//!
//! ## Labels
//! - `method`: HTTP method (GET, POST, etc.)
//! - `endpoint`: Normalized path (e.g., `/api/escrow/{id}` not `/api/escrow/abc123`)
//! - `status`: HTTP status code

use actix_web::dev::{forward_ready, Service, Transform};
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    Error,
};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::rc::Rc;
use std::time::Instant;

use crate::metrics::{HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION, HTTP_REQUEST_SIZE};

/// Metrics middleware factory
pub struct MetricsMiddleware;

impl MetricsMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MetricsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, B> Transform<S, ServiceRequest> for MetricsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = MetricsMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(MetricsMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct MetricsMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for MetricsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start = Instant::now();
        let method = req.method().to_string();
        let path = req.path().to_string();

        // Normalize path for metrics (replace IDs with placeholders)
        let endpoint = normalize_path(&path);

        // Get request size if available
        let request_size = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);

        let service = self.service.clone();

        Box::pin(async move {
            let res = service.call(req).await?;

            // Record metrics
            let duration = start.elapsed().as_secs_f64();
            let status = res.status().as_u16().to_string();

            HTTP_REQUEST_DURATION
                .with_label_values(&[&method, &endpoint, &status])
                .observe(duration);

            HTTP_REQUESTS_TOTAL
                .with_label_values(&[&method, &endpoint, &status])
                .inc();

            if request_size > 0.0 {
                HTTP_REQUEST_SIZE
                    .with_label_values(&[&method, &endpoint])
                    .observe(request_size);
            }

            Ok(res)
        })
    }
}

/// Normalize path by replacing dynamic segments with placeholders
///
/// Examples:
/// - `/api/escrow/abc123-def456` -> `/api/escrow/{id}`
/// - `/api/user/550e8400-e29b-41d4-a716-446655440000` -> `/api/user/{id}`
/// - `/api/v2/escrow/123/messages` -> `/api/v2/escrow/{id}/messages`
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = segments
        .iter()
        .map(|segment| {
            // Replace UUIDs
            if is_uuid(segment) {
                return "{id}".to_string();
            }
            // Replace numeric IDs
            if segment.chars().all(|c| c.is_ascii_digit()) && !segment.is_empty() {
                return "{id}".to_string();
            }
            // Replace hex strings that look like IDs (32+ chars)
            if segment.len() >= 32 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
                return "{id}".to_string();
            }
            // Replace ULID-like strings (26 chars alphanumeric)
            if segment.len() == 26 && segment.chars().all(|c| c.is_ascii_alphanumeric()) {
                return "{id}".to_string();
            }
            segment.to_string()
        })
        .collect();

    normalized.join("/")
}

/// Check if string looks like a UUID
fn is_uuid(s: &str) -> bool {
    // UUID format: 8-4-4-4-12 hex digits with dashes
    if s.len() == 36 {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 5 {
            return parts[0].len() == 8
                && parts[1].len() == 4
                && parts[2].len() == 4
                && parts[3].len() == 4
                && parts[4].len() == 12
                && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        }
    }
    // UUID without dashes (32 hex chars)
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_uuid() {
        assert_eq!(
            normalize_path("/api/escrow/550e8400-e29b-41d4-a716-446655440000"),
            "/api/escrow/{id}"
        );
        assert_eq!(
            normalize_path("/api/v2/escrow/550e8400-e29b-41d4-a716-446655440000/messages"),
            "/api/v2/escrow/{id}/messages"
        );
    }

    #[test]
    fn test_normalize_path_numeric() {
        assert_eq!(normalize_path("/api/user/12345"), "/api/user/{id}");
        assert_eq!(
            normalize_path("/api/order/999/items"),
            "/api/order/{id}/items"
        );
    }

    #[test]
    fn test_normalize_path_hex() {
        assert_eq!(
            normalize_path("/api/tx/abcdef1234567890abcdef1234567890"),
            "/api/tx/{id}"
        );
    }

    #[test]
    fn test_normalize_path_static() {
        assert_eq!(normalize_path("/api/health"), "/api/health");
        assert_eq!(normalize_path("/api/auth/login"), "/api/auth/login");
        assert_eq!(normalize_path("/metrics"), "/metrics");
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("550e8400e29b41d4a716446655440000"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("12345"));
    }
}
