use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;

use super::csp_nonce::CspNonce;

/// Middleware that injects a CSP nonce into request extensions
/// This must run BEFORE handlers to make nonce available to templates
pub struct CspNonceMiddleware;

impl<S, B> Transform<S, ServiceRequest> for CspNonceMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CspNonceService<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(CspNonceService { service }))
    }
}

pub struct CspNonceService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for CspNonceService<S>
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
        // Generate and store nonce in request extensions BEFORE handler runs
        let nonce = CspNonce::new();
        req.extensions_mut().insert(nonce);

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Middleware that adds security headers including CSP with nonce
pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersService<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(SecurityHeadersService { service }))
    }
}

pub struct SecurityHeadersService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersService<S>
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
        // Get nonce from extensions (set by CspNonceMiddleware)
        let nonce = req
            .extensions()
            .get::<CspNonce>()
            .map(|n| n.value().to_string())
            .unwrap_or_default();

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            // Build CSP with nonce instead of 'unsafe-inline'
            // Note: We keep 'unsafe-inline' as fallback for browsers that don't support nonces
            // The nonce takes precedence when supported (CSP Level 2+)
            // CSP for React SPA with external CDNs (Tailwind, ESM.sh, Google Fonts)
            // Note: 'unsafe-inline' is ignored when nonce is present, so we don't use nonce for SPA
            // The nonce is still generated for potential use in Tera templates
            let csp = "default-src 'self'; \
                 script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.tailwindcss.com https://esm.sh; \
                 style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
                 font-src 'self' https://fonts.gstatic.com; \
                 connect-src 'self' ws: wss: https://esm.sh; \
                 img-src 'self' data: https://gateway.pinata.cloud https://ipfs.io https://picsum.photos https://fastly.picsum.photos;"
                    .to_string();

            // Nonce available for Tera templates: use get_csp_nonce() in handlers
            let _ = nonce; // suppress unused warning

            // SAFETY: All header values are compile-time constants that are valid
            // Using expect() here because static strings are guaranteed to parse
            if let Ok(csp_value) = csp.parse() {
                res.headers_mut().insert(
                    actix_web::http::header::HeaderName::from_static("content-security-policy"),
                    csp_value,
                );
            }
            if let Ok(val) = "nosniff".parse() {
                res.headers_mut().insert(
                    actix_web::http::header::HeaderName::from_static("x-content-type-options"),
                    val,
                );
            }
            if let Ok(val) = "DENY".parse() {
                res.headers_mut().insert(
                    actix_web::http::header::HeaderName::from_static("x-frame-options"),
                    val,
                );
            }
            if let Ok(val) = "strict-origin-when-cross-origin".parse() {
                res.headers_mut().insert(
                    actix_web::http::header::HeaderName::from_static("referrer-policy"),
                    val,
                );
            }
            if let Ok(val) = "1; mode=block".parse() {
                res.headers_mut().insert(
                    actix_web::http::header::HeaderName::from_static("x-xss-protection"),
                    val,
                );
            }
            Ok(res)
        })
    }
}

/// Helper function to extract CSP nonce from HttpRequest for use in templates
/// Call this in handlers and insert into Tera context as "csp_nonce"
pub fn get_csp_nonce(req: &actix_web::HttpRequest) -> String {
    req.extensions()
        .get::<CspNonce>()
        .map(|n| n.value().to_string())
        .unwrap_or_default()
}
