use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub type RateLimitStorage = Arc<Mutex<HashMap<String, Vec<u64>>>>;

pub struct RateLimitMiddleware {
    limits: RateLimitStorage,
    max_requests: u32,
    window_secs: u64,
}

impl RateLimitMiddleware {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_secs,
        }
    }

    pub fn new_with_storage(limits: RateLimitStorage, max_requests: u32, window_secs: u64) -> Self {
        Self {
            limits,
            max_requests,
            window_secs,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddlewareService<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(RateLimitMiddlewareService {
            service,
            limits: self.limits.clone(),
            max_requests: self.max_requests,
            window_secs: self.window_secs,
        }))
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: S,
    limits: RateLimitStorage,
    max_requests: u32,
    window_secs: u64,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = req
            .connection_info()
            .peer_addr()
            .unwrap_or("unknown")
            .to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Use unwrap_or_else to handle poisoned mutex gracefully
        let mut limits = match self.limits.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(), // Recover from poisoned mutex
        };
        let requests = limits.entry(client_ip.clone()).or_insert_with(Vec::new);

        // Clean old requests outside window
        requests.retain(|&timestamp| now - timestamp < self.window_secs);

        if requests.len() >= self.max_requests as usize {
            return Box::pin(async move {
                let res = req.into_response(
                    HttpResponse::TooManyRequests()
                        .insert_header(("Retry-After", "60"))
                        .body("Rate limit exceeded. Try again in 60 seconds."),
                );
                Ok(res.map_into_right_body())
            });
        }

        requests.push(now);
        drop(limits);

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
