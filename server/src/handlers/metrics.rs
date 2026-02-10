//! Prometheus Metrics Handler
//!
//! Exposes `/metrics` endpoint for Prometheus scraping.
//!
//! ## Usage
//! ```bash
//! curl http://localhost:8080/metrics
//! ```
//!
//! ## Grafana Integration
//! Add Prometheus data source pointing to this endpoint,
//! then import Onyx dashboard from `docs/grafana/onyx-dashboard.json`

use actix_web::{get, HttpResponse};

use crate::metrics::encode_metrics;

/// GET /metrics - Prometheus metrics endpoint
///
/// Returns all metrics in Prometheus text exposition format.
/// This endpoint should be scraped by Prometheus at regular intervals (e.g., 15s).
///
/// ## Response
/// Content-Type: text/plain; version=0.0.4; charset=utf-8
///
/// ## Example Response
/// ```text
/// # HELP nexus_http_requests_total Total number of HTTP requests
/// # TYPE nexus_http_requests_total counter
/// nexus_http_requests_total{method="GET",endpoint="/api/health",status="200"} 42
/// ```
#[get("/metrics")]
pub async fn prometheus_metrics() -> HttpResponse {
    match encode_metrics() {
        Ok(metrics) => HttpResponse::Ok()
            .content_type("text/plain; version=0.0.4; charset=utf-8")
            .body(metrics),
        Err(e) => {
            tracing::error!("Failed to encode Prometheus metrics: {}", e);
            HttpResponse::InternalServerError().body(format!("Failed to encode metrics: {}", e))
        }
    }
}

/// Lightweight health check that also updates metrics
/// Used by load balancers and Kubernetes probes
#[get("/metrics/health")]
pub async fn metrics_health() -> HttpResponse {
    // Just return OK - the /metrics endpoint handles the actual metrics
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "metrics_endpoint": "/metrics"
    }))
}
