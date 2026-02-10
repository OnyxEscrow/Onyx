//! Prometheus Metrics for NEXUS EaaS
//!
//! Provides production-grade observability with:
//! - HTTP request metrics (latency, status codes, throughput)
//! - Business metrics (escrows, webhooks, API usage)
//! - System metrics (connections, queue depths)
//!
//! ## Scrape Endpoint
//! GET /metrics - Prometheus-compatible metrics endpoint
//!
//! ## Metric Naming Convention
//! - `nexus_` prefix for all custom metrics
//! - `_total` suffix for counters
//! - `_seconds` suffix for histograms measuring duration
//! - `_bytes` suffix for size metrics

use once_cell::sync::Lazy;
use prometheus::{
    opts, register_counter_vec, register_gauge, register_gauge_vec,
    CounterVec, Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, TextEncoder,
};

// =============================================================================
// HTTP Request Metrics
// =============================================================================

/// HTTP request duration histogram (seconds)
/// Labels: method, endpoint, status
pub static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new("nexus_http_request_duration_seconds", "HTTP request duration in seconds")
            .namespace("nexus")
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["method", "endpoint", "status"]
    )
    .expect("Failed to create HTTP_REQUEST_DURATION metric")
});

/// HTTP requests total counter
/// Labels: method, endpoint, status
pub static HTTP_REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!("nexus_http_requests_total", "Total number of HTTP requests").namespace("nexus"),
        &["method", "endpoint", "status"]
    )
    .expect("Failed to create HTTP_REQUESTS_TOTAL metric")
});

/// HTTP request size histogram (bytes)
pub static HTTP_REQUEST_SIZE: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new("nexus_http_request_size_bytes", "HTTP request size in bytes")
            .namespace("nexus")
            .buckets(vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0]),
        &["method", "endpoint"]
    )
    .expect("Failed to create HTTP_REQUEST_SIZE metric")
});

// =============================================================================
// Escrow Business Metrics
// =============================================================================

/// Escrows created counter
/// Labels: type (b2b, b2c)
pub static ESCROWS_CREATED_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_escrows_created_total",
            "Total number of escrows created"
        )
        .namespace("nexus"),
        &["type"]
    )
    .expect("Failed to create ESCROWS_CREATED_TOTAL metric")
});

/// Escrow status transitions counter
/// Labels: from_status, to_status
pub static ESCROW_TRANSITIONS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_escrow_transitions_total",
            "Total number of escrow status transitions"
        )
        .namespace("nexus"),
        &["from_status", "to_status"]
    )
    .expect("Failed to create ESCROW_TRANSITIONS_TOTAL metric")
});

/// Active escrows gauge
/// Labels: status
pub static ESCROWS_ACTIVE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        opts!("nexus_escrows_active", "Number of active escrows by status").namespace("nexus"),
        &["status"]
    )
    .expect("Failed to create ESCROWS_ACTIVE metric")
});

/// Escrow amount histogram (in atomic units)
pub static ESCROW_AMOUNT: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new("nexus_escrow_amount_atomic", "Escrow amounts in atomic units (piconero)")
            .namespace("nexus")
            // Buckets: 0.001 XMR to 100 XMR in atomic units
            .buckets(vec![
                1_000_000_000.0,       // 0.001 XMR
                10_000_000_000.0,      // 0.01 XMR
                100_000_000_000.0,     // 0.1 XMR
                1_000_000_000_000.0,   // 1 XMR
                10_000_000_000_000.0,  // 10 XMR
                100_000_000_000_000.0  // 100 XMR
            ]),
        &["type"]
    )
    .expect("Failed to create ESCROW_AMOUNT metric")
});

// =============================================================================
// Webhook Metrics
// =============================================================================

/// Webhooks delivered counter
/// Labels: event_type, status (success, failed)
pub static WEBHOOKS_DELIVERED_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_webhooks_delivered_total",
            "Total number of webhook deliveries"
        )
        .namespace("nexus"),
        &["event_type", "status"]
    )
    .expect("Failed to create WEBHOOKS_DELIVERED_TOTAL metric")
});

/// Webhook delivery latency histogram
pub static WEBHOOK_DELIVERY_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new("nexus_webhook_delivery_duration_seconds", "Webhook delivery duration in seconds")
            .namespace("nexus")
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]),
        &["event_type"]
    )
    .expect("Failed to create WEBHOOK_DELIVERY_DURATION metric")
});

/// Webhook retry queue depth
pub static WEBHOOK_RETRY_QUEUE_DEPTH: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(opts!(
        "nexus_webhook_retry_queue_depth",
        "Number of webhooks pending retry"
    )
    .namespace("nexus"))
    .expect("Failed to create WEBHOOK_RETRY_QUEUE_DEPTH metric")
});

// =============================================================================
// API Key Metrics
// =============================================================================

/// API requests by key tier
/// Labels: tier (free, pro, enterprise), endpoint
pub static API_REQUESTS_BY_TIER: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_api_requests_by_tier_total",
            "API requests by key tier"
        )
        .namespace("nexus"),
        &["tier", "endpoint"]
    )
    .expect("Failed to create API_REQUESTS_BY_TIER metric")
});

/// Active API keys gauge
/// Labels: tier
pub static API_KEYS_ACTIVE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        opts!("nexus_api_keys_active", "Number of active API keys by tier").namespace("nexus"),
        &["tier"]
    )
    .expect("Failed to create API_KEYS_ACTIVE metric")
});

// =============================================================================
// Authentication Metrics
// =============================================================================

/// Login attempts counter
/// Labels: status (success, failed), method (session, api_key)
pub static LOGIN_ATTEMPTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_login_attempts_total",
            "Total number of login attempts"
        )
        .namespace("nexus"),
        &["status", "method"]
    )
    .expect("Failed to create LOGIN_ATTEMPTS_TOTAL metric")
});

/// Active sessions gauge
pub static ACTIVE_SESSIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(opts!("nexus_active_sessions", "Number of active sessions").namespace("nexus"))
        .expect("Failed to create ACTIVE_SESSIONS metric")
});

// =============================================================================
// WebSocket Metrics
// =============================================================================

/// Active WebSocket connections
pub static WEBSOCKET_CONNECTIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(opts!(
        "nexus_websocket_connections",
        "Number of active WebSocket connections"
    )
    .namespace("nexus"))
    .expect("Failed to create WEBSOCKET_CONNECTIONS metric")
});

/// WebSocket messages sent counter
/// Labels: event_type
pub static WEBSOCKET_MESSAGES_SENT: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_websocket_messages_sent_total",
            "Total WebSocket messages sent"
        )
        .namespace("nexus"),
        &["event_type"]
    )
    .expect("Failed to create WEBSOCKET_MESSAGES_SENT metric")
});

// =============================================================================
// Database Metrics
// =============================================================================

/// Database query duration histogram
/// Labels: operation (select, insert, update, delete)
pub static DB_QUERY_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new("nexus_db_query_duration_seconds", "Database query duration in seconds")
            .namespace("nexus")
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        &["operation"]
    )
    .expect("Failed to create DB_QUERY_DURATION metric")
});

/// Database connection pool size
pub static DB_POOL_CONNECTIONS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        opts!(
            "nexus_db_pool_connections",
            "Database connection pool state"
        )
        .namespace("nexus"),
        &["state"] // active, idle
    )
    .expect("Failed to create DB_POOL_CONNECTIONS metric")
});

// =============================================================================
// Monero/Wallet Metrics
// =============================================================================

/// Wallet RPC request duration
/// Labels: method
pub static WALLET_RPC_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    HistogramVec::new(
        HistogramOpts::new("nexus_wallet_rpc_duration_seconds", "Wallet RPC request duration")
            .namespace("nexus")
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
        &["method"]
    )
    .expect("Failed to create WALLET_RPC_DURATION metric")
});

/// Wallet RPC errors counter
/// Labels: method, error_type
pub static WALLET_RPC_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!("nexus_wallet_rpc_errors_total", "Wallet RPC errors").namespace("nexus"),
        &["method", "error_type"]
    )
    .expect("Failed to create WALLET_RPC_ERRORS metric")
});

// =============================================================================
// FROST/Multisig Metrics
// =============================================================================

/// FROST DKG sessions counter
/// Labels: status (started, completed, failed)
pub static FROST_DKG_SESSIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_frost_dkg_sessions_total",
            "FROST DKG sessions by status"
        )
        .namespace("nexus"),
        &["status"]
    )
    .expect("Failed to create FROST_DKG_SESSIONS metric")
});

/// FROST signing operations counter
/// Labels: status (success, failed)
pub static FROST_SIGNING_OPS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        opts!(
            "nexus_frost_signing_operations_total",
            "FROST signing operations"
        )
        .namespace("nexus"),
        &["status"]
    )
    .expect("Failed to create FROST_SIGNING_OPS metric")
});

// =============================================================================
// Helper Functions
// =============================================================================

/// Encode all metrics to Prometheus text format
pub fn encode_metrics() -> Result<String, prometheus::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    String::from_utf8(buffer).map_err(|e| prometheus::Error::Msg(e.to_string()))
}

/// Initialize all metrics (force lazy initialization)
pub fn init_metrics() {
    // Touch each metric to ensure it's initialized
    let _ = &*HTTP_REQUEST_DURATION;
    let _ = &*HTTP_REQUESTS_TOTAL;
    let _ = &*HTTP_REQUEST_SIZE;
    let _ = &*ESCROWS_CREATED_TOTAL;
    let _ = &*ESCROW_TRANSITIONS_TOTAL;
    let _ = &*ESCROWS_ACTIVE;
    let _ = &*ESCROW_AMOUNT;
    let _ = &*WEBHOOKS_DELIVERED_TOTAL;
    let _ = &*WEBHOOK_DELIVERY_DURATION;
    let _ = &*WEBHOOK_RETRY_QUEUE_DEPTH;
    let _ = &*API_REQUESTS_BY_TIER;
    let _ = &*API_KEYS_ACTIVE;
    let _ = &*LOGIN_ATTEMPTS_TOTAL;
    let _ = &*ACTIVE_SESSIONS;
    let _ = &*WEBSOCKET_CONNECTIONS;
    let _ = &*WEBSOCKET_MESSAGES_SENT;
    let _ = &*DB_QUERY_DURATION;
    let _ = &*DB_POOL_CONNECTIONS;
    let _ = &*WALLET_RPC_DURATION;
    let _ = &*WALLET_RPC_ERRORS;
    let _ = &*FROST_DKG_SESSIONS;
    let _ = &*FROST_SIGNING_OPS;

    tracing::info!("Prometheus metrics initialized");
}

/// Record HTTP request metrics
pub fn record_http_request(method: &str, endpoint: &str, status: u16, duration_secs: f64) {
    let status_str = status.to_string();
    HTTP_REQUEST_DURATION
        .with_label_values(&[method, endpoint, &status_str])
        .observe(duration_secs);
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, endpoint, &status_str])
        .inc();
}

/// Record escrow creation
pub fn record_escrow_created(escrow_type: &str, amount_atomic: i64) {
    ESCROWS_CREATED_TOTAL
        .with_label_values(&[escrow_type])
        .inc();
    ESCROW_AMOUNT
        .with_label_values(&[escrow_type])
        .observe(amount_atomic as f64);
}

/// Record escrow status transition
pub fn record_escrow_transition(from_status: &str, to_status: &str) {
    ESCROW_TRANSITIONS_TOTAL
        .with_label_values(&[from_status, to_status])
        .inc();
}

/// Record webhook delivery
pub fn record_webhook_delivery(event_type: &str, success: bool, duration_secs: f64) {
    let status = if success { "success" } else { "failed" };
    WEBHOOKS_DELIVERED_TOTAL
        .with_label_values(&[event_type, status])
        .inc();
    WEBHOOK_DELIVERY_DURATION
        .with_label_values(&[event_type])
        .observe(duration_secs);
}

/// Record login attempt
pub fn record_login_attempt(success: bool, method: &str) {
    let status = if success { "success" } else { "failed" };
    LOGIN_ATTEMPTS_TOTAL
        .with_label_values(&[status, method])
        .inc();
}

/// Record API request by tier
pub fn record_api_request(tier: &str, endpoint: &str) {
    API_REQUESTS_BY_TIER
        .with_label_values(&[tier, endpoint])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        init_metrics();
        // Should not panic
    }

    #[test]
    fn test_encode_metrics() {
        init_metrics();
        let encoded = encode_metrics().expect("Failed to encode metrics");
        assert!(encoded.contains("nexus_"));
    }

    #[test]
    fn test_record_http_request() {
        record_http_request("GET", "/api/health", 200, 0.001);
        // Should not panic
    }
}
