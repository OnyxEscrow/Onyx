/// Prometheus Metrics Exporter
///
/// Exposes critical operational metrics for monitoring:
/// - Escrow counts by state
/// - RPC call success/failure rates
/// - Dispute resolution metrics
/// - Database connection pool health

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use actix_web::{get, HttpResponse, web};

/// Global metrics collector
#[derive(Clone)]
pub struct Metrics {
    // Escrow metrics
    escrows_created: Arc<AtomicU64>,
    escrows_funded: Arc<AtomicU64>,
    escrows_completed: Arc<AtomicU64>,
    escrows_disputed: Arc<AtomicU64>,
    escrows_resolved: Arc<AtomicU64>,

    // RPC metrics
    rpc_calls_total: Arc<AtomicU64>,
    rpc_calls_failed: Arc<AtomicU64>,

    // Dispute metrics
    disputes_buyer_won: Arc<AtomicU64>,
    disputes_vendor_won: Arc<AtomicU64>,

    // System metrics
    uptime_seconds: Arc<AtomicU64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            escrows_created: Arc::new(AtomicU64::new(0)),
            escrows_funded: Arc::new(AtomicU64::new(0)),
            escrows_completed: Arc::new(AtomicU64::new(0)),
            escrows_disputed: Arc::new(AtomicU64::new(0)),
            escrows_resolved: Arc::new(AtomicU64::new(0)),

            rpc_calls_total: Arc::new(AtomicU64::new(0)),
            rpc_calls_failed: Arc::new(AtomicU64::new(0)),

            disputes_buyer_won: Arc::new(AtomicU64::new(0)),
            disputes_vendor_won: Arc::new(AtomicU64::new(0)),

            uptime_seconds: Arc::new(AtomicU64::new(0)),
        }
    }

    // Escrow tracking
    pub fn record_escrow_created(&self) {
        self.escrows_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_escrow_funded(&self) {
        self.escrows_funded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_escrow_completed(&self) {
        self.escrows_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_escrow_disputed(&self) {
        self.escrows_disputed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_escrow_resolved(&self) {
        self.escrows_resolved.fetch_add(1, Ordering::Relaxed);
    }

    // RPC tracking
    pub fn record_rpc_call(&self, success: bool) {
        self.rpc_calls_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.rpc_calls_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Dispute outcome tracking
    pub fn record_dispute_resolved(&self, buyer_won: bool) {
        if buyer_won {
            self.disputes_buyer_won.fetch_add(1, Ordering::Relaxed);
        } else {
            self.disputes_vendor_won.fetch_add(1, Ordering::Relaxed);
        }
    }

    // System uptime
    pub fn increment_uptime(&self) {
        self.uptime_seconds.fetch_add(1, Ordering::Relaxed);
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> String {
        format!(
            r#"# HELP escrows_created_total Total escrows created
# TYPE escrows_created_total counter
escrows_created_total {}

# HELP escrows_funded_total Total escrows funded
# TYPE escrows_funded_total counter
escrows_funded_total {}

# HELP escrows_completed_total Total escrows completed successfully
# TYPE escrows_completed_total counter
escrows_completed_total {}

# HELP escrows_disputed_total Total escrows that entered dispute
# TYPE escrows_disputed_total counter
escrows_disputed_total {}

# HELP escrows_resolved_total Total disputed escrows resolved
# TYPE escrows_resolved_total counter
escrows_resolved_total {}

# HELP rpc_calls_total Total Monero RPC calls made
# TYPE rpc_calls_total counter
rpc_calls_total {}

# HELP rpc_calls_failed_total Total Monero RPC calls that failed
# TYPE rpc_calls_failed_total counter
rpc_calls_failed_total {}

# HELP disputes_buyer_won_total Total disputes resolved in buyer favor
# TYPE disputes_buyer_won_total counter
disputes_buyer_won_total {}

# HELP disputes_vendor_won_total Total disputes resolved in vendor favor
# TYPE disputes_vendor_won_total counter
disputes_vendor_won_total {}

# HELP uptime_seconds Server uptime in seconds
# TYPE uptime_seconds counter
uptime_seconds {}
"#,
            self.escrows_created.load(Ordering::Relaxed),
            self.escrows_funded.load(Ordering::Relaxed),
            self.escrows_completed.load(Ordering::Relaxed),
            self.escrows_disputed.load(Ordering::Relaxed),
            self.escrows_resolved.load(Ordering::Relaxed),
            self.rpc_calls_total.load(Ordering::Relaxed),
            self.rpc_calls_failed.load(Ordering::Relaxed),
            self.disputes_buyer_won.load(Ordering::Relaxed),
            self.disputes_vendor_won.load(Ordering::Relaxed),
            self.uptime_seconds.load(Ordering::Relaxed),
        )
    }
}

/// GET /metrics endpoint for Prometheus scraping
#[get("/metrics")]
pub async fn metrics_handler(metrics: web::Data<Metrics>) -> HttpResponse {
    let prometheus_text = metrics.export_prometheus();

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(prometheus_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        let metrics = Metrics::new();

        assert_eq!(metrics.escrows_created.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.rpc_calls_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_escrow_tracking() {
        let metrics = Metrics::new();

        metrics.record_escrow_created();
        metrics.record_escrow_created();
        metrics.record_escrow_funded();

        assert_eq!(metrics.escrows_created.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.escrows_funded.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_rpc_tracking() {
        let metrics = Metrics::new();

        metrics.record_rpc_call(true);
        metrics.record_rpc_call(true);
        metrics.record_rpc_call(false);

        assert_eq!(metrics.rpc_calls_total.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.rpc_calls_failed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_dispute_outcome_tracking() {
        let metrics = Metrics::new();

        metrics.record_dispute_resolved(true);  // Buyer won
        metrics.record_dispute_resolved(true);  // Buyer won
        metrics.record_dispute_resolved(false); // Vendor won

        assert_eq!(metrics.disputes_buyer_won.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.disputes_vendor_won.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_prometheus_export_format() {
        let metrics = Metrics::new();

        metrics.record_escrow_created();
        metrics.record_rpc_call(true);

        let export = metrics.export_prometheus();

        // Verify Prometheus format
        assert!(export.contains("# HELP escrows_created_total"));
        assert!(export.contains("# TYPE escrows_created_total counter"));
        assert!(export.contains("escrows_created_total 1"));
        assert!(export.contains("rpc_calls_total 1"));
    }

    #[test]
    fn test_concurrent_updates() {
        use std::thread;

        let metrics = Arc::new(Metrics::new());
        let mut handles = vec![];

        // Spawn 10 threads, each recording 100 escrows
        for _ in 0..10 {
            let m = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    m.record_escrow_created();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have exactly 1000 (10 threads * 100 each)
        assert_eq!(metrics.escrows_created.load(Ordering::Relaxed), 1000);
    }
}
