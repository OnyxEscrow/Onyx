//! Telemetry module for NEXUS
//!
//! Provides unified observability:
//! - OPS-001: Sentry error tracking (free tier: 5k events/month)
//! - OPS-002: Jaeger distributed tracing (via OpenTelemetry OTLP)
//!
//! Environment Variables:
//! - SENTRY_DSN: Sentry DSN (optional, disables Sentry if not set)
//! - ENVIRONMENT: deployment environment (development/staging/production)
//! - OTEL_EXPORTER_OTLP_ENDPOINT: Jaeger OTLP endpoint (default: http://localhost:4317)
//! - ENABLE_JAEGER: set to "true" to enable Jaeger tracing (default: false)

use anyhow::{Context, Result};
use opentelemetry_otlp::WithExportConfig;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Sentry guard that flushes events on drop
pub struct TelemetryGuard {
    _sentry_guard: Option<sentry::ClientInitGuard>,
}

impl TelemetryGuard {
    /// Create a no-op guard when telemetry is disabled
    pub fn noop() -> Self {
        Self {
            _sentry_guard: None,
        }
    }
}

/// Initialize Sentry error tracking
///
/// Returns a guard that must be kept alive for the duration of the program.
/// When dropped, it flushes all pending events to Sentry.
fn init_sentry() -> Option<sentry::ClientInitGuard> {
    let dsn = std::env::var("SENTRY_DSN").ok().filter(|s| !s.is_empty());

    if dsn.is_none() {
        tracing::info!("SENTRY_DSN not set, Sentry error tracking disabled");
        return None;
    }

    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(environment.into()),
            traces_sample_rate: 0.1, // 10% of transactions for performance monitoring
            attach_stacktrace: true,
            send_default_pii: false, // OPSEC: Never send PII
            ..Default::default()
        },
    ));

    tracing::info!("Sentry error tracking initialized");
    Some(guard)
}

/// Initialize OpenTelemetry tracing with Jaeger exporter
///
/// Sends traces to Jaeger via OTLP protocol (gRPC on port 4317).
fn init_jaeger_tracer() -> Result<opentelemetry_sdk::trace::Tracer> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&endpoint);

    // install_batch returns a Tracer directly in opentelemetry 0.21
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::Config::default().with_resource(
            opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", "nexus-server"),
                opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            ]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .context("Failed to install OpenTelemetry tracer")?;

    tracing::info!("Jaeger tracing initialized (OTLP endpoint: {})", endpoint);
    Ok(tracer)
}

/// Initialize all telemetry systems
///
/// This function sets up:
/// 1. Structured logging with tracing-subscriber
/// 2. Sentry error tracking (if SENTRY_DSN is set)
/// 3. Jaeger distributed tracing (if ENABLE_JAEGER=true)
///
/// Returns a guard that must be kept alive for the duration of the program.
pub fn init_telemetry() -> Result<TelemetryGuard> {
    // Initialize Sentry first (returns guard)
    let sentry_guard = init_sentry();

    // Build the subscriber layers
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,actix_web=info,actix_server=info,diesel=warn".into());

    let fmt_layer = tracing_subscriber::fmt::layer();

    // Check if Jaeger is enabled
    let enable_jaeger = std::env::var("ENABLE_JAEGER")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false);

    if enable_jaeger {
        // With Jaeger tracing
        let tracer = init_jaeger_tracer()?;
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        // Add Sentry layer if enabled
        if sentry_guard.is_some() {
            let sentry_layer = sentry_tracing::layer();
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .with(sentry_layer)
                .init();
        } else {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();
        }
    } else {
        // Without Jaeger tracing
        if sentry_guard.is_some() {
            let sentry_layer = sentry_tracing::layer();
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(sentry_layer)
                .init();
        } else {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
    }

    Ok(TelemetryGuard {
        _sentry_guard: sentry_guard,
    })
}

/// Shutdown telemetry systems gracefully
///
/// Flushes all pending traces and events before shutdown.
pub fn shutdown_telemetry() {
    // Flush OpenTelemetry traces
    opentelemetry::global::shutdown_tracer_provider();
    tracing::info!("Telemetry shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_guard_noop() {
        let guard = TelemetryGuard::noop();
        assert!(guard._sentry_guard.is_none());
    }
}
