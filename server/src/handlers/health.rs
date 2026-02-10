//! Health check endpoints for monitoring
//!
//! Provides health check endpoints for load balancers, monitoring systems,
//! and operational dashboards.

use actix_web::{get, web, HttpResponse, Responder};
use serde::Serialize;
use std::time::Instant;

use crate::db::DbPool;
use crate::redis_pool::RedisPool;

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub checks: HealthChecks,
}

/// Individual health checks
#[derive(Serialize)]
pub struct HealthChecks {
    pub database: ComponentHealth,
    pub redis: ComponentHealth,
}

/// Health status of a component
#[derive(Serialize)]
pub struct ComponentHealth {
    pub status: &'static str,
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ComponentHealth {
    fn healthy(latency_ms: u64) -> Self {
        Self {
            status: "healthy",
            latency_ms: Some(latency_ms),
            error: None,
        }
    }

    fn unhealthy(error: String) -> Self {
        Self {
            status: "unhealthy",
            latency_ms: None,
            error: Some(error),
        }
    }

    fn unavailable() -> Self {
        Self {
            status: "unavailable",
            latency_ms: None,
            error: Some("Service not configured".to_string()),
        }
    }
}

/// Comprehensive health check endpoint
///
/// Returns health status of all system components including database and Redis.
///
/// # Endpoint
///
/// `GET /health`
///
/// # Response
///
/// ```json
/// {
///   "status": "healthy",
///   "service": "nexus",
///   "version": "0.7.0",
///   "checks": {
///     "database": { "status": "healthy", "latency_ms": 5 },
///     "redis": { "status": "healthy", "latency_ms": 2 }
///   }
/// }
/// ```
#[get("/health")]
pub async fn health_check(
    pool: web::Data<DbPool>,
    redis_pool: web::Data<RedisPool>,
) -> impl Responder {
    let db_health = check_database_health(&pool).await;
    let redis_health = check_redis_health(&redis_pool).await;

    let overall_status = if db_health.status == "healthy" && redis_health.status == "healthy" {
        "healthy"
    } else if db_health.status == "unhealthy" || redis_health.status == "unhealthy" {
        "degraded"
    } else {
        "unhealthy"
    };

    let response = HealthResponse {
        status: overall_status,
        service: "nexus",
        version: env!("CARGO_PKG_VERSION"),
        checks: HealthChecks {
            database: db_health,
            redis: redis_health,
        },
    };

    if overall_status == "healthy" {
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::ServiceUnavailable().json(response)
    }
}

/// Redis-specific health check endpoint
///
/// # Endpoint
///
/// `GET /health/redis`
///
/// # Response
///
/// ```json
/// {
///   "status": "healthy",
///   "latency_ms": 2,
///   "info": {
///     "connected_clients": 5,
///     "used_memory_human": "1.5M"
///   }
/// }
/// ```
#[get("/health/redis")]
pub async fn redis_health_check(redis_pool: web::Data<RedisPool>) -> impl Responder {
    let start = Instant::now();

    match redis_pool.get().await {
        Ok(mut conn) => {
            // PING command
            let ping_result: Result<String, _> = redis::cmd("PING").query_async(&mut *conn).await;

            match ping_result {
                Ok(pong) if pong == "PONG" => {
                    let latency = start.elapsed().as_millis() as u64;

                    // Get Redis INFO
                    let info: Result<String, _> = redis::cmd("INFO")
                        .arg("clients")
                        .query_async(&mut *conn)
                        .await;

                    let mut connected_clients: Option<u64> = None;
                    if let Ok(info_str) = info {
                        for line in info_str.lines() {
                            if line.starts_with("connected_clients:") {
                                connected_clients =
                                    line.split(':').nth(1).and_then(|s| s.trim().parse().ok());
                                break;
                            }
                        }
                    }

                    HttpResponse::Ok().json(serde_json::json!({
                        "status": "healthy",
                        "latency_ms": latency,
                        "info": {
                            "connected_clients": connected_clients,
                            "pool_status": "connected"
                        }
                    }))
                }
                Ok(unexpected) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
                    "status": "unhealthy",
                    "error": format!("Unexpected PING response: {}", unexpected)
                })),
                Err(e) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
                    "status": "unhealthy",
                    "error": format!("PING failed: {}", e)
                })),
            }
        }
        Err(e) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "status": "unhealthy",
            "error": format!("Connection failed: {}", e)
        })),
    }
}

/// Database health check endpoint
///
/// # Endpoint
///
/// `GET /health/db`
#[get("/health/db")]
pub async fn database_health_check(pool: web::Data<DbPool>) -> impl Responder {
    let health = check_database_health(&pool).await;

    if health.status == "healthy" {
        HttpResponse::Ok().json(health)
    } else {
        HttpResponse::ServiceUnavailable().json(health)
    }
}

/// Check database health
async fn check_database_health(pool: &DbPool) -> ComponentHealth {
    let start = Instant::now();

    match pool.get() {
        Ok(mut conn) => {
            // Execute a simple query using diesel
            let result = web::block(move || {
                use diesel::prelude::*;
                diesel::sql_query("SELECT 1 AS val").execute(&mut conn)
            })
            .await;

            match result {
                Ok(Ok(_)) => ComponentHealth::healthy(start.elapsed().as_millis() as u64),
                Ok(Err(e)) => ComponentHealth::unhealthy(format!("Query failed: {}", e)),
                Err(e) => ComponentHealth::unhealthy(format!("Block error: {}", e)),
            }
        }
        Err(e) => ComponentHealth::unhealthy(format!("Connection failed: {}", e)),
    }
}

/// Check Redis health
async fn check_redis_health(pool: &RedisPool) -> ComponentHealth {
    let start = Instant::now();

    match pool.get().await {
        Ok(mut conn) => {
            let result: Result<String, _> = redis::cmd("PING").query_async(&mut *conn).await;

            match result {
                Ok(pong) if pong == "PONG" => {
                    ComponentHealth::healthy(start.elapsed().as_millis() as u64)
                }
                Ok(unexpected) => {
                    ComponentHealth::unhealthy(format!("Unexpected response: {}", unexpected))
                }
                Err(e) => ComponentHealth::unhealthy(format!("PING failed: {}", e)),
            }
        }
        Err(e) => ComponentHealth::unhealthy(format!("Connection failed: {}", e)),
    }
}

/// Readiness probe for Kubernetes
///
/// Returns 200 if the service is ready to accept traffic.
/// Used by load balancers to determine if instance should receive traffic.
#[get("/ready")]
pub async fn readiness_probe(
    pool: web::Data<DbPool>,
    redis_pool: web::Data<RedisPool>,
) -> impl Responder {
    let db_ok = check_database_health(&pool).await.status == "healthy";
    let redis_ok = check_redis_health(&redis_pool).await.status == "healthy";

    if db_ok && redis_ok {
        HttpResponse::Ok().json(serde_json::json!({
            "ready": true
        }))
    } else {
        HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "ready": false,
            "database": db_ok,
            "redis": redis_ok
        }))
    }
}

/// Liveness probe for Kubernetes
///
/// Returns 200 if the process is alive.
/// Used by orchestrators to determine if instance should be restarted.
#[get("/live")]
pub async fn liveness_probe() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "alive": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
