#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments,
    deprecated
)]
// TM-006: Export macros pour sanitization des logs (AVANT modules)
#[macro_export]
macro_rules! log_uuid {
    ($uuid:expr) => {
        $crate::logging::sanitize::sanitize_uuid(&$uuid)
    };
}

#[macro_export]
macro_rules! log_address {
    ($addr:expr) => {
        $crate::logging::sanitize::sanitize_address($addr)
    };
}

#[macro_export]
macro_rules! log_amount {
    ($amount:expr) => {
        $crate::logging::sanitize::sanitize_amount($amount)
    };
}

pub mod config;
pub mod coordination;
pub mod crypto;
pub mod db;
pub mod error;
pub mod handlers;
pub mod ipfs;
pub mod logging;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod monitoring;
pub mod redis;
pub mod redis_pool;
pub mod repositories;
pub mod schema;
pub mod security;
pub mod services;
pub mod telemetry;
pub mod validation;
pub mod wallet_manager;
pub mod wallet_pool;
pub mod watchdog;
pub mod websocket;
