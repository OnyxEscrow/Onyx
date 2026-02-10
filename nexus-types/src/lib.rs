//! NEXUS Shared Types
//!
//! This crate provides types shared between:
//! - NEXUS server (Rust)
//! - NEXUS WASM clients (browser)
//!
//! All types are `#[wasm_bindgen]` compatible when compiled with `--features wasm`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  nexus-types (this crate)                                       │
//! │  ├─ Shared between server & WASM                               │
//! │  ├─ Serde serialization for API transport                      │
//! │  └─ wasm_bindgen exports for JS interop                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod currency;
pub mod swap;

pub use currency::*;
pub use swap::*;
