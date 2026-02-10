//! Key operations module
//!
//! This module provides:
//! - Address validation with cryptographic checksum verification
//! - Key derivation and view key validation
//! - Key image generation for Monero ring signatures

pub mod derive;
pub mod image;
pub mod validate;

// Re-export validation functions
pub use validate::{
    decode_address, extract_payment_id, extract_public_keys, is_integrated_address, is_subaddress,
    quick_network_check, validate_address, validate_address_for_network,
};

// Re-export derivation functions
pub use derive::{
    constant_time_compare, constant_time_compare_slices, derive_public_key,
    derive_public_key_from_hex, extract_spend_pub_from_address, extract_view_pub_from_address,
    get_network_from_address, validate_view_key_matches_address,
};

// Re-export key image functions
pub use image::{
    aggregate_partial_key_images, compute_key_image, compute_partial_key_image,
    compute_partial_key_image_with_derivation, KeyImageResult, PartialKeyImageResult,
    PartialKeyImageWithDerivationResult,
};
