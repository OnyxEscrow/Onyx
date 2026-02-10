//! Commitment Mask Derivation (CMD) Protocol
//!
//! This module enables server-side derivation of the commitment mask (blinding factor)
//! needed for CLSAG ring signatures. The derivation uses only the view key and
//! transaction public key - no user interaction required.
//!
//! # Cryptographic Background
//!
//! In Monero RingCT, outputs use Pedersen commitments: C = mask*G + amount*H
//!
//! The mask is derived using ECDH:
//! - Sender computes: shared_secret = tx_key * recipient_view_pub
//! - Recipient computes: shared_secret = recipient_view_priv * tx_pub_key
//!
//! These are equal due to elliptic curve properties: r*A = r*(a*G) = a*(r*G) = a*R
//!
//! The mask is derived as:
//! 1. derivation = 8 * view_priv * tx_pub_key (point)
//! 2. shared_secret = Hs(derivation || varint(output_index)) (scalar)
//! 3. mask = Hs("commitment_mask" || shared_secret)
//!
//! # Core IP - Onyx EaaS
//!
//! This protocol is the foundation of browser-based Monero escrow, enabling
//! "zero-friction" funding where the server can derive masks without user interaction.

pub mod amounts;
pub mod derivation;
pub mod masks;
pub mod utils;

// Re-export main functions
pub use amounts::decode_encrypted_amount;
pub use derivation::derive_commitment_mask;
pub use masks::{find_our_output_and_derive_mask, OutputOwnershipResult};
pub use utils::{encode_varint, extract_tx_pub_key_from_extra};
