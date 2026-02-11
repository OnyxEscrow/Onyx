//! CLSAG domain separators and constants.
//!
//! These constants match Monero's implementation in rctSigs.cpp.

/// CLSAG round hash domain separator.
///
/// Used in `compute_round_hash` for computing challenge at each ring position.
pub const CLSAG_DOMAIN: &[u8] = b"CLSAG_round";

/// CLSAG aggregation domain separator for `μ_P`.
///
/// Used in mixing coefficient computation for the public key component.
pub const CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";

/// CLSAG aggregation domain separator for `μ_C`.
///
/// Used in mixing coefficient computation for the commitment component.
pub const CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";

/// Monero H generator constant from rctTypes.h.
///
/// This is the Pedersen commitment generator for amounts.
/// H = 8 * `hash_to_point(G)` where G is the ed25519 basepoint.
///
/// **IMPORTANT**: This is NOT the same as `hash_to_point(G)`!
/// The multiplication by 8 (cofactor) is critical.
pub const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Pad a domain separator to 32 bytes.
///
/// Monero uses 32-byte key slots for domain separators.
#[inline]
#[must_use]
pub fn pad_domain_separator(domain: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let len = domain.len().min(32);
    padded[..len].copy_from_slice(&domain[..len]);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separators_length() {
        assert_eq!(CLSAG_DOMAIN.len(), 11);
        assert_eq!(CLSAG_AGG_0.len(), 11);
        assert_eq!(CLSAG_AGG_1.len(), 11);
    }

    #[test]
    fn test_pad_domain_separator() {
        let padded = pad_domain_separator(CLSAG_DOMAIN);
        assert_eq!(&padded[..11], CLSAG_DOMAIN);
        assert_eq!(&padded[11..], &[0u8; 21]);
    }

    #[test]
    fn test_h_bytes_length() {
        assert_eq!(H_BYTES.len(), 32);
    }
}
