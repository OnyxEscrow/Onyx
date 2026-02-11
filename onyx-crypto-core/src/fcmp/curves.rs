//! Helios/Selene curve cycle operations for FCMP++ Curve Trees.
//!
//! This module provides the foundational curve operations for the two-cycle
//! (Helios ↔ Selene) that enables efficient recursive membership proofs.
//!
//! ## Curve Cycle Property
//!
//! - **Ed25519** (output curve): Leaves — `(O, I, C)` tuples
//! - **Selene** (C1, odd layers): `base_field(Ed25519) == scalar_field(Selene)`
//! - **Helios** (C2, even layers): `base_field(Selene) == scalar_field(Helios)`
//!
//! This cycle means constraints on one curve's base field can reference the
//! other curve's scalar field, enabling pairing-free recursive proofs.

use crate::types::errors::{CryptoError, CryptoResult};

// Re-export curve types from vendor
pub use ciphersuite::{Ciphersuite, Ed25519, Helios, Selene};
pub use ciphersuite::group::{
    ff::{Field, PrimeField, PrimeFieldBits},
    Group, GroupEncoding,
};
pub use dalek_ff_group::{EdwardsPoint, Scalar};

// Re-export FCMP curve configuration
pub use monero_fcmp_plus_plus::{
    Curves, Ed25519Params, SeleneParams, HeliosParams,
    FCMP_PARAMS, HELIOS_GENERATORS, SELENE_GENERATORS,
    HELIOS_HASH_INIT, SELENE_HASH_INIT,
};

// Re-export tree-building types from fcmps
pub use monero_fcmp_plus_plus::fcmps::{
    FcmpCurves, FcmpParams, TreeRoot,
    Output as FcmpOutput,
    Input as FcmpInput,
    Fcmp, FcmpError,
    LAYER_ONE_LEN, LAYER_TWO_LEN,
    tree::{hash_grow, hash_trim},
};

// Re-export prover types
pub use monero_fcmp_plus_plus::fcmps::{
    Path, Branches, BranchesWithBlinds,
    OutputBlinds, OBlind, IBlind, IBlindBlind, CBlind, BranchBlind,
};

// Re-export divisor types for blind construction
pub use ec_divisors::{DivisorCurve, ScalarDecomposition};

// Re-export batch verifier types for membership proof verification
pub use generalized_bulletproofs::{
    BatchVerifier,
    Generators as GbpGenerators,
};


// Generators
pub use fcmp_monero_generators::{T, FCMP_U, FCMP_V};

/// Selene scalar field element type (= Ed25519 base field).
pub type SeleneScalar = <Selene as Ciphersuite>::F;
/// Selene group element type.
pub type SelenePoint = <Selene as Ciphersuite>::G;
/// Helios scalar field element type (= Selene base field).
pub type HeliosScalar = <Helios as Ciphersuite>::F;
/// Helios group element type.
pub type HeliosPoint = <Helios as Ciphersuite>::G;

/// Convert a 32-byte array to a Selene scalar field element.
pub fn bytes_to_selene_scalar(bytes: &[u8; 32]) -> CryptoResult<SeleneScalar> {
    let mut repr = <SeleneScalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Option::from(SeleneScalar::from_repr(repr))
        .ok_or_else(|| CryptoError::CurveTreeError("Invalid Selene scalar encoding".into()))
}

/// Convert a 32-byte array to a Helios scalar field element.
pub fn bytes_to_helios_scalar(bytes: &[u8; 32]) -> CryptoResult<HeliosScalar> {
    let mut repr = <HeliosScalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Option::from(HeliosScalar::from_repr(repr))
        .ok_or_else(|| CryptoError::CurveTreeError("Invalid Helios scalar encoding".into()))
}

/// Convert a 32-byte array to a Selene point.
pub fn bytes_to_selene_point(bytes: &[u8; 32]) -> CryptoResult<SelenePoint> {
    let mut repr = <SelenePoint as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Option::from(SelenePoint::from_bytes(&repr))
        .ok_or_else(|| CryptoError::CurveTreeError("Invalid Selene point encoding".into()))
}

/// Convert a 32-byte array to a Helios point.
pub fn bytes_to_helios_point(bytes: &[u8; 32]) -> CryptoResult<HeliosPoint> {
    let mut repr = <HeliosPoint as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Option::from(HeliosPoint::from_bytes(&repr))
        .ok_or_else(|| CryptoError::CurveTreeError("Invalid Helios point encoding".into()))
}

/// Serialize a Selene point to 32 bytes.
pub fn selene_point_to_bytes(point: &SelenePoint) -> [u8; 32] {
    let repr = point.to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

/// Serialize a Helios point to 32 bytes.
pub fn helios_point_to_bytes(point: &HeliosPoint) -> [u8; 32] {
    let repr = point.to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

/// Decompose a scalar for use in membership proof blinds.
///
/// `ScalarDecomposition` is required by all blind constructors (`OBlind`, `IBlind`, etc.).
/// It decomposes the scalar into a binary representation suitable for the
/// discrete-log circuit gadget.
///
/// Returns `None` if the scalar is zero (which would produce an identity point).
pub fn decompose_ed25519_scalar(
    scalar: <Ed25519 as Ciphersuite>::F,
) -> CryptoResult<ScalarDecomposition<<Ed25519 as Ciphersuite>::F>> {
    ScalarDecomposition::new(scalar)
        .ok_or_else(|| CryptoError::CurveTreeError("Failed to decompose scalar (zero?)".into()))
}

/// Decompose a Selene scalar for branch blinds on C1 layers.
pub fn decompose_selene_scalar(
    scalar: SeleneScalar,
) -> CryptoResult<ScalarDecomposition<SeleneScalar>> {
    ScalarDecomposition::new(scalar)
        .ok_or_else(|| CryptoError::CurveTreeError("Failed to decompose Selene scalar".into()))
}

/// Decompose a Helios scalar for branch blinds on C2 layers.
pub fn decompose_helios_scalar(
    scalar: HeliosScalar,
) -> CryptoResult<ScalarDecomposition<HeliosScalar>> {
    ScalarDecomposition::new(scalar)
        .ok_or_else(|| CryptoError::CurveTreeError("Failed to decompose Helios scalar".into()))
}

/// Construct an FCMP Output tuple from Ed25519 points.
///
/// Validates that none of O, I, C are the identity point.
pub fn make_output(
    O: EdwardsPoint,
    I: EdwardsPoint,
    C: EdwardsPoint,
) -> CryptoResult<FcmpOutput<EdwardsPoint>> {
    FcmpOutput::new(O, I, C)
        .map_err(|e| CryptoError::CurveTreeError(format!("Invalid output tuple: {e:?}")))
}

/// Hash a set of leaf outputs into a Selene point (layer 0 → layer 1).
///
/// Each output contributes 6 field elements (O.x, O.y, I.x, I.y, C.x, C.y)
/// to a Pedersen vector commitment using Selene generators.
pub fn hash_leaves(leaves: &[FcmpOutput<EdwardsPoint>]) -> CryptoResult<SelenePoint> {
    let generators = SELENE_GENERATORS();
    let g_bold = generators.g_bold_slice();

    let mut pairs = Vec::with_capacity(leaves.len() * 6);
    for leaf in leaves {
        let (ox, oy) = EdwardsPoint::to_xy(leaf.O())
            .ok_or_else(|| CryptoError::CurveTreeError("O is identity".into()))?;
        let (ix, iy) = EdwardsPoint::to_xy(leaf.I())
            .ok_or_else(|| CryptoError::CurveTreeError("I is identity".into()))?;
        let (cx, cy) = EdwardsPoint::to_xy(leaf.C())
            .ok_or_else(|| CryptoError::CurveTreeError("C is identity".into()))?;

        let base = pairs.len();
        for (i, scalar) in [ox, oy, ix, iy, cx, cy].into_iter().enumerate() {
            let gen = g_bold.get(base + i)
                .ok_or_else(|| CryptoError::CurveTreeError("Not enough Selene generators".into()))?;
            pairs.push((scalar, *gen));
        }
    }

    let point = SELENE_HASH_INIT() + multiexp::multiexp_vartime(&pairs);
    Ok(point)
}

/// Hash a C1 (Selene) layer: Pedersen commitment of SeleneScalars → SelenePoint.
///
/// Used for odd tree layers. Input scalars are x-coordinates of child nodes.
pub fn hash_selene_branch(children: &[SeleneScalar]) -> CryptoResult<SelenePoint> {
    let generators = SELENE_GENERATORS();
    let g_bold = generators.g_bold_slice();

    let mut pairs = Vec::with_capacity(children.len());
    for (i, scalar) in children.iter().enumerate() {
        let gen = g_bold.get(i)
            .ok_or_else(|| CryptoError::CurveTreeError("Not enough Selene generators".into()))?;
        pairs.push((*scalar, *gen));
    }

    let point = SELENE_HASH_INIT() + multiexp::multiexp_vartime(&pairs);
    Ok(point)
}

/// Hash a C2 (Helios) layer: Pedersen commitment of HeliosScalars → HeliosPoint.
///
/// Used for even tree layers. Input scalars are x-coordinates of child nodes.
pub fn hash_helios_branch(children: &[HeliosScalar]) -> CryptoResult<HeliosPoint> {
    let generators = HELIOS_GENERATORS();
    let g_bold = generators.g_bold_slice();

    let mut pairs = Vec::with_capacity(children.len());
    for (i, scalar) in children.iter().enumerate() {
        let gen = g_bold.get(i)
            .ok_or_else(|| CryptoError::CurveTreeError("Not enough Helios generators".into()))?;
        pairs.push((*scalar, *gen));
    }

    let point = HELIOS_HASH_INIT() + multiexp::multiexp_vartime(&pairs);
    Ok(point)
}

/// Extract the x-coordinate of a Selene point as a Helios scalar.
///
/// This is the fundamental cross-curve conversion: a Selene point's
/// x-coordinate lives in Selene's base field, which IS Helios's scalar field.
pub fn selene_x_as_helios_scalar(point: &SelenePoint) -> CryptoResult<HeliosScalar> {
    let (x, _y) = SelenePoint::to_xy(*point)
        .ok_or_else(|| CryptoError::CurveTreeError("Selene point is identity".into()))?;
    // Selene's base field = Helios's scalar field — direct cast
    // Both are the same field, the type system just names them differently
    // The x-coordinate is already a C2::F (Helios scalar)
    Ok(x)
}

/// Extract the x-coordinate of a Helios point as a Selene scalar.
///
/// Helios base field = Selene scalar field — direct cast.
pub fn helios_x_as_selene_scalar(point: &HeliosPoint) -> CryptoResult<SeleneScalar> {
    let (x, _y) = HeliosPoint::to_xy(*point)
        .ok_or_else(|| CryptoError::CurveTreeError("Helios point is identity".into()))?;
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_selene_scalar_roundtrip() {
        let scalar = SeleneScalar::random(&mut OsRng);
        let repr = scalar.to_repr();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        let recovered = bytes_to_selene_scalar(&bytes).expect("roundtrip failed");
        assert_eq!(scalar, recovered);
    }

    #[test]
    fn test_helios_scalar_roundtrip() {
        let scalar = HeliosScalar::random(&mut OsRng);
        let repr = scalar.to_repr();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        let recovered = bytes_to_helios_scalar(&bytes).expect("roundtrip failed");
        assert_eq!(scalar, recovered);
    }

    #[test]
    fn test_make_output_rejects_identity() {
        let identity = EdwardsPoint::identity();
        let point = <Ed25519 as Ciphersuite>::generator();
        assert!(make_output(identity, point, point).is_err());
        assert!(make_output(point, identity, point).is_err());
        assert!(make_output(point, point, identity).is_err());
    }

    #[test]
    fn test_leaf_hashing_deterministic() {
        // Same leaves should hash to same point
        let g = <Ed25519 as Ciphersuite>::generator();
        let s = Scalar::from(42u64);
        let p1 = g * s;
        let p2 = g * Scalar::from(7u64);
        let p3 = g * Scalar::from(13u64);
        let output = make_output(p1, p2, p3).expect("valid output");

        let h1 = hash_leaves(&[output]).expect("hash failed");
        let h2 = hash_leaves(&[output]).expect("hash failed");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_cross_curve_x_extraction() {
        // Selene point → x-coordinate → Helios scalar should work
        let selene_g = Selene::generator();
        let result = selene_x_as_helios_scalar(&selene_g);
        assert!(result.is_ok());
        let _helios_scalar = result.expect("extraction failed");

        // Helios point → x-coordinate → Selene scalar
        let helios_g = Helios::generator();
        let result = helios_x_as_selene_scalar(&helios_g);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scalar_decomposition_nonzero() {
        let scalar = Scalar::from(1u64);
        let result = decompose_ed25519_scalar(scalar);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scalar_decomposition_zero_rejected() {
        let zero = Scalar::from(0u64);
        let result = decompose_ed25519_scalar(zero);
        assert!(result.is_err());
    }

    #[test]
    fn test_params_initialization() {
        // FCMP_PARAMS should initialize without panic
        let params = FCMP_PARAMS();
        // Verify generators exist
        let selene_gens = SELENE_GENERATORS();
        let helios_gens = HELIOS_GENERATORS();
        assert!(!selene_gens.g_bold_slice().is_empty());
        assert!(!helios_gens.g_bold_slice().is_empty());
        let _ = params; // suppress unused
    }
}
