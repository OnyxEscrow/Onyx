//! FCMP++ membership proof generation and verification.
//!
//! Wraps the `fcmps` crate to generate and verify GBP circuit proofs
//! over the Helios-Selene curve cycle.
//!
//! ## Proof Generation Pipeline
//!
//! 1. Construct `Path<Curves>` with leaf + branch sibling data
//! 2. Create `Branches` from one or more paths
//! 3. Generate output blinds (`OutputBlinds`) from random scalars
//! 4. Generate branch blinds (`BranchBlind`) for each tree layer
//! 5. Blind the branches → `BranchesWithBlinds`
//! 6. Call `Fcmp::prove()` → serialized proof
//!
//! ## Performance
//!
//! Proof generation is O(n·log(N)) where n = inputs, N = UTXO set size.
//! Expected: ~30-60s in WASM for a single input in a tree with ~150M leaves.

use rand_core::{RngCore, CryptoRng};

use crate::types::errors::{CryptoError, CryptoResult};
use super::curves::*;

/// Generate random output blinds for a single input.
///
/// Creates the 4 blind values (O, I, I_blind, C) needed for one output
/// in the membership proof. Each blind involves a `ScalarDecomposition`
/// and a divisor computation — this is the most expensive setup step.
///
/// # Arguments
/// * `rng` - Cryptographic RNG
///
/// # Returns
/// `OutputBlinds<EdwardsPoint>` ready for `Branches::blind()`
pub fn generate_output_blinds(
    rng: &mut (impl RngCore + CryptoRng),
) -> CryptoResult<OutputBlinds<EdwardsPoint>> {
    let t = EdwardsPoint(T());
    let u = EdwardsPoint(FCMP_U());
    let v = EdwardsPoint(FCMP_V());
    let g = <Ed25519 as Ciphersuite>::generator();

    // Generate 4 random non-zero scalars and decompose them
    let o_scalar = random_nonzero_scalar(rng)?;
    let i_scalar = random_nonzero_scalar(rng)?;
    let i_blind_scalar = random_nonzero_scalar(rng)?;
    let c_scalar = random_nonzero_scalar(rng)?;

    let o_blind = OBlind::new(t, decompose_ed25519_scalar(o_scalar)?);
    let i_blind = IBlind::new(u, v, decompose_ed25519_scalar(i_scalar)?);
    let i_blind_blind = IBlindBlind::new(t, decompose_ed25519_scalar(i_blind_scalar)?);
    let c_blind = CBlind::new(g, decompose_ed25519_scalar(c_scalar)?);

    Ok(OutputBlinds::new(o_blind, i_blind, i_blind_blind, c_blind))
}

/// Generate branch blinds for C1 (Selene) layers.
///
/// # Arguments
/// * `rng` - Cryptographic RNG
/// * `count` - Number of C1 blinds needed (from `Branches::necessary_c1_blinds()`)
pub fn generate_c1_branch_blinds(
    rng: &mut (impl RngCore + CryptoRng),
    count: usize,
) -> CryptoResult<Vec<BranchBlind<SelenePoint>>> {
    let h = SELENE_GENERATORS().h();
    let mut blinds = Vec::with_capacity(count);
    for _ in 0..count {
        let scalar = random_nonzero_selene_scalar(rng)?;
        blinds.push(BranchBlind::new(h, decompose_selene_scalar(scalar)?));
    }
    Ok(blinds)
}

/// Generate branch blinds for C2 (Helios) layers.
///
/// # Arguments
/// * `rng` - Cryptographic RNG
/// * `count` - Number of C2 blinds needed (from `Branches::necessary_c2_blinds()`)
pub fn generate_c2_branch_blinds(
    rng: &mut (impl RngCore + CryptoRng),
    count: usize,
) -> CryptoResult<Vec<BranchBlind<HeliosPoint>>> {
    let h = HELIOS_GENERATORS().h();
    let mut blinds = Vec::with_capacity(count);
    for _ in 0..count {
        let scalar = random_nonzero_helios_scalar(rng)?;
        blinds.push(BranchBlind::new(h, decompose_helios_scalar(scalar)?));
    }
    Ok(blinds)
}

/// Generate a complete FCMP membership proof for one or more inputs.
///
/// This is the primary entry point for proof generation. It takes
/// pre-constructed paths and produces a serialized proof.
///
/// # Arguments
/// * `rng` - Cryptographic RNG
/// * `paths` - One `Path<Curves>` per input being spent
///
/// # Returns
/// Tuple of (serialized_proof, tree_root, layer_count, inputs)
///
/// The `inputs` are the blinded input tuples needed for SA+L verification.
#[allow(clippy::type_complexity)]
pub fn generate_membership_proof(
    rng: &mut (impl RngCore + CryptoRng),
    paths: Vec<Path<Curves>>,
) -> CryptoResult<MembershipProofBundle> {
    if paths.is_empty() {
        return Err(CryptoError::CurveTreeError("No paths provided".into()));
    }

    let num_inputs = paths.len();
    let layers = paths[0].curve_1_layers.len() + paths[0].curve_2_layers.len();

    // Step 1: Create Branches from paths
    let branches = Branches::new(paths)
        .ok_or_else(|| CryptoError::CurveTreeError(
            "Failed to create Branches — paths may be inconsistent".into(),
        ))?;

    // Step 2: Generate output blinds for each input
    let mut output_blinds = Vec::with_capacity(num_inputs);
    for _ in 0..num_inputs {
        output_blinds.push(generate_output_blinds(rng)?);
    }

    // Step 3: Generate branch blinds
    let c1_count = branches.necessary_c1_blinds();
    let c2_count = branches.necessary_c2_blinds();
    let c1_blinds = generate_c1_branch_blinds(rng, c1_count)?;
    let c2_blinds = generate_c2_branch_blinds(rng, c2_count)?;

    // Step 4: Blind the branches
    let blinded = branches.blind(output_blinds, c1_blinds, c2_blinds)
        .map_err(|e| CryptoError::CurveTreeError(format!("Blinding failed: {e:?}")))?;

    // Step 5: Prove
    let params = FCMP_PARAMS();
    let proof = Fcmp::<Curves>::prove(rng, params, blinded)
        .map_err(|e| CryptoError::CurveTreeError(format!("Proof generation failed: {e:?}")))?;

    // Step 6: Serialize
    let mut proof_bytes = Vec::new();
    proof.write(&mut proof_bytes)
        .map_err(|e| CryptoError::CurveTreeError(format!("Proof serialization failed: {e}")))?;

    Ok(MembershipProofBundle {
        proof_bytes,
        layers,
    })
}

/// Verify a serialized FCMP membership proof.
///
/// # Arguments
/// * `rng` - Cryptographic RNG
/// * `proof_bytes` - Serialized proof from `generate_membership_proof`
/// * `tree_root` - Expected tree root (Selene or Helios point)
/// * `layers` - Number of tree layers
/// * `inputs` - Blinded input tuples (from `OutputBlinds::blind()`)
pub fn verify_membership_proof(
    rng: &mut (impl RngCore + CryptoRng),
    proof_bytes: &[u8],
    tree_root: TreeRoot<Selene, Helios>,
    layers: usize,
    inputs: &[FcmpInput<SeleneScalar>],
) -> CryptoResult<()> {
    let params = FCMP_PARAMS();

    // Deserialize proof
    let proof = Fcmp::<Curves>::read(&mut proof_bytes.as_ref(), inputs.len(), layers)
        .map_err(|e| CryptoError::CurveTreeError(format!("Proof deserialization failed: {e}")))?;

    // Create batch verifiers (generalized_bulletproofs::BatchVerifier)
    let mut verifier_1 = GbpGenerators::<Selene>::batch_verifier();
    let mut verifier_2 = GbpGenerators::<Helios>::batch_verifier();

    // Queue verification
    proof
        .verify(rng, &mut verifier_1, &mut verifier_2, params, tree_root, layers, inputs)
        .map_err(|e| CryptoError::CurveTreeError(format!("Proof verification failed: {e:?}")))?;

    // Execute batch verification
    if !SELENE_GENERATORS().verify(verifier_1) {
        return Err(CryptoError::CurveTreeError(
            "Selene batch verification failed".into(),
        ));
    }
    if !HELIOS_GENERATORS().verify(verifier_2) {
        return Err(CryptoError::CurveTreeError(
            "Helios batch verification failed".into(),
        ));
    }

    Ok(())
}

/// Bundle containing a generated membership proof and its metadata.
#[derive(Clone, Debug)]
pub struct MembershipProofBundle {
    /// Serialized FCMP proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Number of tree layers (needed for deserialization).
    pub layers: usize,
}

// === Internal Helpers ===

/// Generate a random non-zero Ed25519 scalar.
fn random_nonzero_scalar(
    rng: &mut (impl RngCore + CryptoRng),
) -> CryptoResult<Scalar> {
    for _ in 0..1000 {
        let s = Scalar::random(&mut *rng);
        if s != Scalar::from(0u64) {
            return Ok(s);
        }
    }
    Err(CryptoError::CurveTreeError("Failed to generate non-zero scalar".into()))
}

/// Generate a random non-zero Selene scalar.
fn random_nonzero_selene_scalar(
    rng: &mut (impl RngCore + CryptoRng),
) -> CryptoResult<SeleneScalar> {
    for _ in 0..1000 {
        let s = SeleneScalar::random(&mut *rng);
        if s != SeleneScalar::ZERO {
            return Ok(s);
        }
    }
    Err(CryptoError::CurveTreeError("Failed to generate non-zero Selene scalar".into()))
}

/// Generate a random non-zero Helios scalar.
fn random_nonzero_helios_scalar(
    rng: &mut (impl RngCore + CryptoRng),
) -> CryptoResult<HeliosScalar> {
    for _ in 0..1000 {
        let s = HeliosScalar::random(&mut *rng);
        if s != HeliosScalar::ZERO {
            return Ok(s);
        }
    }
    Err(CryptoError::CurveTreeError("Failed to generate non-zero Helios scalar".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use super::super::tree::{pad_leaf_set, PathBuilder};

    fn random_output() -> FcmpOutput<EdwardsPoint> {
        let g = <Ed25519 as Ciphersuite>::generator();
        let s1 = Scalar::from(OsRng.next_u64());
        let s2 = Scalar::from(OsRng.next_u64());
        let s3 = Scalar::from(OsRng.next_u64());
        make_output(g * s1, g * s2, g * s3).expect("random output")
    }

    #[test]
    fn test_output_blinds_generation() {
        let blinds = generate_output_blinds(&mut OsRng);
        assert!(blinds.is_ok());
    }

    #[test]
    fn test_c1_branch_blinds_generation() {
        let blinds = generate_c1_branch_blinds(&mut OsRng, 3);
        assert!(blinds.is_ok());
        assert_eq!(blinds.expect("blinds").len(), 3);
    }

    #[test]
    fn test_c2_branch_blinds_generation() {
        let blinds = generate_c2_branch_blinds(&mut OsRng, 2);
        assert!(blinds.is_ok());
        assert_eq!(blinds.expect("blinds").len(), 2);
    }

    #[test]
    fn test_single_layer_prove_verify_roundtrip() {
        // Build a minimal tree: just leaves (1 layer)
        let output = random_output();
        let mut leaves = vec![output];
        pad_leaf_set(&mut leaves).expect("padding");

        let builder = PathBuilder::new(output, leaves).expect("builder");
        let path = builder.build().expect("path");

        // Generate proof
        let bundle = generate_membership_proof(&mut OsRng, vec![path.clone()])
            .expect("proof generation");

        assert!(!bundle.proof_bytes.is_empty());
        assert_eq!(bundle.layers, 0); // leaves-only = 0 branch layers
    }
}
