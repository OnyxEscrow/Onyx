//! Curve Tree path construction and tree operations.
//!
//! Builds the `Path<Curves>` structure needed by `Fcmp::prove()`.
//! The path represents a single output's location in the tree,
//! including all sibling nodes at each layer from leaf to root.
//!
//! ## Tree Structure
//!
//! ```text
//! Layer 0 (leaves):  38 outputs × 6 coords = 228 Selene scalars
//! Layer 1 (C2):      18 Helios scalars  (LAYER_TWO_LEN)
//! Layer 2 (C1):      38 Selene scalars  (LAYER_ONE_LEN)
//! Layer 3 (C2):      18 Helios scalars
//! ...alternating up to root
//! ```

use crate::types::errors::{CryptoError, CryptoResult};
use super::curves::*;

/// A tree layer's sibling data, typed by which curve it belongs to.
#[derive(Clone, Debug)]
pub enum LayerData {
    /// Selene (C1) layer — x-coordinates of sibling branches.
    Selene(Vec<SeleneScalar>),
    /// Helios (C2) layer — x-coordinates of sibling branches.
    Helios(Vec<HeliosScalar>),
}

/// Builder for constructing a `Path<Curves>` from raw sibling data.
///
/// The path is built bottom-up: first the leaf layer (outputs), then
/// alternating C2 (Helios) and C1 (Selene) branch layers up to the root.
pub struct PathBuilder {
    /// The output being proved.
    output: FcmpOutput<EdwardsPoint>,
    /// All outputs in the leaf layer (including the proved output).
    leaves: Vec<FcmpOutput<EdwardsPoint>>,
    /// Branch layers from leaf to root (alternating C2, C1, C2, C1...).
    layers: Vec<LayerData>,
}

impl PathBuilder {
    /// Create a new path builder.
    ///
    /// # Arguments
    /// * `output` - The specific output being proved
    /// * `leaves` - All outputs in the same leaf bucket (up to LAYER_ONE_LEN)
    pub fn new(
        output: FcmpOutput<EdwardsPoint>,
        leaves: Vec<FcmpOutput<EdwardsPoint>>,
    ) -> CryptoResult<Self> {
        if leaves.is_empty() {
            return Err(CryptoError::CurveTreeError("Leaf set cannot be empty".into()));
        }
        // Verify the proved output is in the leaf set
        let found = leaves.iter().any(|l| {
            l.O() == output.O() && l.I() == output.I() && l.C() == output.C()
        });
        if !found {
            return Err(CryptoError::CurveTreeError(
                "Proved output must be present in leaf set".into(),
            ));
        }
        Ok(Self { output, leaves, layers: Vec::new() })
    }

    /// Push a Helios (C2) branch layer.
    ///
    /// After the leaf layer, the first branch is always C2 (Helios).
    /// Subsequent C2 layers alternate with C1 layers.
    pub fn push_helios_layer(&mut self, siblings: Vec<HeliosScalar>) -> CryptoResult<()> {
        // Pad to LAYER_TWO_LEN if needed
        if siblings.len() > LAYER_TWO_LEN {
            return Err(CryptoError::CurveTreeError(format!(
                "Helios layer has {} elements, max is {LAYER_TWO_LEN}",
                siblings.len()
            )));
        }
        self.layers.push(LayerData::Helios(siblings));
        Ok(())
    }

    /// Push a Selene (C1) branch layer.
    pub fn push_selene_layer(&mut self, siblings: Vec<SeleneScalar>) -> CryptoResult<()> {
        if siblings.len() > LAYER_ONE_LEN {
            return Err(CryptoError::CurveTreeError(format!(
                "Selene layer has {} elements, max is {LAYER_ONE_LEN}",
                siblings.len()
            )));
        }
        self.layers.push(LayerData::Selene(siblings));
        Ok(())
    }

    /// Build the final `Path<Curves>` for use with `Branches::new()`.
    ///
    /// Separates the alternating layers into `curve_2_layers` (Helios) and
    /// `curve_1_layers` (Selene) as required by the vendor API.
    pub fn build(self) -> CryptoResult<Path<Curves>> {
        let mut curve_2_layers: Vec<Vec<HeliosScalar>> = Vec::new();
        let mut curve_1_layers: Vec<Vec<SeleneScalar>> = Vec::new();

        for layer in &self.layers {
            match layer {
                LayerData::Helios(data) => curve_2_layers.push(data.clone()),
                LayerData::Selene(data) => curve_1_layers.push(data.clone()),
            }
        }

        // Validate layer count relationship:
        // curve_2_layers.len() should equal curve_1_layers.len() or curve_1_layers.len() + 1
        let c2 = curve_2_layers.len();
        let c1 = curve_1_layers.len();
        if c2 > 0 && c2.checked_sub(c1).map_or(true, |diff| diff > 1) {
            return Err(CryptoError::CurveTreeError(format!(
                "Invalid layer counts: C2={c2}, C1={c1}. C2 must be C1 or C1+1"
            )));
        }

        Ok(Path {
            output: self.output,
            leaves: self.leaves,
            curve_2_layers,
            curve_1_layers,
        })
    }
}

/// Compute the tree root from a path by hashing up from leaves.
///
/// This recomputes the root hash to verify path consistency.
/// The root is either a Selene or Helios point depending on the number of layers.
pub fn compute_tree_root(path: &Path<Curves>) -> CryptoResult<TreeRoot<Selene, Helios>> {
    // Layer 0: hash leaves → Selene point
    let leaf_hash = hash_leaves(&path.leaves)?;

    if path.curve_2_layers.is_empty() && path.curve_1_layers.is_empty() {
        // Tree has only one layer (leaves). Root is the Selene hash.
        return Ok(TreeRoot::C1(leaf_hash));
    }

    // Extract x-coordinate of leaf hash for first C2 layer
    let mut current_helios_x = selene_x_as_helios_scalar(&leaf_hash)?;

    let mut c2_idx = 0;
    let mut c1_idx = 0;

    // Process layers in pairs: C2 (Helios) then C1 (Selene)
    loop {
        // C2 (Helios) layer: hash HeliosScalars with Helios generators → HeliosPoint
        if c2_idx >= path.curve_2_layers.len() {
            return Err(CryptoError::CurveTreeError("Missing C2 layer".into()));
        }
        let c2_branch = &path.curve_2_layers[c2_idx];
        let mut c2_input = vec![current_helios_x];
        c2_input.extend_from_slice(c2_branch);
        let helios_hash = hash_helios_branch(&c2_input)?;
        c2_idx += 1;

        // Check if this is the last layer
        if c2_idx == path.curve_2_layers.len() && c1_idx == path.curve_1_layers.len() {
            return Ok(TreeRoot::C2(helios_hash));
        }

        // C1 (Selene) layer: hash SeleneScalars with Selene generators → SelenePoint
        let selene_x = helios_x_as_selene_scalar(&helios_hash)?;
        if c1_idx >= path.curve_1_layers.len() {
            return Err(CryptoError::CurveTreeError("Missing C1 layer".into()));
        }
        let c1_branch = &path.curve_1_layers[c1_idx];
        let mut c1_input = vec![selene_x];
        c1_input.extend_from_slice(c1_branch);
        let selene_hash = hash_selene_branch(&c1_input)?;
        c1_idx += 1;

        if c2_idx == path.curve_2_layers.len() && c1_idx == path.curve_1_layers.len() {
            return Ok(TreeRoot::C1(selene_hash));
        }

        current_helios_x = selene_x_as_helios_scalar(&selene_hash)?;
    }
}

/// Pad a Selene branch to `LAYER_ONE_LEN` with zeros.
pub fn pad_selene_branch(branch: &mut Vec<SeleneScalar>) {
    while branch.len() < LAYER_ONE_LEN {
        branch.push(SeleneScalar::ZERO);
    }
}

/// Pad a Helios branch to `LAYER_TWO_LEN` with zeros.
pub fn pad_helios_branch(branch: &mut Vec<HeliosScalar>) {
    while branch.len() < LAYER_TWO_LEN {
        branch.push(HeliosScalar::ZERO);
    }
}

/// Pad a leaf set to `LAYER_ONE_LEN` outputs with identity-safe padding.
///
/// In practice, the tree is always full (padded with random non-identity points),
/// but for testing we can pad with generator multiples.
pub fn pad_leaf_set(
    leaves: &mut Vec<FcmpOutput<EdwardsPoint>>,
) -> CryptoResult<()> {
    let g = <Ed25519 as Ciphersuite>::generator();
    let mut counter = leaves.len() as u64 + 1;
    while leaves.len() < LAYER_ONE_LEN {
        // Generate deterministic non-identity padding points
        let s = Scalar::from(counter);
        let p = g * s;
        let p2 = g * Scalar::from(counter + 1000);
        let p3 = g * Scalar::from(counter + 2000);
        leaves.push(make_output(p, p2, p3)?);
        counter += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn random_output() -> FcmpOutput<EdwardsPoint> {
        let g = <Ed25519 as Ciphersuite>::generator();
        let s1 = Scalar::from(OsRng.next_u64());
        let s2 = Scalar::from(OsRng.next_u64());
        let s3 = Scalar::from(OsRng.next_u64());
        make_output(g * s1, g * s2, g * s3).expect("random output")
    }

    #[test]
    fn test_path_builder_basic() {
        let output = random_output();
        let mut leaves = vec![output];
        pad_leaf_set(&mut leaves).expect("padding");

        let builder = PathBuilder::new(output, leaves).expect("builder");
        let path = builder.build().expect("build");
        assert_eq!(path.leaves.len(), LAYER_ONE_LEN);
        assert!(path.curve_1_layers.is_empty());
        assert!(path.curve_2_layers.is_empty());
    }

    #[test]
    fn test_path_builder_rejects_missing_output() {
        let output = random_output();
        let other = random_output();
        let leaves = vec![other];
        assert!(PathBuilder::new(output, leaves).is_err());
    }

    #[test]
    fn test_path_builder_with_layers() {
        let output = random_output();
        let mut leaves = vec![output];
        pad_leaf_set(&mut leaves).expect("padding");

        let mut builder = PathBuilder::new(output, leaves).expect("builder");

        // Push C2 (Helios) layer
        let helios_siblings: Vec<HeliosScalar> = (0..LAYER_TWO_LEN)
            .map(|i| HeliosScalar::from(i as u64 + 1))
            .collect();
        builder.push_helios_layer(helios_siblings).expect("c2 layer");

        let path = builder.build().expect("build");
        assert_eq!(path.curve_2_layers.len(), 1);
        assert_eq!(path.curve_1_layers.len(), 0);
    }

    #[test]
    fn test_leaf_set_padding() {
        let output = random_output();
        let mut leaves = vec![output];
        assert!(leaves.len() < LAYER_ONE_LEN);
        pad_leaf_set(&mut leaves).expect("padding");
        assert_eq!(leaves.len(), LAYER_ONE_LEN);
    }
}
