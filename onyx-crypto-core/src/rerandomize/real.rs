//! Real re-randomization using `monero-fcmp-plus-plus` crate.
//!
//! This wraps `monero_fcmp_plus_plus::sal::RerandomizedOutput` which
//! handles the full additive re-randomization scheme with generators T, U, V.

use rand_core::{CryptoRng, RngCore};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ed25519};
use dalek_ff_group::EdwardsPoint;
use fcmp_monero_generators::{FCMP_U, FCMP_V, T};
use monero_fcmp_plus_plus::sal::RerandomizedOutput as VendorRerandomizedOutput;
use monero_fcmp_plus_plus::Output as FcmpOutput;

use crate::types::errors::{CryptoError, CryptoResult};

/// The vendor's `RerandomizedOutput` — a thin re-export with Onyx ergonomics.
///
/// This type wraps the actual cryptographic re-randomization from kayabaNerve's crate.
/// It contains the input tuple `(O~, I~, R, C~)` plus the 4 blinding scalars
/// `(r_o, r_i, r_r_i, r_c)`.
pub struct OnyxRerandomizedOutput {
    inner: VendorRerandomizedOutput,
}

impl OnyxRerandomizedOutput {
    /// Re-randomize a Monero output for FCMP++ proving.
    ///
    /// Creates fresh random scalars `(r_o, r_i, r_r_i, r_c)` and computes
    /// the re-randomized input tuple.
    ///
    /// # Arguments
    /// * `rng` - Cryptographic RNG
    /// * `output` - The FCMP++ output (O, I, C) to re-randomize
    pub fn new(rng: &mut (impl RngCore + CryptoRng), output: FcmpOutput) -> Self {
        Self {
            inner: VendorRerandomizedOutput::new(rng, output),
        }
    }

    /// The scalar for `OBlind::new` (additive inverse of `r_o`).
    pub fn o_blind(&self) -> <Ed25519 as Ciphersuite>::F {
        self.inner.o_blind()
    }

    /// The scalar for `IBlind::new` (additive inverse of `r_i`).
    pub fn i_blind(&self) -> <Ed25519 as Ciphersuite>::F {
        self.inner.i_blind()
    }

    /// The scalar for `IBlindBlind::new` (`r_r_i`, NOT negated).
    pub fn i_blind_blind(&self) -> <Ed25519 as Ciphersuite>::F {
        self.inner.i_blind_blind()
    }

    /// The scalar for `CBlind::new` (additive inverse of `r_c`).
    pub fn c_blind(&self) -> <Ed25519 as Ciphersuite>::F {
        self.inner.c_blind()
    }

    /// The re-randomized input tuple `(O~, I~, R, C~)`.
    pub fn input(&self) -> monero_fcmp_plus_plus::Input {
        self.inner.input()
    }

    /// Consume and return the inner vendor type for direct use with `SalAlgorithm`.
    pub fn into_inner(self) -> VendorRerandomizedOutput {
        self.inner
    }

    /// Serialize the re-randomized output (including secrets).
    ///
    /// WARNING: The serialized form contains secrets that link the output
    /// to the input it's spent with. Handle with care.
    pub fn serialize(&self) -> CryptoResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.inner
            .write(&mut buf)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize a previously serialized re-randomized output.
    pub fn deserialize(data: &[u8]) -> CryptoResult<Self> {
        let inner = VendorRerandomizedOutput::read(&mut &data[..])
            .map_err(|e| CryptoError::DeserializationError(e.to_string()))?;
        Ok(Self { inner })
    }
}

/// Return the FCMP++ generators T, U, V as compressed bytes.
///
/// These are the fixed generators from `monero-generators`:
/// - T: output key re-randomization
/// - U: key image blinding (linking domain)
/// - V: key image blinding verification
pub fn fcmp_generators() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t = EdwardsPoint(T()).to_bytes();
    let u = EdwardsPoint(FCMP_U()).to_bytes();
    let v = EdwardsPoint(FCMP_V()).to_bytes();

    let mut t_bytes = [0u8; 32];
    let mut u_bytes = [0u8; 32];
    let mut v_bytes = [0u8; 32];

    t_bytes.copy_from_slice(t.as_ref());
    u_bytes.copy_from_slice(u.as_ref());
    v_bytes.copy_from_slice(v.as_ref());

    (t_bytes, u_bytes, v_bytes)
}
