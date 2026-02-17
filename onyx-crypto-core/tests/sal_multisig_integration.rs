//! Integration tests: Full FCMP++ SA+L 2-of-3 multisig signing.
//!
//! Tests the complete pipeline that Onyx EaaS will use:
//! 1. FROST DKG → ThresholdKeys<Ed25519T>
//! 2. Output creation → RerandomizedOutput
//! 3. SA+L proof generation via threshold signing
//! 4. Proof verification (single + batch)
//!
//! Run: `cargo test --test sal_multisig_integration`

#![cfg(feature = "fcmp")]

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};

use ciphersuite::{
    group::{ff::PrimeField, Group, GroupEncoding},
    Ciphersuite,
};
use dalek_ff_group::{EdwardsPoint, Scalar};
use flexible_transcript::{Transcript, RecommendedTranscript};
use fcmp_monero_generators::T;
use multiexp::BatchVerifier;

use modular_frost::{
    FrostError, Participant, ThresholdCore, ThresholdKeys, ThresholdParams,
    dkg::frost::KeyGenMachine,
    sign::{AlgorithmMachine, PreprocessMachine, SignMachine, SignatureMachine, Writable},
    tests::{algorithm_machines, clone_without, key_gen, sign},
};

use monero_fcmp_plus_plus::{
    Output,
    sal::{
        multisig::{Ed25519T, SalAlgorithm},
        RerandomizedOutput,
    },
};

use onyx_crypto_core::gsp::{
    multisig::{bytes_to_point, bytes_to_scalar, participant, OnyxSalSigner},
    verify::{verify_sal_proofs_batch, verify_sal_single},
};

// =====================================================================
// Helpers
// =====================================================================

/// Construct 2-of-3 threshold keys for Ed25519T using Shamir's Secret Sharing.
///
/// Returns (keys_per_participant, group_secret_y).
/// The group key is y * T (Ed25519T generator).
fn threshold_keys_2of3() -> (HashMap<Participant, ThresholdKeys<Ed25519T>>, Scalar) {
    use ciphersuite::group::ff::Field;

    let y_secret = Scalar::random(&mut OsRng);
    let coeff = Scalar::random(&mut OsRng);

    // f(x) = y_secret + coeff * x  (degree-1 polynomial, threshold = 2)
    let shares = [
        y_secret + coeff * Scalar::from(1u64),
        y_secret + coeff * Scalar::from(2u64),
        y_secret + coeff * Scalar::from(3u64),
    ];

    // Verification shares: vs_i = share_i * T  (Ed25519T generator)
    let generator = <Ed25519T as Ciphersuite>::generator();
    let verification_shares: Vec<EdwardsPoint> = shares.iter().map(|s| generator * *s).collect();

    let id = <Ed25519T as Ciphersuite>::ID;
    let t: u16 = 2;
    let n: u16 = 3;

    let mut keys = HashMap::new();
    for i in 0u16..3 {
        let participant_idx = i + 1;

        // Serialize ThresholdCore manually:
        //   [4 bytes: ID len][ID bytes][2: t][2: n][2: i][32: secret_share][n * 32: verification_shares]
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&u32::try_from(id.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(id);
        buf.extend_from_slice(&t.to_le_bytes());
        buf.extend_from_slice(&n.to_le_bytes());
        buf.extend_from_slice(&participant_idx.to_le_bytes());
        buf.extend_from_slice(shares[i as usize].to_repr().as_ref());
        for vs in &verification_shares {
            buf.extend_from_slice(vs.to_bytes().as_ref());
        }

        let core = ThresholdCore::<Ed25519T>::read::<&[u8]>(&mut buf.as_slice())
            .expect("ThresholdCore deserialization failed");
        keys.insert(
            Participant::new(participant_idx).unwrap(),
            ThresholdKeys::new(core),
        );
    }

    // All participants must agree on the group key
    let gk = keys[&Participant::new(1).unwrap()].group_key();
    for k in keys.values() {
        assert_eq!(k.group_key(), gk, "group keys must agree");
    }
    // Verify group key = y * T
    assert_eq!(gk, generator * y_secret, "group key must equal y * T");

    (keys, y_secret)
}

/// Execute the 2-round FROST signing protocol manually with exactly 2 signers.
///
/// This simulates the real Onyx escrow flow where 2-of-3 parties cooperate.
fn frost_sign_2of2(
    algorithm: &SalAlgorithm<OsRng, RecommendedTranscript>,
    keys: &HashMap<Participant, ThresholdKeys<Ed25519T>>,
    signers: [Participant; 2],
) -> monero_fcmp_plus_plus::sal::SpendAuthAndLinkability {
    // Create machines for the two signers
    let mut machines: Vec<(Participant, _)> = signers
        .iter()
        .map(|&s| (s, AlgorithmMachine::new(algorithm.clone(), keys[&s].clone())))
        .collect();

    // === Round 1: Preprocess ===
    let mut sign_machines = Vec::new();
    let mut preprocesses = HashMap::new();

    for (i, machine) in machines.drain(..) {
        let (sign_machine, preprocess) = machine.preprocess(&mut OsRng);
        // Serialize/deserialize (simulates wire transport)
        let mut buf = vec![];
        preprocess.write(&mut buf).unwrap();
        let parsed = sign_machine
            .read_preprocess::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        preprocesses.insert(i, parsed);
        sign_machines.push((i, sign_machine));
    }

    // === Round 2: Sign ===
    let mut sig_machines = Vec::new();
    let mut shares = HashMap::new();

    for (i, machine) in sign_machines.drain(..) {
        // Collect other signers' preprocesses
        let others: HashMap<_, _> = preprocesses
            .iter()
            .filter(|(p, _)| **p != i)
            .map(|(p, pp)| (*p, pp.clone()))
            .collect();

        let (sig_machine, share) = machine.sign(others, &[]).unwrap();
        // Serialize/deserialize share
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        let parsed = sig_machine
            .read_share::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        shares.insert(i, parsed);
        sig_machines.push((i, sig_machine));
    }

    // === Complete: Aggregate shares ===
    let mut signature = None;
    for (i, machine) in sig_machines.drain(..) {
        let others: HashMap<_, _> = shares
            .iter()
            .filter(|(p, _)| **p != i)
            .map(|(p, s)| (*p, s.clone()))
            .collect();

        let sig = machine.complete(others).unwrap();
        if let Some(ref prev) = signature {
            assert_eq!(&sig, prev, "all signers must produce identical proof");
        }
        signature = Some(sig);
    }

    signature.unwrap()
}

/// Create a test output, re-randomize it, and return (rerandomized_output, key_image).
fn create_test_output(
    x: &Scalar,
    group_key: EdwardsPoint,
) -> (RerandomizedOutput, EdwardsPoint, [u8; 32]) {
    let o_key = (EdwardsPoint::generator() * *x) + group_key; // O = xG + yT
    let i_base = EdwardsPoint::random(&mut OsRng); // Key image base
    let c_point = EdwardsPoint::random(&mut OsRng); // Commitment
    let key_image = i_base * *x; // L = x * I

    let output = Output::new(o_key, i_base, c_point).expect("valid output");
    let rerandomized = RerandomizedOutput::new(&mut OsRng, output);

    let tx_hash = {
        let mut h = [0u8; 32];
        OsRng.fill_bytes(&mut h);
        h
    };

    (rerandomized, key_image, tx_hash)
}

// =====================================================================
// Test 1: Vendor round-trip (proves vendor crate integration works)
// =====================================================================

#[test]
fn test_vendor_sal_multisig_roundtrip() {
    use ciphersuite::group::ff::Field;

    let x = Scalar::random(&mut OsRng);
    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    let o_key = (EdwardsPoint::generator() * x) + keys.values().next().unwrap().group_key();
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);
    let key_image = i_base * x;

    let rerandomized =
        RerandomizedOutput::new(&mut OsRng, Output::new(o_key, i_base, c_point).unwrap());
    let input = rerandomized.input();

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Onyx Vendor Integration Test"),
        [0u8; 32],
        rerandomized.clone(),
        x,
    );

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let sig = sign(
        &mut OsRng,
        &algorithm,
        keys.clone(),
        algorithm_machines(&mut OsRng, &algorithm, &keys),
        &[],
    );

    let mut verifier = BatchVerifier::new(1);
    sig.verify(&mut OsRng, &mut verifier, [0u8; 32], &input, key_image);
    assert!(verifier.verify_vartime(), "SA+L proof verification failed");
}

// =====================================================================
// Test 2: OnyxSalSigner wrapper (proves our abstraction layer works)
// =====================================================================

#[test]
fn test_onyx_sal_signer_wrapper() {
    use ciphersuite::group::ff::Field;

    let x = Scalar::random(&mut OsRng);
    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    let o_key = (EdwardsPoint::generator() * x) + keys.values().next().unwrap().group_key();
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);
    let key_image = i_base * x;

    let rerandomized =
        RerandomizedOutput::new(&mut OsRng, Output::new(o_key, i_base, c_point).unwrap());
    let input = rerandomized.input();

    // Use OnyxSalSigner wrapper instead of SalAlgorithm directly
    let signer = OnyxSalSigner::new(OsRng, [0u8; 32], rerandomized.clone(), x);
    let algorithm = signer.into_algorithm();

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let sig = sign(
        &mut OsRng,
        &algorithm,
        keys.clone(),
        algorithm_machines(&mut OsRng, &algorithm, &keys),
        &[],
    );

    // Verify through Onyx's verify_sal_single wrapper
    verify_sal_single(&mut OsRng, &sig, [0u8; 32], &input, key_image)
        .expect("Onyx verify_sal_single failed");
}

// =====================================================================
// Test 3: Full 2-of-3 escrow — all signer combinations
// =====================================================================

#[test]
fn test_2of3_escrow_all_signer_combinations() {
    use ciphersuite::group::ff::Field;

    let (mut keys, _y_secret) = threshold_keys_2of3();
    let x = Scalar::random(&mut OsRng);

    let group_key = keys.values().next().unwrap().group_key();
    let (rerandomized, key_image, tx_hash) = create_test_output(&x, group_key);
    let input = rerandomized.input();

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Onyx 2-of-3 Escrow Test"),
        tx_hash,
        rerandomized.clone(),
        x,
    );

    // Offset keys by -o_blind
    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let p1 = Participant::new(1).unwrap(); // Buyer
    let p2 = Participant::new(2).unwrap(); // Seller
    let p3 = Participant::new(3).unwrap(); // Arbiter

    // === Combination 1: Buyer + Seller (happy path) ===
    let sig_bs = frost_sign_2of2(&algorithm, &keys, [p1, p2]);
    let mut verifier = BatchVerifier::new(1);
    sig_bs.verify(&mut OsRng, &mut verifier, tx_hash, &input, key_image);
    assert!(
        verifier.verify_vartime(),
        "Buyer+Seller signing failed"
    );

    // === Combination 2: Buyer + Arbiter (dispute, buyer wins) ===
    let sig_ba = frost_sign_2of2(&algorithm, &keys, [p1, p3]);
    let mut verifier = BatchVerifier::new(1);
    sig_ba.verify(&mut OsRng, &mut verifier, tx_hash, &input, key_image);
    assert!(
        verifier.verify_vartime(),
        "Buyer+Arbiter signing failed"
    );

    // === Combination 3: Seller + Arbiter (dispute, seller wins) ===
    let sig_sa = frost_sign_2of2(&algorithm, &keys, [p2, p3]);
    let mut verifier = BatchVerifier::new(1);
    sig_sa.verify(&mut OsRng, &mut verifier, tx_hash, &input, key_image);
    assert!(
        verifier.verify_vartime(),
        "Seller+Arbiter signing failed"
    );
}

// =====================================================================
// Test 4: Batch verification of multiple proofs
// =====================================================================

#[test]
fn test_batch_verification_3_proofs() {
    use ciphersuite::group::ff::Field;

    let mut proof_data = Vec::new();

    for _ in 0..3 {
        let x = Scalar::random(&mut OsRng);
        let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

        let o_key = (EdwardsPoint::generator() * x) + keys.values().next().unwrap().group_key();
        let i_base = EdwardsPoint::random(&mut OsRng);
        let c_point = EdwardsPoint::random(&mut OsRng);
        let key_image = i_base * x;

        let rerandomized =
            RerandomizedOutput::new(&mut OsRng, Output::new(o_key, i_base, c_point).unwrap());
        let input = rerandomized.input();
        let tx_hash = [0u8; 32];

        let algorithm = SalAlgorithm::new(
            OsRng,
            RecommendedTranscript::new(b"Onyx Batch Test"),
            tx_hash,
            rerandomized.clone(),
            x,
        );

        for keys in keys.values_mut() {
            *keys = keys.offset(-rerandomized.o_blind());
        }

        let sig = sign(
            &mut OsRng,
            &algorithm,
            keys.clone(),
            algorithm_machines(&mut OsRng, &algorithm, &keys),
            &[],
        );

        proof_data.push((sig, tx_hash, input, key_image));
    }

    // Batch verify through Onyx wrapper
    let batch_input: Vec<_> = proof_data
        .iter()
        .map(|(sig, tx_hash, input, key_image)| (sig, *tx_hash, input, *key_image))
        .collect();

    verify_sal_proofs_batch(&mut OsRng, &batch_input).expect("Batch verification failed");
}

// =====================================================================
// Test 5: Onyx type conversion helpers
// =====================================================================

#[test]
fn test_bytes_to_scalar_roundtrip() {
    use ciphersuite::group::ff::Field;

    // Zero
    let zero = [0u8; 32];
    let s = bytes_to_scalar(&zero).expect("zero is valid");
    assert_eq!(s, Scalar::from(0u64));

    // One
    let mut one = [0u8; 32];
    one[0] = 1;
    let s = bytes_to_scalar(&one).expect("one is valid");
    assert_eq!(s, Scalar::from(1u64));

    // Roundtrip with random scalar
    let random_s = Scalar::random(&mut OsRng);
    let bytes: [u8; 32] = random_s.to_repr().into();
    let recovered = bytes_to_scalar(&bytes).expect("random scalar roundtrip");
    assert_eq!(recovered, random_s);
}

#[test]
fn test_bytes_to_point_roundtrip() {

    // Generator point
    let gen = EdwardsPoint::generator();
    let bytes: [u8; 32] = gen.to_bytes().into();
    let recovered = bytes_to_point(&bytes).expect("generator roundtrip");
    assert_eq!(recovered, gen);

    // T generator
    let t_gen = EdwardsPoint(T());
    let bytes: [u8; 32] = t_gen.to_bytes().into();
    let recovered = bytes_to_point(&bytes).expect("T generator roundtrip");
    assert_eq!(recovered, t_gen);

    // Random point
    let random_p = EdwardsPoint::random(&mut OsRng);
    let bytes: [u8; 32] = random_p.to_bytes().into();
    let recovered = bytes_to_point(&bytes).expect("random point roundtrip");
    assert_eq!(recovered, random_p);
}

#[test]
fn test_participant_helper() {
    assert!(participant(1).is_ok());
    assert!(participant(2).is_ok());
    assert!(participant(3).is_ok());
    assert!(participant(0).is_err(), "participant 0 must be invalid");
}

// =====================================================================
// Test 6: 2-of-3 with OnyxSalSigner + Onyx verify wrappers (full stack)
// =====================================================================

#[test]
fn test_2of3_full_onyx_stack() {
    use ciphersuite::group::ff::Field;

    let (mut keys, _) = threshold_keys_2of3();
    let x = Scalar::random(&mut OsRng);

    let group_key = keys.values().next().unwrap().group_key();
    let (rerandomized, key_image, tx_hash) = create_test_output(&x, group_key);
    let input = rerandomized.input();

    // Use OnyxSalSigner wrapper
    let signer = OnyxSalSigner::new(OsRng, tx_hash, rerandomized.clone(), x);
    let algorithm = signer.into_algorithm();

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let p1 = Participant::new(1).unwrap();
    let p2 = Participant::new(2).unwrap();

    // Sign with buyer + seller using manual protocol
    let sig = frost_sign_2of2(&algorithm, &keys, [p1, p2]);

    // Verify through Onyx verify_sal_single
    verify_sal_single(&mut OsRng, &sig, tx_hash, &input, key_image)
        .expect("Full Onyx stack: verify_sal_single failed");
}

// =====================================================================
// Test 7: Verify that single-signer == multisig (consistency check)
// =====================================================================

#[test]
fn test_single_vs_multisig_consistency() {
    use ciphersuite::group::ff::Field;
    use monero_fcmp_plus_plus::sal::{OpenedInputTuple, SpendAuthAndLinkability};

    let x = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);

    let o_key = (EdwardsPoint::generator() * x) + (EdwardsPoint(T()) * y);
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);
    let key_image = i_base * x;

    let output = Output::new(o_key, i_base, c_point).unwrap();
    let rerandomized = RerandomizedOutput::new(&mut OsRng, output);
    let input = rerandomized.input();

    // Single-signer proof (direct, no FROST)
    let opening = OpenedInputTuple::open(rerandomized.clone(), &x, &y).unwrap();
    let (l_single, proof_single) = SpendAuthAndLinkability::prove(&mut OsRng, [0u8; 32], opening);
    assert_eq!(l_single, key_image);

    // Verify single-signer proof
    let mut verifier = BatchVerifier::new(1);
    proof_single.verify(&mut OsRng, &mut verifier, [0u8; 32], &input, key_image);
    assert!(
        verifier.verify_vartime(),
        "Single-signer proof should verify"
    );

    // Multisig proof (via FROST with vendor test helpers)
    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    // Need the output to use the multisig group key as y component.
    // Re-create output with the DKG group key.
    let ms_group_key = keys.values().next().unwrap().group_key();
    let ms_o = (EdwardsPoint::generator() * x) + ms_group_key;
    let ms_output = Output::new(ms_o, i_base, c_point).unwrap();
    let ms_rerandomized = RerandomizedOutput::new(&mut OsRng, ms_output);
    let ms_input = ms_rerandomized.input();

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Consistency Test"),
        [0u8; 32],
        ms_rerandomized.clone(),
        x,
    );

    for keys in keys.values_mut() {
        *keys = keys.offset(-ms_rerandomized.o_blind());
    }

    let sig_multi = sign(
        &mut OsRng,
        &algorithm,
        keys.clone(),
        algorithm_machines(&mut OsRng, &algorithm, &keys),
        &[],
    );

    // Both proofs verify independently
    let mut verifier = BatchVerifier::new(1);
    sig_multi.verify(&mut OsRng, &mut verifier, [0u8; 32], &ms_input, key_image);
    assert!(
        verifier.verify_vartime(),
        "Multisig proof should verify"
    );
}

// =====================================================================
// Test 8: Threshold key serialization roundtrip
// =====================================================================

#[test]
fn test_threshold_keys_serialization() {
    let (keys, _) = threshold_keys_2of3();

    for (participant, key) in &keys {
        // Serialize
        let serialized = key.serialize();

        // Deserialize
        let core = ThresholdCore::<Ed25519T>::read::<&[u8]>(&mut serialized.as_ref())
            .expect("deserialization must succeed");
        let recovered = ThresholdKeys::new(core);

        // Verify consistency
        assert_eq!(recovered.group_key(), key.group_key());
        assert_eq!(recovered.params().t(), 2);
        assert_eq!(recovered.params().n(), 3);
        assert_eq!(recovered.params().i(), *participant);
    }
}

// =====================================================================
// PHASE 2b: Negative tests — proving rejection
// =====================================================================

/// Test 9: A single signer (1-of-3) cannot meet the threshold.
///
/// The FROST protocol MUST reject signing sets below the threshold `t`.
/// This is critical for escrow security — a single dishonest party
/// cannot unilaterally spend funds.
#[test]
fn test_1of3_below_threshold_fails() {
    use ciphersuite::group::ff::Field;

    let (mut keys, _) = threshold_keys_2of3();
    let x = Scalar::random(&mut OsRng);

    let group_key = keys.values().next().unwrap().group_key();
    let (rerandomized, _key_image, tx_hash) = create_test_output(&x, group_key);

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Below Threshold Test"),
        tx_hash,
        rerandomized.clone(),
        x,
    );

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let p1 = Participant::new(1).unwrap();

    // Single signer creates machine and preprocesses
    let machine = AlgorithmMachine::new(algorithm, keys[&p1].clone());
    let (sign_machine, _preprocess) = machine.preprocess(&mut OsRng);

    // Attempt to sign with empty preprocesses (only self = 1 signer < threshold 2)
    let result = sign_machine.sign(HashMap::new(), &[]);
    match result {
        Err(FrostError::InvalidSigningSet(_)) => {} // Expected
        Err(e) => panic!("Expected InvalidSigningSet, got: {e}"),
        Ok(_) => panic!("1-of-3 signing must fail (below threshold)"),
    }
}

/// Test 10: Verification with wrong tx_hash must fail.
///
/// The SA+L proof is bound to the transaction hash. Verifying against
/// a different hash proves the proof is non-transferable.
#[test]
fn test_wrong_tx_hash_verification_fails() {
    use ciphersuite::group::ff::Field;

    let x = Scalar::random(&mut OsRng);
    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    let o_key = (EdwardsPoint::generator() * x) + keys.values().next().unwrap().group_key();
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);
    let key_image = i_base * x;

    let sign_hash = [0xAA; 32];
    let wrong_hash = [0xBB; 32];

    let rerandomized = RerandomizedOutput::new(
        &mut OsRng,
        Output::new(o_key, i_base, c_point).unwrap(),
    );
    let input = rerandomized.input();

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Wrong Hash Test"),
        sign_hash,
        rerandomized.clone(),
        x,
    );

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let sig = sign(
        &mut OsRng,
        &algorithm,
        keys.clone(),
        algorithm_machines(&mut OsRng, &algorithm, &keys),
        &[],
    );

    // Verify with WRONG tx_hash — must fail
    let mut verifier = BatchVerifier::new(1);
    sig.verify(&mut OsRng, &mut verifier, wrong_hash, &input, key_image);
    assert!(
        !verifier.verify_vartime(),
        "Verification with wrong tx_hash must fail"
    );

    // Sanity: correct tx_hash succeeds
    let mut verifier = BatchVerifier::new(1);
    sig.verify(&mut OsRng, &mut verifier, sign_hash, &input, key_image);
    assert!(
        verifier.verify_vartime(),
        "Verification with correct tx_hash must succeed"
    );
}

/// Test 11: Verification with wrong key image must fail.
///
/// The key image binds spend authorization to linkability.
/// A wrong key image means either double-spend or forgery.
#[test]
fn test_wrong_key_image_verification_fails() {
    use ciphersuite::group::ff::Field;

    let x = Scalar::random(&mut OsRng);
    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    let o_key = (EdwardsPoint::generator() * x) + keys.values().next().unwrap().group_key();
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);
    let key_image = i_base * x;
    let wrong_ki = EdwardsPoint::random(&mut OsRng);

    let rerandomized = RerandomizedOutput::new(
        &mut OsRng,
        Output::new(o_key, i_base, c_point).unwrap(),
    );
    let input = rerandomized.input();

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Wrong KI Test"),
        [0u8; 32],
        rerandomized.clone(),
        x,
    );

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let sig = sign(
        &mut OsRng,
        &algorithm,
        keys.clone(),
        algorithm_machines(&mut OsRng, &algorithm, &keys),
        &[],
    );

    // Verify with WRONG key image — must fail
    let mut verifier = BatchVerifier::new(1);
    sig.verify(&mut OsRng, &mut verifier, [0u8; 32], &input, wrong_ki);
    assert!(
        !verifier.verify_vartime(),
        "Verification with wrong key image must fail"
    );

    // Sanity: correct key image succeeds
    let mut verifier = BatchVerifier::new(1);
    sig.verify(&mut OsRng, &mut verifier, [0u8; 32], &input, key_image);
    assert!(
        verifier.verify_vartime(),
        "Verification with correct key image must succeed"
    );
}

// =====================================================================
// PHASE 2b: Adversarial tests — malicious signer identification
// =====================================================================

/// Test 12: Corrupted signature share triggers identifiable abort.
///
/// A malicious signer submits a corrupted share. The FROST `complete()`
/// method MUST identify the exact faulty participant via batch verification
/// blame. This is the cryptographic foundation for escrow dispute resolution.
#[test]
fn test_corrupted_share_blame_identification() {
    use ciphersuite::group::ff::Field;

    let x = Scalar::random(&mut OsRng);
    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    let o_key = (EdwardsPoint::generator() * x) + keys.values().next().unwrap().group_key();
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);

    let rerandomized = RerandomizedOutput::new(
        &mut OsRng,
        Output::new(o_key, i_base, c_point).unwrap(),
    );

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Blame Test"),
        [0u8; 32],
        rerandomized.clone(),
        x,
    );

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    // Manually execute the FROST protocol to intercept shares
    // (preprocess_and_shares is pub(crate) in vendor, so we inline it)

    // Collect all signers
    let signers: Vec<Participant> = keys.keys().copied().collect();
    let faulty = signers[0]; // First signer is the malicious party

    // Create machines for all signers
    let mut machines: HashMap<Participant, _> = signers
        .iter()
        .map(|&s| (s, AlgorithmMachine::new(algorithm.clone(), keys[&s].clone())))
        .collect();

    // Round 1: Preprocess
    let mut sign_machines = HashMap::new();
    let mut preprocesses = HashMap::new();
    for (i, machine) in machines.drain() {
        let (sign_machine, preprocess) = machine.preprocess(&mut OsRng);
        let mut buf = vec![];
        preprocess.write(&mut buf).unwrap();
        let parsed = sign_machine
            .read_preprocess::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        preprocesses.insert(i, parsed);
        sign_machines.insert(i, sign_machine);
    }

    // Round 2: Sign
    let mut sig_machines = HashMap::new();
    let mut shares = HashMap::new();
    for (i, machine) in sign_machines.drain() {
        let others: HashMap<_, _> = preprocesses
            .iter()
            .filter(|(p, _)| **p != i)
            .map(|(p, pp)| (*p, pp.clone()))
            .collect();
        let (sig_machine, share) = machine.sign(others, &[]).unwrap();
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        let parsed = sig_machine
            .read_share::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        shares.insert(i, parsed);
        sig_machines.insert(i, sig_machine);
    }

    // Corrupt the faulty signer's share via serialize → flip bit → deserialize
    let valid_share = shares.remove(&faulty).unwrap();
    let mut buf = vec![];
    valid_share.write(&mut buf).unwrap();
    buf[0] ^= 0x01; // Flip LSB — produces a valid but incorrect scalar

    // Use any sig_machine to deserialize the corrupted bytes
    let corrupted = sig_machines
        .values()
        .next()
        .unwrap()
        .read_share::<&[u8]>(&mut buf.as_ref())
        .unwrap();
    shares.insert(faulty, corrupted);

    // Every honest signer must identify the faulty participant
    for (i, machine) in sig_machines {
        if i == faulty {
            continue; // Faulty signer's own internal share is valid
        }
        let my_shares = clone_without(&shares, &i);
        let result = machine.complete(my_shares);
        match result {
            Err(FrostError::InvalidShare(blamed)) => {
                assert_eq!(
                    blamed, faulty,
                    "Blame must identify the exact faulty participant"
                );
            }
            Err(e) => panic!("Expected InvalidShare({faulty}), got: {e}"),
            Ok(_) => panic!("Honest signer {i} must detect corrupted share"),
        }
    }
}

// =====================================================================
// PHASE 2b: Full FROST DKG — production path proof
// =====================================================================

/// Test 13: Full FROST DKG (t=2, n=3) → SA+L sign → verify.
///
/// Unlike the Shamir serialization bypass used in other tests, this runs
/// the actual FROST Distributed Key Generation protocol with encrypted
/// share transport — the exact production code path for Onyx EaaS.
#[test]
fn test_full_frost_dkg_2of3_then_sign() {
    use ciphersuite::group::ff::Field;

    let t: u16 = 2;
    let n: u16 = 3;
    let context = "Onyx FCMP++ 2-of-3 DKG".to_string();

    // === DKG Round 1: Generate commitments ===
    let participants: Vec<Participant> = (1..=n)
        .map(|i| Participant::new(i).unwrap())
        .collect();

    let mut secret_machines = HashMap::new();
    let mut commitment_msgs = HashMap::new();

    for &p in &participants {
        let params = ThresholdParams::new(t, n, p).unwrap();
        let machine = KeyGenMachine::<Ed25519T>::new(params, context.clone());
        let (machine, msg) = machine.generate_coefficients(&mut OsRng);
        secret_machines.insert(p, machine);
        commitment_msgs.insert(p, msg);
    }

    // === DKG Round 2: Generate and distribute encrypted secret shares ===
    let mut key_machines = HashMap::new();
    let mut all_shares = HashMap::new();

    for &p in &participants {
        let machine = secret_machines.remove(&p).unwrap();
        let others = clone_without(&commitment_msgs, &p);
        let (key_machine, shares) = machine
            .generate_secret_shares(&mut OsRng, others)
            .expect("DKG round 2 must succeed");
        key_machines.insert(p, key_machine);
        all_shares.insert(p, shares);
    }

    // === DKG Round 3: Calculate final key shares ===
    let mut threshold_keys: HashMap<Participant, ThresholdKeys<Ed25519T>> = HashMap::new();

    for &p in &participants {
        let machine = key_machines.remove(&p).unwrap();

        // Collect shares sent TO this participant from all others
        let mut my_shares = HashMap::new();
        for &sender in &participants {
            if sender != p {
                my_shares.insert(sender, all_shares[&sender][&p].clone());
            }
        }

        let core = machine
            .calculate_share(&mut OsRng, my_shares)
            .expect("DKG round 3 must succeed")
            .complete();
        threshold_keys.insert(p, ThresholdKeys::new(core));
    }

    // === Verify DKG results ===
    let group_key = threshold_keys.values().next().unwrap().group_key();
    for k in threshold_keys.values() {
        assert_eq!(
            k.group_key(),
            group_key,
            "All parties must agree on group key"
        );
        assert_eq!(k.params().t(), t);
        assert_eq!(k.params().n(), n);
    }

    // === Sign SA+L proof with DKG-derived keys ===
    let x = Scalar::random(&mut OsRng);
    let o_key = (EdwardsPoint::generator() * x) + group_key;
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);
    let key_image = i_base * x;

    let output = Output::new(o_key, i_base, c_point).unwrap();
    let rerandomized = RerandomizedOutput::new(&mut OsRng, output);
    let input = rerandomized.input();

    let tx_hash = {
        let mut h = [0u8; 32];
        OsRng.fill_bytes(&mut h);
        h
    };

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Onyx DKG-to-Sign Test"),
        tx_hash,
        rerandomized.clone(),
        x,
    );

    for keys in threshold_keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    // Sign with participants 1 and 3 (buyer + arbiter — dispute scenario)
    let p1 = Participant::new(1).unwrap();
    let p3 = Participant::new(3).unwrap();
    let sig = frost_sign_2of2(&algorithm, &threshold_keys, [p1, p3]);

    // Verify the proof
    let mut verifier = BatchVerifier::new(1);
    sig.verify(&mut OsRng, &mut verifier, tx_hash, &input, key_image);
    assert!(
        verifier.verify_vartime(),
        "DKG-derived keys must produce valid SA+L proof"
    );

    // Also verify through Onyx wrapper
    verify_sal_single(&mut OsRng, &sig, tx_hash, &input, key_image)
        .expect("DKG keys → Onyx verify_sal_single must succeed");
}

// =====================================================================
// PHASE 2b: Determinism and edge cases
// =====================================================================

/// Test 14: Repeated signing with same inputs always verifies.
///
/// Runs the full signing pipeline multiple times with different random
/// nonces. Every proof must verify, demonstrating robustness against
/// edge cases in randomized nonce generation.
#[test]
fn test_repeated_signing_always_verifies() {
    use ciphersuite::group::ff::Field;

    let x = Scalar::random(&mut OsRng);
    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    let group_key = keys.values().next().unwrap().group_key();
    let o_key = (EdwardsPoint::generator() * x) + group_key;
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);
    let key_image = i_base * x;

    let rerandomized = RerandomizedOutput::new(
        &mut OsRng,
        Output::new(o_key, i_base, c_point).unwrap(),
    );
    let input = rerandomized.input();

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    // Sign 10 times with different nonces — each must verify
    for round in 0..10 {
        let algorithm = SalAlgorithm::new(
            OsRng,
            RecommendedTranscript::new(b"Robustness Test"),
            [0u8; 32],
            rerandomized.clone(),
            x,
        );

        let machines = algorithm_machines(&mut OsRng, &algorithm, &keys);
        let sig = sign(
            &mut OsRng,
            &algorithm,
            keys.clone(),
            machines,
            &[],
        );

        let mut verifier = BatchVerifier::new(1);
        sig.verify(&mut OsRng, &mut verifier, [0u8; 32], &input, key_image);
        assert!(
            verifier.verify_vartime(),
            "Round {round}: SA+L proof must verify regardless of nonces"
        );
    }
}

/// Test 15: Scalar above field order is rejected.
///
/// bytes_to_scalar must reject byte sequences that represent values
/// >= the ed25519 scalar field order l.
#[test]
fn test_scalar_above_order_rejected() {
    // All 0xFF bytes = 2^256 - 1, far above the scalar field order
    let above_order = [0xFF; 32];
    assert!(
        bytes_to_scalar(&above_order).is_err(),
        "Scalar above field order must be rejected"
    );

    // The ed25519 scalar field order l in little-endian:
    // l = 2^252 + 27742317777372353535851937790883648493
    let order_le: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
        0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10,
    ];
    assert!(
        bytes_to_scalar(&order_le).is_err(),
        "Scalar equal to field order must be rejected"
    );

    // l + 1 must also be rejected
    let mut order_plus_one = order_le;
    order_plus_one[0] = 0xee; // l + 1 in LE
    assert!(
        bytes_to_scalar(&order_plus_one).is_err(),
        "Scalar l+1 must be rejected"
    );
}

/// Test 16: Invalid point encodings are rejected.
///
/// bytes_to_point must reject byte sequences that do not correspond to
/// valid compressed Ed25519 points.
#[test]
fn test_invalid_point_encoding_rejected() {
    // All 0xFF bytes — y-coordinate exceeds field prime
    let invalid_ff = [0xFF; 32];
    assert!(
        bytes_to_point(&invalid_ff).is_err(),
        "All-0xFF bytes must be rejected (y >= p)"
    );

    // All zeros — check if this is a valid point (y=0)
    // Whether this passes depends on whether y=0 is on the curve;
    // the important thing is bytes_to_point doesn't panic
    let zero_bytes = [0u8; 32];
    let _ = bytes_to_point(&zero_bytes); // Must not panic

    // Random garbage that almost certainly isn't a valid point
    let mut garbage = [0u8; 32];
    garbage[0] = 0xDE;
    garbage[1] = 0xAD;
    garbage[31] = 0x80; // Set sign bit but invalid y
    // This may or may not be valid — just verify no panic
    let _ = bytes_to_point(&garbage);
}

/// Test 17: Wrong offset key causes FROST internal abort.
///
/// The FROST keys MUST be offset by `-o_blind` before signing with
/// SalAlgorithm. Signing with the wrong offset causes the SA+L internal
/// verification to fail at the `complete()` step — individual shares are
/// valid but the aggregate proof is inconsistent with the RerandomizedOutput.
/// This returns `FrostError::InternalError`, proving the protocol is
/// self-checking even before external verification.
#[test]
fn test_wrong_offset_causes_internal_abort() {
    use ciphersuite::group::ff::Field;

    let (mut keys, _) = threshold_keys_2of3();
    let x = Scalar::random(&mut OsRng);

    let group_key = keys.values().next().unwrap().group_key();
    let (rerandomized, _key_image, tx_hash) = create_test_output(&x, group_key);

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Wrong Offset Test"),
        tx_hash,
        rerandomized.clone(),
        x,
    );

    // Deliberately apply WRONG offset (positive instead of negative)
    for keys in keys.values_mut() {
        *keys = keys.offset(rerandomized.o_blind()); // Wrong! Should be -o_blind
    }

    let p1 = Participant::new(1).unwrap();
    let p2 = Participant::new(2).unwrap();

    // Manually execute FROST to capture the error from complete()
    let mut machines: Vec<(Participant, _)> = [p1, p2]
        .iter()
        .map(|&s| (s, AlgorithmMachine::new(algorithm.clone(), keys[&s].clone())))
        .collect();

    // Round 1: Preprocess
    let mut sign_machines = Vec::new();
    let mut preprocesses = HashMap::new();
    for (i, machine) in machines.drain(..) {
        let (sign_machine, preprocess) = machine.preprocess(&mut OsRng);
        let mut buf = vec![];
        preprocess.write(&mut buf).unwrap();
        let parsed = sign_machine
            .read_preprocess::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        preprocesses.insert(i, parsed);
        sign_machines.push((i, sign_machine));
    }

    // Round 2: Sign
    let mut sig_machines = Vec::new();
    let mut shares = HashMap::new();
    for (i, machine) in sign_machines.drain(..) {
        let others: HashMap<_, _> = preprocesses
            .iter()
            .filter(|(p, _)| **p != i)
            .map(|(p, pp)| (*p, pp.clone()))
            .collect();
        let (sig_machine, share) = machine.sign(others, &[]).unwrap();
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        let parsed = sig_machine
            .read_share::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        shares.insert(i, parsed);
        sig_machines.push((i, sig_machine));
    }

    // Complete: Each signer should get InternalError (shares valid, aggregate invalid)
    for (i, machine) in sig_machines.drain(..) {
        let others: HashMap<_, _> = shares
            .iter()
            .filter(|(p, _)| **p != i)
            .map(|(p, s)| (*p, s.clone()))
            .collect();
        match machine.complete(others) {
            Err(FrostError::InternalError(_)) => {} // Expected: self-checking abort
            Err(e) => panic!("Expected InternalError for wrong offset, got: {e}"),
            Ok(_) => panic!("Wrong offset must not produce a valid proof"),
        }
    }
}

/// Test 18: Wrong x secret causes FROST internal abort.
///
/// The SA+L proof binds to both secrets (x, y). Using the wrong x
/// while the output was constructed with the correct x causes the SA+L
/// internal verification to reject the aggregate proof.
#[test]
fn test_wrong_x_secret_causes_internal_abort() {
    use ciphersuite::group::ff::Field;

    let x = Scalar::random(&mut OsRng);
    let wrong_x = Scalar::random(&mut OsRng);

    let (mut keys, _) = threshold_keys_2of3();
    let group_key = keys.values().next().unwrap().group_key();

    // Output uses correct x
    let o_key = (EdwardsPoint::generator() * x) + group_key;
    let i_base = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);

    let rerandomized = RerandomizedOutput::new(
        &mut OsRng,
        Output::new(o_key, i_base, c_point).unwrap(),
    );

    // Sign with WRONG x
    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"Wrong x Test"),
        [0u8; 32],
        rerandomized.clone(),
        wrong_x, // <-- wrong
    );

    for keys in keys.values_mut() {
        *keys = keys.offset(-rerandomized.o_blind());
    }

    let p1 = Participant::new(1).unwrap();
    let p2 = Participant::new(2).unwrap();

    // Manual FROST to capture error
    let mut machines: Vec<(Participant, _)> = [p1, p2]
        .iter()
        .map(|&s| (s, AlgorithmMachine::new(algorithm.clone(), keys[&s].clone())))
        .collect();

    let mut sign_machines = Vec::new();
    let mut preprocesses = HashMap::new();
    for (i, machine) in machines.drain(..) {
        let (sign_machine, preprocess) = machine.preprocess(&mut OsRng);
        let mut buf = vec![];
        preprocess.write(&mut buf).unwrap();
        let parsed = sign_machine
            .read_preprocess::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        preprocesses.insert(i, parsed);
        sign_machines.push((i, sign_machine));
    }

    let mut sig_machines = Vec::new();
    let mut shares = HashMap::new();
    for (i, machine) in sign_machines.drain(..) {
        let others: HashMap<_, _> = preprocesses
            .iter()
            .filter(|(p, _)| **p != i)
            .map(|(p, pp)| (*p, pp.clone()))
            .collect();
        let (sig_machine, share) = machine.sign(others, &[]).unwrap();
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        let parsed = sig_machine
            .read_share::<&[u8]>(&mut buf.as_ref())
            .unwrap();
        shares.insert(i, parsed);
        sig_machines.push((i, sig_machine));
    }

    for (i, machine) in sig_machines.drain(..) {
        let others: HashMap<_, _> = shares
            .iter()
            .filter(|(p, _)| **p != i)
            .map(|(p, s)| (*p, s.clone()))
            .collect();
        match machine.complete(others) {
            Err(FrostError::InternalError(_)) => {} // Expected
            Err(e) => panic!("Expected InternalError for wrong x, got: {e}"),
            Ok(_) => panic!("Wrong x secret must not produce a valid proof"),
        }
    }
}
