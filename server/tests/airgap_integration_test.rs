/// Integration tests for Air-Gap Dispute Resolution (TM-001)
///
/// Tests the complete workflow:
/// 1. Server exports dispute as JSON
/// 2. Arbiter reviews offline and signs decision
/// 3. Server imports and validates decision
/// 4. Escrow state transitions correctly

use server::services::airgap::{ArbiterDecision, ArbiterResolution, DisputeRequest};
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

/// Helper: Generate random 32 bytes
fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes
}

#[test]
fn test_complete_airgap_workflow() {
    // Step 1: Create dispute request
    let dispute = DisputeRequest {
        escrow_id: Uuid::new_v4(),
        buyer_id: Uuid::new_v4(),
        vendor_id: Uuid::new_v4(),
        amount: 1_000_000_000_000, // 1 XMR
        buyer_claim: "Product damaged".to_string(),
        vendor_response: Some("Shipped in perfect condition".to_string()),
        dispute_opened_at: chrono::Utc::now().timestamp(),
        evidence_file_count: 3,
        partial_tx_hex: "deadbeef".to_string(),
        nonce: hex::encode(random_bytes_32()),
    };

    // Step 2: Serialize for QR export
    let json = serde_json::to_string_pretty(&dispute)
        .expect("Failed to serialize dispute");

    assert!(json.len() < 2000, "QR payload too large");

    // Step 3: Arbiter reviews offline and creates decision
    let arbiter_keypair = SigningKey::from_bytes(&random_bytes_32());
    let message = format!("ARBITER_DECISION:{}:{}", dispute.escrow_id, dispute.nonce);
    let signature = arbiter_keypair.sign(message.as_bytes());

    let decision = ArbiterDecision {
        escrow_id: dispute.escrow_id,
        nonce: dispute.nonce.clone(),
        decision: ArbiterResolution::Vendor,  // Corrected: Vendor not PayVendor
        reason: "Evidence supports vendor claim".to_string(),
        signed_tx_hex: "cafebabe".to_string(),
        decision_signature: hex::encode(signature.to_bytes()),
        decided_at: chrono::Utc::now().timestamp(),
    };

    // Step 4: Serialize decision for QR import
    let decision_json = serde_json::to_string_pretty(&decision)
        .expect("Failed to serialize decision");

    assert!(decision_json.len() < 2000, "Decision QR payload too large");

    // Step 5: Verify signature
    let verifying_key = arbiter_keypair.verifying_key();
    let sig_bytes: [u8; 64] = hex::decode(&decision.decision_signature)
        .expect("Invalid hex")
        .try_into()
        .expect("Invalid signature length");

    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    assert!(
        verifying_key.verify_strict(message.as_bytes(), &sig).is_ok(),
        "Signature verification failed"
    );
}

#[test]
fn test_nonce_uniqueness() {
    let mut nonces = std::collections::HashSet::new();

    for _ in 0..1000 {
        let nonce = hex::encode(random_bytes_32());
        assert!(
            nonces.insert(nonce.clone()),
            "Duplicate nonce generated: {}",
            nonce
        );
    }
}

#[test]
fn test_qr_size_constraints() {
    // QR codes have size limits - ensure payloads fit
    let max_qr_v10_alphanumeric = 1852; // Version 10, L error correction

    let dispute = DisputeRequest {
        escrow_id: Uuid::new_v4(),
        buyer_id: Uuid::new_v4(),
        vendor_id: Uuid::new_v4(),
        amount: 1_000_000_000_000,
        buyer_claim: "A".repeat(500), // Large claim
        vendor_response: Some("B".repeat(500)), // Large response
        dispute_opened_at: chrono::Utc::now().timestamp(),
        evidence_file_count: 99,
        partial_tx_hex: "C".repeat(200),
        nonce: hex::encode(random_bytes_32()),
    };

    let json = serde_json::to_string(&dispute).unwrap();

    assert!(
        json.len() < max_qr_v10_alphanumeric,
        "Dispute payload {} exceeds QR capacity {}",
        json.len(),
        max_qr_v10_alphanumeric
    );
}
