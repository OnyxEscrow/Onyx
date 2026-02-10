use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use reputation_common::types::{SignedReview, ReputationStats};
use chrono::Utc;

/// Génère une signature cryptographique pour un avis
///
/// # Arguments
/// * `txid` - Transaction hash Monero
/// * `rating` - Note 1-5
/// * `comment` - Commentaire optionnel
/// * `buyer_signing_key` - Clé de signature ed25519 de l'acheteur
///
/// # Returns
/// * `SignedReview` - Avis avec signature cryptographique
///
/// # Exemple
/// ```no_run
/// use ed25519_dalek::SigningKey;
/// use rand::{RngCore, rngs::OsRng};
/// use reputation_crypto::reputation::sign_review;
///
/// let mut csprng = OsRng;
/// let mut secret_bytes = [0u8; 32];
/// csprng.fill_bytes(&mut secret_bytes);
/// let signing_key = SigningKey::from_bytes(&secret_bytes);
/// let review = sign_review(
///     "abc123".to_string(),
///     5,
///     Some("Great!".to_string()),
///     &signing_key,
/// ).unwrap();
/// ```
pub fn sign_review(
    txid: String,
    rating: u8,
    comment: Option<String>,
    buyer_signing_key: &SigningKey,
) -> Result<SignedReview> {
    // Validate rating
    if !(1..=5).contains(&rating) {
        return Err(anyhow::anyhow!("Rating must be between 1 and 5"));
    }

    let timestamp = Utc::now();

    // 1. Construire le message à signer (format canonique)
    let message = format!(
        "{}|{}|{}|{}",
        txid,
        rating,
        comment.as_deref().unwrap_or(""),
        timestamp.to_rfc3339()
    );

    // 2. Hash du message (SHA-256)
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let message_hash = hasher.finalize();

    // 3. Signer avec clé privée acheteur
    let signature = buyer_signing_key.sign(&message_hash);

    // 4. Encoder en base64
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let verifying_key = buyer_signing_key.verifying_key();
    let buyer_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes());

    Ok(SignedReview {
        txid,
        rating,
        comment,
        timestamp,
        buyer_pubkey: buyer_pubkey_b64,
        signature: signature_b64,
    })
}

/// Vérifie la signature cryptographique d'un avis
///
/// # Arguments
/// * `review` - Avis à vérifier
///
/// # Returns
/// * `bool` - true si signature valide, false sinon
///
/// # Exemple
/// ```ignore
/// // Example requires a SignedReview instance
/// use reputation_crypto::reputation::verify_review_signature;
///
/// let is_valid = verify_review_signature(&review).unwrap();
/// if is_valid {
///     println!("Signature valide!");
/// }
/// ```
pub fn verify_review_signature(review: &SignedReview) -> Result<bool> {
    // 1. Décoder la clé publique
    let pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(&review.buyer_pubkey)
        .context("Invalid base64 in buyer_pubkey")?;

    if pubkey_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid public key length: expected 32 bytes"));
    }

    let mut pubkey_array = [0u8; 32];
    pubkey_array.copy_from_slice(&pubkey_bytes);

    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .context("Invalid ed25519 public key")?;

    // 2. Décoder la signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&review.signature)
        .context("Invalid base64 in signature")?;

    if sig_bytes.len() != 64 {
        return Err(anyhow::anyhow!("Invalid signature length: expected 64 bytes"));
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);

    let signature = Signature::from_bytes(&sig_array);

    // 3. Reconstruire le message original
    let message = format!(
        "{}|{}|{}|{}",
        review.txid,
        review.rating,
        review.comment.as_deref().unwrap_or(""),
        review.timestamp.to_rfc3339()
    );

    // 4. Hash du message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let message_hash = hasher.finalize();

    // 5. Vérifier la signature
    Ok(verifying_key.verify(&message_hash, &signature).is_ok())
}

/// Calcule les statistiques d'une liste d'avis
///
/// # Arguments
/// * `reviews` - Liste d'avis signés
///
/// # Returns
/// * `ReputationStats` - Statistiques calculées
///
/// Note: This function sets completed_transactions, shield_score and trust_level
/// to defaults. Use `calculate_stats_full` for complete stats with transaction data.
pub fn calculate_stats(reviews: &[SignedReview]) -> ReputationStats {
    calculate_stats_full(reviews, 0)
}

/// Calcule les statistiques complètes incluant Shield Score V2
///
/// # Arguments
/// * `reviews` - Liste d'avis signés
/// * `completed_transactions` - Nombre de transactions complétées (from escrows table)
///
/// # Returns
/// * `ReputationStats` - Statistiques calculées avec Shield Score
///
/// # Shield Score V2 Formula
/// - 40% transaction volume (min(completed_tx / 100, 1) × 100)
/// - 30% review quality (avg_rating / 5 × 100)
/// - 30% review volume (min(total_reviews / 50, 1) × 100)
pub fn calculate_stats_full(reviews: &[SignedReview], completed_transactions: u32) -> ReputationStats {
    if reviews.is_empty() {
        let now = Utc::now();

        // Calculate shield score even with no reviews (transaction volume still counts)
        let tx_component = ((completed_transactions as f64 / 100.0).min(1.0)) * 100.0;
        let shield_score = (0.40 * tx_component) as u32;
        let trust_level = get_trust_level(shield_score);

        return ReputationStats {
            total_reviews: 0,
            average_rating: 0.0,
            rating_distribution: [0; 5],
            oldest_review: now,
            newest_review: now,
            completed_transactions,
            shield_score,
            trust_level: trust_level.to_string(),
        };
    }

    let mut rating_dist = [0u32; 5];
    let mut total_rating = 0u32;

    let mut oldest = reviews[0].timestamp;
    let mut newest = reviews[0].timestamp;

    for review in reviews {
        // Distribution
        let idx = (review.rating - 1) as usize;
        rating_dist[idx] += 1;
        total_rating += review.rating as u32;

        // Min/Max dates
        if review.timestamp < oldest {
            oldest = review.timestamp;
        }
        if review.timestamp > newest {
            newest = review.timestamp;
        }
    }

    let avg = total_rating as f32 / reviews.len() as f32;
    let total_reviews = reviews.len() as u32;

    // Calculate Shield Score V2
    let review_quality = (avg as f64 / 5.0) * 100.0;
    let review_volume = ((total_reviews as f64 / 50.0).min(1.0)) * 100.0;
    let tx_volume = ((completed_transactions as f64 / 100.0).min(1.0)) * 100.0;

    let shield_score = ((0.30 * review_quality) + (0.30 * review_volume) + (0.40 * tx_volume)).round() as u32;
    let trust_level = get_trust_level(shield_score);

    ReputationStats {
        total_reviews,
        average_rating: avg,
        rating_distribution: rating_dist,
        oldest_review: oldest,
        newest_review: newest,
        completed_transactions,
        shield_score,
        trust_level: trust_level.to_string(),
    }
}

/// Determine trust level from shield score
fn get_trust_level(shield_score: u32) -> &'static str {
    match shield_score {
        90..=100 => "platinum",
        70..=89 => "gold",
        40..=69 => "silver",
        _ => "bronze",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_and_verify_review() {
        // Générer clé acheteur
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // Créer avis signé
        let review = sign_review(
            "abc123def456".to_string(),
            5,
            Some("Excellent product!".to_string()),
            &signing_key,
        )
        .unwrap();

        // Vérifier signature
        assert!(verify_review_signature(&review).unwrap());
    }

    #[test]
    fn test_tampered_review_fails_verification() {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        let review = sign_review(
            "abc123".to_string(),
            5,
            Some("Great!".to_string()),
            &signing_key,
        )
        .unwrap();

        // Modifier le rating (altération)
        let mut tampered = review.clone();
        tampered.rating = 1;

        // Vérification doit échouer
        assert!(!verify_review_signature(&tampered).unwrap());
    }

    #[test]
    fn test_invalid_rating_rejected() {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        let result = sign_review(
            "abc".to_string(),
            6,  // Invalid rating
            None,
            &signing_key,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_stats() {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        let review1 = sign_review("tx1".to_string(), 5, None, &signing_key).unwrap();
        let review2 = sign_review("tx2".to_string(), 4, None, &signing_key).unwrap();
        let review3 = sign_review("tx3".to_string(), 5, None, &signing_key).unwrap();

        let reviews = vec![review1, review2, review3];
        let stats = calculate_stats(&reviews);

        assert_eq!(stats.total_reviews, 3);
        assert!((stats.average_rating - 4.666667).abs() < 0.001);  // (5+4+5)/3
        assert_eq!(stats.rating_distribution[3], 1);  // 1x 4★
        assert_eq!(stats.rating_distribution[4], 2);  // 2x 5★
        assert_eq!(stats.completed_transactions, 0);  // Default
        assert_eq!(stats.trust_level, "bronze");  // Low shield score without TX
    }

    #[test]
    fn test_empty_reviews_stats() {
        let stats = calculate_stats(&[]);

        assert_eq!(stats.total_reviews, 0);
        assert_eq!(stats.average_rating, 0.0);
        assert_eq!(stats.shield_score, 0);
        assert_eq!(stats.trust_level, "bronze");
    }

    #[test]
    fn test_calculate_stats_full_with_transactions() {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // Create 50 reviews with 5-star ratings
        let mut reviews = Vec::new();
        for i in 0..50 {
            let review = sign_review(format!("tx{}", i), 5, None, &signing_key).unwrap();
            reviews.push(review);
        }

        // 100 completed transactions
        let stats = calculate_stats_full(&reviews, 100);

        assert_eq!(stats.total_reviews, 50);
        assert!((stats.average_rating - 5.0).abs() < 0.001);
        assert_eq!(stats.completed_transactions, 100);

        // Expected shield score:
        // 30% * (5/5 * 100) = 30
        // 30% * (50/50 * 100) = 30
        // 40% * (100/100 * 100) = 40
        // Total = 100 (platinum)
        assert_eq!(stats.shield_score, 100);
        assert_eq!(stats.trust_level, "platinum");
    }

    #[test]
    fn test_shield_score_partial() {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // 10 reviews with 4-star average
        let mut reviews = Vec::new();
        for i in 0..10 {
            let review = sign_review(format!("tx{}", i), 4, None, &signing_key).unwrap();
            reviews.push(review);
        }

        // 50 completed transactions
        let stats = calculate_stats_full(&reviews, 50);

        // Expected shield score:
        // 30% * (4/5 * 100) = 30% * 80 = 24
        // 30% * (10/50 * 100) = 30% * 20 = 6
        // 40% * (50/100 * 100) = 40% * 50 = 20
        // Total = 50 (silver)
        assert_eq!(stats.shield_score, 50);
        assert_eq!(stats.trust_level, "silver");
    }

    #[test]
    fn test_get_trust_level() {
        assert_eq!(get_trust_level(0), "bronze");
        assert_eq!(get_trust_level(39), "bronze");
        assert_eq!(get_trust_level(40), "silver");
        assert_eq!(get_trust_level(69), "silver");
        assert_eq!(get_trust_level(70), "gold");
        assert_eq!(get_trust_level(89), "gold");
        assert_eq!(get_trust_level(90), "platinum");
        assert_eq!(get_trust_level(100), "platinum");
    }
}
