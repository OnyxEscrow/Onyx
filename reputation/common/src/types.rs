use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Avis signé cryptographiquement par un acheteur
///
/// Chaque avis est une preuve vérifiable qu'une transaction réelle
/// a eu lieu et que l'acheteur a émis cet avis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReview {
    /// Transaction hash Monero (preuve on-chain)
    pub txid: String,

    /// Rating 1-5 étoiles
    #[serde(deserialize_with = "validate_rating")]
    pub rating: u8,

    /// Commentaire optionnel (max 500 chars)
    pub comment: Option<String>,

    /// Timestamp de création de l'avis
    pub timestamp: DateTime<Utc>,

    /// Clé publique de l'acheteur (ed25519, base64)
    pub buyer_pubkey: String,

    /// Signature cryptographique de l'avis
    /// Signature = sign(sha256(txid || rating || comment || timestamp))
    pub signature: String,
}

/// Fichier de réputation complet d'un vendeur
///
/// C'est le fichier portable qui peut être exporté vers IPFS
/// et importé sur n'importe quelle marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorReputation {
    /// Version du format (pour compatibilité future)
    pub format_version: String, // "1.0"

    /// Clé publique du vendeur
    pub vendor_pubkey: String,

    /// Date de génération du fichier
    pub generated_at: DateTime<Utc>,

    /// Liste de tous les avis signés
    pub reviews: Vec<SignedReview>,

    /// Statistiques pré-calculées
    pub stats: ReputationStats,
}

/// Statistiques de réputation pré-calculées
///
/// Ces stats sont calculées côté serveur pour performance,
/// mais peuvent être recalculées côté client pour vérification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationStats {
    /// Nombre total d'avis
    pub total_reviews: u32,

    /// Note moyenne (0.0 à 5.0)
    pub average_rating: f32,

    /// Distribution des notes [1★, 2★, 3★, 4★, 5★]
    pub rating_distribution: [u32; 5],

    /// Date du plus ancien avis
    pub oldest_review: DateTime<Utc>,

    /// Date du plus récent avis
    pub newest_review: DateTime<Utc>,

    /// Nombre de transactions complétées (nouveau v1.1)
    /// Cette métrique est objective et basée sur les preuves on-chain
    #[serde(default)]
    pub completed_transactions: u32,

    /// Shield Score V2 (0-100)
    /// Formule: 40% TX volume + 30% review quality + 30% review volume
    #[serde(default)]
    pub shield_score: u32,

    /// Trust level derived from shield_score
    /// Values: "bronze" (0-39), "silver" (40-69), "gold" (70-89), "platinum" (90-100)
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
}

fn default_trust_level() -> String {
    "bronze".to_string()
}

// Validation Helpers

fn validate_rating<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rating: u8 = Deserialize::deserialize(deserializer)?;
    if !(1..=5).contains(&rating) {
        return Err(serde::de::Error::custom("Rating must be between 1 and 5"));
    }
    Ok(rating)
}

impl SignedReview {
    /// Valide la longueur du commentaire
    pub fn validate_comment(&self) -> Result<(), String> {
        if let Some(ref comment) = self.comment {
            if comment.len() > 500 {
                return Err(format!(
                    "Comment too long: {} chars (max 500)",
                    comment.len()
                ));
            }
        }
        Ok(())
    }
}

impl VendorReputation {
    /// Crée une nouvelle réputation vide
    pub fn new(vendor_pubkey: String) -> Self {
        let now = Utc::now();
        Self {
            format_version: "1.1".to_string(),
            vendor_pubkey,
            generated_at: now,
            reviews: Vec::new(),
            stats: ReputationStats {
                total_reviews: 0,
                average_rating: 0.0,
                rating_distribution: [0; 5],
                oldest_review: now,
                newest_review: now,
                completed_transactions: 0,
                shield_score: 0,
                trust_level: "bronze".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_review_serialization() {
        let review = SignedReview {
            txid: "abc123def456".to_string(),
            rating: 5,
            comment: Some("Excellent product!".to_string()),
            timestamp: Utc::now(),
            buyer_pubkey: "pubkey_base64_encoded".to_string(),
            signature: "signature_base64_encoded".to_string(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&review).unwrap();

        // Deserialize back
        let parsed: SignedReview = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.rating, 5);
        assert_eq!(parsed.txid, "abc123def456");
    }

    #[test]
    fn test_invalid_rating_rejected() {
        let json = r#"{
            "txid": "abc123",
            "rating": 6,
            "comment": null,
            "timestamp": "2025-10-21T00:00:00Z",
            "buyer_pubkey": "pub",
            "signature": "sig"
        }"#;

        let result: Result<SignedReview, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_comment_validation() {
        let mut review = SignedReview {
            txid: "abc".to_string(),
            rating: 5,
            comment: Some("x".repeat(501)), // 501 chars
            timestamp: Utc::now(),
            buyer_pubkey: "pub".to_string(),
            signature: "sig".to_string(),
        };

        assert!(review.validate_comment().is_err());

        review.comment = Some("Valid comment".to_string());
        assert!(review.validate_comment().is_ok());
    }

    #[test]
    fn test_vendor_reputation_new() {
        let reputation = VendorReputation::new("vendor_pubkey_123".to_string());

        assert_eq!(reputation.format_version, "1.1");
        assert_eq!(reputation.reviews.len(), 0);
        assert_eq!(reputation.stats.total_reviews, 0);
        assert_eq!(reputation.stats.completed_transactions, 0);
        assert_eq!(reputation.stats.shield_score, 0);
        assert_eq!(reputation.stats.trust_level, "bronze");
    }
}
