//! Non-Custodial Multisig Coordination
//!
//! This module provides a **cryptographic mailbox** for coordinating multisig setup
//! between remote clients (browser WASM, CLI) and the local arbiter wallet.
//!
//! **Architecture:**
//! - Remote clients (Buyer/Seller): Submit/retrieve multisig blobs via API
//! - Local Arbiter: Managed via wallet RPC on localhost
//! - Zero-knowledge server: Only stores encrypted blobs, never sees private keys
//!
//! **Security:**
//! - All multisig_info blobs are treated as opaque encrypted data
//! - No validation of blob contents (preserves end-to-end encryption)
//! - Session timeouts prevent denial-of-service
//! - Role-based access control (participants can only access their session)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug, Error)]
pub enum MultisigCoordinationError {
    #[error("Session multisig non trouvée pour l'escrow {0}")]
    SessionNotFound(Uuid),

    #[error("Participant {0} non autorisé dans cette session")]
    UnauthorizedParticipant(String),

    #[error("État invalide pour l'opération: attendu {expected}, actuel {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("Données multisig invalides: {0}")]
    InvalidMultisigData(String),

    #[error("Timeout de la session multisig")]
    SessionTimeout,

    #[error("Erreur interne de stockage: {0}")]
    StorageError(String),
}

// ============================================================================
// PUBLIC TYPES
// ============================================================================

/// Type de participant dans le multisig
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParticipantType {
    /// Wallet géré localement par le serveur (ex: Arbiter) via RPC
    LocalManaged { wallet_id: Uuid },
    /// Participant distant (ex: Client WASM) qui push/pull via API
    Remote { user_id: String },
}

/// État d'avancement du setup multisig
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MultisigStage {
    /// En attente des infos d'initialisation (Round 1)
    Initialization,
    /// Infos Round 1 reçues, prêt pour échange
    Round1Complete,
    /// En attente des infos de finalisation (Round 2 - Export/Import)
    KeyExchange,
    /// Setup complet, adresse multisig générée
    Ready,
    /// Transaction en cours de signature
    Signing,
}

/// État d'un participant individuel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantState {
    pub participant_type: ParticipantType,
    pub has_submitted_round1: bool,
    pub has_submitted_round2: bool,
    pub public_spend_key: Option<String>, // Pour vérification d'identité
    pub multisig_info_round1: Option<String>, // Blob exporté par prepare_multisig
    pub multisig_info_round2: Option<String>, // Blob exporté par export_multisig_info
}

impl ParticipantState {
    /// Crée un nouveau participant vide
    pub fn new(participant_type: ParticipantType) -> Self {
        Self {
            participant_type,
            has_submitted_round1: false,
            has_submitted_round2: false,
            public_spend_key: None,
            multisig_info_round1: None,
            multisig_info_round2: None,
        }
    }

    /// Soumet les données du Round 1 (prepare_multisig)
    pub fn submit_round1(&mut self, info: String) -> Result<(), MultisigCoordinationError> {
        if self.has_submitted_round1 {
            return Err(MultisigCoordinationError::InvalidState {
                expected: "not_submitted".to_string(),
                actual: "already_submitted_round1".to_string(),
            });
        }

        // Validation basique: blob non vide
        if info.trim().is_empty() {
            return Err(MultisigCoordinationError::InvalidMultisigData(
                "Round 1 info cannot be empty".to_string(),
            ));
        }

        self.multisig_info_round1 = Some(info);
        self.has_submitted_round1 = true;
        Ok(())
    }

    /// Soumet les données du Round 2 (export_multisig_info)
    pub fn submit_round2(&mut self, info: String) -> Result<(), MultisigCoordinationError> {
        if !self.has_submitted_round1 {
            return Err(MultisigCoordinationError::InvalidState {
                expected: "round1_submitted".to_string(),
                actual: "round1_not_submitted".to_string(),
            });
        }

        if self.has_submitted_round2 {
            return Err(MultisigCoordinationError::InvalidState {
                expected: "not_submitted".to_string(),
                actual: "already_submitted_round2".to_string(),
            });
        }

        if info.trim().is_empty() {
            return Err(MultisigCoordinationError::InvalidMultisigData(
                "Round 2 info cannot be empty".to_string(),
            ));
        }

        self.multisig_info_round2 = Some(info);
        self.has_submitted_round2 = true;
        Ok(())
    }
}

/// Session complète de multisig pour un escrow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSession {
    pub escrow_id: Uuid,
    pub stage: MultisigStage,
    pub created_at: i64,
    /// Map de Role (Buyer/Seller/Arbiter) -> État
    pub participants: HashMap<String, ParticipantState>,
    /// Adresse multisig finale (une fois générée)
    pub multisig_address: Option<String>,
}

impl MultisigSession {
    /// Crée une nouvelle session
    pub fn new(escrow_id: Uuid, participants: Vec<(String, ParticipantType)>) -> Self {
        let participants_map = participants
            .into_iter()
            .map(|(role, ptype)| (role, ParticipantState::new(ptype)))
            .collect();

        Self {
            escrow_id,
            stage: MultisigStage::Initialization,
            created_at: chrono::Utc::now().timestamp(),
            participants: participants_map,
            multisig_address: None,
        }
    }

    /// Vérifie si tous les participants ont soumis leurs infos Round 1
    pub fn is_round1_complete(&self) -> bool {
        self.participants.values().all(|p| p.has_submitted_round1)
    }

    /// Vérifie si tous les participants ont soumis leurs infos Round 2
    pub fn is_round2_complete(&self) -> bool {
        self.participants.values().all(|p| p.has_submitted_round2)
    }

    /// Récupère les blobs Round 1 de TOUS les autres participants (N-1)
    pub fn get_peer_round1_infos(&self, my_role: &str) -> Vec<String> {
        self.participants
            .iter()
            .filter(|(role, _)| *role != my_role)
            .filter_map(|(_, state)| state.multisig_info_round1.clone())
            .collect()
    }

    /// Récupère les blobs Round 2 de TOUS les autres participants (N-1)
    pub fn get_peer_round2_infos(&self, my_role: &str) -> Vec<String> {
        self.participants
            .iter()
            .filter(|(role, _)| *role != my_role)
            .filter_map(|(_, state)| state.multisig_info_round2.clone())
            .collect()
    }

    /// Avance la session à la prochaine étape si les conditions sont remplies
    pub fn advance_stage(&mut self) -> Result<(), MultisigCoordinationError> {
        match self.stage {
            MultisigStage::Initialization => {
                if self.is_round1_complete() {
                    self.stage = MultisigStage::Round1Complete;
                    Ok(())
                } else {
                    Err(MultisigCoordinationError::InvalidState {
                        expected: "all_round1_submitted".to_string(),
                        actual: format!("{}/3 submitted", self.count_round1_submissions()),
                    })
                }
            }
            MultisigStage::Round1Complete => {
                // Avance vers KeyExchange une fois Round1 validé
                self.stage = MultisigStage::KeyExchange;
                Ok(())
            }
            MultisigStage::KeyExchange => {
                if self.is_round2_complete() {
                    self.stage = MultisigStage::Ready;
                    Ok(())
                } else {
                    Err(MultisigCoordinationError::InvalidState {
                        expected: "all_round2_submitted".to_string(),
                        actual: format!("{}/3 submitted", self.count_round2_submissions()),
                    })
                }
            }
            MultisigStage::Ready | MultisigStage::Signing => {
                // Terminal states - cannot advance further
                Err(MultisigCoordinationError::InvalidState {
                    expected: "non_terminal_state".to_string(),
                    actual: format!("{:?}", self.stage),
                })
            }
        }
    }

    fn count_round1_submissions(&self) -> usize {
        self.participants
            .values()
            .filter(|p| p.has_submitted_round1)
            .count()
    }

    fn count_round2_submissions(&self) -> usize {
        self.participants
            .values()
            .filter(|p| p.has_submitted_round2)
            .count()
    }
}

/// Réponse d'état pour le frontend
#[derive(Debug, Serialize)]
pub struct MultisigStatusResponse {
    pub stage: MultisigStage,
    pub waiting_for: Vec<String>, // Liste des rôles qu'on attend
    pub my_action_required: bool,
    pub peer_data: Option<Vec<String>>, // Données à importer si dispo
}

// ============================================================================
// TRAIT: MultisigCoordinator
// ============================================================================

/// Trait définissant l'interface du coordinateur multisig
#[async_trait]
pub trait MultisigCoordinator: Send + Sync {
    /// Initialise une nouvelle session pour un escrow
    ///
    /// # Arguments
    /// * `escrow_id` - UUID de l'escrow
    /// * `participants` - Vec de (role, type) ex: [("buyer", Remote), ("arbiter", LocalManaged)]
    ///
    /// # Errors
    /// - `StorageError` si impossible de persister la session
    async fn init_session(
        &self,
        escrow_id: Uuid,
        participants: Vec<(String, ParticipantType)>,
    ) -> Result<(), MultisigCoordinationError>;

    /// Soumet un blob multisig pour un participant (Round 1 ou 2)
    ///
    /// # Arguments
    /// * `escrow_id` - UUID de l'escrow
    /// * `user_id` - Identifiant du participant (role: "buyer", "vendor", "arbiter")
    /// * `info` - Blob multisig (prepare_multisig ou export_multisig_info)
    /// * `stage` - Stage actuel (Initialization ou KeyExchange)
    ///
    /// # Errors
    /// - `SessionNotFound` si session n'existe pas
    /// - `UnauthorizedParticipant` si user_id n'est pas dans la session
    /// - `InvalidState` si soumission hors séquence
    /// - `InvalidMultisigData` si blob vide ou invalide
    async fn submit_info(
        &self,
        escrow_id: Uuid,
        user_id: String,
        info: String,
        stage: MultisigStage,
    ) -> Result<(), MultisigCoordinationError>;

    /// Récupère les blobs des AUTRES participants nécessaires pour avancer
    ///
    /// # Arguments
    /// * `escrow_id` - UUID de l'escrow
    /// * `user_id` - Identifiant du participant demandeur
    ///
    /// # Returns
    /// Vec<String> contenant les blobs des N-1 autres participants (vide si incomplet)
    ///
    /// # Errors
    /// - `SessionNotFound` si session n'existe pas
    /// - `UnauthorizedParticipant` si user_id n'est pas dans la session
    async fn get_peer_info(
        &self,
        escrow_id: Uuid,
        user_id: String,
    ) -> Result<Vec<String>, MultisigCoordinationError>;

    /// Vérifie si la session peut avancer à l'étape suivante
    ///
    /// # Arguments
    /// * `escrow_id` - UUID de l'escrow
    ///
    /// # Returns
    /// Le stage actuel de la session
    ///
    /// # Errors
    /// - `SessionNotFound` si session n'existe pas
    async fn check_progress(
        &self,
        escrow_id: Uuid,
    ) -> Result<MultisigStage, MultisigCoordinationError>;

    /// Récupère l'état actuel de la session
    ///
    /// # Arguments
    /// * `escrow_id` - UUID de l'escrow
    ///
    /// # Returns
    /// Copie complète de la MultisigSession
    ///
    /// # Errors
    /// - `SessionNotFound` si session n'existe pas
    async fn get_session_state(
        &self,
        escrow_id: Uuid,
    ) -> Result<MultisigSession, MultisigCoordinationError>;
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Happy Path Tests
    // ========================================================================

    #[test]
    fn test_participant_state_round1_submission() {
        let mut state = ParticipantState::new(ParticipantType::Remote {
            user_id: "buyer123".to_string(),
        });

        assert!(!state.has_submitted_round1);

        let result = state.submit_round1("multisig_info_blob_round1".to_string());
        assert!(result.is_ok());
        assert!(state.has_submitted_round1);
        assert_eq!(
            state.multisig_info_round1,
            Some("multisig_info_blob_round1".to_string())
        );
    }

    #[test]
    fn test_participant_state_round2_submission() {
        let mut state = ParticipantState::new(ParticipantType::Remote {
            user_id: "buyer123".to_string(),
        });

        // Round 1 d'abord
        state
            .submit_round1("round1_blob".to_string())
            .expect("Round 1 should succeed");

        // Maintenant Round 2
        let result = state.submit_round2("round2_blob".to_string());
        assert!(result.is_ok());
        assert!(state.has_submitted_round2);
        assert_eq!(state.multisig_info_round2, Some("round2_blob".to_string()));
    }

    #[test]
    fn test_multisig_session_creation() {
        let escrow_id = Uuid::new_v4();
        let participants = vec![
            (
                "buyer".to_string(),
                ParticipantType::Remote {
                    user_id: "user1".to_string(),
                },
            ),
            (
                "vendor".to_string(),
                ParticipantType::Remote {
                    user_id: "user2".to_string(),
                },
            ),
            (
                "arbiter".to_string(),
                ParticipantType::LocalManaged {
                    wallet_id: Uuid::new_v4(),
                },
            ),
        ];

        let session = MultisigSession::new(escrow_id, participants);

        assert_eq!(session.escrow_id, escrow_id);
        assert_eq!(session.stage, MultisigStage::Initialization);
        assert_eq!(session.participants.len(), 3);
        assert!(session.participants.contains_key("buyer"));
        assert!(session.participants.contains_key("vendor"));
        assert!(session.participants.contains_key("arbiter"));
    }

    #[test]
    fn test_session_round1_complete_detection() {
        let escrow_id = Uuid::new_v4();
        let participants = vec![
            (
                "buyer".to_string(),
                ParticipantType::Remote {
                    user_id: "user1".to_string(),
                },
            ),
            (
                "vendor".to_string(),
                ParticipantType::Remote {
                    user_id: "user2".to_string(),
                },
            ),
        ];

        let mut session = MultisigSession::new(escrow_id, participants);

        assert!(!session.is_round1_complete());

        // Soumettre Round 1 pour buyer
        session
            .participants
            .get_mut("buyer")
            .unwrap()
            .submit_round1("buyer_blob".to_string())
            .unwrap();
        assert!(!session.is_round1_complete());

        // Soumettre Round 1 pour vendor
        session
            .participants
            .get_mut("vendor")
            .unwrap()
            .submit_round1("vendor_blob".to_string())
            .unwrap();
        assert!(session.is_round1_complete());
    }

    #[test]
    fn test_session_get_peer_round1_infos() {
        let escrow_id = Uuid::new_v4();
        let participants = vec![
            (
                "buyer".to_string(),
                ParticipantType::Remote {
                    user_id: "user1".to_string(),
                },
            ),
            (
                "vendor".to_string(),
                ParticipantType::Remote {
                    user_id: "user2".to_string(),
                },
            ),
            (
                "arbiter".to_string(),
                ParticipantType::LocalManaged {
                    wallet_id: Uuid::new_v4(),
                },
            ),
        ];

        let mut session = MultisigSession::new(escrow_id, participants);

        // Soumettre pour buyer et vendor
        session
            .participants
            .get_mut("buyer")
            .unwrap()
            .submit_round1("buyer_blob".to_string())
            .unwrap();
        session
            .participants
            .get_mut("vendor")
            .unwrap()
            .submit_round1("vendor_blob".to_string())
            .unwrap();

        // Arbiter récupère les blobs des autres
        let peer_infos = session.get_peer_round1_infos("arbiter");
        assert_eq!(peer_infos.len(), 2);
        assert!(peer_infos.contains(&"buyer_blob".to_string()));
        assert!(peer_infos.contains(&"vendor_blob".to_string()));
    }

    #[test]
    fn test_session_stage_advancement() {
        let escrow_id = Uuid::new_v4();
        let participants = vec![
            (
                "buyer".to_string(),
                ParticipantType::Remote {
                    user_id: "user1".to_string(),
                },
            ),
            (
                "vendor".to_string(),
                ParticipantType::Remote {
                    user_id: "user2".to_string(),
                },
            ),
        ];

        let mut session = MultisigSession::new(escrow_id, participants);

        // Cannot advance without submissions
        assert!(session.advance_stage().is_err());

        // Submit Round 1 for all
        session
            .participants
            .get_mut("buyer")
            .unwrap()
            .submit_round1("buyer_blob".to_string())
            .unwrap();
        session
            .participants
            .get_mut("vendor")
            .unwrap()
            .submit_round1("vendor_blob".to_string())
            .unwrap();

        // Now can advance to Round1Complete
        assert!(session.advance_stage().is_ok());
        assert_eq!(session.stage, MultisigStage::Round1Complete);

        // Advance to KeyExchange
        assert!(session.advance_stage().is_ok());
        assert_eq!(session.stage, MultisigStage::KeyExchange);
    }

    // ========================================================================
    // Error Case Tests
    // ========================================================================

    #[test]
    fn test_participant_state_empty_round1_rejected() {
        let mut state = ParticipantState::new(ParticipantType::Remote {
            user_id: "buyer123".to_string(),
        });

        let result = state.submit_round1("".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigCoordinationError::InvalidMultisigData(_)
        ));
    }

    #[test]
    fn test_participant_state_duplicate_round1_rejected() {
        let mut state = ParticipantState::new(ParticipantType::Remote {
            user_id: "buyer123".to_string(),
        });

        state
            .submit_round1("first_blob".to_string())
            .expect("First submission should succeed");

        // Try to submit again
        let result = state.submit_round1("second_blob".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigCoordinationError::InvalidState { .. }
        ));
    }

    #[test]
    fn test_participant_state_round2_before_round1_rejected() {
        let mut state = ParticipantState::new(ParticipantType::Remote {
            user_id: "buyer123".to_string(),
        });

        // Try Round 2 without Round 1
        let result = state.submit_round2("round2_blob".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigCoordinationError::InvalidState { .. }
        ));
    }

    #[test]
    fn test_session_advance_from_terminal_state_fails() {
        let escrow_id = Uuid::new_v4();
        let participants = vec![(
            "buyer".to_string(),
            ParticipantType::Remote {
                user_id: "user1".to_string(),
            },
        )];

        let mut session = MultisigSession::new(escrow_id, participants);
        session.stage = MultisigStage::Ready;
        session.multisig_address = Some("4xxx".to_string());

        // Cannot advance from Ready state
        let result = session.advance_stage();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigCoordinationError::InvalidState { .. }
        ));
    }

    #[test]
    fn test_session_get_peer_infos_excludes_self() {
        let escrow_id = Uuid::new_v4();
        let participants = vec![
            (
                "buyer".to_string(),
                ParticipantType::Remote {
                    user_id: "user1".to_string(),
                },
            ),
            (
                "vendor".to_string(),
                ParticipantType::Remote {
                    user_id: "user2".to_string(),
                },
            ),
        ];

        let mut session = MultisigSession::new(escrow_id, participants);

        session
            .participants
            .get_mut("buyer")
            .unwrap()
            .submit_round1("buyer_blob".to_string())
            .unwrap();
        session
            .participants
            .get_mut("vendor")
            .unwrap()
            .submit_round1("vendor_blob".to_string())
            .unwrap();

        // Buyer récupère seulement vendor (N-1)
        let buyer_peers = session.get_peer_round1_infos("buyer");
        assert_eq!(buyer_peers.len(), 1);
        assert_eq!(buyer_peers[0], "vendor_blob");
        assert!(!buyer_peers.contains(&"buyer_blob".to_string()));
    }

    #[test]
    fn test_participant_type_serialization() {
        let local = ParticipantType::LocalManaged {
            wallet_id: Uuid::new_v4(),
        };
        let remote = ParticipantType::Remote {
            user_id: "user123".to_string(),
        };

        let local_json = serde_json::to_string(&local).expect("Serialize local");
        let remote_json = serde_json::to_string(&remote).expect("Serialize remote");

        let local_de: ParticipantType =
            serde_json::from_str(&local_json).expect("Deserialize local");
        let remote_de: ParticipantType =
            serde_json::from_str(&remote_json).expect("Deserialize remote");

        assert_eq!(local, local_de);
        assert_eq!(remote, remote_de);
    }
}
