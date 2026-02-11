//! Database-backed implementation of MultisigCoordinator
//!
//! Production-ready coordinator with:
//! - Atomic database transactions
//! - Session timeout management
//! - Connection pooling
//! - Error recovery

use async_trait::async_trait;
use diesel::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::coordination::multisig_coordinator::{
    MultisigCoordinationError, MultisigCoordinator, MultisigSession, MultisigStage,
    ParticipantState, ParticipantType,
};
use crate::db::DbPool;
use crate::models::multisig_session::{
    DbMultisigParticipant, DbMultisigSession, NewDbMultisigParticipant, NewDbMultisigSession,
};
use crate::schema::{multisig_participants, multisig_sessions};

/// Database-backed multisig coordinator
pub struct DbMultisigCoordinator {
    pool: Arc<DbPool>,
    session_timeout_seconds: i32,
}

impl DbMultisigCoordinator {
    /// Create a new coordinator with database pool
    ///
    /// # Arguments
    /// * `pool` - Diesel connection pool
    /// * `session_timeout_seconds` - Timeout for inactive sessions (default: 3600 = 1 hour)
    pub fn new(pool: Arc<DbPool>, session_timeout_seconds: Option<i32>) -> Self {
        Self {
            pool,
            session_timeout_seconds: session_timeout_seconds.unwrap_or(3600),
        }
    }

    /// Convert database stage string to MultisigStage enum
    fn parse_stage(stage: &str) -> Result<MultisigStage, MultisigCoordinationError> {
        match stage {
            "initialization" => Ok(MultisigStage::Initialization),
            "round1_complete" => Ok(MultisigStage::Round1Complete),
            "key_exchange" => Ok(MultisigStage::KeyExchange),
            "ready" => Ok(MultisigStage::Ready),
            "signing" => Ok(MultisigStage::Signing),
            _ => Err(MultisigCoordinationError::InvalidMultisigData(format!(
                "Unknown stage: {stage}"
            ))),
        }
    }

    /// Convert MultisigStage enum to database stage string
    fn stage_to_db(stage: &MultisigStage) -> &'static str {
        match stage {
            MultisigStage::Initialization => "initialization",
            MultisigStage::Round1Complete => "round1_complete",
            MultisigStage::KeyExchange => "key_exchange",
            MultisigStage::Ready => "ready",
            MultisigStage::Signing => "signing",
        }
    }

    /// Convert database participant to ParticipantType
    fn parse_participant_type(
        ptype: &str,
        wallet_id: Option<String>,
        user_id: Option<String>,
    ) -> Result<ParticipantType, MultisigCoordinationError> {
        match ptype {
            "local_managed" => {
                let wallet_uuid = wallet_id
                    .and_then(|id| Uuid::parse_str(&id).ok())
                    .ok_or_else(|| {
                        MultisigCoordinationError::InvalidMultisigData(
                            "LocalManaged participant missing wallet_id".to_string(),
                        )
                    })?;
                Ok(ParticipantType::LocalManaged {
                    wallet_id: wallet_uuid,
                })
            }
            "remote" => {
                let uid = user_id.ok_or_else(|| {
                    MultisigCoordinationError::InvalidMultisigData(
                        "Remote participant missing user_id".to_string(),
                    )
                })?;
                Ok(ParticipantType::Remote { user_id: uid })
            }
            _ => Err(MultisigCoordinationError::InvalidMultisigData(format!(
                "Unknown participant type: {ptype}"
            ))),
        }
    }

    /// Convert ParticipantType to database fields
    fn participant_type_to_db(
        ptype: &ParticipantType,
    ) -> (&'static str, Option<String>, Option<String>) {
        match ptype {
            ParticipantType::LocalManaged { wallet_id } => {
                ("local_managed", Some(wallet_id.to_string()), None)
            }
            ParticipantType::Remote { user_id } => ("remote", None, Some(user_id.clone())),
        }
    }

    /// Convert database participant to ParticipantState
    fn db_to_participant_state(
        db: &DbMultisigParticipant,
    ) -> Result<ParticipantState, MultisigCoordinationError> {
        let participant_type = Self::parse_participant_type(
            &db.participant_type,
            db.wallet_id.clone(),
            db.user_id.clone(),
        )?;

        Ok(ParticipantState {
            participant_type,
            has_submitted_round1: db.has_submitted_round1,
            has_submitted_round2: db.has_submitted_round2,
            public_spend_key: db.public_spend_key.clone(),
            multisig_info_round1: db.multisig_info_round1.clone(),
            multisig_info_round2: db.multisig_info_round2.clone(),
        })
    }

    /// Load full MultisigSession from database
    fn load_session(&self, escrow_id: Uuid) -> Result<MultisigSession, MultisigCoordinationError> {
        let mut conn = self.pool.get().map_err(|e| {
            MultisigCoordinationError::StorageError(format!("Connection pool: {e}"))
        })?;

        let db_session = DbMultisigSession::find_by_escrow(&mut conn, &escrow_id.to_string())
            .map_err(|_| MultisigCoordinationError::SessionNotFound(escrow_id))?;

        let db_participants = DbMultisigParticipant::find_by_session(&mut conn, &db_session.id)
            .map_err(|e| {
                MultisigCoordinationError::StorageError(format!("Load participants: {e}"))
            })?;

        let stage = Self::parse_stage(&db_session.stage)?;

        let participants: HashMap<String, ParticipantState> = db_participants
            .iter()
            .map(|p| {
                let state = Self::db_to_participant_state(p)?;
                Ok((p.role.clone(), state))
            })
            .collect::<Result<HashMap<_, _>, MultisigCoordinationError>>()?;

        Ok(MultisigSession {
            escrow_id,
            stage,
            created_at: db_session.created_at as i64,
            participants,
            multisig_address: db_session.multisig_address.clone(),
        })
    }
}

#[async_trait]
impl MultisigCoordinator for DbMultisigCoordinator {
    async fn init_session(
        &self,
        escrow_id: Uuid,
        participants: Vec<(String, ParticipantType)>,
    ) -> Result<(), MultisigCoordinationError> {
        let mut conn = self.pool.get().map_err(|e| {
            MultisigCoordinationError::StorageError(format!("Connection pool: {e}"))
        })?;

        let session_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp() as i32;
        let timeout_at = now + self.session_timeout_seconds;

        // Create session and participants in a transaction
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            // Insert session
            let new_session = NewDbMultisigSession {
                id: session_id.clone(),
                escrow_id: escrow_id.to_string(),
                stage: Self::stage_to_db(&MultisigStage::Initialization).to_string(),
                created_at: now,
                updated_at: now,
                timeout_at: Some(timeout_at),
                multisig_address: None,
            };

            diesel::insert_into(multisig_sessions::table)
                .values(&new_session)
                .execute(conn)?;

            // Insert participants
            for (role, ptype) in participants {
                let (ptype_str, wallet_id, user_id) = Self::participant_type_to_db(&ptype);

                let new_participant = NewDbMultisigParticipant {
                    id: Uuid::new_v4().to_string(),
                    session_id: session_id.clone(),
                    role: role.clone(),
                    participant_type: ptype_str.to_string(),
                    wallet_id,
                    user_id,
                    has_submitted_round1: false,
                    has_submitted_round2: false,
                    public_spend_key: None,
                    multisig_info_round1: None,
                    multisig_info_round2: None,
                    submitted_at_round1: None,
                    submitted_at_round2: None,
                };

                diesel::insert_into(multisig_participants::table)
                    .values(&new_participant)
                    .execute(conn)?;
            }

            Ok(())
        })
        .map_err(|e| MultisigCoordinationError::StorageError(format!("Transaction failed: {e}")))?;

        tracing::info!(
            "✅ Multisig session initialized for escrow {} (session: {})",
            escrow_id,
            session_id
        );

        Ok(())
    }

    async fn submit_info(
        &self,
        escrow_id: Uuid,
        user_id: String,
        info: String,
        stage: MultisigStage,
    ) -> Result<(), MultisigCoordinationError> {
        // Validate info is not empty
        if info.trim().is_empty() {
            return Err(MultisigCoordinationError::InvalidMultisigData(
                "Multisig info cannot be empty".to_string(),
            ));
        }

        let mut conn = self.pool.get().map_err(|e| {
            MultisigCoordinationError::StorageError(format!("Connection pool: {e}"))
        })?;

        // Load session to get session_id
        let db_session = DbMultisigSession::find_by_escrow(&mut conn, &escrow_id.to_string())
            .map_err(|_| MultisigCoordinationError::SessionNotFound(escrow_id))?;

        // Find participant by user_id
        let participant = multisig_participants::table
            .filter(multisig_participants::session_id.eq(&db_session.id))
            .filter(multisig_participants::user_id.eq(&user_id))
            .first::<DbMultisigParticipant>(&mut conn)
            .map_err(|_| {
                MultisigCoordinationError::UnauthorizedParticipant(format!(
                    "User {user_id} not found in session"
                ))
            })?;

        // Determine which round to update based on stage
        match stage {
            MultisigStage::Initialization => {
                // Round 1 submission
                if participant.has_submitted_round1 {
                    return Err(MultisigCoordinationError::InvalidState {
                        expected: "not_submitted".to_string(),
                        actual: "already_submitted_round1".to_string(),
                    });
                }

                DbMultisigParticipant::update_round1(
                    &mut conn,
                    &db_session.id,
                    &participant.role,
                    &info,
                )
                .map_err(|e| {
                    MultisigCoordinationError::StorageError(format!("Update round1: {e}"))
                })?;

                tracing::info!(
                    "✅ Round 1 submitted for {} in escrow {}",
                    participant.role,
                    escrow_id
                );
            }
            MultisigStage::KeyExchange => {
                // Round 2 submission
                if !participant.has_submitted_round1 {
                    return Err(MultisigCoordinationError::InvalidState {
                        expected: "round1_submitted".to_string(),
                        actual: "round1_not_submitted".to_string(),
                    });
                }

                if participant.has_submitted_round2 {
                    return Err(MultisigCoordinationError::InvalidState {
                        expected: "not_submitted".to_string(),
                        actual: "already_submitted_round2".to_string(),
                    });
                }

                DbMultisigParticipant::update_round2(
                    &mut conn,
                    &db_session.id,
                    &participant.role,
                    &info,
                )
                .map_err(|e| {
                    MultisigCoordinationError::StorageError(format!("Update round2: {e}"))
                })?;

                tracing::info!(
                    "✅ Round 2 submitted for {} in escrow {}",
                    participant.role,
                    escrow_id
                );
            }
            _ => {
                return Err(MultisigCoordinationError::InvalidState {
                    expected: "Initialization or KeyExchange".to_string(),
                    actual: format!("{stage:?}"),
                });
            }
        }

        // Check if we can advance stage
        let all_participants = DbMultisigParticipant::find_by_session(&mut conn, &db_session.id)
            .map_err(|e| {
                MultisigCoordinationError::StorageError(format!("Load participants: {e}"))
            })?;

        let current_stage = Self::parse_stage(&db_session.stage)?;

        match current_stage {
            MultisigStage::Initialization => {
                // Check if all submitted Round 1
                if all_participants.iter().all(|p| p.has_submitted_round1) {
                    DbMultisigSession::update_stage(
                        &mut conn,
                        &db_session.id,
                        Self::stage_to_db(&MultisigStage::Round1Complete),
                    )
                    .map_err(|e| {
                        MultisigCoordinationError::StorageError(format!("Update stage: {e}"))
                    })?;

                    tracing::info!(
                        "✅ All Round 1 submissions complete for escrow {} → Round1Complete",
                        escrow_id
                    );
                }
            }
            MultisigStage::KeyExchange => {
                // Check if all submitted Round 2
                if all_participants.iter().all(|p| p.has_submitted_round2) {
                    DbMultisigSession::update_stage(
                        &mut conn,
                        &db_session.id,
                        Self::stage_to_db(&MultisigStage::Ready),
                    )
                    .map_err(|e| {
                        MultisigCoordinationError::StorageError(format!("Update stage: {e}"))
                    })?;

                    tracing::info!(
                        "✅ All Round 2 submissions complete for escrow {} → Ready",
                        escrow_id
                    );
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn get_peer_info(
        &self,
        escrow_id: Uuid,
        user_id: String,
    ) -> Result<Vec<String>, MultisigCoordinationError> {
        let mut conn = self.pool.get().map_err(|e| {
            MultisigCoordinationError::StorageError(format!("Connection pool: {e}"))
        })?;

        let db_session = DbMultisigSession::find_by_escrow(&mut conn, &escrow_id.to_string())
            .map_err(|_| MultisigCoordinationError::SessionNotFound(escrow_id))?;

        // Find requester's participant
        let requester = multisig_participants::table
            .filter(multisig_participants::session_id.eq(&db_session.id))
            .filter(multisig_participants::user_id.eq(&user_id))
            .first::<DbMultisigParticipant>(&mut conn)
            .map_err(|_| {
                MultisigCoordinationError::UnauthorizedParticipant(format!(
                    "User {user_id} not in session"
                ))
            })?;

        // Load all participants
        let all_participants = DbMultisigParticipant::find_by_session(&mut conn, &db_session.id)
            .map_err(|e| {
                MultisigCoordinationError::StorageError(format!("Load participants: {e}"))
            })?;

        let current_stage = Self::parse_stage(&db_session.stage)?;

        // Collect peer info based on current stage
        let peer_infos: Vec<String> = match current_stage {
            MultisigStage::Initialization | MultisigStage::Round1Complete => {
                // Return Round 1 infos from all OTHERS
                all_participants
                    .iter()
                    .filter(|p| p.role != requester.role)
                    .filter_map(|p| p.multisig_info_round1.clone())
                    .collect()
            }
            MultisigStage::KeyExchange | MultisigStage::Ready => {
                // Return Round 2 infos from all OTHERS
                all_participants
                    .iter()
                    .filter(|p| p.role != requester.role)
                    .filter_map(|p| p.multisig_info_round2.clone())
                    .collect()
            }
            MultisigStage::Signing => Vec::new(), // No peer exchange needed during signing
        };

        tracing::debug!(
            "Retrieved {} peer infos for {} in escrow {} (stage: {:?})",
            peer_infos.len(),
            requester.role,
            escrow_id,
            current_stage
        );

        Ok(peer_infos)
    }

    async fn check_progress(
        &self,
        escrow_id: Uuid,
    ) -> Result<MultisigStage, MultisigCoordinationError> {
        let mut conn = self.pool.get().map_err(|e| {
            MultisigCoordinationError::StorageError(format!("Connection pool: {e}"))
        })?;

        let db_session = DbMultisigSession::find_by_escrow(&mut conn, &escrow_id.to_string())
            .map_err(|_| MultisigCoordinationError::SessionNotFound(escrow_id))?;

        Self::parse_stage(&db_session.stage)
    }

    async fn get_session_state(
        &self,
        escrow_id: Uuid,
    ) -> Result<MultisigSession, MultisigCoordinationError> {
        self.load_session(escrow_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_conversion() {
        assert_eq!(
            DbMultisigCoordinator::stage_to_db(&MultisigStage::Initialization),
            "initialization"
        );
        assert_eq!(
            DbMultisigCoordinator::stage_to_db(&MultisigStage::Round1Complete),
            "round1_complete"
        );
        assert_eq!(
            DbMultisigCoordinator::stage_to_db(&MultisigStage::KeyExchange),
            "key_exchange"
        );
        assert_eq!(
            DbMultisigCoordinator::stage_to_db(&MultisigStage::Ready),
            "ready"
        );
        assert_eq!(
            DbMultisigCoordinator::stage_to_db(&MultisigStage::Signing),
            "signing"
        );
    }

    #[test]
    fn test_parse_stage() {
        assert!(matches!(
            DbMultisigCoordinator::parse_stage("initialization"),
            Ok(MultisigStage::Initialization)
        ));
        assert!(matches!(
            DbMultisigCoordinator::parse_stage("round1_complete"),
            Ok(MultisigStage::Round1Complete)
        ));
        assert!(matches!(
            DbMultisigCoordinator::parse_stage("key_exchange"),
            Ok(MultisigStage::KeyExchange)
        ));
        assert!(matches!(
            DbMultisigCoordinator::parse_stage("ready"),
            Ok(MultisigStage::Ready)
        ));
        assert!(matches!(
            DbMultisigCoordinator::parse_stage("signing"),
            Ok(MultisigStage::Signing)
        ));
        assert!(DbMultisigCoordinator::parse_stage("invalid").is_err());
    }

    #[test]
    fn test_participant_type_conversion() {
        let wallet_uuid = Uuid::new_v4();
        let local = ParticipantType::LocalManaged {
            wallet_id: wallet_uuid,
        };
        let (ptype, wid, uid) = DbMultisigCoordinator::participant_type_to_db(&local);
        assert_eq!(ptype, "local_managed");
        assert_eq!(wid, Some(wallet_uuid.to_string()));
        assert_eq!(uid, None);

        let remote = ParticipantType::Remote {
            user_id: "user123".to_string(),
        };
        let (ptype, wid, uid) = DbMultisigCoordinator::participant_type_to_db(&remote);
        assert_eq!(ptype, "remote");
        assert_eq!(wid, None);
        assert_eq!(uid, Some("user123".to_string()));
    }
}
