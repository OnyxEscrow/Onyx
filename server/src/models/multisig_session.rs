//! Diesel models for multisig coordination tables
//!
//! Maps database schema to Rust structs for type-safe queries

use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::{multisig_participants, multisig_sessions};

/// Queryable model for multisig_sessions table
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = multisig_sessions)]
pub struct DbMultisigSession {
    pub id: String,
    pub escrow_id: String,
    pub stage: String,
    pub created_at: i32,
    pub updated_at: i32,
    pub timeout_at: Option<i32>,
    pub multisig_address: Option<String>,
}

/// Insertable model for creating new sessions
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = multisig_sessions)]
pub struct NewDbMultisigSession {
    pub id: String,
    pub escrow_id: String,
    pub stage: String,
    pub created_at: i32,
    pub updated_at: i32,
    pub timeout_at: Option<i32>,
    pub multisig_address: Option<String>,
}

/// Queryable model for multisig_participants table
#[derive(Debug, Clone, Queryable, Identifiable, Associations, Serialize, Deserialize)]
#[diesel(belongs_to(DbMultisigSession, foreign_key = session_id))]
#[diesel(table_name = multisig_participants)]
pub struct DbMultisigParticipant {
    pub id: String,
    pub session_id: String,
    pub role: String,
    pub participant_type: String,
    pub wallet_id: Option<String>,
    pub user_id: Option<String>,
    pub has_submitted_round1: bool,
    pub has_submitted_round2: bool,
    pub public_spend_key: Option<String>,
    pub multisig_info_round1: Option<String>,
    pub multisig_info_round2: Option<String>,
    pub submitted_at_round1: Option<i32>,
    pub submitted_at_round2: Option<i32>,
}

/// Insertable model for creating new participants
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = multisig_participants)]
pub struct NewDbMultisigParticipant {
    pub id: String,
    pub session_id: String,
    pub role: String,
    pub participant_type: String,
    pub wallet_id: Option<String>,
    pub user_id: Option<String>,
    pub has_submitted_round1: bool,
    pub has_submitted_round2: bool,
    pub public_spend_key: Option<String>,
    pub multisig_info_round1: Option<String>,
    pub multisig_info_round2: Option<String>,
    pub submitted_at_round1: Option<i32>,
    pub submitted_at_round2: Option<i32>,
}

impl DbMultisigSession {
    /// Load session by escrow_id
    pub fn find_by_escrow(
        conn: &mut SqliteConnection,
        escrow_id_val: &str,
    ) -> QueryResult<Self> {
        multisig_sessions::table
            .filter(multisig_sessions::escrow_id.eq(escrow_id_val))
            .first(conn)
    }

    /// Load session by ID
    pub fn find_by_id(conn: &mut SqliteConnection, session_id: &str) -> QueryResult<Self> {
        multisig_sessions::table
            .filter(multisig_sessions::id.eq(session_id))
            .first(conn)
    }

    /// Update session stage
    pub fn update_stage(
        conn: &mut SqliteConnection,
        session_id: &str,
        new_stage: &str,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now().timestamp() as i32;
        diesel::update(multisig_sessions::table.filter(multisig_sessions::id.eq(session_id)))
            .set((
                multisig_sessions::stage.eq(new_stage),
                multisig_sessions::updated_at.eq(now),
            ))
            .execute(conn)
    }

    /// Update multisig address (when stage = Ready)
    pub fn update_address(
        conn: &mut SqliteConnection,
        session_id: &str,
        address: &str,
    ) -> QueryResult<usize> {
        diesel::update(multisig_sessions::table.filter(multisig_sessions::id.eq(session_id)))
            .set(multisig_sessions::multisig_address.eq(address))
            .execute(conn)
    }
}

impl DbMultisigParticipant {
    /// Load all participants for a session
    pub fn find_by_session(
        conn: &mut SqliteConnection,
        session_id_val: &str,
    ) -> QueryResult<Vec<Self>> {
        multisig_participants::table
            .filter(multisig_participants::session_id.eq(session_id_val))
            .load(conn)
    }

    /// Load participant by session and role
    pub fn find_by_session_and_role(
        conn: &mut SqliteConnection,
        session_id_val: &str,
        role_val: &str,
    ) -> QueryResult<Self> {
        multisig_participants::table
            .filter(multisig_participants::session_id.eq(session_id_val))
            .filter(multisig_participants::role.eq(role_val))
            .first(conn)
    }

    /// Update Round 1 submission
    pub fn update_round1(
        conn: &mut SqliteConnection,
        session_id_val: &str,
        role_val: &str,
        info: &str,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now().timestamp() as i32;
        diesel::update(
            multisig_participants::table
                .filter(multisig_participants::session_id.eq(session_id_val))
                .filter(multisig_participants::role.eq(role_val)),
        )
        .set((
            multisig_participants::has_submitted_round1.eq(true),
            multisig_participants::multisig_info_round1.eq(info),
            multisig_participants::submitted_at_round1.eq(now),
        ))
        .execute(conn)
    }

    /// Update Round 2 submission
    pub fn update_round2(
        conn: &mut SqliteConnection,
        session_id_val: &str,
        role_val: &str,
        info: &str,
    ) -> QueryResult<usize> {
        let now = chrono::Utc::now().timestamp() as i32;
        diesel::update(
            multisig_participants::table
                .filter(multisig_participants::session_id.eq(session_id_val))
                .filter(multisig_participants::role.eq(role_val)),
        )
        .set((
            multisig_participants::has_submitted_round2.eq(true),
            multisig_participants::multisig_info_round2.eq(info),
            multisig_participants::submitted_at_round2.eq(now),
        ))
        .execute(conn)
    }
}
