//! Diesel model for multisig_challenges table (BE-001)
//!
//! Replaces the in-memory ChallengeStore with persistent SQLite storage.
//! Challenges are used for proof-of-possession verification during multisig setup.

use diesel::prelude::*;
use uuid::Uuid;

use crate::db::DbPool;
use crate::schema::multisig_challenges;

/// Queryable model for multisig_challenges table
#[derive(Debug, Clone, Queryable, Identifiable)]
#[diesel(table_name = multisig_challenges)]
pub struct MultisigChallengeRow {
    pub id: String,
    pub user_id: String,
    pub escrow_id: String,
    pub nonce: Vec<u8>,
    pub created_at: i32,  // Maps to Integer in SQLite
    pub expires_at: i32,  // Maps to Integer in SQLite
}

/// Insertable model for multisig_challenges table
#[derive(Debug, Insertable)]
#[diesel(table_name = multisig_challenges)]
pub struct NewMultisigChallenge {
    pub id: String,
    pub user_id: String,
    pub escrow_id: String,
    pub nonce: Vec<u8>,
    pub created_at: i32,  // Maps to Integer in SQLite
    pub expires_at: i32,  // Maps to Integer in SQLite
}

impl MultisigChallengeRow {
    /// Store a new challenge in the database, replacing any existing one for the user/escrow pair
    pub fn store(
        conn: &mut diesel::SqliteConnection,
        user_id: Uuid,
        escrow_id: Uuid,
        nonce: &[u8; 32],
        created_at: u64,
        expires_at: u64,
    ) -> Result<(), diesel::result::Error> {
        use crate::schema::multisig_challenges::dsl;

        let new_challenge = NewMultisigChallenge {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            escrow_id: escrow_id.to_string(),
            nonce: nonce.to_vec(),
            created_at: created_at as i32,
            expires_at: expires_at as i32,
        };

        // Delete existing challenge for this user/escrow pair
        diesel::delete(
            dsl::multisig_challenges
                .filter(dsl::user_id.eq(user_id.to_string()))
                .filter(dsl::escrow_id.eq(escrow_id.to_string())),
        )
        .execute(conn)?;

        // Insert new challenge
        diesel::insert_into(dsl::multisig_challenges)
            .values(&new_challenge)
            .execute(conn)?;

        Ok(())
    }

    /// Retrieve a challenge for a specific user/escrow pair
    pub fn get(
        conn: &mut diesel::SqliteConnection,
        user_id: Uuid,
        escrow_id: Uuid,
    ) -> Result<Option<Self>, diesel::result::Error> {
        use crate::schema::multisig_challenges::dsl;

        dsl::multisig_challenges
            .filter(dsl::user_id.eq(user_id.to_string()))
            .filter(dsl::escrow_id.eq(escrow_id.to_string()))
            .first(conn)
            .optional()
    }

    /// Remove a challenge after use (one-time use)
    pub fn remove(
        conn: &mut diesel::SqliteConnection,
        user_id: Uuid,
        escrow_id: Uuid,
    ) -> Result<usize, diesel::result::Error> {
        use crate::schema::multisig_challenges::dsl;

        diesel::delete(
            dsl::multisig_challenges
                .filter(dsl::user_id.eq(user_id.to_string()))
                .filter(dsl::escrow_id.eq(escrow_id.to_string())),
        )
        .execute(conn)
    }

    /// Clean up expired challenges
    pub fn cleanup_expired(conn: &mut diesel::SqliteConnection) -> Result<usize, diesel::result::Error> {
        use crate::schema::multisig_challenges::dsl;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;

        diesel::delete(dsl::multisig_challenges.filter(dsl::expires_at.lt(now))).execute(conn)
    }

    /// Convert nonce bytes to fixed array
    pub fn nonce_array(&self) -> Option<[u8; 32]> {
        if self.nonce.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self.nonce);
            Some(arr)
        } else {
            None
        }
    }
}

/// SQLite-backed ChallengeStore that replaces the in-memory HashMap implementation
pub struct SqliteChallengeStore {
    pool: DbPool,
}

impl SqliteChallengeStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Store a new challenge for user/escrow
    pub fn store(
        &self,
        user_id: Uuid,
        escrow_id: Uuid,
        nonce: &[u8; 32],
        created_at: u64,
        expires_at: u64,
    ) -> Result<(), anyhow::Error> {
        let mut conn = self.pool.get()?;
        MultisigChallengeRow::store(&mut conn, user_id, escrow_id, nonce, created_at, expires_at)?;
        Ok(())
    }

    /// Retrieve challenge for user/escrow
    pub fn get(&self, user_id: Uuid, escrow_id: Uuid) -> Result<Option<MultisigChallengeRow>, anyhow::Error> {
        let mut conn = self.pool.get()?;
        let result = MultisigChallengeRow::get(&mut conn, user_id, escrow_id)?;
        Ok(result)
    }

    /// Remove challenge after use (one-time use)
    pub fn remove(&self, user_id: Uuid, escrow_id: Uuid) -> Result<(), anyhow::Error> {
        let mut conn = self.pool.get()?;
        MultisigChallengeRow::remove(&mut conn, user_id, escrow_id)?;
        Ok(())
    }

    /// Clean up expired challenges
    pub fn cleanup_expired(&self) -> Result<usize, anyhow::Error> {
        let mut conn = self.pool.get()?;
        let count = MultisigChallengeRow::cleanup_expired(&mut conn)?;
        Ok(count)
    }
}
