//! Diesel model for wasm_multisig_infos table (BE-002)
//!
//! Replaces the in-memory WasmMultisigStore with persistent SQLite storage.
//! Stores multisig info and view key components during WASM-based multisig setup.

use diesel::prelude::*;
use uuid::Uuid;

use crate::db::DbPool;
use crate::schema::wasm_multisig_infos;

/// Queryable model for wasm_multisig_infos table
#[derive(Debug, Clone, Queryable, Identifiable)]
#[diesel(table_name = wasm_multisig_infos)]
pub struct WasmMultisigInfoRow {
    pub id: String,
    pub escrow_id: String,
    pub role: String,
    pub multisig_info: String,
    pub view_key_component: Option<String>,
    pub created_at: i32,  // Maps to Integer in SQLite
}

/// Insertable model for wasm_multisig_infos table
#[derive(Debug, Insertable)]
#[diesel(table_name = wasm_multisig_infos)]
pub struct NewWasmMultisigInfo {
    pub id: String,
    pub escrow_id: String,
    pub role: String,
    pub multisig_info: String,
    pub view_key_component: Option<String>,
    pub created_at: i32,  // Maps to Integer in SQLite
}

impl WasmMultisigInfoRow {
    /// Submit or update multisig info for a participant
    /// Returns the total count of participants for this escrow
    pub fn submit(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
        role: &str,
        multisig_info: &str,
        view_key_component: Option<&str>,
    ) -> Result<usize, diesel::result::Error> {
        use crate::schema::wasm_multisig_infos::dsl;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;

        // Check if this role already submitted
        let existing: Option<Self> = dsl::wasm_multisig_infos
            .filter(dsl::escrow_id.eq(escrow_id))
            .filter(dsl::role.eq(role))
            .first(conn)
            .optional()?;

        if let Some(existing_row) = existing {
            // Update existing entry
            diesel::update(dsl::wasm_multisig_infos.filter(dsl::id.eq(&existing_row.id)))
                .set((
                    dsl::multisig_info.eq(multisig_info),
                    dsl::view_key_component.eq(view_key_component),
                    dsl::created_at.eq(now),
                ))
                .execute(conn)?;
        } else {
            // Insert new entry
            let new_info = NewWasmMultisigInfo {
                id: Uuid::new_v4().to_string(),
                escrow_id: escrow_id.to_string(),
                role: role.to_string(),
                multisig_info: multisig_info.to_string(),
                view_key_component: view_key_component.map(String::from),
                created_at: now,
            };

            diesel::insert_into(dsl::wasm_multisig_infos)
                .values(&new_info)
                .execute(conn)?;
        }

        // Return total count for this escrow
        let count: i64 = dsl::wasm_multisig_infos
            .filter(dsl::escrow_id.eq(escrow_id))
            .count()
            .get_result(conn)?;

        Ok(count as usize)
    }

    /// Get all peer infos for an escrow (excluding the requesting role)
    pub fn get_peer_infos(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
        my_role: &str,
    ) -> Result<Vec<Self>, diesel::result::Error> {
        use crate::schema::wasm_multisig_infos::dsl;

        let mut peers: Vec<Self> = dsl::wasm_multisig_infos
            .filter(dsl::escrow_id.eq(escrow_id))
            .filter(dsl::role.ne(my_role))
            .load(conn)?;

        // Sort by role alphabetically: "arbiter" < "buyer" < "vendor"
        peers.sort_by(|a, b| a.role.cmp(&b.role));

        Ok(peers)
    }

    /// Get all infos for an escrow
    pub fn get_all_for_escrow(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
    ) -> Result<Vec<Self>, diesel::result::Error> {
        use crate::schema::wasm_multisig_infos::dsl;

        dsl::wasm_multisig_infos
            .filter(dsl::escrow_id.eq(escrow_id))
            .order(dsl::role.asc())
            .load(conn)
    }

    /// Delete all infos for an escrow (cleanup after finalization)
    pub fn delete_for_escrow(
        conn: &mut diesel::SqliteConnection,
        escrow_id: &str,
    ) -> Result<usize, diesel::result::Error> {
        use crate::schema::wasm_multisig_infos::dsl;

        diesel::delete(dsl::wasm_multisig_infos.filter(dsl::escrow_id.eq(escrow_id))).execute(conn)
    }
}

/// SQLite-backed WasmMultisigStore that replaces the in-memory HashMap implementation
pub struct SqliteWasmMultisigStore {
    pool: DbPool,
}

impl SqliteWasmMultisigStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Submit multisig info for a participant
    /// Returns the total count of participants for this escrow
    pub fn submit(
        &self,
        escrow_id: &str,
        role: &str,
        info: &str,
        view_key: Option<&str>,
    ) -> Result<usize, anyhow::Error> {
        let mut conn = self.pool.get()?;
        let count = WasmMultisigInfoRow::submit(&mut conn, escrow_id, role, info, view_key)?;
        Ok(count)
    }

    /// Get peer infos for an escrow (excluding the requesting role)
    pub fn get_peer_infos(
        &self,
        escrow_id: &str,
        my_role: &str,
    ) -> Result<Vec<WasmMultisigInfoRow>, anyhow::Error> {
        let mut conn = self.pool.get()?;
        let peers = WasmMultisigInfoRow::get_peer_infos(&mut conn, escrow_id, my_role)?;
        Ok(peers)
    }

    /// Get all infos for an escrow
    pub fn get_all_for_escrow(&self, escrow_id: &str) -> Result<Vec<WasmMultisigInfoRow>, anyhow::Error> {
        let mut conn = self.pool.get()?;
        let infos = WasmMultisigInfoRow::get_all_for_escrow(&mut conn, escrow_id)?;
        Ok(infos)
    }

    /// Cleanup infos for a finalized escrow
    pub fn delete_for_escrow(&self, escrow_id: &str) -> Result<usize, anyhow::Error> {
        let mut conn = self.pool.get()?;
        let count = WasmMultisigInfoRow::delete_for_escrow(&mut conn, escrow_id)?;
        Ok(count)
    }
}
