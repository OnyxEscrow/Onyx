//! User model and related database operations

use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::users;

#[derive(Clone, Serialize, Deserialize, Queryable, Insertable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub wallet_address: Option<String>,
    pub wallet_id: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    // Phase 6: Non-custodial wallet seed management
    pub encrypted_wallet_seed: Option<Vec<u8>>,
    pub wallet_seed_salt: Option<Vec<u8>>,
    pub bip39_backup_seed: Option<String>,
    pub seed_created_at: Option<i32>,
    pub seed_backup_acknowledged: Option<bool>,
}

// TM-005 Fix: Custom Debug qui redacte les champs sensibles
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .field("role", &self.role)
            .field(
                "wallet_address",
                &self.wallet_address.as_ref().map(|_| "<redacted>"),
            )
            .field("wallet_id", &self.wallet_id.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub wallet_address: Option<String>,
    pub wallet_id: Option<String>,
}

impl User {
    /// Create a new user in the database
    pub fn create(conn: &mut SqliteConnection, new_user: NewUser) -> Result<User> {
        diesel::insert_into(users::table)
            .values(&new_user)
            .execute(conn)
            .context("Failed to insert user")?;

        users::table
            .filter(users::id.eq(new_user.id))
            .first(conn)
            .context("Failed to retrieve created user")
    }

    /// Find user by ID
    pub fn find_by_id(conn: &mut SqliteConnection, user_id: String) -> Result<User> {
        users::table
            .filter(users::id.eq(user_id.clone()))
            .first(conn)
            .context(format!("User with ID {} not found", user_id))
    }

    /// Find user by username
    pub fn find_by_username(conn: &mut SqliteConnection, username_str: &str) -> Result<User> {
        users::table
            .filter(users::username.eq(username_str))
            .first(conn)
            .context(format!("User with username '{}' not found", username_str))
    }

    /// Check if username already exists
    pub fn username_exists(conn: &mut SqliteConnection, username_str: &str) -> Result<bool> {
        let count: i64 = users::table
            .filter(users::username.eq(username_str))
            .count()
            .get_result(conn)
            .context("Failed to check username existence")?;
        Ok(count > 0)
    }

    /// Update user's updated_at timestamp
    pub fn touch(conn: &mut SqliteConnection, user_id: String) -> Result<()> {
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::updated_at.eq(diesel::dsl::now))
            .execute(conn)
            .context("Failed to update user timestamp")?;
        Ok(())
    }

    /// Delete user by ID
    pub fn delete(conn: &mut SqliteConnection, user_id: String) -> Result<()> {
        diesel::delete(users::table.filter(users::id.eq(user_id.clone())))
            .execute(conn)
            .context(format!("Failed to delete user {}", user_id))?;
        Ok(())
    }

    /// List all users with a specific role
    pub fn find_by_role(conn: &mut SqliteConnection, role_str: &str) -> Result<Vec<User>> {
        users::table
            .filter(users::role.eq(role_str))
            .load(conn)
            .context(format!("Failed to load users with role '{}'", role_str))
    }
}
