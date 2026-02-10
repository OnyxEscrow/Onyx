//! User Escrow Role model
//!
//! Tracks which user has which role (buyer/seller/arbiter) in each escrow.
//! Used by Phase 6 to determine which wallet seed to derive for signing.

use anyhow::{Context, Result};
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::user_escrow_roles;

/// User's role in an escrow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EscrowRole {
    Buyer,
    Seller,
    Arbiter,
}

impl EscrowRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            EscrowRole::Buyer => "buyer",
            EscrowRole::Seller => "seller",
            EscrowRole::Arbiter => "arbiter",
        }
    }
}

impl std::str::FromStr for EscrowRole {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "buyer" => Ok(EscrowRole::Buyer),
            "seller" => Ok(EscrowRole::Seller),
            "arbiter" => Ok(EscrowRole::Arbiter),
            _ => anyhow::bail!("Invalid escrow role: {}", s),
        }
    }
}

/// User escrow role database model
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = user_escrow_roles)]
pub struct UserEscrowRole {
    pub id: Option<String>,
    pub user_id: String,
    pub escrow_id: String,
    pub role: String,
    pub created_at: i32,
}

/// New user escrow role for insertion
#[derive(Insertable)]
#[diesel(table_name = user_escrow_roles)]
pub struct NewUserEscrowRole {
    pub id: String,
    pub user_id: String,
    pub escrow_id: String,
    pub role: String,
    pub created_at: i32,
}

impl UserEscrowRole {
    /// Create a new user-escrow role mapping
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `user_id` - User UUID
    /// * `escrow_id` - Escrow UUID
    /// * `role` - User's role (buyer/seller/arbiter)
    pub fn create(
        conn: &mut SqliteConnection,
        user_id: Uuid,
        escrow_id: Uuid,
        role: EscrowRole,
    ) -> Result<Self> {
        let new_role = NewUserEscrowRole {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            escrow_id: escrow_id.to_string(),
            role: role.as_str().to_string(),
            created_at: Utc::now().timestamp() as i32,
        };

        diesel::insert_into(user_escrow_roles::table)
            .values(&new_role)
            .execute(conn)
            .context("Failed to insert user escrow role")?;

        user_escrow_roles::table
            .filter(user_escrow_roles::id.eq(&new_role.id))
            .first(conn)
            .context("Failed to retrieve created user escrow role")
    }

    /// Get user's role in an escrow
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `user_id` - User UUID
    /// * `escrow_id` - Escrow UUID
    ///
    /// # Returns
    ///
    /// * `Ok(EscrowRole)` - User's role
    /// * `Err` - User has no role in this escrow
    pub fn get_user_role(
        conn: &mut SqliteConnection,
        user_id: Uuid,
        escrow_id: Uuid,
    ) -> Result<EscrowRole> {
        let role_record: Self = user_escrow_roles::table
            .filter(user_escrow_roles::user_id.eq(user_id.to_string()))
            .filter(user_escrow_roles::escrow_id.eq(escrow_id.to_string()))
            .first(conn)
            .context(format!(
                "User {} has no role in escrow {}",
                user_id, escrow_id
            ))?;

        role_record.role.parse::<EscrowRole>()
    }

    /// Check if user has a role in the escrow
    pub fn user_has_role(
        conn: &mut SqliteConnection,
        user_id: Uuid,
        escrow_id: Uuid,
    ) -> Result<bool> {
        let count: i64 = user_escrow_roles::table
            .filter(user_escrow_roles::user_id.eq(user_id.to_string()))
            .filter(user_escrow_roles::escrow_id.eq(escrow_id.to_string()))
            .count()
            .get_result(conn)
            .context("Failed to check user role")?;

        Ok(count > 0)
    }

    /// Get all escrows for a user with a specific role
    pub fn find_by_user_and_role(
        conn: &mut SqliteConnection,
        user_id: Uuid,
        role: EscrowRole,
    ) -> Result<Vec<Self>> {
        user_escrow_roles::table
            .filter(user_escrow_roles::user_id.eq(user_id.to_string()))
            .filter(user_escrow_roles::role.eq(role.as_str()))
            .load(conn)
            .context("Failed to load user escrow roles")
    }

    /// Get all users for an escrow
    pub fn find_by_escrow(
        conn: &mut SqliteConnection,
        escrow_id: Uuid,
    ) -> Result<Vec<Self>> {
        user_escrow_roles::table
            .filter(user_escrow_roles::escrow_id.eq(escrow_id.to_string()))
            .load(conn)
            .context("Failed to load escrow participants")
    }

    /// Get parsed role enum
    pub fn get_role(&self) -> Result<EscrowRole> {
        self.role.parse::<EscrowRole>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escrow_role_conversion() {
        assert_eq!(EscrowRole::Buyer.as_str(), "buyer");
        assert_eq!(EscrowRole::Seller.as_str(), "seller");
        assert_eq!(EscrowRole::Arbiter.as_str(), "arbiter");

        assert!(matches!(
            "buyer".parse::<EscrowRole>(),
            Ok(EscrowRole::Buyer)
        ));
        assert!(matches!(
            "seller".parse::<EscrowRole>(),
            Ok(EscrowRole::Seller)
        ));
        assert!(matches!(
            "arbiter".parse::<EscrowRole>(),
            Ok(EscrowRole::Arbiter)
        ));
        assert!("invalid".parse::<EscrowRole>().is_err());
    }
}
