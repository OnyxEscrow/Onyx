//! Marketplace Client model for B2B fee configuration
//!
//! Stores B2B client configuration including custom fee schedules.

use anyhow::{Context, Result};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::marketplace_clients;

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = marketplace_clients)]
pub struct MarketplaceClient {
    pub id: String,
    pub api_key_user_id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub fee_bps: i32,
    pub webhook_url: Option<String>,
    pub is_active: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = marketplace_clients)]
pub struct NewMarketplaceClient {
    pub id: String,
    pub api_key_user_id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub fee_bps: i32,
    pub webhook_url: Option<String>,
    pub is_active: i32,
    pub created_at: String,
    pub updated_at: String,
}

impl MarketplaceClient {
    pub fn create(conn: &mut SqliteConnection, new: NewMarketplaceClient) -> Result<Self> {
        let client_id = new.id.clone();
        diesel::insert_into(marketplace_clients::table)
            .values(&new)
            .execute(conn)
            .context("Failed to insert marketplace client")?;
        marketplace_clients::table
            .find(client_id)
            .first(conn)
            .context("Failed to retrieve created marketplace client")
    }

    pub fn find_by_id(conn: &mut SqliteConnection, client_id: &str) -> Result<Option<Self>> {
        marketplace_clients::table
            .find(client_id)
            .first(conn)
            .optional()
            .context("Failed to query marketplace client")
    }

    pub fn find_by_api_user_id(conn: &mut SqliteConnection, user_id: &str) -> Result<Vec<Self>> {
        marketplace_clients::table
            .filter(marketplace_clients::api_key_user_id.eq(user_id))
            .load(conn)
            .context("Failed to query marketplace clients by user")
    }

    pub fn find_active(conn: &mut SqliteConnection) -> Result<Vec<Self>> {
        marketplace_clients::table
            .filter(marketplace_clients::is_active.eq(1))
            .load(conn)
            .context("Failed to query active marketplace clients")
    }

    pub fn update_fee_bps(
        conn: &mut SqliteConnection,
        client_id: &str,
        fee_bps: i32,
    ) -> Result<()> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        diesel::update(marketplace_clients::table.find(client_id))
            .set((
                marketplace_clients::fee_bps.eq(fee_bps),
                marketplace_clients::updated_at.eq(now),
            ))
            .execute(conn)
            .context("Failed to update marketplace client fee_bps")?;
        Ok(())
    }

    pub fn update_webhook_url(
        conn: &mut SqliteConnection,
        client_id: &str,
        url: Option<&str>,
    ) -> Result<()> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        diesel::update(marketplace_clients::table.find(client_id))
            .set((
                marketplace_clients::webhook_url.eq(url),
                marketplace_clients::updated_at.eq(now),
            ))
            .execute(conn)
            .context("Failed to update marketplace client webhook_url")?;
        Ok(())
    }

    pub fn deactivate(conn: &mut SqliteConnection, client_id: &str) -> Result<()> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        diesel::update(marketplace_clients::table.find(client_id))
            .set((
                marketplace_clients::is_active.eq(0),
                marketplace_clients::updated_at.eq(now),
            ))
            .execute(conn)
            .context("Failed to deactivate marketplace client")?;
        Ok(())
    }

    pub fn new_with_defaults(api_key_user_id: &str, name: &str) -> NewMarketplaceClient {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        NewMarketplaceClient {
            id: Uuid::new_v4().to_string(),
            api_key_user_id: api_key_user_id.to_string(),
            name: name.to_string(),
            display_name: None,
            fee_bps: 150,
            webhook_url: None,
            is_active: 1,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}
