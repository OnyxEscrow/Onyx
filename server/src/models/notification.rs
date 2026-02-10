//! Notification model for persistent user notifications
//!
//! Stores notifications that appear in the header notification icon.
//! WebSocket events are also persisted here for later retrieval.

use anyhow::Result;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::notifications;

/// Notification types for categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    NewOrder,
    OrderStatusChanged,
    EscrowUpdate,
    DisputeOpened,
    DisputeResolved,
    DkgRoundRequired,
    SignatureRequired,
    PaymentReceived,
    ReviewReceived,
    System,
}

impl NotificationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationType::NewOrder => "new_order",
            NotificationType::OrderStatusChanged => "order_status_changed",
            NotificationType::EscrowUpdate => "escrow_update",
            NotificationType::DisputeOpened => "dispute_opened",
            NotificationType::DisputeResolved => "dispute_resolved",
            NotificationType::DkgRoundRequired => "dkg_round_required",
            NotificationType::SignatureRequired => "signature_required",
            NotificationType::PaymentReceived => "payment_received",
            NotificationType::ReviewReceived => "review_received",
            NotificationType::System => "system",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "new_order" => NotificationType::NewOrder,
            "order_status_changed" => NotificationType::OrderStatusChanged,
            "escrow_update" => NotificationType::EscrowUpdate,
            "dispute_opened" => NotificationType::DisputeOpened,
            "dispute_resolved" => NotificationType::DisputeResolved,
            "dkg_round_required" => NotificationType::DkgRoundRequired,
            "signature_required" => NotificationType::SignatureRequired,
            "payment_received" => NotificationType::PaymentReceived,
            "review_received" => NotificationType::ReviewReceived,
            _ => NotificationType::System,
        }
    }
}

/// Notification database model
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Identifiable)]
#[diesel(table_name = notifications)]
pub struct Notification {
    pub id: String,
    pub user_id: String,
    pub notification_type: String,
    pub title: String,
    pub message: String,
    pub link: Option<String>,
    pub data: Option<String>,
    pub read: i32,
    pub created_at: NaiveDateTime,
}

/// New notification for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = notifications)]
pub struct NewNotification {
    pub id: String,
    pub user_id: String,
    pub notification_type: String,
    pub title: String,
    pub message: String,
    pub link: Option<String>,
    pub data: Option<String>,
    pub read: i32,
}

impl NewNotification {
    /// Create a new notification
    pub fn new(
        user_id: String,
        notification_type: NotificationType,
        title: String,
        message: String,
        link: Option<String>,
        data: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            notification_type: notification_type.as_str().to_string(),
            title,
            message,
            link,
            data,
            read: 0,
        }
    }
}

/// API response format for notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationResponse {
    pub id: String,
    /// Full notification type (e.g., "new_order", "escrow_update")
    pub notification_type: String,
    /// Alias for JavaScript compatibility (n.type)
    #[serde(rename = "type")]
    pub type_alias: String,
    pub title: String,
    pub message: String,
    pub link: Option<String>,
    pub data: Option<String>,
    pub read: bool,
    pub created_at: String,
    pub time_ago: String,
}

impl From<Notification> for NotificationResponse {
    fn from(n: Notification) -> Self {
        let now = chrono::Utc::now().naive_utc();
        let duration = now.signed_duration_since(n.created_at);

        let time_ago = if duration.num_days() > 0 {
            format!("{}d ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{}h ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{}m ago", duration.num_minutes())
        } else {
            "just now".to_string()
        };

        // Convert notification_type to JS-friendly format (e.g., "new_order" -> "order")
        let type_alias = n.notification_type
            .trim_start_matches("new_")
            .trim_end_matches("_update")
            .trim_end_matches("_changed")
            .to_string();

        Self {
            id: n.id,
            notification_type: n.notification_type.clone(),
            type_alias,
            title: n.title,
            message: n.message,
            link: n.link,
            data: n.data,
            read: n.read != 0,
            created_at: n.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            time_ago,
        }
    }
}

impl Notification {
    /// Get all notifications for a user, ordered by most recent first
    pub fn get_by_user_id(
        user_id: &str,
        limit: i64,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<Notification>> {
        use crate::schema::notifications::dsl;

        let results = dsl::notifications
            .filter(dsl::user_id.eq(user_id))
            .order(dsl::created_at.desc())
            .limit(limit)
            .load::<Notification>(conn)?;

        Ok(results)
    }

    /// Get unread notifications count for a user
    pub fn count_unread(
        user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<i64> {
        use crate::schema::notifications::dsl;

        let count = dsl::notifications
            .filter(dsl::user_id.eq(user_id))
            .filter(dsl::read.eq(0))
            .count()
            .get_result(conn)?;

        Ok(count)
    }

    /// Create a new notification
    pub fn create(
        new_notification: NewNotification,
        conn: &mut SqliteConnection,
    ) -> Result<Notification> {
        use crate::schema::notifications::dsl;

        diesel::insert_into(dsl::notifications)
            .values(&new_notification)
            .execute(conn)?;

        let notification = dsl::notifications
            .find(&new_notification.id)
            .first::<Notification>(conn)?;

        Ok(notification)
    }

    /// Mark a notification as read
    pub fn mark_as_read(
        notification_id: &str,
        user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        use crate::schema::notifications::dsl;

        diesel::update(
            dsl::notifications
                .filter(dsl::id.eq(notification_id))
                .filter(dsl::user_id.eq(user_id)),
        )
        .set(dsl::read.eq(1))
        .execute(conn)?;

        Ok(())
    }

    /// Mark all notifications as read for a user
    pub fn mark_all_as_read(
        user_id: &str,
        conn: &mut SqliteConnection,
    ) -> Result<usize> {
        use crate::schema::notifications::dsl;

        let updated = diesel::update(
            dsl::notifications
                .filter(dsl::user_id.eq(user_id))
                .filter(dsl::read.eq(0)),
        )
        .set(dsl::read.eq(1))
        .execute(conn)?;

        Ok(updated)
    }

    /// Mark notifications as read by link (for persistent toast dismissal)
    pub fn mark_read_by_link(
        user_id: &str,
        link: &str,
        conn: &mut SqliteConnection,
    ) -> Result<usize> {
        use crate::schema::notifications::dsl;

        let updated = diesel::update(
            dsl::notifications
                .filter(dsl::user_id.eq(user_id))
                .filter(dsl::link.eq(link))
                .filter(dsl::read.eq(0)),
        )
        .set(dsl::read.eq(1))
        .execute(conn)?;

        Ok(updated)
    }

    /// Delete old notifications (cleanup, keep last 100 per user)
    pub fn cleanup_old(
        user_id: &str,
        keep_count: i64,
        conn: &mut SqliteConnection,
    ) -> Result<usize> {
        use crate::schema::notifications::dsl;

        // Get IDs to keep
        let ids_to_keep: Vec<String> = dsl::notifications
            .filter(dsl::user_id.eq(user_id))
            .order(dsl::created_at.desc())
            .limit(keep_count)
            .select(dsl::id)
            .load(conn)?;

        // Delete the rest
        let deleted = diesel::delete(
            dsl::notifications
                .filter(dsl::user_id.eq(user_id))
                .filter(dsl::id.ne_all(&ids_to_keep)),
        )
        .execute(conn)?;

        Ok(deleted)
    }
}
