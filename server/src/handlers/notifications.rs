//! Notification API handlers
//!
//! REST API endpoints for persistent user notifications.
//! These notifications appear in the header notification icon.

use actix_session::Session;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::middleware::csrf::validate_csrf_token;
use crate::models::notification::{Notification, NotificationResponse};

/// Response for notification list
#[derive(Debug, Serialize)]
pub struct NotificationsListResponse {
    pub notifications: Vec<NotificationResponse>,
    pub unread_count: i64,
    pub total_count: usize,
}

/// Response for unread count
#[derive(Debug, Serialize)]
pub struct UnreadCountResponse {
    pub unread_count: i64,
}

/// Request for marking notification as read
#[derive(Debug, Deserialize)]
pub struct MarkReadRequest {
    pub notification_id: Option<String>,
}

/// Query params for marking notification as read by link
#[derive(Debug, Deserialize)]
pub struct MarkReadByLinkQuery {
    pub link: String,
}

/// Helper to get authenticated user ID from session
fn get_user_id_from_session(session: &Session) -> Result<String, HttpResponse> {
    session
        .get::<String>("user_id")
        .map_err(|_| {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to read session"
            }))
        })?
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Not authenticated"
            }))
        })
}

/// GET /api/notifications - Get all notifications for the current user
///
/// Returns up to 50 most recent notifications, ordered by most recent first.
/// Includes unread count for badge display.
///
/// Requires authentication.
#[get("/notifications")]
pub async fn get_notifications(
    pool: web::Data<DbPool>,
    session: Session,
) -> impl Responder {
    // Get authenticated user
    let user_id = match get_user_id_from_session(&session) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // Get database connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Get notifications (limit 50)
    let notifications = match Notification::get_by_user_id(&user_id, 50, &mut conn) {
        Ok(notifs) => notifs,
        Err(e) => {
            tracing::error!("Failed to load notifications: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to load notifications"
            }));
        }
    };

    // Get unread count
    let unread_count = match Notification::count_unread(&user_id, &mut conn) {
        Ok(count) => count,
        Err(e) => {
            tracing::error!("Failed to count unread notifications: {:?}", e);
            0
        }
    };

    let total_count = notifications.len();
    let notifications_response: Vec<NotificationResponse> = notifications
        .into_iter()
        .map(NotificationResponse::from)
        .collect();

    HttpResponse::Ok().json(NotificationsListResponse {
        notifications: notifications_response,
        unread_count,
        total_count,
    })
}

/// GET /api/notifications/unread-count - Get unread notification count
///
/// Returns only the count of unread notifications for badge display.
/// Lighter endpoint for frequent polling.
///
/// Requires authentication.
#[get("/notifications/unread-count")]
pub async fn get_unread_count(
    pool: web::Data<DbPool>,
    session: Session,
) -> impl Responder {
    // Get authenticated user
    let user_id = match get_user_id_from_session(&session) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // Get database connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Get unread count
    let unread_count = match Notification::count_unread(&user_id, &mut conn) {
        Ok(count) => count,
        Err(e) => {
            tracing::error!("Failed to count unread notifications: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to count notifications"
            }));
        }
    };

    HttpResponse::Ok().json(UnreadCountResponse { unread_count })
}

/// POST /api/notifications/{id}/read - Mark a notification as read
///
/// Marks the specified notification as read.
/// Only the owner can mark their own notifications.
///
/// Requires authentication and CSRF protection.
#[post("/notifications/{id}/read")]
pub async fn mark_notification_read(
    pool: web::Data<DbPool>,
    session: Session,
    http_req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let notification_id = path.into_inner();

    // SECURITY: Validate CSRF token
    let csrf_token = http_req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if !validate_csrf_token(&session, csrf_token) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Invalid or missing CSRF token"
        }));
    }

    // Get authenticated user
    let user_id = match get_user_id_from_session(&session) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // Get database connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Mark as read (user_id ensures ownership)
    match Notification::mark_as_read(&notification_id, &user_id, &mut conn) {
        Ok(_) => {
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Notification marked as read"
            }))
        }
        Err(e) => {
            tracing::error!("Failed to mark notification as read: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to mark notification as read"
            }))
        }
    }
}

/// POST /api/notifications/mark-all-read - Mark all notifications as read
///
/// Marks all unread notifications for the current user as read.
///
/// Requires authentication and CSRF protection.
#[post("/notifications/mark-all-read")]
pub async fn mark_all_notifications_read(
    pool: web::Data<DbPool>,
    session: Session,
    http_req: HttpRequest,
) -> impl Responder {
    // SECURITY: Validate CSRF token
    let csrf_token = http_req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if !validate_csrf_token(&session, csrf_token) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Invalid or missing CSRF token"
        }));
    }

    // Get authenticated user
    let user_id = match get_user_id_from_session(&session) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // Get database connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Mark all as read
    match Notification::mark_all_as_read(&user_id, &mut conn) {
        Ok(count) => {
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "marked_count": count
            }))
        }
        Err(e) => {
            tracing::error!("Failed to mark all notifications as read: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to mark notifications as read"
            }))
        }
    }
}

/// POST /api/notifications/mark-read-by-link - Mark notifications as read by link
///
/// Marks all unread notifications with a specific link as read.
/// Used when user visits a page that has pending notifications.
///
/// Requires authentication. No CSRF required (non-destructive action).
#[post("/notifications/mark-read-by-link")]
pub async fn mark_read_by_link(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<MarkReadByLinkQuery>,
) -> impl Responder {
    // Get authenticated user
    let user_id = match get_user_id_from_session(&session) {
        Ok(id) => id,
        Err(response) => return response,
    };

    // Get database connection
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Database connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database connection failed"
            }));
        }
    };

    // Mark notifications with this link as read
    match Notification::mark_read_by_link(&user_id, &query.link, &mut conn) {
        Ok(count) => {
            tracing::info!(
                user_id = %user_id,
                link = %query.link,
                marked_count = count,
                "Marked notifications as read by link"
            );
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "marked_count": count
            }))
        }
        Err(e) => {
            tracing::error!("Failed to mark notifications as read by link: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to mark notifications as read"
            }))
        }
    }
}
