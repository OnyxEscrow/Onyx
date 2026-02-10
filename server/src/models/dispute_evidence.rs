//! Diesel models for dispute_evidence table
//!
//! Stores IPFS-based evidence files for dispute resolution.
//! Evidence is uploaded by buyers, vendors, or arbiters during disputes.

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::dispute_evidence;

/// Evidence uploader role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploaderRole {
    Buyer,
    Vendor,
    Arbiter,
}

impl UploaderRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UploaderRole::Buyer => "buyer",
            UploaderRole::Vendor => "vendor",
            UploaderRole::Arbiter => "arbiter",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "buyer" => Some(UploaderRole::Buyer),
            "vendor" => Some(UploaderRole::Vendor),
            "arbiter" => Some(UploaderRole::Arbiter),
            _ => None,
        }
    }
}

/// Constants for evidence configuration
pub const MAX_EVIDENCE_FILES: usize = 10;
pub const MAX_FILE_SIZE: usize = 5 * 1024 * 1024; // 5MB
pub const ALLOWED_MIME_TYPES: &[&str] = &[
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/gif",
    "text/plain",
];

/// Queryable model for dispute_evidence table
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = dispute_evidence)]
pub struct DisputeEvidence {
    pub id: String,
    pub escrow_id: String,
    pub uploader_id: String,
    pub uploader_role: String,
    pub ipfs_cid: String,
    pub file_name: String,
    pub file_size: i32,
    pub mime_type: String,
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
}

/// Insertable model for creating new evidence entries
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = dispute_evidence)]
pub struct NewDisputeEvidence {
    pub id: String,
    pub escrow_id: String,
    pub uploader_id: String,
    pub uploader_role: String,
    pub ipfs_cid: String,
    pub file_name: String,
    pub file_size: i32,
    pub mime_type: String,
    pub description: Option<String>,
}

/// Response model for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceResponse {
    pub id: String,
    pub escrow_id: String,
    pub uploader_role: String,
    pub ipfs_cid: String,
    pub file_name: String,
    pub file_size: i32,
    pub mime_type: String,
    pub description: Option<String>,
    pub created_at: String,
    pub download_url: String,
}

impl DisputeEvidence {
    /// Find all evidence for an escrow
    pub fn find_by_escrow(
        conn: &mut SqliteConnection,
        escrow_id_val: &str,
    ) -> QueryResult<Vec<Self>> {
        dispute_evidence::table
            .filter(dispute_evidence::escrow_id.eq(escrow_id_val))
            .order(dispute_evidence::created_at.asc())
            .load(conn)
    }

    /// Find evidence by ID
    pub fn find_by_id(conn: &mut SqliteConnection, evidence_id: &str) -> QueryResult<Option<Self>> {
        dispute_evidence::table
            .filter(dispute_evidence::id.eq(evidence_id))
            .first(conn)
            .optional()
    }

    /// Count evidence for an escrow
    pub fn count_by_escrow(conn: &mut SqliteConnection, escrow_id_val: &str) -> QueryResult<i64> {
        dispute_evidence::table
            .filter(dispute_evidence::escrow_id.eq(escrow_id_val))
            .count()
            .get_result(conn)
    }

    /// Delete evidence by ID
    pub fn delete_by_id(conn: &mut SqliteConnection, evidence_id: &str) -> QueryResult<usize> {
        diesel::delete(dispute_evidence::table.filter(dispute_evidence::id.eq(evidence_id)))
            .execute(conn)
    }

    /// Get uploader role as enum
    pub fn get_uploader_role(&self) -> Option<UploaderRole> {
        UploaderRole::from_str(&self.uploader_role)
    }

    /// Convert to API response
    pub fn to_response(&self, ipfs_gateway: &str) -> EvidenceResponse {
        EvidenceResponse {
            id: self.id.clone(),
            escrow_id: self.escrow_id.clone(),
            uploader_role: self.uploader_role.clone(),
            ipfs_cid: self.ipfs_cid.clone(),
            file_name: self.file_name.clone(),
            file_size: self.file_size,
            mime_type: self.mime_type.clone(),
            description: self.description.clone(),
            created_at: self.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            download_url: format!("{}/ipfs/{}", ipfs_gateway, self.ipfs_cid),
        }
    }
}

impl NewDisputeEvidence {
    /// Create a new evidence entry
    pub fn new(
        escrow_id: String,
        uploader_id: String,
        uploader_role: UploaderRole,
        ipfs_cid: String,
        file_name: String,
        file_size: i32,
        mime_type: String,
        description: Option<String>,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();

        Self {
            id,
            escrow_id,
            uploader_id,
            uploader_role: uploader_role.as_str().to_string(),
            ipfs_cid,
            file_name,
            file_size,
            mime_type,
            description,
        }
    }

    /// Insert into database
    pub fn insert(&self, conn: &mut SqliteConnection) -> QueryResult<DisputeEvidence> {
        diesel::insert_into(dispute_evidence::table)
            .values(self)
            .execute(conn)?;

        dispute_evidence::table
            .filter(dispute_evidence::id.eq(&self.id))
            .first(conn)
    }
}

/// Check if a MIME type is allowed for evidence
pub fn is_allowed_mime_type(mime_type: &str) -> bool {
    ALLOWED_MIME_TYPES.contains(&mime_type)
}

/// Validate file size
pub fn is_valid_file_size(size: usize) -> bool {
    size > 0 && size <= MAX_FILE_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uploader_role_conversion() {
        assert_eq!(UploaderRole::Buyer.as_str(), "buyer");
        assert_eq!(UploaderRole::Vendor.as_str(), "vendor");
        assert_eq!(UploaderRole::Arbiter.as_str(), "arbiter");

        assert_eq!(UploaderRole::from_str("buyer"), Some(UploaderRole::Buyer));
        assert_eq!(UploaderRole::from_str("vendor"), Some(UploaderRole::Vendor));
        assert_eq!(
            UploaderRole::from_str("arbiter"),
            Some(UploaderRole::Arbiter)
        );
        assert_eq!(UploaderRole::from_str("invalid"), None);
    }

    #[test]
    fn test_mime_type_validation() {
        assert!(is_allowed_mime_type("application/pdf"));
        assert!(is_allowed_mime_type("image/jpeg"));
        assert!(is_allowed_mime_type("image/png"));
        assert!(!is_allowed_mime_type("application/exe"));
        assert!(!is_allowed_mime_type("video/mp4"));
    }

    #[test]
    fn test_file_size_validation() {
        assert!(is_valid_file_size(1024)); // 1KB
        assert!(is_valid_file_size(MAX_FILE_SIZE)); // 5MB
        assert!(!is_valid_file_size(0));
        assert!(!is_valid_file_size(MAX_FILE_SIZE + 1));
    }

    #[test]
    fn test_new_dispute_evidence() {
        let evidence = NewDisputeEvidence::new(
            "escrow_123".to_string(),
            "user_456".to_string(),
            UploaderRole::Buyer,
            "QmTestCid123".to_string(),
            "receipt.pdf".to_string(),
            1024,
            "application/pdf".to_string(),
            Some("Payment receipt".to_string()),
        );

        assert!(!evidence.id.is_empty());
        assert_eq!(evidence.escrow_id, "escrow_123");
        assert_eq!(evidence.uploader_role, "buyer");
        assert_eq!(evidence.file_name, "receipt.pdf");
    }
}
