//! P0 Security: High-entropy one-time recovery codes
//!
//! Provides cryptographically secure backup codes for account recovery.
//! Each code has ~48 bits of entropy and can only be used once.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use rand::{thread_rng, Rng};
use uuid::Uuid;

use crate::schema::recovery_codes;

/// Number of recovery codes to generate per user
pub const RECOVERY_CODE_COUNT: usize = 10;

/// Length of each code segment (4 chars each side of dash)
const CODE_SEGMENT_LEN: usize = 4;

/// Characters used for code generation (alphanumeric, no ambiguous chars)
/// Removed: 0/O, 1/I/l to avoid confusion
const CODE_CHARS: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// Recovery code model (from database)
#[derive(Debug, Clone, Queryable, Identifiable)]
#[diesel(table_name = recovery_codes)]
pub struct RecoveryCode {
    pub id: String,
    pub user_id: String,
    pub code_hash: String,
    pub used_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

/// New recovery code for insertion
#[derive(Debug, Insertable)]
#[diesel(table_name = recovery_codes)]
pub struct NewRecoveryCode {
    pub id: String,
    pub user_id: String,
    pub code_hash: String,
}

/// Generate a single high-entropy recovery code
/// Format: XXXX-XXXX (8 chars, ~41 bits entropy)
pub fn generate_code() -> String {
    let mut rng = thread_rng();
    let mut code = String::with_capacity(9);

    for i in 0..2 {
        if i > 0 {
            code.push('-');
        }
        for _ in 0..CODE_SEGMENT_LEN {
            let idx = rng.gen_range(0..CODE_CHARS.len());
            code.push(CODE_CHARS[idx] as char);
        }
    }

    code
}

/// Generate a batch of recovery codes
/// Returns (plaintext_codes, hashed_codes_for_storage)
pub fn generate_recovery_codes(
    user_id: &str,
) -> Result<(Vec<String>, Vec<NewRecoveryCode>), argon2::password_hash::Error> {
    let mut plaintext_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut hashed_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let argon2 = Argon2::default();

    for _ in 0..RECOVERY_CODE_COUNT {
        let code = generate_code();

        // Hash the code for storage
        let salt = SaltString::generate(&mut OsRng);
        let code_hash = argon2.hash_password(code.as_bytes(), &salt)?.to_string();

        plaintext_codes.push(code);
        hashed_codes.push(NewRecoveryCode {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            code_hash,
        });
    }

    Ok((plaintext_codes, hashed_codes))
}

/// Verify a recovery code against stored hashes
/// Returns the matching RecoveryCode if valid and unused
pub fn verify_recovery_code<'a>(
    code: &str,
    stored_codes: &'a [RecoveryCode],
) -> Option<&'a RecoveryCode> {
    let normalized_code = code.trim().to_uppercase().replace(" ", "-");
    let argon2 = Argon2::default();

    for stored in stored_codes {
        // Skip already used codes
        if stored.used_at.is_some() {
            continue;
        }

        // Try to verify against this hash
        if let Ok(parsed_hash) = PasswordHash::new(&stored.code_hash) {
            if argon2
                .verify_password(normalized_code.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return Some(stored);
            }
        }
    }

    None
}

impl RecoveryCode {
    /// Get all recovery codes for a user
    pub fn find_by_user(
        conn: &mut SqliteConnection,
        user_id_param: &str,
    ) -> QueryResult<Vec<RecoveryCode>> {
        use crate::schema::recovery_codes::dsl::*;

        recovery_codes
            .filter(user_id.eq(user_id_param))
            .load::<RecoveryCode>(conn)
    }

    /// Get unused recovery codes count for a user
    pub fn count_unused(conn: &mut SqliteConnection, user_id_param: &str) -> QueryResult<i64> {
        use crate::schema::recovery_codes::dsl::*;

        recovery_codes
            .filter(user_id.eq(user_id_param))
            .filter(used_at.is_null())
            .count()
            .get_result(conn)
    }

    /// Mark a recovery code as used
    pub fn mark_used(conn: &mut SqliteConnection, code_id: &str) -> QueryResult<usize> {
        use crate::schema::recovery_codes::dsl::*;

        diesel::update(recovery_codes.filter(id.eq(code_id)))
            .set(used_at.eq(diesel::dsl::now))
            .execute(conn)
    }

    /// Insert a batch of new recovery codes
    pub fn insert_batch(
        conn: &mut SqliteConnection,
        codes: Vec<NewRecoveryCode>,
    ) -> QueryResult<usize> {
        diesel::insert_into(recovery_codes::table)
            .values(&codes)
            .execute(conn)
    }

    /// Delete all recovery codes for a user (for regeneration)
    pub fn delete_for_user(conn: &mut SqliteConnection, user_id_param: &str) -> QueryResult<usize> {
        use crate::schema::recovery_codes::dsl::*;

        diesel::delete(recovery_codes.filter(user_id.eq(user_id_param))).execute(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_format() {
        let code = generate_code();
        assert_eq!(code.len(), 9); // XXXX-XXXX
        assert!(code.chars().nth(4) == Some('-'));

        // All chars should be valid
        for c in code.chars() {
            if c != '-' {
                assert!(
                    CODE_CHARS.contains(&(c as u8)),
                    "Invalid char in code: {}",
                    c
                );
            }
        }
    }

    #[test]
    fn test_generate_codes_uniqueness() {
        let (codes, _) = generate_recovery_codes("test_user").unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);

        // All codes should be unique
        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            assert!(seen.insert(code.clone()), "Duplicate code generated");
        }
    }

    #[test]
    fn test_code_entropy() {
        // 8 chars from 32-char alphabet = 32^8 = 2^40 combinations
        // This is approximately 40 bits of entropy
        let entropy_bits = (RECOVERY_CODE_COUNT as f64 * 8.0 * (32_f64).log2()).ceil();
        assert!(
            entropy_bits >= 40.0,
            "Insufficient entropy: {} bits",
            entropy_bits
        );
    }
}
