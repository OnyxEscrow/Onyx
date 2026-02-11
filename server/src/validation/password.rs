//! Password strength validation using zxcvbn
//!
//! P0 Security: Ensures passwords meet minimum security requirements
//! beyond simple length checks.

use zxcvbn::{zxcvbn, Score};

/// Minimum password score (0-4 scale, 2 = "fair", 3 = "good")
pub const MIN_PASSWORD_SCORE: Score = Score::Two;

/// Minimum password length
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum password length (prevent DoS via long password hashing)
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// Password validation result
#[derive(Debug)]
pub struct PasswordValidation {
    pub is_valid: bool,
    pub score: Score,
    pub feedback: Vec<String>,
    pub crack_time_display: String,
}

/// Validate password strength using zxcvbn
///
/// # Arguments
/// * `password` - The password to validate
/// * `user_inputs` - Optional context (username, email) to penalize if used in password
///
/// # Returns
/// * `PasswordValidation` with score, feedback, and validity
pub fn validate_password_strength(password: &str, user_inputs: &[&str]) -> PasswordValidation {
    // Length checks
    if password.len() < MIN_PASSWORD_LENGTH {
        return PasswordValidation {
            is_valid: false,
            score: Score::Zero,
            feedback: vec![format!(
                "Password must be at least {} characters",
                MIN_PASSWORD_LENGTH
            )],
            crack_time_display: "instant".to_string(),
        };
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return PasswordValidation {
            is_valid: false,
            score: Score::Zero,
            feedback: vec![format!(
                "Password cannot exceed {} characters",
                MAX_PASSWORD_LENGTH
            )],
            crack_time_display: "N/A".to_string(),
        };
    }

    // Run zxcvbn analysis
    let entropy = zxcvbn(password, user_inputs);
    let score = entropy.score();

    // Collect feedback
    let mut feedback_messages = Vec::new();

    if let Some(feedback) = entropy.feedback() {
        if let Some(warning) = feedback.warning() {
            feedback_messages.push(format!("Warning: {warning}"));
        }
        for suggestion in feedback.suggestions() {
            feedback_messages.push(format!("Suggestion: {suggestion}"));
        }
    }

    // Get crack time display
    let crack_time = entropy
        .crack_times()
        .offline_slow_hashing_1e4_per_second()
        .to_string();

    let is_valid = score >= MIN_PASSWORD_SCORE;

    if !is_valid && feedback_messages.is_empty() {
        feedback_messages.push(
            "Password is too weak. Try adding numbers, symbols, or making it longer.".to_string(),
        );
    }

    PasswordValidation {
        is_valid,
        score,
        feedback: feedback_messages,
        crack_time_display: crack_time,
    }
}

/// Get human-readable score description
pub fn score_description(score: Score) -> &'static str {
    match score {
        Score::Zero => "Very weak",
        Score::One => "Weak",
        Score::Two => "Fair",
        Score::Three => "Strong",
        Score::Four => "Very strong",
        _ => "Unknown",
    }
}

/// Format validation result as user-friendly error message
pub fn format_validation_error(validation: &PasswordValidation) -> String {
    let mut parts = vec![format!(
        "Password strength: {} ({})",
        score_description(validation.score),
        validation.crack_time_display
    )];

    for fb in &validation.feedback {
        parts.push(fb.clone());
    }

    parts.join(". ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_password() {
        let result = validate_password_strength("password123", &[]);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_strong_password() {
        let result = validate_password_strength("c0rr3ct-h0rs3-b4tt3ry-st4pl3!", &[]);
        assert!(result.is_valid);
    }

    #[test]
    fn test_too_short() {
        let result = validate_password_strength("abc", &[]);
        assert!(!result.is_valid);
        assert!(result.feedback[0].contains("at least"));
    }

    #[test]
    fn test_username_in_password() {
        let result = validate_password_strength("username123!", &["username"]);
        // Should penalize using username in password - typically reduces score
        // Just verify we get some feedback or reduced validity
        assert!(!result.feedback.is_empty() || !result.is_valid);
    }
}
