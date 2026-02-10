//! P0 Security: Registration rate limiting
//!
//! Prevents automated account creation attacks by limiting registration
//! attempts per IP address.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum registrations per IP within the time window
const MAX_REGISTRATIONS_PER_IP: u32 = 5;

/// Time window for registration rate limiting (1 hour)
const REGISTRATION_WINDOW_SECS: u64 = 3600;

/// Thread-safe storage for registration attempts
pub type RegistrationRateLimitStorage = Arc<Mutex<HashMap<String, Vec<Instant>>>>;

/// Create a new registration rate limit storage
pub fn new_registration_rate_limit_storage() -> RegistrationRateLimitStorage {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Check if IP is allowed to register
/// Returns Ok(()) if allowed, Err(seconds_until_allowed) if rate limited
pub fn check_registration_rate_limit(
    storage: &RegistrationRateLimitStorage,
    ip: &str,
) -> Result<(), u64> {
    let mut limits = match storage.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = Instant::now();
    let window = Duration::from_secs(REGISTRATION_WINDOW_SECS);

    // Get or create entry for this IP
    let attempts = limits.entry(ip.to_string()).or_insert_with(Vec::new);

    // Remove old attempts outside the window
    attempts.retain(|&instant| now.duration_since(instant) < window);

    if attempts.len() >= MAX_REGISTRATIONS_PER_IP as usize {
        // Calculate when the oldest attempt will expire
        if let Some(oldest) = attempts.first() {
            let elapsed = now.duration_since(*oldest);
            let remaining = REGISTRATION_WINDOW_SECS - elapsed.as_secs();
            return Err(remaining);
        }
        return Err(REGISTRATION_WINDOW_SECS);
    }

    Ok(())
}

/// Record a registration attempt
pub fn record_registration_attempt(storage: &RegistrationRateLimitStorage, ip: &str) {
    let mut limits = match storage.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let attempts = limits.entry(ip.to_string()).or_insert_with(Vec::new);
    attempts.push(Instant::now());
}

/// Get remaining registration attempts for an IP
pub fn remaining_registrations(storage: &RegistrationRateLimitStorage, ip: &str) -> u32 {
    let limits = match storage.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = Instant::now();
    let window = Duration::from_secs(REGISTRATION_WINDOW_SECS);

    if let Some(attempts) = limits.get(ip) {
        let valid_attempts = attempts
            .iter()
            .filter(|&&instant| now.duration_since(instant) < window)
            .count();
        MAX_REGISTRATIONS_PER_IP.saturating_sub(valid_attempts as u32)
    } else {
        MAX_REGISTRATIONS_PER_IP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_registration_rate_limit() {
        let storage = new_registration_rate_limit_storage();
        let ip = "192.168.1.1";

        // First 5 registrations should be allowed
        for _ in 0..5 {
            assert!(check_registration_rate_limit(&storage, ip).is_ok());
            record_registration_attempt(&storage, ip);
        }

        // 6th should be blocked
        assert!(check_registration_rate_limit(&storage, ip).is_err());
    }

    #[test]
    fn test_different_ips() {
        let storage = new_registration_rate_limit_storage();

        // Fill up IP1
        for _ in 0..5 {
            assert!(check_registration_rate_limit(&storage, "ip1").is_ok());
            record_registration_attempt(&storage, "ip1");
        }

        // IP2 should still be allowed
        assert!(check_registration_rate_limit(&storage, "ip2").is_ok());
    }

    #[test]
    fn test_remaining_count() {
        let storage = new_registration_rate_limit_storage();
        let ip = "test_ip";

        assert_eq!(remaining_registrations(&storage, ip), 5);

        record_registration_attempt(&storage, ip);
        assert_eq!(remaining_registrations(&storage, ip), 4);

        record_registration_attempt(&storage, ip);
        assert_eq!(remaining_registrations(&storage, ip), 3);
    }
}
