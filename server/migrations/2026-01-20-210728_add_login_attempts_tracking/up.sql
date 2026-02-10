-- Login attempts tracking for per-username brute-force protection
-- P0 Security: Tracks failed login attempts per username (not just IP)

CREATE TABLE login_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT,
    attempt_type TEXT NOT NULL DEFAULT 'failed' CHECK(attempt_type IN ('failed', 'success', 'lockout')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast lookup by username (most common query)
CREATE INDEX idx_login_attempts_username ON login_attempts(username);

-- Index for cleanup of old attempts
CREATE INDEX idx_login_attempts_created_at ON login_attempts(created_at);

-- Composite index for checking recent failed attempts per username
CREATE INDEX idx_login_attempts_username_type_time ON login_attempts(username, attempt_type, created_at);
