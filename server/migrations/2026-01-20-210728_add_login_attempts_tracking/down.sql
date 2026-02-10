-- Rollback login attempts tracking
DROP INDEX IF EXISTS idx_login_attempts_username_type_time;
DROP INDEX IF EXISTS idx_login_attempts_created_at;
DROP INDEX IF EXISTS idx_login_attempts_username;
DROP TABLE IF EXISTS login_attempts;
