-- Rollback audit_events table
DROP TRIGGER IF EXISTS audit_events_no_delete;
DROP TRIGGER IF EXISTS audit_events_no_update;
DROP INDEX IF EXISTS idx_audit_type_time;
DROP INDEX IF EXISTS idx_audit_request_id;
DROP INDEX IF EXISTS idx_audit_org;
DROP INDEX IF EXISTS idx_audit_event_type;
DROP INDEX IF EXISTS idx_audit_resource;
DROP INDEX IF EXISTS idx_audit_actor;
DROP INDEX IF EXISTS idx_audit_timestamp;
DROP TABLE IF EXISTS audit_events;
