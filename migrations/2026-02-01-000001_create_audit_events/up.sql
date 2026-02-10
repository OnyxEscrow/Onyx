-- Audit Events table for SOC2/GDPR compliance
-- Append-only, tamper-evident audit log

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL,               -- ULID (sortable, unique)
    timestamp TEXT NOT NULL,                    -- ISO8601 UTC
    event_type TEXT NOT NULL,                   -- 'escrow.created', 'auth.login', etc.
    actor_id TEXT,                              -- User/API key who performed the action
    actor_type TEXT NOT NULL,                   -- 'user', 'api_key', 'system', 'arbiter'
    org_id TEXT,                                -- For future multi-tenancy (nullable)
    resource_type TEXT,                         -- 'escrow', 'user', 'api_key'
    resource_id TEXT,                           -- ID of affected resource
    action TEXT NOT NULL,                       -- 'create', 'update', 'delete', 'read'
    ip_hash TEXT,                               -- SHA256(IP) - never raw IP (GDPR)
    user_agent TEXT,                            -- Browser/client info
    request_id TEXT,                            -- X-Request-ID for distributed tracing
    old_value TEXT,                             -- JSON serialized previous state
    new_value TEXT,                             -- JSON serialized new state
    metadata TEXT DEFAULT '{}',                 -- Extra context as JSON

    -- Tamper evidence (blockchain-style chaining)
    prev_hash TEXT,                             -- Hash of previous record
    record_hash TEXT NOT NULL                   -- SHA256(all fields + prev_hash)
);

-- Indexes for common query patterns
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_actor ON audit_events(actor_id);
CREATE INDEX idx_audit_resource ON audit_events(resource_type, resource_id);
CREATE INDEX idx_audit_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_org ON audit_events(org_id);
CREATE INDEX idx_audit_request_id ON audit_events(request_id);

-- Composite index for time-range queries with filtering
CREATE INDEX idx_audit_type_time ON audit_events(event_type, timestamp);

-- Prevent updates and deletes (append-only enforcement)
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'Audit events are immutable - updates forbidden');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'Audit events are immutable - deletes forbidden');
END;
