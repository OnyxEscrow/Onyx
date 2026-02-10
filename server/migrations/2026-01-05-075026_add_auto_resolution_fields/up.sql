-- Add auto-resolution fields to escrows table for dispute timeout escalation
-- evidence_count tracks how many evidence files have been uploaded
-- auto_escalated_at records when dispute was auto-escalated after 7-day timeout
-- escalation_reason explains why the escalation occurred
ALTER TABLE escrows ADD COLUMN evidence_count INTEGER;
ALTER TABLE escrows ADD COLUMN auto_escalated_at TIMESTAMP;
ALTER TABLE escrows ADD COLUMN escalation_reason TEXT;
