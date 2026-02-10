ALTER TABLE escrows ADD COLUMN client_id TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN metadata_json TEXT DEFAULT NULL;
CREATE INDEX idx_escrows_client_id ON escrows(client_id);
