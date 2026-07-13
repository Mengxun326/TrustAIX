CREATE TABLE IF NOT EXISTS audit_events (
  event_id TEXT PRIMARY KEY, payload JSONB NOT NULL, evaluated_at TIMESTAMPTZ NOT NULL, tenant_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_tenant_time ON audit_events (tenant_id, evaluated_at DESC);
CREATE TABLE IF NOT EXISTS audit_feedback (
  event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id) ON DELETE CASCADE,
  verdict TEXT NOT NULL, note TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, document JSONB NOT NULL, status TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, note TEXT NOT NULL, parent_id TEXT,
  approved_by TEXT, approved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS policy_versions_tenant_status ON policy_versions (tenant_id, status, created_at DESC);
