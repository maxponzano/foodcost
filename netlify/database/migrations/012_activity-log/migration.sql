-- Registro delle attività dei clienti (accessi e modifiche), visibile solo al super admin; si tiene 12 mesi
CREATE TABLE activity_log (
  id         BIGSERIAL PRIMARY KEY,
  at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
  user_label TEXT NOT NULL DEFAULT '',
  tenant_id  UUID REFERENCES tenants(id) ON DELETE CASCADE,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  device     TEXT NOT NULL DEFAULT '',
  ckey       TEXT
);
CREATE INDEX activity_log_at_idx ON activity_log(at DESC);
CREATE INDEX activity_log_tenant_idx ON activity_log(tenant_id, at DESC);
CREATE INDEX activity_log_user_idx ON activity_log(user_id, at DESC);
