-- DB gateway API v1 audit log (dbx-response T27 / ADR-0005 §2.2).
--
-- Append-only transport-level security audit for `/api/gw/*`: authentication
-- rejections, rate-limit rejections, query executions (outcome only), and
-- connection-registration lifecycle. Mirrors mcp_audit (migration 011)
-- discipline — separate table because the gateway is a distinct surface with
-- its own action vocabulary.
--
-- Hard rule (same as 011): NO SQL text, NO credentials, NO returned data,
-- NO PII in any column. `error` carries a short redacted summary only
-- (query rows store the stable error CODE, never engine message).
--
-- 'user_id' is the JWT subject; NULL for pre-auth rejections.
-- 'action' values: 'auth_rejected' | 'rate_limited' | 'query_exec'
--                  | 'connection_registered' | 'connection_removed'.
-- 'status' values: 'ok' | 'error'.
CREATE TABLE IF NOT EXISTS gw_audit (
    id      TEXT PRIMARY KEY,
    user_id TEXT,
    action  TEXT NOT NULL,
    status  TEXT NOT NULL,
    error   TEXT,
    at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gw_audit_time ON gw_audit(at DESC);
CREATE INDEX IF NOT EXISTS idx_gw_audit_user_time ON gw_audit(user_id, at DESC);
