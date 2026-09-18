-- MCP endpoint audit log (dbx-response T04 / ADR-0005 §2.2).
--
-- Append-only transport-level security audit for `/mcp`: authentication
-- rejections, rate-limit rejections, and session lifecycle events. Tool-call
-- level audit (tool name + risk class only) joins in T06/T07 when the tool
-- surface lands.
--
-- Hard rule (mirrors credential_access_audit / ADR §4.2.4): NO SQL text, NO
-- credentials, NO returned data, NO PII in any column. `error` carries a
-- short redacted summary only.
--
-- 'user_id' is the JWT subject; NULL for pre-auth rejections (unknown caller).
-- 'action' values: 'auth_rejected' | 'rate_limited' | 'session_close'.
-- 'status' values: 'ok' | 'error'.
CREATE TABLE IF NOT EXISTS mcp_audit (
    id      TEXT PRIMARY KEY,
    user_id TEXT,
    action  TEXT NOT NULL,
    status  TEXT NOT NULL,
    error   TEXT,
    at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mcp_audit_time ON mcp_audit(at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_user_time ON mcp_audit(user_id, at DESC);
