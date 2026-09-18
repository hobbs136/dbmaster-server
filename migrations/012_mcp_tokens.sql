-- Long-lived MCP personal tokens (dbx-response T04 follow-up; user decision
-- 2026-08-15: MCP token lifecycle = 长效 MCP 专用 token，可删除/吊销).
--
-- Solves the 15-minute access-JWT expiry problem for static client configs
-- (Claude Code / Cursor mcp.json): tokens are opaque high-entropy strings
-- with no expiry by design; revocation is the deletion path.
--
-- Only a sha256 of the token is stored — the plaintext is returned exactly
-- once at creation and never recoverable afterwards.
--
-- 'token_prefix' is the first characters of the plaintext (e.g.
-- 'dbm_mcp_9f2a…') kept for user recognition in list views, the same way
-- GitHub PATs display a short prefix.
-- 'revoked_at' non-NULL = soft-deleted (rows retained as audit trail;
-- lookups must always filter revoked_at IS NULL).
CREATE TABLE IF NOT EXISTS mcp_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT 'MCP token',
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_tokens_user ON mcp_tokens(user_id, created_at DESC);
