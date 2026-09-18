-- ADR-0003 S3 — extend database_connections to carry the full client DbServer
-- shape so connections migrated from the client keychain round-trip without
-- field loss.
--
-- Background: the client (Flutter) DbServer carries many fields the original
-- schema (002/005/007) doesn't: SSL/timeout/charset/timezone/environment/
-- read-only/group, MongoDB-cluster `extra`, and full SSH credentials. S3
-- migrates SQL-library connections (mysql/postgres/sqlite) to this table.
-- Without these columns the migration would silently drop configuration.
--
-- All new columns are nullable or have defaults so existing rows (drift
-- source connections, legacy collab connections) continue to work unchanged.

-- ── Client connection options (apply to mysql/postgres) ──
ALTER TABLE database_connections ADD COLUMN use_ssl INTEGER NOT NULL DEFAULT 0;
ALTER TABLE database_connections ADD COLUMN timeout_seconds INTEGER NOT NULL DEFAULT 30;
ALTER TABLE database_connections ADD COLUMN auto_reconnect INTEGER NOT NULL DEFAULT 0;
ALTER TABLE database_connections ADD COLUMN charset TEXT;
ALTER TABLE database_connections ADD COLUMN timezone TEXT;
ALTER TABLE database_connections ADD COLUMN environment TEXT;
ALTER TABLE database_connections ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0;
ALTER TABLE database_connections ADD COLUMN group_id TEXT;

-- MongoDB cluster config / Redis auth mode / other vendor-specific options.
-- Stored as a JSON blob; consumers decode on read.
ALTER TABLE database_connections ADD COLUMN extra TEXT;

-- ── SSH tunnel credentials (002 only stored ssh_enabled/host/port) ──
ALTER TABLE database_connections ADD COLUMN ssh_username TEXT;
ALTER TABLE database_connections ADD COLUMN ssh_auth_mode TEXT;   -- 'password' | 'privateKey'
ALTER TABLE database_connections ADD COLUMN ssh_password_encrypted TEXT;
ALTER TABLE database_connections ADD COLUMN ssh_private_key_encrypted TEXT;
ALTER TABLE database_connections ADD COLUMN ssh_passphrase_encrypted TEXT;
