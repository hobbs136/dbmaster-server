-- Telemetry funnel schema delta (telemetry-funnel-plan.md §6.4).
-- Adds the columns + unique index needed for: app-version slicing,
-- idempotency-keyed dedup, and redacted-IP storage.

-- CHANGE: telemetry-funnel-plan.md §6.1.2 — promote app_version to a
-- first-class column so funnel metrics can GROUP BY version.
ALTER TABLE telemetry_events ADD COLUMN app_version TEXT;

-- CHANGE: telemetry-funnel-plan.md §6.1.5 — idempotency key (client-generated
-- UUID v4 per event). NULL for legacy clients; the partial unique index below
-- excludes them so dedup only applies when the key is present.
ALTER TABLE telemetry_events ADD COLUMN idempotency_key TEXT;

-- client_ip_redacted already exists (002_automation.sql) and is now actually
-- populated by the ingestion handler — no schema change needed here.

-- CHANGE: telemetry-funnel-plan.md §6.1.5 — idempotency unique index. A retry
-- with the same (install_uuid, event_type, idempotency_key) trips this and is
-- reported as a successful dedup rather than a duplicate insert.
-- Partial index (WHERE idempotency_key IS NOT NULL) so legacy events without
-- a key remain insertable.
CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_idempotency
  ON telemetry_events(install_uuid, event_type, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
