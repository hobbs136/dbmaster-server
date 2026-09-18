-- Instance metadata: install_uuid + trial window (ADR-0001 D4=A / D5=A).
-- Single conceptual row: install_uuid is generated once on first launch.
-- DEFENSIVE-NOTE: 删行重置是诚实用户模式接受的语义（ADR §4.4 / §6），不在此防御。
-- CHANGE: ADR-0001 §7.1 — new table for instance fingerprint + trial state.

CREATE TABLE IF NOT EXISTS instance_meta (
    install_uuid        TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    trial_started_at    TEXT,
    trial_expires_at    TEXT
);
