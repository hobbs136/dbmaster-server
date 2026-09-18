# DbMaster Drift Webhook — `dbmaster.drift-event.v1` Payload Contract

- **Status**: Locked at v1 schema-drift release (ADR-0002 §4.4.2 / DoD v1-C-18)
- **Schema identifier**: the literal string `dbmaster.drift-event.v1`, carried in the payload's top-level `schema` field.
- **Authoritative sources**: this document plus `crates/drift/src/notify.rs` (payload struct, delivery loop) and `crates/drift/src/diff.rs` (drift kinds, structures). Where the ADR draft and the implementation differ, **the implementation wins**; the difference is footnoted in §5.
- **Evolution rule** (定律 2 / ADR §4.4.2): append-only. Existing fields and drift kinds will not be renamed or removed. New kinds may be appended. v2 additions (e.g., HMAC signature header) are required to remain backward-compatible with v1 receivers.

This is the contract between DbMaster Server and customer webhook receivers. Customers build receivers against this document, not against the ADR draft.

---

## 1. When the webhook fires

For each enabled `task_type = 'schema_drift'` task, the scheduler (`crates/drift/src/scheduler.rs`) ticks on a 60-second scan cadence and decides due-ness from `scheduled_tasks.last_run_at` plus the task's per-task interval (`config.interval_minutes`, falling back to `DBMASTER_DRIFT_DEFAULT_INTERVAL_MINS`, default 30).

Per due run (`crates/drift/src/runner.rs`):

1. The runner opens a `task_run_history` row with `status = 'running'`.
2. The source-DB credential is decrypted (audited as `schema_snapshot`).
3. A short-lived source-DB pool is opened; if `database_connections.kind = 'source_drift'` the read-only canary is re-run (defence in depth; aborts run if account is writable).
4. Schema metadata is collected via parameterised `information_schema` / `pg_catalog` queries — no business-row reads.
5. The result is canonicalised to JSON (BTreeMap-sorted, serde struct order) and SHA-256 hashed.
6. The new hash is compared to the prior snapshot's hash for the same connection.
7. **Trigger condition**: `prior exists AND prior.schema_hash != new_hash AND compute_drifts(prior, new).len() > 0`. Identical hashes produce no webhook. A first snapshot (no prior) produces no webhook. A snapshot pair whose hash differs but yields zero enumerated drifts also produces no webhook (see §2.3.3 for the cases).
8. If triggered, exactly one webhook is delivered for that snapshot pair.

The new snapshot row is always inserted (append-only, hash-chained) regardless of whether the webhook fires.

---

## 2. Payload schema

```json
{
  "schema": "dbmaster.drift-event.v1",
  "event_id": "<uuid v4>",
  "event_at": "<RFC3339 UTC>",
  "instance_uuid": "<server install uuid>",
  "task": { "id": "<scheduled_task_id>", "name": "<human label>" },
  "connection": { "id": "<connection_id>", "name": "<human label>" },
  "source": { "db_type": "mysql|postgres", "database": "<db name>" },
  "drift_summary": {
    "prior_snapshot_at": "<RFC3339 or null>",
    "new_snapshot_at": "<RFC3339>",
    "change_count": <u32>,
    "kinds": {
      "table_added": <u32>,
      "table_dropped": <u32>,
      "column_added": <u32>,
      "column_dropped": <u32>,
      "column_type_changed": <u32>,
      "column_nullability_changed": <u32>,
      "index_added": <u32>,
      "index_dropped": <u32>,
      "pk_changed": <u32>,
      "fk_added": <u32>,
      "fk_dropped": <u32>
    }
  },
  "drifts": [
    {
      "kind": "<one of the 11 kinds>",
      "object": { "schema": "...", "table": "...", "column": "...", "index": "..." },
      "before": <JSON value or null>,
      "after":  <JSON value or null>
    }
  ]
}
```

### 2.1 Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema` | string (const) | Always the literal `"dbmaster.drift-event.v1"`. Receivers should dispatch by this value and refuse payloads carrying a different schema. |
| `event_id` | string (uuid v4) | Unique per delivery. Receivers should deduplicate by this id (the server does not intentionally re-deliver the same `event_id`). |
| `event_at` | string (RFC3339) | UTC timestamp the payload was constructed. Distinct from `new_snapshot_at` (when the snapshot was taken). |
| `instance_uuid` | string | The server's random install UUID. Not a PII field — corresponds to no end-user identity. Useful when a customer operates multiple server instances. |
| `task` | object | Reference to the scheduled task. `id` is the task row id; `name` is the customer-supplied human label (customer's responsibility for any PII embedded in it). |
| `connection` | object | Reference to the source-DB connection. `id` is the connection row id; `name` is the customer-supplied label. |
| `source` | object | Source DB descriptor. `db_type` is `"mysql"` or `"postgres"` (lowercase). `database` is the database name that was introspected. **No host, port, user, or password is ever carried** — structurally enforced by the payload type. |
| `drift_summary` | object | Summary block (see §2.2). |
| `drifts` | array | Full, untruncated list of structural drifts (see §2.3). v1 does not truncate even for large changes. |

### 2.2 `drift_summary`

| Field | Type | Meaning |
|---|---|---|
| `prior_snapshot_at` | string or null | RFC3339 timestamp of the prior snapshot, or `null` if no prior existed. (Per §1, first-snapshot pairs do not fire a webhook; receivers will see this field only when a prior existed.) |
| `new_snapshot_at` | string (RFC3339) | UTC timestamp the new snapshot was captured. |
| `change_count` | u32 | Total number of drift entries across all kinds. Equal to `drifts.length`. |
| `kinds` | object | Per-kind tally. All 11 fields are **always present** (locked v1 enumeration); a kind with zero occurrences carries `0`, never omitted. |

### 2.3 `drifts[]`

Each entry describes one structural change.

```json
{
  "kind": "column_type_changed",
  "object": { "schema": "public", "table": "users", "column": "email" },
  "before": { "data_type": "varchar", "char_max_length": 50, "numeric_precision": null, "numeric_scale": null },
  "after":  { "data_type": "varchar", "char_max_length": 100, "numeric_precision": null, "numeric_scale": null }
}
```

#### 2.3.1 The 11 drift kinds (locked at v1)

| Kind | Meaning | `before` shape | `after` shape |
|---|---|---|---|
| `table_added` | Table present in current, absent in prior. | `null` | `{ "columns": int, "indexes": int, "foreign_keys": int }` (counts) |
| `table_dropped` | Table absent in current, present in prior. | counts | `null` |
| `column_added` | New column on an existing table. | `null` | full column object (see below) |
| `column_dropped` | Column removed from an existing table. | full column object | `null` |
| `column_type_changed` | Any of `data_type`, `char_max_length`, `numeric_precision`, `numeric_scale` differs. | type summary (4 fields) | type summary |
| `column_nullability_changed` | `is_nullable` differs. | boolean | boolean |
| `index_added` | New secondary index. | `null` | `{ "columns": [...], "is_unique": bool }` |
| `index_dropped` | Secondary index removed. | `{ "columns": [...], "is_unique": bool }` | `null` |
| `pk_changed` | Primary key added, removed, or column-list changed. | PK summary or `null` | PK summary or `null` |
| `fk_added` | New foreign key constraint. | `null` | FK summary |
| `fk_dropped` | Foreign key constraint removed. | FK summary | `null` |

**Full column object** (used in `column_added` / `column_dropped`):

```json
{
  "data_type": "varchar",
  "is_nullable": false,
  "column_default": null,
  "char_max_length": 255,
  "numeric_precision": null,
  "numeric_scale": null
}
```

**Type summary** (used in `column_type_changed`):

```json
{ "data_type": "varchar", "char_max_length": 50, "numeric_precision": null, "numeric_scale": null }
```

**PK summary** (used in `pk_changed`):

```json
{ "name": "users_pkey", "columns": ["id"] }
```

`name` is the constraint name (`"PRIMARY"` on MySQL; conventionally `<table>_pkey` on PostgreSQL; may be `null` if the underlying report omitted it). `columns` is in PK order (NOT alphabetical) — order matters for composite PKs.

**Index summary** (used in `index_added` / `index_dropped`):

```json
{ "columns": ["email"], "is_unique": true }
```

`columns` is in index order (NOT alphabetical).

**FK summary** (used in `fk_added` / `fk_dropped`):

```json
{
  "columns": ["user_id"],
  "ref_schema": "public",
  "ref_table": "users",
  "ref_columns": ["id"]
}
```

`columns[i]` maps positionally to `ref_columns[i]`. On MySQL, `ref_schema` is the same database name (MySQL does not support cross-database FKs).

#### 2.3.2 `object` locator

The `object` field carries up to four string sub-fields, each **omitted from the JSON when empty** (serde `skip_serializing_if = "Option::is_none"`):

| Sub-field | When present |
|---|---|
| `schema` | Always present (PG namespace name, or MySQL database name). |
| `table` | Always present (the change is scoped to a table). |
| `column` | Present only for column-level kinds: `column_added`, `column_dropped`, `column_type_changed`, `column_nullability_changed`. |
| `index` | Present for `index_added` / `index_dropped` (carries the index name). **Also used for `fk_added` / `fk_dropped`** to carry the FK constraint name — see footnote ¹. |

So for a column-level drift, expect `{ "schema": ..., "table": ..., "column": ... }` (no `index` key). For an index-level drift, expect `{ "schema": ..., "table": ..., "index": ... }` (no `column` key). For a table-level or PK drift, expect `{ "schema": ..., "table": ... }`.

#### 2.3.3 Changes that move the hash but produce no webhook

The hash moves (so the snapshot chain advances and `schema_snapshots` records a new row), but no drift kind fires, so **no webhook is sent**:

- **`column_default`-only change.** A column's default value changed without any type/nullability change. The 11-kind enumeration has no `column_default_changed` in v1.
- **Index definition change without rename.** E.g., a uniqueness toggle on an existing index. A pure metadata change is silent in v1; a drop+recreate surfaces as `index_dropped` + `index_added`.
- **Foreign-key definition change without rename.** E.g., column re-mapping. A renamed FK surfaces as `fk_dropped` + `fk_added`.

These may be added as new kinds in v2 (ADR §11 Q5) without breaking v1 receivers (append-only).

---

## 3. Delivery semantics

### 3.1 HTTP request

- **Method**: `POST`.
- **URL**: per-task. The server reads the first element of `scheduled_tasks.notify_channels` (a JSON array of strings). There is **no global default URL** — this is deliberate, to prevent test webhooks being sent to production endpoints when an operator forgets to override.
- **Headers**:
  - `Content-Type: application/json`
  - `User-Agent: dbmaster-server/<version> drift-webhook` (e.g., `dbmaster-server/0.1.0 drift-webhook`).
- **Body**: the JSON payload (compact form; whitespace is not significant).

### 3.2 URL scheme rule (定律 5 — payload never traverses a plaintext link)

The URL must satisfy one of:

- `https://` — accepted in any mode.
- `http://localhost`, `http://127.0.0.1`, or `http://[::1]` — **dev mode only** (loopback only).

Anything else (`http://` to a non-loopback host, `file://`, `ftp://`, etc.) is rejected before any network call with a permanent error. In production mode, even loopback http is refused — use `https://`, or set `DBMASTER_DEV=1` to enable dev-mode loopback. (See footnote ² — ADR §4.4.2 lists `localhost` / `127.0.0.1` only; the implementation also accepts the IPv6 loopback `[::1]`.)

### 3.3 Timeout, retries, permanent failure

- **Per-request timeout**: `DBMASTER_DRIFT_WEBHOOK_TIMEOUT_SECS` (default 10 seconds). Applies independently to each attempt.
- **Retry schedule**: 3 retries with exponential backoff — **1s, 4s, 16s** between attempts. Total attempts per delivery: 4 (initial + 3 retries). See footnote ³ for the ADR's "3 retries" phrasing.
- **Success criterion**: HTTP status `2xx` (200–299, inclusive). Anything else — 3xx, 4xx, 5xx, transport error, or timeout — triggers the next retry.
- **Permanent failure**: after all 4 attempts fail, the delivery is abandoned. The runner records the failure in `task_run_history.error` (with the last HTTP status code and last error string) and emits a WARN-level log. The failure is **never silently swallowed**. The credential-use audit row for `webhook_deliver` is also written with `status = 'error'`.
- **Snapshot is preserved on delivery failure.** A webhook failure does not roll back the new `schema_snapshots` row. The drift is a fact (it happened in the source DB); a delivery failure is an alerting problem, not a reason to undo the record. The next snapshot that produces further drift triggers its own webhook; the failed one is not retried on subsequent scheduler ticks.

### 3.4 Idempotency

- Each delivery carries a unique `event_id` (uuid v4). Receivers should deduplicate by `event_id`.
- The server does not intentionally re-deliver the same event. The same drift will not produce a second webhook on subsequent scheduler ticks — the next tick compares the new prior (this run's snapshot) to a new current; if no further drift occurred, hashes match and nothing fires.

### 3.5 What the payload never carries (定律 5 hard exclusion)

Structurally impossible — the payload type has no fields for these, so they cannot leak even by accident:

- Source-DB **host**, **port**, **user**, **password** (in any form).
- Source-DB **row data**. The introspection queries read metadata only; business rows are never selected.
- Customer **PII**. `instance_uuid` is a random server-generated UUID (no end-user identity). `task.name` and `connection.name` are customer-supplied labels — the customer is responsible for not embedding PII in them.

The webhook URL itself is never written to logs (only the masked delivery outcome: HTTP status code or transport error string). A test in `crates/drift/src/notify.rs` (`payload_excludes_connection_secrets`) grep-asserts the serialized JSON cannot contain `host`, `port`, `username`, `user`, or `password` keys.

---

## 4. v2 evolution (non-breaking)

The following are candidates for v2 and will be added in a way that does not break v1 receivers:

- **HMAC signature header.** A `X-DbMaster-Signature: sha256=<hex>` header carrying an HMAC of the body under a customer-configured secret. Receivers that do not check it are unaffected; receivers that want to verify can opt in. (Tracked as v1-C-21.)
- **New drift kinds** appended to the 11-kind enumeration (e.g., `column_default_changed`, `index_changed`, `view_added`). Existing receivers that switch on `kind` should keep a default branch.
- **Multi-channel delivery** (Slack / Feishu / DingTalk / email). The generic webhook stays.
- **SSRF allowlist** to restrict webhook target hosts (v1-C-22).
- **Cron-expression scheduling** (v1-C-23) — would land alongside a possible switch to `tokio-cron-scheduler`. Orthogonal to the payload contract.

A schema-version bump (e.g., `dbmaster.drift-event.v2`) would occur only for an **incompatible** change (field rename / removal / semantic shift). The v1 commitment is that no such change will be made to v1; new payload variants get a new schema identifier.

---

## 5. Footnotes — ADR draft vs implementation

¹ **Object schema for FK drifts.** ADR §4.4.2 lists the `object` fields as `{ schema, table, column, index }` with no `foreign_key` field. The implementation (`crates/drift/src/diff.rs::object_for_fk`) reuses the `index` slot to carry the FK constraint name, on the principle that introducing a new field would expand the locked v1 surface for a single kind. Receivers handling `fk_added` / `fk_dropped` should read the constraint name from `object.index`.

² **Loopback URL acceptance.** ADR §4.4.2 names `http://localhost` and `http://127.0.0.1` as the dev-mode exceptions. The implementation (`crates/drift/src/notify.rs::is_loopback_host`) additionally accepts `http://[::1]` (IPv6 loopback). This is a strict superset of the ADR's allowance and does not weaken the production-mode rule (https-only).

³ **Retry count phrasing.** ADR §4.4.2 phrases the schedule as "3 retries, exponential backoff 1s / 4s / 16s". The implementation treats this as 3 retry intervals between 4 total attempts (initial + 3 retries). These two phrasings describe the same schedule.

⁴ **First-snapshot behaviour.** A connection's first snapshot has no prior to diff against and produces no webhook. `prior_snapshot_at: null` is therefore unreachable in v1 firing payloads; it is kept in the schema for forward-compatibility.

⁵ **Defence-in-depth canary.** ADR §4.2.3 recommends create-time canary (L2) and rules out periodic canary (L3) as over-engineering. The implementation runs the same canary both at connection-create and at the start of every drift run (runner.rs steps before snapshot collection). The runner-path canary is a defence-in-depth against privilege escalation between create-time and run-time, not the periodic L3 of the ADR — it aborts only the run in question, not the scheduler.
