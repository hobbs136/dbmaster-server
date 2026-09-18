# DbMaster Health-Check Webhook — `dbmaster.health-event.v1` Payload Contract

- **Status**: Locked at v1 health-check release (ADR-0004 §2.5 / M6 T31)
- **Schema identifier**: the literal string `dbmaster.health-event.v1`, carried in the payload's top-level `schema` field.
- **Authoritative sources**: this document plus `crates/health_check/src/notify.rs` (payload struct, delivery loop) and `crates/health_check/src/alert.rs` (severity / trigger / detail shapes). Where the ADR draft and the implementation differ, **the implementation wins**.
- **Evolution rule** (定律 2 / ADR-0004 §2.5): append-only. Existing fields will not be renamed or removed. New `metric` values, `severity` values, and `detail` sub-fields may be appended. v2 additions (e.g., HMAC signature header) are required to remain backward-compatible with v1 receivers.

This is the contract between DbMaster Server and customer webhook receivers. Customers build receivers against this document, not against the ADR draft.

---

## 1. When the webhook fires

For each enabled `task_type = 'health_check'` task, the scheduler (`crates/health_check/src/scheduler.rs`) ticks on a 60-second scan cadence and decides due-ness from the task's `cron_expr` (5-field, evaluated in UTC) plus `scheduled_tasks.last_run_at`.

Per due run (`crates/health_check/src/runner.rs`):

1. The runner opens a `task_run_history` row with `status = 'running'`.
2. The task + source connection rows are loaded; `config` JSON is parsed into `HealthCheckTaskConfig`.
3. The source-DB credential is decrypted. For `database_connections.kind = 'source_drift'`, a read-only canary (`CREATE TEMP TABLE` probe) re-validates the account is read-only — aborts the run if writable (defence in depth).
4. A short-lived source-DB pool is opened (MySQL / PostgreSQL only; `max_connections = 2`).
5. The 4 core metrics are collected (see §2.3 for per-metric semantics). Non-MySQL/PG connections degrade to connectivity-only.
6. Per-metric alert state is evaluated against the persisted prior state (`health_alert_state`):
   - **Threshold metrics** (connectivity / row_count / connection_count): a consecutive-failure counter provides flap suppression. `Failing → Alerting` fires after `config.fail_threshold` consecutive failing samples.
   - **Structural metric** (missing_pk): set-difference against the prior missing-PK table set.
7. **Trigger condition**: each `AlertChange` produced by step 6 fires **its own webhook** (one event per change, so receivers can dedupe by `event_id` and route by `metric` without parsing a list).
8. The run result is persisted to `health_check_results` regardless of whether any webhook fired.

First-run baseline: when no prior `health_alert_state` row exists, the first sample establishes baseline WITHOUT alerting — even connectivity starts the `Failing` counter rather than alerting immediately (a transient blip is indistinguishable from a real outage on first contact; the cost of a delayed alert is far lower than a false-positive page).

---

## 2. Payload schema

```json
{
  "schema": "dbmaster.health-event.v1",
  "event_id": "<uuid v4>",
  "event_at": "<RFC3339 UTC>",
  "instance_uuid": "<server install uuid>",
  "task": { "id": "<scheduled_task_id>", "name": "<human label>" },
  "connection": { "id": "<connection_id>", "name": "<human label>" },
  "source": { "db_type": "mysql|postgres|...", "database": "<db name>" },
  "alert": {
    "metric": "connectivity|row_count|missing_pk|connection_count",
    "severity": "critical|warning|info",
    "state": "alert|resolved",
    "detail": { "...metric-specific context..." }
  }
}
```

### 2.1 Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema` | string (const) | Always the literal `"dbmaster.health-event.v1"`. Receivers should dispatch by this value and refuse payloads carrying a different schema. |
| `event_id` | string (uuid v4) | Unique per delivery. Receivers should deduplicate by this id (the server does not intentionally re-deliver the same `event_id`). |
| `event_at` | string (RFC3339) | UTC timestamp the payload was constructed. |
| `instance_uuid` | string | The server's random install UUID. Not a PII field — corresponds to no end-user identity. Useful when a customer operates multiple server instances. |
| `task` | object | Reference to the scheduled task. `id` is the task row id; `name` is the customer-supplied human label (customer's responsibility for any PII embedded in it). |
| `connection` | object | Reference to the source-DB connection. `id` is the connection row id; `name` is the customer-supplied label. |
| `source` | object | Source DB descriptor. `db_type` is lowercase (`"mysql"`, `"postgres"`, etc.). `database` is the database name that was probed. **No host, port, user, or password is ever carried** — structurally enforced by the payload type. |
| `alert` | object | The alert block (see §2.2). Exactly one alert per payload. |

### 2.2 `alert`

| Field | Type | Meaning |
|---|---|---|
| `metric` | string (enum) | One of `connectivity`, `row_count`, `missing_pk`, `connection_count` (see §2.3). |
| `severity` | string (enum) | `critical` (connectivity down), `warning` (threshold exceeded / missing PK detected), `info` (a missing_pk table was restored). |
| `state` | string (enum) | `alert` (newly breached) or `resolved` (recovered). |
| `detail` | object | Metric-specific context (see §2.3). Redacted — no credential / SQL / PII. |

### 2.3 Metrics (locked v1 enumeration)

#### `connectivity`
The `SELECT 1` round-trip probe. `severity: critical` because a connectivity loss means the database is unreachable.

`detail` on `alert`:
```json
{ "consecutive_failures": 3, "latency_ms": 0, "error": "connection refused" }
```
`detail` on `resolved`: `{ "latency_ms": 5, "error": null }` (the success that ended the alert).

#### `row_count`
Tables whose estimated row count exceeds `config.large_table_threshold` (default 10,000,000). `severity: warning`. Note: MySQL `information_schema.tables.table_rows` is an InnoDB estimate; receivers should treat the count as approximate.

`detail` on `alert`:
```json
{
  "consecutive_failures": 3,
  "large_tables": [ { "table": "events", "estimated_rows": 25000000 } ]
}
```
`detail` on `resolved`: `{}` (empty object).

#### `missing_pk`
Base tables lacking a PRIMARY KEY. `severity: warning` on `alert`, `info` on `resolved`. **Set-difference alerting** (not consecutive-count): each newly-missing table fires its own `alert` webhook; each restored table (gained a PK) fires its own `resolved` webhook.

`detail` always carries the single table that changed:
```json
{ "table": "audit_log" }
```

#### `connection_count`
Active connection count exceeds `config.connection_count_threshold` (default 100). `severity: warning`.

`detail`:
```json
{ "consecutive_failures": 3, "current": 142, "threshold": 100 }
```

---

## 3. Delivery semantics

### 3.1 HTTP request

- **Method**: `POST`.
- **URL**: per-task. The server reads the first element of `scheduled_tasks.notify_channels` (a JSON array of `{"url": "..."}` objects). There is **no global default URL** — this is deliberate, to prevent test webhooks being sent to production endpoints when an operator forgets to override.
- **Headers**:
  - `Content-Type: application/json`
  - `User-Agent: dbmaster-server/<version> health-check-webhook` (e.g., `dbmaster-server/0.1.0 health-check-webhook`).
- **Body**: the JSON payload (compact form; whitespace is not significant).

### 3.2 URL scheme rule (定律 5 — payload never traverses a plaintext link)

The URL must satisfy one of:

- `https://` — accepted in any mode.
- `http://localhost`, `http://127.0.0.1`, or `http://[::1]` — **dev mode only** (loopback only).

Anything else (`http://` to a non-loopback host, `file://`, `ftp://`, etc.) is rejected before any network call with a permanent error. In production mode, even loopback http is refused — use `https://`, or set `DBMASTER_DEV=1` to enable dev-mode loopback.

### 3.3 Timeout, retries, permanent failure

- **Per-request timeout**: 10 seconds (`DEFAULT_TIMEOUT_SECS`). Applies independently to each attempt.
- **Retry schedule**: 3 retries with exponential backoff — **1s, 4s, 16s** between attempts. Total attempts per delivery: 4 (initial + 3 retries).
- **Success criterion**: HTTP status `2xx` (200–299, inclusive). Anything else — 3xx, 4xx, 5xx, transport error, or timeout — triggers the next retry.
- **Permanent failure**: after all 4 attempts fail, the delivery is abandoned. The runner records the failure in the run summary (last HTTP status code + last error string) and emits a WARN-level log. The failure is **never silently swallowed**. The `health_check_results` row is preserved (the alert is a fact; a delivery failure is an alerting problem).

### 3.4 Idempotency

- Each delivery carries a unique `event_id` (uuid v4). Receivers should deduplicate by `event_id`.
- A given alert state transition fires at most once. The `Alerting` state suppresses re-alerting on continued failure; only the `Alerting → Ok` transition fires a `resolved` webhook.

### 3.5 What the payload never carries (定律 5 hard exclusion)

Structurally impossible — the payload type has no fields for these, so they cannot leak even by accident:

- Source-DB **host**, **port**, **user**, **password** (in any form).
- Source-DB **row data**. The probes read metadata / catalog rows / status counters only; business rows are never selected.
- Customer **PII**. `instance_uuid` is a random server-generated UUID (no end-user identity). `task.name` and `connection.name` are customer-supplied labels — the customer is responsible for not embedding PII in them.

A test in `crates/health_check/src/notify.rs` (`payload_excludes_connection_credentials_by_construction`) grep-asserts the serialized JSON cannot contain `host`, `port`, `user`, or `password` keys.

---

## 4. v2 evolution (non-breaking)

The following are candidates for v2 and will be added in a way that does not break v1 receivers:

- **HMAC signature header.** A `X-DbMaster-Signature: sha256=<hex>` header carrying an HMAC of the body under a customer-configured secret.
- **New metrics** appended to the v1 enumeration (e.g., `index_effectiveness`, `table_bloat`, `replication_lag`). Existing receivers that switch on `metric` should keep a default branch.
- **Multi-channel delivery** (Slack / Feishu / DingTalk / email). The generic webhook stays.
- **Alert aggregation** (batch multiple changes into one payload with an `alerts[]` array). v1 carries one alert per payload; v2 would add the array form alongside.
- **SSRF allowlist** to restrict webhook target hosts.

A schema-version bump (e.g., `dbmaster.health-event.v2`) would occur only for an **incompatible** change (field rename / removal / semantic shift). The v1 commitment is that no such change will be made to v1; new payload variants get a new schema identifier.

---

## 5. Footnotes — design decisions

¹ **One-webhook-per-change** (vs. one-webhook-per-run). v1 emits a separate payload for each `AlertChange` a run produces. A run that newly detects 3 missing-PK tables + a connectivity failure fires 4 webhooks (3 `missing_pk` alerts + 1 `connectivity` alert). This lets receivers route by `metric` / `severity` without parsing a list, and dedupe per-change. The trade-off is more HTTP requests on a noisy run; receivers that prefer batching can correlate by `event_at` proximity (all changes from one run share the same `event_at` second).

² **First-run baseline + flap suppression apply uniformly.** ADR-0004 brainstorm floated a "connectivity first-run exception" (immediate alert on first failure). The implementation (`crates/health_check/src/alert.rs`) chose NOT to special-case connectivity: even a first-contact failure starts the `Failing` counter and must reach `fail_threshold` consecutive failures before alerting. Rationale: a single transient blip on first contact is indistinguishable from a real outage, and the cost of a delayed alert (`fail_threshold × cron-interval` seconds) is far lower than the cost of a false-positive page.

³ **Per-metric independent delivery.** If one metric's webhook delivery fails (after all retries), the other metrics' deliveries in the same run are unaffected — each `deliver()` call is independent. A run with 4 alert changes where 1 delivery ultimately fails still records `webhook_status: "failed"` in `health_check_results` (any_fail wins), but the 3 successful deliveries are not rolled back.
