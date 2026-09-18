# DbMaster Server

> **The automation engine that turns DbMaster from a database GUI into your team's DBA.**

DbMaster Server is a self-hosted **database automation engine**: scheduled automation tasks, data synchronization between databases, schema-drift detection, and team collaboration — the things you would otherwise glue together with cron scripts. It pairs with [DbMaster Desktop](https://github.com/hobbs136/dbmaster), the free open-source desktop client, and runs at 2 AM so you don't have to.

**Rust · Axum · Tokio · SQLx · SQLite internal store · single binary or Docker · AGPL-3.0-only**

---

## Why this exists

Your 2–5 person team manages PostgreSQL, MySQL, Redis, and MongoDB. Nobody is a DBA: syncing data between environments means a hand-rolled cron script, and a slow query is noticed days later — when a user complains. DbMaster Server is not another database GUI. It is **proactive database operations for teams without a dedicated DBA**: the desktop client helps you manage databases manually, the server automates what you'd otherwise script by hand.

## What it does

| Capability | What you get | Where |
|---|---|---|
| Scheduled data sync | Paginated, retryable, time-batched ETL between databases; cron scheduling; cancellable runs | `crates/data_sync` |
| Schema drift detection | Snapshot → collect → diff → notify pipeline with webhook alerts; source access is read-only, enforced by canary probes | `crates/drift` |
| Health checks | Connectivity + metric probes (missing indexes, table bloat, connection count) with threshold alerting | `crates/health_check` |
| Slow query statistics & weekly reports | Gateway sampling plus native slow-log / performance-schema collection; 14-day detail + weekly aggregation | migrations 016–019 |
| Team collaboration | Users & JWT auth, workspaces, DDL approval workflow (approve → async execute), credential vault (AES-256-GCM at rest) | `crates/core` · `crates/automation` |
| DB gateway API | `/api/gw/*` metadata + SSE streaming query execution, cancel/timeout with server-side termination, SSH tunneling, TLS pass-through | `crates/gateway` |
| MCP surface for AI agents | Read-only tools plus approval-gated writes over Streamable HTTP | `crates/mcp` |
| License & entitlement | Offline Ed25519 license verification, 14-day trial, runtime entitlement swap | `crates/license` |
| Notifications | Webhook delivery (Slack-compatible) with a retry schedule; `https://`-only outside dev mode | `crates/drift` · `crates/health_check` |

The whole stack is pure Rust — sqlx (MySQL/PostgreSQL/SQLite), tiberius (SQL Server), redis, reqwest with rustls — so there is no OpenSSL/pkg-config setup anywhere, and cross-compiling needs only a linker.

## How it fits together

```
┌──────────────┐     REST (JSON)      ┌──────────────────────┐
│  DbMaster    │ ←─────────────────→  │  DbMaster Server     │
│  Desktop     │                      │  (Rust + Axum)       │
│  (Flutter)   │                      │                      │
│              │                      │  ┌────────────────┐  │
│  Free        │                      │  │ Auth + JWT     │  │
│  Open source │                      │  │ Workspace      │  │
│  Offline OK  │                      │  └────────────────┘  │
└──────┬───────┘                      │  ┌────────────────┐  │
       │ direct                       │  │ Schedulers     │  │
       │ connection                   │  │ Data Sync      │  │
       │ (offline)                    │  │ Drift Watch    │  │
       ↓                              │  │ Health Check   │  │
┌──────────────┐                      │  │ Reports        │  │
│  PostgreSQL  │                      │  └────────────────┘  │
│  MySQL       │                      │  ┌────────────────┐  │
│  Redis       │                      │  │ DB Gateway     │  │
│  MongoDB     │←─── sqlx/etc ────────│  │ MCP / Webhook  │  │
│  SQL Server  │                      │  └────────────────┘  │
│  ...         │                      │                      │
└──────────────┘                      │  SQLite (internal)   │
                                      └──────────────────────┘
```

- **Desktop client** ([github.com/hobbs136/dbmaster](https://github.com/hobbs136/dbmaster)) works fully offline with direct database connections.
- **Server** adds automation, monitoring, and team features when connected (client → Settings → Team Server).
- **Embedded mode**: the same binary can be spawned by the desktop client as a local child process (`--embedded`) for a free single-user local setup — one codebase, two run modes.

---

## License and official services

All code in this repository is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0-only)** — see [LICENSE](LICENSE).

- **The code is free — including commercial use.** Self-host it, modify it, self-compile it; a self-compiled instance has all features enabled.
- **What you pay for is the official service, not the code**: license activation & signing (bound to your server instance's fingerprint), updates, and support are provided by dbmaster.tech. Every instance runs full-featured for a 14-day trial; afterwards a license (¥399/year per server instance) keeps automation running. A self-compiled instance never stops working — it just cannot obtain an official activation.
- If it lapses, automation pauses but your data and configuration stay intact — renew anytime to resume.

### Applying a license to a running server

After subscribing and receiving your license PEM from `dbmaster.tech`, apply it to a running remote server without restart:

```bash
# 1. Learn the server's install_uuid (the identifier the license binds to):
curl https://your-server/api/instance
# → {"ok":true,"data":{"install_uuid":"abcd…","version":"0.1.0","embedded_mode":false}}

# 2. POST the license (requires DBMASTER_SERVER_ADMIN_TOKEN configured on the server):
curl -X POST https://your-server/api/license \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $DBMASTER_SERVER_ADMIN_TOKEN" \
  -d "{\"license\": \"$(cat your-license.pem)\"}"
# → {"ok":true,"data":{"state":"licensed","license_type":"yearly","expires_at":"…","scheduler_note":"restart_required_for_schedulers"}}
```

HTTP-gated endpoints (`/api/tasks`, `/api/approvals`, etc.) reflect the new Licensed state immediately. Background schedulers (drift/data-sync/health-check cron) still require a server restart — note the `scheduler_note` in the response. Embedded-server mode skips this flow entirely (always Licensed).

---

## Getting started

### Prerequisites

- **Rust** stable (`rustup install stable`), or **Docker** for containerized runs. All dependencies are pure Rust — no OpenSSL or native libraries needed.
- Two JWT secrets (required in production; dev defaults exist but are insecure):
  ```bash
  export SERVER_JWT_SECRET=$(openssl rand -base64 64)
  export SERVER_JWT_REFRESH_SECRET=$(openssl rand -base64 64)
  ```
- A credential-vault master key — `DBMASTER_CREDENTIAL_KEY`, 32-byte AES-256-GCM key as hex. Required in production; the server fails fast if it is unset.

### Build and run

```bash
cargo build
cargo run
# → Listening on 0.0.0.0:3000
curl http://localhost:3000/api/health
# → {"status":"ok","version":"0.1.0"}
```

- **Configuration comes entirely from environment variables** (`Config::from_env`) — see the table below.
- **Database migrations run automatically** at startup (sqlx) against the SQLite internal store.
- **Sensitive values never live in code**: JWT secrets and the vault master key are injected via environment variables; database credentials you register are encrypted (AES-256-GCM) into the server-side vault.

### Run with Docker

```bash
# Single container
docker build -t dbmaster-server .
docker run -d -p 3000:3000 \
  -e SERVER_JWT_SECRET=$(openssl rand -base64 64) \
  -e SERVER_JWT_REFRESH_SECRET=$(openssl rand -base64 64) \
  -e DBMASTER_CREDENTIAL_KEY=$(openssl rand -hex 32) \
  -v dbmaster-data:/home/dbmaster/data \
  dbmaster-server

# Or docker compose (copy .env.example or export the secrets first)
docker compose up -d
```

### Cross-platform builds

The release profile (`opt-level="s"`, `lto`, `strip`) is already configured in `Cargo.toml`.

| Target | Command |
|---|---|
| Linux x86_64 | `cargo build --release --target x86_64-unknown-linux-gnu` |
| Windows x86_64 | `cargo build --release --target x86_64-pc-windows-msvc` |
| macOS Intel | `cargo build --release --target x86_64-apple-darwin` |
| macOS Apple Silicon | `cargo build --release --target aarch64-apple-darwin` |

All dependencies are pure-Rust (sqlx with `runtime-tokio` + `sqlite`, no OpenSSL/native libs), so cross-compiling needs only `rustup target add <target>` plus a linker for the target platform.

---

## Configuration

> **macOS deployment note (Sequoia / 26+)**: the OS "Local Network" privacy
> permission silently denies unsigned/ad-hoc-signed daemons access to LAN
> addresses — outbound connections to `192.168.x.x` fail instantly with
> `No route to host` while public IPs work. For a launchd deployment, wrap the
> binary in a `.app` bundle (with `NSLocalNetworkUsageDescription` in
> `Info.plist`, stable `CFBundleIdentifier`, ad-hoc codesigned) and grant it
> Local Network under System Settings → Privacy & Security → Local Network.
> The gateway surfaces such failures only as a generic error; check the server
> WARN log line (`db test/connect failed`) for the underlying cause.

| Variable | Default | Purpose |
|---|---|---|
| `SERVER_HOST` | `0.0.0.0` | Bind address |
| `SERVER_PORT` | `3000` | Listen port |
| `SERVER_JWT_SECRET` | dev-only default | HS256 secret for access tokens — **set in production** |
| `SERVER_JWT_REFRESH_SECRET` | dev-only default | HS256 secret for refresh tokens — **set in production, must differ** |
| `DATABASE_URL` | `sqlite:dbmaster.db?mode=rwc` | SQLite path (`sqlite::memory:` for tests) |
| `RUST_LOG` | `dbmaster_server=info` | Log filter |
| `DBMASTER_CREDENTIAL_KEY` | none (dev: random per-boot) | 32-byte AES-256-GCM master key (hex) encrypting stored DB credentials — **required in production** (server fails fast if unset). |
| `DBMASTER_DRIFT_DEFAULT_INTERVAL_MINS` | `30` | Default per-task drift-watch scan interval in minutes. Each task may override via its `config.interval_minutes`. Clamped to `1..=1440` (1 minute to 24 hours); out-of-range or unparseable values fall back to the default with a WARN log. |
| `DBMASTER_DRIFT_WEBHOOK_TIMEOUT_SECS` | `10` | Per-HTTP-request timeout for drift webhook delivery. Each delivery still receives the full retry schedule. |
| `DBMASTER_DEV` | unset | Set to `1` to enable dev mode, which permits `http://localhost` / `http://127.0.0.1` / `http://[::1]` webhook URLs (loopback only). Production mode refuses any non-`https://` URL — payload must never traverse a plaintext link. |
| `DBMASTER_MCP_RATE_LIMIT_PER_MIN` | `120` | MCP `/mcp` per-user rate limit (requests per minute, sliding window). Agents issue one HTTP request per tool call, so this is higher than the auth endpoints' 5/min-per-IP. Clamped to `1..=10000` — a typo can't disable rate limiting. |
| `DBMASTER_MCP_READ_QUERY_MAX_ROWS` | `10000` | Ceiling for the `read_query` MCP tool's per-call `max_rows` (per-call default 500). Matches the REST gateway row cap so both entry points share the same blast radius. Clamped `1..=100000`. |
| `DBMASTER_MCP_READ_QUERY_TIMEOUT_SECS` | `30` | Server-side statement timeout for `read_query` (the per-call connection pool is dropped on expiry, killing the query server-side). Clamped `1..=600`. |
| `DBMASTER_MCP_ALLOWED_HOSTS` | empty (allow all) | Comma-separated `host[:port]` values the MCP endpoint accepts in its `Host` header (rmcp's DNS-rebinding defence defaults to loopback-only, which breaks LAN/public deployments). Empty = allow all: MCP auth is Bearer-token (no cookies to steal via rebinding). Example: `localhost,dbmaster.example.com:8080`. |
| `DBMASTER_MCP_ALLOWED_CONNECTIONS` | empty (no filter) | MCP connection whitelist: comma-separated connection **ids or names**. When set, only the listed connections are visible/usable over the MCP tool surface (`list_connections` output is filtered, and every connection-scoped tool re-checks before touching the target database, returning `CONNECTION_NOT_ALLOWED` otherwise). Empty = MCP mirrors `/api/connections` visibility. The REST gateway is unaffected. Example: `prod-main,analytics`. |
| `DBMASTER_GW_RATE_LIMIT_PER_MIN` | `600` | DB gateway API v1 (`/api/gw/*`) per-user rate limit (requests per minute, sliding window). Higher than MCP's 120 because a GUI client's tree browsing is request-dense (one expand = one request). Clamped `1..=100000`. |
| `DBMASTER_GW_QUERY_DEFAULT_ROWS` | `500` | Default row limit for gateway query executions when the client doesn't send an explicit `rowLimit` (same default as the MCP `read_query` tool). Clamped `1..=100000`. |
| `DBMASTER_GW_QUERY_MAX_ROWS` | `10000` | Ceiling for the gateway's per-request `rowLimit` (explicit values are clamped to this). Matches the MCP/REST row cap. Clamped `1..=100000`. |
| `DBMASTER_GW_QUERY_TIMEOUT_SECS` | `30` | Default statement timeout (wall clock) for gateway query executions; the client may override per request via `timeoutMs` (clamped to 1s..=600s). On timeout the per-execution connection pool is dropped, killing the query server-side. |
| `DBMASTER_MSSQL_TRUST_SERVER_CERT` | `true` | SQL Server (tiberius/TDS): skip TLS certificate validation when connecting. SQL Server ships a self-signed certificate out of the box (nearly all on-prem deployments have no enterprise CA), so the default mirrors SSMS's ubiquitous `TrustServerCertificate=yes`; traffic is still TLS-encrypted. Set to `0`/`false` to validate against the system trust store (LAN servers with self-signed certs will then fail to connect until their CA is trusted). |
| `DBMASTER_SLOW_QUERY_ENABLED` | `true` | Slow-query sampling kill switch (migration 016). `0` stops capturing; the read endpoints (`GET /api/query-stats{,/summary}`) are unaffected. |
| `DBMASTER_SLOW_QUERY_THRESHOLD_MS` | `1000` | Sampling threshold (ms) — executions at or above this are recorded into `query_stats` (capture points: the 4 SSE stream entries, sync query, txn query, admin script statements, MCP `read_query`). Clamped `100..=600000`. |
| `DBMASTER_SLOW_QUERY_STORE_SQL` | `true` | Plaintext SQL storage (dual-track: the normalized digest is always stored). `0` stores digests only — `sql_text` stays NULL in the table and absent from every API response. |
| `DBMASTER_SLOW_QUERY_RETENTION_DAYS` | `14` | Retention window: an hourly background task deletes `query_stats` rows older than this (runs unconditionally in both remote and embedded modes — bounded growth). Clamped `1..=365`. |
| `DBMASTER_SLOW_QUERY_CAP_PER_DIGEST_PER_HOUR` | `20` | Per-digest sampling cap (sliding hour, in-memory — resets on restart; retention is the hard bound). Clamped `1..=10000`. All slow-query knobs take effect on restart (env-sourced config; the only runtime-swappable server state is the license entitlement). |

---

## Testing

- **Unit & integration tests**: just `cargo test`. The default suite is fully offline — no external services needed.
- **Real-database e2e tests** are gated behind environment variables (`DS_E2E_*`, `GW_E2E_*`, `NC_E2E_*`, plus `QS_E2E_*` and script-level `BASE`/`ADMIN_TOKEN`). **When a variable is unset, the corresponding test prints `SKIP` and passes**, so the suite stays green offline. The complete variable list — with URL formats and per-suite run commands — lives in [.env.example](.env.example). Bring your own test databases; the repository carries no real deployment addresses or credentials.
- Example (data-sync e2e against your own MySQL/PostgreSQL/ClickHouse):
  ```bash
  export DS_E2E_MYSQL_URL=mysql://user:pass@host:3306/dbmaster_e2e
  export DS_E2E_MYSQL_ADMIN_URL=mysql://user:pass@host:3306/
  export DS_E2E_PG_URL=postgres://user:pass@host:5432/postgres
  cargo test --test e2e_data_sync_test -- --ignored --nocapture
  ```
- **Verification ladder before submitting a change**: `cargo clippy` → `cargo test -p <crate>` for every crate you touched → full-workspace `cargo test`. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## DB gateway API v1

`/api/gw/*` — the migration foundation for the thin-client architecture. Bearer access token; per-user rate limit `DBMASTER_GW_RATE_LIMIT_PER_MIN`. Supported `dbType`s: `mysql`, `doris`, `postgres`/`postgresql`/`pg`, `sqlite`, `sqlserver`/`mssql` (full path: register/test, tree, SSE execution, cancel/timeout with server-side termination), and `clickhouse` (metadata only; execution lands with the thin-adapter). SQL Server connects via tiberius (pure-Rust TDS, TLS-encrypted by default — see `DBMASTER_MSSQL_TRUST_SERVER_CERT`); `dbo` is the schema scope (same trade-off as PostgreSQL's `public`-only; schema pass-through is a planned follow-up):

- `GET /api/gw/connections` — connection safe projection (never host/credentials)
- `GET /api/gw/connections/{id}/databases` · `…/tables?db=` · `…/describe?db=&table=` — metadata, same backend as the MCP tools
- `POST /api/gw/connections/{id}/query` — **SSE** streaming execution. Body `{sql, database?, schema?, rowLimit?, timeoutMs?, kind?}` (`kind` is always `"sql"`; anything else → 400 `UNSUPPORTED_KIND`; multi-statement → 400 `MULTI_STATEMENT`). Events: `meta` (columns) → `rows` (positional-array row batches) → `complete` (`rowCount`/`truncated`/`elapsedMs`, plus `affectedRows` for DDL/DML) or `error` (`code`/`message`/`engineCode?`), each with a sequence `id`. Send an `X-Execution-Id` header (uuid) to pre-choose the execution handle; the response echoes it.
- `DELETE /api/gw/executions/{executionId}` — explicit cancel (idempotent 204). Server-side termination — the per-execution connection is dropped, killing the query at the engine.
- `POST /api/gw/connections/test` — test a connection draft without storing it → `{ok, error?, elapsedMs, serverVersion?}`
- `POST /api/gw/connections` / `DELETE /api/gw/connections/{id}` — connection registration family (credentials go into the server vault; response carries `serverConnId`).
- **SSH tunnel & TLS (server-side)**: the register/test draft body accepts an optional `ssh` block (`{host, port?, username, authMode: "password"|"privateKey", password? | privateKey+passphrase?}`) — the server builds and holds the tunnel (russh, process-level cache keyed by config+secret+target; lazy reconnect; TOFU host-key acceptance with fingerprint logging), and all gateway connection types then reach the target through a local forward. SSH secrets are AES-256-GCM encrypted in the vault (`ssh_secret_encrypted`, migration 020); non-secret fields live in `extra`. TLS pass-through for `redis`/`mongodb`/`tdengine` is enabled via the non-credential `extra` keys `useTls`/`tlsInsecure` (TLS+ tunnel forces insecure cert validation since the visible host becomes `127.0.0.1`).

Errors use `{"error":{"code","message"}}` with a stable code set (`NOT_FOUND`/`UNSUPPORTED_DB_TYPE`/`UNSUPPORTED_KIND`/`CONNECTION_FAILED`/`DB_ERROR`/`TIMEOUT`/`CANCELLED`/`CONFIG`/`MULTI_STATEMENT`). Query executions audit one row per run into `gw_audit` (outcome code only — no SQL text, no credentials, no PII).

Core REST surface quick map:

- `GET /api/health` — no auth
- `POST /api/auth/register|login|refresh` — no auth, **rate-limited 5 req/min per IP (shared counter)**
- `GET|PATCH /api/me` — Bearer token
- `GET|POST /api/workspaces`, `GET|DELETE /api/workspaces/:id`, `POST .../join|leave`, `DELETE .../members/:uid` — Bearer token

## MCP endpoint & client setup

The server exposes an MCP (Model Context Protocol) surface at **`POST /mcp`** (Streamable HTTP, rmcp). Auth is `Authorization: Bearer <token>` — either a short-lived access JWT or, recommended for agents, a **long-lived MCP token** (`dbm_mcp_*`): create one via `POST /api/mcp/tokens` (`{name}` → plaintext returned once) or from the desktop client (Server status bar → *MCP Tokens*). See the env table above for `DBMASTER_MCP_ALLOWED_HOSTS` (LAN/public deploys) and `DBMASTER_MCP_ALLOWED_CONNECTIONS` (connection whitelist).

Read-only tools: `list_connections` → `list_databases` → `list_tables` → `describe_table`, plus `read_query` (SELECT-only, fail-closed risk gate, row limit + statement timeout). Write path (approval-gated): `submit_write` → human approves in the desktop client (`/api/approvals`) → `execute_write` (approved-only, idempotent) / `get_approval`. Approving in the client claims and executes the DDL immediately — `execute_write` then acts as an idempotent trigger/observer for approvals that reach `approved` without executing; repeated calls never re-run a finished approval.

**License gating**: on a `Gated` instance (trial expired / no valid license), `submit_write` and `execute_write` return `ENTITLEMENT_GATED` (static text, points to activation) while sessions, all read tools and `get_approval` keep working — visible-but-locked, same philosophy as the automation gates. Embedded mode synthesizes a lifetime `Licensed` entitlement, so the free local tier is fully unaffected; `Trial` and `Licensed` instances are not gated. The gate reads the runtime entitlement (same ArcSwap as `POST /api/license`), so activating mid-session unlocks write tools without reconnecting the agent.

**Client samples** (replace `<host>` / `<port>` and the token):

```jsonc
// Claude Code — .mcp.json in the project root (or `claude mcp add`):
{
  "mcpServers": {
    "dbmaster": {
      "type": "http",
      "url": "http://<host>:<port>/mcp",
      "headers": { "Authorization": "Bearer dbm_mcp_xxx" }
    }
  }
}
```

```jsonc
// Cursor — ~/.cursor/mcp.json (same shape):
{
  "mcpServers": {
    "dbmaster": {
      "url": "http://<host>:<port>/mcp",
      "headers": { "Authorization": "Bearer dbm_mcp_xxx" }
    }
  }
}
```

Other Streamable-HTTP clients (ZCode etc.): same `url` + Bearer header under their `mcpServers` config.

---

## Slow query reports pipeline

The `reports` table is the durable aggregation layer on top of the 14-day `query_stats` detail (the only permanent product of the slow-query pipeline — one row per week). Weekly writer (`slow_query_weekly`, `content_version: 1`): rolling 7-day window recorded as `window_from/window_to` in the content JSON, honestly truncated when retention predates the window start (`window_truncated`), week-over-week total-time delta only when the previous window has data (null otherwise).

- **Automatic**: a lightweight hourly ticker generates whenever the latest report is older than 7 days (and the window actually has samples — no empty reports on boot). Remote mode follows the scheduler convention (no ticker under `Gated`); embedded runs it unconditionally (synthesized `Licensed`).
- **Manual**: `POST /api/reports/generate` (mutation → `ENTITLEMENT_GATED` 403 under Gated; idempotent — if this window already has a report the existing id is returned with `created:false`).
- **Read**: `GET /api/reports?report_type=&limit=&offset=` (paginated `{items,total,limit,offset}`) and `GET /api/reports/:id`; both visible-but-locked under Gated, matching the other read routes.
- `report_type` is the hub namespace: unknown future types render raw-JSON in the client instead of breaking it; `task_id` is nullable (system reports have no owning scheduled task).

### Native slow-log collection

Besides gateway-sampled queries, the server pulls the database's *own* slow log into the same `query_stats` table (`source='db_native:*'`, `entry='native'`) — this is what makes the Top N / weekly report a whole-database picture (third-party app traffic included), complementing the gateway source. Hourly ticker (same gating as the weekly writer: no collection under `Gated` in remote mode; embedded runs unconditionally).

Event-shaped sources (one row per event, monotonic-watermark cursor):

- **Redis** (`db_native:redis_slowlog`): `SLOWLOG GET` every hour; cursor = highest consumed entry id (ring-buffer friendly, survives restarts). Collector's own `SLOWLOG` commands are filtered out (self-reference immunity).
- **MySQL / MariaDB** (`db_native:mysql_slow_log`): reads the `mysql.slow_log` table. **Prerequisites**: `slow_query_log=ON` and `log_output` containing `TABLE` on the instance — when unset the collector logs an INFO skip and retries next hour (no server restart needed once enabled). Cursor = max `start_time`.

Cumulative-counter source (snapshot-diff state machine — one row per digest **interval delta**; `elapsed_ms` = interval total time, `query_count` (migration 019) = interval call count, aggregation reads count as `SUM(COALESCE(query_count,1))`):

- **MySQL / MariaDB** (`db_native:mysql_ps_digest`): reads `performance_schema.events_statements_summary_by_digest` — **zero-config** (on by default since 5.7), which fills the whole-database picture for instances where the DBA never enabled slow logging. **Connection-level source preference**: when slow_log-table logging is active it wins (exact SQL text); PS digest is the fallback — a connection is never double-counted. Snapshot = top 500 digests by total time, stored as JSON in the 018 cursor row keyed by `(DIGEST, SCHEMA_NAME)` (composite key — the table really is keyed that way, and a hex-only key collides across schemas). Conservative diffing: counter regression (restart/TRUNCATE) re-baselines silently; digests absent from the previous snapshot (new or evicted out of top-500) skip their first interval; the first collection is baseline-only. Empirical MySQL 8 note: digest aggregation counts **text-protocol (COM_QUERY) statements only** — prepared/binary-protocol executes don't land in the digest table, so this source captures third-party text-protocol traffic while dbmaster's own gateway queries are sampled by the gateway hooks; the two sources are complementary by construction.
- Rows go through the same digest normalization and retention as gateway samples; `sql_text` truncates at 8192 chars.
- **Not yet** (per-source prerequisites make real-world yield low; revisit on demand): PostgreSQL `pg_stat_statements` (needs `shared_preload_libraries` + restart), ClickHouse `system.query_log`, SQL Server Query Store (off by default).

Weekly-report AI analysis is client-side by design — the server keeps zero AI outbound surface; the desktop report viewer hands the typed weekly content to the existing AI panel with the user's own provider/key.

---

## Database account requirements

### Source database account (drift watch)

DbMaster Server connects to your source database **read-only** to introspect schema metadata. The server **never reads business rows** — it queries `information_schema` (MySQL) or `information_schema` + `pg_catalog` (PostgreSQL) only. To make this enforceable in trust as well as in code, create a dedicated read-only account for the server; do **not** reuse a DBA or application account.

**MySQL 5.7+**

```sql
CREATE USER 'dbmaster'@'<server-host>' IDENTIFIED BY '<strong-password>';
GRANT SELECT ON information_schema.* TO 'dbmaster'@'<server-host>';
-- Do NOT grant SELECT on business schemas. Drift watch never queries them,
-- so granting broader read adds blast radius without enabling any feature.
FLUSH PRIVILEGES;
```

**PostgreSQL 12+**

```sql
CREATE ROLE dbmaster LOGIN PASSWORD '<strong-password>';
-- information_schema (column metadata)
GRANT USAGE ON SCHEMA information_schema TO dbmaster;
GRANT SELECT ON ALL TABLES IN SCHEMA information_schema TO dbmaster;
-- pg_catalog (index / PK / FK metadata; PG exposes these via system catalogs)
GRANT USAGE ON SCHEMA pg_catalog TO dbmaster;
GRANT SELECT ON ALL TABLES IN SCHEMA pg_catalog TO dbmaster;
-- Do NOT grant SELECT on business schemas.
```

**Why a dedicated account (not your app or DBA account)?**

- **Blast radius.** Stored credentials are AES-256-GCM encrypted at rest (`DBMASTER_CREDENTIAL_KEY`), but if the key and ciphertext are ever compromised together, the attacker gets only metadata-read — no business data, no writes.
- **Audit clarity.** Every credential decryption is recorded in the `credential_access_audit` table (action, time, status, triggered-by). A dedicated account makes those rows unambiguous.
- **Canary verification.** When you save a `kind = source_drift` connection, the server runs a write probe that **must fail**:
  - MySQL: `CREATE TEMPORARY TABLE dbmaster_canary_readonly (id INT)` (session-scoped; even on crash the table dies with the connection).
  - PostgreSQL: `BEGIN; CREATE TEMP TABLE dbmaster_canary_readonly (id INT); ROLLBACK;` (transactional DDL; the ROLLBACK undoes any successful CREATE).

  If the probe **succeeds** (the account can write), the server refuses to save the connection. The probe SQL touches no business rows and leaves no persistent footprint. As defence in depth, the runner repeats the same canary on each drift run — if a privilege escalation between create-time and run-time is detected, the run is aborted and the failure is recorded in `task_run_history`.

The canary and metadata-only SQL paths enforce the read-only contract. If the canary reports the account as writable, redo the GRANTs above before re-saving the connection.

### Health check account

Health check probes are SELECT-only and read the same `information_schema` / `pg_catalog` / status views as drift watch, plus two additional metric sources. A connection created for drift watch already satisfies health check's requirements **except** for the connection-count metric, which needs one extra privilege on MySQL.

**MySQL** — the `Threads_connected` status query needs `PROCESS` (or MySQL 8.0+ `performance_schema` access):

```sql
-- Reuses the drift-watch read-only grants (information_schema SELECT).
GRANT SELECT ON information_schema.* TO 'dbmaster'@'<server-host>';
-- Connection-count metric (pick ONE of the two):
-- Option A: PROCESS global privilege (covers SHOW STATUS).
GRANT PROCESS ON *.* TO 'dbmaster'@'<server-host>';
-- Option B (MySQL 8.0+): performance_schema threads table.
GRANT SELECT ON performance_schema.threads TO 'dbmaster'@'<server-host>';
```

If neither grant is present, the connection-count metric is skipped (recorded as `unsupported_metrics`); the other 3 metrics still collect. The run status becomes `partial`.

**PostgreSQL** — no extra grants beyond drift watch. `pg_stat_user_tables` and `pg_stat_activity` are readable by `PUBLIC` by default; `pg_tables` is a system catalog view (default read).

**Other db types** (Doris / SQL Server / SQLite / MongoDB / Redis / Oracle) — health check degrades to connectivity-only. Full metric support for these is a follow-up.

---

## Contributing

Bug reports, feature ideas, and pull requests are welcome — start with [CONTRIBUTING.md](CONTRIBUTING.md) (environment, verification ladder, e2e test setup) and GitHub Issues.

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md). Do not open a public issue for security problems.

## Trademark and branding

The AGPL-3.0 license covers the **code**, not the name. The name "DbMaster", the dbmaster.tech domain, and the project's visual identity are not licensed under AGPL-3.0. If you redistribute a modified version, you must clearly present it as an **unofficial fork** (e.g. in your README and about page) and must not present it as the official DbMaster product in a way that suggests endorsement by the upstream project.

## Author

Built by [hobbs136](https://github.com/hobbs136) — solo developer, part-time. [DbMaster Desktop](https://github.com/hobbs136/dbmaster) is the free open-source desktop client; DbMaster Server (this repo) is the automation engine.
