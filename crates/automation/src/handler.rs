//! Automation API handlers — tasks, connections, approvals, queries, reports.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use dbmaster_core::auth::jwt::Claims;
use dbmaster_core::server::AppState;

use crate::{
    CreateConnectionRequest, CreateTaskRequest, RunHistoryQuery, SaveQueryRequest,
    SavedQueryListQuery, SnapshotListQuery, SubmitApprovalRequest,
};
use crate::db_handler::{db_error, not_found, ok_response};

// ── Entitlement gate (ADR-0002 §8 v1-C-2) ──

// CHANGE: ADR-0002 v1-C-2 — when EntitlementState::Gated, refuse every
// automation mutation with 403 + actionable error code. Read routes (list_*)
// stay open so gated users can still see their data; only writes are blocked,
// matching the desktop gated-screen UX (visible-but-locked).
///
/// Returns the 403 response tuple when gated, or `None` to proceed. Mutation
/// handlers early-return on `Some(...)`.
pub fn gate_blocked_pub(
    state: &AppState,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    gate_blocked(state)
}

fn gate_blocked(
    state: &AppState,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    use dbmaster_license::EntitlementState;
    // CHANGE: #3 — entitlement is now Arc<ArcSwap<EntitlementState>>
    // (runtime-swappable via POST /api/license). `.load()` returns a Guard
    // that derefs to Arc<EntitlementState>; `**` gets us &EntitlementState.
    if matches!(&**state.entitlement.load(), EntitlementState::Gated { .. }) {
        Some((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "data": null,
                // DEFENSIVE-NOTE: do not echo which GatedReason (trial_expired
                // vs license_invalid vs instance_mismatch) — the client can
                // read that from /api/entitlement; here we surface a stable
                // machine code so the desktop can branch without parsing prose.
                "error": {
                    "code": "ENTITLEMENT_GATED",
                    "message": "License gated. Activate or renew your license to perform this action."
                }
            })),
        ))
    } else {
        None
    }
}

// ── Tasks ──

pub async fn list_tasks(
    _claims: Claims,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let tasks = sqlx::query_as::<_, crate::ScheduledTask>(
        "SELECT id, name, task_type, cron_expr, config, source_db_id, target_db_id,
                notify_channels, enabled, last_run_at, last_status, created_at
         FROM scheduled_tasks ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await;

    match tasks {
        Ok(t) => Json(serde_json::json!({"ok": true, "data": t, "error": null})),
        Err(e) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
    }
}

pub async fn create_task(
    _claims: Claims,
    State(state): State<AppState>,
    Json(body): Json<CreateTaskRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // CHANGE: ADR-0002 v1-C-2 — gate mutations when entitlement is Gated.
    // NOTE: scheduled_tasks has no created_by column (see 002_automation.sql),
    // so claims is not consumed here; the extractor still enforces auth.
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    // Embedded deployments run drift/health_check on Noop runners (ADR-0003
    // S2): accepting these task types there would only create rows that never
    // execute. Reject up front with an explicit error instead.
    if state.embedded_mode
        && matches!(body.task_type.as_str(), "schema_drift" | "health_check")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {
                    "code": "UNSUPPORTED_IN_EMBEDDED",
                    "message": "schema drift and health check require a remote dbmaster-server deployment; the embedded local engine does not run them"
                }
            })),
        ));
    }
    let id = uuid::Uuid::new_v4().to_string();
    // U05 (#32): validate referenced connections before INSERT. The FK
    // (migration 002) would catch a bad id anyway, but only as a raw
    // "FOREIGN KEY constraint failed" CREATE_FAILED the user can't act on;
    // a 404 naming the missing side tells them to register the connection
    // under Server connections first.
    if let Some(err) = validate_task_connections(&state, &body).await {
        return Err(err);
    }
    let now = chrono::Utc::now().to_rfc3339();
    let config = body.config.to_string();
    let notify = serde_json::to_string(&body.notify_channels.unwrap_or_default()).unwrap_or_default();

    let result = sqlx::query(
        "INSERT INTO scheduled_tasks (id, name, task_type, cron_expr, config, source_db_id, target_db_id, notify_channels, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&id)
    .bind(&body.name)
    .bind(&body.task_type)
    .bind(&body.cron_expr)
    .bind(&config)
    .bind(&body.source_db_id)
    .bind(&body.target_db_id)
    .bind(&notify)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            let task = sqlx::query_as::<_, crate::ScheduledTask>(
                "SELECT * FROM scheduled_tasks WHERE id = ?1",
            )
            .bind(&id)
            .fetch_one(&state.pool)
            .await;

            match task {
                Ok(t) => Ok(Json(serde_json::json!({"ok": true, "data": t, "error": null}))),
                Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "FETCH_FAILED", "message": e.to_string()}}))),
            }
        }
        Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "CREATE_FAILED", "message": e.to_string()}}))),
    }
}

/// U05 (#32) — connection-existence pre-check for [create_task]. Returns the
/// 404 error tuple naming the missing side, or `None` to proceed.
///
/// Embedded mirrors mint a fresh server UUID per local connection and remote
/// deployments historically had no writer at all, so clients used to submit
/// local ids that only failed at INSERT (raw FK error) or — after a later
/// `ON DELETE SET NULL` on target — at run time with an opaque
/// "connection not found". Fail fast with an actionable message instead.
async fn validate_task_connections(
    state: &AppState,
    body: &CreateTaskRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    fn missing(side: &str, id: &str) -> (StatusCode, Json<serde_json::Value>) {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {
                    "code": "CONNECTION_NOT_FOUND",
                    "message": format!(
                        "{side} connection not found: {id}. Register the connection under Server connections before creating the task."
                    )
                }
            })),
        )
    }

    async fn exists(state: &AppState, id: &str) -> sqlx::Result<bool> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM database_connections WHERE id = ?1",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await
        .map(|n| n > 0)
    }

    match exists(state, &body.source_db_id).await {
        Ok(true) => {}
        Ok(false) => return Some(missing("source", &body.source_db_id)),
        Err(e) => {
            tracing::warn!(error = %e, "create_task connection validation failed");
            return Some((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": {"code": "INTERNAL", "message": "failed to validate task connections"}
                })),
            ));
        }
    }
    if let Some(target) = body.target_db_id.as_deref() {
        match exists(state, target).await {
            Ok(true) => {}
            Ok(false) => return Some(missing("target", target)),
            Err(e) => {
                tracing::warn!(error = %e, "create_task connection validation failed");
                return Some((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "ok": false, "data": null,
                        "error": {"code": "INTERNAL", "message": "failed to validate task connections"}
                    })),
                ));
            }
        }
    }
    None
}

pub async fn run_task_now(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // CHANGE: ADR-0002 v1-C-2 — gate manual runs the same as other mutations.
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }

    // CHANGE: ADR-0002 v1-C-9 — dispatch to the real drift runner via the
    // AppState trait bridge (core::DriftRunner), the same implementation the
    // scheduler uses. The handler returns 202 immediately; the runner opens
    // its own task_run_history row, runs canary/snapshot/diff/webhook/audit,
    // and updates scheduled_tasks.last_status. Clients poll /api/tasks to
    // observe last_status, or query task_run_history for the per-run trail.
    //
    // DEFENSIVE-NOTE: drift runs may take seconds (network to customer DB +
    // webhook retries). Blocking the HTTP request would tie up an axum worker
    // and risk client timeouts. Spawn-and-forget is safe because:
    //   - the runner is idempotent per ADR §4 D6 (re-running just snapshots
    //     again and writes a new run_history row);
    //   - the runner writes its own audit/run_history rows, so failure is
    //     observable even though the handler has already returned;
    //   - the canary/snapshot chain runs unchanged from the scheduler path.
    //
    // Known v1 limitation (out of quick-fix scope): no in-flight coordination
    // with the scheduler's InFlightTasks; a manual run that overlaps a
    // scheduler tick on the same task produces two run_history rows and may
    // chain snapshots imperfectly. The next run recovers a clean chain.
    //
    // CHANGE: data-sync 一期 — dispatch by task_type. data_sync tasks go to
    // state.data_sync_runner (writes to data_sync_runs); schema_drift stays
    // on state.drift_runner (writes to task_run_history). Unknown types → 400.

    // Read the task_type from the row so we can pick the right runner.
    let task_type: String = match sqlx::query_scalar::<_, String>(
        "SELECT task_type FROM scheduled_tasks WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": { "code": "TASK_NOT_FOUND", "message": "task not found" }
                })),
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to load task_type for run_task_now");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": { "code": "INTERNAL", "message": "failed to load task" }
                })),
            ));
        }
    };

    // Embedded mode dispatches these types to Noop runners — reject explicitly
    // instead of the historical silent 202 that never produced run history.
    if state.embedded_mode && matches!(task_type.as_str(), "schema_drift" | "health_check") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {
                    "code": "UNSUPPORTED_IN_EMBEDDED",
                    "message": "schema drift and health check require a remote dbmaster-server deployment; the embedded local engine does not run them"
                }
            })),
        ));
    }

    let triggered_by = format!("manual:{}", claims.sub);
    let pool = state.pool.clone();
    let state_for_task = state.clone();
    let task_id = id.clone();

    let spawn_result = match task_type.as_str() {
        "schema_drift" => {
            let runner = state.drift_runner.clone();
            tokio::spawn(async move {
                let result = runner.run(&pool, &state_for_task, &task_id, &triggered_by).await;
                if let Err(msg) = result {
                    tracing::warn!(task_id = %task_id, error = %msg, "manual drift run failed");
                }
            });
            Ok(())
        }
        "data_sync" => {
            let runner = state.data_sync_runner.clone();
            tokio::spawn(async move {
                let result = runner.run(&pool, &state_for_task, &task_id, &triggered_by).await;
                if let Err(msg) = result {
                    tracing::warn!(task_id = %task_id, error = %msg, "manual data_sync run failed");
                }
            });
            Ok(())
        }
        // CHANGE: ADR-0004 §2.2 — health_check dispatch (mirrors drift/data_sync).
        "health_check" => {
            let runner = state.health_check_runner.clone();
            tokio::spawn(async move {
                let result = runner.run(&pool, &state_for_task, &task_id, &triggered_by).await;
                if let Err(msg) = result {
                    tracing::warn!(task_id = %task_id, error = %msg, "manual health_check run failed");
                }
            });
            Ok(())
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {
                    "code": "UNSUPPORTED_TASK_TYPE",
                    "message": format!("manual run is not supported for task_type '{other}'")
                }
            })),
        )),
    };
    spawn_result?;

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ok": true,
            "data": {
                "task_id": id,
                "status": "queued",
                // Tell the client where to read the result.
                "result_at": "GET /api/tasks (last_status) or task_run_history"
            },
            "error": null
        })),
    ))
}

pub async fn delete_task(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    let result = sqlx::query("DELETE FROM scheduled_tasks WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await;

    match result {
        Ok(_) => Ok(Json(serde_json::json!({"ok": true, "data": {"deleted": true}, "error": null}))),
        Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}}))),
    }
}

// ── Connections ──

pub async fn list_connections(
    _claims: Claims,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let conns = sqlx::query_as::<_, crate::DatabaseConnection>(
        "SELECT * FROM database_connections ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await;

    match conns {
        Ok(c) => Json(serde_json::json!({"ok": true, "data": c, "error": null})),
        Err(e) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
    }
}

/// `GET /api/connections/:id/credential` — return the DECRYPTED plaintext
/// credentials for a connection.
///
/// **Security policy (ADR-0003 S3)**: this endpoint is enabled ONLY in
/// embedded mode (`AppState.embedded_mode == true`). In embedded mode the
/// server runs as a loopback (127.0.0.1) child process of the desktop client,
/// so plaintext never traverses a network link. On a remote deployment the
/// endpoint returns 403 `NOT_EMBEDDED` unconditionally — plaintext credentials
/// must never leave the embedded loopback transport.
///
/// The client needs the plaintext password because, in S3, it still opens DB
/// connections locally via its own adapters (S4 will route queries through the
/// server gateway, at which point this endpoint can be retired).
// plaintext credential retrieval, embedded-only.
pub async fn get_connection_credential(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // DEFENSIVE-NOTE: the policy gate is the first thing we check. This endpoint
    // MUST refuse in non-embedded mode even though auth (Claims) succeeded.
    if !state.embedded_mode {
        return Ok(Json(serde_json::json!({
            "ok": false,
            "data": null,
            "error": {"code": "NOT_EMBEDDED",
                      "message": "Credential retrieval is available only in embedded mode."}
        })));
    }

    let row: Option<crate::DatabaseConnection> = sqlx::query_as::<_, crate::DatabaseConnection>(
        "SELECT * FROM database_connections WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {"code": "DB_ERROR", "message": e.to_string()}
            })),
        )
    })?;

    let row = match row {
        Some(r) => r,
        None => {
            return Ok(Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {"code": "NOT_FOUND", "message": "connection not found"}
            })))
        }
    };

    // Decrypt the main password.
    let password = match crate::credential::decrypt_password(
        &row.password_encrypted,
        &state.credential_key,
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = ?e, conn_id = %id, "failed to decrypt connection password");
            return Ok(Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {"code": "DECRYPT_FAILED",
                          "message": "stored credential could not be decrypted (key changed?)"}
            })));
        }
    };

    // Helper to decrypt optional SSH secrets.
    let decrypt_opt = |stored: &Option<String>| -> Result<Option<String>, (StatusCode, Json<serde_json::Value>)> {
        match stored {
            Some(s) if !s.is_empty() => {
                crate::credential::decrypt_password(s, &state.credential_key).map(Some).map_err(|e| {
                    tracing::error!(error = ?e, conn_id = %id, "failed to decrypt ssh credential");
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "ok": false, "data": null,
                            "error": {"code": "DECRYPT_FAILED",
                                      "message": "stored ssh credential could not be decrypted"}
                        })),
                    )
                })
            }
            _ => Ok(None),
        }
    };

    let ssh_password = decrypt_opt(&row.ssh_password_encrypted)?;
    let ssh_private_key = decrypt_opt(&row.ssh_private_key_encrypted)?;
    let ssh_passphrase = decrypt_opt(&row.ssh_passphrase_encrypted)?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "data": {
            "id": id,
            "password": password,
            "ssh_username": row.ssh_username,
            "ssh_auth_mode": row.ssh_auth_mode,
            "ssh_password": ssh_password,
            "ssh_private_key": ssh_private_key,
            "ssh_passphrase": ssh_passphrase,
        },
        "error": null,
    })))
}

pub async fn create_connection(
    claims: Claims,
    State(state): State<AppState>,
    Json(body): Json<CreateConnectionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // CHANGE: ADR-0002 v1-C-2 — gate mutations when entitlement is Gated.
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }

    // CHANGE: ADR-0002 §4.2.1 — normalise kind to "collab" | "source_drift".
    // Unknown / empty values fall back to "collab" (back-compat).
    let kind = match body.kind.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("source_drift") => "source_drift",
        _ => "collab",
    };

    // CHANGE: ADR-0002 §4.2.3 L2 / v1-C-4 — for source_drift connections,
    // verify the supplied account is read-only BEFORE we encrypt and store.
    // DEFENSIVE-NOTE: this canary is duplicated from drift::canary (which the
    // runner also runs as defence-in-depth) because drift already depends on
    // automation for credential decrypt, so automation cannot depend back on
    // drift without a cycle. The SQL strings are intentionally identical to
    // drift::canary::mysql_canary_create_sql / pg_canary_create_sql; a future
    // refactor (move decrypt into a shared trait) would let both call sites
    // share one source. TODO-REFACTOR.
    if kind == "source_drift" {
        if let Err(msg) = run_create_canary(&body).await {
            return Ok(Json(serde_json::json!({
                "ok": false,
                "data": null,
                "error": {"code": "CANARY_REJECTED", "message": msg}
            })));
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    // CHANGE: ADR-0001 §4.8 D8.2 — encrypt password with AES-256-GCM (v1).
    // DEFENSIVE-NOTE: encrypt failure is surfaced as a CREATE_FAILED error; we
    // never fall back to plaintext. Key comes from AppState (env-loaded at boot).
    let encrypted = match crate::credential::encrypt_v1(&body.password, &state.credential_key) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::error!(error = %e, "credential encryption failed");
            return Ok(Json(serde_json::json!({
                "ok": false,
                "data": null,
                "error": {"code": "CREATE_FAILED", "message": "credential encryption failed"}
            })));
        }
    };

    // encrypt the optional SSH credentials with the same
    // AES-256-GCM key. A failure here is CREATE_FAILED (never store plaintext).
    let ssh_password_enc = match body.ssh_password.as_deref() {
        Some(p) if !p.is_empty() => Some(encrypt_secret(p, &state.credential_key, "ssh password")?),
        _ => None,
    };
    let ssh_private_key_enc = match body.ssh_private_key.as_deref() {
        Some(k) if !k.is_empty() => Some(encrypt_secret(k, &state.credential_key, "ssh private key")?),
        _ => None,
    };
    let ssh_passphrase_enc = match body.ssh_passphrase.as_deref() {
        Some(p) if !p.is_empty() => Some(encrypt_secret(p, &state.credential_key, "ssh passphrase")?),
        _ => None,
    };

    let result = sqlx::query(
        "INSERT INTO database_connections (
            id, name, db_type, host, port, username, password_encrypted,
            default_database, ssh_enabled, ssh_host, ssh_port, created_by, created_at, kind, file_path,
            use_ssl, timeout_seconds, auto_reconnect, charset, timezone, environment,
            read_only, group_id, extra,
            ssh_username, ssh_auth_mode,
            ssh_password_encrypted, ssh_private_key_encrypted, ssh_passphrase_encrypted)
         VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
            ?16, ?17, ?18, ?19, ?20, ?21,
            ?22, ?23, ?24,
            ?25, ?26,
            ?27, ?28, ?29)",
    )
    .bind(&id).bind(&body.name).bind(&body.db_type).bind(&body.host)
    .bind(body.port).bind(&body.username).bind(&encrypted)
    .bind(&body.default_database).bind(body.ssh_enabled)
    .bind(&body.ssh_host).bind(&body.ssh_port)
    .bind(&claims.sub).bind(&now)
    .bind(kind)
    .bind(&body.file_path)
    // extended fields.
    .bind(body.use_ssl)
    .bind(body.timeout_seconds)
    .bind(body.auto_reconnect)
    .bind(&body.charset)
    .bind(&body.timezone)
    .bind(&body.environment)
    .bind(body.read_only)
    .bind(&body.group_id)
    .bind(&body.extra)
    .bind(&body.ssh_username)
    .bind(&body.ssh_auth_mode)
    .bind(&ssh_password_enc)
    .bind(&ssh_private_key_enc)
    .bind(&ssh_passphrase_enc)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            let conn = sqlx::query_as::<_, crate::DatabaseConnection>(
                "SELECT * FROM database_connections WHERE id = ?1",
            ).bind(&id).fetch_one(&state.pool).await;

            match conn {
                Ok(c) => Ok(Json(serde_json::json!({"ok": true, "data": c, "error": null}))),
                Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "FETCH_FAILED", "message": e.to_string()}}))),
            }
        }
        Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "CREATE_FAILED", "message": e.to_string()}}))),
    }
}

/// Encrypt a secret for storage, returning the `(StatusCode, Json)` error the
/// create handlers use on failure. Used for the optional SSH credentials so
/// their encryption errors surface identically to the main password's.
// shared encrypt-or-fail helper for SSH fields.
fn encrypt_secret(
    plaintext: &str,
    key: &[u8; 32],
    field_name: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    match crate::credential::encrypt_v1(plaintext, key) {
        Ok(ct) => Ok(ct),
        Err(e) => {
            tracing::error!(error = %e, field = field_name, "credential encryption failed");
            Err((
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": false,
                    "data": null,
                    "error": {"code": "CREATE_FAILED", "message": "credential encryption failed"}
                })),
            ))
        }
    }
}

/// Open a short-lived pool to the customer source DB and run a write probe
/// that read-only accounts will fail. See `create_connection` doc above for
/// the cycle-avoidance rationale.
async fn run_create_canary(body: &CreateConnectionRequest) -> Result<(), String> {
    let db_type = body.db_type.to_ascii_lowercase();
    let db = body.default_database.as_deref().unwrap_or("");
    match db_type.as_str() {
        "mysql" => {
            use sqlx::mysql::MySqlConnectOptions;
            let opts = MySqlConnectOptions::new()
                .host(&body.host)
                .port(body.port as u16)
                .username(&body.username)
                .password(&body.password)
                .database(db);
            let pool = sqlx::mysql::MySqlPoolOptions::new()
                .max_connections(1)
                .connect_with(opts)
                .await
                .map_err(|e| format!("cannot connect to source DB: {e}"))?;
            // CREATE TEMPORARY TABLE — session-scoped, drops with the pool.
            let r = sqlx::query("CREATE TEMPORARY TABLE dbmaster_canary_readonly (id INT)")
                .execute(&pool)
                .await;
            drop(pool);
            match r {
                Ok(_) => Err(
                    "source account is writable; create a read-only account (SELECT on information_schema only)"
                        .to_string(),
                ),
                Err(_) => Ok(()), // CREATE failed → read-only (the desired state)
            }
        }
        "postgres" | "postgresql" | "pg" => {
            use sqlx::Acquire;
            use sqlx::postgres::PgConnectOptions;
            let opts = PgConnectOptions::new()
                .host(&body.host)
                .port(body.port as u16)
                .username(&body.username)
                .password(&body.password)
                .database(db);
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with(opts)
                .await
                .map_err(|e| format!("cannot connect to source DB: {e}"))?;
            let mut conn = pool.acquire().await.map_err(|e| format!("pool acquire failed: {e}"))?;
            let tx = conn.begin().await.map_err(|e| format!("begin failed: {e}"))?;
            let mut tx = tx;
            let r = sqlx::query("CREATE TEMP TABLE dbmaster_canary_readonly (id INT)")
                .execute(&mut *tx)
                .await;
            let _ = tx.rollback().await;
            drop(conn);
            drop(pool);
            match r {
                Ok(_) => Err(
                    "source account is writable; create a read-only account (SELECT on information_schema only)"
                        .to_string(),
                ),
                Err(_) => Ok(()),
            }
        }
        _ => Err(format!("unsupported db_type for source_drift: {db_type}")),
    }
}

pub async fn delete_connection(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    let _ = sqlx::query("DELETE FROM database_connections WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await;
    Ok(Json(serde_json::json!({"ok": true, "data": {"deleted": true}, "error": null})))
}

/// U05 (#32) — `PUT /api/connections/:id`: in-place partial update.
///
/// Why not delete+recreate (the S3 embedded-mirror trick): recreation mints a
/// new id, and `scheduled_tasks.source_db_id` has `ON DELETE CASCADE` /
/// `target_db_id` `ON DELETE SET NULL` (migration 002) — an edit would
/// silently delete or break every task referencing the row. Updating in place
/// keeps the id (and therefore all references) stable.
///
/// Semantics: omitted fields keep their stored values; `kind` and
/// `created_by`/`created_at` are never editable (source_drift canary
/// guarantees must survive an edit). A non-empty `password` is re-encrypted;
/// None/empty keeps the stored ciphertext so edit forms can omit the secret.
pub async fn update_connection(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<crate::UpdateConnectionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }

    let existing: Option<crate::DatabaseConnection> =
        sqlx::query_as::<_, crate::DatabaseConnection>(
            "SELECT * FROM database_connections WHERE id = ?1",
        )
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": {"code": "DB_ERROR", "message": e.to_string()}
                })),
            )
        })?;
    let row = match existing {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": {"code": "NOT_FOUND", "message": "connection not found"}
                })),
            ))
        }
    };

    let name = body.name.unwrap_or(row.name);
    let db_type = body.db_type.unwrap_or(row.db_type);
    let host = body.host.unwrap_or(row.host);
    let port = body.port.unwrap_or(row.port);
    let username = body.username.unwrap_or(row.username);
    let default_database = body.default_database.or(row.default_database);
    let file_path = body.file_path.or(row.file_path);
    let use_ssl = body.use_ssl.unwrap_or(row.use_ssl);
    let read_only = body.read_only.unwrap_or(row.read_only);
    let timeout_seconds = body.timeout_seconds.unwrap_or(row.timeout_seconds);
    let charset = body.charset.or(row.charset);
    let timezone = body.timezone.or(row.timezone);
    let environment = body.environment.or(row.environment);

    let password_encrypted = match body.password.as_deref() {
        Some(p) if !p.is_empty() => {
            match crate::credential::encrypt_v1(p, &state.credential_key) {
                Ok(ct) => ct,
                Err(e) => {
                    tracing::error!(error = %e, "credential encryption failed (update)");
                    return Ok(Json(serde_json::json!({
                        "ok": false, "data": null,
                        "error": {"code": "UPDATE_FAILED", "message": "credential encryption failed"}
                    })));
                }
            }
        }
        _ => row.password_encrypted,
    };

    let result = sqlx::query(
        "UPDATE database_connections SET
            name = ?2, db_type = ?3, host = ?4, port = ?5, username = ?6,
            password_encrypted = ?7, default_database = ?8, file_path = ?9,
            use_ssl = ?10, read_only = ?11, timeout_seconds = ?12,
            charset = ?13, timezone = ?14, environment = ?15
         WHERE id = ?1",
    )
    .bind(&id)
    .bind(&name)
    .bind(&db_type)
    .bind(&host)
    .bind(port)
    .bind(&username)
    .bind(&password_encrypted)
    .bind(&default_database)
    .bind(&file_path)
    .bind(use_ssl)
    .bind(read_only)
    .bind(timeout_seconds)
    .bind(&charset)
    .bind(&timezone)
    .bind(&environment)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => {
            let conn = sqlx::query_as::<_, crate::DatabaseConnection>(
                "SELECT * FROM database_connections WHERE id = ?1",
            )
            .bind(&id)
            .fetch_one(&state.pool)
            .await;
            match conn {
                Ok(c) => Ok(Json(serde_json::json!({"ok": true, "data": c, "error": null}))),
                Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "FETCH_FAILED", "message": e.to_string()}}))),
            }
        }
        Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "UPDATE_FAILED", "message": e.to_string()}}))),
    }
}

// ── Approvals ──

pub async fn list_approvals(
    _claims: Claims,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let approvals = sqlx::query_as::<_, crate::DdlApproval>(
        "SELECT * FROM ddl_approvals ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await;

    match approvals {
        Ok(a) => Json(serde_json::json!({"ok": true, "data": a, "error": null})),
        Err(e) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
    }
}

pub async fn submit_approval(
    claims: Claims,
    State(state): State<AppState>,
    Json(body): Json<SubmitApprovalRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let result = sqlx::query(
        "INSERT INTO ddl_approvals (id, ddl_sql, target_db_id, submitter_id, status, created_at)
         VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
    )
    .bind(&id).bind(&body.ddl_sql).bind(&body.target_db_id)
    // CHANGE: ADR-0002 v1-C-1 — verified submitter id replaces "system".
    .bind(&claims.sub).bind(&now)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => Ok(Json(serde_json::json!({"ok": true, "data": {"id": id, "status": "pending"}, "error": null}))),
        Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "SUBMIT_FAILED", "message": e.to_string()}}))),
    }
}

pub async fn approve_approval(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }

    // 1. Load the approval — must exist and be pending.
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT ddl_sql, target_db_id, status FROM ddl_approvals WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| db_error("DB_ERROR", &e.to_string(), 500))?;

    let (ddl_sql, target_db_id, current_status) = match row {
        Some(r) => r,
        None => return Err(not_found("APPROVAL_NOT_FOUND", &format!("approval {id} not found"))),
    };

    // 2. Status guard — only pending can be approved (idempotency check).
    if current_status != "pending" {
        return Err(db_error(
            "ALREADY_RESOLVED",
            &format!("approval is {current_status}, not pending"),
            409,
        ));
    }

    // 3. Atomically claim: status=pending → executing, set reviewer_id.
    let now = chrono::Utc::now().to_rfc3339();
    let result = sqlx::query(
        "UPDATE ddl_approvals
         SET status = 'executing', exec_status = 'executing',
             reviewer_id = ?1, resolved_at = ?2, executed_at = ?2
         WHERE id = ?3 AND status = 'pending'",
    )
    .bind(&claims.sub)
    .bind(&now)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|e| db_error("DB_ERROR", &e.to_string(), 500))?;

    if result.rows_affected() == 0 {
        return Err(db_error(
            "CONFLICT",
            "approval was already claimed by another reviewer",
            409,
        ));
    }

    // 4. Spawn async DDL execution. Returns 202 immediately.
    let state_clone = state.clone();
    let id_clone = id.clone();
    tokio::spawn(async move {
        let exec_result = crate::db_handler::execute_ddl_on_target(
            &state_clone,
            &target_db_id,
            &ddl_sql,
        )
        .await;

        // Capture status + error before consuming exec_result in match.
        let (audit_status, audit_error): (&str, Option<String>) = match &exec_result {
            Ok(()) => ("ok", None),
            Err(e) => ("error", Some(e.clone())),
        };

        let now = chrono::Utc::now().to_rfc3339();
        match exec_result {
            Ok(()) => {
                let _ = sqlx::query(
                    "UPDATE ddl_approvals
                     SET status = 'approved', exec_status = 'approved'
                     WHERE id = ?1",
                )
                .bind(&id_clone)
                .execute(&state_clone.pool)
                .await;
                tracing::info!(approval_id = %id_clone, reviewer = %claims.sub, "DDL approval executed successfully");
            }
            Err(err) => {
                let _ = sqlx::query(
                    "UPDATE ddl_approvals
                     SET status = 'failed', exec_status = 'failed', exec_error = ?1
                     WHERE id = ?2",
                )
                .bind(&err)
                .bind(&id_clone)
                .execute(&state_clone.pool)
                .await;
                tracing::warn!(approval_id = %id_clone, reviewer = %claims.sub, error = %err, "DDL approval execution failed");
            }
        }

        // Audit log (best-effort) — record credential access for DDL execution.
        let audit_id = uuid::Uuid::new_v4().to_string();
        let _ = sqlx::query(
            "INSERT INTO credential_access_audit (id, connection_id, action, status, error, at, triggered_by)
             VALUES (?1, ?2, 'ddl_execute', ?3, ?4, ?5, ?6)",
        )
        .bind(&audit_id)
        .bind(&target_db_id)
        .bind(audit_status)
        .bind(audit_error)
        .bind(&now)
        .bind(&claims.sub)
        .execute(&state_clone.pool)
        .await;
    });

    Ok(Json(serde_json::json!({
        "ok": true,
        "data": {"id": id, "status": "executing", "exec_status": "executing"},
        "error": null
    })))
}

pub async fn reject_approval(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    let _ = sqlx::query(
        "UPDATE ddl_approvals SET status = 'rejected', resolved_at = ?1 WHERE id = ?2",
    )
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(&id)
    .execute(&state.pool)
    .await;
    Ok(Json(serde_json::json!({"ok": true, "data": {"status": "rejected"}, "error": null})))
}

// ── Saved Queries ──

pub async fn save_query(
    claims: Claims,
    State(state): State<AppState>,
    Json(body): Json<SaveQueryRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let tags = serde_json::to_string(&body.tags).unwrap_or_default();

    let result = sqlx::query(
        "INSERT INTO saved_queries (id, title, sql_text, tags, workspace_id, created_by, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(&id).bind(&body.title).bind(&body.sql_text)
    .bind(&tags).bind("default")
    // CHANGE: ADR-0002 v1-C-1 — verified user id replaces "system".
    .bind(&claims.sub).bind(&now)
    .execute(&state.pool)
    .await;

    match result {
        Ok(_) => Ok(Json(serde_json::json!({"ok": true, "data": {"id": id, "saved": true}, "error": null}))),
        Err(e) => Ok(Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "SAVE_FAILED", "message": e.to_string()}}))),
    }
}

/// `GET /api/queries?tag=&q=&limit=` — list saved queries with optional filters.
/// Read-only (no gate); mirrors list_reports / list_tasks policy.
// CHANGE: #4 — read side of the team query library. tag filter uses SQL LIKE
// against the JSON-encoded tags column (`["foo","bar"]` → match `%"foo"%`);
// q filter is case-insensitive LIKE on title + sql_text. All values are bind
// parameters — no string concatenation into SQL (defensive against injection).
pub async fn list_saved_queries(
    _claims: Claims,
    State(state): State<AppState>,
    query: Result<Query<SavedQueryListQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Query(q) = query.map_err(|_| bad_query(
        "invalid query parameters (optional: tag, q, limit)"
    ))?;
    let limit = clamp_limit(q.limit, SAVED_QUERY_DEFAULT_LIMIT, SAVED_QUERY_MAX_LIMIT);

    // Build WHERE clause dynamically based on which filters are present.
    // Structure is fixed per case; only values flow through bind params.
    let mut where_clauses: Vec<&'static str> = Vec::new();
    if q.tag.is_some() {
        where_clauses.push("tags LIKE ?");
    }
    if q.q.is_some() {
        where_clauses.push("(title LIKE ? OR sql_text LIKE ?)");
    }
    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };
    // SQLsplice-safe: where_sql only ever contains the two literal fragments
    // above (no user data); user values go through .bind() below.
    let sql = format!(
        "SELECT id, title, sql_text, tags, workspace_id, created_by, created_at \
         FROM saved_queries {where_sql} \
         ORDER BY created_at DESC \
         LIMIT ?"
    );

    let mut stmt = sqlx::query_as::<_, crate::SavedQuery>(&sql);
    if let Some(tag) = &q.tag {
        // Match the tag as a JSON array element: tags column is `["foo","bar"]`,
        // so '%"tag"%' matches the quoted element (avoiding substring collisions
        // between e.g. "foo" and "foobar").
        let pattern = format!("%\"{tag}\"%");
        stmt = stmt.bind(pattern);
    }
    if let Some(needle) = &q.q {
        // Two binds (title + sql_text) of the same pattern; clone because
        // sqlx::Query takes ownership of each bind value.
        let pat = format!("%{needle}%");
        let pat2 = pat.clone();
        stmt = stmt.bind(pat).bind(pat2);
    }
    stmt = stmt.bind(limit);
    let rows = stmt.fetch_all(&state.pool).await;

    match rows {
        Ok(r) => Ok(Json(serde_json::json!({"ok": true, "data": r, "error": null}))),
        Err(e) => Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "DB_ERROR", "message": e.to_string()}
        }))),
    }
}

/// `GET /api/queries/:id` — fetch one saved query. Read-only (no gate).
pub async fn get_saved_query(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let row = sqlx::query_as::<_, crate::SavedQuery>(
        "SELECT id, title, sql_text, tags, workspace_id, created_by, created_at \
         FROM saved_queries WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await;

    match row {
        Ok(Some(r)) => Ok(Json(serde_json::json!({"ok": true, "data": r, "error": null}))),
        Ok(None) => Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "NOT_FOUND", "message": "Saved query not found"}
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "DB_ERROR", "message": e.to_string()}
        }))),
    }
}

/// `DELETE /api/queries/:id` — delete one saved query. Gated like other writes.
// D2-B (#32)：saved_queries 全局共享（workspace_id 未接线），删除权限收紧为
// 仅作者可删——此前任意认证用户可删任何人的共享查询。
pub async fn delete_saved_query(
    claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    let author = sqlx::query_scalar::<_, String>(
        "SELECT created_by FROM saved_queries WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await;
    let created_by = match author {
        Ok(a) => a,
        Err(e) => {
            return Ok(Json(serde_json::json!(
                {"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}}
            )))
        }
    };
    let Some(created_by) = created_by else {
        return Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "NOT_FOUND", "message": "Saved query not found"}
        })));
    };
    if created_by != claims.sub {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {"code": "FORBIDDEN", "message": "Only the author can delete a saved query."}
            })),
        ));
    }
    let result = sqlx::query("DELETE FROM saved_queries WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await;
    match result {
        Ok(done) => {
            if done.rows_affected() == 0 {
                Ok(Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": {"code": "NOT_FOUND", "message": "Saved query not found"}
                })))
            } else {
                Ok(Json(serde_json::json!({
                    "ok": true, "data": {"id": id, "deleted": true}, "error": null
                })))
            }
        }
        Err(e) => Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "DB_ERROR", "message": e.to_string()}
        }))),
    }
}

// ── Reports ──

// reports-M2（#29）— 列表整形：report_type 过滤 + 分页（data 形状从裸数组
// 改为 {items,total,limit,offset}，对齐 query-stats；旧形状零消费者）。
const REPORTS_DEFAULT_LIMIT: i64 = 50;
const REPORTS_MAX_LIMIT: i64 = 200;

#[derive(serde::Deserialize)]
pub struct ListReportsQuery {
    pub report_type: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_reports(
    _claims: Claims,
    State(state): State<AppState>,
    Query(q): Query<ListReportsQuery>,
) -> Json<serde_json::Value> {
    let limit = q
        .limit
        .unwrap_or(REPORTS_DEFAULT_LIMIT)
        .clamp(1, REPORTS_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0).max(0);

    let reports = sqlx::query_as::<_, crate::Report>(
        "SELECT * FROM reports \
         WHERE (?1 IS NULL OR report_type = ?1) \
         ORDER BY generated_at DESC LIMIT ?2 OFFSET ?3",
    )
    .bind(&q.report_type)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await;

    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM reports WHERE (?1 IS NULL OR report_type = ?1)",
    )
    .bind(&q.report_type)
    .fetch_one(&state.pool)
    .await;

    match (reports, total) {
        (Ok(items), Ok(total)) => Json(serde_json::json!({
            "ok": true,
            "data": {"items": items, "total": total, "limit": limit, "offset": offset},
            "error": null,
        })),
        (Err(e), _) | (_, Err(e)) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
    }
}

pub async fn get_report(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let report = sqlx::query_as::<_, crate::Report>(
        "SELECT * FROM reports WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await;

    match report {
        Ok(Some(r)) => Json(serde_json::json!({"ok": true, "data": r, "error": null})),
        Ok(None) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "NOT_FOUND", "message": "Report not found"}})),
        Err(e) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
    }
}

/// `POST /api/reports/generate` — 手动生成本期周报（幂等：本窗口已有则
/// 返回已有行 `created:false`）。mutation 端点 → 走 Gated 门（对齐
/// ADR-0002 v1-C-2 全 mutation 惯例；embedded 合成 Licensed 不受影响）。
#[derive(serde::Deserialize)]
pub struct GenerateReportBody {
    pub report_type: Option<String>,
}

pub async fn generate_report(
    _claims: Claims,
    State(state): State<AppState>,
    Json(body): Json<GenerateReportBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    match body.report_type.as_deref() {
        None | Some(crate::report_writer::SLOW_QUERY_WEEKLY) => {}
        Some(other) => {
            return Err(crate::db_handler::db_error(
                "UNKNOWN_REPORT_TYPE",
                &format!("unsupported report_type: {other}"),
                400,
            ));
        }
    }
    match crate::report_writer::generate_slow_query_report(&state.pool).await {
        Ok(g) => Ok(ok_response(serde_json::json!({
            "id": g.id,
            "created": g.created,
            "report_type": crate::report_writer::SLOW_QUERY_WEEKLY,
        }))),
        // sqlite 层错误信息不含 SQL 明文/凭据。
        Err(e) => Err(crate::db_handler::db_error(
            "REPORT_GENERATION_FAILED",
            &e.to_string(),
            500,
        )),
    }
}

// ── Query stats（reports-M1 / #29，migration 016）──
//
// 慢查询采样的读面。读端点不做 entitlement gate——对齐 list_reports /
// run-history 的 visible-but-locked 策略（Claims extractor 仍挡未认证请求）。
// 明文纪律：`sql_text` 只在实例 DBMASTER_SLOW_QUERY_STORE_SQL=true 时有值
// （写入侧就不落 NULL），错误信封不带 SQL 内容。

/// `?window=` 预设：`1h` / `24h`（默认）/ `7d`。非法值回退默认。
fn query_stats_window(raw: Option<&str>) -> chrono::Duration {
    match raw {
        Some("1h") => chrono::Duration::hours(1),
        Some("7d") => chrono::Duration::days(7),
        _ => chrono::Duration::hours(24),
    }
}

/// `?sort=` 白名单（防注入：直接映射到固定 SQL 片段）。默认 `total_ms`。
fn query_stats_sort_expr(raw: Option<&str>) -> &'static str {
    match raw {
        Some("count") => "COUNT(*)",
        Some("avg_ms") => "AVG(elapsed_ms)",
        Some("max_ms") => "MAX(elapsed_ms)",
        _ => "SUM(elapsed_ms)",
    }
}

const QUERY_STATS_SUMMARY_DEFAULT_LIMIT: i64 = 20;
const QUERY_STATS_SUMMARY_MAX_LIMIT: i64 = 100;
const QUERY_STATS_DEFAULT_LIMIT: i64 = 50;
const QUERY_STATS_MAX_LIMIT: i64 = 200;

#[derive(serde::Deserialize)]
pub struct QueryStatsSummaryQuery {
    pub window: Option<String>,
    pub conn_id: Option<String>,
    pub sort: Option<String>,
    pub limit: Option<i64>,
}

/// `GET /api/query-stats/summary` — 按 digest(+连接+库种) 聚合的 Top N
/// （聚合 SQL 与 M2 周报 writer 同源：`query_stats::aggregate`）。
/// `sample_sql_text` 两步查询取最新明文样本；meta 供客户端渲染口径横幅。
pub async fn query_stats_summary(
    _claims: Claims,
    State(state): State<AppState>,
    Query(q): Query<QueryStatsSummaryQuery>,
) -> Json<serde_json::Value> {
    let since = (chrono::Utc::now() - query_stats_window(q.window.as_deref())).to_rfc3339();
    let sort_expr = query_stats_sort_expr(q.sort.as_deref());
    let limit = q
        .limit
        .unwrap_or(QUERY_STATS_SUMMARY_DEFAULT_LIMIT)
        .clamp(1, QUERY_STATS_SUMMARY_MAX_LIMIT);

    let groups = crate::query_stats::aggregate(&state.pool, &since, q.conn_id.as_deref(), sort_expr, limit).await;

    match groups {
        Ok(groups) => {
            let mut items = Vec::with_capacity(groups.len());
            for g in groups {
                let sample =
                    crate::query_stats::latest_sample(&state.pool, &g.digest, &g.conn_id).await;
                items.push(serde_json::json!({
                    "digest": g.digest,
                    "db_kind": g.db_kind,
                    "conn_id": g.conn_id,
                    "count": g.count,
                    "total_ms": g.total_ms,
                    "avg_ms": g.avg_ms,
                    "max_ms": g.max_ms,
                    "first_seen": g.first_seen,
                    "last_seen": g.last_seen,
                    "sample_sql_text": sample,
                }));
            }
            Json(serde_json::json!({
                "ok": true,
                "data": {
                    "items": items,
                    "meta": {
                        "threshold_ms": state.config.slow_query_threshold_ms,
                        "store_sql": state.config.slow_query_store_sql,
                        "retention_days": state.config.slow_query_retention_days,
                        "dropped_total": crate::query_stats::dropped_total(),
                        "window_from": since,
                    },
                },
                "error": null,
            }))
        }
        Err(e) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
    }
}

#[derive(serde::Deserialize)]
pub struct QueryStatsListQuery {
    pub window: Option<String>,
    pub conn_id: Option<String>,
    pub digest: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(sqlx::FromRow, serde::Serialize)]
struct QueryStatsRow {
    id: String,
    source: String,
    conn_id: String,
    db_kind: String,
    database: Option<String>,
    digest: String,
    sql_text: Option<String>,
    elapsed_ms: i64,
    row_count: Option<i64>,
    affected_rows: Option<i64>,
    status: String,
    error_code: Option<String>,
    user_id: Option<String>,
    entry: String,
    captured_at: String,
}

/// `GET /api/query-stats` — 明细分页（时间窗/连接/digest/状态过滤）。
pub async fn query_stats_list(
    _claims: Claims,
    State(state): State<AppState>,
    Query(q): Query<QueryStatsListQuery>,
) -> Json<serde_json::Value> {
    let since = (chrono::Utc::now() - query_stats_window(q.window.as_deref())).to_rfc3339();
    let limit = q
        .limit
        .unwrap_or(QUERY_STATS_DEFAULT_LIMIT)
        .clamp(1, QUERY_STATS_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0).max(0);

    let rows = sqlx::query_as::<_, QueryStatsRow>(
        "SELECT id, source, conn_id, db_kind, database, digest, sql_text, elapsed_ms, \
         row_count, affected_rows, status, error_code, user_id, entry, captured_at \
         FROM query_stats \
         WHERE captured_at >= ?1 AND (?2 IS NULL OR conn_id = ?2) \
         AND (?3 IS NULL OR digest = ?3) AND (?4 IS NULL OR status = ?4) \
         ORDER BY captured_at DESC LIMIT ?5 OFFSET ?6",
    )
    .bind(&since)
    .bind(&q.conn_id)
    .bind(&q.digest)
    .bind(&q.status)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await;

    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM query_stats \
         WHERE captured_at >= ?1 AND (?2 IS NULL OR conn_id = ?2) \
         AND (?3 IS NULL OR digest = ?3) AND (?4 IS NULL OR status = ?4)",
    )
    .bind(&since)
    .bind(&q.conn_id)
    .bind(&q.digest)
    .bind(&q.status)
    .fetch_one(&state.pool)
    .await;

    match (rows, total) {
        (Ok(items), Ok(total)) => Json(serde_json::json!({
            "ok": true,
            "data": {"items": items, "total": total, "limit": limit, "offset": offset},
            "error": null,
        })),
        (Err(e), _) | (_, Err(e)) => Json(serde_json::json!({"ok": false, "data": null, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
    }
}

// ── Drift: run history + snapshot reads (Phase F desktop UI) ──
// CHANGE: read-only views over Phase E tables. No gate — matches list_reports
// policy (visible-but-locked under EntitlementState::Gated). The Claims
// extractor still rejects unauthenticated requests at the router layer, so
// these handlers only execute for verified users.

/// Default and max bounds for `?limit` on list endpoints. Default applies when
/// the client omits the param or passes a non-positive value; max caps
/// pathological requests to keep response payloads bounded.
const RUN_HISTORY_DEFAULT_LIMIT: i64 = 50;
const RUN_HISTORY_MAX_LIMIT: i64 = 200;
// #4 Saved Queries list — limit clamps. Default 100 covers a team library;
// max 500 bounds payload size for very active workspaces.
const SAVED_QUERY_DEFAULT_LIMIT: i64 = 100;
const SAVED_QUERY_MAX_LIMIT: i64 = 500;
const SNAPSHOT_LIST_DEFAULT_LIMIT: i64 = 50;
const SNAPSHOT_LIST_MAX_LIMIT: i64 = 200;

/// Clamp a client-supplied limit to `[1, max]`, returning `default` for None
/// or non-positive values. Centralised so each handler stays a one-liner and
/// the bounds are auditable in one place.
fn clamp_limit(raw: Option<i64>, default: i64, max: i64) -> i64 {
    match raw {
        Some(n) if n > 0 => n.min(max),
        _ => default,
    }
}

/// 400 envelope for malformed / missing query string params.
fn bad_query(message: &'static str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "ok": false,
            "data": null,
            "error": {"code": "BAD_QUERY", "message": message}
        })),
    )
}

pub async fn list_run_history(
    _claims: Claims,
    State(state): State<AppState>,
    // CHANGE: axum::extract::Query returns QueryRejection on missing/invalid
    // params (e.g. task_id absent, or limit=abc). We capture the Result so we
    // can surface our standard {ok,data,error} envelope instead of axum's
    // plain-text rejection. The Claims extractor runs first (parts extractors
    // fire in declaration order), so an unauthenticated request returns 401
    // before this query-decode path is reached.
    query: Result<Query<RunHistoryQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Query(q) = query.map_err(|_| bad_query(
        "missing or invalid query parameters (expected task_id, optional limit)"
    ))?;
    let limit = clamp_limit(q.limit, RUN_HISTORY_DEFAULT_LIMIT, RUN_HISTORY_MAX_LIMIT);

    // DEFENSIVE-NOTE: parameterised query — task_id / limit never concatenated
    // into SQL, so a hostile task_id (e.g. "'; DROP TABLE …") is bound as a
    // literal and the FK lookup simply returns no rows. We bind limit as i64
    // (SQLite's native int) — sqlx rejects fractional / out-of-range values at
    // the type level, so no runtime check needed.
    let rows = sqlx::query_as::<_, crate::TaskRunHistory>(
        "SELECT id, task_id, started_at, finished_at, status, error, summary, triggered_by
         FROM task_run_history
         WHERE task_id = ?1
         ORDER BY started_at DESC
         LIMIT ?2",
    )
    .bind(&q.task_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await;

    match rows {
        // DEFENSIVE-NOTE: missing task_id returns [] (list semantics — caller
        // decides whether [] means "no such task" or "task has never run"),
        // matching the brief: "connection_id/task_id 不存在 → 返回空数组（不 404）".
        Ok(r) => Ok(Json(serde_json::json!({"ok": true, "data": r, "error": null}))),
        Err(e) => Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "DB_ERROR", "message": e.to_string()}
        }))),
    }
}

/// `GET /api/health-results?task_id=&limit=` — read-only history of
/// health_check runs (ADR-0004 §5 M5 T29). Mirrors `list_run_history` shape:
/// parameterised query, clamp_limit, list-missing-task-returns-[] semantics.
/// No gate (read-only; visible-but-locked under Gated, same as run-history).
// CHANGE: ADR-0004 §5 — read endpoint for the M4 runner's health_check_results rows.
pub async fn list_health_results(
    _claims: Claims,
    State(state): State<AppState>,
    query: Result<Query<crate::HealthResultsQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Query(q) = query.map_err(|_| bad_query(
        "missing or invalid query parameters (expected task_id, optional limit)"
    ))?;
    let limit = clamp_limit(q.limit, RUN_HISTORY_DEFAULT_LIMIT, RUN_HISTORY_MAX_LIMIT);

    let rows = sqlx::query_as::<_, crate::HealthCheckResult>(
        "SELECT id, task_id, started_at, finished_at, status, \
                metrics_summary, alert_changes, triggered_by, error \
         FROM health_check_results \
         WHERE task_id = ?1 \
         ORDER BY started_at DESC \
         LIMIT ?2",
    )
    .bind(&q.task_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(r) => Ok(Json(serde_json::json!({"ok": true, "data": r, "error": null}))),
        Err(e) => Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "DB_ERROR", "message": e.to_string()}
        }))),
    }
}

pub async fn list_snapshots(
    _claims: Claims,
    State(state): State<AppState>,
    query: Result<Query<SnapshotListQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Query(q) = query.map_err(|_| bad_query(
        "missing or invalid query parameters (expected connection_id, optional limit)"
    ))?;
    let limit = clamp_limit(q.limit, SNAPSHOT_LIST_DEFAULT_LIMIT, SNAPSHOT_LIST_MAX_LIMIT);

    // DEFENSIVE-NOTE: schema_json intentionally omitted from this projection.
    // For wide customer schemas it can reach tens of KB to MB; a list of N
    // snapshots would multiply that. The desktop fetches the full row lazily
    // via GET /api/snapshots/:id when the user actually opens a diff. Column
    // list mirrors SchemaSnapshotMeta field set exactly so sqlx FromRow maps
    // cleanly (extra/missing columns would error at row-decode time).
    let rows = sqlx::query_as::<_, crate::SchemaSnapshotMeta>(
        "SELECT id, connection_id, captured_at, schema_hash, prior_hash, task_id, change_count
         FROM schema_snapshots
         WHERE connection_id = ?1
         ORDER BY captured_at DESC
         LIMIT ?2",
    )
    .bind(&q.connection_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(r) => Ok(Json(serde_json::json!({"ok": true, "data": r, "error": null}))),
        Err(e) => Ok(Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "DB_ERROR", "message": e.to_string()}
        }))),
    }
}

pub async fn get_snapshot(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let row = sqlx::query_as::<_, crate::SchemaSnapshot>(
        "SELECT id, connection_id, captured_at, schema_hash, schema_json, prior_hash, task_id, change_count
         FROM schema_snapshots
         WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await;

    match row {
        Ok(Some(s)) => Json(serde_json::json!({"ok": true, "data": s, "error": null})),
        Ok(None) => Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "NOT_FOUND", "message": "Snapshot not found"}
        })),
        Err(e) => Json(serde_json::json!({
            "ok": false, "data": null,
            "error": {"code": "DB_ERROR", "message": e.to_string()}
        })),
    }
}

// ── data-sync 一期 — task enable/disable + cancel + run listing ──

/// PATCH /api/tasks/:id — partial update of a scheduled task.
///
/// All fields optional (PATCH semantics): only provided fields are updated.
/// Existing clients sending `{"enabled": true}` continue to work — the
/// previously-required `enabled: bool` is now `Option<bool>`, and `true`/
/// `false` deserialize as `Some(true)`/`Some(false)`.
///
/// #5 — previously only `enabled` was mutable; users had to DELETE + recreate
/// to change cron/config/target/notify, breaking run_history association.
///
/// **Limitation**: `target_db_id: None` means "leave unchanged"; clearing it
/// (setting to NULL) is not supported via PATCH because serde can't distinguish
/// absent-vs-explicit-null with `Option<String>`. To clear, DELETE + recreate.
/// Same applies to `notify_channels` (use empty array `[]` to clear).
// CHANGE: #5 — extended from `{ enabled: bool }` to partial PATCH. Cron format
// is NOT validated here (mirrors create_task, which also doesn't validate) —
// the scheduler will fail at the next tick on malformed cron, surfacing via
// last_status.
pub async fn update_task(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateTaskRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }

    // Build SET clause + bind values dynamically based on which fields present.
    // Set literals are fixed strings; user data only flows through .bind().
    let mut sets: Vec<&'static str> = Vec::new();
    if body.enabled.is_some() {
        sets.push("enabled = ?");
    }
    if body.name.is_some() {
        sets.push("name = ?");
    }
    if body.cron_expr.is_some() {
        sets.push("cron_expr = ?");
    }
    if body.config.is_some() {
        sets.push("config = ?");
    }
    if body.target_db_id.is_some() {
        sets.push("target_db_id = ?");
    }
    if body.notify_channels.is_some() {
        sets.push("notify_channels = ?");
    }
    if sets.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": {"code": "EMPTY_PATCH", "message": "No updatable fields provided"}
            })),
        ));
    }
    // Always bump updated_at — the column exists but was previously never
    // written by any UPDATE (latent schema/contract bug fixed alongside #5).
    sets.push("updated_at = ?");
    let set_sql = sets.join(", ");
    let sql = format!("UPDATE scheduled_tasks SET {set_sql} WHERE id = ?");
    // Splice-safe: set_sql only contains the literal fragments above + the
    // literal "updated_at = ?"; user values flow through .bind() below.

    let mut stmt = sqlx::query(&sql);
    if let Some(enabled) = body.enabled {
        stmt = stmt.bind(enabled);
    }
    if let Some(name) = &body.name {
        stmt = stmt.bind(name);
    }
    if let Some(cron) = &body.cron_expr {
        stmt = stmt.bind(cron);
    }
    if let Some(config) = &body.config {
        stmt = stmt.bind(config.to_string());
    }
    if let Some(target) = &body.target_db_id {
        stmt = stmt.bind(target);
    }
    if let Some(channels) = &body.notify_channels {
        let json = serde_json::to_string(channels).unwrap_or_else(|_| "[]".into());
        stmt = stmt.bind(json);
    }
    let now = chrono::Utc::now().to_rfc3339();
    stmt = stmt.bind(now);
    stmt = stmt.bind(&id);

    let result = stmt.execute(&state.pool).await;
    match result {
        Ok(done) => {
            if done.rows_affected() == 0 {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "ok": false, "data": null,
                        "error": {"code": "NOT_FOUND", "message": "Task not found"}
                    })),
                ));
            }
            // Fetch + return the updated row (mirrors create_task shape).
            let task = sqlx::query_as::<_, crate::ScheduledTask>(
                "SELECT id, name, task_type, cron_expr, config, source_db_id, target_db_id,
                        notify_channels, enabled, last_run_at, last_status, created_at
                 FROM scheduled_tasks WHERE id = ?1",
            )
            .bind(&id)
            .fetch_one(&state.pool)
            .await;
            match task {
                Ok(t) => Ok(Json(serde_json::json!({
                    "ok": true, "data": t, "error": null
                }))),
                Err(e) => Ok(Json(serde_json::json!({
                    "ok": false, "data": null,
                    "error": {"code": "FETCH_FAILED", "message": e.to_string()}
                }))),
            }
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": { "code": "DB_ERROR", "message": e.to_string() }
            })),
        )),
    }
}

/// POST /api/tasks/:id/cancel — request cancellation of the running data_sync
/// run for this task. Sets `cancel_requested = 1` on the latest running row;
/// the runner polls this between batches and stops at the next batch boundary.
/// Returns 200 even if nothing is running (idempotent).
pub async fn cancel_task(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(gated) = gate_blocked(&state) {
        return Err(gated);
    }
    let result = sqlx::query(
        "UPDATE data_sync_runs SET cancel_requested = 1
         WHERE task_id = ?1 AND status = 'running'",
    )
    .bind(&id)
    .execute(&state.pool)
    .await;
    match result {
        Ok(done) => Ok(Json(serde_json::json!({
            "ok": true,
            "data": {
                "task_id": id,
                "cancel_requested": true,
                "rows_affected": done.rows_affected()
            },
            "error": null
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": { "code": "DB_ERROR", "message": e.to_string() }
            })),
        )),
    }
}

/// GET /api/tasks/:id/data-sync-runs?limit=N — list recent data_sync run
/// rows (progress / cursor / status / processed_rows / failed_rows). Read-only
/// (no gate). The desktop polls this every 2-3s for the progress panel.
#[derive(serde::Deserialize)]
pub struct DataSyncRunsQuery {
    pub limit: Option<i64>,
}

pub async fn list_data_sync_runs(
    _claims: Claims,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<DataSyncRunsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let rows: Result<Vec<DataSyncRunRow>, _> = sqlx::query_as::<_, DataSyncRunRow>(
        "SELECT id, task_id, started_at, finished_at, status, progress, cursor,
                processed_rows, failed_rows, error, summary, triggered_by
         FROM data_sync_runs WHERE task_id = ?1
         ORDER BY started_at DESC LIMIT ?2",
    )
    .bind(&id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(list) => Ok(Json(serde_json::json!({
            "ok": true,
            "data": list.iter().map(|r| serde_json::json!({
                "id": r.id,
                "task_id": r.task_id,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "status": r.status,
                "progress": r.progress,
                "cursor": r.cursor,
                "processed_rows": r.processed_rows,
                "failed_rows": r.failed_rows,
                "error": r.error,
                "summary": r.summary.as_ref().and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()),
                "triggered_by": r.triggered_by,
            })).collect::<Vec<_>>(),
            "error": null
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false, "data": null,
                "error": { "code": "DB_ERROR", "message": e.to_string() }
            })),
        )),
    }
}

// CHANGE: #5 — extended from `{ enabled: bool }` (single required field) to
// partial-PATCH shape. All fields optional → existing clients sending
// `{"enabled": true}` still work (deserializes as Some(true)).
#[derive(serde::Deserialize)]
pub struct UpdateTaskRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub cron_expr: Option<String>,
    /// Stored as JSON text (server serializes via serde_json::to_string).
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// None = leave unchanged. Clearing (→ NULL) not supported via PATCH
    /// (see update_task doc); DELETE + recreate to clear.
    #[serde(default)]
    pub target_db_id: Option<String>,
    /// None = leave unchanged. Empty Vec `[]` clears the list.
    #[serde(default)]
    pub notify_channels: Option<Vec<String>>,
}

#[derive(sqlx::FromRow)]
struct DataSyncRunRow {
    id: String,
    task_id: String,
    started_at: String,
    finished_at: Option<String>,
    status: String,
    progress: i64,
    cursor: Option<String>,
    processed_rows: i64,
    failed_rows: i64,
    error: Option<String>,
    summary: Option<String>,
    triggered_by: String,
}
