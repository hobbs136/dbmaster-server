//! T27 集成测试：连接注册族（register/test/remove，T28 前置）+ per-user
//! 限流 + 审计动作。

mod common;

use axum::http::StatusCode;
use sqlx::SqlitePool;
use tower::ServiceExt;

use common::*;

fn router(
    config: std::sync::Arc<dbmaster_core::config::Config>,
    pool: SqlitePool,
) -> axum::Router {
    dbmaster_gateway::router(config, pool, [7u8; 32])
}

#[tokio::test]
async fn register_query_remove_lifecycle() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("lifecycle").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool.clone());

    // 注册（凭据入 vault；返回 serverConnId）。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "gw-lifecycle",
                "dbType": "sqlite",
                "filePath": target,
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let server_conn_id = v["serverConnId"].as_str().unwrap().to_string();
    assert!(!server_conn_id.is_empty());

    // 注册后即可树 + 查询。
    let resp = app
        .clone()
        .oneshot(authed_get(&token, &format!("/api/gw/connections/{server_conn_id}/tables")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            &format!("/api/gw/connections/{server_conn_id}/query"),
            serde_json::json!({ "sql": "SELECT count(*) AS n FROM artist" }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_string(resp.into_body()).await;
    let events = parse_sse(&text);
    assert_eq!(events.last().unwrap().0, "complete");
    assert_eq!(events.last().unwrap().1["rowCount"], 1);

    // 删除幂等 204；之后查询 NOT_FOUND。
    let resp = app
        .clone()
        .oneshot(authed_delete(&token, &format!("/api/gw/connections/{server_conn_id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app
        .clone()
        .oneshot(authed_get(&token, &format!("/api/gw/connections/{server_conn_id}/databases")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 审计：注册/删除各一行。
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM gw_audit WHERE action LIKE 'connection_%' ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(actions, vec!["connection_registered".to_string(), "connection_removed".to_string()]);
}

#[tokio::test]
async fn register_stores_encrypted_password_not_plaintext() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool.clone());

    let resp = app
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({
                "name": "never-used", "dbType": "mysql",
                "host": "127.0.0.1", "port": 3306,
                "username": "root", "password": "S3cret-plain",
            })
            .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let stored: String = sqlx::query_scalar(
        "SELECT password_encrypted FROM database_connections WHERE name = 'never-used'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // AES-256-GCM v1 前缀 + base64 密文，绝无明文。
    assert!(stored.starts_with("v1:"));
    assert!(!stored.contains("S3cret-plain"));
}

// 网络层批次回归（真 e2e 抓出的 INSERT bind 缺失）：带 ssh 块注册 →
// `ssh_secret_encrypted` 必须落密文（e2e 曾证 INSERT 漏 bind 后 SQLite 把
// 未绑定占位符静默落 NULL，extra 四键在而 secret 空 → 执行期 "secret is
// missing"）；同指纹重注册不带 ssh → UPDATE 置 NULL（删隧道重注册生效）。
#[tokio::test]
async fn register_persists_then_clears_ssh_secret() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool.clone());

    let body_with_ssh = serde_json::json!({
        "name": "ssh-vault", "dbType": "mysql",
        "host": "10.0.0.9", "port": 3306,
        "username": "root", "password": "db-pass",
        "ssh": {"host": "jump.example.com", "port": 2222, "username": "deploy",
                 "authMode": "password", "password": "jump-pass"},
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(authed_post_json(&token, "/api/gw/connections", body_with_ssh))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (secret, extra): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT ssh_secret_encrypted, extra FROM database_connections WHERE name = 'ssh-vault'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // INSERT 路径：秘密落密文（v1 前缀，无明文），extra 携带非秘密四键。
    let secret = secret.expect("INSERT must persist ssh_secret_encrypted (bind was once missing)");
    assert!(secret.starts_with("v1:"));
    assert!(!secret.contains("jump-pass"));
    let extra = extra.expect("extra carries ssh non-secret keys");
    assert!(extra.contains("jump.example.com"));
    assert!(extra.contains("sshAuthMode"));
    assert!(!extra.contains("jump-pass"), "secret must never land in extra: {extra}");

    // 同指纹重注册（不带 ssh）→ UPDATE 复用行并清空 secret。
    let body_no_ssh = serde_json::json!({
        "name": "ssh-vault", "dbType": "mysql",
        "host": "10.0.0.9", "port": 3306,
        "username": "root", "password": "db-pass",
    })
    .to_string();
    let resp = app
        .oneshot(authed_post_json(&token, "/api/gw/connections", body_no_ssh))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["reused"], serde_json::json!(true), "same fingerprint must reuse the row");
    let (secret, extra): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT ssh_secret_encrypted, extra FROM database_connections WHERE name = 'ssh-vault'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(secret.is_none(), "UPDATE must clear ssh_secret_encrypted when draft has no ssh");
    let extra = extra.unwrap_or_default();
    assert!(!extra.contains("sshHost"), "ssh non-secret keys must be gone: {extra}");
}

// vault 无界增长根治①（P1）：注册幂等——同 owner + 同指纹（name+db_type+
// host+port+username+default_database+file_path，不含密码）复用 serverConnId
// 并刷新凭据/会话参数；指纹任一字段不同则新建；删除后重注册 = 新行。
#[tokio::test]
async fn register_is_idempotent_on_fingerprint() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("dedupe").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool.clone());

    let register = |name: &str, path: &str, read_only: bool| {
        serde_json::json!({
            "name": name, "dbType": "sqlite", "filePath": path,
            "readOnly": read_only,
        })
        .to_string()
    };

    // 首次注册：新 id，无 reused 标记。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            register("dup-conn", &target, false),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let id1 = v["serverConnId"].as_str().unwrap().to_string();
    assert!(!id1.is_empty());
    assert!(v.get("reused").is_none(), "first register must not be flagged reused: {v}");

    // 同指纹重注册（参数变化）：复用 id1 + reused:true，read_only 刷新。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            register("dup-conn", &target, true),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["serverConnId"].as_str().unwrap(), id1, "same fingerprint must reuse id: {v}");
    assert_eq!(v["reused"], true);

    let (rows, read_only): (i64, i64) = sqlx::query_as(
        "SELECT count(*), max(read_only) FROM database_connections WHERE name = 'dup-conn'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1, "same fingerprint must not accumulate rows");
    assert_eq!(read_only, 1, "reuse path must refresh gateway params");

    // 不同名（不同指纹）：新行新 id。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            register("other-conn", &target, false),
        ))
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let id2 = v["serverConnId"].as_str().unwrap().to_string();
    assert_ne!(id1, id2);

    // 删除后同指纹重注册：新行（复用只对存活行）。
    let resp = app
        .clone()
        .oneshot(authed_delete(&token, &format!("/api/gw/connections/{id1}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            register("dup-conn", &target, false),
        ))
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let id3 = v["serverConnId"].as_str().unwrap().to_string();
    assert_ne!(id1, id3, "register after delete must create a fresh row");
}

#[tokio::test]
async fn register_validates_required_fields_per_family() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    // sqlite 缺 filePath。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({ "name": "x", "dbType": "sqlite" }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "CONFIG");

    // mysql 缺 host。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({ "name": "x", "dbType": "mysql", "port": 3306, "username": "u", "password": "p" }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // T28 — sqlserver 缺 password（host+port+user+pwd 族校验，注册不触库）。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({ "name": "ss-no-pwd", "dbType": "sqlserver", "host": "h", "port": 1433, "username": "sa" }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "CONFIG");

    // T28 — sqlserver 完整草稿过校验（register 不试连）。
    let resp = app
        .clone()
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({ "name": "ss-ok", "dbType": "sqlserver", "host": "h", "port": 1433, "username": "sa", "password": "p" }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 未知 dbType。
    let resp = app
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections",
            serde_json::json!({ "name": "x", "dbType": "oracle", "host": "h", "port": 1, "username": "u", "password": "p" }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "UNSUPPORTED_DB_TYPE");
}

#[tokio::test]
async fn test_connection_ok_with_server_version() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("test-ok").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let resp = app
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/test",
            serde_json::json!({ "dbType": "sqlite", "filePath": target }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["elapsedMs"].as_u64().is_some());
    // SQLite 版本字符串（如 "3.45.x"）。
    assert!(v["serverVersion"].as_str().unwrap().starts_with("3."));
}

#[tokio::test]
async fn test_connection_failure_is_ok_false_with_redacted_error() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    // 不存在的 SQLite 文件（create_if_missing=false → 即时失败；避免
    // TCP 拒连在 Windows 上吃满 sqlx 默认 30s acquire 超时拖慢套件）。
    let bogus = std::env::temp_dir().join("dbmaster-gw-never-exists.db");
    let resp = app
        .oneshot(authed_post_json(
            &token,
            "/api/gw/connections/test",
            serde_json::json!({ "dbType": "sqlite", "filePath": bogus.display().to_string() }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["ok"], false);
    // redact 纪律：不回传本地路径细节。
    assert!(!v["error"].as_str().unwrap().contains("dbmaster-gw-never-exists"));
}

#[tokio::test]
async fn per_user_rate_limit_returns_429() {
    let knobs = GwKnobs { rate_limit_per_minute: 1, ..Default::default() };
    let config = test_config(knobs);
    let pool = server_pool().await;
    let token = token_for(&config, "user-rl");
    let token_other = token_for(&config, "user-other");
    let app = router(config, pool);

    // 第一发过。
    let resp = app
        .clone()
        .oneshot(authed_get(&token, "/api/gw/connections"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 同用户第二发 429。
    let resp = app
        .clone()
        .oneshot(authed_get(&token, "/api/gw/connections"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "RATE_LIMITED");
    // per-user 隔离：另一用户不受累。
    let resp = app
        .oneshot(authed_get(&token_other, "/api/gw/connections"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
