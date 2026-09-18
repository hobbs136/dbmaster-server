//! T27 集成测试：网关元数据端点 + 认证（真 SQLite 目标库，不 mock DB）。
//!
//! 覆盖：401/无质询头、连接列表安全投影、三级钻取、NOT_FOUND /
//! UNSUPPORTED_DB_TYPE 错误码与 wire 形状（`{"error":{"code","message"}}`）。

mod common;

use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
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
async fn missing_token_is_401_with_challenge() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let app = router(config.clone(), pool);

    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/api/gw/connections").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers().get("www-authenticate").unwrap(), "Bearer");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn invalid_token_is_401() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let app = router(config, pool);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/gw/connections")
                .header("Authorization", "Bearer not-a-jwt")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_connections_is_safe_projection() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("meta").await;
    register_connection(&pool, "conn-1", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let resp = app
        .oneshot(authed_get(&token, "/api/gw/connections"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "conn-1");
    assert_eq!(arr[0]["dbType"], "sqlite");
    // 安全投影：永不回 host/凭据/文件路径。
    assert!(body.to_string().find(&target).is_none());
    assert!(body.to_string().find("host").is_none());
}

#[tokio::test]
async fn three_level_drilldown_on_real_sqlite() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let target = target_sqlite_db("drill").await;
    register_connection(&pool, "conn-d", &target, "sqlite").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    // databases
    let resp = app
        .clone()
        .oneshot(authed_get(&token, "/api/gw/connections/conn-d/databases"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let dbs: Vec<String> = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(dbs, vec!["main".to_string()]);

    // tables（camelCase 键 + table/view kind）
    let resp = app
        .clone()
        .oneshot(authed_get(&token, "/api/gw/connections/conn-d/tables"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tables: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let names: Vec<&str> = tables.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"artist"));
    assert!(names.contains(&"big"));

    // describe（列 + PK）
    let resp = app
        .clone()
        .oneshot(authed_get(&token, "/api/gw/connections/conn-d/describe?table=artist"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let desc: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(desc["table"], "artist");
    assert_eq!(desc["columns"][0]["name"], "id");
    assert_eq!(desc["primaryKey"], serde_json::json!(["id"]));
}

#[tokio::test]
async fn unknown_connection_is_not_found_with_wire_error() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let resp = app
        .oneshot(authed_get(&token, "/api/gw/connections/nope/databases"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "NOT_FOUND");
    assert!(v["error"]["message"].as_str().unwrap().contains("nope"));
}

#[tokio::test]
async fn unsupported_db_type_is_400() {
    let config = test_config(GwKnobs::default());
    let pool = server_pool().await;
    // metadata 族外的 db_type 走 load_connection → UNSUPPORTED_DB_TYPE。
    //（T29 非 SQL 批次后 mongodb 已支持——换 oracle 钉「真不支持」边界。）
    register_connection(&pool, "conn-x", "unused", "oracle").await;
    let token = token_for(&config, "user-1");
    let app = router(config, pool);

    let resp = app
        .oneshot(authed_get(&token, "/api/gw/connections/conn-x/databases"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(v["error"]["code"], "UNSUPPORTED_DB_TYPE");
}
