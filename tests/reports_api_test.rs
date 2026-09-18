//! Reports 端点集成测试（#29 reports 管道 M2，migration 017）。
//!
//! 覆盖：`POST /api/reports/generate`（认证/幂等/未知类型 400/Gated 403）、
//! `GET /api/reports` 新分页形状（{items,total,limit,offset} + report_type
//! 过滤）、`GET /api/reports/:id`、generate→list→detail HTTP 闭环。
//! Gated 态 GET 放行断言在 automation_gate_test.rs（已有 /api/reports URI）。

mod common;

use axum::http::StatusCode;
use serde_json::json;

async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: serde_json::Value = common::post(
        app,
        "/api/auth/register",
        json!({
            "email": email,
            "password": "secure12345",
            "display_name": "Test User"
        }),
    )
    .await
    .json_value()
    .await;
    body["access_token"].as_str().unwrap().to_string()
}

async fn seed_sample(pool: &sqlx::SqlitePool, id: &str, elapsed: i64, mins_ago: i64) {
    let at = (chrono::Utc::now() - chrono::Duration::minutes(mins_ago)).to_rfc3339();
    sqlx::query(
        "INSERT INTO query_stats (id, source, conn_id, db_kind, database, digest, sql_text, \
         elapsed_ms, row_count, affected_rows, status, error_code, user_id, entry, captured_at) \
         VALUES (?1, 'gateway', 'c1', 'mysql', 'db', 'SELECT SLEEP(?)', 'SELECT SLEEP(1.5)', \
         ?2, 1, NULL, 'ok', NULL, NULL, 'sync_query', ?3)",
    )
    .bind(id)
    .bind(elapsed)
    .bind(at)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn generate_requires_auth_and_unknown_type_rejected() {
    let mut app = common::build_test_app().await;
    // 无认证 → 401。
    common::post(&mut app, "/api/reports/generate", json!({}))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let token = register_and_get_token(&mut app, "rep-gen@example.com").await;
    // 未知类型 → 400 UNKNOWN_REPORT_TYPE。
    let resp = common::post_with_auth(
        &mut app,
        "/api/reports/generate",
        json!({"report_type": "drift_weekly"}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body = resp.json_value().await;
    assert_eq!(body["error"]["code"], json!("UNKNOWN_REPORT_TYPE"));
}

#[tokio::test]
async fn generate_list_detail_roundtrip_with_pagination() {
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "rep-round@example.com").await;
    seed_sample(&pool, "s1", 3000, 60).await;
    seed_sample(&pool, "s2", 2500, 30).await;

    // 生成 → created:true。
    let resp = common::post_with_auth(
        &mut app,
        "/api/reports/generate",
        json!({}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::OK);
    let body = resp.json_value().await;
    assert_eq!(body["data"]["created"], json!(true));
    let report_id = body["data"]["id"].as_str().unwrap().to_string();

    // 幂等：再生成 → created:false、同 id。
    let body: serde_json::Value = common::post_with_auth(
        &mut app,
        "/api/reports/generate",
        json!({}),
        &token,
    )
    .await
    .json_value()
    .await;
    assert_eq!(body["data"]["created"], json!(false));
    assert_eq!(body["data"]["id"], json!(report_id));

    // 列表新形状 + type 过滤。
    let body: serde_json::Value = common::get_with_auth(
        &mut app,
        "/api/reports?report_type=slow_query_weekly&limit=10&offset=0",
        &token,
    )
    .await
    .json_value()
    .await;
    assert_eq!(body["ok"], json!(true));
    assert_eq!(body["data"]["total"], json!(1));
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], json!(report_id));
    assert_eq!(items[0]["report_type"], json!("slow_query_weekly"));
    assert_eq!(items[0]["task_id"], json!(null), "系统周报无任务归属");
    assert!(
        items[0]["title"].as_str().unwrap().contains("W"),
        "标题应带周标识: {}",
        items[0]["title"]
    );

    // 其它类型过滤 → 0。
    let body: serde_json::Value = common::get_with_auth(
        &mut app,
        "/api/reports?report_type=drift_weekly",
        &token,
    )
    .await
    .json_value()
    .await;
    assert_eq!(body["data"]["total"], json!(0));

    // detail：content 是 JSON 字符串（客户端解码），带 content_version。
    let body: serde_json::Value = common::get_with_auth(
        &mut app,
        &format!("/api/reports/{report_id}"),
        &token,
    )
    .await
    .json_value()
    .await;
    assert_eq!(body["ok"], json!(true));
    let content: serde_json::Value =
        serde_json::from_str(body["data"]["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["content_version"], json!(1));
    assert_eq!(content["summary"]["total_samples"], json!(2));
    assert_eq!(content["summary"]["total_ms"], json!(5500));
}

#[tokio::test]
async fn gated_blocks_generate_but_allows_list() {
    let mut app = common::build_test_app_with_entitlement(
        dbmaster_license::EntitlementState::Gated {
            reason: dbmaster_license::GatedReason::TrialExpired,
        },
    )
    .await;
    let token = register_and_get_token(&mut app, "rep-gated@example.com").await;

    let resp = common::post_with_auth(
        &mut app,
        "/api/reports/generate",
        json!({}),
        &token,
    )
    .await;
    resp.assert_status(StatusCode::FORBIDDEN);
    let body = resp.json_value().await;
    assert_eq!(body["error"]["code"], json!("ENTITLEMENT_GATED"));

    // 读路径放行（visible-but-locked）。
    common::get_with_auth(&mut app, "/api/reports", &token)
        .await
        .assert_status(StatusCode::OK);
}
