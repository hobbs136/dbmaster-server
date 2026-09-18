//! 原生慢查源采集器真库 e2e（#29 reports 管道 M3，N-T5）。
//!
//! - **MySQL**：临时开启 `slow_query_log`/`log_output=TABLE`/`long_query_time=1`
//!   → 经数据面跑 SLEEP → 进程内调 `collect_all` → 断言 `db_native:mysql_slow_log`
//!   行 → 二次 collect 幂等 → **finally 恢复全局变量**。
//! - **Redis**：`CONFIG SET slowlog-log-slower-than 1`（1µs 全记）→ 经 gw
//!   kind:"redis" 跑命令 → collect → 断言 `db_native:redis_slowlog` 行 →
//!   恢复原阈值。
//!
//! 门控：`NC_E2E_MYSQL_HOST` / `NC_E2E_REDIS_HOST` 缺失时对应组跳过
//! （凭据见仓库外 test_db_server.txt）：
//! ```sh
//! NC_E2E_MYSQL_HOST=<host> NC_E2E_MYSQL_PASSWORD=... \
//! NC_E2E_REDIS_HOST=<host> NC_E2E_REDIS_PASSWORD=... \
//! cargo test --test native_collector_e2e_test -- --nocapture
//! ```

mod common;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::SqlitePool;

async fn register_and_get_token(app: &mut axum::Router, email: &str) -> String {
    let body: serde_json::Value = common::post(
        app,
        "/api/auth/register",
        json!({"email": email, "password": "secure12345", "display_name": "T"}),
    )
    .await
    .json_value()
    .await;
    body["access_token"].as_str().unwrap().to_string()
}

async fn create_connection(
    app: &mut axum::Router,
    token: &str,
    body: serde_json::Value,
) -> String {
    // gw 注册面（与网关适配器同通道；返回 {"serverConnId": id}）。
    let resp = common::post_with_auth(app, "/api/gw/connections", body, token).await;
    resp.assert_ok();
    resp.json_value().await["serverConnId"].as_str().unwrap().to_string()
}

fn mysql_env() -> Option<(String, i64, String, String)> {
    let host = std::env::var("NC_E2E_MYSQL_HOST").ok().filter(|v| !v.is_empty())?;
    let port = std::env::var("NC_E2E_MYSQL_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(3306);
    let user = std::env::var("NC_E2E_MYSQL_USER").unwrap_or_else(|_| "root".to_string());
    let password = std::env::var("NC_E2E_MYSQL_PASSWORD").unwrap_or_default();
    Some((host, port, user, password))
}

fn redis_env() -> Option<(String, i64, String, String)> {
    let host = std::env::var("NC_E2E_REDIS_HOST").ok().filter(|v| !v.is_empty())?;
    let port = std::env::var("NC_E2E_REDIS_PORT")
        .ok()
        .and_then(|p| p.parse::<i64>().ok())
        .unwrap_or(6379);
    let user = std::env::var("NC_E2E_REDIS_USER").unwrap_or_else(|_| "default".to_string());
    let password = std::env::var("NC_E2E_REDIS_PASSWORD").unwrap_or_default();
    Some((host, port, user, password))
}

async fn native_rows(pool: &SqlitePool, source: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM query_stats WHERE source = ?1")
        .bind(source)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// 两个 MySQL e2e 都改全局 slow log 变量且采集器按其分流——并行会互相
/// 踩（slow_log 测试开 TABLE 会让 PS 测试的 collect 走错路径）。静态锁
/// 串行化（同 binary 内；Redis 测试不受影响）。
static MYSQL_E2E_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[tokio::test]
async fn mysql_slow_log_table_collection_e2e() {
    let _guard = MYSQL_E2E_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let Some((host, port, user, password)) = mysql_env() else {
        eprintln!("NC_E2E_MYSQL_HOST not set; skipping");
        return;
    };
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "nc-mysql@example.com").await;
    let conn_id = create_connection(
        &mut app,
        &token,
        json!({
            "name": "nc-e2e-mysql",
            "dbType": "mysql",
            "host": host, "port": port,
            "username": user, "password": password,
        }),
    )
    .await;

    // 目标库原值保存（恢复用）。
    let mp = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&format!("mysql://{user}:{password}@{host}:{port}/mysql"))
        .await
        .unwrap();
    let restore = async {
        let (on, out, lqt): (i32, String, f64) =
            sqlx::query_as("SELECT @@global.slow_query_log, @@global.log_output, @@global.long_query_time")
                .fetch_one(&mp)
                .await
                .unwrap();
        let _ = sqlx::query("SET GLOBAL slow_query_log = 1, log_output = 'TABLE', long_query_time = 1")
            .execute(&mp)
            .await
            .unwrap();
        (on, out, lqt)
    }
    .await;

    let result: anyhow::Result<()> = async {
        // 触发一条必然进 slow_log 的查询（>1s）。
        let resp = common::post_with_auth(
            &mut app,
            &format!("/api/db/{conn_id}/query"),
            json!({"sql": "SELECT SLEEP(1.6)", "limit": 10}),
            &token,
        )
        .await;
        resp.assert_status(StatusCode::OK);

        // 等慢日志落表（同事务可见性即时，留小缓冲）。
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        dbmaster_automation::native_collector::collect_all(&pool, &[0u8; 32]).await;
        let n = native_rows(&pool, "db_native:mysql_slow_log").await;
        assert!(n >= 1, "mysql slow_log 样本应被采集");

        let row: (String, String, String, i64) = sqlx::query_as(
            "SELECT digest, sql_text, entry, elapsed_ms FROM query_stats \
             WHERE source = 'db_native:mysql_slow_log' ORDER BY captured_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "SELECT SLEEP(?)", "原生行 digest 走同一归一化");
        assert!(row.1.contains("SLEEP"), "sql_text: {}", row.1);
        assert_eq!(row.2, "native");
        assert!(row.3 >= 1000, "elapsed 来自 query_time: {}", row.3);

        // 幂等：游标推进后重采不重复。
        dbmaster_automation::native_collector::collect_all(&pool, &[0u8; 32]).await;
        assert_eq!(
            native_rows(&pool, "db_native:mysql_slow_log").await,
            n,
            "游标幂等：重采不应新增"
        );
        Ok(())
    }
    .await;

    // 恢复全局变量（无论断言成败）。
    let (on, out, lqt) = restore;
    let _ = sqlx::query("SET GLOBAL slow_query_log = ?, log_output = ?, long_query_time = ?")
        .bind(on)
        .bind(out)
        .bind(lqt)
        .execute(&mp)
        .await;
    mp.close().await;

    result.unwrap();
}

// ── v2 PS digest（累积计数器源，2026-08-27）──
//
// 场景：slow_query_log 关闭（log_output 不含 TABLE → 源优先级回退 PS
// digest 路径）。标记流量走**文本协议**（`raw_sql` 直连目标库）——实机
// 钉定：MySQL 8.0 的 digest 聚合只计 COM_QUERY（文本协议）语句，
// PREPARE/EXECUTE（二进制协议，sqlx 网关腿默认）不进
// events_statements_summary_by_digest。产品语义因此互补：PS digest 源
// 抓第三方/文本协议流量（整库画像盲区），dbmaster 网关流量由 M1 hook
// 自采——两源天然无重叠。
//
// 两轮采集验证快照差分：预热 SLEEP 进基线 → 首采零发射 → 增量 SLEEP →
// 次采出增量行（row_count ≥ 2，elapsed = 区间总耗时）→ 三采不回退。
// finally 恢复全局变量。
#[tokio::test]
async fn mysql_ps_digest_diff_collection_e2e() {
    let _guard = MYSQL_E2E_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let Some((host, port, user, password)) = mysql_env() else {
        eprintln!("NC_E2E_MYSQL_HOST not set; skipping");
        return;
    };
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "nc-ps@example.com").await;
    // 注册即用（collect_all 扫 database_connections）；PS 路径不经数据面
    // 查询——标记流量走下方直连文本协议。
    let _conn_id = create_connection(
        &mut app,
        &token,
        json!({
            "name": "nc-e2e-mysql-ps",
            "dbType": "mysql",
            "host": host, "port": port,
            "username": user, "password": password,
        }),
    )
    .await;

    let mp = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&format!("mysql://{user}:{password}@{host}:{port}/mysql"))
        .await
        .unwrap();
    // 关 slow log 强制走 PS 路径；保存原值恢复。
    let (orig_on, orig_out): (i32, String) =
        sqlx::query_as("SELECT @@global.slow_query_log, @@global.log_output")
            .fetch_one(&mp)
            .await
            .unwrap();
    let _ = sqlx::query("SET GLOBAL slow_query_log = 0")
        .execute(&mp)
        .await
        .unwrap();

    async fn sleep_count(p: &SqlitePool) -> i64 {
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT SUM(query_count) FROM query_stats \
             WHERE source = 'db_native:mysql_ps_digest' \
               AND LOWER(sql_text) LIKE '%sleep%'",
        )
        .fetch_one(p)
        .await
        .unwrap()
        .unwrap_or(0)
    }
    // 文本协议标记流量（COM_QUERY → 进 digest 聚合）。
    async fn run_sleep_markers(mp: &sqlx::MySqlPool) {
        for _ in 0..2 {
            sqlx::raw_sql("SELECT SLEEP(0.05)")
                .execute(mp)
                .await
                .unwrap();
        }
    }

    let result: anyhow::Result<()> = async {
        // 预热：先跑 SLEEP ×2——让 SLEEP digest 进首采基线（保守差分：
        // 基线里没有的新 digest 首区间跳过，历史归属不明）。
        run_sleep_markers(&mp).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // 首采：建基线（含 SLEEP digest 的当前计数；零发射）。
        dbmaster_automation::native_collector::collect_all(&pool, &[0u8; 32]).await;
        assert_eq!(
            sleep_count(&pool).await,
            0,
            "首采是基线，不应有 SLEEP 增量行"
        );

        // 基线后再跑 SLEEP ×2（digest 计数器 +2）。
        run_sleep_markers(&mp).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // 次采：SLEEP digest 增量行出现（row_count ≥ 2，elapsed ≥ 100ms
        // 区间总耗时，entry='native'）。
        dbmaster_automation::native_collector::collect_all(&pool, &[0u8; 32]).await;
        let after_first = sleep_count(&pool).await;
        assert!(after_first >= 2, "SLEEP 增量次数应 ≥ 2，实际 {after_first}");
        let (entry, rc, ms): (String, i64, i64) = sqlx::query_as(
            "SELECT entry, COALESCE(query_count, 1), elapsed_ms FROM query_stats \
             WHERE source = 'db_native:mysql_ps_digest' AND LOWER(sql_text) LIKE '%sleep%' \
             ORDER BY captured_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(entry, "native");
        assert!(rc >= 2, "row_count = 增量次数: {rc}");
        assert!(ms >= 100, "elapsed = 区间总耗时（2×SLEEP 0.05s）: {ms}");

        // 三采幂等方向：无新 SLEEP 查询则无新 SLEEP 行（共享测试库若有并发
        // 属外来流量，断言只对「我们不再贡献」负责——行数不减少）。
        dbmaster_automation::native_collector::collect_all(&pool, &[0u8; 32]).await;
        let after_third = sleep_count(&pool).await;
        assert!(after_third >= after_first, "SLEEP 行数不应回退: {after_third} < {after_first}");

        // 聚合语义：aggregate 的 count 按 row_count 计（≥ 真实行数）。
        let rows = dbmaster_automation::query_stats::aggregate(
            &pool,
            "2000-01-01T00:00:00Z",
            None,
            "SUM(elapsed_ms)",
            1000,
        )
        .await
        .unwrap();
        let total_count: i64 = rows.iter().map(|r| r.count).sum();
        let row_total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM query_stats WHERE source = 'db_native:mysql_ps_digest'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            total_count >= row_total,
            "聚合次数（row_count 语义）应 ≥ 明细行数: {total_count} vs {row_total}"
        );
        Ok(())
    }
    .await;

    // 恢复全局变量。
    let _ = sqlx::query("SET GLOBAL slow_query_log = ?, log_output = ?")
        .bind(orig_on)
        .bind(orig_out)
        .execute(&mp)
        .await;
    mp.close().await;

    result.unwrap();
}

#[tokio::test]
async fn redis_slowlog_collection_e2e() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let Some((host, port, user, password)) = redis_env() else {
        eprintln!("NC_E2E_REDIS_HOST not set; skipping");
        return;
    };
    let (mut app, pool) = common::build_test_app_with_pool().await;
    let token = register_and_get_token(&mut app, "nc-redis@example.com").await;
    let conn_id = create_connection(
        &mut app,
        &token,
        json!({
            "name": "nc-e2e-redis",
            "dbType": "redis",
            "host": host, "port": port,
            "username": user, "password": password,
        }),
    )
    .await;

    // 阈值降到 1µs（全记）并保存原值。
    let cfg = format!("redis://:{password}@{host}:{port}/");
    let client = redis::Client::open(cfg).unwrap();
    let mut r = client.get_multiplexed_async_connection().await.unwrap();
    let orig: String = redis::cmd("CONFIG")
        .arg("GET")
        .arg("slowlog-log-slower-than")
        .query_async(&mut r)
        .await
        .ok()
        .and_then(|v: Vec<String>| v.into_iter().nth(1))
        .unwrap_or_else(|| "10000".to_string());
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("slowlog-log-slower-than")
        .arg("1")
        .query_async(&mut r)
        .await
        .unwrap();

    let result: anyhow::Result<()> = async {
        // 经 gw kind:"redis" 跑命令（>1µs → 进 SLOWLOG）。
        for cmd_args in [
            vec!["SET".to_string(), "nc_e2e_key".to_string(), "1".to_string()],
            vec!["GET".to_string(), "nc_e2e_key".to_string()],
        ] {
            let resp = common::post_with_auth(
                &mut app,
                &format!("/api/gw/connections/{conn_id}/query"),
                json!({"kind": "redis", "command": cmd_args}),
                &token,
            )
            .await;
            resp.assert_status(StatusCode::OK);
        }

        // 缓冲：gw redis 腿偶发把用户命令跨连接**重发**一次（连接重建
        // retry——实机 slowlog 钉定，同条 SET 两次不同源端口）。重试落在
        // 两次 collect 之间会让幂等断言误报（+1 是新条目非重采）——留
        // 300ms 让重试在首采前落定。
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        dbmaster_automation::native_collector::collect_all(&pool, &[0u8; 32]).await;
        let n = native_rows(&pool, "db_native:redis_slowlog").await;
        assert!(n >= 1, "redis SLOWLOG 样本应被采集");

        let digests: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT digest FROM query_stats WHERE source = 'db_native:redis_slowlog'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            digests.iter().any(|d| d.starts_with("redis:SET:")),
            "digest 应为 redis 命令形态: {digests:?}"
        );

        // 幂等：游标不重采旧条目。目标命令（SET/GET）只在第一次 collect 前
        // 发过——第二次后其行数必须不变。（total 可能 +连接握手命令：阈值
        // 1µs 人为放大；生产 ms 级阈值下握手不会进 slowlog。）
        let target_count = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM query_stats WHERE source = 'db_native:redis_slowlog'                  AND sql_text LIKE '%nc_e2e_key%'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        let target_before = target_count().await;
        dbmaster_automation::native_collector::collect_all(&pool, &[0u8; 32]).await;
        assert_eq!(
            target_count().await,
            target_before,
            "id 游标幂等：目标命令不应被重采"
        );
        Ok(())
    }
    .await;

    // 恢复阈值。
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("slowlog-log-slower-than")
        .arg(&orig)
        .query_async(&mut r)
        .await
        .unwrap();

    result.unwrap();
}
