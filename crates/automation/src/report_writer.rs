//! 周报 writer（#29 reports 管道 M2，`.specs/tasks-reports-m2.md`）。
//!
//! 把 `query_stats` 明细按滚动 7 天窗口聚合成一条 reports 行
//! （`report_type = "slow_query_weekly"`，content 携带 `content_version: 1`）。
//! reports 表不设 retention——周报一周一行，是管道里唯一**永久**的聚合
//! 产物（明细 14 天即清，历史回溯靠这里）。
//!
//! 幂等：当前窗口（now-7d..now）内已有同类型报告 → 复用（`created:false`）。
//! 窗口诚实：retention 早于理论起点时截断 `window_from` 并标记
//! `window_truncated`，环比无数据时置 null——不假装覆盖。
//!
//! 触发：手动 `POST /api/reports/generate`（handler）+ [`spawn_weekly`]
//! 周期 ticker（每小时查「距上一份 > 7 天」；远程模式随 scheduler 同门
//! ——Gated 不启动，embedded 合成 Licensed 不受影响）。

use sqlx::SqlitePool;
use tokio::task::JoinHandle;

/// 周报类型常量（`report_type` 命名空间第一员；未来 drift/health 摘要周报
/// 同挂 reports 表）。
pub const SLOW_QUERY_WEEKLY: &str = "slow_query_weekly";

/// 窗口长度（天，滚动）。
const WINDOW_DAYS: i64 = 7;
/// top digest 数上限。
const TOP_N: i64 = 10;
/// ticker 检查间隔（秒）。
const WEEKLY_TICK_SECS: u64 = 3600;

/// 生成结果：`created = false` 表示本窗口已有报告、返回的是已有行。
pub struct GeneratedReport {
    pub id: String,
    pub created: bool,
}

/// 幂等生成当前窗口的慢查询周报。
pub async fn generate_slow_query_report(pool: &SqlitePool) -> anyhow::Result<GeneratedReport> {
    let now = chrono::Utc::now();
    let window_to = now.to_rfc3339();
    let window_from = (now - chrono::Duration::days(WINDOW_DAYS)).to_rfc3339();

    // 幂等：本窗口已有同类型报告（RFC3339 字符串序 = 时间序）→ 复用。
    if let Some((id, generated_at)) = latest_report(pool, SLOW_QUERY_WEEKLY).await? {
        if generated_at > window_from {
            return Ok(GeneratedReport { id, created: false });
        }
    }

    // 窗口诚实截断：最老可用明细晚于理论起点 → 以明细为准并标记。
    let oldest: Option<String> =
        sqlx::query_scalar("SELECT MIN(captured_at) FROM query_stats")
            .fetch_one(pool)
            .await
            .ok()
            .flatten();
    let (from, truncated) = match oldest {
        Some(o) if o > window_from => (o, true),
        _ => (window_from.clone(), false),
    };

    // 汇总基数（全窗口）。
    let (total_samples, distinct_digests, total_ms, error_count, cancelled_count): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        // total_samples 按 row_count 语义（事件行 1、计数器差分行 N）——
        // PS digest 一行代表整个区间的 N 次查询。
        "SELECT CAST(SUM(COALESCE(query_count, 1)) AS INTEGER), COUNT(DISTINCT digest), \
         COALESCE(SUM(elapsed_ms), 0), \
         COALESCE(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END), 0), \
         COALESCE(SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END), 0) \
         FROM query_stats WHERE captured_at >= ?1",
    )
    .bind(&from)
    .fetch_one(pool)
    .await?;

    // 环比：真实窗口起点往前再推 7 天；上一窗口无数据 → null（不猜）。
    let week_over_week_pct: Option<f64> = match parse_rfc3339(&from) {
        Some(prev_to) => {
            let prev_from = prev_to - chrono::Duration::days(WINDOW_DAYS);
            let prev_total: Option<i64> = sqlx::query_scalar(
                "SELECT SUM(elapsed_ms) FROM query_stats \
                 WHERE captured_at >= ?1 AND captured_at < ?2",
            )
            .bind(prev_from.to_rfc3339())
            .bind(&from)
            .fetch_one(pool)
            .await
            .ok()
            .flatten();
            match (prev_total, total_ms) {
                (Some(p), t) if p > 0 && t > 0 => {
                    Some(((t - p) as f64 / p as f64) * 100.0)
                }
                _ => None,
            }
        }
        None => None,
    };

    // Top digest（聚合 SQL 与 stats summary 端点同源）。
    let top_rows = crate::query_stats::aggregate(
        pool,
        &from,
        None,
        "SUM(elapsed_ms)",
        TOP_N,
    )
    .await?;
    let mut top = Vec::with_capacity(top_rows.len());
    for row in &top_rows {
        let sample = crate::query_stats::latest_sample(pool, &row.digest, &row.conn_id).await;
        top.push(serde_json::json!({
            "digest": row.digest,
            "db_kind": row.db_kind,
            "conn_id": row.conn_id,
            "count": row.count,
            "total_ms": row.total_ms,
            "avg_ms": row.avg_ms,
            "max_ms": row.max_ms,
            "sample_sql_text": sample,
        }));
    }

    // 按连接分布（连接数有限，全量）。
    let by_connection: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT conn_id, db_kind, CAST(SUM(COALESCE(query_count, 1)) AS INTEGER) AS count, \
         SUM(elapsed_ms) AS total_ms \
         FROM query_stats WHERE captured_at >= ?1 \
         GROUP BY conn_id, db_kind ORDER BY total_ms DESC",
    )
    .bind(&from)
    .fetch_all(pool)
    .await?;
    let by_connection: Vec<serde_json::Value> = by_connection
        .into_iter()
        .map(|(conn_id, db_kind, count, total_ms)| {
            serde_json::json!({"conn_id": conn_id, "db_kind": db_kind, "count": count, "total_ms": total_ms})
        })
        .collect();

    // 按天分布（RFC3339 前 10 字符 = UTC 日期）。
    let by_day: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT substr(captured_at, 1, 10) AS date, \
         CAST(SUM(COALESCE(query_count, 1)) AS INTEGER) AS count, \
         SUM(elapsed_ms) AS total_ms \
         FROM query_stats WHERE captured_at >= ?1 \
         GROUP BY date ORDER BY date",
    )
    .bind(&from)
    .fetch_all(pool)
    .await?;
    let by_day: Vec<serde_json::Value> = by_day
        .into_iter()
        .map(|(date, count, total_ms)| {
            serde_json::json!({"date": date, "count": count, "total_ms": total_ms})
        })
        .collect();

    use chrono::Datelike;
    let iso = now.iso_week();
    let title = format!(
        "Slow query weekly · {}-W{:02}",
        iso.year(),
        iso.week()
    );
    let content = serde_json::json!({
        "content_version": 1,
        "report_type": SLOW_QUERY_WEEKLY,
        "window_from": from,
        "window_to": window_to,
        "window_truncated": truncated,
        "summary": {
            "total_samples": total_samples,
            "distinct_digests": distinct_digests,
            "total_ms": total_ms,
            "error_count": error_count,
            "cancelled_count": cancelled_count,
            "week_over_week_pct": week_over_week_pct,
        },
        "top": top,
        "by_connection": by_connection,
        "by_day": by_day,
    });

    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO reports (id, task_id, report_type, title, content, generated_at) \
         VALUES (?1, NULL, ?2, ?3, ?4, ?5)",
    )
    .bind(&id)
    .bind(SLOW_QUERY_WEEKLY)
    .bind(&title)
    .bind(content.to_string())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(GeneratedReport { id, created: true })
}

/// 最新一份指定类型报告的 (id, generated_at)。
async fn latest_report(
    pool: &SqlitePool,
    report_type: &str,
) -> anyhow::Result<Option<(String, String)>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT id, generated_at FROM reports WHERE report_type = ?1 \
         ORDER BY generated_at DESC LIMIT 1",
    )
    .bind(report_type)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

fn parse_rfc3339(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

/// 周期 ticker：每小时检查「距上一份周报 > 窗口长度」即生成。双模式由
/// 调用方接线（远程 Gated 不启动——对齐 scheduler 惯例；embedded 无条件）。
///
/// 无报告时的到期判据带数据门槛（窗口内已有样本）——否则 `interval` 的
/// 首个立即 tick 会在启动瞬间产出一份空报告并占掉本周幂等窗口（启动
/// 即空报，实测钉定）。手动 [`crate::handler::generate_report`] 不受此限。
pub fn spawn_weekly(pool: SqlitePool) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(WEEKLY_TICK_SECS));
        // 消费首个立即 tick（语义见上：无数据不生成，无需启动即查）。
        tick.tick().await;
        loop {
            tick.tick().await;
            let horizon = (chrono::Utc::now() - chrono::Duration::days(WINDOW_DAYS)).to_rfc3339();
            let due = match latest_report(&pool, SLOW_QUERY_WEEKLY).await {
                Ok(Some((_, generated_at))) => generated_at <= horizon,
                Ok(None) => {
                    // 无报告：窗口内已有样本才值得生成（防启动空报）。
                    match sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM query_stats WHERE captured_at >= ?1",
                    )
                    .bind(&horizon)
                    .fetch_one(&pool)
                    .await
                    {
                        Ok(n) => n > 0,
                        Err(e) => {
                            tracing::warn!("report weekly due-check failed: {e}");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("report weekly due-check failed: {e}");
                    continue;
                }
            };
            if due {
                match generate_slow_query_report(&pool).await {
                    Ok(g) if g.created => {
                        tracing::info!(report_id = %g.id, "slow query weekly report generated")
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("report weekly generation failed: {e}"),
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        dbmaster_core::db::run_migrations(&pool).await.unwrap();
        pool
    }

    async fn seed(
        pool: &SqlitePool,
        id: &str,
        digest: &str,
        elapsed: i64,
        at: chrono::DateTime<chrono::Utc>,
        status: &str,
    ) {
        let at = at.to_rfc3339();
        sqlx::query(
            "INSERT INTO query_stats (id, source, conn_id, db_kind, database, digest, sql_text, \
             elapsed_ms, row_count, affected_rows, status, error_code, user_id, entry, captured_at) \
             VALUES (?1, 'gateway', 'c1', 'mysql', 'db', ?2, ?3, ?4, NULL, NULL, ?5, NULL, NULL, \
             'sync_query', ?6)",
        )
        .bind(id)
        .bind(digest)
        .bind(format!("RAW {id}"))
        .bind(elapsed)
        .bind(status)
        .bind(at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn fetch_content(pool: &SqlitePool, id: &str) -> serde_json::Value {
        let content: String =
            sqlx::query_scalar("SELECT content FROM reports WHERE id = ?1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
        serde_json::from_str(&content).unwrap()
    }

    #[tokio::test]
    async fn generates_content_v1_shape_and_is_idempotent() {
        let pool = test_pool().await;
        // 时间确定性（原"60 分钟前"写法在 UTC 午夜附近跨日，by_day 会多出
        // 一个日桶）：窗口内样本锚定「今天 UTC 日 0 点」+ 固定偏移
        // （day0+1..4 分钟）——恒落在同一 UTC 日（by_day 单桶）、恒在 7 天
        // 窗口内，与运行时刻无关；偏移互异保证 latest_sample 取样确定。
        // 窗口与环比上一窗口（7-14 天前）之外（now-15 天）一行——两窗口
        // 都不计入。
        let now = chrono::Utc::now();
        let day0 = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
        let at = |min: i64| day0 + chrono::Duration::minutes(min);
        seed(&pool, "a1", "SELECT SLEEP(?)", 3000, at(1), "ok").await;
        seed(&pool, "a2", "SELECT SLEEP(?)", 2000, at(2), "ok").await;
        seed(&pool, "a3", "SELECT * FROM u", 1500, at(3), "ok").await;
        seed(&pool, "a4", "SELECT * FROM u", 9000, at(4), "error").await;
        seed(&pool, "old", "SELECT OLD(?)", 5000, now - chrono::Duration::days(15), "ok").await;

        let g = generate_slow_query_report(&pool).await.unwrap();
        assert!(g.created);
        let c = fetch_content(&pool, &g.id).await;
        assert_eq!(c["content_version"], serde_json::json!(1));
        assert_eq!(c["report_type"], serde_json::json!("slow_query_weekly"));
        assert_eq!(c["summary"]["total_samples"], serde_json::json!(4));
        assert_eq!(c["summary"]["distinct_digests"], serde_json::json!(2));
        assert_eq!(c["summary"]["total_ms"], serde_json::json!(15_500));
        assert_eq!(c["summary"]["error_count"], serde_json::json!(1));
        assert_eq!(c["summary"]["cancelled_count"], serde_json::json!(0));
        // 无上一窗口数据 → 环比 null（不猜）。
        assert_eq!(c["summary"]["week_over_week_pct"], serde_json::json!(null));
        // top 按 total_ms 排序：SLEEP 组 5000 在 u 组 10500 之后。
        let top = c["top"].as_array().unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["digest"], serde_json::json!("SELECT * FROM u"));
        assert_eq!(top[0]["count"], serde_json::json!(2));
        // 样本 = 最新一条（a4，10 分钟前）。
        assert_eq!(top[0]["sample_sql_text"], serde_json::json!("RAW a4"));
        // by_day / by_connection 形状。
        assert_eq!(c["by_day"].as_array().unwrap().len(), 1);
        assert_eq!(c["by_connection"].as_array().unwrap().len(), 1);

        // 幂等：同窗口再触发 → 复用已有行。
        let again = generate_slow_query_report(&pool).await.unwrap();
        assert!(!again.created);
        assert_eq!(again.id, g.id);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn empty_window_still_generates_honest_report() {
        let pool = test_pool().await;
        let g = generate_slow_query_report(&pool).await.unwrap();
        assert!(g.created);
        let c = fetch_content(&pool, &g.id).await;
        assert_eq!(c["summary"]["total_samples"], serde_json::json!(0));
        assert!(c["top"].as_array().unwrap().is_empty());
    }
}
