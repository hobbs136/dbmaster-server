//! 原生慢查源采集器（#29 reports 管道 M3 + v2 累积源，`.specs/tasks-reports-m3.md`）。
//!
//! 把数据库**自身**的慢查询日志拉进 `query_stats`（`source='db_native:*'`，
//! `entry='native'`）——与网关源（经 dbmaster 执行的查询）互补，合成整库
//! 慢查询画像。
//!
//! **事件形态源**（一行一事件，游标 = 单调水位）：
//!
//! - **Redis `SLOWLOG GET`**：环形缓冲、id 单调 → 游标 = 最大已消费 id；
//! - **MySQL `mysql.slow_log` 表**（`log_output=TABLE`，db_type =
//!   `mysql`/`mariadb`）：逐事件行 → 游标 = 最大 `start_time`（源格式
//!   原样回存，字符串序即时间序）。
//!
//! **累积计数器形态源**（v2，2026-08-27 拍板只做 MySQL；快照差分状态机）：
//!
//! - **MySQL `performance_schema.events_statements_summary_by_digest`**：
//!   digest 计数器快照（COUNT_STAR/SUM_TIMER_WAIT）→ 与上次快照按
//!   digest 求区间增量，**一行代表一个 digest 的 `(次数, 总耗时)` 增量**
//!   （`row_count`= 次数、`elapsed_ms`= 总耗时，聚合读路径按
//!   `SUM(COALESCE(row_count,1))` 计次数）。快照本体以 JSON 存
//!   `query_stats_native_cursor.cursor`（source =
//!   `db_native:mysql_ps_digest`；top 500 by 总耗时，驱逐不影响正确性
//!   ——被挤出再回来的 digest 首区间保守跳过）。**连接级源优先级**：
//!   slow_log 可用（`log_output=TABLE` 且开启）走 slow_log（精确明文），
//!   否则回退 PS digest——同连接永不双计数。PS 零配置（5.7+ 默认开），
//!   填补「DBA 未开 slow log」实例的整库画像空白。
//!
//! 差分边界（保守优先，同 M2 诚实截断哲学）：计数器回退（重启/
//! TRUNCATE）→ 全量重置基线、本轮不发射；digest 不在上次快照（新建
//! 或被驱逐）→ 首区间跳过（历史归属不明，宁少勿多）；首采（无快照）
//! 只建基线（对齐 slow_log 首采 1 小时前语义）。
//!
//! PG `pg_stat_statements`（需重启加载）/ CH `system.query_log` / SS
//! Query Store（默认关）留挂条按需。前置条件不满足 → INFO 跳过；
//! 连接级失败 → WARN（下个 tick 重试）。
//!
//! 通道纪律与 M1 同源：日志/错误不带凭据；`sql_text` 截断 8192；
//! 样本受统一 retention 清理。触发 = [`spawn_collector`] 每小时
//! （远程 Gated 不启动——对齐 scheduler 惯例；embedded 合成 Licensed
//! 无条件）。

use dbmaster_core::server::CredentialKey;
use sqlx::SqlitePool;
use tokio::task::JoinHandle;

pub(crate) const REDIS_SOURCE: &str = "db_native:redis_slowlog";
pub(crate) const MYSQL_SOURCE: &str = "db_native:mysql_slow_log";
pub(crate) const PS_DIGEST_SOURCE: &str = "db_native:mysql_ps_digest";

const TICK_SECS: u64 = 3600;
const SLOWLOG_BATCH: isize = 128;
/// PS digest 快照的 digest 上限（按 SUM_TIMER_WAIT 取 top）——超出部分
/// 贡献的时间占比可忽略；被挤出再回来的 digest 首区间按保守跳过。
const PS_SNAPSHOT_DIGESTS: usize = 500;

/// 遍历所有可采集的已注册连接，逐连接采集。单个连接失败只 WARN 不中断。
pub async fn collect_all(pool: &SqlitePool, key: &CredentialKey) {
    let conns: Vec<(String, String)> = match sqlx::query_as(
        "SELECT id, db_type FROM database_connections \
         WHERE db_type IN ('redis', 'mysql', 'mariadb')",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("native collector connection scan failed: {e}");
            return;
        }
    };
    for (conn_id, db_type) in conns {
        let result = match db_type.as_str() {
            "redis" => collect_redis(pool, key, &conn_id).await,
            _ => collect_mysql(pool, key, &conn_id).await,
        };
        match result {
            Ok(n) if n > 0 => {
                tracing::info!(conn_id = %conn_id, db_type = %db_type, collected = n, "native slow-log samples collected")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(conn_id = %conn_id, "native collect failed: {e}"),
        }
    }
}

async fn load_conn(
    pool: &SqlitePool,
    key: &CredentialKey,
    conn_id: &str,
) -> Result<(crate::db_handler::DbConnectionRow, String), String> {
    crate::metadata::load_connection(pool, key, conn_id)
        .await
        .map(|(conn, _, password)| (conn, password))
        .map_err(|e| e.message)
}

// ── 游标（migration 018）──

async fn cursor_get(pool: &SqlitePool, conn_id: &str, source: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT cursor FROM query_stats_native_cursor WHERE conn_id = ?1 AND source = ?2",
    )
    .bind(conn_id)
    .bind(source)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

async fn cursor_put(pool: &SqlitePool, conn_id: &str, source: &str, cursor: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let res = sqlx::query(
        "INSERT INTO query_stats_native_cursor (conn_id, source, cursor, updated_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (conn_id, source) DO UPDATE SET \
         cursor = excluded.cursor, updated_at = excluded.updated_at",
    )
    .bind(conn_id)
    .bind(source)
    .bind(cursor)
    .bind(now)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!("native collector cursor update failed: {e}");
    }
}

// ── Redis：SLOWLOG ──

async fn collect_redis(pool: &SqlitePool, key: &CredentialKey, conn_id: &str) -> Result<usize, String> {
    let (conn, password) = load_conn(pool, key, conn_id).await?;
    let mut r = crate::redis_leg::open_redis(&conn, &password, 0)
        .await
        .map_err(|e| e.to_string())?;

    let raw: redis::Value = redis::cmd("SLOWLOG")
        .arg("GET")
        .arg(SLOWLOG_BATCH)
        .query_async(&mut r)
        .await
        .map_err(|e| e.to_string())?;
    // 复用 RESP→JSON 转换（避开 redis::Value 枚举跨版本成员名风险）：
    // [[id, ts, dur_us, [args...], client...], ...]
    let json = crate::redis_leg::resp_to_json(raw);
    let entries = json.as_array().cloned().unwrap_or_default();

    let last: u64 = cursor_get(pool, conn_id, REDIS_SOURCE)
        .await
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut max_id = last;
    let mut n = 0usize;
    for entry in entries {
        let parts = match entry.as_array() {
            Some(p) if p.len() >= 4 => p,
            _ => continue,
        };
        let id = parts[0].as_i64().unwrap_or(0);
        let dur_us = parts[2].as_i64().unwrap_or(0);
        let args: Vec<String> = parts[3]
            .as_array()
            .map(|xs| {
                xs.iter()
                    .map(|x| x.as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default();
        // 自引用免疫：采集器自己的 SLOWLOG GET（实例阈值被调低时）
        // 会以新 id 进 slowlog——跳过 SLOWLOG 开头的条目，防自增长。
        if args.is_empty()
            || args[0].eq_ignore_ascii_case("SLOWLOG")
            || id <= 0
            || (id as u64) <= last
        {
            continue;
        }
        let digest =
            crate::query_stats::normalize_digest(&crate::query_stats::CapturePayload::Redis(&args));
        let plaintext = args.join(" ");
        // 原生时长 µs→ms（0ms 钳到 1——源阈值极低时保序）。
        let elapsed_ms = (dur_us / 1000).max(1);
        if let Err(e) = crate::query_stats::insert_native(
            pool,
            conn_id,
            "redis",
            None,
            REDIS_SOURCE,
            &digest,
            Some(&plaintext),
            elapsed_ms,
            None,
        )
        .await
        {
            tracing::warn!("native redis insert failed: {e}");
            continue;
        }
        max_id = max_id.max(id as u64);
        n += 1;
    }
    if max_id > last {
        cursor_put(pool, conn_id, REDIS_SOURCE, &max_id.to_string()).await;
    }
    Ok(n)
}

// ── MySQL：slow_log 表 ──

async fn collect_mysql(pool: &SqlitePool, key: &CredentialKey, conn_id: &str) -> Result<usize, String> {
    let (conn, password) = load_conn(pool, key, conn_id).await?;
    let mp = crate::db_handler::open_mysql_db(&conn, &password, None)
        .await
        .map_err(|_| "mysql pool open failed".to_string())?;

    // 前置：slow_query_log=ON 且 log_output 含 TABLE → 走 slow_log 事件源
    // （精确明文）。不满足 → 回退 PS digest 计数器源（连接级源优先级——
    // 同连接永不双计数；实例侧开启 slow log 后下个 tick 自动切回）。
    let (slow_on, log_output): (i32, String) =
        sqlx::query_as("SELECT @@global.slow_query_log, @@global.log_output")
            .fetch_one(&mp)
            .await
            .map_err(|e| format!("slow log settings read failed: {e}"))?;
    if slow_on == 0 || !log_output.to_lowercase().contains("table") {
        return collect_mysql_ps_digest(pool, conn_id, &conn.db_type, &mp).await;
    }

    // 首采起点：1 小时前（源格式）；已有游标则原样使用（同格式字符串序=时间序）。
    let cursor = cursor_get(pool, conn_id, MYSQL_SOURCE)
        .await
        .unwrap_or_else(|| mysql_source_now_minus_hours(1));

    // CAST ... AS CHAR：slow_log 的 TIMESTAMP/TIME/sql_text(BLOB) 列直解
    // String/Option<String> 会 type-mismatch（错误被 WARN 吞表现为静默
    // 0 行，e2e 实测）。
    let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT CAST(start_time AS CHAR), CAST(query_time AS CHAR), \
         CAST(sql_text AS CHAR), CAST(db AS CHAR) \
         FROM mysql.slow_log \
         WHERE start_time > ? ORDER BY start_time",
    )
    .bind(&cursor)
    .fetch_all(&mp)
    .await
    .map_err(|e| format!("mysql.slow_log read failed: {e}"))?;

    let mut max_ts = cursor.clone();
    let mut n = 0usize;
    for (start_time, query_time, sql_text, db) in rows {
        let elapsed_ms = parse_mysql_time_ms(&query_time).max(1);
        let digest = crate::query_stats::normalize_digest(
            &crate::query_stats::CapturePayload::Sql(sql_text.as_deref().unwrap_or("")),
        );
        if let Err(e) = crate::query_stats::insert_native(
            pool,
            conn_id,
            &conn.db_type,
            db.as_deref(),
            MYSQL_SOURCE,
            &digest,
            sql_text.as_deref(),
            elapsed_ms,
            None,
        )
        .await
        {
            tracing::warn!("native mysql insert failed: {e}");
            continue;
        }
        max_ts = max_ts.max(start_time);
        n += 1;
    }
    if n > 0 {
        cursor_put(pool, conn_id, MYSQL_SOURCE, &max_ts).await;
    }
    Ok(n)
}

// ── MySQL：performance_schema digest 快照差分（v2 累积源）──

/// PS digest 快照（cursor 列的 JSON 形态）。键 = **复合键** `hex|schema`
/// （实机钉定：digest 表真实键是 `(DIGEST, SCHEMA_NAME)`——同一语句跨库
/// 执行会产生多行同 hex，单用 hex 会在 map 里碰撞覆盖，伪触发重置检测）；
/// 值 = `[COUNT_STAR, 总耗时 ms]`（已换算，回存原样）。
#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct PsSnapshot {
    /// 快照取得时刻（unix ms，本机钟——差分只比大小，跨源不比绝对值）。
    t: i64,
    d: std::collections::HashMap<String, [i64; 2]>,
}

/// 差分结果：一个 digest 的区间增量（次数、总耗时 ms、归一化前文本）。
#[derive(Debug)]
struct PsDelta {
    count: i64,
    total_ms: i64,
    digest_text: String,
    /// 该 digest 行的 SCHEMA_NAME（database 维度直取，不再回表查）。
    schema: Option<String>,
}

/// 快照复合键：`|` 分隔（hex 是 [0-9a-f]，schema 名不含 `|`——MySQL 标识
/// 符允许的字符集里 `|` 非法定，实际不可碰撞）。
fn ps_key(digest_hex: &str, schema: Option<&str>) -> String {
    format!("{digest_hex}|{}", schema.unwrap_or(""))
}

/// 皮秒（`*_TIMER_WAIT`）→ 毫秒（1ms = 10⁹ ps）。i64 上限 ≈ 9.2e18 ps
/// ≈ 107 天累计耗时，不溢出。
pub(crate) fn ps_to_ms(ps: i64) -> i64 {
    ps / 1_000_000_000
}

/// 快照差分（纯函数，单测覆盖）。保守规则见模块文档：
/// - 任一共有键计数回退 → 整体视为重置（重启/TRUNCATE），本轮零发射；
/// - 不在上次快照的键（新建或被驱逐出 top）→ 跳过首区间；
/// - 增量次数 ≤ 0 → 跳过（时间漂移不构成样本）。
fn diff_ps_snapshots(
    prev: Option<&PsSnapshot>,
    cur: &[(String, String, i64, i64)], // (复合键, digest_text, count_star, total_ms)
) -> Vec<PsDelta> {
    let Some(prev) = prev else { return Vec::new() };
    // 重置检测：任一共有键计数回退即判定（PS 表整体清零，全量重建基线）。
    if cur
        .iter()
        .any(|(k, _, c, _)| prev.d.get(k).is_some_and(|[pc, _]| *c < *pc))
    {
        return Vec::new();
    }
    cur.iter()
        .filter_map(|(k, text, c, total_ms)| {
            let &[pc, ptotal] = prev.d.get(k)?;
            let count = c - pc;
            if count <= 0 {
                return None;
            }
            // 复合键 `hex|schema` → 还原 schema（None 段 = 无默认库）。
            let schema = k.rsplit_once('|').and_then(|(_, s)| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            });
            Some(PsDelta {
                count,
                total_ms: (total_ms - ptotal).max(0),
                digest_text: text.clone(),
                schema,
            })
        })
        .collect()
}

/// PS digest 采集：读当前快照 → 与 cursor 里上次快照差分 → 增量逐 digest
/// 落一行 → 新快照回存 cursor（差分为空也回存——计数基线推进）。
async fn collect_mysql_ps_digest(
    server_pool: &SqlitePool,
    conn_id: &str,
    db_kind: &str,
    mp: &sqlx::MySqlPool,
) -> Result<usize, String> {
    // 前置：performance_schema 开启（5.7+ 默认开；显式关闭 → INFO 跳过，
    // 不算连接失败）。权限不足会在 digest 查询报错 → WARN 由上层记。
    let ps_on: i32 = sqlx::query_scalar("SELECT @@performance_schema")
        .fetch_one(mp)
        .await
        .map_err(|e| format!("performance_schema flag read failed: {e}"))?;
    if ps_on == 0 {
        tracing::info!(
            conn_id = %conn_id,
            "performance_schema disabled; ps digest collection skipped"
        );
        return Ok(0);
    }

    // CAST ... AS CHAR：DIGEST/DIGEST_TEXT 直解 String 在部分版本/驱动组合
    // 下 type-mismatch（slow_log 同款教训）；COUNT_STAR/SUM_TIMER_WAIT 是
    // BIGINT UNSIGNED → 解 u64 再饱和转 i64。SCHEMA_NAME 作 database 维度；
    // LIMIT 走常量（format! 里拼写，非用户输入）。
    let rows: Vec<(String, String, u64, u64, Option<String>)> = sqlx::query_as(
        format!(
            "SELECT DIGEST, CAST(DIGEST_TEXT AS CHAR), COUNT_STAR, SUM_TIMER_WAIT, \
             CAST(SCHEMA_NAME AS CHAR) \
             FROM performance_schema.events_statements_summary_by_digest \
             WHERE DIGEST IS NOT NULL \
             ORDER BY SUM_TIMER_WAIT DESC LIMIT {PS_SNAPSHOT_DIGESTS}"
        )
        .as_str(),
    )
    .fetch_all(mp)
    .await
    .map_err(|e| format!("ps digest table read failed: {e}"))?;

    let now_rows: Vec<(String, String, i64, i64)> = rows
        .iter()
        .map(|(dh, text, c, tps, schema)| {
            (
                ps_key(dh, schema.as_deref()),
                text.clone(),
                i64::try_from(*c).unwrap_or(i64::MAX),
                ps_to_ms(i64::try_from(*tps).unwrap_or(i64::MAX)),
            )
        })
        .collect();

    let prev: Option<PsSnapshot> = cursor_get(server_pool, conn_id, PS_DIGEST_SOURCE)
        .await
        .and_then(|s| serde_json::from_str(&s).ok());
    tracing::debug!(
        conn_id = %conn_id,
        prev_entries = prev.as_ref().map(|p| p.d.len()),
        cur_rows = now_rows.len(),
        "ps digest diff input"
    );
    let deltas = diff_ps_snapshots(prev.as_ref(), &now_rows);
    tracing::debug!(conn_id = %conn_id, deltas = deltas.len(), "ps digest diff output");

    let mut n = 0usize;
    for delta in &deltas {
        let digest = crate::query_stats::normalize_digest(
            &crate::query_stats::CapturePayload::Sql(&delta.digest_text),
        );
        if let Err(e) = crate::query_stats::insert_native(
            server_pool,
            conn_id,
            db_kind,
            delta.schema.as_deref(),
            PS_DIGEST_SOURCE,
            &digest,
            Some(&delta.digest_text),
            delta.total_ms.max(1),
            Some(delta.count),
        )
        .await
        {
            tracing::warn!("native ps digest insert failed: {e}");
            continue;
        }
        n += 1;
    }

    // 新快照回存（含全部 top 行——含无增量的，保住下轮差分基线）。
    let snap = PsSnapshot {
        t: chrono::Utc::now().timestamp_millis(),
        d: now_rows
            .iter()
            .map(|(k, _, c, ms)| (k.clone(), [*c, *ms]))
            .collect(),
    };
    match serde_json::to_string(&snap) {
        Ok(json) => cursor_put(server_pool, conn_id, PS_DIGEST_SOURCE, &json).await,
        Err(e) => tracing::warn!("ps snapshot serialize failed: {e}"),
    }
    Ok(n)
}

/// `"HH:MM:SS[.ffffff]"`（MySQL TIME 列的字符串形态）→ 毫秒。
pub(crate) fn parse_mysql_time_ms(s: &str) -> i64 {
    let mut parts = s.split(':');
    let h: i64 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let m: i64 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let sec_str = parts.next().unwrap_or("0");
    let (sec, frac_ms) = match sec_str.split_once('.') {
        Some((sec, frac)) => {
            let sec: i64 = sec.parse().unwrap_or(0);
            let frac_ms = if frac.is_empty() {
                0
            } else {
                // 微秒（最多 6 位）→ 毫秒。
                let padded = format!("{frac:0<6}");
                padded[..3].parse().unwrap_or(0)
            };
            (sec, frac_ms)
        }
        None => (sec_str.parse().unwrap_or(0), 0),
    };
    h * 3_600_000 + m * 60_000 + sec * 1000 + frac_ms
}

/// MySQL `DATETIME(6)` 字符串形态的「N 小时前」（UTC——slow_log 的
/// start_time 用服务器时区，游标语义按同源比较仍然自洽）。
pub(crate) fn mysql_source_now_minus_hours(hours: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::hours(hours))
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string()
}

/// 每小时采集一轮（消费首个立即 tick——与 weekly ticker 同款纪律）。
/// 远程 Gated 不启动由调用方（main.rs）决定；embedded 无条件。
pub fn spawn_collector(pool: SqlitePool, key: CredentialKey) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(TICK_SECS));
        tick.tick().await;
        loop {
            tick.tick().await;
            collect_all(&pool, &key).await;
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

    #[test]
    fn mysql_time_parsing() {
        assert_eq!(parse_mysql_time_ms("00:00:01.500000"), 1500);
        assert_eq!(parse_mysql_time_ms("00:02:05.250000"), 125_250);
        assert_eq!(parse_mysql_time_ms("01:00:00"), 3_600_000);
        assert_eq!(parse_mysql_time_ms("00:00:00.000999"), 0);
        // 退化输入不 panic。
        assert_eq!(parse_mysql_time_ms("garbage"), 0);
    }

    #[test]
    fn mysql_source_format_is_lexicographically_ordered() {
        let a = mysql_source_now_minus_hours(2);
        let b = mysql_source_now_minus_hours(1);
        assert!(a < b, "同格式 datetime 字符串序应即时间序: {a} vs {b}");
        assert!(a.starts_with("20"), "格式形如 YYYY-MM-DD HH:MM:SS.ffffff: {a}");
    }

    #[tokio::test]
    async fn cursor_roundtrip_and_upsert() {
        let pool = test_pool().await;
        assert_eq!(cursor_get(&pool, "c1", REDIS_SOURCE).await, None);
        cursor_put(&pool, "c1", REDIS_SOURCE, "42").await;
        assert_eq!(cursor_get(&pool, "c1", REDIS_SOURCE).await.as_deref(), Some("42"));
        // UPSERT 覆盖而非新行。
        cursor_put(&pool, "c1", REDIS_SOURCE, "99").await;
        assert_eq!(cursor_get(&pool, "c1", REDIS_SOURCE).await.as_deref(), Some("99"));
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM query_stats_native_cursor")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    // ── v2 PS digest：差分状态机 ──

    #[test]
    fn ps_timer_conversion() {
        // 1ms = 10⁹ ps。
        assert_eq!(ps_to_ms(1_500_000_000_000), 1500); // 1.5s
        assert_eq!(ps_to_ms(1_000_000_000), 1);
        assert_eq!(ps_to_ms(999_999_999), 0); // 不足 1ms 截断
        assert_eq!(ps_to_ms(0), 0);
    }

    fn snap(entries: &[(&str, [i64; 2])]) -> PsSnapshot {
        PsSnapshot {
            t: 1,
            d: entries
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
        }
    }

    fn cur_row(h: &str, text: &str, c: i64, ms: i64) -> (String, String, i64, i64) {
        (h.into(), text.into(), c, ms)
    }

    #[test]
    fn ps_diff_emits_per_digest_deltas() {
        // 键 = 复合键（hex|schema）：同语句跨库两行不碰撞。
        let prev = snap(&[("aa|db1", [10, 100]), ("bb|db1", [5, 50]), ("aa|", [3, 30])]);
        let cur = vec![
            cur_row("aa|db1", "SELECT `t` . `x` FROM `t`", 15, 260),
            cur_row("bb|db1", "UPDATE `t` SET `x` = ?", 5, 50), // 零增量 → skip
            cur_row("cc|db1", "DELETE FROM `t`", 3, 30),        // 新键 → 首区间跳过
            cur_row("aa|", "SELECT `t` . `x` FROM `t`", 5, 80), // 同 hex 不同库，独立差分
        ];
        let out = diff_ps_snapshots(Some(&prev), &cur);
        assert_eq!(out.len(), 2, "aa|db1 与 aa|（空库）各自出增量: {out:?}");
        assert_eq!((out[0].count, out[0].total_ms), (5, 160));
        assert_eq!(out[0].schema.as_deref(), Some("db1"));
        assert_eq!((out[1].count, out[1].total_ms), (2, 50));
        assert_eq!(out[1].schema, None, "空 schema 段还原为 None");
    }

    #[test]
    fn ps_diff_first_collect_is_baseline_only() {
        let cur = vec![cur_row("aa", "SELECT ?", 42, 100)];
        assert!(diff_ps_snapshots(None, &cur).is_empty());
    }

    #[test]
    fn ps_diff_counter_regression_resets() {
        // 服务器重启/TRUNCATE → 计数回退 → 整体重置（零发射，重建基线）。
        let prev = snap(&[("aa", [10, 100])]);
        let cur = vec![cur_row("aa", "SELECT ?", 2, 20)];
        assert!(diff_ps_snapshots(Some(&prev), &cur).is_empty());
    }

    #[test]
    fn ps_diff_partial_regression_also_resets() {
        // 任一共有 digest 回退即整体重置（即使另一个正常增长）。
        let prev = snap(&[("aa", [10, 100]), ("bb", [5, 50])]);
        let cur = vec![
            cur_row("aa", "SELECT ?", 12, 130),
            cur_row("bb", "SELECT 1", 1, 5),
        ];
        assert!(diff_ps_snapshots(Some(&prev), &cur).is_empty());
    }

    #[test]
    fn ps_diff_evicted_digest_skipped_then_recovers() {
        // 被挤出 top 又回来：首区间（不在 prev）跳过，其后正常差分。
        let prev = snap(&[("aa", [10, 100])]);
        let first = vec![cur_row("bb", "SELECT ?", 7, 70)];
        assert!(diff_ps_snapshots(Some(&prev), &first).is_empty());
        let second_prev = snap(&[("bb", [7, 70])]);
        let second = vec![cur_row("bb", "SELECT ?", 9, 95)];
        let out = diff_ps_snapshots(Some(&second_prev), &second);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].count, out[0].total_ms), (2, 25));
    }

    #[tokio::test]
    async fn ps_snapshot_json_roundtrip_via_cursor() {
        let pool = test_pool().await;
        let snap = PsSnapshot {
            t: 12345,
            d: std::iter::once(("aa".to_string(), [10, 100])).collect(),
        };
        let json = serde_json::to_string(&snap).unwrap();
        cursor_put(&pool, "c-ps", PS_DIGEST_SOURCE, &json).await;
        let back: PsSnapshot =
            serde_json::from_str(&cursor_get(&pool, "c-ps", PS_DIGEST_SOURCE).await.unwrap())
                .unwrap();
        assert_eq!(back.t, 12345);
        assert_eq!(back.d["aa"], [10, 100]);
    }

    #[tokio::test]
    async fn aggregate_counts_row_count_semantics() {
        let pool = test_pool().await;
        // 差分行：一行代表 10 次、总 250ms（PS digest）；事件行 ×2（slow_log）。
        // digest 归一化后同为 "SELECT ?" → 两源聚合进同一组（连接换源不断档）。
        for (source, ms, rc) in [
            ("db_native:mysql_ps_digest", 250i64, Some(10i64)),
            ("db_native:mysql_slow_log", 100, None),
            ("db_native:mysql_slow_log", 100, None),
        ] {
            crate::query_stats::insert_native(
                &pool, "c1", "mysql", None, source, "SELECT ?", Some("SELECT ?"), ms, rc,
            )
            .await
            .unwrap();
        }
        let rows =
            crate::query_stats::aggregate(&pool, "2000-01-01T00:00:00Z", None, "SUM(elapsed_ms)", 10)
                .await
                .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, 12, "次数 = 10（差分）+ 1 + 1（事件）");
        assert_eq!(rows[0].total_ms, 450);
        assert!((rows[0].avg_ms - 37.5).abs() < 1e-9, "avg: {}", rows[0].avg_ms);
    }
}
