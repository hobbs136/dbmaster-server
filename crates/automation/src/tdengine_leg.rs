//! T29 TDengine 批次 — 网关执行腿（taosAdapter REST 通道）。
//!
//! 通道取舍：TDengine 无 MySQL 协议兼容口（CH 先例不可复制），原生驱动需
//! C 库（taosc）不可行；taosAdapter REST（:6041）无状态、JSON 进出，与
//! 客户端旧直连适配器同一通道——**执行语义零漂移**（SQL 原文 + URL 路径
//! db 路由 + Basic auth）。reqwest 为 automation 既有依赖，零新增 crate。
//!
//! 响应形状（3.3.6 实机钉定，2026-08-27）：
//! - 查询：`{code:0, column_meta:[[name,type,bytes],...], data:[[...],...],
//!   rows:N}`；TIMESTAMP 值为 RFC3339 字符串（`2026-08-27T05:40:38.398Z`）。
//! - 写（DML+DDL 同形）：单列 `affected_rows`（INSERT 实际行数 / DDL 0）。
//! - 错误：`{code:非0, desc:"..."}`。
//! - DESCRIBE：7 列 [field,type,length,note,encode,compress,level]，TAG
//!   标记在 note（客户端旧代码读 index 4 判 TAG 是死代码——那是 encode 列）。

use std::time::Duration;

use serde_json::Value;

use crate::db_handler::DbConnectionRow;

/// REST 执行结果（错误见 [TdError]）。
pub(crate) struct TdQueryOutcome {
    /// (列名, 原生类型名) 对——column_meta 前两元。
    pub columns: Vec<(String, String)>,
    /// 数据行（值域 JSON 直通：字符串/数值/bool/null）。
    pub rows: Vec<Vec<Value>>,
}

impl TdQueryOutcome {
    /// 写响应形状：单列且列名为 affected_rows（值在 data[0][0]，无行数时 0）。
    /// 调用方先经语句分类（防 `SELECT affected_rows` 假阳性）再判形状。
    pub fn affected_rows(&self) -> Option<u64> {
        match (self.columns.as_slice(), self.rows.first()) {
            ([(name, _)], Some(row)) if name == "affected_rows" => {
                Some(row.first().and_then(Value::as_u64).unwrap_or(0))
            }
            _ => None,
        }
    }
}

/// REST 通道错误三分类（映射约定见 stream_query::run_stream_tdengine）。
/// Debug：gw_net_e2e 断言与调试打印（错误负载不含凭据——desc 上游已截断）。
#[derive(Debug)]
pub(crate) enum TdError {
    /// 传输层（连接拒绝/DNS/超时）→ CONNECTION_FAILED（不回传细节）。
    Transport,
    /// 认证失败（401/403）→ CONNECTION_FAILED（对齐 mongo ping 归一——auth
    /// 属连接级）。
    Auth,
    /// HTTP 非 200 且非认证 → DB_ERROR。
    Http(u16, String),
    /// TDengine 业务错误（code != 0）→ DB_ERROR + engineCode。
    Engine(i64, String),
}

/// 写语句静态分类（首词集，对齐 redis_leg 静态表白名单思路的反面）。
/// 未知首词按读放行（SHOW/SELECT/DESCRIBE/EXPLAIN…）；read_only 连接拒
/// 写的语义见 stream_query。前导注释剥离（`--`/`//`/`/* */`）。
pub(crate) fn is_write_statement(sql: &str) -> bool {
    let mut rest = sql.trim_start();
    loop {
        if let Some(r) = rest.strip_prefix("--") {
            rest = r.split_once('\n').map_or("", |(_, r)| r).trim_start();
        } else if let Some(r) = rest.strip_prefix("//") {
            rest = r.split_once('\n').map_or("", |(_, r)| r).trim_start();
        } else if let Some(r) = rest.strip_prefix("/*") {
            rest = match r.find("*/") {
                Some(end) => r[end + 2..].trim_start(),
                None => "",
            };
        } else {
            break;
        }
    }
    let first = rest
        .split(|c: char| c.is_whitespace() || c == '(')
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    matches!(
        first.to_ascii_uppercase().as_str(),
        "INSERT" | "DELETE" | "UPDATE" | "CREATE" | "DROP" | "ALTER" | "TRUNCATE" | "GRANT"
            | "REVOKE" | "USE" | "MERGE" | "COMPACT" | "KILL"
    )
}

/// REST URL 组装（纯函数，供单测钉语义）：`useTls` → https，否则 http；
/// db 路由是路径段（空串不路由，与旧客户端适配器同语义）。
fn rest_url(host: &str, port: i64, db: Option<&str>, use_tls: bool) -> String {
    let scheme = if use_tls { "https" } else { "http" };
    let mut url = format!("{scheme}://{host}:{port}/rest/sql");
    if let Some(db) = db.filter(|d| !d.is_empty()) {
        url.push('/');
        url.push_str(db);
    }
    url
}

/// 执行单条 SQL（db = None 时打到 /rest/sql 根——SQL 需自含库名限定，
/// 与旧客户端适配器同语义）。
///
/// 网络层批次（2026-08-29）— extra `useTls` → https；`tlsInsecure` 或经
/// 隧道（收口改写后连的是 127.0.0.1，证书域名必失配）时放宽证书校验
///（danger_accept_invalid_certs 仅在需要时启用）。
pub(crate) async fn exec_sql(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
    sql: &str,
    timeout: Duration,
) -> Result<TdQueryOutcome, TdError> {
    let (use_tls, tls_insecure) = crate::net_flags::tls_flags(conn.extra.as_deref());
    let insecure = tls_insecure || crate::net_flags::tunneled(conn.extra.as_deref());
    let url = rest_url(&conn.host, conn.port, db, use_tls);
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if use_tls && insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder.build().map_err(|_| TdError::Transport)?;
    let resp = client
        .post(&url)
        .basic_auth(&conn.username, Some(password))
        .body(sql.to_string())
        .send()
        .await
        .map_err(|_| TdError::Transport)?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|_| TdError::Transport)?;
    if status == 401 || status == 403 {
        return Err(TdError::Auth);
    }
    if status != 200 {
        return Err(TdError::Http(status, body.chars().take(200).collect()));
    }
    let v: Value = serde_json::from_str(&body)
        .map_err(|_| TdError::Http(status, "malformed JSON response".to_string()))?;
    let code = v.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        // 实机钉定（3.3.6）：认证失败不是 HTTP 401 而是 HTTP 200 + code 855
        //（"Authentication failure"）——集中归一到 Auth（连接级）。
        if code == 855 {
            return Err(TdError::Auth);
        }
        let desc = v
            .get("desc")
            .and_then(Value::as_str)
            .unwrap_or("unknown engine error")
            .to_string();
        return Err(TdError::Engine(code, desc.chars().take(200).collect()));
    }
    let columns = v
        .get("column_meta")
        .and_then(Value::as_array)
        .map(|meta| {
            meta.iter()
                .filter_map(|c| {
                    let arr = c.as_array()?;
                    let name = arr.first()?.as_str()?.to_string();
                    let ty = arr.get(1).and_then(Value::as_str).unwrap_or("").to_string();
                    Some((name, ty))
                })
                .collect()
        })
        .unwrap_or_default();
    let rows = v
        .get("data")
        .and_then(Value::as_array)
        .map(|data| {
            data.iter()
                .map(|row| row.as_array().cloned().unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    Ok(TdQueryOutcome { columns, rows })
}

/// 尽力取版本（SELECT SERVER_VERSION() 首行首列；失败返回空串——版本是
/// 展示性信息）。
pub(crate) async fn server_version(conn: &DbConnectionRow, password: &str) -> String {
    let Ok(outcome) = exec_sql(conn, password, None, "SELECT SERVER_VERSION()", Duration::from_secs(10)).await
    else {
        return String::new();
    };
    outcome
        .rows
        .first()
        .and_then(|r| r.first())
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// 连接测试（同语句同口径：code == 0 即可达且凭据有效）。T12s — 返回
/// 类型化 TdError（Auth/Transport 判别是 gw 草稿测试 error_code 的入口，
/// 见 db_handler::tdengine_failure；不再串行化成 String 丢判别信息）。
pub(crate) async fn test_tdengine(conn: &DbConnectionRow, password: &str) -> Result<(), TdError> {
    exec_sql(conn, password, None, "SELECT SERVER_VERSION()", Duration::from_secs(10))
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(columns: &[(&str, &str)], rows: Vec<Vec<Value>>) -> TdQueryOutcome {
        TdQueryOutcome {
            columns: columns
                .iter()
                .map(|(n, t)| (n.to_string(), t.to_string()))
                .collect(),
            rows,
        }
    }

    #[test]
    fn write_classification_first_keyword() {
        assert!(is_write_statement("INSERT INTO t VALUES (1)"));
        assert!(is_write_statement("  create\nstable s (...)"));
        assert!(is_write_statement("DROP DATABASE db"));
        assert!(is_write_statement("alter table t add column"));
        assert!(!is_write_statement("SELECT 1"));
        assert!(!is_write_statement("show databases"));
        assert!(!is_write_statement("DESCRIBE t"));
        assert!(!is_write_statement("explain select * from t"));
    }

    #[test]
    fn write_classification_strips_leading_comments() {
        assert!(is_write_statement("-- header\nINSERT INTO t VALUES (1)"));
        assert!(is_write_statement("/* block */ DELETE FROM t"));
        assert!(!is_write_statement("-- comment only\nSELECT 1"));
    }

    #[test]
    fn write_classification_parenthesized_insert() {
        assert!(is_write_statement("(INSERT INTO t VALUES (1))"));
    }

    #[test]
    fn affected_rows_shape_detection() {
        let write = outcome(&[("affected_rows", "INT")], vec![vec![Value::from(3u64)]]);
        assert_eq!(write.affected_rows(), Some(3));
        // 形状不符（多列 / 列名不同 / 无数据行）→ None（调用方按查询处理
        // 或 unwrap_or(0)——实机写响应恒有 data[[n]]，连 DDL 也是 [[0]]）。
        let query = outcome(&[("ts", "TIMESTAMP"), ("v", "DOUBLE")], vec![]);
        assert_eq!(query.affected_rows(), None);
        let no_data = outcome(&[("affected_rows", "INT")], vec![]);
        assert_eq!(no_data.affected_rows(), None);
    }

    #[test]
    fn url_db_routing_is_path_segment() {
        // exec_sql 的 URL 组装是纯字符串拼接；此处钉 db 过滤语义（空串不路由）。
        let db: Option<&str> = Some("");
        assert!(db.filter(|d| !d.is_empty()).is_none());
    }

    #[test]
    fn rest_url_scheme_and_db_routing() {
        // 缺省 http；db 是路径段。
        assert_eq!(rest_url("h", 6041, None, false), "http://h:6041/rest/sql");
        assert_eq!(rest_url("h", 6041, Some(""), false), "http://h:6041/rest/sql");
        assert_eq!(rest_url("h", 6041, Some("db1"), false), "http://h:6041/rest/sql/db1");
        // useTls → https（隧道收口后 host 已是 127.0.0.1——证书校验放宽在
        // exec_sql 判定，URL 本身不变）。
        assert_eq!(rest_url("127.0.0.1", 6041, Some("db1"), true), "https://127.0.0.1:6041/rest/sql/db1");
    }
}
