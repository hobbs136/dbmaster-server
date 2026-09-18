//! SQL Server（TDS）后端基建（dbx-response T28 / ADR-0005 §2.4）。
//!
//! tiberius 是纯 async TDS 客户端（非 sqlx），连接管理 / 参数绑定 / 值解码
//! 都与 MySQL/PG 族不同，集中在本模块，供三处消费（同源纪律）：
//! - `db_handler.rs`：DbBackend::SqlServerBackend（REST /api/db/* 老网关 +
//!   网关注册/测试草稿路径 `test_draft_connection`）；
//! - `metadata.rs`：Tier 1 元数据三件（MCP 工具与 /api/gw/* 网关同源）；
//! - `stream_query.rs`：网关 SSE 流式执行。
//!
//! **取消/超时语义（#30 锚点 / SS-TIMEOUT-301 不复发）**：本模块不做连接
//! 池——每次执行一条专用 `Client<Compat<TcpStream>>`，取消/超时/行限统一以
//! drop client 收尾；TCP 断开后 SQL Server 随会话终止终止正在执行的批处理
//! （等价 KILL session），不会复现「FFI 层超时静默成功」。
//!
//! **加密协商**：启用 rustls feature 后 tiberius 默认 `EncryptionLevel::Required`
//! （流量 + 登录全 TLS）。SQL Server 开箱自带自签证书（绝大多数内网部署
//! 无企业 CA），`DBMASTER_MSSQL_TRUST_SERVER_CERT`（默认 1）控制是否跳过
//! 证书校验——对齐 SSMS 连接串常见的 TrustServerCertificate=yes。置 0 时
//! 走系统信任链校验（内网自签服务器将连接失败，需先信任 CA）。
//!
//! **值解码**：TDS 列是强类型（FromSql 严格按列类型匹配，无 sqlx 式宽松
//! 链），解码按类型逐一尝试（字符串 → bool → 整数族 → 浮点族 → Numeric →
//! 日期时间族 → Uuid → bytes → null），输出 JSON 语义值：日期/时间/
//! decimal/uuid 为 ISO/十进制字符串，二进制尝试 UTF-8 否则占位符
//! （与 decode_cell_mysql 链同口径）。xml 列暂落 null（已知边界，同既有
//! REST 网关对部分类型落 null 的口径）。

use tiberius::{error::Error as TdsError, AuthMethod, Client, Config as TdsConfig, Row};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use crate::db_handler::DbConnectionRow;

/// 专用连接的流类型：tokio TcpStream 经 compat_write 适配 tiberius 的
/// futures::AsyncRead/AsyncWrite 约束（官方 README 同款写法）。
pub(crate) type SsStream = Compat<TcpStream>;

/// 是否信任 SQL Server 证书（跳过校验）。见模块级文档。
pub(crate) const TRUST_CERT_ENV: &str = "DBMASTER_MSSQL_TRUST_SERVER_CERT";

pub(crate) fn trust_server_cert() -> bool {
    match std::env::var(TRUST_CERT_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            // 空/1/true/yes/on → 信任；其余（0/false/no/off/任意输入）→ 校验。
            v.is_empty() || v == "1" || v == "true" || v == "yes" || v == "on"
        }
        // 未配置默认信任：SQL Server 自签证书是内网常态，默认校验会让
        // 绝大多数开箱连接失败（等价 SSMS 的 TrustServerCertificate=yes）。
        Err(_) => true,
    }
}

/// 组装 tiberius 连接配置。`db` 缺省回退连接行的 default_database，再缺省
/// 用 master（tiberius 默认），与 MySQL 族「空库名不下发」的特判不同——
/// TDS 握手必须落在某个库上下文。
pub(crate) fn tds_config(conn: &DbConnectionRow, password: &str, db: Option<&str>) -> TdsConfig {
    let mut config = TdsConfig::new();
    config.host(&conn.host);
    config.port(conn.port as u16);
    config.authentication(AuthMethod::sql_server(&conn.username, password));
    let database = db
        .or(conn.default_database.as_deref())
        .filter(|d| !d.is_empty())
        .unwrap_or("master");
    config.database(database);
    config.application_name("dbmaster-server");
    if trust_server_cert() {
        config.trust_cert();
    }
    config
}

/// 打开一条专用连接（每调用一条，drop 即断连终止服务端批处理）。
/// 错误为 tiberius 原始错误，调用方自行映射（连接失败统一不回传引擎细节）。
pub(crate) async fn open_sqlserver(
    conn: &DbConnectionRow,
    password: &str,
    db: Option<&str>,
) -> Result<Client<SsStream>, TdsError> {
    let config = tds_config(conn, password, db);
    let tcp = TcpStream::connect(config.get_addr()).await?;
    let client = Client::connect(config, tcp.compat_write()).await?;
    Ok(client)
}

/// tiberius 错误 → 引擎原始码透传（TDS 错误号，如 208 = Invalid object name）。
/// 仅 `Error::Server` 携带；网络/协议错误无引擎码。
pub(crate) fn tiberius_engine_code(e: &TdsError) -> Option<String> {
    e.code().map(|c| c.to_string())
}

/// 执行非查询语句（DDL/DML）并返回受影响行数。
///
/// 双路分流：
/// - **DML（INSERT/UPDATE/DELETE/MERGE）** → `execute`（sp_executesql），
///   返回精确受影响行数；
/// - **其余（DDL/EXEC/WAITFOR…）** → `simple_query` 原生 SQL batch——
///   CREATE VIEW/PROCEDURE 等「模块」语句在 sp_executesql 上下文报语法错
///   （实机 SQL Server 2022 验证：error 156 Incorrect syntax near the
///   keyword 'VIEW'；CREATE TABLE/INDEX 不受影响），必须是 batch 首语句。
///   非 DML 的受影响行数报 0（对齐 sqlx execute 对 DDL 报 0 的口径；
///   tiberius QueryStream 不暴露 Done 令牌的 rowcount）。
pub(crate) async fn execute_tds(
    client: &mut Client<SsStream>,
    sql: &str,
) -> Result<u64, TdsError> {
    use futures::StreamExt;
    if is_dml_statement(sql) {
        let result = client.execute(sql, &[]).await?;
        return Ok(result.total());
    }
    let stream = client.simple_query(sql).await?;
    // 消费到终态（执行错误即时抛出）。
    let mut stream = Box::pin(stream);
    while let Some(item) = stream.next().await {
        item?;
    }
    Ok(0)
}

/// DML 前缀判据（首词）。多语句已被网关/上游拒掉；此处只辨「要不要行数」。
fn is_dml_statement(sql: &str) -> bool {
    let first = sql.trim_start().split_whitespace().next().unwrap_or_default();
    let first = first.to_ascii_lowercase();
    matches!(first.as_str(), "insert" | "update" | "delete" | "merge")
}

/// tiberius 行 → (列名数组, 位置数组值)——stream_query 的归一形状。
pub(crate) fn map_tds_row(
    row: &Row,
) -> (Vec<String>, Vec<serde_json::Value>, Option<Vec<String>>) {
    let columns = row.columns().iter().map(|c| c.name().to_string()).collect();
    let values = (0..row.columns().len()).map(|i| decode_cell_tds(row, i)).collect();
    // T29 — 列类型名暂不随 meta 上抛（客户端 T031 语义只消费 mysql/pg
    // 族的 json 类型名）。
    (columns, values, None)
}

/// TDS 单元格解码（类型逐一尝试，见模块级文档）。解码失败统一 null——
/// 与既有 REST 网关 decode 链对部分类型落 null 的口径一致，非回归。
pub(crate) fn decode_cell_tds(row: &Row, idx: usize) -> serde_json::Value {
    use serde_json::Value;
    // try_get 直接返回 Result<Option<T>>（NULL 由驱动内化），链上每个具体
    // 类型一次匹配，失败即换下个（无分配开销）。
    if let Ok(v) = row.try_get::<&str, _>(idx) {
        return v.map(|s| Value::String(s.to_string())).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<bool, _>(idx) {
        return v.map(Value::Bool).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<i64, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<i32, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<i16, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<u8, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<f64, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<f32, _>(idx) {
        return v.map(|n| serde_json::json!(n)).unwrap_or(Value::Null);
    }
    // decimal/numeric/money：十进制字符串（保持精度，不用浮点丢尾）。
    if let Ok(v) = row.try_get::<tiberius::numeric::Numeric, _>(idx) {
        return v.map(|n| Value::String(n.to_string())).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDateTime, _>(idx) {
        return v
            .map(|t| Value::String(t.format("%Y-%m-%dT%H:%M:%S%.f").to_string()))
            .unwrap_or(Value::Null);
    }
    // datetimeoffset：保留原时区偏移（RFC 3339）。
    if let Ok(v) = row.try_get::<chrono::DateTime<chrono::FixedOffset>, _>(idx) {
        return v.map(|t| Value::String(t.to_rfc3339())).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDate, _>(idx) {
        return v.map(|d| Value::String(d.format("%Y-%m-%d").to_string())).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<chrono::NaiveTime, _>(idx) {
        return v.map(|t| Value::String(t.format("%H:%M:%S%.f").to_string())).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<uuid::Uuid, _>(idx) {
        return v.map(|u| Value::String(u.to_string())).unwrap_or(Value::Null);
    }
    // Vec<u8> 只有 FromSqlOwned（借用面是 &[u8]）——借用解码后拷贝。
    if let Ok(v) = row.try_get::<&[u8], _>(idx) {
        return v
            .map(|b| match String::from_utf8(b.to_vec()) {
                Ok(s) => Value::String(s),
                Err(e) => Value::String(format!("<{} bytes>", e.as_bytes().len())),
            })
            .unwrap_or(Value::Null);
    }
    Value::Null
}

/// sys.columns × sys.types 的类型投影 → 引擎完整类型字符串（对齐 MySQL
/// describe 用 column_type 的口径：`nvarchar(50)` / `decimal(18,2)`）。
///
/// 长度语义：`max_length` 是**字节**（-1 = MAX）；n 前缀类型按 2 字节/字符
/// 折半。precision/scale 只对 decimal/numeric 与 时间小数秒类型 有意义。
pub(crate) fn format_sqlserver_type(
    type_name: &str,
    max_length: i16,
    precision: u8,
    scale: u8,
) -> String {
    let name = type_name.to_ascii_lowercase();
    let simple = || name.clone();
    match name.as_str() {
        "nvarchar" | "nchar" => match max_length {
            -1 => format!("{name}(max)"),
            n if n > 0 => format!("{name}({})", n / 2),
            _ => simple(),
        },
        "varchar" | "char" | "varbinary" | "binary" => match max_length {
            -1 => format!("{name}(max)"),
            n if n > 0 => format!("{name}({n})"),
            _ => simple(),
        },
        "decimal" | "numeric" => format!("{name}({precision},{scale})"),
        "time" | "datetime2" | "datetimeoffset" => format!("{name}({scale})"),
        _ => simple(),
    }
}

/// OBJECT_DEFINITION(default_object_id) 的默认值清洗：SS 默认值外层带
/// 引擎生成的一层以上包裹括号（`((0))`），剥到配对外括号为止；`(1)+(2)`
/// 这类「首尾恰好是括号但内部已配对闭合」的表达式不动（配对深度检查）。
/// NULL（无默认）→ None。wire 上 default_value 是干净表达式（对齐 MySQL
/// column_default 的输出风格）。
pub(crate) fn strip_default_parens_opt(v: &serde_json::Value) -> Option<String> {
    let s = v.as_str()?.trim();
    if s.is_empty() {
        return None;
    }
    let mut s = s;
    while s.starts_with('(') && s.ends_with(')') {
        // 外层括号是否配对：内部深度永不归零（归零点在末尾才算一层完整包裹）。
        let mut depth = 0i32;
        let mut wraps = false;
        for (i, c) in s.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        wraps = i + c.len_utf8() == s.len();
                        break;
                    }
                }
                _ => {}
            }
        }
        if !wraps {
            break;
        }
        s = s[1..s.len() - 1].trim(); // 括号是单字节，边界安全
    }
    if s.is_empty() { None } else { Some(s.to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_type_covers_common_families() {
        // n 前缀按 2 字节/字符折半；-1 = max。
        assert_eq!(format_sqlserver_type("nvarchar", 100, 0, 0), "nvarchar(50)");
        assert_eq!(format_sqlserver_type("nvarchar", -1, 0, 0), "nvarchar(max)");
        assert_eq!(format_sqlserver_type("varchar", 50, 0, 0), "varchar(50)");
        assert_eq!(format_sqlserver_type("varchar", -1, 0, 0), "varchar(max)");
        assert_eq!(format_sqlserver_type("decimal", 0, 18, 2), "decimal(18,2)");
        assert_eq!(format_sqlserver_type("numeric", 0, 38, 4), "numeric(38,4)");
        assert_eq!(format_sqlserver_type("datetime2", 0, 0, 7), "datetime2(7)");
        assert_eq!(format_sqlserver_type("time", 0, 0, 3), "time(3)");
        // 无维度类型保持裸名（大小写归一小写）。
        assert_eq!(format_sqlserver_type("INT", 4, 0, 0), "int");
        assert_eq!(format_sqlserver_type("bigint", 8, 0, 0), "bigint");
    }

    #[test]
    fn trust_env_parse() {
        // 未配置默认信任（模块级文档的取舍）。
        assert!(trust_server_cert());
    }

    #[test]
    fn dml_prefix_classifier() {
        assert!(is_dml_statement("INSERT INTO t VALUES (1)"));
        assert!(is_dml_statement("  update t set x = 1"));
        assert!(is_dml_statement("DELETE FROM t"));
        assert!(is_dml_statement("MERGE INTO t USING s ON 1 = 1"));
        // DDL/其它走原生 batch 路径。
        assert!(!is_dml_statement("CREATE VIEW v AS SELECT 1"));
        assert!(!is_dml_statement("WAITFOR DELAY '0:0:5'"));
        assert!(!is_dml_statement("EXEC sp_help"));
        assert!(!is_dml_statement(""));
    }

    #[test]
    fn strip_default_parens_unwraps_balanced_layers_only() {
        use serde_json::json;
        // 引擎包裹层逐层剥。
        assert_eq!(
            strip_default_parens_opt(&json!("((0))")).as_deref(),
            Some("0")
        );
        assert_eq!(
            strip_default_parens_opt(&json!("(N'tz')")).as_deref(),
            Some("N'tz'")
        );
        // 内部已配对闭合的表达式不动（首尾括号不是一层包裹）。
        assert_eq!(
            strip_default_parens_opt(&json!("(1)+(2)")).as_deref(),
            Some("(1)+(2)")
        );
        // NULL / 空串 → None。
        assert!(strip_default_parens_opt(&json!(null)).is_none());
        assert!(strip_default_parens_opt(&json!("")).is_none());
        assert!(strip_default_parens_opt(&json!("( )")).is_none());
    }
}
