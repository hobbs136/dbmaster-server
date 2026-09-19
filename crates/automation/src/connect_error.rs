//! gw `POST /api/gw/connections/test` 失败响应 `error_code` 的契约常量与
//! 驱动错误 → 码判别（T12s）。
//!
//! # 值域（稳定码集，只加不删；旧客户端忽略新字段）
//!
//! | 码 | 语义 |
//! |---|---|
//! | [`AUTH_DENIED`] | 凭据/认证被拒（用户名/密码/认证机制失败） |
//! | [`UNREACHABLE`] | 网络不可达（DNS 解析失败、TCP 拒绝/重置、SSH 隧道建立失败） |
//! | [`TIMEOUT`] | 超时（驱动连接超时/池获取超时；复用 stream_query SSE 既有码） |
//! | [`DB_ERROR`] | 其余失败（引擎错误、文件错误、未知），与 stream_query SSE
//!   error 事件的 DB_ERROR 同码同义 |
//!
//! 判别收在 automation（gateway 是薄 HTTP 封装层、无驱动依赖；驱动错误
//! 类型与既有判别件 mongo/redis_leg 仅本 crate 可见）。[`DraftTestError::code`]
//! 是枚举串，永不含用户名/IP/凭据明文；[`DraftTestError::message`] 一律经
//! `db_handler::redact`（不含 host/凭据）。

/// 凭据/认证被拒（用户名/密码/认证机制失败）。
pub const AUTH_DENIED: &str = "AUTH_DENIED";

/// 网络不可达：DNS 解析失败、TCP 连接拒绝/重置、SSH 隧道建立失败。
pub const UNREACHABLE: &str = "UNREACHABLE";

/// 超时（驱动连接超时/池获取超时；复用既有码）。
pub const TIMEOUT: &str = "TIMEOUT";

/// 其余失败（引擎错误、文件错误、未知）兜底码。
pub const DB_ERROR: &str = "DB_ERROR";

/// 草稿连接测试失败（`test_draft_connection` 的 Err 形态）：稳定码 +
/// redact 后文案。`code` 只取上面的值域。
#[derive(Debug)]
pub struct DraftTestError {
    /// 稳定码（值域见模块文档）。
    pub code: &'static str,
    /// redact 后的错误文案（wire `error` 字段，语义与旧裸 String 一致）。
    pub message: String,
}

/// 驱动错误对象 → 稳定码（纯函数；判别优先级：sqlx → tiberius → mongodb →
/// redis → io → 兜底 DB_ERROR）。输入是 test_* helper 抛出的 anyhow 包装，
/// 下层为各驱动原生错误类型。
pub fn classify_driver_error(e: &anyhow::Error) -> &'static str {
    if let Some(e) = e.downcast_ref::<sqlx::Error>() {
        return classify_sqlx(e);
    }
    if let Some(e) = e.downcast_ref::<tiberius::error::Error>() {
        return classify_tiberius(e);
    }
    if let Some(e) = e.downcast_ref::<mongodb::error::Error>() {
        return classify_mongo(e);
    }
    if let Some(e) = e.downcast_ref::<redis::RedisError>() {
        return classify_redis(e);
    }
    if let Some(e) = e.downcast_ref::<std::io::Error>() {
        return classify_io_parts(e.kind(), &e.to_string());
    }
    DB_ERROR
}

/// sqlx 错误判别（MySQL 协议族 / PostgreSQL / SQLite / ClickHouse MySQL 口）。
fn classify_sqlx(e: &sqlx::Error) -> &'static str {
    match e {
        // 握手/执行期服务端错误：按错误码判（连接测试聚焦握手错误）。
        sqlx::Error::Database(db) => classify_db_code(db.code().as_deref()),
        sqlx::Error::Io(io) => classify_io_parts(io.kind(), &io.to_string()),
        // 池在 acquire 超时窗口内对拒连等退避重试（sqlx-core pool/inner），
        // 耗尽后归一为本错——驱动侧的"超时"事实。
        sqlx::Error::PoolTimedOut => TIMEOUT,
        _ => DB_ERROR,
    }
}

/// 驱动数据库错误码 → 码：MySQL 族拒绝访问（1045，含 Doris/OceanBase 等
/// 族成员与 ClickHouse MySQL 口）与 PostgreSQL SQLSTATE 28 类
/// （invalid_password / invalid_authorization_specification）归 AUTH_DENIED；
/// 其余（表不存在 42S02、库不存在 3D000 等）DB_ERROR。
fn classify_db_code(code: Option<&str>) -> &'static str {
    match code {
        Some("1045") => AUTH_DENIED,
        // SQLSTATE 恰 5 字符；MySQL 族错误号是 4 位数字，不会误伤。
        Some(c) if c.len() == 5 && c.starts_with("28") => AUTH_DENIED,
        _ => DB_ERROR,
    }
}

/// tiberius 错误判别（SQL Server 单次直连，无池重试）。
fn classify_tiberius(e: &tiberius::error::Error) -> &'static str {
    match e {
        tiberius::error::Error::Io { kind, message } => classify_io_parts(*kind, message),
        // TDS 服务端错误号：18456（登录失败）/ 18452（非信任域登录）= 凭据被拒。
        tiberius::error::Error::Server(te) => match te.code() {
            18456 | 18452 => AUTH_DENIED,
            _ => DB_ERROR,
        },
        _ => DB_ERROR,
    }
}

/// mongodb 错误判别（连接测试 = open + ping）。
fn classify_mongo(e: &mongodb::error::Error) -> &'static str {
    use mongodb::error::ErrorKind;
    match e.kind.as_ref() {
        ErrorKind::Authentication { .. } => AUTH_DENIED,
        // code 18 = AuthenticationFailed（认证在服务端命令层被拒）。
        ErrorKind::Command(cmd) if cmd.code == 18 => AUTH_DENIED,
        ErrorKind::Io(_)
        | ErrorKind::DnsResolve { .. }
        | ErrorKind::ServerSelection { .. } => UNREACHABLE,
        _ => DB_ERROR,
    }
}

/// redis 错误判别（单次直连 + PING）。
fn classify_redis(e: &redis::RedisError) -> &'static str {
    if e.is_timeout() {
        return TIMEOUT;
    }
    // ACL 认证失败：驱动侧 AuthenticationFailed 与服务端 WRONGPASS/NOAUTH。
    if matches!(e.kind(), redis::ErrorKind::AuthenticationFailed)
        || matches!(e.code(), Some("WRONGPASS") | Some("NOAUTH"))
    {
        return AUTH_DENIED;
    }
    // 草稿测试只有连接 + PING，io 级失败即网络不可达（DNS 失败也落此臂——
    // redis 驱动不透出 io kind，拒连判定 is_connection_refusal 优先命中）。
    if e.is_connection_refusal() || e.is_io_error() {
        return UNREACHABLE;
    }
    DB_ERROR
}

/// io 错误（kind + Display 文案）→ 码。sqlx/tiberius 的 io 臂与裸 io 错误
/// 共用一份判别。
fn classify_io_parts(kind: std::io::ErrorKind, message: &str) -> &'static str {
    match kind {
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::NetworkUnreachable
        | std::io::ErrorKind::NetworkDown
        | std::io::ErrorKind::HostUnreachable
        // 部分平台解析器把 DNS 域不存在映射为 NotFound。
        | std::io::ErrorKind::NotFound => UNREACHABLE,
        std::io::ErrorKind::TimedOut => TIMEOUT,
        _ => {
            // std getaddrinfo 解析失败的 de-facto 稳定消息前缀（kind 不定型，
            // Windows/macOS/Linux 同源构造点）。
            if message.contains("failed to lookup address information") {
                UNREACHABLE
            } else {
                DB_ERROR
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试假数据库错误（sqlx 的具体 DatabaseError 类型不可外部构造，
    /// trait 是唯一入口）。
    #[derive(Debug)]
    struct FakeDbError {
        code: Option<&'static str>,
    }

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fake db error")
        }
    }

    impl std::error::Error for FakeDbError {}

    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            "fake db error"
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.map(std::borrow::Cow::Borrowed)
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
    }

    fn sqlx_db(code: Option<&'static str>) -> anyhow::Error {
        anyhow::Error::from(sqlx::Error::Database(Box::new(FakeDbError { code })))
    }

    fn io_error(kind: std::io::ErrorKind) -> anyhow::Error {
        anyhow::Error::from(std::io::Error::new(kind, "io failure"))
    }

    // ── auth denied 路 ──

    #[test]
    fn sqlx_mysql_access_denied_is_auth() {
        assert_eq!(classify_driver_error(&sqlx_db(Some("1045"))), AUTH_DENIED);
    }

    #[test]
    fn sqlx_pg_sqlstate_28_is_auth() {
        assert_eq!(classify_driver_error(&sqlx_db(Some("28P01"))), AUTH_DENIED);
        assert_eq!(classify_driver_error(&sqlx_db(Some("28000"))), AUTH_DENIED);
    }

    #[test]
    fn redis_authentication_failed_is_auth() {
        let e = anyhow::Error::from(redis::RedisError::from((
            redis::ErrorKind::AuthenticationFailed,
            "auth failed",
        )));
        assert_eq!(classify_driver_error(&e), AUTH_DENIED);
    }

    // ── unreachable 路 ──

    #[test]
    fn sqlx_io_refused_is_unreachable() {
        let e = anyhow::Error::from(sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        )));
        assert_eq!(classify_driver_error(&e), UNREACHABLE);
    }

    #[test]
    fn sqlx_io_dns_lookup_failure_is_unreachable() {
        let e = anyhow::Error::from(sqlx::Error::Io(std::io::Error::other(
            "failed to lookup address information: Name or service not known",
        )));
        assert_eq!(classify_driver_error(&e), UNREACHABLE);
    }

    #[test]
    fn tiberius_io_refused_is_unreachable() {
        let e = anyhow::Error::from(tiberius::error::Error::Io {
            kind: std::io::ErrorKind::ConnectionRefused,
            message: "refused".to_string(),
        });
        assert_eq!(classify_driver_error(&e), UNREACHABLE);
    }

    #[test]
    fn redis_io_refused_is_unreachable() {
        let e = anyhow::Error::from(redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        )));
        assert_eq!(classify_driver_error(&e), UNREACHABLE);
    }

    #[test]
    fn bare_io_refused_is_unreachable() {
        assert_eq!(classify_driver_error(&io_error(std::io::ErrorKind::ConnectionRefused)), UNREACHABLE);
    }

    // ── timeout 路 ──

    #[test]
    fn sqlx_pool_timed_out_is_timeout() {
        assert_eq!(classify_driver_error(&anyhow::Error::from(sqlx::Error::PoolTimedOut)), TIMEOUT);
    }

    #[test]
    fn io_timed_out_is_timeout() {
        assert_eq!(classify_driver_error(&io_error(std::io::ErrorKind::TimedOut)), TIMEOUT);
    }

    #[test]
    fn redis_io_timed_out_is_timeout() {
        let e = anyhow::Error::from(redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )));
        assert_eq!(classify_driver_error(&e), TIMEOUT);
    }

    // ── 其它 → DB_ERROR 兜底 ──

    #[test]
    fn sqlx_engine_error_is_db_error() {
        // 表不存在（42S02）非认证/网络。
        assert_eq!(classify_driver_error(&sqlx_db(Some("42S02"))), DB_ERROR);
        assert_eq!(classify_driver_error(&sqlx_db(None)), DB_ERROR);
    }

    #[test]
    fn tiberius_protocol_error_is_db_error() {
        let e = anyhow::Error::from(tiberius::error::Error::Protocol("bad token".into()));
        assert_eq!(classify_driver_error(&e), DB_ERROR);
    }

    #[test]
    fn redis_command_error_is_db_error() {
        // 客户端侧错误（非认证/网络/超时）。
        let e = anyhow::Error::from(redis::RedisError::from((
            redis::ErrorKind::Client,
            "client sent invalid command",
        )));
        assert_eq!(classify_driver_error(&e), DB_ERROR);
    }

    #[test]
    fn untyped_message_defaults_to_db_error() {
        assert_eq!(
            classify_driver_error(&anyhow::Error::msg("engine error 855: boom")),
            DB_ERROR
        );
    }
}
