//! Server configuration loaded from environment variables.
//!
//! All settings have sensible defaults for development. Production deployments
//! MUST set `SERVER_JWT_SECRET` and `SERVER_JWT_REFRESH_SECRET` to strong random values.

/// Server configuration sourced from environment variables (with `.env` support via `dotenvy`).
#[derive(Clone, Debug)]
pub struct Config {
    /// Host address to bind to (e.g. "0.0.0.0" or "127.0.0.1").
    pub host: String,
    /// Port to listen on.
    pub port: u16,
    /// Secret key for signing access tokens (HS256). Must be set in production.
    pub jwt_secret: String,
    /// Secret key for signing refresh tokens (HS256). Must differ from `jwt_secret` in production.
    pub jwt_refresh_secret: String,
    /// SQLite database URL (e.g. "sqlite:dbmaster.db" or "sqlite::memory:").
    pub database_url: String,
    // CHANGE: telemetry-funnel-plan.md D5 — funnel-lite kill switch. Defaults
    // ON; flip off via `DBMASTER_FUNNEL_LITE_ENABLED=0`. Surfaced via
    // /api/health (architect ratification of D5 placement is pending —
    // moving it to /api/feature-flags later is a desktop one-liner).
    pub funnel_lite_enabled: bool,
    // CHANGE: ADR-0002 §4 D7 / §7.1 / Phase E — drift scheduler interval and
    // webhook timeout. Interval is the per-scan cadence in minutes (clamped
    // to 1..=1440 per ADR §6 input validation). Webhook timeout bounds each
    // individual HTTP attempt.
    pub drift_default_interval_mins: u32,
    pub drift_webhook_timeout_secs: u64,
    // CHANGE: data-sync 一期 — default batch size for time-batched ETL, and a
    // reserved max-concurrency knob (v1 runs serially; the knob exists so a
    // future parallel-shard phase doesn't need a Config schema change).
    pub data_sync_default_batch_size: u64,
    pub data_sync_max_concurrency: u32,
    // CHANGE: dbx-response T04 — MCP `/mcp` per-user rate limit (requests per
    // minute, sliding window). AI agents issue one HTTP request per tool call,
    // so this ceiling is much higher than the auth endpoints' 5/min-per-IP;
    // clamped to [1, 10000] so a typo can't silently disable rate limiting.
    pub mcp_rate_limit_per_minute: u32,
    // CHANGE: dbx-response T07 — MCP read_query row-limit ceiling (per-call
    // `max_rows` is clamped to this; the per-call default of 500 lives in the
    // mcp tools layer). Default 10000 matches the REST gateway's row cap so
    // both entry points share the same blast radius; clamped [1, 100000].
    pub mcp_read_query_max_rows: u32,
    // CHANGE: dbx-response T07 — MCP read_query statement timeout (seconds).
    // Bounds every read_query execution server-side (tokio wall clock; the
    // per-call pool is dropped on expiry, killing the query server-side);
    // clamped [1, 600] so a typo can't pin connections for hours.
    pub mcp_read_query_timeout_secs: u32,
    // CHANGE: T07 部署发现 — MCP Host 头放行表（rmcp DNS-rebinding 防护默认
    // 只认回环地址，LAN/公网部署全部 403）。空 = 放行全部 host：本 server 的
    // MCP 认证是 Bearer token（无 cookie 可被 rebinding 窃取），远程访问是
    // 产品主路径；要收紧时逗号分隔填 host[:port]，如
    // `DBMASTER_MCP_ALLOWED_HOSTS=localhost,192.0.2.10:38080`。
    pub mcp_allowed_hosts: Vec<String>,
    // dbx-response T08 — MCP 连接白名单（对齐 dbx 的 connection allowlist）。
    // 非空时只有列表中的连接对 MCP 工具面可见/可用：list_connections 输出被
    // 过滤，所有按 connection_id 取参的工具在触达目标库前重查。条目按连接
    // id 或 name 精确匹配（运维认 name——桌面端可见；agent 持 id——工具参数）。
    // 空 = 不过滤（对齐 `/api/connections` v1 可见性，产品默认）。REST 网关
    // 不受影响——白名单只约束 MCP 面。
    pub mcp_allowed_connections: Vec<String>,
    // dbx-response T27 — DB 网关 API v1（/api/gw/*，c01_port_contract §4）：
    // per-user 限流（req/min）。GUI 客户端的树浏览/网格刷新是请求密集面
    // （一次展开 = 一请求），默认比 MCP 的 120 高一档；clamp [1, 100000]。
    pub gw_rate_limit_per_minute: u32,
    // T27 — 查询执行缺省行限（客户端未显式传 rowLimit 时；对齐 MCP read_query
    // 的 500 口径）。显式 rowLimit 由 gw_query_max_rows 钳制。
    pub gw_query_default_rows: u32,
    // T27 — 查询执行行限上限（显式 rowLimit 的天花板；与 MCP/REST 网关的
    // 10000 同一爆炸半径）；clamp [1, 100000]。
    pub gw_query_max_rows: u32,
    // T27 — 查询执行 statement_timeout（秒，tokio 墙钟；缺省值，客户端可经
    // timeoutMs 显式覆盖——GUI 大查询场景需要更长的窗口）；clamp [1, 600]。
    pub gw_query_timeout_secs: u32,
    // reports-M1（#29）— 慢查询采样总开关（kill switch）。默认开；
    // `DBMASTER_SLOW_QUERY_ENABLED=0` 停止捕获（读端点不受影响）。
    pub slow_query_enabled: bool,
    // reports-M1 — 慢查询采样阈值（毫秒）。低于阈值的执行不落库；默认 1000
    // 与客户端本地 Performance Analyzer 对齐；clamp [100, 600000]。
    pub slow_query_threshold_ms: u32,
    // reports-M1 — 明文 SQL 开关（双轨存储，2026-08-27 拍板）：digest 恒存；
    // false 时 sql_text 不落库且不出现在任何 API 响应。默认 true——M1 网关源
    // 捕获的都是用户自己经 dbmaster 发出的查询，字面量本就在用户手里。
    pub slow_query_store_sql: bool,
    // reports-M1 — retention（天）。每小时后台清理 captured_at 早于窗口的行；
    // clamp [1, 365]。
    pub slow_query_retention_days: u32,
    // reports-M1 — 同 digest 每小时采样上限（封顶；内存滑窗、重启归零——
    // 增长的硬界由 retention 兜底）；clamp [1, 10000]。
    pub slow_query_cap_per_digest_per_hour: u32,
}

impl Config {
    /// Load configuration from environment variables, with `.env` file support.
    ///
    /// # Errors
    ///
    /// Returns an error if the `.env` file exists but cannot be read (e.g. permission denied).
    /// Missing `.env` is silently ignored.
    pub fn from_env() -> anyhow::Result<Self> {
        // Load .env file if present (silently ignore missing)
        let _ = dotenvy::dotenv();

        Ok(Self {
            host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            jwt_secret: std::env::var("SERVER_JWT_SECRET")
                .unwrap_or_else(|_| "dev-jwt-secret-change-in-production".to_string()),
            jwt_refresh_secret: std::env::var("SERVER_JWT_REFRESH_SECRET")
                .unwrap_or_else(|_| "dev-refresh-secret-change-in-production".to_string()),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:dbmaster.db?mode=rwc".to_string()),
            // CHANGE: telemetry-funnel-plan.md D5 — env-controlled funnel-lite flag.
            funnel_lite_enabled: parse_bool_env("DBMASTER_FUNNEL_LITE_ENABLED", true),
            // CHANGE: ADR-0002 §4 D7 — drift scheduler interval (minutes).
            // Clamp to [1, 1440] (1 minute..24h) per ADR §6 input validation;
            // out-of-range values fall back to default with a WARN.
            drift_default_interval_mins: parse_interval_env(
                "DBMASTER_DRIFT_DEFAULT_INTERVAL_MINS",
                30,
                1,
                1440,
            ),
            // CHANGE: ADR-0002 §4.4.2 — webhook per-request timeout (seconds).
            drift_webhook_timeout_secs: parse_u64_env(
                "DBMASTER_DRIFT_WEBHOOK_TIMEOUT_SECS",
                10,
            ),
            // CHANGE: data-sync 一期 — batch size default 10000 rows/batch
            // (balances source-DB pressure vs round-trips for a 3000M-row
            // main table). Concurrency is serial in v1 (max_concurrency=1);
            // the env knob is reserved for a future parallel-shard phase.
            data_sync_default_batch_size: parse_u64_env("DBMASTER_DATASYNC_BATCH_SIZE", 10000),
            data_sync_max_concurrency: parse_interval_env(
                "DBMASTER_DATASYNC_MAX_CONCURRENCY",
                1,
                1,
                32,
            ),
            // CHANGE: dbx-response T04 — MCP per-user rate limit (req/min).
            // Default 120 leaves headroom for an agentic tool loop while
            // bounding runaway clients; override via env for tuning.
            mcp_rate_limit_per_minute: parse_interval_env(
                "DBMASTER_MCP_RATE_LIMIT_PER_MIN",
                120,
                1,
                10000,
            ),
            // CHANGE: dbx-response T07 — read_query row ceiling / timeout.
            mcp_read_query_max_rows: parse_interval_env(
                "DBMASTER_MCP_READ_QUERY_MAX_ROWS",
                10000,
                1,
                100000,
            ),
            mcp_read_query_timeout_secs: parse_interval_env(
                "DBMASTER_MCP_READ_QUERY_TIMEOUT_SECS",
                30,
                1,
                600,
            ),
            // CHANGE: T07 部署发现 — 空 = 放行全部 Host（产品主路径是远程
            // 访问 + Bearer 认证）；显式列表时严格匹配 host[:port]。
            mcp_allowed_hosts: parse_list_env("DBMASTER_MCP_ALLOWED_HOSTS"),
            // T08 — MCP 连接白名单（空 = 不过滤；条目 = id 或 name）。
            mcp_allowed_connections: parse_list_env("DBMASTER_MCP_ALLOWED_CONNECTIONS"),
            // T27 — DB 网关 API v1 限额族（c01_port_contract §4.3）。
            gw_rate_limit_per_minute: parse_interval_env(
                "DBMASTER_GW_RATE_LIMIT_PER_MIN",
                600,
                1,
                100000,
            ),
            gw_query_default_rows: parse_interval_env(
                "DBMASTER_GW_QUERY_DEFAULT_ROWS",
                500,
                1,
                100000,
            ),
            gw_query_max_rows: parse_interval_env("DBMASTER_GW_QUERY_MAX_ROWS", 10000, 1, 100000),
            gw_query_timeout_secs: parse_interval_env("DBMASTER_GW_QUERY_TIMEOUT_SECS", 30, 1, 600),
            // reports-M1（#29）— 慢查询采样配置族（design-reports-m1.md §4.4）。
            slow_query_enabled: parse_bool_env("DBMASTER_SLOW_QUERY_ENABLED", true),
            slow_query_threshold_ms: parse_interval_env(
                "DBMASTER_SLOW_QUERY_THRESHOLD_MS",
                1000,
                100,
                600_000,
            ),
            slow_query_store_sql: parse_bool_env("DBMASTER_SLOW_QUERY_STORE_SQL", true),
            slow_query_retention_days: parse_interval_env(
                "DBMASTER_SLOW_QUERY_RETENTION_DAYS",
                14,
                1,
                365,
            ),
            slow_query_cap_per_digest_per_hour: parse_interval_env(
                "DBMASTER_SLOW_QUERY_CAP_PER_DIGEST_PER_HOUR",
                20,
                1,
                10000,
            ),
        })
    }
}

/// Parse a boolean environment variable: "1"/"true"/"yes"/"on" (case-insensitive)
/// → true; any other value → false; unset → `default`.
// CHANGE: telemetry-funnel-plan.md D5 — centralised parser so other bool flags
// can reuse it.
fn parse_bool_env(key: &str, default: bool) -> bool {
    match std::env::var(key).ok().map(|s| s.to_lowercase()) {
        Some(s) => matches!(s.as_str(), "1" | "true" | "yes" | "on"),
        None => default,
    }
}

/// Parse a `u32` env var clamped to `[min, max]`. Unset → `default`;
/// unparseable or out-of-range → `default` + WARN (boot continues so a typo
/// can't take the server down — operators notice via the WARN).
// CHANGE: ADR-0002 §4 D7 / §6 — bounded interval parser for drift scheduler.
fn parse_interval_env(key: &str, default: u32, min: u32, max: u32) -> u32 {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().parse::<u32>() {
            Ok(v) if v >= min && v <= max => v,
            Ok(v) => {
                tracing::warn!(
                    key, value = v, min, max,
                    "env var out of range; falling back to default"
                );
                default
            }
            Err(_) => {
                tracing::warn!(key, raw = %raw, "env var not a u32; falling back to default");
                default
            }
        },
        Err(_) => default,
    }
}

/// Parse a `u64` env var with a fallback default. Unset or unparseable → default.
// CHANGE: ADR-0002 §4.4.2 — webhook timeout parser.
fn parse_u64_env(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(raw) => raw.trim().parse::<u64>().unwrap_or_else(|_| {
            tracing::warn!(key, raw = %raw, "env var not a u64; falling back to default");
            default
        }),
        Err(_) => default,
    }
}

/// Parse a comma-separated string-list env var. Unset / blank → empty list
/// (callers treat empty as "no restriction" — see `Config::mcp_allowed_hosts`).
// CHANGE: T07 — MCP allowed-hosts knob.
fn parse_list_env(key: &str) -> Vec<String> {
    match std::env::var(key) {
        Ok(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_env_defaults_when_unset() {
        std::env::remove_var("DBMASTER_TEST_BOOL_UNSET");
        assert!(parse_bool_env("DBMASTER_TEST_BOOL_UNSET", true));
        assert!(!parse_bool_env("DBMASTER_TEST_BOOL_UNSET", false));
    }

    // CHANGE: isolate env-var name per test (mirrors the DBMASTER_TEST_INTERVAL_*
    // pattern below). Previously both tests shared DBMASTER_TEST_BOOL_SET, so
    // parallel execution had them racing to set/remove the same var.
    #[test]
    fn parse_bool_env_recognises_truthy_values() {
        for v in ["1", "true", "TRUE", "Yes", "on"] {
            std::env::set_var("DBMASTER_TEST_BOOL_TRUTHY", v);
            assert!(
                parse_bool_env("DBMASTER_TEST_BOOL_TRUTHY", false),
                "{v} should be true"
            );
        }
        std::env::remove_var("DBMASTER_TEST_BOOL_TRUTHY");
    }

    #[test]
    fn parse_bool_env_treats_unknown_as_false() {
        std::env::set_var("DBMASTER_TEST_BOOL_UNKNOWN", "maybe");
        assert!(!parse_bool_env("DBMASTER_TEST_BOOL_UNKNOWN", true));
        std::env::remove_var("DBMASTER_TEST_BOOL_UNKNOWN");
    }

    // CHANGE: ADR-0002 Phase E — env parsers for drift config. Each test uses
    // a UNIQUE env var name so parallel test execution can't race (the lesson
    // of the parse_bool_env_* tests above where two tests share one var name).

    #[test]
    fn parse_interval_env_returns_default_when_unset() {
        // Unique var per assertion → no race with sibling tests.
        assert_eq!(parse_interval_env("DBMASTER_TEST_INTERVAL_UNSET_1", 30, 1, 1440), 30);
        assert_eq!(parse_interval_env("DBMASTER_TEST_INTERVAL_UNSET_2", 7, 1, 1440), 7);
    }

    #[test]
    fn parse_interval_env_clamps_below_min() {
        std::env::set_var("DBMASTER_TEST_INTERVAL_LO", "0");
        assert_eq!(parse_interval_env("DBMASTER_TEST_INTERVAL_LO", 30, 1, 1440), 30);
        std::env::remove_var("DBMASTER_TEST_INTERVAL_LO");
    }

    #[test]
    fn parse_interval_env_clamps_above_max() {
        std::env::set_var("DBMASTER_TEST_INTERVAL_HI", "99999");
        assert_eq!(parse_interval_env("DBMASTER_TEST_INTERVAL_HI", 30, 1, 1440), 30);
        std::env::remove_var("DBMASTER_TEST_INTERVAL_HI");
    }

    #[test]
    fn parse_interval_env_accepts_in_range() {
        std::env::set_var("DBMASTER_TEST_INTERVAL_OK", "15");
        assert_eq!(parse_interval_env("DBMASTER_TEST_INTERVAL_OK", 30, 1, 1440), 15);
        std::env::remove_var("DBMASTER_TEST_INTERVAL_OK");
    }

    #[test]
    fn parse_interval_env_rejects_garbage() {
        std::env::set_var("DBMASTER_TEST_INTERVAL_GARBAGE", "soon");
        assert_eq!(parse_interval_env("DBMASTER_TEST_INTERVAL_GARBAGE", 30, 1, 1440), 30);
        std::env::remove_var("DBMASTER_TEST_INTERVAL_GARBAGE");
    }

    #[test]
    fn parse_u64_env_returns_default_when_unset() {
        assert_eq!(parse_u64_env("DBMASTER_TEST_U64_UNSET", 10), 10);
    }

    #[test]
    fn parse_u64_env_accepts_numeric() {
        std::env::set_var("DBMASTER_TEST_U64_OK", "25");
        assert_eq!(parse_u64_env("DBMASTER_TEST_U64_OK", 10), 25);
        std::env::remove_var("DBMASTER_TEST_U64_OK");
    }

    #[test]
    fn parse_u64_env_rejects_garbage() {
        std::env::set_var("DBMASTER_TEST_U64_GARBAGE", "fast");
        assert_eq!(parse_u64_env("DBMASTER_TEST_U64_GARBAGE", 10), 10);
        std::env::remove_var("DBMASTER_TEST_U64_GARBAGE");
    }

    // T07 — MCP allowed-hosts 列表解析（空 = 放行全部）。
    #[test]
    fn parse_list_env_splits_trims_and_drops_empty() {
        std::env::remove_var("DBMASTER_TEST_LIST_UNSET");
        assert!(parse_list_env("DBMASTER_TEST_LIST_UNSET").is_empty());
        std::env::set_var("DBMASTER_TEST_LIST_SET", "localhost, 192.0.2.10:38080 ,,dbmaster.io");
        assert_eq!(
            parse_list_env("DBMASTER_TEST_LIST_SET"),
            vec!["localhost", "192.0.2.10:38080", "dbmaster.io"]
        );
        std::env::remove_var("DBMASTER_TEST_LIST_SET");
        std::env::set_var("DBMASTER_TEST_LIST_BLANK", " , ");
        assert!(parse_list_env("DBMASTER_TEST_LIST_BLANK").is_empty());
        std::env::remove_var("DBMASTER_TEST_LIST_BLANK");
    }

    #[test]
    fn mcp_rate_limit_defaults_and_clamps() {
        // Unset → default 120.
        std::env::remove_var("DBMASTER_TEST_MCP_RL_UNSET");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_MCP_RL_UNSET", 120, 1, 10000),
            120
        );
        // In-range override honoured.
        std::env::set_var("DBMASTER_TEST_MCP_RL_OK", "300");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_MCP_RL_OK", 120, 1, 10000),
            300
        );
        std::env::remove_var("DBMASTER_TEST_MCP_RL_OK");
        // Zero (disabling) and absurd values fall back to default — the limit
        // is a security property and cannot be switched off via a typo.
        std::env::set_var("DBMASTER_TEST_MCP_RL_ZERO", "0");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_MCP_RL_ZERO", 120, 1, 10000),
            120
        );
        std::env::remove_var("DBMASTER_TEST_MCP_RL_ZERO");
    }

    // reports-M1（#29）— 慢查询采样配置族：默认值 / 越界回退 / 在界生效。
    // 阈值是采样门槛（低界 100 防误配把所有查询都记），retention 是增长
    // 硬界（上界 365），二者都不可经 typo 关闭。
    #[test]
    fn slow_query_knobs_default_and_clamp() {
        // 阈值：unset → 1000；低于 100 回退默认；在界生效。
        std::env::remove_var("DBMASTER_TEST_SQ_THRESHOLD_UNSET");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_SQ_THRESHOLD_UNSET", 1000, 100, 600_000),
            1000
        );
        std::env::set_var("DBMASTER_TEST_SQ_THRESHOLD_LO", "50");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_SQ_THRESHOLD_LO", 1000, 100, 600_000),
            1000
        );
        std::env::remove_var("DBMASTER_TEST_SQ_THRESHOLD_LO");
        std::env::set_var("DBMASTER_TEST_SQ_THRESHOLD_OK", "250");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_SQ_THRESHOLD_OK", 1000, 100, 600_000),
            250
        );
        std::env::remove_var("DBMASTER_TEST_SQ_THRESHOLD_OK");
        // retention：超过 365 回退默认 14。
        std::env::set_var("DBMASTER_TEST_SQ_RETENTION_HI", "9999");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_SQ_RETENTION_HI", 14, 1, 365),
            14
        );
        std::env::remove_var("DBMASTER_TEST_SQ_RETENTION_HI");
        // 封顶：0（= 关闭封顶）回退默认 20——封顶是增长防线不可经 typo 关掉。
        std::env::set_var("DBMASTER_TEST_SQ_CAP_ZERO", "0");
        assert_eq!(
            parse_interval_env("DBMASTER_TEST_SQ_CAP_ZERO", 20, 1, 10000),
            20
        );
        std::env::remove_var("DBMASTER_TEST_SQ_CAP_ZERO");
        // 两个 bool 开关默认值：采样默认开、明文默认开。
        std::env::remove_var("DBMASTER_TEST_SQ_ENABLED_UNSET");
        assert!(parse_bool_env("DBMASTER_TEST_SQ_ENABLED_UNSET", true));
        std::env::remove_var("DBMASTER_TEST_SQ_STORE_UNSET");
        assert!(parse_bool_env("DBMASTER_TEST_SQ_STORE_UNSET", true));
    }
}
