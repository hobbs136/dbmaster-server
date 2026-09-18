//! MySQL 协议族薄适配层（dbx-response M7 T21 / ADR-0005 §2.3）。
//!
//! 照竞品 DBX 的 `tidb.rs` 子类模式：MySQL 协议族的新成员不再各写一个
//! 完整 backend，而是复用 MySQL 通道，只覆写「与原生 MySQL 的差异」钩子。
//! Doris 是首个迁入的子类（原有 workaround 全部收敛至此）；T22-T25 的
//! OceanBase / TiDB / StarRocks / MariaDB 已按同模板接入（差异面见各
//! profile struct 的实机探测文档）。
//!
//! **钩子面**（默认实现 = 原生 MySQL 行为，零变化；成员按需覆写）：
//! - [`MysqlFamilyHooks::handshake`]——连接握手参数（sql_mode 相关
//!   capability 位；Doris 关 PIPES_AS_CONCAT / NO_ENGINE_SUBSTITUTION）；
//! - [`MysqlFamilyHooks::session_statements`]——会话初始化 SET 语句集
//!   （charset 的 SET NAMES / timezone 的 SET time_zone；Doris 不支持后者）；
//! - [`MysqlFamilyHooks::catalog_mode`]——目录/查询执行的协议模式
//!   （prepare 绑定参数 vs raw_sql 文本协议 + 转义字面量内联）；
//! - [`MysqlFamilyHooks::schema_condition`] / [`MysqlFamilyHooks::table_condition`]
//!   ——information_schema 目录查询的过滤条件片段（随 catalog_mode 派生）；
//! - [`MysqlFamilyHooks::row_estimate_expr`]——list_tables 行数估计来源；
//! - [`MysqlFamilyHooks::system_databases`]——目录噪音系统库过滤清单；
//! - [`MysqlFamilyHooks::supports_transactions`] /
//!   [`MysqlFamilyHooks::supports_kill_query`]——能力位。
//!
//! **注册表**：[`mysql_family_for`] 是 db_type 字符串 → 薄适配的唯一映射
//! 点；`db_handler::backend_for` / `metadata::family_for` / `stream_query`
//! / `txn` 的 MySQL 族分发全部经它，新成员一处注册全家生效。族外但走
//! MySQL wire 的库（ClickHouse 9004 兼容口）不经注册表——回落
//! [`mysql_profile_for`] 的默认 profile，行为与既有完全一致。

use sqlx::mysql::MySqlConnectOptions;

/// 目录/查询执行的协议模式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CatalogQueryMode {
    /// sqlx 预备协议（`sqlx::query` + `?` 绑定参数）——原生 MySQL 默认，
    /// 注入面默认收紧。
    Prepare,
    /// COM_QUERY 文本协议（`sqlx::raw_sql` + 转义字面量内联）——Doris 的
    /// MySQL 口对 PREPARE 有两处不合规（information_schema 报
    /// UnsupportedCommand、prepare-ok 包短 2 字节，T06 实机三坑）。
    RawSql,
}

/// MySQL 协议族薄适配钩子。默认实现 = 原生 MySQL 行为；子类只覆写差异项
/// （模板见 [`DORIS_PROFILE`] 的 `DorisProfile`）。
pub(crate) trait MysqlFamilyHooks: Send + Sync {
    /// profile 逻辑名（= db_type 规范名；注册键与诊断标识）。
    fn name(&self) -> &'static str;

    /// 连接握手参数 hook：默认原样返回。子类覆写以调整 sql_mode 相关
    /// capability 位等——sqlx 默认握手会发
    /// `SET sql_mode=(SELECT CONCAT(@@sql_mode, 'PIPES_AS_CONCAT,
    /// NO_ENGINE_SUBSTITUTION'))`，不兼容该非恒表达式的引擎需关掉对应位。
    fn handshake(&self, opts: MySqlConnectOptions) -> MySqlConnectOptions {
        opts
    }

    /// 会话初始化语句集（charset / timezone）。默认：SET NAMES（charset
    /// 非空时）+ SET time_zone（timezone 非空时）；执行失败由调用方按
    /// non-fatal 记日志（坏 charset 不应阻断连接）。
    fn session_statements(&self, charset: Option<&str>, timezone: Option<&str>) -> Vec<String> {
        let mut stmts = Vec::new();
        if let Some(cs) = charset.filter(|s| !s.is_empty()) {
            stmts.push(format!("SET NAMES '{}'", cs.replace('\'', "\\'")));
        }
        if let Some(tz) = timezone.filter(|s| !s.is_empty()) {
            stmts.push(format!("SET time_zone = '{}'", tz.replace('\'', "\\'")));
        }
        stmts
    }

    /// 目录/查询执行的协议模式（决定条件片段形状与执行通道）。
    fn catalog_mode(&self) -> CatalogQueryMode {
        CatalogQueryMode::Prepare
    }

    /// information_schema 目录查询的库名过滤条件片段。Prepare 模式用
    /// `DATABASE()`（连接握手已定位库）；RawSql 模式内联转义字面量。
    fn schema_condition(&self, db: &str) -> String {
        match self.catalog_mode() {
            CatalogQueryMode::Prepare => "table_schema = DATABASE()".to_string(),
            CatalogQueryMode::RawSql => {
                format!("table_schema = {}", mysql_str_literal(db))
            }
        }
    }

    /// 目录查询的表名过滤条件片段。Prepare 模式返回 `?` 占位（调用方经
    /// 绑定参数传值）；RawSql 模式内联转义字面量。
    fn table_condition(&self, table: &str) -> String {
        match self.catalog_mode() {
            CatalogQueryMode::Prepare => "table_name = ?".to_string(),
            CatalogQueryMode::RawSql => {
                format!("table_name = {}", mysql_str_literal(table))
            }
        }
    }

    /// list_tables 的行数估计表达式（information_schema.tables 的估计列）。
    /// 视图为 NULL；InnoDB 表值为估计值——统计来源不同的引擎可覆写。
    fn row_estimate_expr(&self) -> &'static str {
        "table_rows"
    }

    /// 目录噪音系统库清单（list_databases 过滤）。只滤纯协议噪音库，
    /// `sys`/`mysql` 保留（可查，给 ops agent）。
    fn system_databases(&self) -> &'static [&'static str] {
        &["information_schema", "performance_schema"]
    }

    /// 能力位：是否支持事务（txn 端点族的前提；Doris 支持，与既有口径一致）。
    fn supports_transactions(&self) -> bool {
        true
    }

    /// 能力位：是否支持 KILL QUERY（admin/kill 端点的适用面）。
    fn supports_kill_query(&self) -> bool {
        true
    }
}

// ── 族成员 profile（每个成员一个小 struct + 一行注册）──

/// 原生 MySQL——族默认（所有钩子零覆写）。
struct MysqlProfile;

impl MysqlFamilyHooks for MysqlProfile {
    fn name(&self) -> &'static str {
        "mysql"
    }
}

/// Doris（MySQL 协议兼容口，默认 9030）——首个薄适配子类（T21 迁入）。
///
/// 覆写项（实机 192.168.x.x Doris 3.0.2 验证）：
/// - 握手：关 PIPES_AS_CONCAT / NO_ENGINE_SUBSTITUTION，让 sqlx 不再发出
///   含非恒表达式的 sql_mode SET（errCode 2 "Set statement does't support
///   non-constant expr"）；
/// - 会话：不支持 `SET time_zone`——只保留 SET NAMES（常量表达式，支持）；
/// - 目录/查询执行：PREPARE 两处不合规——统一 raw_sql 文本协议 +
///   转义字面量内联（原 metadata.rs / stream_query.rs 的 doris 分支）。
///
/// 其余（系统库过滤/行数估计/事务/KILL）用族默认，与既有 Doris 行为一致。
struct DorisProfile;

impl MysqlFamilyHooks for DorisProfile {
    fn name(&self) -> &'static str {
        "doris"
    }

    fn handshake(&self, opts: MySqlConnectOptions) -> MySqlConnectOptions {
        opts.pipes_as_concat(false).no_engine_substitution(false)
    }

    fn session_statements(&self, charset: Option<&str>, _timezone: Option<&str>) -> Vec<String> {
        // Doris 不支持 SET time_zone——跳过；SET NAMES 保留。
        let mut stmts = Vec::new();
        if let Some(cs) = charset.filter(|s| !s.is_empty()) {
            stmts.push(format!("SET NAMES '{}'", cs.replace('\'', "\\'")));
        }
        stmts
    }

    fn catalog_mode(&self) -> CatalogQueryMode {
        CatalogQueryMode::RawSql
    }
}

// ── T22-T25 四个族成员（2026-08-21 实机 192.168.x.x 探测定差异面）──

/// OceanBase CE 4.4（sys 租户 MySQL 模式，默认 2881）——T22。
///
/// 实机探测：sqlx 默认握手（sql_mode 非恒 SET）/ SET time_zone /
/// information_schema 全 PREPARE / 事务 / KILL QUERY / SLEEP 全部与原生
/// MySQL 一致——唯一差异是目录噪音系统库形态（`oceanbase`/`SYS`/`LBACSYS`/
/// `ORAAUDITOR`/`ocs`/`sys_external_tbs` 均为内部库）。table_rows 为 NULL
/// （无估计值，metadata 已容忍）。只覆写 system_databases。
struct OceanbaseProfile;

impl MysqlFamilyHooks for OceanbaseProfile {
    fn name(&self) -> &'static str {
        "oceanbase"
    }

    /// OB 内部库（sys 租户 MINI 部署的实测清单）；`mysql`/`test` 照族默认
    /// 保留（可查，给 ops agent）。
    fn system_databases(&self) -> &'static [&'static str] {
        &[
            "information_schema",
            "performance_schema",
            "oceanbase",
            "SYS",
            "LBACSYS",
            "ORAAUDITOR",
            "ocs",
            "sys_external_tbs",
        ]
    }
}

/// TiDB 8.5（默认 4000）——T23。
///
/// 实机探测：默认握手 / SET time_zone / PREPARE 全家 / 事务（真事务）/
/// KILL QUERY / SLEEP 与原生一致；table_rows 有估计值（0 起）。差异两点：
/// ①系统库以**大写**形态出现（`INFORMATION_SCHEMA`/`PERFORMANCE_SCHEMA`，
/// 族默认小写清单精确匹配滤不掉）+ 独有 `METRICS_SCHEMA`；②root 常无密码
/// ——空密码握手处理见 `db_handler::mysql_connect_options` 的统一修正。
/// 只覆写 system_databases。
struct TidbProfile;

impl MysqlFamilyHooks for TidbProfile {
    fn name(&self) -> &'static str {
        "tidb"
    }

    /// TiDB 大写系统库 + 独有 METRICS_SCHEMA（小写两项照留，幂等无害）；
    /// `mysql`/`sys`/`test` 保留。
    fn system_databases(&self) -> &'static [&'static str] {
        &[
            "information_schema",
            "performance_schema",
            "INFORMATION_SCHEMA",
            "PERFORMANCE_SCHEMA",
            "METRICS_SCHEMA",
        ]
    }
}

/// StarRocks 3.5（FE MySQL 口，默认 9030）——T24。
///
/// 实机探测差异面（与 Doris 高度同源 + 事务阉割）：
/// - 握手：拒非恒表达式 SET（sql_mode 的 SELECT CONCAT 形态）——关
///   PIPES_AS_CONCAT / NO_ENGINE_SUBSTITUTION，与 Doris 同款；
/// - PREPARE 协议**只支持 SELECT**（SHOW/SET/DDL/DML 全报 1295 "not
///   supported in the prepared statement protocol"）——统一 RawSql 文本
///   协议；SET NAMES / SET time_zone 常量表达式在文本协议下均支持，
///   会话语句集不覆写；
/// - 事务：接受 START TRANSACTION 语法，但显式事务内只允许 begin/
///   commit/rollback/insert/update/delete（连 SELECT / DDL 都拒，实机
///   5305 "Explicit transaction only support ..."）——DBA 会话（浏览 +
///   查询 + DDL）不可用，`supports_transactions` 关闭（txn 端点族拒绝，
///   备注登记：窄面「纯 DML 事务」理论可行但无工具价值）；
/// - KILL QUERY / SHOW PROCESSLIST（文本协议）/ SLEEP 可用；
/// - 系统库噪音：`information_schema` / `sys`（引擎内部库，非 MySQL 的
///   sys 视图集）/ `_statistics_`。
struct StarrocksProfile;

impl MysqlFamilyHooks for StarrocksProfile {
    fn name(&self) -> &'static str {
        "starrocks"
    }

    fn handshake(&self, opts: MySqlConnectOptions) -> MySqlConnectOptions {
        opts.pipes_as_concat(false).no_engine_substitution(false)
    }

    fn catalog_mode(&self) -> CatalogQueryMode {
        CatalogQueryMode::RawSql
    }

    fn system_databases(&self) -> &'static [&'static str] {
        // StarRocks 的 `sys` 是引擎内部库（与 MySQL 的 sys 运维视图集无关），
        // 对用户纯噪音——与族默认「保留 sys」口径刻意不同。
        &["information_schema", "performance_schema", "sys", "_statistics_"]
    }

    fn supports_transactions(&self) -> bool {
        false
    }
}

/// MariaDB 11.8（默认 3306）——T25。
///
/// 实机探测：默认握手 / SET time_zone / PREPARE / 事务 / KILL / SLEEP /
/// DML / information_schema 全部与原生 MySQL 一致，系统库形态同 MySQL
/// （information_schema/mysql/performance_schema/sys）——**零覆写成员**
/// （注册即可用，同 `MysqlProfile` 的空 impl，仅 name 不同）。
struct MariadbProfile;

impl MysqlFamilyHooks for MariadbProfile {
    fn name(&self) -> &'static str {
        "mariadb"
    }
}

static MYSQL_PROFILE: MysqlProfile = MysqlProfile;
static DORIS_PROFILE: DorisProfile = DorisProfile;
static OCEANBASE_PROFILE: OceanbaseProfile = OceanbaseProfile;
static TIDB_PROFILE: TidbProfile = TidbProfile;
static STARROCKS_PROFILE: StarrocksProfile = StarrocksProfile;
static MARIADB_PROFILE: MariadbProfile = MariadbProfile;

/// db_type → 薄适配 profile 注册表。
///
/// 新库接入步骤（每库 ≤1 个小文件改动 + 一行注册）：
/// 1. 本文件（或独立的 `mysql_family/<name>.rs`）加一个 profile struct +
///    `impl MysqlFamilyHooks`，只覆写与 MySQL 的差异项（照 `DorisProfile`
///    模板；无差异的项一律不覆写——MariaDB 即零覆写成员）；
/// 2. 此 match 加一行 `"oceanbase" => Some(&OCEANBASE_PROFILE),`；
/// 3. 网关 wire 白名单 `gateway/src/handlers.rs` 的 `SUPPORTED_DB_TYPES`
///    加对应 dbType 值（客户端 UI 元数据另见 task_dbx_response T22 条目）。
///
/// 注册后 `db_handler::backend_for` / `metadata::family_for` /
/// `stream_query` / `txn` 的 MySQL 族分发即自动生效。未注册的 db_type
/// 返回 None（各面维持 UNSUPPORTED_DB_TYPE）。
pub(crate) fn mysql_family_for(db_type: &str) -> Option<&'static dyn MysqlFamilyHooks> {
    match db_type.to_ascii_lowercase().as_str() {
        "mysql" => Some(&MYSQL_PROFILE),
        "doris" => Some(&DORIS_PROFILE),
        // T22-T25 四成员（差异面见各自 struct 文档）。
        "oceanbase" => Some(&OCEANBASE_PROFILE),
        "tidb" => Some(&TIDB_PROFILE),
        "starrocks" => Some(&STARROCKS_PROFILE),
        "mariadb" => Some(&MARIADB_PROFILE),
        _ => None,
    }
}

/// db_type → profile，非族成员回落族默认（ClickHouse 的 9004 兼容口等
/// 复用 MySQL 通道但不在注册表内的调用方——行为与既有完全一致）。
pub(crate) fn mysql_profile_for(db_type: &str) -> &'static dyn MysqlFamilyHooks {
    mysql_family_for(db_type).unwrap_or(&MYSQL_PROFILE)
}

// ── 执行辅助（prepare / raw_sql 双模式统一入口，调用方不再散落 if doris）──

/// 按模式执行取全行。Prepare 模式绑定 `bind`（表名参数，SQL 含 `?` 占位
/// 时传入）；RawSql 模式文本直发（条件已内联转义，bind 忽略）。
pub(crate) async fn fetch_all_by_mode(
    pool: &sqlx::Pool<sqlx::MySql>,
    mode: CatalogQueryMode,
    sql: &str,
    bind: Option<&str>,
) -> Result<Vec<sqlx::mysql::MySqlRow>, sqlx::Error> {
    match (mode, bind) {
        (CatalogQueryMode::RawSql, _) => sqlx::raw_sql(sql).fetch_all(pool).await,
        (CatalogQueryMode::Prepare, Some(t)) => sqlx::query(sql).bind(t).fetch_all(pool).await,
        (CatalogQueryMode::Prepare, None) => sqlx::query(sql).fetch_all(pool).await,
    }
}

/// 按模式执行无结果集语句（事务控制 / 会话 SET 等），返回受影响行数。
///
/// T29 — Prepare 模式遇 MySQL 1295（"not supported in the prepared
/// statement protocol"，如 CREATE TRIGGER/PROCEDURE/FUNCTION/EVENT 等
/// 带体模块语句）自动回退 raw_sql 文本协议重试一次：该错误发生在
/// prepare 阶段、语句未执行，重试幂等安全。
pub(crate) async fn execute_by_mode(
    pool: &sqlx::Pool<sqlx::MySql>,
    mode: CatalogQueryMode,
    sql: &str,
) -> Result<u64, sqlx::Error> {
    match mode {
        CatalogQueryMode::RawSql => sqlx::raw_sql(sql).execute(pool).await.map(|r| r.rows_affected()),
        CatalogQueryMode::Prepare => {
            match sqlx::query(sql).execute(pool).await {
                Ok(r) => Ok(r.rows_affected()),
                Err(e) if is_mysql_1295(&e) => {
                    sqlx::raw_sql(sql).execute(pool).await.map(|r| r.rows_affected())
                }
                Err(e) => Err(e),
            }
        }
    }
}

/// MySQL 引擎错误 1295（ER_UNSUPPORTED_PS）判定——prepare 协议不支持的语句。
/// 注意：sqlx `DatabaseError::code()` 对 MySQL 返回 SQLSTATE（如 HY000），
/// 引擎错误号须 downcast 到 `MySqlDatabaseError::number()`。
fn is_mysql_1295(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db) => db
            .downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
            .number()
            == 1295,
        _ => false,
    }
}

/// MySQL 方言字符串字面量（RawSql 模式的内联转义用）。双转义 backslash +
/// 单引号加倍——字符串内不可能提前闭合，无注入面。
pub(crate) fn mysql_str_literal(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_family_members() {
        assert_eq!(mysql_family_for("mysql").unwrap().name(), "mysql");
        assert_eq!(mysql_family_for("Doris").unwrap().name(), "doris");
        // T22-T25 四成员（大小写不敏感注册）。
        assert_eq!(mysql_family_for("oceanbase").unwrap().name(), "oceanbase");
        assert_eq!(mysql_family_for("OceanBase").unwrap().name(), "oceanbase");
        assert_eq!(mysql_family_for("tidb").unwrap().name(), "tidb");
        assert_eq!(mysql_family_for("starrocks").unwrap().name(), "starrocks");
        assert_eq!(mysql_family_for("mariadb").unwrap().name(), "mariadb");
        // 族外：ClickHouse 走独立 Family；Oracle 走客户端路径。
        assert!(mysql_family_for("clickhouse").is_none());
        assert!(mysql_family_for("oracle").is_none());
        assert!(mysql_family_for("postgres").is_none());
        // 非族成员回落族默认（ClickHouse 兼容口等复用 MySQL 通道的场景）。
        assert_eq!(mysql_profile_for("clickhouse").name(), "mysql");
    }

    #[test]
    fn doris_profile_overrides_raw_mode_and_skips_timezone() {
        let d = mysql_family_for("doris").unwrap();
        assert_eq!(d.catalog_mode(), CatalogQueryMode::RawSql);
        // Doris 会话：只 SET NAMES，跳过 SET time_zone。
        let stmts = d.session_statements(Some("utf8mb4"), Some("Asia/Shanghai"));
        assert_eq!(stmts, vec!["SET NAMES 'utf8mb4'".to_string()]);

        // 族默认（原生 MySQL）：charset + timezone 双 SET；空值跳过。
        let m = mysql_profile_for("mysql");
        assert_eq!(m.catalog_mode(), CatalogQueryMode::Prepare);
        let stmts = m.session_statements(Some("utf8mb4"), Some("Asia/Shanghai"));
        assert_eq!(
            stmts,
            vec![
                "SET NAMES 'utf8mb4'".to_string(),
                "SET time_zone = 'Asia/Shanghai'".to_string(),
            ]
        );
        assert!(m.session_statements(None, Some("")).is_empty());
    }

    #[test]
    fn condition_fragments_follow_catalog_mode() {
        // Prepare：DATABASE() 定位 + `?` 占位（调用方绑定）。
        let m = mysql_profile_for("mysql");
        assert_eq!(m.schema_condition("db1"), "table_schema = DATABASE()");
        assert_eq!(m.table_condition("t1"), "table_name = ?");
        // RawSql：内联转义字面量（Doris 不吃 PREPARE）。
        let d = mysql_profile_for("doris");
        assert_eq!(d.schema_condition("db1"), "table_schema = 'db1'");
        assert_eq!(d.table_condition("t1"), "table_name = 't1'");
        // 注入面：引号 / 反斜杠转义后不可能提前闭合。
        assert_eq!(d.table_condition("o'brien"), "table_name = 'o''brien'");
        assert_eq!(d.schema_condition("a\\b"), "table_schema = 'a\\\\b'");
    }

    #[test]
    fn default_system_databases_and_row_estimate_match_legacy() {
        // 只滤纯协议噪音库；sys/mysql 保留给 ops agent（原 metadata 口径）。
        let m = mysql_profile_for("mysql");
        assert!(m.system_databases().contains(&"information_schema"));
        assert!(m.system_databases().contains(&"performance_schema"));
        assert!(!m.system_databases().contains(&"mysql"));
        assert!(!m.system_databases().contains(&"sys"));
        assert_eq!(m.row_estimate_expr(), "table_rows");
        // Doris 沿用族默认。
        let d = mysql_family_for("doris").unwrap();
        assert_eq!(d.system_databases(), m.system_databases());
        assert_eq!(d.row_estimate_expr(), "table_rows");
    }

    #[test]
    fn capability_bits_match_current_surface() {
        // Doris：事务 / KILL 均支持（txn.rs 与 admin_kill 的既有口径）。
        assert!(mysql_family_for("doris").unwrap().supports_transactions());
        assert!(mysql_family_for("doris").unwrap().supports_kill_query());
        assert!(mysql_profile_for("mysql").supports_transactions());
        assert!(mysql_profile_for("mysql").supports_kill_query());
        // T22-T25：OB / TiDB / MariaDB 全能力；StarRocks 事务关闭（显式
        // 事务内连 SELECT 都拒——实机 5305，txn 端点族不可用），KILL 保留。
        assert!(mysql_family_for("oceanbase").unwrap().supports_transactions());
        assert!(mysql_family_for("oceanbase").unwrap().supports_kill_query());
        assert!(mysql_family_for("tidb").unwrap().supports_transactions());
        assert!(mysql_family_for("tidb").unwrap().supports_kill_query());
        assert!(!mysql_family_for("starrocks").unwrap().supports_transactions());
        assert!(mysql_family_for("starrocks").unwrap().supports_kill_query());
        assert!(mysql_family_for("mariadb").unwrap().supports_transactions());
        assert!(mysql_family_for("mariadb").unwrap().supports_kill_query());
    }

    #[test]
    fn t22_t25_profiles_override_only_probed_differences() {
        // OceanBase：只覆写系统库清单（其余全默认——实机与原生一致）。
        let ob = mysql_family_for("oceanbase").unwrap();
        assert!(ob.system_databases().contains(&"oceanbase"));
        assert!(ob.system_databases().contains(&"SYS"));
        assert!(ob.system_databases().contains(&"LBACSYS"));
        assert!(ob.system_databases().contains(&"ORAAUDITOR"));
        assert!(!ob.system_databases().contains(&"mysql")); // mysql/test 照保留
        assert_eq!(ob.catalog_mode(), CatalogQueryMode::Prepare);

        // TiDB：大写系统库 + METRICS_SCHEMA；其余默认。
        let tidb = mysql_family_for("tidb").unwrap();
        assert!(tidb.system_databases().contains(&"INFORMATION_SCHEMA"));
        assert!(tidb.system_databases().contains(&"METRICS_SCHEMA"));
        assert!(!tidb.system_databases().contains(&"mysql"));
        assert_eq!(tidb.catalog_mode(), CatalogQueryMode::Prepare);

        // StarRocks：Doris 同款握手 + RawSql；系统库滤 sys/_statistics_。
        let sr = mysql_family_for("starrocks").unwrap();
        assert_eq!(sr.catalog_mode(), CatalogQueryMode::RawSql);
        assert!(sr.system_databases().contains(&"sys"));
        assert!(sr.system_databases().contains(&"_statistics_"));
        assert_eq!(sr.system_databases().len(), 4);
        // 会话语句集不覆写：SET NAMES / SET time_zone 文本协议下均支持
        // （与 Doris 跳过 time_zone 的取舍不同——实机验证）。
        let stmts = sr.session_statements(Some("utf8mb4"), Some("+00:00"));
        assert_eq!(stmts.len(), 2);

        // MariaDB：零覆写成员——全部钩子等于族默认。
        let md = mysql_family_for("mariadb").unwrap();
        let m = mysql_profile_for("mysql");
        assert_eq!(md.catalog_mode(), m.catalog_mode());
        assert_eq!(md.system_databases(), m.system_databases());
        assert_eq!(md.row_estimate_expr(), m.row_estimate_expr());
        assert_eq!(md.session_statements(Some("utf8mb4"), Some("UTC")), m.session_statements(Some("utf8mb4"), Some("UTC")));
    }
}
