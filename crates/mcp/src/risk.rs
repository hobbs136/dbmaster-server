//! SQL 风险分级（dbx-response T05 / 方案 §1.3；对齐 dbx sql_risk 语义）。
//!
//! 四级：ReadOnly < Write < Ddl < Transaction（多语句取最重）。
//!
//! 铁律：
//! - **fail-closed**：解析失败（所有方言都不认）按 **Write** 处理并给原因——
//!   绝不允许「解析不了就放行」（dbx 同款教训）。
//! - 未知语句形态 → Write（白名单式：只有明确认识的读语句才是 ReadOnly）。
//! - `USE` 拦截（防 agent 越权换库）→ Write + 专属原因。
//! - 可执行注释 `/*! ... */` 预扫描（方言无关，藏在任何位置都算）→ Write +
//!   专属原因——注释内容不尝试解析（fail-closed）。
//! - 可写 CTE（`WITH ... AS (DELETE ... RETURNING *)`）→ Write：递归下钻
//!   CTE 体 / 集合表达式 / 嵌套子查询（`SetExpr::Insert/Update/Delete/Merge`）。
//! - `SELECT ... INTO`、锁子句（`FOR UPDATE`/`FOR SHARE`，Query 级）、副作用
//!   函数（nextval/setval/pg_advisory_* /pg_terminate_backend/…）→ Write。
//!
//! 隐私纪律：`reasons` 全部为静态字符串——**不携带任何 SQL 明文**（它们会流进
//! 审计与日志，见 audit.rs）。
//!
//! 消费方：T07 read_query（非 ReadOnly 拒绝）、T19 submit_write（风险摘要）。
//! 方言链：MySQL → PostgreSQL → Generic 依次尝试（任一成功即用；全部失败才
//! fail-closed）。覆盖 MySQL/Doris（MySQL 系）与 PG/ANSI 系的常用语法。
//! sqlparser 0.62：DML/DDL 多为新型变体（`Insert(Insert)` 等），读型多为结构
//! 变体——匹配臂形状以该版 AST 为准。

use sqlparser::ast::{Cte, Expr, Function, Query, SetExpr, Statement};
use sqlparser::dialect::{Dialect, GenericDialect, MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;

/// 语句风险等级。`Ord` 即合并用的严重度序（多语句取 max）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskClass {
    /// 纯读：SELECT（无锁子句/INTO/副作用函数）、SHOW、EXPLAIN（非 ANALYZE）。
    ReadOnly,
    /// 数据变更或等效副作用：INSERT/UPDATE/DELETE/MERGE/REPLACE、SELECT INTO、
    /// 锁读、副作用函数、USE、SET、CALL/EXECUTE、以及一切无法识别的形态。
    Write,
    /// 结构变更：CREATE/ALTER/DROP/TRUNCATE/GRANT/REVOKE。
    Ddl,
    /// 事务控制：BEGIN/START TRANSACTION/COMMIT/ROLLBACK/SAVEPOINT。
    /// agent 不许自行开事务（dbx 同款约束）。
    Transaction,
}

impl RiskClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Write => "write",
            Self::Ddl => "ddl",
            Self::Transaction => "transaction",
        }
    }
}

/// 分级结论：等级 + 人读拒因（静态字符串，无 SQL 明文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskVerdict {
    pub class: RiskClass,
    pub reasons: Vec<&'static str>,
}

impl RiskVerdict {
    fn empty() -> Self {
        Self { class: RiskClass::ReadOnly, reasons: Vec::new() }
    }

    /// T07 便捷判据：是否纯读。
    pub fn is_read_only(&self) -> bool {
        self.class == RiskClass::ReadOnly
    }

    /// 抬升等级（只升不降）并按需记录原因（去重）。
    fn bump(&mut self, class: RiskClass, reason: &'static str) {
        if class > self.class {
            self.class = class;
        }
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}

/// 对整段 SQL 分级（可含多语句，以 `;` 分隔——取最重等级，原因合并）。
pub fn classify(sql: &str) -> RiskVerdict {
    let mut verdict = RiskVerdict::empty();

    // ── 预扫描：可执行注释（方言无关，先于解析）──
    // `/*! ... */` 是 MySQL 版本条件执行注释，内容可能藏任何语句；
    // 不解析其内容，直接 fail-closed。`/*+ ... */`（优化器 hint）不含
    // 可执行语义，不在拦截范围。
    if contains_executable_comment(sql) {
        verdict.bump(RiskClass::Write, "executable comment (/*! */) not allowed");
    }

    // ── 解析：方言链，任一成功即用 ──
    let statements = parse_any(sql);

    let Some(statements) = statements else {
        // fail-closed：解析不了 ≠ 无害。
        let mut v = RiskVerdict::empty();
        v.class = RiskClass::Write;
        v.reasons.push("parse failure (fail-closed: treated as write)");
        return v;
    };

    if statements.is_empty() {
        // 空串/纯注释串：没有可执行语句，但也没有「读」可言——按 Write
        // 拒绝，交由调用方给「空 SQL」文案。
        let mut v = RiskVerdict::empty();
        v.class = RiskClass::Write;
        v.reasons.push("no parseable statement");
        return v;
    }

    for stmt in &statements {
        classify_statement(stmt, &mut verdict);
    }
    verdict
}

/// 方言解析：成功返回语句列表（空表 = 无可执行语句）。
fn parse_with(dialect: &dyn Dialect, sql: &str) -> Option<Vec<Statement>> {
    Parser::new(dialect)
        .try_with_sql(sql)
        .ok()?
        .parse_statements()
        .ok()
}

/// 方言链解析（MySQL → PG → Generic，任一成功即用）。classify 与
/// statement_count 共用同一解析路径，保证计数与分级看到同一组语句。
fn parse_any(sql: &str) -> Option<Vec<Statement>> {
    parse_with(&MySqlDialect {}, sql)
        .or_else(|| parse_with(&PostgreSqlDialect {}, sql))
        .or_else(|| parse_with(&GenericDialect {}, sql))
}

/// 语句条数（`;` 分隔的多语句各算一条）。解析失败返回 0——该路径上
/// classify 已 fail-closed 为 Write，消费方（T07 read_query 的单语句
/// 约束）不会在解析失败时拿到 0。
pub fn statement_count(sql: &str) -> usize {
    parse_any(sql).map_or(0, |stmts| stmts.len())
}

/// `/*!` 出现即视为含可执行注释（无嵌套注释语义，够用且保守）。
fn contains_executable_comment(sql: &str) -> bool {
    sql.contains("/*!")
}

/// 单语句分级。**白名单式**：只有命中已知读形态才保持 ReadOnly；
/// 兜底 `_` 一律 Write（fail-closed）。
fn classify_statement(stmt: &Statement, verdict: &mut RiskVerdict) {
    match stmt {
        // ── 读 ──
        Statement::Query(q) => classify_query(q, verdict),
        // EXPLAIN 不执行；EXPLAIN ANALYZE 会真执行内层语句 → 按内层分级。
        Statement::Explain { analyze, statement, .. } => {
            if *analyze {
                classify_statement(statement, verdict);
            }
        }
        Statement::ShowVariable { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowFunctions { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ExplainTable { .. } => {}

        // ── 事务（最重级）──
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. } => {
            verdict.bump(RiskClass::Transaction, "transaction control statement");
        }

        // ── 写 ──（0.62 新型变体：REPLACE 语法由 Insert 表达）
        Statement::Insert(_)
        | Statement::Update(_)
        | Statement::Delete(_)
        | Statement::Merge(_)
        | Statement::Load { .. } => {
            verdict.bump(RiskClass::Write, "data-modifying statement");
        }
        // 会话/过程面：agent 不许改会话状态，也不许 CALL（过程体不可分析）。
        Statement::Use(_) => {
            verdict.bump(RiskClass::Write, "USE statement forbidden (database switch)");
        }
        Statement::Set(_) => {
            verdict.bump(RiskClass::Write, "SET statement forbidden (session state change)");
        }
        Statement::Call(_) => {
            verdict.bump(RiskClass::Write, "CALL forbidden (procedure body not analyzable)");
        }
        Statement::Execute { .. } | Statement::Prepare { .. } => {
            verdict.bump(RiskClass::Write, "prepared-statement execution forbidden");
        }

        // ── DDL / 权限 ──
        Statement::CreateTable(_)
        | Statement::CreateIndex(_)
        | Statement::CreateView(_)
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateFunction(_)
        | Statement::CreateRole(_)
        | Statement::AlterTable(_)
        | Statement::Drop { .. }
        | Statement::Truncate(_)
        | Statement::Grant(_)
        | Statement::Revoke(_) => {
            verdict.bump(RiskClass::Ddl, "schema/privilege change (DDL)");
        }

        // ── 兜底：不认识 = 潜在风险（fail-closed）──
        _ => {
            verdict.bump(RiskClass::Write, "unrecognized statement form (fail-closed)");
        }
    }
}

/// 查询体分级：CTE → 集合表达式 → SELECT 细节（锁/INTO/副作用函数）。
fn classify_query(query: &Query, verdict: &mut RiskVerdict) {
    // 可写 CTE：`WITH t AS (DELETE ... RETURNING *) SELECT * FROM t`
    // —— CTE 体是独立 Query，必须先下钻（dbx 拆解点名的攻击面）。
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            classify_cte(cte, verdict);
        }
    }

    // 锁读（0.62：锁子句在 Query 级）：FOR UPDATE / FOR SHARE …
    if !query.locks.is_empty() {
        verdict.bump(RiskClass::Write, "locking read (FOR UPDATE/FOR SHARE)");
    }

    match &*query.body {
        SetExpr::Select(select) => classify_select(select, verdict),
        SetExpr::Query(inner) => classify_query(inner, verdict),
        SetExpr::SetOperation { left, right, .. } => {
            classify_set_expr(left, verdict);
            classify_set_expr(right, verdict);
        }
        // 集合运算/CTE 体里藏的数据变更语句（`SetExpr::Statement` 在 0.62
        // 拆成了四个具名变体）。
        SetExpr::Insert(stmt) | SetExpr::Update(stmt) | SetExpr::Delete(stmt) | SetExpr::Merge(stmt) => {
            classify_statement(stmt, verdict);
        }
        // VALUES / TABLE 等：无副作用。
        _ => {}
    }
}

fn classify_cte(cte: &Cte, verdict: &mut RiskVerdict) {
    classify_query(&cte.query, verdict);
}

fn classify_set_expr(expr: &SetExpr, verdict: &mut RiskVerdict) {
    match expr {
        SetExpr::Select(select) => classify_select(select, verdict),
        SetExpr::Query(inner) => classify_query(inner, verdict),
        SetExpr::SetOperation { left, right, .. } => {
            classify_set_expr(left, verdict);
            classify_set_expr(right, verdict);
        }
        SetExpr::Insert(stmt) | SetExpr::Update(stmt) | SetExpr::Delete(stmt) | SetExpr::Merge(stmt) => {
            classify_statement(stmt, verdict);
        }
        _ => {}
    }
}

/// SELECT 细节：SELECT INTO、投影/WHERE/HAVING 里的副作用函数。
/// （锁子句在 [`classify_query`]——Query 级。）
fn classify_select(select: &Select, verdict: &mut RiskVerdict) {
    // SELECT ... INTO（建新对象/写文件方向，因方言而异，一律按写）。
    if select.into.is_some() {
        verdict.bump(RiskClass::Write, "SELECT INTO");
    }

    for item in &select.projection {
        if let sqlparser::ast::SelectItem::UnnamedExpr(expr)
        | sqlparser::ast::SelectItem::ExprWithAlias { expr, .. } = item
        {
            classify_expr(expr, verdict);
        }
    }
    if let Some(expr) = &select.selection {
        classify_expr(expr, verdict);
    }
    if let Some(expr) = &select.having {
        classify_expr(expr, verdict);
    }
}

/// 表达式下钻：找副作用函数与嵌套子查询。
///
/// 覆盖常见形态（函数/二元/一元/嵌套/CAST/CASE/IN/EXISTS/子查询等）；
/// 枚举之外的 Expr 变体不递归——残余风险由语句级 fail-closed 与 T07 的
/// 行限/超时兜底（此处记录为已知取舍）。
fn classify_expr(expr: &Expr, verdict: &mut RiskVerdict) {
    match expr {
        Expr::Function(func) => {
            if is_side_effect_function(func) {
                verdict.bump(RiskClass::Write, "side-effect function in expression");
            }
            // 递归参数：coalesce(nextval('s'), 0) 这类嵌套。
            walk_function_args(func, verdict);
        }
        Expr::Nested(inner) | Expr::UnaryOp { expr: inner, .. } => {
            classify_expr(inner, verdict)
        }
        Expr::BinaryOp { left, right, .. } => {
            classify_expr(left, verdict);
            classify_expr(right, verdict);
        }
        Expr::Cast { expr: inner, .. } => classify_expr(inner, verdict),
        Expr::IsNull(inner) | Expr::IsNotNull(inner) => classify_expr(inner, verdict),
        Expr::InList { expr, list, .. } => {
            classify_expr(expr, verdict);
            for e in list {
                classify_expr(e, verdict);
            }
        }
        Expr::InSubquery { expr, subquery, .. } => {
            classify_expr(expr, verdict);
            classify_query(subquery, verdict);
        }
        Expr::Exists { subquery, .. } => classify_query(subquery, verdict),
        Expr::Subquery(subquery) => classify_query(subquery, verdict),
        Expr::Case { operand, conditions, else_result, .. } => {
            if let Some(op) = operand {
                classify_expr(op, verdict);
            }
            for w in conditions {
                classify_expr(&w.condition, verdict);
                classify_expr(&w.result, verdict);
            }
            if let Some(e) = else_result {
                classify_expr(e, verdict);
            }
        }
        Expr::Between { expr, .. }
        | Expr::Like { expr, .. }
        | Expr::ILike { expr, .. }
        | Expr::SimilarTo { expr, .. } => classify_expr(expr, verdict),
        Expr::InUnnest { expr, array_expr, .. } => {
            classify_expr(expr, verdict);
            classify_expr(array_expr, verdict);
        }
        _ => {}
    }
}

/// 参数递归（FunctionArguments::List 形态下钻；None/Subquery 形态无
/// 嵌套表达式需求——Subquery 形态本身是读）。
fn walk_function_args(func: &Function, verdict: &mut RiskVerdict) {
    use sqlparser::ast::{FunctionArg, FunctionArgExpr, FunctionArguments};
    if let FunctionArguments::List(list) = &func.args {
        for arg in &list.args {
            if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg {
                classify_expr(e, verdict);
            }
        }
    }
}

/// 副作用函数表（dbx 语义对齐 + 明显同族）。小写比较，取最后一段
/// 标识符（schema 前缀忽略——pg_catalog.nextval 也命中）。
fn is_side_effect_function(func: &Function) -> bool {
    const FNS: [&str; 9] = [
        "nextval",
        "setval",
        "pg_advisory_lock",
        "pg_advisory_unlock",
        "pg_advisory_xact_lock",
        "pg_advisory_unlock_all",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
    ];
    let last = func
        .name
        .0
        .last()
        .and_then(|part| match part {
            sqlparser::ast::ObjectNamePart::Identifier(ident) => {
                Some(ident.value.to_lowercase())
            }
            _ => None,
        })
        .unwrap_or_default();
    FNS.contains(&last.as_str())
}

// Select 完整字段引用（避免误import裁剪）。
use sqlparser::ast::Select;

#[cfg(test)]
mod tests {
    use super::*;

    fn class_of(sql: &str) -> RiskClass {
        classify(sql).class
    }

    // ── ReadOnly ──

    #[test]
    fn plain_selects_are_read_only() {
        assert_eq!(class_of("SELECT 1"), RiskClass::ReadOnly);
        assert_eq!(class_of("select * from t where id = 1"), RiskClass::ReadOnly);
        assert_eq!(
            class_of("SELECT a, count(*) FROM t GROUP BY a HAVING count(*) > 1"),
            RiskClass::ReadOnly
        );
        // 读型 CTE
        assert_eq!(
            class_of("WITH cte AS (SELECT 1 AS x) SELECT * FROM cte"),
            RiskClass::ReadOnly
        );
    }

    #[test]
    fn show_and_plain_explain_are_read_only() {
        assert_eq!(class_of("SHOW TABLES"), RiskClass::ReadOnly);
        assert_eq!(class_of("EXPLAIN SELECT * FROM t"), RiskClass::ReadOnly);
        assert_eq!(class_of("DESCRIBE t"), RiskClass::ReadOnly);
    }

    #[test]
    fn subqueries_stay_read_only() {
        assert_eq!(
            class_of("SELECT * FROM a WHERE id IN (SELECT id FROM b)"),
            RiskClass::ReadOnly
        );
        assert_eq!(
            class_of("SELECT EXISTS(SELECT 1 FROM t)"),
            RiskClass::ReadOnly
        );
    }

    // ── Write ──

    #[test]
    fn dml_is_write() {
        assert_eq!(class_of("INSERT INTO t VALUES (1)"), RiskClass::Write);
        assert_eq!(class_of("INSERT INTO a SELECT * FROM b"), RiskClass::Write);
        assert_eq!(class_of("UPDATE t SET a = 1 WHERE id = 2"), RiskClass::Write);
        assert_eq!(class_of("DELETE FROM t"), RiskClass::Write);
        assert_eq!(class_of("REPLACE INTO t VALUES (1)"), RiskClass::Write);
    }

    #[test]
    fn select_into_is_write() {
        assert_eq!(class_of("SELECT * INTO new_t FROM t"), RiskClass::Write);
    }

    #[test]
    fn locking_read_is_write() {
        let v = classify("SELECT * FROM t WHERE id = 1 FOR UPDATE");
        assert_eq!(v.class, RiskClass::Write);
        assert!(v.reasons.iter().any(|r| r.contains("locking read")));
    }

    #[test]
    fn side_effect_functions_are_write() {
        for sql in [
            "SELECT nextval('seq')",
            "SELECT pg_advisory_lock(42)",
            "SELECT pg_terminate_backend(123)",
            "SELECT coalesce(nextval('s'), 0)", // 嵌套参数也要下钻
            "SELECT * FROM t WHERE id = nextval('seq')",
        ] {
            let v = classify(sql);
            assert_eq!(v.class, RiskClass::Write, "sql classified as read: {sql}");
            assert!(
                v.reasons.iter().any(|r| r.contains("side-effect")),
                "missing side-effect reason for: {sql}"
            );
        }
    }

    #[test]
    fn writable_cte_is_write() {
        // dbx 拆解点名的攻击面：WITH 体里的数据变更 + RETURNING。
        let sql = "WITH del AS (DELETE FROM t WHERE ts < now() - interval '7 days' RETURNING *) SELECT count(*) FROM del";
        let v = classify(sql);
        assert_eq!(v.class, RiskClass::Write, "writable CTE must not be read-only");
        assert!(v.reasons.iter().any(|r| r.contains("data-modifying")));
    }

    #[test]
    fn use_statement_is_write_with_reason() {
        let v = classify("USE other_db");
        assert_eq!(v.class, RiskClass::Write);
        assert!(v.reasons.iter().any(|r| r.contains("USE")));
    }

    #[test]
    fn session_set_and_call_are_write() {
        assert_eq!(class_of("SET autocommit = 0"), RiskClass::Write);
        assert_eq!(class_of("CALL do_stuff()"), RiskClass::Write);
    }

    // ── Ddl ──

    #[test]
    fn schema_changes_are_ddl() {
        for sql in [
            "CREATE TABLE t (id INT PRIMARY KEY)",
            "ALTER TABLE t ADD COLUMN c INT",
            "DROP TABLE t",
            "TRUNCATE TABLE t",
            "CREATE INDEX ix ON t (c)",
            "GRANT SELECT ON t TO u",
        ] {
            assert_eq!(class_of(sql), RiskClass::Ddl, "not Ddl: {sql}");
        }
    }

    // ── Transaction ──

    #[test]
    fn transaction_control_is_transaction() {
        for sql in ["BEGIN", "START TRANSACTION", "COMMIT", "ROLLBACK", "SAVEPOINT sp1"] {
            assert_eq!(class_of(sql), RiskClass::Transaction, "not txn: {sql}");
        }
    }

    // ── fail-closed 与拦截 ──

    #[test]
    fn unparseable_sql_fails_closed_as_write() {
        let v = classify("GARBAGE (( NOT SQL @@@");
        assert_eq!(v.class, RiskClass::Write);
        assert!(v.reasons.iter().any(|r| r.contains("fail-closed")));
    }

    #[test]
    fn empty_sql_fails_closed() {
        let v = classify("");
        let v2 = classify("   ");
        assert_eq!(v.class, RiskClass::Write);
        assert_eq!(v2.class, RiskClass::Write);
    }

    #[test]
    fn executable_comment_is_blocked_wherever_it_hides() {
        // 单独出现
        let v = classify("/*! INSERT INTO t VALUES (1) */");
        assert_eq!(v.class, RiskClass::Write);
        assert!(v.reasons.iter().any(|r| r.contains("executable comment")));
        // 藏在读语句后
        let v = classify("SELECT 1; /*! USE other_db */");
        assert_eq!(v.class, RiskClass::Write);
        assert!(v.reasons.iter().any(|r| r.contains("executable comment")));
    }

    #[test]
    fn optimizer_hint_comment_is_not_blocked() {
        // /*+ ... */ 是优化器提示，不含可执行语义。
        assert_eq!(class_of("SELECT /*+ INDEX(t idx) */ * FROM t"), RiskClass::ReadOnly);
    }

    // ── 多语句合并 ──

    #[test]
    fn multi_statement_takes_max_severity() {
        assert_eq!(class_of("SELECT 1; SELECT 2"), RiskClass::ReadOnly);
        assert_eq!(class_of("SELECT 1; INSERT INTO t VALUES (1)"), RiskClass::Write);
        assert_eq!(class_of("INSERT INTO t VALUES (1); COMMIT"), RiskClass::Transaction);
        assert_eq!(class_of("SELECT 1; DROP TABLE t"), RiskClass::Ddl);
    }

    // T07 — read_query 的单语句约束依赖计数与分级看到同一组语句。
    #[test]
    fn statement_count_matches_parsed_statements() {
        assert_eq!(statement_count("SELECT 1"), 1);
        assert_eq!(statement_count("SELECT 1; SELECT 2"), 2);
        assert_eq!(statement_count("SELECT 1;"), 1, "尾分号不产生空语句");
        // 解析失败 → 0（classify 同输入已 fail-closed 为 Write，消费方
        // 不会在 0 上做单语句判定）。
        assert_eq!(statement_count("TOTALLY NOT SQL @@@"), 0);
    }

    #[test]
    fn explain_analyze_executes_inner_statement() {
        // EXPLAIN ANALYZE 会真执行内层语句。
        assert_eq!(
            class_of("EXPLAIN ANALYZE UPDATE t SET a = 1"),
            RiskClass::Write
        );
        // 普通 EXPLAIN 只出计划。
        assert_eq!(class_of("EXPLAIN UPDATE t SET a = 1"), RiskClass::ReadOnly);
    }

    #[test]
    fn reasons_never_contain_sql_text() {
        // 隐私纪律：reasons 是静态字符串集，抽查几条不泄露输入。
        let secret = "s3cret_table";
        let v = classify(&format!("SELECT * FROM {secret} WHERE x FOR UPDATE"));
        for r in &v.reasons {
            assert!(!r.contains(secret), "reason leaked SQL text: {r}");
        }
    }
}
