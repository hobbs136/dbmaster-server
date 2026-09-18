-- 慢查询采样明细（#29 reports 管道 M1，.specs/design-reports-m1.md §5）。
--
-- 承载经 dbmaster-server 执行、耗时超过阈值的查询采样（捕获点 = 8 个已有
-- elapsed 计算处：4 个 SSE 流式入口 + 同步查询 + 事务查询 + admin_script
-- 逐条 + MCP read_query）。M1 'source' 恒为 'gateway'（经 server 的查询），
-- 预留 'db_native:*'（DB 原生慢查源，后续里程碑接入）。
--
-- 口径边界：不含 SQLite（永久直连豁免，不经 server）；不含第三方应用发到
-- 同库的查询（整库画像属 db_native 源范围）。
--
-- 与审计表（mcp_audit/gw_audit，硬规则禁 SQL 文本）的区别：本表是产品域
-- 慢查询日志（对齐 MySQL slow log / pg_stat_statements 的品类），'sql_text'
-- 存明文是功能需要——受 DBMASTER_SLOW_QUERY_STORE_SQL 开关控制（false 时
-- 恒 NULL），且日志与错误路径仍然禁止输出 SQL 明文/凭据；'error_code' 只放
-- 稳定错误码。digest 是归一化文本（字面量→'?'，截断 1000 字符）。
--
-- 增长有界（vault 前科教训）：阈值过滤 + 同 digest 每小时封顶（内存，重启
-- 归零）+ 每小时 retention DELETE 硬兜底；sql_text 截断 8192。
--
-- 'status': 'ok' | 'error' | 'cancelled'。'entry': 'gw_sse' | 'sync_query'
-- | 'txn_query' | 'admin_script' | 'mcp_read'（捕获点审计面）。'user_id' 是
-- JWT subject，stream 路径无 claims 时 NULL。'database' 事务路径可 NULL
-- （session 不保存 db）。
CREATE TABLE IF NOT EXISTS query_stats (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    conn_id       TEXT NOT NULL,
    db_kind       TEXT NOT NULL,
    database      TEXT,
    digest        TEXT NOT NULL,
    sql_text      TEXT,
    elapsed_ms    INTEGER NOT NULL,
    row_count     INTEGER,
    affected_rows INTEGER,
    status        TEXT NOT NULL DEFAULT 'ok',
    error_code    TEXT,
    user_id       TEXT,
    entry         TEXT NOT NULL,
    captured_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_query_stats_time ON query_stats(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_stats_digest ON query_stats(digest, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_stats_conn ON query_stats(conn_id, captured_at DESC);
