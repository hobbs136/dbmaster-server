-- 原生慢查源采集游标（#29 reports 管道 M3，tasks-reports-m3.md）。
--
-- 每个已注册连接 × 每个原生源一行游标（重启不重采）：
-- - Redis SLOWLOG：cursor = 已消费的最大慢日志 id（环形缓冲单调递增）；
-- - MySQL slow_log 表（log_output=TABLE）：cursor = 已消费的最大
--   start_time（源格式 'YYYY-MM-DD HH:MM:SS.ffffff'，原样回存）。
--
-- 采集的样本行直接落 query_stats（migration 016，不改表）：
-- source = 'db_native:redis_slowlog' | 'db_native:mysql_slow_log'，
-- entry = 'native'，elapsed/digest/sql_text 复用 M1 的归一化与生命周期
-- （受统一 retention 清理）。前置条件不满足（如 MySQL slow log 关闭）→
-- 采集器 WARN 跳过，不算错误。
CREATE TABLE IF NOT EXISTS query_stats_native_cursor (
    conn_id    TEXT NOT NULL,
    source     TEXT NOT NULL,
    cursor     TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (conn_id, source)
);
