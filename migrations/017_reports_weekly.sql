-- reports 管道 M2（#29）：reports 表从死表预埋转为周报载体。
--
-- 背景（migration 002 预埋后零 writer 零消费者）：task_id NOT NULL
-- FK→scheduled_tasks 把 reports 绑死在「用户任务的报告」上，而慢查询周报
-- 是系统级聚合产物（不隶属任何 scheduled task）。SQLite 无法 ALTER 列
-- 约束 → 建新表 + 拷贝 + 重命名（存量行数预期为 0，拷贝保留以防万一）。
--
-- 变更：
-- - task_id 放宽为 nullable（保留 FK 语义：未来任务附属报告仍可关联）；
-- - 新增 (report_type, generated_at DESC) 索引支撑报告中心按类型过滤；
-- - 旧 idx_reports_task 重建保留（兼容潜在按任务查询）。
--
-- content 契约：JSON 本体携带 content_version（首个 'slow_query_weekly' =
-- version 1，形状见 .specs/tasks-reports-m2.md），结构演进靠版本标记而非
-- 加列。reports 不设 retention——周报一周一行，年 52 行，体量可忽略。
CREATE TABLE IF NOT EXISTS reports_new (
    id           TEXT PRIMARY KEY,
    task_id      TEXT REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    report_type  TEXT NOT NULL,
    title        TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '{}',
    generated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO reports_new (id, task_id, report_type, title, content, generated_at)
SELECT id, task_id, report_type, title, content, generated_at FROM reports;

DROP TABLE reports;

ALTER TABLE reports_new RENAME TO reports;

CREATE INDEX IF NOT EXISTS idx_reports_type_time ON reports(report_type, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_task ON reports(task_id, generated_at DESC);
