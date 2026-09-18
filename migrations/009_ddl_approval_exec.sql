-- M2: DDL 审批「批准即异步执行」——给 ddl_approvals 加执行结果列。
--
-- Background: 当前 approve handler 只改 status 字段（不执行 DDL），见
-- automation/handler.rs:670-686。M2 让 approve 异步执行 ddl_sql 到 target_db，
-- 需要追踪执行状态（pending→executing→approved/failed）+ 错误 + 审批人。
--
-- reviewer_id 列已存在（002_automation.sql:49）但 approve 从未 set；
-- 本次开始使用它。exec_* 是新增列。

ALTER TABLE ddl_approvals ADD COLUMN exec_status TEXT NOT NULL DEFAULT 'pending';
-- exec_status: 'pending'（未执行）| 'executing'（spawn 中）| 'approved'（执行成功）| 'failed'（执行失败）
ALTER TABLE ddl_approvals ADD COLUMN executed_at TEXT;
ALTER TABLE ddl_approvals ADD COLUMN exec_error TEXT;
