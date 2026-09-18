-- 计数器差分源的「区间查询次数」（#29 reports 管道 v2 累积源，2026-08-27）。
--
-- 背景：PS digest 差分行「一行代表一个 digest 的区间增量」——elapsed_ms
-- 存区间总耗时，次数需要一个独立列。row_count 已有语义（网关捕获的
-- 「该查询返回行数」），不可复用——此前误用会把聚合次数算成返回行数。
--
-- 语义：NULL = 1（事件型行：一行一事件，与 COUNT(*) 同义）；计数器差分
-- 行存区间查询次数。聚合读路径按 SUM(COALESCE(query_count, 1)) 计次数。
ALTER TABLE query_stats ADD COLUMN query_count INTEGER;
