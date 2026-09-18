# Requirements: health check 引擎

Date: 2026-08-12
Source: brainstorm.md（+ 用户拍板的 2 个产品决策 + Explore agent 调研）

## 1. 背景

dbmaster-server 已有 schema drift（`crates/drift`）和 data sync（`crates/data_sync`）两个周期性自动化引擎，其「collector + scheduler + runner + notify + audit」范式已成熟。README 把 **Scheduled Health Checks** 列为 M3 roadmap（🔲 Not started，零代码、零 schema）。

本功能新增 `crates/health_check` crate，定期巡检已登记的数据库连接健康状态（连通性 + 关键指标），发现异常时通过 webhook 告警。与 drift 的「schema 变化」正交——drift 关心结构变化，health check 关心**运行时健康**（连不连得上、表胀没胀、缺不缺主键）。

**关键差异**：drift 的告警模型是「状态变化触发」（hash 变就发），简单。health check 需要**阈值 + 连续 N 次防 flapping + 恢复 Resolved 通知**——这是 drift 没有的新工作面，因为运行时健康指标天然会抖动（网络抖一下不能告警风暴）。

## 2. 目标用户

- **DBA / 运维**（Server 订阅用户，¥399/年/实例）：管理多个数据库实例，需要 always-on 监控，出问题第一时间收到 webhook（Slack/钉钉/企业微信 receiver）
- **团队管理者**：通过 webhook 集成到现有运维告警系统

## 3. 功能需求

### R1: 周期巡检调度（cron 驱动）
- **描述**：用户创建 `task_type = 'health_check'` 的定时任务，按 cron 表达式周期性巡检指定数据库连接的健康指标。scheduler 扫描启用的任务，到期就派发给 runner 执行
- **验收标准**：
  - [ ] 用户可创建 health_check task，配置：源连接（source_db_id）、cron 表达式、指标开关、阈值、webhook URL
  - [ ] 默认 cron = `*/10 * * * *`（每 10 分钟），per-task 可配
  - [ ] scheduler 按 cron 判断 due（参考 data_sync 的 cron 调度），到期任务派发 runner
  - [ ] 同一 task 不重叠执行（InFlightTasks 模式，同 drift scheduler）
  - [ ] gated 实例（trial 过期 / 无 license）scheduler 不启动（entitlement gate，同 drift/data_sync）

### R2: 指标采集（核心 4 项，MySQL + PostgreSQL）
- **描述**：runner 对源连接采集 4 项健康指标。初版支持 MySQL + PostgreSQL，其他库类型降级为仅连通性
- **验收标准**：
  - [ ] **连通性 + 延迟**：执行 `SELECT 1`（或等价），记录成功/失败 + 耗时（毫秒）。所有库类型都做
  - [ ] **表行数估算**：MySQL 查 `information_schema.tables.table_rows`（按表聚合）；PG 查 `pg_class.reltuples`。记录 TOP N（默认 10）最大表。仅 MySQL/PG
  - [ ] **缺失主键检测**：查 `information_schema.table_constraints` 找无 PK 的基表（非系统库）。记录缺失 PK 的表名列表。仅 MySQL/PG
  - [ ] **连接数**：MySQL `SHOW STATUS LIKE 'Threads_connected'`；PG `SELECT count(*) FROM pg_stat_activity`。仅 MySQL/PG
  - [ ] 非 MySQL/PG 连接：仅做连通性，其余 3 项跳过（结果标记 `unsupported_db_type`）
  - [ ] 指标采集全用 SELECT，不写源库（只读巡检）
  - [ ] 单项指标采集失败（如权限不足）不中断整次巡检——该项标记错误，其余继续

### R3: 告警状态机（防 flapping + Resolved）
- **描述**：基于采集结果判断是否告警。核心是防抖动——连续 N 次失败才告警，恢复时发 Resolved。结构问题（缺主键）用增量告警（只告新增的）
- **验收标准**：
  - [ ] **连通性告警**：连续 N 次失败（默认 N=3，per-task 可配）→ 触发 Alert webhook。处于告警态后下次成功 → 触发 Resolved webhook
  - [ ] **阈值指标告警**（行数/连接数）：超阈值 → 连续 N 次超阈值才告警；恢复到阈值内 → Resolved
  - [ ] **结构问题告警**（缺主键）：增量模式——只告「本次新发现的缺 PK 表」（对比上次巡检结果）。已告过的不再重复告警。恢复（表加了 PK）→ Resolved
  - [ ] 状态持久化：per-task × per-metric 的告警态存 `health_alert_state` 表（OK / Failing(count) / Alerting），跨巡检保留
  - [ ] 告警去重：同一 task × metric 处于 Alerting 态时，不重复发 Alert（只发一次），直到 Resolved

### R4: webhook 投递（dbmaster.health-event.v1）
- **描述**：告警/恢复时投递 webhook，payload schema = `dbmaster.health-event.v1`（仿 drift 的 `dbmaster.drift-event.v1` 契约结构）
- **验收标准**：
  - [ ] webhook payload 含：schema / event_id(uuid) / event_at(RFC3339) / instance_uuid / task{id,name} / connection{id,name} / source{db_type,database} / alert{metric, severity, state(alert/resolved), detail}
  - [ ] 投递走 notify.rs（抄 data_sync notify 模式：validate_webhook_url https 强制 + deliver_with_backoff 重试 1s/4s/16s）
  - [ ] 投递结果（ok/failed/skipped）写 task_run_history.summary + 审计
  - [ ] v1 单 webhook URL（notify_channels JSON 数组取第一个，同 drift）

### R5: 结果存储与轮转
- **描述**：每次巡检写一行结果到 `health_check_results`，定期清理过期数据
- **验收标准**：
  - [ ] 每次巡检写一行：task_id / started_at / finished_at / status(success/failed/partial) / metrics_summary(JSON 含 4 项指标的快照) / alert_changes(JSON 本轮触发的告警/恢复)
  - [ ] 结果保留默认 30 天，scheduler 定期 DELETE 过期行（per-task 可配保留天数）
  - [ ] 提供 API 查询历史结果（按 task + 时间范围）

### R6: API 端点
- **描述**：提供 HTTP API 管理任务和查询结果，复用 automation crate 的路由注册模式
- **验收标准**：
  - [ ] `GET /api/health-results?task_id=&limit=`：查巡检历史（分页）
  - [ ] `POST /api/tasks/:id/run`（复用既有 run_task_now，加 health_check 分支）：手动触发巡检
  - [ ] task CRUD（`POST/GET/PUT/DELETE /api/tasks`）：复用既有 scheduled_tasks 表，task_type='health_check'。创建/修改走 license gate
  - [ ] 所有 mutation 端点第一行调 `gate_blocked`（同 drift/data_sync）
  - [ ] 所有端点经 `Claims` 认证中间件保护

### R7: 只读 canary 校验（安全纵深）
- **描述**：巡检前验证源连接账号是只读的（drift 的 canary 模式），防止误配置的写账号被巡检 SQL 意外写入
- **验收标准**：
  - [ ] 巡检前跑只读 canary（drift canary.rs 模式），若账号可写 → 中止本次巡检 + 记录错误
  - [ ] `database_connections.kind = 'source_drift'` 的连接复用 drift 的 canary；其他连接 health_check 自己做 canary 校验

### R8: embedded 模式 NoopRunner
- **描述**：桌面内嵌模式（免费本地）不跑 health check——纯远程付费功能，同 drift
- **验收标准**：
  - [ ] main.rs embedded 分支装配 NoopHealthCheckRunner（同 NoopDriftRunner 模式）
  - [ ] embedded 模式 health_check scheduler 不启动
  - [ ] health_check Runner trait 的 noop 实现返回 Ok（不报错），与 drift NoopRunner 一致

## 4. 非功能需求

### NF1: 性能
- 单次巡检（4 项指标 + canary）< 10 秒完成（含源库连接建立）
- scheduler 扫描周期 60 秒（同 drift），不阻塞主线程（tokio spawn 后台任务）
- 单 task 不重叠执行（InFlightTasks）

### NF2: 安全
- 凭据加密：源连接密码复用 `automation/credential.rs`（AES-256-GCM），解密写 `credential_access_audit`
- 只读巡检：所有指标 SQL 是 SELECT，canary 防写账号误配置
- webhook URL 强制 https（dev 模式 `DBMASTER_DEV=1` 例外，同 drift notify）
- 不在 webhook payload / 日志里放凭据 / PII（同 drift 契约边界）

### NF3: 可靠性
- 单项指标失败不中断整次巡检（partial 容错）
- webhook 投递失败有重试（1s/4s/16s 三次），最终失败记 task_run_history
- 告警状态持久化（SQLite），server 重启不丢告警态

### NF4: 商业门控
- health_check 是 Pro 功能（BSL-1.1 crate），走 license gate
- mutation API + scheduler 启动都受 entitlement gate（gated 返 403 / scheduler 不启动）
- embedded 模式 NoopRunner

### NF5: 可观测性
- 每次巡检验写 task_run_history（status + summary + 耗时）
- webhook 投递结果审计
- 客户侧权限不足时明确标记（不静默失败）

### NF6: 测试
- collector 单测（MySQL/PG 指标 SQL 逻辑 + 方言适配）
- 告警状态机单测（OK→Failing(N)→Alerting→Resolved 全路径 + 增量结构告警）
- notify 单测（payload 构造 + 重试）
- scheduler 集成测试（due 判断 + 不重叠）
- canary 单测（只读校验）
- runner 端到端集成测试（mock 源库，验证全链路）
- license gate 测试（gated 实例拒绝）

## 5. 范围边界

### 不做（Out of scope）
- ❌ **全库支持**：初版 MySQL + PG。其他库（Doris/SQL Server/SQLite/MongoDB/Redis/Oracle）降级为仅连通性，完整指标留后续
- ❌ **多通道 webhook**：v1 单 URL（同 drift/data_sync），同时发多个 webhook 留后续
- ❌ **AI 驱动的指标分析 / 自愈建议**：确定性规则告警，不碰 ADR-0002 §4.6「AI 设计期提议 / 运行期确定性执行」红线
- ❌ **实时监控 / push 模式**：cron 周期巡检，非数据库主动推送
- ❌ **desktop UI 集成**：本 spec 仅 Server 端 + webhook。客户端连接状态指示器是 README M3 后半段，单独 spec
- ❌ **指标可视化 / 趋势图表**：只存结果 + API 查询，可视化留后续
- ❌ **自定义指标 SQL**：v1 固定 4 项指标，用户可开关但不能自定义 SQL（注入面 + 设计复杂度）
- ❌ **告警合并 / 升级**：多连接同时断不做全局合并（per-task 独立去重），告警升级（critical→page）留 receiver 侧

## 6. 假设与依赖

- **复用 drift/data_sync 架构**：scheduler 范式（tokio interval + InFlightTasks + is_due）、runner 编排、notify 重试、credential 加解密、canary 只读校验、task_run_history、credential_access_audit——均已有成熟实现可抄
- **bridge trait 扩展点已预留**：core 的 `DriftRunner`/`DataSyncRunner` trait + AppState + main.rs 装配模式定型，新增 `HealthCheckRunner` 是 5 处改动
- **scheduled_tasks 表通用**：task_type 字段区分，health_check 复用既有表 + 新增 config JSON schema
- **cron crate 已在 workspace**：data_sync 引入，health_check 可复用依赖
- **客户侧权限**：与 drift 一致（只读 catalog）。MySQL 需 `information_schema` SELECT + `PROCESS`（看 Threads_connected）；PG 需 `pg_stat_user_tables` + `pg_stat_activity` 读权限（默认有）。README 需补 GRANT 文档（design 阶段产出）

## 7. 开放问题

无未决问题。brainstorm 的 4 个开放问题全部采纳推荐默认值（作为可配置项）：
1. 默认 cron `*/10 * * * *` ✓
2. 连续失败阈值 N=3 ✓
3. 结果保留 30 天 ✓
4. 单 webhook URL（v1）✓

---

下一步：运行 `/dev-design` 进入方案设计阶段，基于本文档产出 design.md + ADR-0004。
