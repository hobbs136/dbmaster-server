# ADR-0004: Health Check 引擎

- **Status**: Proposed（2026-08-12，spec 流程中）
- **Deciders**: 架构师 + 后端工程师
- **Context**: spec `specs/health-check/`（brainstorm → requirements → design）
- **Supersedes**: 无（新功能）
- **Related**: ADR-0002（schema-drift，架构模板）、ADR-0003（embedded 模式，NoopRunner 模式）

## 1. 背景 与 决策驱动因素

README M3 roadmap 列出 **Scheduled Health Checks**（连通性 / 缺失索引 / 表膨胀），当前零代码、零 schema。需求见 `specs/health-check/requirements.md`（R1-R8）。

核心决策驱动因素：
1. **已有两个成熟的周期性引擎**（drift 3,400 行、data_sync 2,490 行），其「collector + scheduler + runner + notify + audit」范式可复用 60-70%
2. **bridge trait 扩展点已预留**（core 的 `DriftRunner`/`DataSyncRunner` + AppState + main.rs 装配），新增第三个是模式化扩展
3. **告警策略是 drift 没有的新工作面**——drift 做「状态变化触发」，health check 需要「阈值 + 连续 N 次防 flapping + Resolved + 增量结构告警」
4. **embedded 模式语义**：health check 是远程付费功能（同 drift），embedded 模式 NoopRunner

## 2. 决策

### 2.1 新增独立 crate `crates/health_check`（BSL-1.1）

**选项考虑**：
- A. 独立 crate（同 drift/data_sync）✅
- B. 塞进 automation crate（已有 task 路由）—— 拒绝：automation 是路由/凭据/分发层，不是业务引擎；drift/data_sync 已证明独立 crate 是正确分层
- C. 塞进 drift crate —— 拒绝：职责正交（结构 vs 运行时），耦合会膨胀 drift

**决策**：A。模块布局（抄 drift）：
```
crates/health_check/src/
├── lib.rs          ~80   (HealthCheckRunner trait impl + re-exports)
├── config.rs       ~200  (HealthCheckTaskConfig：cron/指标开关/阈值/notify/轮转)
├── collector.rs    ~550  (4 项指标 SQL：MySQL/PG 方言 + 降级)
├── alert.rs        ~350  (告警状态机：OK→Failing(N)→Alerting→Resolved + 增量结构告警)
├── runner.rs       ~450  (端到端编排：canary→collect→alert→notify→persist→retention)
├── scheduler.rs    ~230  (cron 扫描 + InFlightTasks，抄 data_sync)
├── notify.rs       ~250  (dbmaster.health-event.v1 payload + 重试，抄 data_sync notify)
└── audit.rs        ~0    (直接调 drift::audit::log_access，跨 crate 依赖可接受)
```
依赖：`dbmaster-core` + `dbmaster-automation`（credential decrypt）+ `dbmaster-license`。同 drift/data_sync。

### 2.2 bridge trait 扩展（5 处改动，模式定型）

core 加 `HealthCheckRunner` trait（镜像 `DriftRunner`/`DataSyncRunner`）：
```rust
#[async_trait]
pub trait HealthCheckRunner: Send + Sync + 'static {
    async fn run(&self, pool: &SqlitePool, state: &AppState,
                 task_id: &str, triggered_by: &str) -> Result<(), String>;
}
```

**5 处改动**：
1. `core/src/server/mod.rs`：+ `HealthCheckRunner` trait + AppState 加 `health_check_runner: Arc<dyn HealthCheckRunner>` 字段 + `new()`/`new_embedded()` 加参数
2. `health_check/src/lib.rs`：`HealthCheckRunnerHandle` unit struct + impl trait（调 `runner::run_task`）
3. `src/main.rs`：normal 模式装配 `Arc::new(HealthCheckRunnerHandle)`；embedded 模式装配 `NoopHealthCheckRunner`
4. `src/main.rs`：scheduler spawn 加 `if entitlement.is_gated()` 分支（同 drift/data_sync）
5. `automation/src/handler.rs`：`run_task_now` 的 task_type 分发加 `'health_check'` 分支 + 路由注册 `/api/health-results`

### 2.3 告警状态机（drift 没有的新工作面）

drift 的告警 = 「hash 变就发」。health check 需要：

**per task × per metric 状态**（存新表 `health_alert_state`）：
```
OK → (指标失败/超阈值) → Failing(count=1) → (再失败) → Failing(count=2)
   → (第 N 次失败, N=阈值) → Alerting(发 Alert webhook)
   → (恢复成功) → Resolved(发 Resolved webhook) → OK
```

**结构问题（缺主键）用增量告警**（类似 drift diff）：
- 记录上次发现的「缺 PK 表集合」，本次只告「新增的」
- 恢复（表加了 PK）→ 对应表发 Resolved

**设计依据**：DBA 场景必须防 flapping（网络抖一下不能告警风暴），drift 的 hash 模型不适用。连续 N 次计数 + Resolved 是运维告警的标准实践（参考 Prometheus Alertmanager 的 pending→firing→resolved 模型）。

### 2.4 数据模型（新 migration `010_health_check.sql`）

**`health_check_results`**（per-巡检一行）：
```sql
CREATE TABLE health_check_results (
    id              TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL,          -- success | failed | partial
    metrics_summary TEXT NOT NULL,          -- JSON: 4 项指标快照
    alert_changes   TEXT NOT NULL DEFAULT '[]', -- JSON: 本轮触发的告警/恢复事件
    triggered_by    TEXT NOT NULL
);
CREATE INDEX idx_health_results_task_time ON health_check_results(task_id, started_at DESC);
```

**`health_alert_state`**（per task × per metric 告警态）：
```sql
CREATE TABLE health_alert_state (
    task_id      TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
    metric       TEXT NOT NULL,              -- connectivity | row_count | missing_pk | connection_count
    state        TEXT NOT NULL,              -- ok | failing | alerting
    fail_count   INTEGER NOT NULL DEFAULT 0, -- 连续失败计数（state=failing 时累加）
    detail       TEXT,                       -- JSON: 上次发现的值（如缺 PK 表集合，用于增量比对）
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (task_id, metric)
);
```

**不新增 task 表**：复用 `scheduled_tasks`（task_type='health_check'），config JSON 存 health_check 专属配置。

### 2.5 webhook 契约 `dbmaster.health-event.v1`（新 schema，仿 drift v1）

append-only 演进规则同 ADR-0002 §4.4.2。payload 结构（仿 `dbmaster.drift-event.v1`）：
```json
{
  "schema": "dbmaster.health-event.v1",
  "event_id": "<uuid v4>",
  "event_at": "<RFC3339 UTC>",
  "instance_uuid": "<server install uuid>",
  "task": { "id": "...", "name": "..." },
  "connection": { "id": "...", "name": "..." },
  "source": { "db_type": "mysql|postgres|...", "database": "..." },
  "alert": {
    "metric": "connectivity|row_count|missing_pk|connection_count",
    "severity": "critical|warning|info",
    "state": "alert|resolved",
    "detail": { "...metric-specific context..." }
  }
}
```

### 2.6 embedded 模式 NoopRunner（同 drift）

`main.rs` 的 `run_embedded` 分支装配 `NoopHealthCheckRunner`（unit struct + impl trait 返 Ok），不 spawn scheduler。依据：health check 是远程付费功能（always-on 监控属团队/远程场景），桌面用户要用得开 Server 订阅。同 ADR-0003 对 drift 的处理。

## 3. 考虑过的替代方案

### 3.1 告警模型：drift 式「状态变化触发」vs 阈值状态机
- drift 式简单（无去重表），但连通性监控不防 flapping → 拒绝
- 选阈值状态机（§2.3），新增 `health_alert_state` 表。复杂度可控（4 个 metric × 简单状态机）

### 3.2 scheduler：interval vs cron
- drift 用 interval_minutes，data_sync 用 cron_expr
- health check 场景天然适合 cron（"每 10 分钟"/"每小时整点"），且 cron crate 已在 workspace（data_sync 引入）
- 选 cron_expr（抄 data_sync scheduler）

### 3.3 结果存储：per-巡检 vs per-metric
- per-metric 粒度过细（4 指标 × 每巡检 = 4 行 × 频率），查询复杂
- 选 per-巡检一行（metrics_summary JSON 含 4 项），趋势按 task 聚合

### 3.4 指标方言：初版范围
- 全库（含 Doris/SQLServer/SQLite/Mongo）—— catalog 差异大，工作量大
- 选初版 MySQL + PG（同 drift collector），其他库降级为仅连通性。drift 已验证这两库路径可行

## 4. 后果

### 正面
- 架构与 drift/data_sync 一致，代码审查和后续维护成本低
- bridge trait 模式定型，未来第六个引擎（如 slow query）可继续复制
- 告警状态机是可复用的运维能力（未来 slow query 告警可复用 alert.rs 模式）

### 负面 + 缓解
- **+5 处跨 crate 改动**（core trait/AppState/main/automation）—— 模式定型，风险低，但 PR 必须一次性改全（否则编译断）
- **新 webhook 契约**—— `dbmaster.health-event.v1` 是对外契约，需文档 + append-only 承诺（同 drift）。design 阶段产出 `docs/webhook-health-event-v1.md`
- **告警状态机复杂度**—— 需完整测试 OK→Failing(N)→Alerting→Resolved 全路径 + 增量结构告警 + 恢复
- **客户侧权限文档**—— MySQL 需 `PROCESS`（看 Threads_connected），需在 README §"Source database account requirements" 补 GRANT 示例

### 中性
- 新 crate 增加编译时间（~2,000 行），可接受

## 5. 合规与安全

- BSL-1.1 crate，Pro 功能走 license gate（mutation handler + scheduler entitlement gate）
- 只读巡检：所有指标 SELECT，canary 防写账号（drift canary 模式复用）
- 凭据 AES-256-GCM 加密（automation/credential.rs），访问写 credential_access_audit
- webhook payload 不含凭据/PII（同 drift 契约边界 D5）
- 不改既有 drift/data_sync API 契约（新功能，不触发跨组件契约铁律）

## 6. 实现里程碑

见 `specs/health-check/tasks.md`（plan 阶段产出）。建议按层推进：
1. M1 脚手架（crate + Cargo.toml + lib.rs trait impl + core 5 处改动 + migration）
2. M2 collector（4 项指标 MySQL/PG SQL + 降级）
3. M3 alert 状态机（OK→Failing→Alerting→Resolved + 增量结构告警）
4. M4 runner 编排 + notify（webhook v1 payload + 重试）
5. M5 scheduler + API 端点 + license gate
6. M6 测试（单测 + 集成）+ 文档（webhook 契约 + GRANT）

## 7. 开放问题

无。requirements 的开放问题已全部采纳推荐默认值。
