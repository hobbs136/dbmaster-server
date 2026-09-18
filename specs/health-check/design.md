# Design: health check 引擎

Date: 2026-08-12
Source: requirements.md + ADR-0004

## 1. 概述

新增 `crates/health_check`（BSL-1.1），架构抄 drift/data_sync。cron 驱动周期巡检已登记数据库连接的 4 项健康指标（连通性+延迟 / 表行数估算 / 缺失主键 / 连接数），基于阈值状态机告警（防 flapping + Resolved + 增量结构告警），通过 `dbmaster.health-event.v1` webhook 通知。初版 MySQL + PostgreSQL，其他库降级为仅连通性。embedded 模式 NoopRunner。

架构决策详见 **ADR-0004**。本 design 聚焦实现细节：模块接口、数据流、SQL、状态机、测试策略。

## 2. 架构（数据流）

```
scheduler.rs (cron 扫描, 60s tick)
    │ 扫 task_type='health_check' + enabled=1 + cron due
    │ InFlightTasks 防重叠
    ▼
runner.rs::run_task(pool, state, task_id, triggered_by)
    │
    ├─ 1. 读 scheduled_tasks row → 解析 config JSON (HealthCheckTaskConfig)
    ├─ 2. 读 database_connections → 解密凭据 (credential.rs, 审计 credential_access_audit)
    ├─ 3. canary 只读校验 (canary.rs, drift 模式) → 可写则中止
    ├─ 4. 开短连接池 (源库, max_connections=2)
    ├─ 5. collector.collect_metrics(pool, db_type, config.metrics) → MetricsSnapshot
    │      ├─ connectivity: SELECT 1 计时
    │      ├─ row_count: information_schema.tables (MySQL) / pg_class.reltuples (PG)
    │      ├─ missing_pk: information_schema.table_constraints → 无 PK 的表
    │      └─ connection_count: SHOW STATUS (MySQL) / pg_stat_activity (PG)
    ├─ 6. alert.evaluate(task_id, metric, snapshot, config.thresholds)
    │      读 health_alert_state → 状态机推进 → 写回 → 产出 AlertChange[]
    ├─ 7. 有 AlertChange → notify.deliver(webhook_url, payload) + 重试
    ├─ 8. 写 health_check_results (metrics_summary + alert_changes)
    ├─ 9. 轮转：DELETE 过期 health_check_results (config.retention_days)
    └─ 10. 写 task_run_history (status + summary + webhook outcome)
```

## 3. 模块设计

### 3.1 `config.rs` — HealthCheckTaskConfig

存 `scheduled_tasks.config` JSON。参考 `data_sync/src/config.rs` 的强类型 + validate 模式。

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckTaskConfig {
    /// 指标开关（默认全开）
    #[serde(default = "default_metrics")]
    pub metrics: MetricFlags,
    /// 连续失败/超阈值次数阈值（默认 3）
    #[serde(default = "default_fail_threshold")]
    pub fail_threshold: u32,
    /// 行数告警阈值（表行数超过此值告警，默认 10_000_000）
    #[serde(default = "default_row_threshold")]
    pub large_table_threshold: u64,
    /// 连接数告警阈值（默认 100）
    #[serde(default = "default_conn_threshold")]
    pub connection_count_threshold: u64,
    /// 结果保留天数（默认 30）
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricFlags {
    pub connectivity: bool,   // 默认 true（不可关，核心指标）
    pub row_count: bool,      // 默认 true
    pub missing_pk: bool,     // 默认 true
    pub connection_count: bool, // 默认 true
}
```

`validate()`：阈值 clamp 到合理范围（fail_threshold 1-10，retention_days 1-365）。

### 3.2 `collector.rs` — 指标采集

**MetricsSnapshot**（采集结果，序列化进 metrics_summary JSON）：
```rust
pub struct MetricsSnapshot {
    pub connectivity: ConnectivityResult,        // ok/failed + latency_ms
    pub row_count: Option<TableRowStats>,        // None = unsupported/partial fail
    pub missing_pk: Option<MissingPkStats>,
    pub connection_count: Option<u64>,
    pub db_type: String,                          // 降级判断依据
    pub unsupported_metrics: Vec<String>,         // 降级时记录
}
```

**collect_metrics 分发**（参考 drift collector 的 MySql/Postgres 分发）：
```rust
pub async fn collect_metrics(
    pool: &sqlx::AnyPool,  // 或枚举 Pool<MySql>/Pool<Postgres>
    db_type: &str,
    flags: &MetricFlags,
) -> Result<MetricsSnapshot> {
    // 1. connectivity 永远做
    let connectivity = measure_connectivity(pool).await;
    // 2. 其余按 db_type 分发
    match db_type {
        "mysql" => collect_mysql_extras(pool, flags).await,
        "postgres" => collect_pg_extras(pool, flags).await,
        _ => MetricsSnapshot { /* 仅 connectivity, 其余 None, unsupported_metrics 记录 */ },
    }
}
```

**MySQL 指标 SQL**（参考 drift collector 的参数化 + information_schema 模式）：
| 指标 | SQL |
|---|---|
| 连通性 | `SELECT 1`（计时） |
| 行数 TOP N | `SELECT table_name, table_rows FROM information_schema.tables WHERE table_schema = ? ORDER BY table_rows DESC LIMIT ?` |
| 缺 PK 的表 | `SELECT t.table_name FROM information_schema.tables t WHERE t.table_schema = ? AND t.table_type = 'BASE TABLE' AND NOT EXISTS (SELECT 1 FROM information_schema.table_constraints c WHERE c.table_schema = t.table_schema AND c.table_name = t.table_name AND c.constraint_type = 'PRIMARY KEY')` |
| 连接数 | `SHOW STATUS LIKE 'Threads_connected'` |

**PG 指标 SQL**：
| 指标 | SQL |
|---|---|
| 连通性 | `SELECT 1`（计时） |
| 行数 TOP N | `SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT ?` |
| 缺 PK 的表 | `SELECT t.tablename FROM pg_tables t WHERE t.schemaname NOT LIKE 'pg_%' AND NOT EXISTS (SELECT 1 FROM pg_indexes i WHERE i.schemaname = t.schemaname AND i.tablename = t.tablename AND i.indexdef LIKE '%PRIMARY KEY%')` |
| 连接数 | `SELECT count(*) FROM pg_stat_activity` |

**权限不足处理**：每项指标独立 try/catch，失败标记 `unsupported_metrics`，不中断。canary 阶段额外检测权限（但 v1 可接受运行时降级）。

### 3.3 `alert.rs` — 告警状态机（核心新逻辑）

**AlertState**（对应 `health_alert_state.state` 列）：
```rust
enum AlertState { Ok, Failing { count: u32 }, Alerting }
```

**AlertChange**（状态机推进产生的事件 → 驱动 webhook）：
```rust
pub struct AlertChange {
    pub metric: String,        // connectivity | row_count | missing_pk | connection_count
    pub new_state: AlertState,
    pub severity: Severity,    // critical | warning | info
    pub trigger: Trigger,      // Alert | Resolved
    pub detail: serde_json::Value, // metric-specific 上下文
}
```

**evaluate 函数**（per metric 推进状态机）：
```rust
/// 读 health_alert_state 当前态 → 根据 snapshot 判断 → 写回新态 → 返回 AlertChange（若有）
pub async fn evaluate(
    pool: &SqlitePool,
    task_id: &str,
    snapshot: &MetricsSnapshot,
    config: &HealthCheckTaskConfig,
) -> Result<Vec<AlertChange>> {
    let mut changes = vec![];
    // connectivity: 失败 → Failing(count+1) → 到阈值 → Alerting(Alert); 成功且 Alerting → Resolved
    // row_count: TOP N 有超 large_table_threshold → 同上逻辑
    // missing_pk: 增量比对 detail.last_missing → 新增的表触发 Alert；消失的表触发 Resolved
    // connection_count: 超阈值 → 同上
    Ok(changes)
}
```

**状态转移规则**（connectivity 为例，其余阈值指标同构）：
| 当前态 | 本次结果 | 新态 | 事件 |
|---|---|---|---|
| Ok | 成功 | Ok | 无 |
| Ok | 失败 | Failing(1) | 无 |
| Failing(n) | 失败, n+1 < threshold | Failing(n+1) | 无 |
| Failing(n) | 失败, n+1 == threshold | Alerting | **Alert(critical)** |
| Failing(n) | 成功 | Ok | 无（抖动恢复，不告警） |
| Alerting | 成功 | Ok | **Resolved** |
| Alerting | 失败 | Alerting | 无（已告警，不重复） |

**missing_pk 增量告警**（不同逻辑）：
- 存 `detail.last_missing = ["table_a", "table_b"]`
- 本次发现 `["table_a", "table_c"]` → 新增 `table_c` → Alert(warning)；`table_b` 消失 → Resolved
- 不走连续 N 次逻辑（结构问题是离散的，不是连续阈值）

### 3.4 `notify.rs` — webhook 投递

抄 `data_sync/src/notify.rs`（逐字复用 `validate_webhook_url` + `deliver_with_backoff`），换 payload struct：

```rust
pub const PAYLOAD_SCHEMA: &str = "dbmaster.health-event.v1";

pub struct WebhookPayload {
    pub schema: String,
    pub event_id: String,        // uuid v4
    pub event_at: String,        // RFC3339 UTC
    pub instance_uuid: String,
    pub task: TaskRef,           // { id, name } — 复用 drift notify 的结构
    pub connection: ConnectionRef,
    pub source: SourceRef,
    pub alert: AlertPayload,     // { metric, severity, state, detail }
}
```

ADR-0002 §4.4.2 的 append-only 演进规则适用。deliver_with_backoff 重试 1s/4s/16s（同 drift/data_sync）。

### 3.5 `runner.rs` — 端到端编排

参考 `drift/src/runner.rs:103-168` 的 `run_task` 结构（10 步，见 §2 数据流）。关键函数签名：
```rust
pub async fn run_task(
    pool: &SqlitePool,
    state: &AppState,
    task_id: &str,
    triggered_by: &str,
) -> Result<RunOutcome>;

pub struct RunOutcome {
    pub status: String,           // success | failed | partial
    pub metrics_collected: u32,
    pub alert_changes: u32,
    pub webhook_status: String,   // ok | failed | skipped
}
```

**凭据解密 + 短连接池**：复用 drift `runner.rs:372-407` 的 `open_mysql_pool`/`open_pg_pool` 模式（max_connections=2，跑完 drop）。

**首次运行基线**（requirements R3 验收）：首次运行（health_alert_state 无记录）建立基线，不告警——但 connectivity 例外（首次失败就告，基线本身是「连不上」）。判断首次：`SELECT count(*) FROM health_alert_state WHERE task_id = ?` == 0。

### 3.6 `scheduler.rs` — cron 扫描

**逐字抄 `data_sync/src/scheduler.rs`**，只改：
- `SCAN_SQL` 的 `task_type = 'health_check'`
- `spawn` 调 `health_check::runner::run_task`
- 文档注释改 health_check 语义

`InFlightTasks` + `is_due`（cron 解析）+ 60s tick + 不重叠执行，全部复用。

## 4. 数据模型（migration `010_health_check.sql`）

见 ADR-0004 §2.4。两表：`health_check_results`（per-巡检）+ `health_alert_state`（per task × metric）。

## 5. API 端点（automation/handler.rs 注册）

| 方法 | 路径 | 说明 | 门控 |
|---|---|---|---|
| GET | `/api/health-results?task_id=&limit=&offset=` | 查巡检历史（分页） | 认证 |
| POST | `/api/tasks`（task_type=health_check） | 创建任务 | gate_blocked |
| POST | `/api/tasks/:id/run` | 手动触发（run_task_now 加 health_check 分支） | gate_blocked |
| GET/PUT/DELETE | `/api/tasks/:id` | 复用既有 task CRUD | gate_blocked |

## 6. 客户侧权限（README 补充）

**MySQL 只读账号 GRANT**（补 README §"Source database account requirements"）：
```sql
GRANT SELECT ON information_schema.* TO 'dbmaster_hc'@'%';
-- Threads_connected 需要 PROCESS 权限（或 MySQL 8.0+ 的 performance_schema）
GRANT PROCESS ON *.* TO 'dbmaster_hc'@'%';
-- 若用 performance_schema 看连接数（8.0+）：
GRANT SELECT ON performance_schema.threads TO 'dbmaster_hc'@'%';
```

**PG 只读账号 GRANT**：
```sql
-- pg_stat_user_tables / pg_stat_activity 默认可读（PUBLIC）
-- pg_tables 默认可读
-- 无需额外 GRANT（只要能连）
```

## 7. 风险与对策（design 层）

| 风险 | 对策 |
|---|---|
| 告警状态机测试复杂（4 metric × 多状态路径） | alert.rs 纯函数化（evaluate 不做 I/O，状态读写分离），单测覆盖全状态转移矩阵 |
| MySQL table_rows 估算不准（InnoDB） | 文档标「估算值」，large_table_threshold 留余量；不在 v1 做精确 COUNT（性能差） |
| 源库连接建立慢拖垮 scheduler | 单 task < 10s 超时（tokio timeout），不重叠执行（InFlightTasks） |
| 增量 missing_pk 的 detail JSON 比对逻辑 | alert.rs 内部用 `HashSet<String>` 做集合差集，序列化进 detail.last_missing |
| webhook payload 是对外契约 | 文档 `docs/webhook-health-event-v1.md`（仿 drift 的 webhook-drift-event-v1.md），append-only |

## 8. 需求覆盖矩阵

| 需求 | 设计位置 |
|---|---|
| R1 周期巡检调度 | §3.6 scheduler + §3.1 config cron |
| R2 指标采集 4 项 MySQL/PG | §3.2 collector + SQL 表 |
| R3 告警状态机防 flapping + Resolved + 增量 | §3.3 alert 状态转移表 + missing_pk 增量 |
| R4 webhook v1 投递 | §3.4 notify + payload schema |
| R5 结果存储 + 轮转 | §4 migration + runner §2 步骤 8/9 |
| R6 API 端点 | §5 端点表 |
| R7 只读 canary | runner §2 步骤 3（复用 drift canary） |
| R8 embedded NoopRunner | ADR-0004 §2.6 + main.rs 装配 |
| NF1 性能 < 10s | §7 超时对策 |
| NF2 安全（凭据/只读/https） | §3.5 凭据解密 + §6 权限 + canary |
| NF4 商业门控 | §5 gate_blocked + ADR §2.6 scheduler entitlement gate |
| NF6 测试 | §9 测试策略 |

## 9. 测试策略

### 9.1 单测
- **config.rs**：validate / clamp / 默认值 / JSON 往返
- **collector.rs**：MySQL/PG SQL 逻辑（mock pool 或 sqlx::Any with test 绑定）+ 降级（非 MySQL/PG 仅 connectivity）+ 单项失败容错
- **alert.rs**（核心）：全状态转移矩阵
  - connectivity: Ok→Failing(1)→...→Failing(N-1)→Alerting(Alert)→Resolved→Ok
  - Failing 恢复（n<N 时成功）→ Ok 无告警
  - Alerting 持续失败 → 不重复 Alert
  - missing_pk 增量：新增表 Alert / 消失表 Resolved / 不变无事件
  - 首次运行基线不告警（connectivity 例外）
- **notify.rs**：payload 序列化 schema 正确 + validate_webhook_url（https 强制/loopback 例外）+ backoff 重试

### 9.2 集成测试
- **scheduler**：cron due 判断 + InFlightTasks 不重叠（mock runner）
- **runner 端到端**：mock 源库（或 sqlx test pool），验证 canary→collect→alert→notify→persist 全链路
- **license gate**：gated 实例 scheduler 不启动 + mutation 返 403

### 9.3 测试基础设施
- 复用 drift/data_sync 的测试 helper（mock pool / mock webhook receiver）
- alert.rs 纯函数化，单测不需要数据库（状态读写分离为独立函数）

## 10. 实现顺序（对齐 ADR §6 里程碑）

M1 脚手架 → M2 collector → M3 alert → M4 runner+notify → M5 scheduler+API → M6 测试+文档。每里程碑可独立编译 + 测试。

---

下一步：运行 `/dev-plan` 进入任务拆解阶段，基于本文档 + ADR-0004 产出可执行的任务清单 tasks.md。
