# Tasks: health check 引擎

Date: 2026-08-12
Source: design.md + ADR-0004

## 里程碑

- **M1: 脚手架** — crate 骨架 + core bridge trait 扩展 + migration，编译通过 + empty runner 能跑通手动触发链路（DoD: `cargo build` 全绿 + `cargo test -p dbmaster-core` 零回归 + 手动触发 health_check task 返回 ok noop）
- **M2: 指标采集** — collector 4 项指标 MySQL/PG SQL + 降级（DoD: collector 单测全绿，覆盖 MySQL/PG 各指标 + 非 MySQL/PG 降级 + 单项失败容错）
- **M3: 告警状态机** — alert.rs OK→Failing→Alerting→Resolved + 增量 missing_pk（DoD: alert 单测全状态转移矩阵覆盖）
- **M4: runner + notify** — 端到端编排 + webhook v1 payload + 重试（DoD: runner 集成测试 mock 源库全链路 + notify payload schema 单测）
- **M5: scheduler + API + 门控** — cron scheduler + /api/health-results + license gate（DoD: scheduler due 判断测试 + gated 实例不启动测试 + API 端点集成测试）
- **M6: 测试 + 文档收尾** — 集成测试补全 + webhook 契约文档 + GRANT 文档 + README 更新（DoD: cargo test 全绿 + 文档审阅）

## 任务清单

| ID | 任务 | 依赖 | 估时 | 里程碑 |
|---|---|---|---|---|
| T01 | 新建 crate `crates/health_check` + Cargo.toml | - | S | M1 |
| T02 | migration `010_health_check.sql`（2 表） | - | S | M1 |
| T03 | core 加 `HealthCheckRunner` trait | T01 | S | M1 |
| T04 | core AppState 加字段 + new/new_embedded 参数 | T03 | S | M1 |
| T05 | health_check lib.rs：HealthCheckRunnerHandle + noop impl + re-exports | T03 | S | M1 |
| T06 | main.rs normal 模式装配 + scheduler spawn gate | T04,T05 | S | M1 |
| T07 | main.rs NoopHealthCheckRunner + embedded 装配 | T04,T05 | S | M1 |
| T08 | automation handler：run_task_now 加 health_check 分支 + 路由注册 | T05 | S | M1 |
| T09 | M1 验证：cargo build + core 回归 | T06,T07,T08 | S | M1 |
| T10 | config.rs：HealthCheckTaskConfig + validate | T05 | S | M2 |
| T11 | collector.rs：MetricsSnapshot 结构 + measure_connectivity | T10 | S | M2 |
| T12 | collector.rs：MySQL 4 项指标 SQL | T11 | M | M2 |
| T13 | collector.rs：PG 4 项指标 SQL | T11 | M | M2 |
| T14 | collector.rs：collect_metrics 分发 + 非 MySQL/PG 降级 | T12,T13 | S | M2 |
| T15 | collector 单测（MySQL/PG 各指标 + 降级 + 容错） | T14 | M | M2 |
| T16 | alert.rs：AlertState + AlertChange 结构 + health_alert_state 读写 | T10 | S | M3 |
| T17 | alert.rs：connectivity 状态转移（Ok→Failing→Alerting→Resolved） | T16 | M | M3 |
| T18 | alert.rs：阈值指标状态转移（row_count/connection_count） | T17 | S | M3 |
| T19 | alert.rs：missing_pk 增量告警（HashSet 差集） | T16 | M | M3 |
| T20 | alert.rs：首次运行基线逻辑（connectivity 例外） | T17 | S | M3 |
| T21 | alert 单测（全状态转移矩阵 + 增量 + 基线） | T17-T20 | L | M3 |
| T22 | notify.rs：dbmaster.health-event.v1 payload + validate/deliver | T05 | S | M4 |
| T23 | runner.rs：run_task 端到端编排（10 步） | T14,T16,T22 | L | M4 |
| T24 | runner.rs：canary 只读校验 + 短连接池 | T23 | M | M4 |
| T25 | runner.rs：结果轮转（DELETE 过期） | T23 | S | M4 |
| T26 | notify 单测（payload schema + webhook url 验证 + backoff） | T22 | M | M4 |
| T27 | runner 集成测试（mock 源库全链路） | T23,T24,T25 | L | M4 |
| T28 | scheduler.rs（抄 data_sync，改 task_type） | T08 | S | M5 |
| T29 | automation：GET /api/health-results 端点 | T08 | S | M5 |
| T30 | license gate 测试（gated 不启动 scheduler + mutation 403） | T28,T29 | M | M5 |
| T31 | docs/webhook-health-event-v1.md（契约文档） | T22 | S | M6 |
| T32 | README 补 health check GRANT 文档 + Feature 表更新 | T14 | S | M6 |
| T33 | 全量 cargo test + cargo clippy 零回归 | 所有 | M | M6 |

## 任务详情

### T01: 新建 crate 骨架
- 做什么：`crates/health_check/` + `Cargo.toml`（BSL-1.1，依赖 dbmaster-core + dbmaster-automation + dbmaster-license + async-trait + serde + serde_json + sqlx + tokio + chrono + cron + tracing + anyhow + uuid）+ 空 `src/lib.rs`（模块声明注释）+ workspace Cargo.toml 加 member
- 验收：`cargo build -p dbmaster-health-check` 通过（空 crate）

### T02: migration 010
- 做什么：`migrations/010_health_check.sql`：`health_check_results`（per-巡检，见 design §4）+ `health_alert_state`（per task×metric，见 ADR §2.4）+ 索引。参考 005_drift_v1.sql 风格
- 验收：sqlx migrate 成功创建两表 + 索引

### T03: core HealthCheckRunner trait
- 做什么：`crates/core/src/server/mod.rs` 加 `HealthCheckRunner` trait（镜像 DriftRunner/DataSyncRunner，run 签名相同）。参考 mod.rs:36-74
- 验收：core 编译通过，trait 定义可见

### T04: core AppState 加字段
- 做什么：AppState 加 `health_check_runner: Arc<dyn HealthCheckRunner>` + `new()`/`new_embedded()`/`build_app_with_config` 加参数。参考现有 drift_runner/data_sync_runner 字段模式
- 验收：core 编译通过（所有 new 调用点会暂时断，T06-T08 修）

### T05: health_check lib.rs trait impl
- 做什么：lib.rs 加 `HealthCheckRunnerHandle` unit struct + impl HealthCheckRunner（暂时 noop 返 Ok，M4 替换为真 runner）+ re-exports 声明（模块先用 `pub mod xxx;` 占位）
- 验收：health_check crate 编译 + impl trait 正确

### T06: main.rs normal 模式装配
- 做什么：`src/main.rs` normal 模式（run_normal）装配 `Arc::new(dbmaster_health_check::HealthCheckRunnerHandle)` 注入 AppState；scheduler spawn 加 `health_check::spawn_scheduler`（M5 实现 spawn，先占位注释）+ `if entitlement.is_gated()` 三 scheduler 同一分支
- 验收：normal 模式编译通过

### T07: main.rs embedded NoopRunner
- 做什么：加 `NoopHealthCheckRunner` struct（同 NoopDriftRunner 模式）+ impl trait 返 Ok；run_embedded 装配它 + 不 spawn scheduler
- 验收：embedded 模式编译通过

### T08: automation run_task_now 分支
- 做什么：`automation/src/handler.rs` 的 run_task_now task_type dispatch 加 `'health_check' => state.health_check_runner.run(...)` 分支（参考现有 drift/data_sync 分支）
- 验收：手动触发 health_check task 能调到 runner（noop 返 ok）

### T09: M1 验证
- 做什么：`cargo build`（全 workspace）+ `cargo test -p dbmaster-core`（零回归）+ 手动创建 health_check task 触发返回 ok
- 验收：编译全绿 + core 测试零回归 + 链路通

### T10: config.rs
- 做什么：HealthCheckTaskConfig + MetricFlags + 默认值函数 + validate（clamp 阈值）。参考 data_sync/config.rs 强类型模式
- 验收：config 单测（默认值 + clamp + JSON 往返）

### T11: collector MetricsSnapshot + connectivity
- 做什么：MetricsSnapshot 结构（connectivity/row_count/missing_pk/connection_count + db_type + unsupported_metrics）+ measure_connectivity（SELECT 1 计时）
- 验收：connectivity 单测（mock pool 成功/失败 + 计时）

### T12-T13: MySQL/PG 指标 SQL
- 做什么：collect_mysql_extras / collect_pg_extras，4 项指标 SQL（见 design §3.2 表）。参考 drift collector 的参数化 + FromRow 模式
- 验收：各指标 SQL 逻辑单测（mock 或 sqlx::Any test）

### T14: collect_metrics 分发
- 做什么：collect_metrics 按 db_type 分发（mysql/postgres/降级）+ 单项失败容错（try/catch 标 unsupported_metrics）
- 验收：分发单测（MySQL/PG/其他库降级路径）

### T15: collector 单测补全
- 做什么：T11-T14 的完整测试套件
- 验收：collector 测试全绿

### T16: alert.rs 基础结构
- 做什么：AlertState enum（Ok/Failing{count}/Alerting）+ AlertChange struct + health_alert_state 表读写函数（read_state/write_state）+ evaluate 函数签名
- 验收：结构定义 + 读写函数单测

### T17-T20: 告警逻辑
- T17 connectivity 状态转移：见 design §3.3 状态转移表
- T18 阈值指标（row_count/connection_count）：复用 T17 的连续 N 次逻辑
- T19 missing_pk 增量：HashSet 差集 + detail.last_missing 序列化
- T20 首次基线：无 health_alert_state 记录时建基线不告警（connectivity 例外）

### T21: alert 单测（核心）
- 做什么：全状态转移矩阵（每 metric 每状态每结果）+ 增量告警 + 基线 + 边界（阈值边界值）
- 验收：alert 测试全绿，覆盖 design §3.3 所有转移

### T22: notify.rs
- 做什么：dbmaster.health-event.v1 WebhookPayload struct + validate_webhook_url（抄 data_sync）+ deliver + deliver_with_backoff（抄 data_sync）
- 验收：payload 序列化 schema 单测 + url 验证单测

### T23: runner.rs run_task
- 做什么：10 步编排（见 design §2 数据流）：读 task/config → 解密凭据 → canary → 开池 → collect → alert → notify → 写 results → 轮转 → 写 task_run_history。参考 drift runner.rs:103-168
- 验收：runner 编译 + 基本链路（mock 源库）

### T24: canary + 短连接池
- 做什么：复用 drift canary.rs 的只读校验逻辑 + open_mysql_pool/open_pg_pool（参考 drift runner.rs:372-407）
- 验收：canary 单测（只读通过/可写拒绝）

### T25: 结果轮转
- 做什么：runner 末尾 DELETE health_check_results WHERE started_at < now - retention_days
- 验收：轮转单测

### T26-T27: notify + runner 测试
- 做：notify payload/backoff 单测 + runner 端到端集成（mock 源库 + mock webhook receiver）

### T28: scheduler.rs
- 做什么：逐字抄 data_sync/scheduler.rs，改 SCAN_SQL task_type='health_check' + spawn 调 health_check runner + lib.rs export spawn_scheduler
- 验收：scheduler due 判断测试 + InFlightTasks 测试

### T29: API 端点
- 做什么：automation/handler.rs 加 GET /api/health-results（分页查询，参考现有 reports handler）+ 路由注册
- 验收：API 集成测试（分页 + task_id 过滤）

### T30: license gate 测试
- 做什么：gated 实例 scheduler 不启动 + mutation handler 返 403 ENTITLEMENT_GATED 的集成测试
- 验收：门控测试全绿

### T31: webhook 契约文档
- 做什么：docs/webhook-health-event-v1.md（仿 docs/webhook-drift-event-v1.md 结构：when fires / payload schema / fields / append-only 演进规则）
- 验收：文档审阅，payload 与 notify.rs 实现一致

### T32: README GRANT + Feature 表
- 做什么：README §"Source database account requirements" 加 health check 的 MySQL/PG GRANT 示例（见 design §6）+ Feature 表 health check 行从 🔲 改 ✅ + Roadmap M3 标 done
- 验收：文档审阅

### T33: 全量验证
- 做什么：`cargo test`（全 workspace）+ `cargo clippy` + 零回归确认 + 清 CHANGE 标记
- 验收：全绿

## 覆盖矩阵

| 需求/设计项 | 覆盖任务 |
|---|---|
| R1 周期巡检调度 | T06,T28 |
| R2 指标采集 4 项 MySQL/PG | T11-T15 |
| R3 告警状态机 | T16-T21 |
| R4 webhook v1 | T22,T26,T31 |
| R5 结果存储 + 轮转 | T02,T23,T25 |
| R6 API 端点 | T08,T29 |
| R7 只读 canary | T24 |
| R8 embedded NoopRunner | T07 |
| NF1 性能 | T23（timeout） |
| NF2 安全（凭据/只读/https） | T22,T24 |
| NF4 商业门控 | T06,T30 |
| NF6 测试 | T15,T21,T26,T27,T30,T33 |
| ADR §2.2 bridge trait 5 处改动 | T03,T04,T05,T06,T08 |
| ADR §2.6 embedded Noop | T07 |

---

下一步：运行 `/dev-build` 进入开发实现阶段，按本文档逐项实现（M1 → M2 → ... → M6）。
