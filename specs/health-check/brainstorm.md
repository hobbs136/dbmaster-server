# Brainstorm: health check 引擎

Date: 2026-08-12

## 背景与目标

dbmaster-server 已落地两个周期性自动化引擎——schema drift（`crates/drift`，3,400 行）和 data sync（`crates/data_sync`，2,490 行），其「collector + scheduler + runner + notify + audit」范式已成熟定型。README 把 **Scheduled Health Checks** 列为 M3（Weeks 9-12）roadmap，当前零代码、零 schema、零 SQL。

目标：新增 `crates/health_check` crate，定期巡检已登记的数据库连接健康状态（连通性 / 关键指标），发现异常时通过 webhook 告警。复用 drift/data_sync 60-70% 的脚手架，但**告警策略是 drift 没有的新工作面**（drift 只做「状态变化触发」，health check 需要「阈值 + 去重 + 恢复通知」）。

**已拍板的产品决策**（不再讨论）：
- 指标清单 = 核心 4 项（连通性+延迟 / 表行数估算 / 缺失主键检测 / 连接数）
- embedded 模式不跑（同 drift，NoopRunner，纯远程付费功能）

## 目标用户与场景

- **DBA / 运维**（Server 订阅用户）：管理多个数据库实例，需要 always-on 监控——连接是否可达、有没有表膨胀、有没有缺主键的表。出问题第一时间收到 webhook（Slack/钉钉/企业微信 receiver）
- **核心场景**：
  1. 周期巡检（cron 驱动，默认每 10 分钟）→ 异常指标超阈值 → webhook 告警
  2. 连续 N 次失败才告警（防抖动/flapping）→ 恢复时发 Resolved
  3. 历史结果查询（API + 可能的 UI）→ 看趋势

## 发散的想法

### 功能方向
- **指标采集**（核心 4 项，已定）：
  1. 连通性 + 延迟（`SELECT 1` 计时，所有库通用）
  2. 表行数估算（MySQL `information_schema.tables.table_rows` / PG `pg_class.reltuples`）
  3. 缺失主键检测（`information_schema.table_constraints` 找无 PK 的表）
  4. 连接数（MySQL `SHOW STATUS LIKE 'Threads_connected'` / PG `pg_stat_activity.count`）
- **告警策略**（drift 没有，新工作面）：
  - 连通性失败：连续 N 次（默认 3）才告警 → 恢复发 Resolved
  - 阈值指标（行数/连接数）：超阈值告警，恢复发 Resolved
  - 结构问题（缺主键）：每次发现就告警？还是只在「新增缺主键的表」时告警（增量，类似 drift）？
- **历史与趋势**：每次巡检写一行结果，保留 N 天（轮转），可查趋势
- **手动触发**：API `/api/tasks/:id/run`（复用既有 run_task_now 分发）

### 技术方向
- **新 crate `health_check`**（BSL-1.1，同 drift/data_sync）
- **架构抄 drift**：collector（指标 SQL）+ scheduler（tokio interval 扫描）+ runner（编排）+ notify（webhook）+ audit（复用 credential_access_audit）
- **bridge trait 扩展**：core 加 `HealthCheckRunner` trait + AppState 字段 + main.rs 装配 + automation run_task_now 加 `health_check` 分支（5 处改动，模式定型）
- **方言适配**：初版只做 **MySQL + PostgreSQL**（与 drift 对齐，drift collector 只支持这两者）。Doris/SQL Server/SQLite/MongoDB 留后续
- **告警去重状态**：需要新表记录「当前是否处于告警态」（per task × per metric），实现连续 N 次计数 + Resolved 检测
- **scheduler 用 cron 还是 interval**：data_sync 用 cron_expr（cron crate），drift 用 interval_minutes。health check 倾向 cron（"每 10 分钟" = `*/10 * * * *`），更灵活

### 用户场景
- DBA 配置：注册连接 → 创建 health_check task（选指标 + 阈值 + cron + webhook URL）→ 等 webhook
- 恢复场景：连接断了 → 连续 3 次失败 → 告警 → 连接恢复 → 下次巡检成功 → Resolved webhook

## 方案对比与推荐

| 决策点 | 选项 A | 选项 B | 推荐 |
|---|---|---|---|
| **告警模型** | A. drift 式「状态变化触发」（简单，无去重） | B. 阈值 + 连续 N 次 + Resolved（防抖动，DBA 场景必需） | **B**。连通性监控必须防 flapping（网络抖一下不能告警风暴），drift 的 hash 变化模型不适用。新增 `health_alert_state` 表记录告警态 |
| **结构问题告警** | A. 每次发现缺主键就告警 | B. 增量告警（只告「新增的缺主键表」，类似 drift diff） | **B**。每次都告同一批缺主键的表 = 噪音。增量告警需要记录上次发现的状态 |
| **scheduler 调度** | A. interval_minutes（drift 式） | B. cron_expr（data_sync 式） | **B**。health check 场景天然适合 cron（"每 10 分钟" / "每小时整点"），cron 更灵活，且 data_sync 已引入 cron crate 依赖可复用 |
| **结果存储** | A. per-巡检一行（summary JSON） | B. per-metric 一行（细粒度） | **A**。每次巡检写一行 `health_check_results`（含所有指标的 JSON summary），查询简单，趋势按 task 聚合。per-metric 粒度过细 |
| **结果轮转** | A. 不轮转（无限增长） | B. 保留 N 天（默认 30） | **B**。周期巡检数据量大（每 10 分钟 × 多连接 × 30 天），需轮转。scheduler 定期 DELETE 过期行 |
| **首次运行** | A. 首次就采集 + 告警 | B. 首次只建基线（不告警） | **B**。首次运行建立「已知状态」基线（哪些表缺主键），之后增量告警。连通性例外——首次失败就告（基线本身就是「连不上」） |
| **指标方言适配** | A. 初版 MySQL+PG（同 drift） | B. 全库（含 Doris/SQLServer/SQLite/Mongo） | **A**。drift 只支持 MySQL+PG，collector 模式已验证。其他库的 catalog 差异大，留后续。连接若不是 MySQL/PG，巡检只做连通性（降级） |
| **webhook payload schema** | A. 仿 drift 的 `dbmaster.drift-event.v1` 风格 | B. 全新设计 | **A**。复用 drift 的契约结构（schema/event_id/event_at/instance_uuid/task/connection/source/ + domain summary），新 schema id = `dbmaster.health-event.v1`。append-only 演进规则同 drift |

## 约束

- **BSL-1.1 crate**（同 drift/data_sync/automation/license），Pro 功能走 license gate
- **只读巡检**：所有指标 SQL 都是 SELECT，不写源库（drift 的 canary 模式可复用——验证账号只读）
- **凭据加密**：复用 `automation/credential.rs`（AES-256-GCM），凭据访问写 `credential_access_audit`
- **客户侧权限**：与 drift 一致（只读 catalog）。MySQL 需 `information_schema` + `PROCESS`（看连接数）；PG 需 `pg_stat_user_tables` 读权限（默认有）。README 需补 GRANT 文档
- **不触及既有 API 契约**：新增端点 + 新 task_type，不改既有 drift/data_sync 契约
- **embedded 模式 NoopRunner**：同 drift，main.rs 装配 NoopHealthCheckRunner

## 风险与未知

- **告警去重状态机的复杂度**：连续 N 次 + Resolved + 增量结构问题告警，状态管理比 drift 复杂。需在 design 阶段画清状态机（OK → Failing(count) → Alerting → Recovering → OK）
- **MySQL 连接数指标权限**：`SHOW STATUS LIKE 'Threads_connected'` 和 `SHOW PROCESSLIST` 需 `PROCESS` 权限，客户只读账号可能没有。需在 canary 阶段检测权限不足 → 降级（跳过该指标，不告警）
- **表行数估算准确性**：`information_schema.tables.table_rows`（MySQL InnoDB）是估算值，可能偏差大。需文档说明「估算值」语义，阈值要留余量
- **cron crate 依赖复用**：data_sync 已用 `cron` crate，health_check 可直接复用 workspace 依赖，无新增
- **webhook 风暴**：多连接同时断（网络分区）→ 同时告警。drift 无此问题（per-connection 独立）。缓解：per-task 去重独立，不做全局合并（YAGNI，留给 receiver 侧）

## 开放问题（需用户决策）

1. **默认巡检间隔**：建议默认 cron = `*/10 * * * *`（每 10 分钟）。可接受？还是更稀疏（每 30 分钟 / 每小时）？
2. **连续失败阈值 N**：建议默认 N=3（连续 3 次失败才告警，防 flapping）。可接受？
3. **结果保留天数**：建议默认 30 天轮转。可接受？
4. **告警通道**：drift/data_sync 只支持单 webhook URL（`notify_channels` JSON 数组取第一个）。health check 是否需要多通道（同时发多个 webhook）？建议 v1 同 drift——单 URL，多通道留后续

> 注：这 4 个开放问题都有推荐默认值，我倾向在 requirements 阶段直接采纳推荐值（作为可配置项带默认），除非你想改。

## 结论

**我们决定做什么**：
- 新建 `crates/health_check`（BSL-1.1），架构抄 drift，新增 `HealthCheckRunner` bridge trait
- 核心 4 项指标（连通性+延迟 / 表行数估算 / 缺失主键 / 连接数），初版只支持 MySQL + PostgreSQL（其他库降级为仅连通性）
- 告警策略：阈值 + 连续 N 次防 flapping + Resolved 恢复通知 + 结构问题增量告警
- 新表：`health_check_results`（per-巡检一行）+ `health_alert_state`（告警去重状态）
- webhook schema = `dbmaster.health-event.v1`（仿 drift 契约结构）
- scheduler 用 cron_expr（复用 data_sync 的 cron crate）
- embedded 模式 NoopRunner（纯远程付费）
- 走 ADR-0004（新增 crate + bridge trait 扩展 = 架构决策）

**我们不做什么**（边界）：
- ❌ 全库支持（初版 MySQL+PG，其他库仅连通性降级）
- ❌ 多通道 webhook（v1 单 URL，同 drift）
- ❌ AI 驱动的指标分析 / 自愈（确定性规则告警，不碰 ADR-0002 §4.6 红线）
- ❌ 实时监控（cron 周期巡检，非 push 模式）
- ❌ desktop UI 集成（Server 端 + webhook，客户端集成是 M3 后半段，本 spec 不含）
- ❌ 指标历史图表（只存结果 + API 查询，可视化留后续）

**预估工作量**：~1,800-2,100 行 Rust + 1 个 migration + ADR-0004 + webhook 契约文档。比 drift（3,400 行）轻 ~40%（无 diff 引擎、无 snapshot 链、无 canonical hash）。

---

下一步：运行 `/dev-req` 进入需求澄清阶段，基于本文档产出 requirements.md。开放问题 1-4 会作为默认可配置项写入（带推荐默认值），除非用户在此阶段调整。
