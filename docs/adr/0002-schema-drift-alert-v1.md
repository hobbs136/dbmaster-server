# ADR-0002 — Schema Drift Alert v1（执行模型 A 锁定 · 源库凭据信任边界 · webhook 通知）

- **Status**: **Accepted**（2026-08-06，用户打包接受 §11 全部 5 项推荐）
- **Date**: 2026-08-06
- **Author**: architect（首席架构师）
- **Supersedes**: 无
- **Related**:
  - `ADR-0001`（license 系统；本 ADR 复用其 AES-256-GCM v1 凭据格式与 `DBMASTER_CREDENTIAL_KEY` 主密钥机制）
  - `.workflows/server-next-features/03-recommend.md`（本 ADR 的决策范围 + 落地路由）
  - `.workflows/server-next-features/02-evaluate.md`（EVALUATE 产出：C 作 v1 的 ROI 论证 + 双时序路径）
  - `.workflows/current-state.md`（H1–H5 约束、Server 现状核实）
- **Deciders**: 用户（打包接受 §11 全部推荐，2026-08-06）
- **Decision Record (2026-08-06)**: Q1=A（执行模型 A 锁定，Server 直连源库）/ Q2=A（复用 `DBMASTER_CREDENTIAL_KEY`）/ Q3=L1+L2（文档+UI 警告 + 创建时 canary 只读校验）/ Q4=A（MySQL + PostgreSQL）/ Q5=接受 `dbmaster.drift-event.v1` payload 草案。Status: Proposed → Accepted。

---

## 1. 背景与动机

### 1.1 商业与产品约束（已锁定，不在本 ADR 讨论范围）

- 经 `server-next-features` brainstorm，用户拍板**双时序 + 双轨**：
  - **v1 = 硬编码 schema drift 告警**（源库 schema 定时巡检 → 检测漂移 → 告警）。执行模型 = **A（Server 直连客户源库，读 schema）**。
  - **v2 = 机制+AI 重构（A′）**：5 分钟向导 / NL transform / 原语 DAG / 抗漂移。v1 的真实实例作为 forcing function 让原语边界涌现。
  - 双轨：v1 build ‖ 4 周 PMF validation。
- 目标客群、定价、分发、license 履约（离线 Ed25519 + 激活 API）—— 见 ADR-0001 §1.1，本 ADR 不重述。
- **当前零付费客户** → 决策可在干净起点上做，不必为存量重新签字。

### 1.2 现状 ground truth（已读源码核实，**修正 README 两处过时假设**）

| 项 | 现状 | 来源 |
|---|---|---|
| README 的"技术栈" | 撒谎：声称 `tokio-cron-scheduler`，实际 Cargo.toml 无此依赖、零行调度代码 | `dbmaster-server/README.md:112` vs `Cargo.toml` |
| sqlx features | **只开了 sqlite**（root 与 automation crate 同）；Cargo.lock 里的 sqlx-mysql/postgres 是未启用的传递依赖 | `Cargo.toml:41` / `crates/automation/Cargo.toml:12` |
| 出站 HTTP | **零**：无 reqwest/ureq/any-HTTP-client；任何 webhook/外部 API 调用都做不了 | `Cargo.toml` 全 grep |
| `run_task_now` | "假装跑完"：只 `UPDATE scheduled_tasks SET last_status='running'`，不执行任何东西 | `crates/automation/src/handler.rs:73` |
| `TaskExecutor` trait | 零实现（全仓库） | `crates/automation/src/lib.rs:135` |
| run history 表 | **不存在**；`scheduled_tasks` 只有 `last_status` / `last_run_at` 标量 | `migrations/002_automation.sql:25` |
| 凭据加密 | **已落地 ADR-0001 §4.8 D8**：`v1:<nonce_b64>:<ct+tag_b64>` AES-256-GCM；AAD = `b"dbmaster-credential-v1"`；主密钥 `DBMASTER_CREDENTIAL_KEY` env var，生产 fail-fast | `crates/automation/src/credential.rs` / `src/main.rs:89` |
| automation 路由鉴权 | **缺失**：无 `Claims` 中间件、`created_by` 硬编码 `"system"`、entitlement gate 建好但**没接线**（trial 过期仍可调所有 automation API） | `crates/automation/src/lib.rs:146` / `crates/automation/src/handler.rs:148` |
| 现有 `database_connections` 表 | 通用连接表（db_type/host/port/username/password_encrypted/...），已存 AES-256-GCM v1 密文；当前无任何执行路径会读它 | `migrations/002_automation.sql:5` / `crates/automation/src/credential.rs` |

**结论**：v1 schema drift 告警不是"加个功能"，是**先补地基（出站 HTTP / 最小调度器 / run history / automation 鉴权 + gate 接线）再叠 drift 引擎**。地基项在 §8 DoD 中是 P0。

### 1.3 与 ADR-0001 的关系

ADR-0001 已解决 license 系统（含 `DBMASTER_CREDENTIAL_KEY` 主密钥与 AES-256-GCM v1 凭据格式）。本 ADR 不改 license 系统，但**扩大凭据信任边界**（Server 从"持本地协作 DB 凭据"扩到"持客户源库凭据，跑出去读 schema"），并复用 ADR-0001 的加密机制——见 §4 D2。

### 1.4 已识别的契约漂移（**问题报告，本 ADR 不擅自修改**）

> README 的"技术栈表"声称用 `tokio-cron-scheduler`——这是 `current-state.md` 已记录的"README 撒谎"问题。本 ADR §4 D7 给出 v1 真实调度器选型；§8 C-15 包含"修正 README"。

---

## 2. 决策驱动因素（按优先级）

1. **定律 1（个人维护成本）**：能复用栈内已有件（sqlx / tokio / AES-256-GCM v1 / 现有 `database_connections` 表）则不新造；不引入新语言运行时 / 新服务；新 crate 依赖从严评估。
2. **定律 5（安全/数据完整性）**：源库凭据 = 客户资产，敏感度 ≥ 本地协作 DB 凭据；只读 + 最小权限；参数化查询；凭据不进日志；审计每次凭据解密使用；webhook payload 不含 PII / 凭据 / 行数据。
3. **定律 2（契约单向演化）**：跨组件契约（webhook payload、源库账号权限要求）只加不删；v1 发布后客户会基于 payload schema 建接收端，schema 形态一旦发布即不可逆。
4. **定律 3（依赖单向）**：`site → server`、`client → server`。本 ADR 不引入新依赖方向；桌面端只读 Server 的 drift 配置/告警展示。
5. **定律 4（不可逆走 ADR）**：本文件即 ADR；可逆决策（如表名、cron 解析器细节）不在此赘述。
6. **H3 跑道（Dec 2026 兼职）**：v1 只做最小可行；机制+AI / transform / 数据搬运留 v2（§4 D5）。
7. **诚实用户模式**（ADR-0001 §1.1）：不与决定的破解者对抗。源库凭据是客户主动录入的，客户 trust boundary 自担；我们尽到加密/审计/最小权限的工程责任。

---

## 3. 范围

**IN**：
- v1 schema drift 告警全链——执行模型 A 锁定、源库凭据信任边界、schema 采集、drift 检测、webhook 通知、最小调度器、run history、automation 鉴权 + gate 接线。
- 产品根基原则的确立（即便 v1 无 AI）。

**OUT**（明确排除，§4 D5 形式化）：
- 机制+AI 策略层（A′；v2）。
- Transform / 数据搬运（ELT/ETL；v2，且 v1 不锁该决策）。
- 数据行读取（v1 只读 schema 元数据，绝不读业务数据）。
- 多目标 / 多源同步、增量同步（v2）。
- 飞书/钉钉/邮件通道（v2；v1 仅 webhook）。
- 桌面端 drift UI 的视觉/交互细节（属 senior-ui-ux-designer + senior-desktop-engineer；本 ADR 只给契约约束）。
- 支付/定价/license（ADR-0001 范围；本 ADR 不动）。

---

## 4. 决策

每条决策给出 2–3 个选项 + 取舍 + 推荐。**标记 🔴 的决策需用户拍板**（定律 5）。本 ADR 引入 `DECIDE:` 前缀标注用户决策项，对应 §11 开放问题。

### 4.1 D1 — 执行模型 A 锁定 🔴

**问题**：v1 schema drift 告警的执行架构——Server 直连客户源库，还是桌面代理执行？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. Server 直连客户源库读 schema** | Server 持源库凭据，定时 `information_schema`/`pg_catalog` 查询 | + "告警必须即使桌面关着也能发"——Server always-on 才是 drift watch 的正确载体；schema 读轻量短连，不要求桌面在线；与现有 `database_connections` 模型一致；− 客户必须开放 Server → 源库 的网络/防火墙；凭据信任边界扩大（D2） |
| B. 桌面代理执行 | Server 不持源库凭据，下发任务给在线桌面客户端跑 | + 客户源库凭据不出桌面；− **桌面关着 = 告警停摆**，对"drift watch"这个 always-on 场景是 deal-breaker；桌面 → Server → 桌面的状态机复杂度（H3 跑道不可控） |
| C. 混合：Server 读 schema，桌面做 data 类操作 | schema watch 走 A；数据搬运类任务（v2 sync）走 B | v1 不涉及数据搬运，C 与 A 在 v1 等价；C 的 B 半边是 v2 决策，本 ADR 不锁（与 §4 D5 一致） |

**推荐 A（v1 范围内锁定）**。理由：
- "Drift 告警"语义 = "我没看着的时候帮我盯着"——必须 always-on；桌面不是 always-on。
- 桌面端已有 schema diff 是**手动触发**工具（用户点一下，比一次），与"定时巡检"语义不同；v1 是给桌面 diff **喂数据**（已验证的漏斗下游），不是替代它。
- 现有 `database_connections` 表已是"Server 持凭据"模型；v1 复用，无新模型。

**🔴 需用户拍板（DECIDE: D1）**。理由是**不可逆性**（非"哪个更好"）：
- 客户必须开放 Server → 源库 的网络；一旦 N 个客户部署，切换到模型 B = 每个客户重新改网络拓扑 + 凭据存放策略。
- "Server 持客户源库凭据" 是一种**对外承诺**——即使零客户，发布后第一份订单签出就锁死。
- 注：锁定 A 不杀 B 永久——v2 数据搬运类任务（sync）仍可走 B（桌面在客户内网访问 OLAP）。A 是 **v1 schema-watch 场景的**锁定，不是全产品全场景的锁定。

---

### 4.2 D2 — 源库凭据信任边界（4 子决策）

#### D2.1 存储格式：复用 ADR-0001 AES-256-GCM v1？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. 复用 `encrypt_v1` / `decrypt_password` 与现有 `database_connections` 表** | 同一 `v1:<nonce>:<ct+tag>` 格式，同一张表，源库连接只是新增的行 | + 定律 1（复用）；ADR-0001 加密机制已实现 + 测试 + 迁移脚本已就绪；− 表语义从"协作 DB 凭据"扩到"协作 + 源库"，需 `purpose`/`kind` 字段区分（见下） |
| B. 新建 `source_db_credentials` 表 + 同格式 | 同样 AES-256-GCM v1，但独立表 | − 表分裂带来 join 复杂度；现有 `database_connections` 已是泛化模型（`db_type` 字段），无收益 |
| C. 新格式（如 `v2:...`）独立加密 | 重新设计 | 过度设计；现有格式无缺陷 |

**推荐 A**。无争议，符合所有定律。**不需用户拍板**。

**实现约束（写入实现派单，不在本 ADR 锁细节）**：
- `database_connections` 表加 `kind` 字段（`'collab'` / `'source_drift'`），区分用途以驱动凭据使用审计策略（D2.4）。
- AAD 仍用 `b"dbmaster-credential-v1"`（同格式同 AAD）；按连接行 id 的隔离由 DB 行实现，不需 AAD 变体。

#### D2.2 主密钥：复用 `DBMASTER_CREDENTIAL_KEY` 还是独立？🔴

**问题**：源库凭据的 AES-256-GCM 主密钥——复用 ADR-0001 已部署的 `DBMASTER_CREDENTIAL_KEY`，还是新设 `DBMASTER_SOURCE_DB_KEY`？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. 复用 `DBMASTER_CREDENTIAL_KEY`** | 所有 DB 凭据（协作 DB + 源库）共用一把 32 字节主密钥 | + 单一密钥备份/轮换；运维简单（定律 1）；ADR-0001 已建立 bootstrap（env 注入、生产 fail-fast、sha256[:4] 指纹核对）；− 爆炸半径耦合：主密钥泄露 = 所有客户凭据泄露（但客户源库凭据与协作 DB 凭据同敏感度，"分密钥"也救不了主密钥泄露本身） |
| B. 独立 `DBMASTER_SOURCE_DB_KEY` | 两把主密钥，各管一类 | + 按用途隔离；− 多一个 env var、多一份备份；源库凭据并不比协作 DB 凭据更敏感，"分钥"是仪式感而非实质安全增益 |
| C. 主密钥 + HKDF 派生子密钥 | 一把主密钥，按 label 派生 | + 密码学最优；− 多一层 HKDF 代码 + 测试；零客户阶段过度设计（定律 1）。**淘汰** |

**推荐 A（复用 `DBMASTER_CREDENTIAL_KEY`）**。理由：
- 源库凭据与现有协作 DB 凭据**同敏感度等级**（都是客户 DB 密码），"分密钥"不增加实质安全，只增加运维负担。
- 真正的安全增益来自**使用侧的审计 + 最小权限账号**（D2.3 / D2.4），不是加密侧的分钥。
- ADR-0001 已建立 bootstrap 与 fail-fast；复用即零新代码。

**🔴 需用户拍板（DECIDE: D2.2）**。理由：凭据安全策略 + 客户信任对外承诺。即便零客户，发布即锁死（切换密钥模型 = 全客户重录凭据）。

#### D2.3 源库账号 = 只读 + 最小权限：强制级别？🔴

**问题**：v1 是否/如何强制客户给 Server 用的源库账号是只读 + 最小权限？

| 选项（强制级别） | 描述 | 取舍 |
|---|---|---|
| L1. **文档 + UI 警告** | README + 创建连接 UI 显著提示"必须建一个只读账号，只授 `information_schema` / `pg_catalog` 的 SELECT 权限，不给任何业务库 SELECT" | + 零额外代码；− 依赖客户自觉；客户误用 DBA 账号 = Server 持全权凭据，全表读权限 |
| L2. **创建时 canary 校验** | `create_connection`（kind=source_drift）时跑一次"安全负面测试"——尝试一个必然失败的写操作（如 `CREATE TEMPORARY TABLE dbmaster_canary (...)`)，**期望失败**；若成功则拒绝保存 | + 工程层兜底，不依赖自觉；− 实现 + 测试成本（每种 DB 类型一个 canary）；canary 逻辑要保证"即使客户真给了写权限也不会污染源库"（用 TEMPORARY + ROLLBACK 事务） |
| L3. **周期性 canary** | 调度器每次跑都先验证账号仍只读 | 过度设计，每次巡检多一次往返；诚实用户场景下不值得。**淘汰** |

**推荐 v1 = L1 + L2**。理由：
- L1 是底线（无成本，必有）。
- L2 把"误用 DBA 账号"这个最常见风险挡在门外，符合定律 5（数据完整性不"以后再说"）。
- L2 实现要点（写入实现派单，不在此锁）：canary 必须自身无副作用（TEMPORARY table / transaction rollback）；canary 失败本身要可解（错误信息告诉客户"请改账号权限"）；canary 不读业务数据。
- v1 不做 L3。

**🔴 需用户拍板（DECIDE: D2.3）**。理由：客户对外承诺 + 安全基线 + 影响 v1 发布范围（选 L1-only 可早一周发布，选 L1+L2 推迟但更稳）。

#### D2.4 凭据访问审计

**问题**：每次 Server 解密源库凭据并使用，记什么、存哪？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. 新表 `credential_access_audit`** | `(id, connection_id, action, status, error, at, triggered_by)`；每次解密使用都记一行 | + 独立可查；定律 5（凭据使用可观测）；− 一张新表 + 写入逻辑 |
| B. 复用 `telemetry_events` | 把审计事件塞进现有 telemetry 表 | − telemetry 是"产品漏斗"语义，混进"安全审计"语义混乱；保留期/导出策略不同 |
| C. 仅日志（tracing） | 不入库，只 `tracing::info!` | − 日志易丢、难查；无法做"列出过去 7 天某连接的所有访问"查询 |

**推荐 A（新表 `credential_access_audit`）**。理由：
- 安全审计与产品 telemetry 是两个语义世界，不混。
- 审计是定律 5 的可观测底线（"Server 何时用了哪条源库凭据"必须可查）。

**字段（写入实现派单）**：
```sql
CREATE TABLE credential_access_audit (
    id            TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    action        TEXT NOT NULL,   -- 'schema_snapshot' | 'drift_compare' | 'canary_check' | 'webhook_deliver'
    status        TEXT NOT NULL,   -- 'ok' | 'error'
    error         TEXT,            -- 失败时的概要错误（不含凭据/SQL/PII）
    at            TEXT NOT NULL,
    triggered_by  TEXT NOT NULL    -- 'scheduler' | 'manual:<user_id>'
);
```

**审计约束**：
- **不记**：凭据本身、解密后明文、SQL 文本、源库返回的任何数据、PII。
- **记**：哪条连接、何时、什么动作、成败、概要错误。

D2.4 不需用户拍板（可逆：表结构可改）。

---

### 4.3 D3 — Schema 采集方式 + v1 源库类型范围 🔴

**问题**：v1 怎么采 schema，支持哪几种源库？

#### 4.3.1 采集方法

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. 标准 `information_schema` + `pg_catalog` 轮询** | MySQL/PG 都查 `information_schema.tables/columns/statistics/key_column_usage`；PG 额外查 `pg_catalog`（pg_class/pg_attribute/pg_index）补索引细节 | + SQL 标准、稳定、不依赖 DBA 权限；跨两种库 SQL 主体相似；− 信息 schema 在老版本 MySQL/部分 PG 修饰语上偶有差异，需测试矩阵 |
| B. 桌面已有 schema diff 引擎复刻 | 把桌面 Dart 的 schema diff 拉到 Rust | 重写 + 维护两份；Rust 端从零开始 |
| C. 用第三分 schema-introspect crate | 引入新依赖 | 引入新依赖（定律 1）；与 sqlx::Any 思路类似但更重 |

**推荐 A**。理由：标准、稳定、复用 sqlx。

**采集粒度（v1）**：库 / 表 / 列（name, ordinal, data_type, is_nullable, column_default, 字符长度/精度）/ 主键 / 索引（name + 列序）/ 外键。**不采集**：视图、存储过程、触发器、行数据、行数（v1）。

**Drift 检测算法**：
- 每连接存最近一次 `schema_snapshots` 行（canonical JSON + sha256 hash）。
- 新一轮采集 → canonical JSON → sha256 → 与上一行 hash 比。
- Hash 不变 → 无 drift；Hash 变 → 对 JSON tree 做结构 diff，枚举具体 drift（kind + object + before + after）。

**存储（写入实现派单）**：
```sql
CREATE TABLE schema_snapshots (
    id            TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    captured_at   TEXT NOT NULL,
    schema_hash   TEXT NOT NULL,    -- sha256 of canonical JSON
    schema_json   TEXT NOT NULL,    -- canonical JSON（不含行数据）
    prior_hash    TEXT,             -- 链式审计：上一次的 hash
    task_id       TEXT,             -- 哪个 task 触发的（可空 = manual）
    change_count  INTEGER NOT NULL DEFAULT 0  -- 与 prior_hash 比，变化项数；首 snap = 0
);
CREATE INDEX idx_snapshots_conn_time ON schema_snapshots(connection_id, captured_at DESC);
```

#### 4.3.2 v1 源库类型范围

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. MySQL + PostgreSQL** | v1 仅这两种 | + 覆盖目标客群（2–5 人开发团队）绝大多数主力库；信息 schema 接口相似；sqlx 已在栈内（加 mysql/postgres feature 即可）；− SQLServer/Oracle/Mongo/Redis 用户被排除（v2 引） |
| B. MySQL + PG + SQLServer | 三种 | − SQLServer 需要 `sqlx` 的 mssql 支持（不稳定，且非 sqlx 主流维护方向）或新 crate；v1 时间不可控 |
| C. 仅 MySQL 或 仅 PG | 一种 | − 单一覆盖太窄；客户场景常见两种并存 |

**推荐 A（MySQL + PostgreSQL）**。理由：
- 覆盖目标客群主力（H2 客群 + EVALUATE §5 PM ROI 分析）。
- sqlx 加 mysql/postgres feature = 一个 Cargo.toml 改动，无新 crate family（定律 1）。
- 老版本支持范围（写入实现派单）：MySQL 5.7+ / PG 12+（信息 schema 稳定基线）。

**🔴 需用户拍板（DECIDE: D3）**。理由：v1 客户对外承诺范围 + marketing/sales 落地页口径。可逆（v2 可加），但 v1 发布后"我们支持 X"是市场声明。

---

### 4.4 D4 — 通知渠道 v1 = webhook + payload 契约 🔴

**问题**：v1 drift 告警通过什么通道发？payload schema 是什么？

#### 4.4.1 通道选型

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. v1 仅 generic webhook（HTTP POST JSON）** | 通用 webhook；客户接收端自便（飞书/钉钉/Slack/自建都靠它） | + 最通用；客户方灵活；一个通道测/文档/支持；飞书/钉钉自身有 webhook 入口可适配；− 客户需自配接收端（但目标客群是开发团队，门槛低） |
| B. v1 同时做飞书 + 钉钉 + webhook | 三通道并行 | − 三份适配 + 三份测试 + 三份文档；H3 跑道不值得；webhook 已能涵盖飞书/钉钉 |
| C. v1 仅邮件 | SMTP | − 邮件投递/反垃圾/模板复杂度高于 webhook；离 ADR-0001 D7 的续费邮件 cron 重复建设 |

**推荐 A（v1 仅 generic webhook）**。无争议，符合定律 1 + H3。

#### 4.4.2 Webhook payload 契约草案（v1）

**这是跨组件契约（定律 2）——一旦发布，客户会基于此 schema 建接收端，schema 形态不可逆。**

```json
{
  "schema": "dbmaster.drift-event.v1",
  "event_id": "<uuid>",
  "event_at": "<RFC3339/ISO8601>",
  "instance_uuid": "<server install_uuid>",
  "task": {
    "id": "<scheduled_task_id>",
    "name": "<human label>"
  },
  "connection": {
    "id": "<connection_id>",
    "name": "<human label>"
  },
  "source": {
    "db_type": "mysql | postgres",
    "database": "<db name>"
  },
  "drift_summary": {
    "prior_snapshot_at": "<RFC3339 or null>",
    "new_snapshot_at": "<RFC3339>",
    "change_count": <int>,
    "kinds": {
      "table_added": <int>,
      "table_dropped": <int>,
      "column_added": <int>,
      "column_dropped": <int>,
      "column_type_changed": <int>,
      "column_nullability_changed": <int>,
      "index_added": <int>,
      "index_dropped": <int>,
      "pk_changed": <int>,
      "fk_added": <int>,
      "fk_dropped": <int>
    }
  },
  "drifts": [
    {
      "kind": "table_added | table_dropped | column_added | column_dropped | column_type_changed | column_nullability_changed | index_added | index_dropped | pk_changed | fk_added | fk_dropped",
      "object": {"schema": "<...>", "table": "<...>", "column": "<...>", "index": "<...>"},
      "before": "<JSON value or null>",
      "after":  "<JSON value or null>"
    }
  ]
}
```

**硬性排除（不进 payload；DEFENSIVE-NOTE + 定律 5）**：
- 连接 host / port / user / password（任何形式）。
- 源库行数据（drift 检测只读 schema 元数据，本来就不读业务数据）。
- PII：不收 / 不发 客户业务数据；`instance_uuid` 是 Server 随机 uuid（非 PII）；`task.name` / `connection.name` 是客户自命名（客户责任）。

**投递语义**：
- HTTP POST，`Content-Type: application/json`，`User-Agent: dbmaster-server/<ver> drift-webhook`。
- 超时 10s（推荐 `DBMASTER_DRIFT_WEBHOOK_TIMEOUT_SECS`，默认 10）。
- 重试：3 次，指数退避（1s / 4s / 16s）；HTTP 2xx 视为成功，其他（含 3xx/4xx/5xx/超时）视为失败重试。
- 永久失败：写 `task_run_history.error` + WARN 日志；不静默吞（定律 5）。
- 幂等：每事件带唯一 `event_id`，接收端可去重；同一 drift 不会被发两次（drift 触发条件 = `change_count > 0 AND prior_hash != new_hash`，每次新 hash 触发一次）。
- URL 配置：**每 task 单独配置**（复用现有 `scheduled_tasks.notify_channels` JSON 数组，v1 读第一项为 webhook URL）；无 env var 全局默认（避免"忘了改"导致测试 webhook 发到生产）。
- URL 必须 https（生产模式 fail-fast）或 `http://localhost` / `http://127.0.0.1`（开发模式允许）；拒绝其他 http URL（定律 5：凭据/payload 不走明文链路）。

**🔴 需用户拍板（DECIDE: D4）**。理由：跨组件契约（payload schema）一旦发布不可逆。建议用户重点看：
- 字段集合是否够客户用（漏字段比加字段难补，定律 2）。
- `kinds` 枚举（v1 锁这 11 种 drift kind；新 kind 在 v2 加，按"只加不删"演化）。
- 是否需要 `drifts[]` 全量明细（v1 给全量；如果 change_count > 某阈值，是否截断 + 给 summary only？建议 v1 不截断，drift 一次通常少量）。

---

### 4.5 D5 — v1↔v2 边界声明（写入 ADR 防后续松动）

**问题**：防止 v1 build 期 scope creep（"顺手做个小 transform 吧"、"加一点点 AI 提议"）。

**v1 显式 OUT 清单（写入 ADR，约束所有 v1 实现派单）**：

| 类别 | v1 不做 | 延后到 |
|---|---|---|
| 机制层 | DB-ops 原语 DAG（connect/read/transform/write/diff/schedule/branch/notify/assert/checkpoint） | v2 A′ |
| AI 层 | NL transform / 自动 join 推断 / AI 建议断言 | v2 A′ |
| 数据搬运 | ELT / ETL / sync / 多源多目标 / 增量同步 | v2 |
| **数据行读取** | v1 只读 schema 元数据，**绝不**读业务表行数据 | 永远不（drift watch 场景本身不需要） |
| Transform | join / 聚合 / 字段计算 / 脱敏 / 行过滤 | v2 A′ |
| 通道 | 飞书 / 钉钉 / 邮件 / Slack | v2 |
| 源库类型 | SQLServer / Oracle / MongoDB / Redis | v2+ |

**关键边界**：
- **ELT vs ETL 决策 v1 不锁**（architect 在 EVALUATE 的 open question）：v1 不搬数据，所以这个 fork 留给 v2 决。本 ADR 不预设答案。
- **机制层在 v1 不预埋**：v1 就是硬编码（schema 采集 → diff → webhook），不抽象"原语"。Unix 教训（EVALUATE §4）：用 v1 真实实例涌现原语边界，不先造通用机制。
- **drift watch 本身不会自然演化成 sync**：v1 的 schema 读 → diff → notify 与 sync（读数据 → 写数据）是两个 trust boundary；后者是 v2 独立决策（甚至可能走模型 B，§4 D1 注）。

**为什么放进 ADR**：ADR 是不可逆决策的书面承诺。把"v1 不做 X"写进 ADR，后续任何"加一点 X"的冲动都需先回 ADR 改决策（触发用户拍板，定律 5），不是工程师顺手改。这是 EVALUATE 双时序路径（v1 硬编码 → v2 机制+AI）的契约化保护。

D5 不需用户拍板（用户已在 brainstorm 拍板"v1 不做 A′"；本节是契约化）。

---

### 4.6 D6 — 产品根基原则：「AI 设计期提议 / 运行期确定性执行」

**问题**：即便 v1 无 AI，是否现在就把"AI 在设计期 / 机制在运行期"立为产品根基原则？

**原则声明**（写入 ADR，作为未来 v2 AI 引入时的不可破红线）：

> **dbmaster Server 的 DB 操作执行模型：AI 仅在用户配置的设计期提议；运行期由确定性机制执行。AI 不在运行期决定执行什么。**

含义：
- **设计期**（用户在线、有上下文、可审核）：AI 可提议——"建议这个 transform"、"建议这个 schedule"、"这里加个 assert"。提议经用户审核/编辑后落为确定配置。
- **运行期**（调度器触发、用户可能离线）：执行的是**用户已确认的确定性配置**——同一输入永远产生同一行为；可审计、可回放、可回滚。
- **AI 不在运行期决定**：调度器不会"问 AI 这一次要不要发告警"；不会"AI 看到结果觉得不对就改 SQL 跑"；不会"AI 决定跳过某个 assert"。

**为什么 v1 立此原则**：
- v1 无 AI，但 v2 引入 AI 时（A′）必有"加一点运行期 AI 判断"的诱惑（如"AI 看一眼 drift 决定要不要发"）。本原则把这条线画在 ADR 层级。
- 这是 R3（AI 错 SQL 静默污染）的预防性根本解——AI 不在运行期决定，就没有"运行期 AI 出错"。
- 安全框架：preview / assert / audit 是机制层组件（v2），但即便机制层尚未实现，"AI 设计期 / 机制运行期"原则现在就生效——v1 任何代码都不能引入"运行期 AI 判断"。

**v1 落地**：v1 完全确定性（采 schema → diff → webhook），无任何"判断"环节。本原则对 v1 是"什么都没限制"，但对所有未来版本是红线。

D6 不需用户拍板（用户已在 brainstorm 拍板此原则；本节是契约化）。

---

### 4.7 D7 — 调度器选型（修正 README 谎言）

**问题**：v1 用什么调度器跑 drift 巡检？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. `tokio::time::interval` + 单进程内扫描** | 单个 tokio task：每 N 分钟扫一次 `scheduled_tasks WHERE enabled=1 AND task_type='schema_drift'`，按 `last_run_at` 判断是否到期，触发采集 | + 零新依赖（tokio 已在栈内 full features）；最小可行；− 只支持"每 N 分钟"语义，不解析 cron 表达式 |
| B. `tokio-cron-scheduler` crate | 引入 README 谎称但实际没装的 crate | + 完整 cron 表达式；− 新依赖（定律 1 评估：cron 解析 + scheduler task 管理 + 自身 bug 面）；v1 客户需求未必到"cron 表达式"层级 |
| C. 手写 cron 解析器 | 自己实现 `*/N * * * *` 子集 | − 重复造轮；解析器 bug 面大 |

**推荐 A（v1 用 `tokio::time::interval`）**。理由：
- v1 客户需求 = "每 5 分钟 / 每 30 分钟 / 每小时"——间隔语义足够。
- 现有 `scheduled_tasks.cron_expr` 字段 v1 不解析；改为读 `config` JSON 里的 `interval_minutes`（每 task 自配）。
- 全局兜底 `DBMASTER_DRIFT_DEFAULT_INTERVAL_MINS` env var（默认 30），单 task 可在 config 覆盖。
- 零新依赖，符合定律 1。

**触发未来切换到 B 的条件**（写入 ADR 作为 v2 升级触发器，而非现在做）：
- 客户要求"每天 02:00 跑一次"等时点语义（间隔表达不了）。
- 或 ≥3 种不同调度模式被客户明确要求。
- 触发时：先评估 `tokio-cron-scheduler`，无替代更轻量选择才引；同时修正 README（C-15 在 v1 就要改，无论是否切 B）。

**调度器约束**（写入实现派单）：
- 单进程模型（v1 不考虑多副本；多副本 = 同一 task 多次跑，需分布式锁，过度设计）。诚实用户模式接受单进程；多副本部署文档化为"v1 不支持"。
- 重启安全：Server 重启后基于 `scheduled_tasks.last_run_at` 决定是否补跑；不补跑（drift 不补跑是合理的——错过的窗口就错过，下一次巡检自然会发现）。**v1 不做 missed-run 补跑**。
- 并发自保护：同一 task 上一次还没跑完，下一次 interval 触发时跳过（不堆积）。

**§1.4 契约漂移修复**：v1 实现派单的 DoD（C-15）必须修正 README 的"tokio-cron-scheduler"声称，改为反映 v1 真实（`tokio::time::interval`），或标"planned: v2"。

D7 不需用户拍板（内部选型 + 可逆：换调度器是内部 refactor）。

---

## 5. 推荐方案汇总（一条命令版）

> 假设用户在 §11 全部采纳推荐：

**执行模型**：Server 直连客户源库读 schema（D1=A）。不可逆——客户开放 Server→源库 网络 + 持源库凭据的 trust model。

**凭据信任边界**：
- 格式复用 AES-256-GCM v1 与 `database_connections` 表（D2.1=A）；`database_connections` 加 `kind` 字段区分协作 vs 源库连接。
- 主密钥复用 `DBMASTER_CREDENTIAL_KEY`（D2.2=A）。
- 源库账号 = 只读 + 最小权限，文档 + UI 警告 + 创建时 canary 校验（D2.3=L1+L2）。
- 新表 `credential_access_audit` 记每次凭据使用（D2.4=A）。

**Schema 采集**：MySQL + PG（D3=A），`information_schema` + `pg_catalog` 轮询；新表 `schema_snapshots` 存 canonical JSON + sha256 hash + 链式 prior_hash；diff 算法 = hash 比 + JSON tree diff。

**通知**：v1 仅 generic webhook（D4=A）；payload = `dbmaster.drift-event.v1` schema；HTTPS 强制；3 次指数退避；永久失败入 `task_run_history`；URL 每 task 自配。

**v1↔v2 边界**：机制+AI / transform / 数据搬运 / 多源多目标 / 飞书钉钉邮件 / SQLServer/Oracle 等全 OUT（D5）；"AI 设计期提议 / 运行期确定性执行"立为产品根基原则（D6）。

**调度器**：`tokio::time::interval` 单进程扫描（D7=A）；`scheduled_tasks.cron_expr` 字段 v1 不解析，改读 `config.interval_minutes`；单 task 上一次未完成则跳过；不补跑。

**地基修复**：automation 路由加 `Claims` 鉴权 + entitlement gate 接线（H5/R5 必修）；新增 `task_run_history` 表；引入 `reqwest` 出站 HTTP（仅 rustls + json feature，避免 openssl 链接痛点）。

---

## 6. 安全考量（定律 5 全条对照）

| 资产 | 威胁 | 缓解 |
|---|---|---|
| 源库凭据（客户 DB 密码） | DB 文件被偷 → 凭据泄露 | AES-256-GCM v1（复用 ADR-0001）；主密钥 env var 不入库；canary 校验确保账号只读 |
| 源库凭据使用 | Server 内部滥用（拿凭据去读业务数据 / 写） | D2.3 只读账号 canary；D2.4 审计表每次使用；v1 代码路径**只读 information_schema/pg_catalog，绝不查业务表**（实现派单硬约束 + 测试覆盖） |
| 源库连接 | Server 被入侵 → 攻击者用源库凭据横向访问客户源库 | 同上 + 源库账号最小权限（只读 metadata）；canary 在 create 时校验；审计可定位异常访问模式 |
| Drift payload | webhook 链路被中间人窥探 | URL 必须 HTTPS（生产 fail-fast）；payload 不含凭据/PII/业务数据（§4.4.2 硬排除）；接收端 URL 客户自管 |
| Webhook URL 泄露 | 攻击者用 webhook URL 投递伪造告警 | URL 不入库日志；payload 带 `instance_uuid` + `event_id`（接收端可校验）；v1 不做签名（v2 加 HMAC 签名头；本 ADR 标记为 v2） |
| 出站 HTTP 被滥用 | SSRF（攻击者配置内网 URL 让 Server 探） | URL 必须 HTTPS（已约束）；拒绝 `localhost`/`127.0.0.1` 在生产模式（仅 dev 模式允许）；v1 不做 SSRF allowlist（v2 评估） |
| 日志泄露 | 日志含凭据 / SQL / PII | tracing 全代码审计；schema_json 入库但不入日志；`tracing::debug!` 禁止打印 schema_json 全文（只打 hash + change_count）；审计表只记概要 |
| 多步操作回滚 | schema 采集 → diff → webhook 多步失败留脏 | `task_run_history` 记每步状态；schema_snapshots 写入是 append-only（不删 prior）；webhook 失败不回滚 snapshot（drift 已发生是事实，告警失败要重试不是回滚）；幂等：drift 触发条件 = hash 变化，重复跑同一 hash 不重发 |
| 调度器空窗口 | Server 重启期间 drift 发生但未捕获 | v1 接受：重启后基于 `last_run_at` 跳过空白窗口，下一次自然捕获；不补跑（drift 已存在 → 下次 snapshot 会发现，告警略迟但不漏） |
| 参数化查询缺失 | SQL 注入（schema 名拼接） | 所有 schema 采集 SQL 用参数化（`sqlx::query` + `.bind`）；连接 row id 等内连接参数也走 bind；**禁止** `format!("/{}", conn_id)` 拼接 |
| 输入校验缺失 | 客户录入畸形 webhook URL / interval | URL 必须 https（生产 fail-fast）；interval `u32` 范围 1..=1440（1 分钟到 24 小时）；超出范围拒绝保存 + 返回明确错误 |

---

## 7. 跨组件影响

### 7.1 dbmaster-server（Rust）

- **Cargo.toml**：
  - 加 `sqlx` 的 `mysql` + `postgres` feature（root + automation crate）。
  - 加 `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }`（仅 rustls + json，避免 OpenSSL 链接痛点）。
  - **不加** `tokio-cron-scheduler`（修正 README）。
- **新表**（新 migration `005_drift_v1.sql`，编号续 `004_telemetry_funnel.sql`）：
  - `schema_snapshots`（§4.3.1 草案）。
  - `credential_access_audit`（§4.2.4 草案）。
  - `task_run_history`（§4 D7 + DoD C-9）：
    ```sql
    CREATE TABLE task_run_history (
        id           TEXT PRIMARY KEY,
        task_id      TEXT NOT NULL REFERENCES scheduled_tasks(id) ON DELETE CASCADE,
        started_at   TEXT NOT NULL,
        finished_at  TEXT,
        status       TEXT NOT NULL,    -- 'running' | 'succeeded' | 'failed'
        error        TEXT,
        summary      TEXT,             -- JSON: {"drift_count": N, "webhook_status": "ok|failed", "duration_ms": M}
        triggered_by TEXT NOT NULL     -- 'scheduler' | 'manual:<user_id>'
    );
    CREATE INDEX idx_run_history_task_time ON task_run_history(task_id, started_at DESC);
    ```
  - `database_connections` 加列 `kind TEXT NOT NULL DEFAULT 'collab'`（D2.1）。
- **新 crate `drift`**（推荐独立 crate 而非 automation 子模块，因 drift 是独立领域 + 未来 v2 可能扩 sync/transform）：
  - `crates/drift/src/`：`collector.rs`（schema 采集） / `snapshot.rs`（canonical JSON + hash） / `diff.rs`（drift 检测） / `notify.rs`（webhook 发送） / `scheduler.rs`（interval 扫描） / `audit.rs`（凭据使用审计包装）。
  - 依赖 `dbmaster-core`、`dbmaster-automation`（复用 credential）、`sqlx`、`reqwest`、`tokio`、`serde`、`sha2`。
- **automation crate 改动**：
  - `routes()` 加 `Claims` 鉴权中间件层（H5/R5）。
  - `handler::create_connection` / `run_task_now` / 所有 mutation handler 接入 `entitlement gate`（trial/gated 状态下拒绝；H5）。
  - `run_task_now` 真的跑（不再只改状态）；目前 fake 实现作为 fallback 保留给非 drift 任务（其他 task_type 仍 stub）。
- **main.rs**：
  - 启动后 spawn `drift::scheduler::run(pool, state)` 作为后台 tokio task。
  - 优雅停机：tokio task 在 shutdown signal 时取消正在进行的 webhook（v1 接受"未发出的丢失"，重启后下一次 interval 不补发——因为 prior_hash 已更新）。
- **新 env var**（D7 + §6）：
  - `DBMASTER_DRIFT_DEFAULT_INTERVAL_MINS`（默认 30）。
  - `DBMASTER_DRIFT_WEBHOOK_TIMEOUT_SECS`（默认 10）。
  - 不加 `DBMASTER_DRIFT_WEBHOOK_URL`（per-task 配置，避免全局默认误发）。

### 7.2 dbmaster-tech-site（Go）

- **本 ADR 不改 tech-site 代码**。drift 是纯 Server 侧能力；license / 激活 / 续费链路（ADR-0001）不受影响。
- marketing 落地页与文案属 marketing 子代理范围，不在本 ADR。

### 7.3 dbmaster-flutter（Dart 桌面）

- 桌面端 drift 配置 UI + 告警展示属 senior-ui-ux-designer + senior-desktop-engineer 范围；本 ADR 只给契约约束：
  - 桌面读 Server `/api/tasks`（drift 任务列表）+ `/api/run-history`（运行历史）+ `/api/snapshots`（snapshot 浏览/diff 展示）。
  - 桌面创建 drift 任务：填源库连接、interval、webhook URL；调用 Server `/api/tasks` POST。
  - UI 不直接持源库凭据明文（凭据在 Server 端，桌面只见 masked）。
  - 桌面端已有 Schema Diff 工具继续作为"用户主动触发"工具存在；Server drift 告警与之**互补不替代**。
- 桌面 UI 需遵守 ADR-0001 的 entitlement 显示（trial/gated 状态下 drift 任务创建按钮 disabled + 引导激活）。

### 7.4 跨组件契约（本 ADR 新增/明确）

| 契约 | 形态 | 演化规则 |
|---|---|---|
| `dbmaster.drift-event.v1` webhook payload | §4.4.2 | 只加不删；新 drift kind 加在 `kinds` 枚举；`drifts[].kind` 复用同枚举；v2 加 HMAC 签名头（不破坏 v1 客户） |
| Server `/api/run-history`、`/api/snapshots` | 实现派单时定义 OpenAPI | 只加不删 |
| `database_connections.kind` 字段 | `'collab'` / `'source_drift'` | 只加新枚举值 |
| v1 源库类型范围 | MySQL 5.7+ / PG 12+ | v2 加 SQLServer 等不删现有 |

---

## 8. 售卖就绪清单（DoD — v1 schema drift 告警正式售卖前必须）

参照 ADR-0001 C-1..C-17 风格。**任一 P0 未完成则不可正式售卖**。

### P0（安全 / 数据完整性 — 定律 5 一票否决）

- [ ] **v1-C-1**. automation 路由全部加 `Claims` 鉴权中间件；`created_by` 从 `"system"` 改为实际 user_id（H5 / R5）。
- [ ] **v1-C-2**. entitlement gate 接线：所有 automation + drift mutation 路由在 `EntitlementState::Gated` 下拒绝（ADR-0001 C-7 P1 的延后项，v1 必须完成）。
- [ ] **v1-C-3**. 源库凭据使用 D2.1 复用 AES-256-GCM v1（已落地，主要审计 + 加 `kind` 字段）。
- [ ] **v1-C-4**. 源库账号只读强制（D2.3 用户拍板后的级别）：README + UI 警告（L1 必有）；如选 L2，canary 校验在 `create_connection(kind=source_drift)` 落地 + 测试。
- [ ] **v1-C-5**. `credential_access_audit` 表 + 每次凭据解密使用都记一行；测试覆盖（D2.4）。
- [ ] **v1-C-6**. grep 全代码库 + 日志路径，确认无源库凭据明文 / SQL 文本 / schema_json 全文 / webhook URL 入日志（定律 5）。
- [ ] **v1-C-7**. webhook URL 必须 HTTPS（生产 fail-fast）；dev 模式允许 localhost；payload 不含凭据/PII/业务数据（§4.4.2 硬排除）。
- [ ] **v1-C-8**. 所有 schema 采集 SQL 走参数化（`sqlx::query` + `.bind`），grep 确认无字符串拼接 SQL。

### P1（drift 功能正确性）

- [ ] **v1-C-9**. `task_run_history` 表 + drift 任务每次跑都写一行（started/finished/status/error/summary）；替换 `scheduled_tasks.last_status` 作为可观测主来源（标量字段保留做 UI 快速预览）。
- [ ] **v1-C-10**. `schema_snapshots` 表 + canonical JSON 序列化稳定（字段排序固定）+ sha256 hash 正确；单测覆盖。
- [ ] **v1-C-11**. drift 检测算法：hash 比 + JSON tree diff；测试矩阵覆盖 11 种 drift kind（§4.4.2 枚举）。
- [ ] **v1-C-12**. 真实 MySQL 5.7 / 8.0 / PG 12 / 14 / 16 测试库端到端跑通 schema 采集（verify.md 第 4 层：连真实测试库）。
- [ ] **v1-C-13**. webhook 投递：成功（2xx）/ 失败（3 次 exponential backoff）/ 永久失败（入 `task_run_history.error`）；测试覆盖所有路径。
- [ ] **v1-C-14**. 调度器：interval 扫描正确（基于 `last_run_at`）；同一 task 上一次未完成则跳过；重启不补跑；测试覆盖。

### P2（运营 / 体验 / 文档）

- [ ] **v1-C-15**. README 修正"tokio-cron-scheduler"声称；改写"技术栈"表反映 v1 真实（`tokio::time::interval` 或标 planned:v2）。
- [ ] **v1-C-16**. README/docs 加"源库账号权限要求"章节（D2.3 L1 文档部分）：MySQL `GRANT SELECT ON information_schema.*` / PG `GRANT SELECT ON information_schema...` 示例 + 最小权限原则说明。
- [ ] **v1-C-17**. 生产部署文档：`DBMASTER_CREDENTIAL_KEY` 已就位（ADR-0001 C-2）；本 ADR 新增 env var（`DBMASTER_DRIFT_DEFAULT_INTERVAL_MINS` 等）入文档。
- [ ] **v1-C-18**. webhook payload 契约文档落到 `dbmaster-server/docs/webhook-drift-event-v1.md`（定律 2：契约显式化）。
- [ ] **v1-C-19**. 桌面端 drift 配置 UI + 告警展示（senior-desktop-engineer + senior-ui-ux-designer）。
- [ ] **v1-C-20**. tech-site landing page 与 marketing 文案（marketing + sales 子代理）。

### P3（可延后到首个付费客户后）

- C-21. webhook HMAC 签名头（payload 完整性 + 接收端验签）。
- C-22. SSRF allowlist（限制 webhook URL 目标域）。
- C-23. `tokio-cron-scheduler` 升级（D7 触发条件满足时）。
- C-24. 飞书 / 钉钉 / 邮件通道（v2）。
- C-25. SQLServer / Oracle / MongoDB 支持（v2+）。

---

## 9. 验证计划（落地后）

按全局 verify.md 分级（本 ADR 属"跨组件/核心链路"→ 全 5 层）。

1. **静态**：`cargo clippy --workspace -- -D warnings`；新增 drift crate 单测覆盖 ≥80%。
2. **模块单测**：
   - `snapshot::canonical_json` 字段排序稳定（同 schema 两次采 → 同 hash）。
   - `diff::compute_drifts` 11 种 drift kind 各覆盖（before/after 枚举）。
   - `notify::deliver_webhook` 成功 / 超时 / 4xx / 5xx / 永久失败 / HTTPS 强制。
   - `audit::log_access` 写入正确，不含凭据/SQL/PII（grep 断言）。
   - `canary::check_readonly`（如 D2.3 选 L2）只读账号通过 / 写账号被拒 / 临时表 rollback 不污染。
3. **全量回归**：`cargo test --workspace`；automation 路由鉴权 + gate 接线后所有现有测试仍通过。
4. **行为验证**：
   - 手工：用 MySQL 5.7 + PG 14 测试库 → 录连接 → 创建 drift task → 改一条 column → 等下一个 interval → 验证 webhook 收到正确 payload → 验证 `schema_snapshots` 新行 + `task_run_history` 记录 + `credential_access_audit` 记录。
   - 手工：源库账号给错（DBA 权限）→ canary 拒绝保存（如选 L2）/ UI 警告显示（如选 L1）。
   - 手工：webhook URL 用 http://（非 localhost）→ 生产模式保存被拒。
   - 手工：trial 过期 → 所有 drift mutation 路由拒绝（gate 接线验证）。
   - 安全审计：grep 日志 + DB，确认无源库凭据明文 / SQL 文本 / schema_json 全文 / webhook URL 入日志。
5. **差异自审**：`git diff` 逐行，确认每处变更对应本 ADR 某条决策或 DoD 项。

---

## 10. 后续 ADR（本 ADR 不解决、但已识别）

- **ADR-0003（候选）**：ELT vs ETL 执行落点（architect 在 EVALUATE 的 open question）。v1 不锁，留给 v2 sync/transform 立项时解决。
- **ADR-0004（候选）**：机制层原语 DAG 设计（v2 A′）。v1 实例涌现边界后立项。
- **ADR-0005（候选）**：AI 集成边界（v2 A′）。落地 D6 原则的具体 AI 提议系统设计；外部 LLM 依赖（成本/ToS/隐私）= 不可逆决策。
- **ADR-0006（候选）**：webhook HMAC 签名与多通道扩展（v2，C-21/C-24 触发）。
- **ADR-0007（候选）**：调度器升级到 cron 表达式（v2，C-23 触发）。

---

## 11. 开放问题 — 需用户拍板（🔴 不可逆）

> 每条给出 architect 推荐 + 一句话理由。用户拍板后本 ADR Status → Accepted。

### Q1. 执行模型 A 是否锁定？（D1，DECIDE: D1）
- **推荐 A（Server 直连客户源库读 schema，v1 范围锁定）**。
- **理由**：drift watch 是 always-on 场景，桌面不是 always-on；锁定不杀 B 永久（v2 数据搬运可走 B）。
- **若用户选 B（桌面代理）的额外后果**：v1 复杂度爆炸（桌面 → Server → 桌面状态机），H3 跑道不可达；drift 告警在桌面关着时失效，与产品语义冲突。
- **不可逆性提示**：一旦发布 + 第一份订单签出 = 客户网络拓扑 + 凭据 trust model 锁定。

### Q2. 源库凭据主密钥是否复用 `DBMASTER_CREDENTIAL_KEY`？（D2.2，DECIDE: D2.2）
- **推荐 A（复用）**。
- **理由**：源库凭据与协作 DB 凭据同敏感度等级；分密钥是仪式感非实质安全；单一密钥备份/轮换运维简单。
- **若用户选 B（独立 `DBMASTER_SOURCE_DB_KEY`）的额外后果**：多一个 env var + 备份；无实质安全增益；automation 代码需重构为多密钥路由。

### Q3. 源库账号只读强制级别？（D2.3，DECIDE: D2.3）
- **推荐 L1 + L2**。
- **理由**：L1 零成本必有；L2 工程层兜底，把"误用 DBA 账号"挡在门外（定律 5 数据完整性不"以后再说"）。
- **若用户选 L1-only 的额外后果**：v1 早 ~1 周发布；但客户误用 DBA 账号 = Server 持全权凭据，事故时责任难界定。
- **若用户选 L1+L2+L3 的额外后果**：每次巡检多一次往返；过度设计；诚实用户场景不值得。

### Q4. v1 源库类型范围？（D3.2，DECIDE: D3）
- **推荐 A（MySQL + PostgreSQL）**。
- **理由**：覆盖目标客群主力；sqlx 加 feature 即可（无新 crate family）；老版本基线 MySQL 5.7+ / PG 12+。
- **若用户加 SQLServer 的额外后果**：v1 时间不可控（sqlx mssql 支持不稳；可能需新 crate）；H3 跑道风险。
- **若用户只选一种的额外后果**：单一覆盖太窄；客户常见两库并存场景被排除。

### Q5. webhook payload `dbmaster.drift-event.v1` schema 是否接受？（D4.2，DECIDE: D4）
- **推荐 接受草案 §4.4.2**。
- **理由**：跨组件契约只加不删；v1 锁这 11 种 drift kind + 字段集合；v2 加新 kind/HMAC 签名头不破坏 v1。
- **重点请用户审阅**：① 字段集合是否够客户用；② `drifts[]` 全量 vs 大变更截断（推荐不截断）；③ 是否需要 `instance_uuid` 之外的去标识符字段（推荐不加，避免 PII 误录入）。
- **若用户希望调整的常见点**：加 `schema_version` 顶层字段（推荐 payload 已有 `"schema": "dbmaster.drift-event.v1"` 等价）；加 HMAC 签名头（推荐 v2，C-21）。

---

## 12. 附录：被淘汰的选项（备查）

- **D1-B 桌面代理执行**：drift watch 是 always-on 场景，桌面不 always-on；H3 跑道不可达。
- **D1-C 混合**：v1 不涉及数据搬运，C 与 A 在 v1 等价；B 半边是 v2 决策。
- **D2.1-B 独立 source_db_credentials 表**：表分裂无收益；现有 database_connections 已泛化。
- **D2.1-C 新格式 v2:...**：过度设计；现有格式无缺陷。
- **D2.2-C HKDF 派生子密钥**：零客户阶段过度设计（定律 1）。
- **D2.3-L3 周期 canary**：过度设计，每次巡检多一次往返。
- **D2.4-B 复用 telemetry_events**：telemetry 与安全审计语义混淆。
- **D2.4-C 仅日志**：日志难查；无法做时间窗查询。
- **D3.1-B 桌面 schema diff 引擎复刻到 Rust**：重写两份；从零开始。
- **D3.1-C 第三方 schema-introspect crate**：引入新依赖（定律 1）。
- **D3.2-B 加 SQLServer**：sqlx mssql 不稳；H3 跑道风险。
- **D4.1-B 飞书+钉钉+webhook 并行**：H3 不值得；webhook 已涵盖飞书/钉钉适配。
- **D4.1-C 仅邮件**：邮件投递/反垃圾/模板复杂度高于 webhook。
- **D7-B tokio-cron-scheduler**：v1 间隔语义足够；新依赖非必要（定律 1）。
- **D7-C 手写 cron 解析器**：重复造轮；bug 面大。

---

## 13. 防御式 checklist（按 ~/.claude/rules/defensive.md）

本 ADR 涉及代码改动前的设计层 checklist 确认；实现派单时由 backend 工程师逐条落代码层。

- [x] **输入边界**：webhook URL（HTTPS 强制 + localhost 例外）/ interval（1..=1440）/ connection id（参数化）/ snapshot JSON（结构化解析，不信任源库返回顺序）—— 设计层已约束；实现层补 binding 校验测试。
- [x] **错误处理**：webhook 失败 3 次重试 + 永久失败入 run_history（不静默）；schema 采集失败入 run_history；canary 失败明确报"账号权限不足"；所有路径显式 `Result` 上抛。
- [x] **状态一致性**：snapshot append-only（不删 prior，链式 hash）；drift 触发条件 = hash 变化（重复跑同 hash 不重发，幂等）；webhook 失败不回滚 snapshot（drift 是事实，告警失败重试不是回滚）。
- [x] **并发**：单进程模型 v1；同一 task 上一次未完成则跳过（不堆积）；多副本部署文档化为 v1 不支持。
- [x] **资源释放**：sqlx 连接池（已配置 max_connections=16）；reqwest 客户端复用单实例（不每次 new）；超时强制（webhook 10s）。
- [x] **日志与可观测性**：每次 task 跑记 run_history；每次凭据使用记 credential_access_audit；日志不含凭据/SQL/schema_json 全文/PII/webhook URL（grep + 测试断言）。
- [x] **安全**：参数化查询（grep 禁拼接）；源库凭据 env var 加载（复用 ADR-0001）；webhook URL 走配置（per-task）；payload 不含 PII/凭据（硬排除）。
- [x] **交付前自审**：本 ADR 设计层全条覆盖；实现派单 DoD（§8）逐条落地 + verify.md 5 层。

---

**本 ADR 是设计文档，不修改任何代码。** 实现由后续 senior-backend-engineer（Server drift crate + automation 鉴权+gate + 地基）与 senior-desktop-engineer（drift UI）在用户拍板 §11 后接手。
