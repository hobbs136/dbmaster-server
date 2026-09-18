# ADR-0003：客户端内嵌 server 架构演进

> **状态**：已决策（执行中：S1 ✅ DB API，S2 ✅ server `--embedded`，S2b ✅ Flutter spawn，S3 ✅ 连接迁移，S4 ✅ 查询走网关，S5 ✅ browse 端点 + DbBackend trait，S6 ✅ ClickHouse 接入验证 trait 价值，S7 ✅ MySQL/Doris browse 切网关，S10 ✅ server 事务端点）
> **日期**：2026-08-07（S2-S10 实施 2026-08-07 ~ 08-08）
> **决策者**：产品负责人
> **影响**：整个客户端数据层 + server 定位

## 背景

### 当前架构（2026-08）
dbmaster 是双产品结构：
- **桌面客户端**（Flutter）：直连数据库，8 个 Dart adapter（MySQL/PG/SQLite/Doris/Redis/MongoDB/TDengine/SQLServer），每加一个数据库要写 ~1500 行 adapter + Dart 驱动依赖。
- **Server**（Rust，¥399/年）：远程自动化引擎（data_sync/drift/scheduler/license），sqlx 支持 MySQL/PG/SQLite。

### 痛点
1. **客户端数据库扩展成本不可持续**：Dart 生态驱动远不如 Rust 丰富。每加一个库（ClickHouse/Oracle/ES/Snowflake）要 1500+ 行 adapter。
2. **data_sync 无法选择 server 端独有的连接**（如 ClickHouse）：客户端目标连接下拉从客户端连接加载，CH/Doris 连接只存 server 端，选不到。
3. **两套数据库能力割裂**：客户端 8 个 adapter + server sqlx，能力重叠但实现独立，维护双份。

### 触发事件
三期 ClickHouse 支持时，发现"客户端不支持 CH 浏览"导致 data_sync 选不到 CH 目标。深入讨论后发现根本问题是客户端的数据库扩展机制（每库一个硬编码 adapter）不可持续。

## 决策

**客户端拆成两个进程：显示进程（Flutter UI）+ 服务进程（内嵌 server）。所有数据库操作经服务进程 API，客户端 adapter 全部退役。**

```
┌─────────────────┐         ┌─────────────────────┐
│  显示进程        │  本地   │  服务进程            │
│  (Flutter UI)   │ ←────→ │  (Rust server)      │
│                 │  HTTP   │                     │
│  • 画布/卡片     │  API    │  • 数据库连接池      │
│  • 渲染引擎      │         │  • SQL 执行          │
│  • 交互逻辑      │         │  • data_sync/drift  │
│  • 零数据库依赖  │         │  • 连接管理          │
└─────────────────┘         └─────────────────────┘
```

### 两种运行模式（一套代码）

| 模式 | 部署 | 能力 | 商业 |
|---|---|---|---|
| **本地独立** | 客户端内嵌 server（127.0.0.1） | DBA 工具 + 本地 data_sync | 免费引流 |
| **远程连接** | server 部署在服务器 | + 团队协作 + 变更审批 + 后台任务 | ¥399/年 |

显示进程不关心连的是本地还是远程 server——同一份代码，只是 base URL 不同。

### 数据库保留范围

最终支持 8 种库（Redis/TDengine 砍掉）：
- 第一阶段（SQL 库先行）：MySQL / PostgreSQL / SQLite
- 第二阶段（OLAP）：ClickHouse / Doris（server 端三期已做）
- 第三阶段（企业/文档）：SQL Server（tiberius）/ MongoDB（mongodb crate）

## 理由

1. **复用已有投资**：server 端已写好（连接管理/SQL/data_sync/drift/license），不是从零开始
2. **解决根本问题**：数据库扩展从"客户端写 Dart adapter"变成"server 加 Rust 驱动"，成本骤降
3. **商业自洽**：免费端 = 本地 server（引流），付费端 = 远程 server（¥399/年）
4. **不破坏体验**：用户感知仍是"桌面原生应用"（Flutter 渲染 + 本地服务）
5. **差异化成立**：桌面原生体验（Flutter）+ 多库广度（Rust server）+ AI（已有）

## 影响

### 工作量评估
- 客户端受影响文件：~60 个（~391 处 adapter 调用）
- Server 端新增端点：30+ 个（executeQuery/目录/DDL/事务/元数据）
- Server 新增驱动：4 类（SQL Server/MongoDB + 已有 CH/Doris）
- 数据迁移：客户端 keychain 凭据 → server database_connections

### 高风险点
1. session 事务的有状态化（begin/commit/rollback 跨多语句）
2. 侧边栏树 8 个 builder 的同步→异步改造
3. 内嵌 server 的生命周期管理（spawn/健康检查/端口冲突/崩溃恢复）
4. 凭据迁移（OS keychain → server，安全传输）

## 执行计划

### 第一阶段：SQL 库核心链路（MySQL/PG/SQLite）
1. server 加 executeQuery + 目录列举端点
2. 客户端内嵌 server（spawn + 生命周期）
3. 连接迁移（keychain → server）
4. 客户端查询/浏览/侧边栏改走 server API
5. adapter 退役（SQL 库部分）

### 第二阶段：OLAP 集成
6. 客户端浏览 CH/Doris（经 server API）
7. data_sync 目标连接从 server 加载

### 第三阶段：企业/文档库
8. server 加 SQL Server（tiberius）+ MongoDB 驱动
9. 客户端对应 UI 改造

### 清理
10. Redis/TDengine 客户端 UI 退役
11. 剩余 adapter 全部删除

## 参考

- data_sync 功能文档：`dbmaster-server/docs/data_sync.md`
- Intent Canvas 架构：`dbmaster-flutter/docs/architecture/intent_canvas_architecture.md`（feature/ai-native-demo 分支）
- 商业模型：`AGENTS.md` 根级指南

---

## 附：S2 实现笔记（2026-08-07，server 端 `--embedded` 模式）

S1 交付了 server 端 DB API（commit `112b67e`）。S2 让 server 能作为 Flutter 桌面客户端的**子进程**运行。本节记录已落地的契约与设计决策，**Flutter S2b（EmbeddedServerService）严格依赖此契约**。

### 启动方式

```
dbmaster-server --embedded [--data-dir <DIR>]
```

- 默认（不带 flag）= 正式生产 server，行为与 S2 前完全一致（零回归）。
- `--embedded` 切到子进程模式：绑 `127.0.0.1:0`（OS 分配端口）、用临时数据目录、合成单用户授权。
- `--data-dir`：embedded 模式的 SQLite 目录；不传则用 `temp_dir/dbmaster-embedded-{pid}`（并发实例零冲突）。

### stdout 握手契约（Flutter S2b 必读）

embedded 模式启动后向 **stdout** 输出**单行 JSON**（其余日志全走 stderr，stdout 专用于握手）：

```json
{"type":"dbmaster_embedded_ready","port":54321,"access_token":"eyJ...","refresh_token":"eyJ...","install_uuid":"...","version":"0.x.y"}
```

| 字段 | 含义 |
|---|---|
| `type` | 固定 `"dbmaster_embedded_ready"` |
| `port` | OS 实际分配的端口（`:0` bind 后回读 `listener.local_addr()`） |
| `access_token` / `refresh_token` | 首启自动创建的 embedded 单用户的 JWT，**远期 TTL（30d access / 31d refresh，见 `auth::jwt` embedded 变体）**。远期 exp 是安全的：JWT secret 每次启动随机重生成，token 真实寿命即子进程寿命。客户端（`ServerConnection.getAccessToken`）对 embedded 同样做透明刷新兜底——旧 server（15m/7d 标准对）与极端长开机（>30d）都能自愈 |
| `install_uuid` | 本实例 UUID（与正式模式同源，`get_install_uuid`） |
| `version` | server 版本 |

Flutter 客户端读到此行即认为 server 就绪；读不到（进程退出/超时）即判定启动失败。

### 关键设计决策

1. **端口协商**：`:0` + stdout 回报。零冲突，无需客户端探测。
2. **首启认证**：server 首启 `INSERT OR IGNORE` 一个固定 email `embedded@local` 的单用户（随机不可记密码，登录走 token），每次启动重新签发一对 token。客户端永不需要登录自己的本地服务。
3. **license 门控**：embedded 模式在 bootstrap 早期**合成一个 lifetime `Licensed`**（`license_type="embedded"`）注入 `AppState`。
   - **不新增 `EntitlementState::Embedded` 变体**——复用现有 `Licensed`，对已发布 license 契约零侵入。
   - `gate_blocked` 检查 `is_gated()`，`Licensed` 返 false → DBA 写操作放行（这正是免费桌面端所需）。
   - 切换到远程付费 server 只需不带 `--embedded` 重启 → 走正常 `resolve_entitlement`。
4. **调度器策略**：embedded 模式起 data_sync scheduler（本地 data_sync 是免费功能），**不起** drift scheduler（drift 是团队/远程功能）——通过传 noop `DriftRunner` 实现。
5. **shutdown**：`tokio::select!` 监听 (a) server 完成 (b) **stdin EOF**（父进程退出→stdin 管道关闭→子进程退出，最可靠的父生命周期绑定）(c) ctrl_c。

### 配置注入

embedded 模式**不读环境变量**构造 Config（避免并发实例 JWT 碰撞）。每次启动：
- JWT secret / refresh secret：随机 32 字节 hex（每次重启重新生成，token 反正每启动重签）
- 凭据密钥：随机 32 字节（不需要 `DBMASTER_DEV=1`）
- host=`127.0.0.1`、port=0

为此新增 `build_app_with_config(...)` / `build_router_with_config(...)`（接受显式 `Config`），原 `build_app` / `build_router` 作为 env 耦合的薄封装保留。

### 测试

- `tests/embedded_test.rs`（3）：进程内验证合成 entitlement 不门控、embedded 用户幂等、`build_app_with_config` 链路。
- `tests/embedded_process_test.rs`（2）：spawn 真实二进制，读 stdout 握手，curl `/api/health` + `/api/entitlement` 验证 `state=licensed, type=embedded`。

工作区全量 `cargo test --workspace`：**233 passed, 0 failed, 8 ignored**（ignored 是需在线 DB 的 e2e）。

### 不在本轮（S2b 及之后）

- ❌ Flutter 端 spawn / 健康检查 / 崩溃恢复 / 退出清理数据目录（S2b，严格按本节 stdout 契约实现）
- ❌ 连接迁移 keychain → server（S3）
- ❌ 客户端查询/浏览改走 server API（S4）
- ❌ adapter 退役（S5）

---

## 附：S3 实现笔记（2026-08-07，连接迁移 keychain → server）

S3 把客户端的 **DB 连接存储** 从本地 keychain + SharedPreferences 镜像到 embedded server 的 `/api/connections`，使同一份连接对客户端 UI 和 server-side 功能（data_sync/drift）都可见、且跨 embedded server 重启持久化。**只迁移存储，不改连库方式**（客户端仍本地 adapter 直连，S4 才走 server 网关）。

### 关键决策

| # | 决策 | 实现 |
|---|---|---|
| A | **embedded 持久化凭据密钥** | `{data_dir}/credential.key`（32 字节，首次生成，Unix 0600）。S2 的随机密钥被替换为 `load_or_create_credential_key`，否则存到 server SQLite 的连接密文重启后无法解密 |
| B | **SQL 库先行** | mysql/postgres/sqlite 走 server；redis/mongodb/doris/tdengine/sqlserver 暂留 keychain。客户端「混合存储」由 `isServerSyncable()` 决定 |
| C | **`GET /api/connections/:id/credential` 返明文（仅 embedded）** | 新端点；handler 查 `AppState.embedded_mode`，非 embedded 返 `NOT_EMBEDDED`。客户端连库前调它拿明文 |
| 字段缺口 | **migration 008 扩展 schema** | 补 use_ssl/timeout/auto_reconnect/charset/timezone/environment/read_only/group_id/extra + SSH 凭据列（ssh_username/auth_mode/password_encrypted/private_key_encrypted/passphrase_encrypted） |

### 客户端存储策略（mirror，非硬切换）

为降低风险，S3 采用**镜像**而非硬切换：本地 keychain + prefs 仍是主存储，server 是镜像。SQL 库连接经 `ConnectionSyncService` 同步到 server（`group_id` 存本地 id 做 reconcile）。`loadSavedConnections` 按 `name+type+host` 自然键合并 server 连接。这样：不破坏现有 keychain 路径、无 id churn、server-side 功能可见、embedded 重启后连接仍在。

### 新增端点 / 字段
- `GET /api/connections/:id/credential`（embedded-only，返明文 password + ssh_*）
- migration 008：13 个新列
- `CreateConnectionRequest` / `DatabaseConnection`：扩展字段，SSH 凭据 AES-256-GCM 加密
- `AppState.embedded_mode: bool`（`new_embedded` 构造器）

### 测试
- server：`tests/connection_migration_test.rs`（4：扩展字段 round-trip、credential 端点 embedded/remote/404）；workspace 全量 237 passed
- client：`connection_mapping_test.dart`（14）、`connection_sync_service_test.dart`（6，mock HTTP）；连同现有测试 341 passed 无回归

### 安全
- credential key 文件 0600 + 在用户私有 app support 目录
- credential 端点仅 127.0.0.1 loopback（embedded 模式绑定），远程模式 403
- SSH 凭据与主密码同样 AES-256-GCM 加密落库

### 不在本轮（S4 及之后）
- ❌ 改连库方式（仍本地 adapter 直连；S4 走 server /api/db/* 网关后可去掉 credential 端点）
- ❌ 非 SQL 库迁移（待 server 加驱动）
- ❌ 远程模式连接迁移

---

## 附：S4 实现笔记（2026-08-08，查询执行改走 server 网关）

S4 把**编辑器的 SQL 查询执行**从客户端本地 adapter 直连库，切到走 embedded server 的 `POST /api/db/:conn_id/query` 网关（S1 加的端点）。**只代理查询执行**：browse（侧边栏树）和事务仍走本地 adapter。

### 三个核心决策

| # | 决策 | 实现 |
|---|---|---|
| A | **只代理查询执行** | 单一拦截点 `_QueryExecutor.executeQueryWithStats`（database_service.dart）；browse（getDatabases/getTables/getColumns/views/procedures/...）仍本地 adapter |
| B | **事务回退本地** | `shouldRouteViaGateway` 检查 `_state.isInTransaction()` + SQL 是否 BEGIN/COMMIT/ROLLBACK/START TRANSACTION/SET AUTOCOMMIT/SAVEPOINT；任一为真走本地 |
| C | **embedded 默认走网关** | 全部条件满足才走：`ServerConnection.isEmbeddedMode` + db_type ∈ {mysql/pg/sqlite} + 非事务 + server-id 映射存在。任一不满足或网关调用失败 → 透明降级本地 adapter |

### 实现要点

- **新增 `lib/services/db_gateway_service.dart`**（单例）：`executeQuery(connId, sql, {db, limit})` POST `/api/db/:conn_id/query`，解包 `{columns, rows, affectedRows, columnTypes, executionTimeMs}` → `QueryResult`。`columnTypes` 从 server 的 `[{name,type}]` 数组转 `Map<String,String>`。
- **`database_service.dart:executeQueryWithStats`** 在 mysql-raw/adapter 分支**前**插入网关分支；`try/catch` 包裹，失败 fall through 到本地路径（透明降级）。
- **server-id 映射**：复用 S3 的 `connection_server_id_map`（SharedPreferences）。`DbGatewayService.lookupServerConnId(localId)` 读它。

### 结果形状映射
- SELECT：`{columns, rows, columnTypes:[{name,type}], executionTimeMs}` → QueryResult
- 非 SELECT：`{columns:[], rows:[], affectedRows, executionTimeMs}` → QueryResult（columnTypes 缺省 null）
- NULL → JSON null（保留）；BLOB 非 UTF-8 → server 返 `<N bytes>` 占位符（已知限制，文档记录）

### 已知限制（S4 v1 接受）
- **无事务**：server 每请求新连接池、无状态。BEGIN 后的查询回退本地（事务功能完整保留）
- **无 browse 网关**：侧边栏树仍本地 adapter（server 网关只有 databases/tables/columns，无 views/procedures 等）
- **BLOB 占位符**：非 UTF-8 二进制数据走网关会丢真值
- **无多语句**：server sqlx 驱动层拒绝多语句（`QUERY_FAILED`）；客户端本就单语句执行

### 测试
- `db_gateway_service_test.dart`（12）：路由判定全分支（embedded/非SQL/事务/事务控制语句）、executeQuery 请求构造 + SELECT/非SELECT 解码 + columnTypes 转换 + NULL 保留 + body 含 db/limit + 错误/401 抛异常
- 连同现有测试 **353 passed 无回归**

### 后续（不在本轮）
- **S5**：adapter 退役（browse 也走网关后，SQL 库 adapter 可删）—— 需 server 补 views/procedures/functions/triggers/indexes/foreignKeys 端点
- server 事务端点（让事务也能走网关）
- 非 SQL 库走网关（待 server 加驱动）

---

## 附：S5 实现笔记（2026-08-08，browse 端点扩展 + adapter 退役可行性）

S5 原目标是「adapter 退役」，但深度探查证明 **SQL adapter 在当前 server 能力下不能删除**——它是 browse/DDL/事务/SSH 隧道/AI/charset 等功能的载体，server 网关覆盖远不足以替代。S5 因此**收窄为 browse 端点扩展**，作为迈向 adapter 退役的实际一步，并诚实标注完整退役是多阶段工作。

### 为什么 adapter 不能删（探查结论）

| 阻断项 | 详情 |
|---|---|
| server 网关覆盖不足 | S4 前仅 4 端点（databases/tables/columns/query）；SQL adapter 有 ~30+ 方法被 browse/DDL/charset/explain/rowCount/processList/AI/JSON 列调用 |
| 事务/tab session | 网关无状态、每请求新连接池；事务必须本地 adapter（S4 已回退本地） |
| SSH 隧道 | 网关**完全不读** SSH 字段，直连 `conn.host/port`——隧道连接走网关会连不到内网主机 |
| 连接生命周期 | S4 只拦截 executeQuery；connect/browse 仍开本地真实连接，adapter 是连接载体 |
| PG 多 schema | 网关 PG 写死 `public` schema |

### S5 实际交付：server browse 端点扩展

新增 6 端点（db_handler.rs），返回对象名列表（`Vec<String>`）：
- `GET /api/db/:conn_id/views` — MySQL information_schema.views / PG pg_views / SQLite sqlite_master
- `GET /api/db/:conn_id/procedures` — routines WHERE type='PROCEDURE'（SQLite 返 []）
- `GET /api/db/:conn_id/functions` — routines WHERE type='FUNCTION'（SQLite 返 []）
- `GET /api/db/:conn_id/triggers` — information_schema.triggers（SQLite 返 []）
- `GET /api/db/:conn_id/indexes?table=` — statistics(pg_indexes/PRAGMA index_list)
- `GET /api/db/:conn_id/foreign_keys?table=` — key_column_usage(pg_constraint/PRAGMA foreign_key_list)

客户端 `DbGatewayService` 新增对应 browse 方法（`listViews/listProcedures/.../listIndexes/listForeignKeys` + 已有的 listDatabases/listTables/listColumns），**但本期未将 browse 路由到网关**——browse 仍走本地 adapter。这些方法是未来 browse 走网关的构建块。

### 测试
- server：`tests/db_browse_test.rs`（5：views/indexes/foreign_keys/empty-procedures/404）；workspace 全量 **242 passed 无回归**
- client：353 passed 无回归（browse 方法未接入路径，暂无单测）

### 完整 adapter 退役的剩余工作（多阶段，非 S5 范围）
1. server 补 DDL 端点（createTable/dropDatabase/addColumn/...）+ charset/collation + explain + rowCount
2. server SSH 隧道支持（db_handler 读取 ssh_* 字段 + 建隧道）
3. server 事务会话端点（BEGIN/COMMIT 跨请求）
4. server PG 多 schema（getSchemas + 非 public schema 查询）
5. server AI schema summary 端点
6. 客户端 browse 路由切网关（用 S5 的 browse 方法）
7. 客户端 SQL adapter 删除

每个都是独立阶段。S5 完成了第 0 步（browse 端点存在性），为后续铺路。（远程模式 credential key 本就持久化，但混合存储决策本期只对 embedded 生效）

---

## 附：S6 实现笔记（2026-08-08，ClickHouse 接入 — DbBackend trait 价值验证）

S5 之后做了两件事：(1) `DbBackend` trait 抽象（消除 db_handler.rs 的 per-DB match 分支，加新库 = 写一个 impl 块）；(2) 用 trait 加了 **ClickHouse**——第一个重构后新增的数据库，验证「加库变简单」的承诺。

### ClickHouse 接入（commit `d86dbce` server + `d26cbb10`/`0130d3f0` flutter）

**关键技术决策**：ClickHouse 暴露 MySQL-wire 协议端口（9004），所以 `ClickhouseBackend` **复用 sqlx 的 MySQL 驱动**，零新 Rust 依赖。browse SQL 用 CH 方言（`system.columns`，nullable 从 `Nullable(T)` 类型前缀推导）。

**实测发现并修复的问题**（commit `0130d3f0`）：
- CH 的 MySQL 协议**不支持 sqlx 的 `?` 预编译绑定** → browse 查询改用转义字面量（`ch_str_literal`）
- 客户端 `testConnection` 假阳性（无脑返回成功）→ 改为真正通过网关测试（临时建连→db_test→删除）
- 网关 HTTP 无超时 → 全部加 `.timeout()`（查询 30s / browse 15s）

### 工作量对比（trait 抽象的价值兑现）

| 维度 | 重构前（如加 CH） | 重构后（实际） |
|---|---|---|
| server 端 | 不适用（server 无网关） | ~90 行 Rust（1 个 impl + 1 行分发），零新依赖 |
| client 端 | ~1500 行 Dart adapter + Dart CH 驱动（生态稀缺） | ~200 行 Dart（网关代理 adapter + enum/switch），零新驱动 |
| 总计 | ~1500 行 + 驱动难题 | ~290 行，机械、不易错 |

**ClickHouse 是当前唯一「真正瘦」的库**——它没有本地 Dart 驱动，adapter 是纯网关代理（connect/browse/query 全经 server）。其他库（mysql/pg/sqlite/redis/mongodb/...）仍是胖的（本地驱动 + adapter + 直连）。

---

## 附：S7 实现笔记（2026-08-08，MySQL/Doris browse 切网关 — 半瘦）

S7 让 **MySQL + Doris 的 browse（侧边栏树）走 embedded server 网关**，达到与 ClickHouse 同等的 browse 瘦度。这是「半瘦」过渡态：browse 瘦了，但 connect/事务/tab session/keepAlive 仍保留本地 MySQL 连接（双连接，待 S8 消化）。

### 为什么是「半瘦」而非「全瘦」

CH 天然无本地驱动，connect/browse/query 全经网关。MySQL 有本地驱动（mysql_client）+ 事务 + tab session + keepAlive 心跳——这些**仍依赖本地 socket**（事务要跨请求共享连接、keepAlive 要探活 socket）。S7 只切 browse（最安全、降级最易），不断本地连接。彻底断本地是 S8（需先验证 browse 稳定）+ S10（server 事务端点）。

### 实现要点

| 改动 | 文件 | 说明 |
|---|---|---|
| `listColumnsRich` + `isBrowseGatewayReady` | `db_gateway_service.dart` | 新增：富 DbColumn 解析（server columns 端点返回 `{name,data_type,is_primary_key,is_nullable,default_value}`）+ browse 路由守卫 |
| 8 个 browse 方法切网关 | `database_service.dart` `_SchemaManager` | getDatabases/getTables/getViews/getProcedures/getFunctions/getTableColumns/getTableIndexes/getForeignKeys + getTablesPaginated |

统一降级形态（照搬 S4）：每方法 `if (mysql||doris)` 分支先 `isBrowseGatewayReady` → `lookupServerConnId` → try 网关端点 → catch 回退本地 `conn.execute`。

### 两个语义差异处理

- **getTableIndexes / getForeignKeys**：server 端点只返回**名字列表**（`Vec<String>`），客户端要富对象（`DbIndex{columns,isUnique}` / `ForeignKey{...}`）。策略：网关返回**空** → 表无索引/FK，返回 `[]`（省本地查询）；**非空或失败** → 回退本地取富对象。
- **getDatabases**：server `SHOW DATABASES` 不过滤系统库，网关分支在客户端补过滤（`information_schema/performance_schema/mysql/sys`），与本地分支一致。

### 不在 S7 范围

- `events` 端点（server 无）→ getEvents 保留本地，独立小活
- connect / keepAlive / tabSessions / 事务 → S8/S10 范围
- `MySQLBaseAdapter`（1249 行）瘦身 → S12 范围（browse 切网关发生在 `_SchemaManager`，不经 adapter）
- PG 多 schema（server 写死 `public`）→ 独立 S7 子项，本期只做 MySQL/Doris

### 降级保护（核心约束）

每个 browse 方法：①`isBrowseGatewayReady` false（非 embedded）→ 直接本地 ②网关 try → 成功 ③catch → `AppLogger.w` + fall through 本地。**kill dbmaster-server.exe → browse 透明降级到本地 socket，用户无感**。本地分支原样保留。

### 测试

- `dart analyze lib/` + `flutter analyze`：零新增 warning/error
- `flutter test`：baseline 与改动后均 `-7` 预存失败（widget/shortcut 测试，与 MySQL 无关），3810 passed 一致，**零回归**
- `cargo test --workspace`：242 passed 0 failed（server 未改）
- 手动验证（待打包后）：连 192.168.x.x:3306 → 侧边栏全节点 + kill server 透明降级

### 双连接代价（诚实标注）

半瘦态下 MySQL 一条连接被两个进程各开一份：客户端（mysql_client socket，供事务/keepAlive）+ server（sqlx 短连接池，供 browse/query）。连接数 ×2、双份心跳、两套连接状态需靠 `_state.servers[id].database` 同步。这是 S7→S8 之间的已知过渡成本。

---

## 附：S10 实现笔记（2026-08-08，server 事务端点 — session-pin）

S10 让 server 能**跨 HTTP 请求维持事务**——BEGIN 后的 INSERT/UPDATE 在 COMMIT/ROLLBACK 前属于同一事务。这是 S8（connect 断本地）的硬前提：事务能走网关后，客户端才可能放弃本地 socket 跑事务。**本次只做 server 端，客户端事务仍走本地**（S8 再切）。

### 核心技术决策：max_connections(1) pool pin + SQL 文本控制

sqlx 的 `pool.begin()` 返回的 `Transaction` 借用单连接，不能跨 await 存进 state（生命周期 + 不可 Send 的 borrow）。因此 S10 用：

- **pin 一个 `max_connections(1)` 的 pool 到 session**——每次 `pool.acquire()` 拿到同一物理连接，事务状态在物理连接上保持。
- **用 SQL 文本**（`START TRANSACTION`/`COMMIT`/`ROLLBACK`）而非 sqlx Transaction API 控制事务。

现有 `open_*` 辅助函数已用 `max_connections(1)`（db_handler.rs:630 等），模式现成。

### 4 个端点

| 端点 | 作用 |
|---|---|
| `POST /api/db/:conn_id/txn/begin` | 开 pin pool → 发 BEGIN → 存 session → 返回 `{sessionId}` |
| `POST /api/db/:conn_id/txn/:session_id/query` | 在事务上下文执行 SQL（不经 mutation gate） |
| `POST /api/db/:conn_id/txn/:session_id/commit` | COMMIT + 移除 session（pool drop 关连接） |
| `POST /api/db/:conn_id/txn/:session_id/rollback` | ROLLBACK + 移除 session |

### 架构：Extension 注入，不污染 AppState

`TxnSession` 持有 sqlx pool（具体类型 `Pool<MySql>`/`Pool<Postgres>`/`SqlitePool`），属 automation crate 关注点。为避免 core crate 的 `AppState` 依赖 sqlx 业务类型，store 通过 **axum Extension layer** 注入（`db_handler.rs` 的 4 个 handler 用 `Extension<Arc<DbTxnSessionStore>>` 提取），core 零改动。

### 实现要点

| 改动 | 文件 |
|---|---|
| dashmap 依赖 + tokio sync/time features | `crates/automation/Cargo.toml` |
| `DbTxnSessionStore` + `TxnSession` + `PinnedPool` | `crates/automation/src/txn.rs`（新文件） |
| 4 个 handler + `TxnPath`/`TxnBeginBody` | `crates/automation/src/db_handler.rs` |
| 路由注册 + Extension 注入 + TTL sweeper spawn | `crates/automation/src/lib.rs` |
| `redact` + `execute_sql_*` 改 `pub(crate)` | `crates/automation/src/db_handler.rs` |

### 安全 / 防泄漏

- **session_id** 用 uuid v4（不可猜）
- **密码**在 begin 开 pool 后立即 drop（不缓存到 session，符合「内存用完即 drop」）
- **TTL 清理**：后台 task 每 60s 扫描，`last_used` 超 5 分钟自动 ROLLBACK + 移除（防客户端崩溃泄漏）
- **并发安全**：每 session 的 `tokio::Mutex` 串行化 acquire（防 max_connections(1) pool 死锁）
- **事务控制语句不经 mutation gate**（BEGIN/COMMIT/ROLLBACK 改事务状态，不是数据 mutation）

### DB 差异

| DB | BEGIN 语法 | 事务支持 |
|---|---|---|
| MySQL/Doris | `START TRANSACTION` | ✅ |
| PostgreSQL | `BEGIN` | ✅ |
| SQLite | `BEGIN TRANSACTION` | ✅ |
| ClickHouse | — | ❌ 返 `UNSUPPORTED_TXN` (400) |

### 测试（tests/db_txn_test.rs，5 个）

- `begin_query_commit_persists`：BEGIN→INSERT→COMMIT，行持久化
- `begin_query_rollback_discards`：BEGIN→INSERT→ROLLBACK，行丢弃
- `unknown_session_query_fails`：未知 session_id → 500
- `double_commit_second_fails`：第二次 COMMIT → 500
- `begin_unsupported_db_type_rejected`：ClickHouse → 400 UNSUPPORTED_TXN

workspace 全量 **247 passed 0 failed**（242 baseline + 5 新）。

### 不在 S10 范围

- **客户端事务切网关**（S8）——客户端 beginTransaction/commit/rollback 仍走本地 socket
- server admin 端点（KILL/CALL，独立工作）
- server batch/复合语句端点（CREATE TRIGGER 的 BEGIN...END，独立工作）

### S8 的剩余阻断（S10 完成后）

S10 解决了事务的 server 端能力，但 S8 纯瘦路线仍有阻断：`USE` 切库/`SET NAMES` 会话变量、`CALL` 过程调用、`CREATE TRIGGER...BEGIN...END` 复合体、`KILL QUERY`、executeSqlScript 多语句——这些 gateway 单语句无状态端点结构上无法覆盖。S8 需先做 server admin/session/batch 端点扩展，或改用 lazy 本地方案。

---

## 附：S8a 实现笔记（2026-08-08，客户端事务切 S10 — S8 第一步）

S8a 把客户端的**主连接事务**（beginTransaction/commit/rollback + 事务中的 query）从本地 socket 切到 S10 server 事务端点。事务不再需要客户端本地连接常驻——这是 S8 的第一步，但 **connect 仍开本地**（其他 raw consumer 还在用）。

### 改动（全在 dbmaster-flutter，server 不动）

| 改动 | 文件 |
|---|---|
| `DbGatewayService` 加 txnBegin/txnQuery/txnCommit/txnRollback | `db_gateway_service.dart` |
| `_ConnectionState` 加 `txnSessionIds` map + getter | `database_service.dart` |
| beginTransaction/commit/rollback 主连接分支切 S10 | `database_service.dart` |
| executeQueryWithStats 加 S10 事务路由分支 | `database_service.dart` |
| disconnect 清理 S10 session（防泄漏） | `database_service.dart` |

### 不破坏 S4 契约

**不改 `shouldRouteViaGateway`**——它对 `inTransaction` 返回 false 的语义保留（测试覆盖）。新增独立 S10 事务路由分支在 `executeQueryWithStats` 里，位于 `shouldRouteViaGateway` 检查**之前**：当 `txnSessionIds[connId]` 存在时，query 走 `txn/:session_id/query`。

### 降级策略（关键设计）

- **beginTransaction/commit/rollback**：S10 失败 → 降级本地 `adapter.beginTransaction/commit/rollback`（边界清晰）
- **事务中的 query**：S10 失败 → **直接抛错，不降级本地**。原因：本地连接不在事务中（本地从未 BEGIN），降级会 autocommit——这是事务语义的 footgun。S10 事务一旦开始，query 只走 S10。

### 只切主连接事务

只改主连接事务（sessionId == null，UI 事务按钮路径）。tab session 事务（sessionId != null）保留本地——它的 query 走 tabConn，机制独立。

### 安全

- S10 session_id 用 uuid v4（server 端生成）
- disconnect 时主动 txnRollback 清理 server session（防泄漏，不必等 TTL 5 分钟）
- server TTL sweeper 兜底（客户端崩溃时）

### 测试

- `dart analyze`：零新增 warning
- `flutter test`：零回归（baseline 与改动均 `-7` 预存 widget 测试失败，3810 passed 一致）
- `db_gateway_service_test`：12 passed（shouldRouteViaGateway 路由逻辑未受影响）

### S8 剩余工作（S8a 之后）

- connect 断本地（需先解决 raw consumer 阻断）
- tab session 事务切 S10
- ~~server admin/batch/复合语句端点（KILL/CALL/多语句/复合DDL）~~ — **KILL + 多语句脚本端点已完成**（见 S8b-prep 笔记）；CALL 复用 S10；复合DDL 单语句 gateway 已覆盖；USE/SET 待架构决策

---

## 附：S8b-prep 实现笔记（2026-08-08，server admin/batch 端点）

为 S8b（connect 断本地）铺路，加两个 admin 端点解决 raw consumer 的结构性阻断。**只做 server 端，客户端不改**（端点先就位供 S8b 切）。

### 端点

| 端点 | 作用 | 消费者（S8b 时切） |
|---|---|---|
| `POST /api/db/:conn_id/admin/kill` | KILL QUERY（独立连接） | `_tryKillMySqlQuery` |
| `POST /api/db/:conn_id/admin/script` | 多语句脚本（真正分割器） | `executeSqlScript` |

### 关键：手写 MySQL 语句分割器（sql_split.rs）

客户端现有 `split(';')` 对含分号的 routine/trigger 体必然出错。server 端 `split_sql_script` 是状态机分割器（~200 行，无外部依赖），处理：
- 单/双/反引号内的 `;`（不分割）
- `--`/`#` 行注释、`/* */` 块注释
- `BEGIN ... END` 复合体（routine/trigger 内的 `;` 不分割）
- `DELIMITER $$` 指令（改分割符）

15 个单测全覆盖（引号/注释/BEGIN...END/DELIMITER/转义/边缘 case）。

### 不需要新端点的能力（单语句 gateway 已覆盖）

探查确认 server 的 `db_query` 用 `sqlx::query(sql)` 纯文本执行（不 split、不 prepared 绑定），所以：
- **复合 DDL**（CREATE PROCEDURE/TRIGGER...BEGIN...END）→ 整段 COM_QUERY，已覆盖
- **SHOW PROCESSLIST** → 单语句 SELECT，已覆盖
- **ER 图元数据查询**（COUNT/FK/PK）→ 单语句 SELECT，已覆盖
- **带参 CALL**（SET @x + CALL）→ 复用 S10 session（客户端 S8b 改）

### 测试

- `sql_split` 单测：15 passed
- `tests/db_admin_test.rs` e2e：5 passed（多语句执行/遇错继续/引号内分号/SQLite KILL 拒绝/空脚本）
- workspace 全量 **267 passed 0 failed**（247 baseline + 20 新）

### S8b 剩余阻断（admin 端点之后）

唯一剩余：**USE 切库 / SET NAMES / SET time_zone 会话状态**。架构抉择（推方案 b：消灭 USE 依赖，查询显式带 schema），不在 admin 端点范围。

---

## 附：S8b 客户端改造笔记（2026-08-08，raw consumer 切网关）

把 3 类 raw consumer 从本地 socket 切到 server 端点（S10 txn + admin kill/script）。纯客户端改造，server 端点已就绪。切换后这些操作不再依赖客户端本地连接常驻。

### 3 个切换点

| 切换点 | server 端点 | 客户端改动 | 降级 |
|---|---|---|---|
| KILL QUERY | admin/kill | `_tryKillMySqlQuery` 前加网关块 | 网关失败 → 本地开连接 KILL |
| 多语句脚本 | admin/script | `executeSqlScript` 执行点切网关（DDL 分析保留客户端） | 网关失败 → 本地 split(';') 循环 |
| 带参 CALL | S10 txn（复用） | `StoredProcedureService.execute` procedure 有参分支 | txnBegin 返回 null → 本地；中途失败 rollback+抛错 |

### 关键设计决策

**CALL 降级语义（数据安全取舍）**：带参 CALL 走 S10 事务（txnBegin→SET→CALL→commit）。txnBegin 返回 null（server 不支持事务，如 CH）→ 降级本地。但 txnBegin 成功后中途失败 → **rollback + 抛错，不降级本地**——因为 server 已 START TRANSACTION，降级到本地 autocommit 重跑 SET+CALL 会重复写入。与 S8a 事务 query 策略一致。

**DDL 分析保留客户端**：executeSqlScript 的 DDL 影响分析（`_interceptor.beforeExecute` 查 information_schema + 弹 DdlConfirmDialog）保留在客户端不动。只有最终执行从本地切到 admin/script 端点。客户端 split(';') 与 server sql_split 的边界理解可能不同，但分析已通过 + 用户已确认 + 降级保护。

### 测试

- `dart analyze`：零新增 warning
- `flutter test`：零回归（baseline 与改动均 `-7` 预存 widget 测试失败，3810 passed 一致）
- `stored_procedure_service_test`：22 passed（带参 CALL 的 session variables 测试过——非 embedded 模式走本地降级，证明降级保护正确）

### 不改

- server 任何文件（端点已就绪）
- DDL 影响分析逻辑（保留客户端）
- function 路径（SELECT name()，单语句无状态）
- threadId 来源（SELECT CONNECTION_ID() 仍需本地连接）

### S8b 之后的剩余阻断

- **USE/SET 会话状态**（架构抉择，推方案 b 消灭依赖）
- **threadId 来源**（CONNECTION_ID() 仍需本地——未来 server 可自报 thread id）
- **connect 彻底断本地**（上述两项解决后）

---

## 附：S8c 实现笔记（2026-08-08，消灭 SELECT DATABASE() 会话依赖）

探查发现方案 b（查询显式带 schema）对**网关路径已基本完成**——`executeQuery`/browse/txn 的 `db` 参数传递已完备。真正剩余的会话依赖集中在本地 fallback 路径。

### 本次改动（P0，纯收益零风险）

database_service.dart 的 **7 处 `SELECT DATABASE()`**（getViews/getProcedures/getFunctions/getEvents/getTablesPaginated/getTriggers/getTableInfo 的本地 fallback 分支）改为读 `_state.servers[id]?.database`。客户端本来就知道当前库名（切库时已同步），无需查询确认。每处省一次 `SELECT DATABASE()` 往返。

### 不改（硬约束 / 边际收益低）

- **本地 fallback 的 USE**（executeQueryWithStats/useDatabase/restoreSessionState）——MySQL 协议连接级状态，无法 per-query 消灭。embedded 模式网关路径用 `db` 参数已绕过 USE。
- **SET NAMES / SET time_zone**（createTabSession/adapter.connect）——字符编码/时区，无状态网关无法保持，需 server 端每次新连接自动 SET（后续工作）。
- **SQL 内嵌 DATABASE()**（11 处 WHERE TABLE_SCHEMA = DATABASE()）——只在本地 fallback 跑，网关路径靠 db 参数已正确。改它们工作量大、收益边际（P1，未做）。
- **performance_analyzer_service.dart** 的 `SELECT DATABASE()`——走 executeQuery 网关路由，已正确。

### 测试

dart analyze 零新增 warning；flutter test 零回归（3810 passed）。

### connect 彻底断本地的最终阻断

经 S7→S10→S8a→S8b→S8c，MySQL 的 browse/查询/事务/KILL/脚本/CALL 都能走网关。~~本地连接仍开着，只剩两个刚需场景~~：

1. ~~**SET NAMES/time_zone**（新连接必设，网关无状态）~~ — **已解决（S8 收尾）**：server 的 `open_mysql`/`open_mysql_db`/`open_mysql_pinned` 打开 pool 后按 `conn.charset`/`conn.timezone` 发 SET NAMES / SET time_zone（Doris 跳过 time_zone）。网关 pool 的 charset/timezone 与客户端本地连接一致。
2. ~~**threadId 来源**（CONNECTION_ID()）~~ — **已解决（S8 收尾，txn 路径）**：`txn_query` 响应追加 server 端 threadId（pin 连接的 CONNECTION_ID），客户端用它覆盖本地 threadId。事务中的查询取消能正确 KILL。db_query（无状态查询）返回后连接 drop，KILL 保持降级（断开重连）。

两个场景解决后，**网关路径的 charset/timezone/KILL 全部正确**。connect 彻底断本地的剩余阻断：本地 fallback 路径仍需 USE（MySQL 协议硬约束）+ 本地 threadId（非网关时仍正确）。这些在非 embedded 模式（远程 server）下才触发，embedded 模式下网关路径已完整。

---

## 现状评估：离完全瘦客户端还有多远（2026-08-08）

### 当前定位：「网关就绪的胖客户端」

ADR-0003 的最终目标是**完全瘦客户端**（客户端零数据库依赖、所有 DB 操作经 server、adapter 全部退役）。当前状态是**第一阶段完成**——基础设施就位 + 查询能走网关，但客户端**还没瘦下来**。

### 逐维度现状

| 维度 | 瘦客户端目标 | 当前状态 | 差距 |
|---|---|---|---|
| Dart DB 驱动依赖 | 零 | **6 个**（mysql_client/mysql1/postgres/redis/mongo_dart/sqlite3） | ❌ 全在 |
| adapter 代码 | 零（或纯 stub） | **~12200 行**（8 个 adapter） | ❌ 全在 |
| 查询执行 | 全走网关 | S4 路由了编辑器查询（mysql/pg/sqlite/CH）；事务回退本地 | 🟡 部分 |
| 连接建立 | 经 server | `connect()` **仍开本地真实连接**（所有库） | ❌ 本地直连 |
| browse（侧边栏） | 经 server | mysql/doris/CH 走网关（S7）；pg/sqlite 仍本地 adapter | 🟡 大部分 |
| DDL | 经 server | 全本地 adapter（server 无 DDL 端点） | ❌ 本地 |
| 非 SQL 库 | server 加驱动 或 砍掉 | redis/mongodb/doris/tdengine/sqlserver **完全本地** | ❌ 本地 |

### 已完成（S1-S6 成果）

- ✅ embedded server 模式（S2）+ Flutter spawn（S2b）
- ✅ 连接镜像到 server（S3，SQL 库）
- ✅ 查询执行走网关（S4，mysql/pg/sqlite/CH）
- ✅ browse 端点扩展（S5，views/procedures/triggers/indexes/foreign_keys）
- ✅ DbBackend trait（S5，加库集中化）
- ✅ ClickHouse 端到端接入（S6，验证 trait 价值）
- ✅ VARBINARY 解码 bug 修复 + testConnection 真实化 + HTTP 超时

### 未完成（完全瘦客户端的阻断项）

1. **客户端驱动 + adapter 全在**（6 驱动 + 12200 行）——最核心差距
2. **connect 仍开本地连接**——所有库类型
3. **browse 未切网关**（除 CH）——mysql/pg/sqlite 仍本地 adapter
4. **DDL/事务/charset/explain/rowCount/processList/AI 全本地**——server 网关不支持
5. **非 SQL 库完全本地**——不经 server

---

## 完整路线图：通向完全瘦客户端

### 已完成阶段

| 阶段 | 内容 | 状态 |
|---|---|---|
| **S1** | server DB API（网关基础：query/databases/tables/columns/test） | ✅ |
| **S2** | server `--embedded` 模式（spawn + 握手 + 合成 entitlement） | ✅ |
| **S2b** | Flutter spawn（EmbeddedServerService + 生命周期 + 崩溃恢复） | ✅ |
| **S3** | 连接迁移（keychain → server 镜像 + credential 端点） | ✅ |
| **S4** | 查询走网关（executeQueryWithStats 网关分支 + 事务回退 + 降级） | ✅ |
| **S5** | browse 端点扩展 + DbBackend trait | ✅ |
| **S6** | ClickHouse 接入（trait 价值验证） | ✅ |
| **S7** | MySQL/Doris browse 切网关（半瘦：browse 走网关，connect/事务仍本地） | ✅ |
| **S10** | server 事务端点（BEGIN/COMMIT/ROLLBACK session-pin，客户端仍走本地待 S8 切） | ✅ |

### 后续阶段（未开始，按依赖排序）

#### S8：connect 不开本地连接（纯经 server）— 进行中
- **已完成第一步（客户端事务切 S10）**：主连接事务（beginTransaction/commit/rollback + 事务中 query）走 server S10 端点，事务不再需客户端本地连接常驻。详见下方「附：S8a 实现笔记」。
- **剩余**：`DatabaseService.connect` 仍开本地 socket（供 raw consumer：USE/CALL/KILL/复合DDL/多语句）。需先做 server admin/batch 端点扩展，或改 lazy 本地方案。
- **剩余阻断**：USE 切库/SET 会话变量/CALL 过程调用/CREATE TRIGGER 复合体/KILL QUERY/executeSqlScript 多语句——gateway 单语句无状态端点结构上无法覆盖。
- **收益**：连接建立不再需要本地驱动（完全瘦客户端）

#### S9：server 补 DDL 端点
- server 加 createTable/dropDatabase/addColumn/dropColumn/renameTable/...（经 DbBackend trait）
- 客户端 DDL 操作切网关
- **收益**：DDL 不再需要本地 adapter

#### S11：server SSH 隧道支持
- `db_handler` 读取 `ssh_*` 字段 + 建隧道（当前完全忽略 SSH）
- 客户端隧道连接能走网关
- **收益**：隧道连接不再需要本地 adapter

#### S12：SQL adapter 退役
- 删除 mysql/pg 的本地 adapter + Dart 驱动依赖（**sqlite 豁免**：2026-08-25 拍板定性本地文件库永久直连，见 ADR-0005 §2.1 修订）
- 仅保留网关代理型 adapter（如 ClickhouseAdapter）——**CH 已于 2026-08-26
  （T29 第三批）收编至 /api/gw 壳**（stream_query `Family::Clickhouse` 腿 +
  clickhouse_adapter.dart 原地重写，旧 /api/db 通道消费面清零）
- **阻断**：需 S7-S11 全部完成
- **收益**：客户端真正变瘦（SQL 库零本地依赖）

#### S13：非 SQL 库决策
- 选项 A：server 加 redis/mongodb 驱动（Rust 生态有），客户端对应库也变瘦
- 选项 B：按 ADR 原计划砍掉 redis/tdengine（客户端 UI 退役）
- **决策点**：哪些非 SQL 库保留

### 阶段依赖关系

```
S7 (browse 切网关) → S8 (connect 不开本地) → S12 (SQL adapter 退役)
S9 (DDL 端点)     ↗
S10 (事务端点)    ↗
S11 (SSH 隧道)    ↗
S13 (非 SQL 决策) — 独立
```

S7-S11 可并行推进（都是 server 补能力 + 客户端切网关），S12 是它们的汇总（删 adapter）。S13 独立决策。

### 优先级建议
- **S7（browse 切网关）**收益最大、阻断最少——让 mysql/pg/sqlite 达到 CH 同等的「瘦」度
- **S9（DDL）**次之——DDL 是 DBA 工具核心功能，走网关后体验一致性最好
- **S10/S11（事务/SSH）**难度最高，可后置

