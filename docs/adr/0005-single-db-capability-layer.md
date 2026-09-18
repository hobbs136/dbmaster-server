# ADR-0005: Rust 单一 DB 能力层（All-DB-on-Server 终局架构）

- **Status**: Accepted（2026-08-15，方向用户拍板；网关 API 细节随 M9 里程碑演进）
- **Deciders**: 用户 + 架构师
- **Context**: DBX 拆解 `dbmaster-flutter/docs/competitive/dbx-teardown.md` §2.2；DBX 应对方案 `dbmaster-flutter/docs/roadmap/2026-08-dbx-response-plan.md`；执行清单 `dbmaster-flutter/docs/tasks/task_dbx_response.md`
- **Supersedes**: 无（不推翻既有架构，定义终局并给出迁移路径）
- **Related**: ADR-0003（embedded 模式——网关的本地形态）、ADR-0002（drift collector——首个 server 侧元数据采集实现）

## 1. 背景与决策驱动因素

1. **两套栈税**：现状每支持一种库要写两遍——客户端 Dart 适配器（交互查询）+ server Rust
   驱动（drift/health/data_sync/MCP 用）。automation 支持哪种库本就必须有 Rust 驱动，
   这笔税已经实际存在。
2. **原生依赖地狱（实证）**：2026-08-15 实测 SQL Server FFI 路线两处缺口——
   `sybdb.dll` 不在 `dist/Release/`（fresh install 连不上 SQL Server）+
   `sqlserver_ffi_bindings.dart:56` 把 exe 文件路径当目录拼（回退路径永不命中）。
   Dart FFI 栈的原生库分发是系统性负担。
3. **DBX 实证（teardown §2.2）**：dbx-core 全 Rust 驱动层（42 个驱动文件）+
   MySQL 兼容薄适配（`tidb.rs` 753B 即一个库），桌面端只是 Tauri 壳；
   「加库快」的真正来源是**单一 Rust 驱动层 + 协议兼容薄层**，而非 UI 层。
   同时 DBX 也没做到纯 Rust 全覆盖——Oracle/Snowflake 走 JVM JDBC 桥补位。
4. **Rust 驱动生态 > Dart**：tiberius（SQL Server）、clickhouse、mongodb、redis、
   taos 等在 Rust 侧均有成熟 crate；Dart 侧纯 Dart 端口少且薄。
5. **MCP（DBX 应对举措一）天然需要 server 侧驱动**——无论客户端架构如何，
   server 侧驱动层都必须建，收拢是顺势而非额外成本。

## 2. 决策

### 2.1 终局：Rust 单一 DB 能力层

所有 DB 连接/查询/元数据能力只存在于 server（含 embedded 本地实例，ADR-0003）。
Flutter 客户端只做 UI，经「DB 网关 API」访问一切数据库。与 DBX 的 dbx-core 结构对齐。

> **修订（2026-08-25 用户拍板）**：**SQLite 豁免**——定性「本地文件库」永久直连
> （`sqlite3` FFI + `sqlite_adapter.dart` 永久保留，不迁网关、适配器不退役）。
> 理由：无凭据入 vault 收益（文件路径非秘密）；原生体验（拖拽打开/PRAGMA/ATTACH/
> Save As）绑定本地适配器；远程模式走网关 = 打开 server 侧文件，语义断裂。
> 详见 `COMPLETED_LOG.md`「T29 决策：SQLite 豁免」。

### 2.2 DB 网关 API v1（迁移地基，M9 交付）

- **元数据**：`list_databases` / `list_tables` / `describe_table`——与 MCP Tier 1
  工具同源同一实现（MCP 工具是网关 API 的薄包装）。
- **查询执行**：流式行返回（chunked/SSE）+ 客户端取消 + `statement_timeout` +
  行限默认值；错误原样透传（保留各库错误码/语义）。
- **分析语义**：EXPLAIN / 锁分析等诊断查询作为普通查询透传，不在 v1 单列协议。
- **非 SQL 库预留**：Redis/Mongo/TDengine 的命令/文档/超表语义**v1 不实现但接口
  不堵死**（网关消息结构留 `kind` 判别字段）——语义设计见 ADR-0006（2026-08-26）。
- **横切**：认证/限流/审计复用 core；连接可见性按 workspace；SQL 明文不进日志
  （`sqlPreview` 纪律）。

### 2.3 新规矩：新增库只落 server 侧

今后新增数据库类型**不再写客户端 Dart 适配器**。M7（OceanBase/TiDB/StarRocks/
MariaDB）改为 server 侧 MySQL 兼容薄适配（照 DBX `tidb.rs` 模式），客户端经网关
使用——这些库与客户端既有 MySQL 交互 UI 同构，代理后 UI 层复用。

### 2.4 存量逐个迁移，SQL Server 首发

按痛感排序：**SQL Server 第一个**（server 加 tiberius ≈ +0.7MB（2026-08-15 实测），
客户端 FFI 整条路下线，sybdb.dll 问题连根拔）。其余按用户量逐个迁（**SQLite 除外**——§2.1 修订豁免），每个迁移
独立可发布、可回滚。迁移完成的判据：客户端该库适配器删除、全部真库 E2E 改走网关。

### 2.5 Oracle 路线（D6 附属决策点）

Rust oracle crate 需 OCI 原生库（等于 dll 问题搬家）。选项：a) JDBC 桥 agent
（照 DBX，JVM 依赖）；b) 暂缓（客户端现有路径维持）；c) 不做。默认 b，随 D6 拍板。

### 2.6 client-only 构建降级

`-SkipServer` 客户端-only 构建不再承诺 DB 查询能力（降级为开发/预览用途）；
embedded server exe 成为客户端**硬依赖**，必随包分发（当前 dist/Release 已如此）。
正式口径随 D6 拍板后写入 README。

## 3. 时序（与 DBX 应对计划的关系）

**依赖是反的：不是「先迁完再 MCP」，而是「MCP 逼出网关 API，迁移踩在验证过的
API 上」。**

```
MCP M1（T03-T08，只读 pilot：MySQL/PG/SQLite）   ← 网关 API 的 read 路径先行验证
  → M9 T27 网关 API v1 交互路径（流式/取消/元数据树，MySQL 协议族）
    → M9 T28 SQL Server 迁移试点（tiberius + 客户端 FFI 下线）
      → M7 T21-T25 新库 server 侧薄适配（不再依赖客户端适配层基建）
        → M9 T29 其余存量滚动迁移（按痛感，独立发布）
```

## 4. 风险与对策

| 风险 | 对策 |
|---|---|
| 大结果集经 localhost HTTP 的性能损耗 | 流式 + 分页；embedded 模式后续可换更高效 IPC（DBX 用 Tauri IPC，我们先 HTTP 证明正确性） |
| ~3700 单测 + 960 集成测试的迁移成本 | 逐库迁移、测试随库走；每库迁移带独立验收，不设大爆炸切换日 |
| 远程模式数据双跳（DB→server→client） | 审计/审批收益对冲；带宽敏感场景文档明示建议 embedded |
| 网关 API 设计缺陷返工 | MCP M1 先以 3 种库小面积验证 read 路径；写路径 T19 审批闭环再验证一次 |
| 迁移期间两套栈并存复杂度 | 2.3 新规矩止损：并存只减不增 |

## 5. 后续行动

- 执行清单落位：`task_dbx_response.md` 新增 **M9 网关+迁移**（T27-T29），
  M7 改 server 侧薄适配（依赖 T27）。
- **D6** 进 M0 拍板表：存量迁移节奏 / client-only 构建处置 / Oracle 路线。
