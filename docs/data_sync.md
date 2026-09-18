# Data Sync 功能文档

> 完整记录 data_sync 功能的设计、实现状态、测试覆盖、架构决策。
> 供未来维护和架构重构参考。

## 功能概述

Data Sync 是 dbmaster 的跨库数据同步（ETL）能力：
- **源库**（MySQL/PostgreSQL）按时间分批拉取数据
- 支持 **LEFT JOIN 多表**构建宽表
- 写入 **目标库**（MySQL/PostgreSQL/ClickHouse/Doris）
- 支持 **cron 调度**（周期执行）、**断点续传**、**取消**

## 架构

```
客户端 (Flutter DataSyncDialog)              服务端 (Rust data_sync crate)
┌──────────────────────────────┐           ┌────────────────────────────┐
│ 配置 UI（执行位置/JOIN/调度） │           │ runner.rs（ETL 引擎）       │
│   ├ 本地即时 → DataSyncService│           │   ├ 时间分批 + LEFT JOIN    │
│   └ 服务端后台 → DataSyncApi  │ HTTP     │   ├ 断点续传（cursor）       │
│      Service（REST 客户端）   │────────→ │   ├ 取消令牌                 │
│                              │           │   └ 多目标库分发             │
│ 任务列表面板                  │           │                              │
│   ├ 进度轮询（3s Timer）      │           │ scheduler.rs（cron 调度）    │
│   └ 运行/取消/历史/删除       │           │ clickhouse.rs（HTTP 写入）   │
└──────────────────────────────┘           │ doris_stream_load.rs（PUT）  │
                                           └────────────────────────────┘
```

## 实现分期

### 一期：端到端主线
- [x] server 端 `data_sync` crate（config/runner/scheduler/sql）
- [x] `DataSyncRunner` trait + AppState 注入
- [x] migration 006（data_sync_runs 表，含 progress/cursor/cancel）
- [x] automation handler 扩展（cancel/patch/progress 端点 + run_task_now 按 type 分发）
- [x] main.rs 装配双 runner + 双 scheduler
- [x] 客户端 TaskType.dataSync 接活 + ProTaskRegistrar 扩展
- [x] DataSyncApiService + wire 模型
- [x] DataSyncDialog 改造（执行位置 radio + 服务端提交分流）

### 二期：多表 JOIN UI + 任务面板
- [x] 多表 JOIN 配置 UI（动态关联表卡片 + ON 条件 + 选列 FilterChip）
- [x] 服务端任务列表面板（进度轮询 + 运行/取消/历史/删除）
- [x] 运行历史对话框
- [x] server_status_bar 加入口
- [x] 源/目标/分段/高级改卡片式 UI
- [x] JOIN 限定同源同库

### P0 修复（测试驱动）
- [x] target_strategy 格式对齐（upsert 带 key 的 map 格式）
- [x] batching.batch_size 语义修正（时间窗口秒数）
- [x] 本地即时模式取消接通 CancellationToken

### P1 健壮性
- [x] e2e 测试覆盖扩展（MySQL→MySQL / truncate / 增量）
- [x] cron 调度端到端测试（scan_and_dispatch）
- [x] _latestRuns map 收敛（防泄漏）
- [x] 误导性注释修正

### 三期：OLAP 目标库
- [x] ClickHouse server 端写入（HTTP INSERT FORMAT JSONEachRow）
- [x] Doris Stream Load（PUT /api/{db}/{table}/_load + JSON stream）
- [x] DbType 扩展（ClickHouse/Doris + 分发逻辑）
- [x] e2e 真实库测试（MySQL→CH / MySQL→Doris）

## 支持的目标库矩阵

| 源 \ 目标 | MySQL | PostgreSQL | ClickHouse | Doris |
|---|---|---|---|---|
| **MySQL** | ✅ e2e | ✅ e2e | ✅ e2e | ✅ e2e |
| **PostgreSQL** | ✅ 代码 | ✅ 代码 | ✅ 代码 | ✅ 代码 |

## 关键设计决策

### 1. 时间分批（非数值主键分批）
- 一期只支持时间字段分批（`WHERE time_field BETWEEN ? AND ?`）
- cursor 是 ISO8601 字符串，存 `data_sync_runs.cursor`
- `advance_cursor`：cursor + batch_size 秒
- 数值主键分批留未来

### 2. JOIN 在源库执行（非 server 内存 JOIN）
- runner 拼 `SELECT ... FROM main LEFT JOIN ... WHERE time >= ? AND time < ?`
- 源库优化器处理 JOIN，server 内存恒定（一批量）
- SELECT 时 CAST 所有列为字符串（解决跨库类型异构 + sqlx decode 问题）

### 3. 标识符方言感知（Dialect）
- MySQL/ClickHouse/Doris：反引号 `` `name` ``
- PostgreSQL/SQLite：双引号 `"name"`
- `sql::quote(name, dialect)` 按驱动选

### 4. ClickHouse/Doris 仅 server 端支持
- 客户端不建 CH/Doris adapter（决策：客户端数据库扩展重心移到 server）
- CH 走 HTTP 8123（JSONEachRow），Doris 走 BE 8040（Stream Load PUT）
- 连接只存 server 端 database_connections 表

### 5. Doris Stream Load 协议细节（实测）
- 端口：**BE 8040**（不是 FE 8030；FE 的 mini_load 在 3.0 默认禁用且配置项移除）
- 方法：PUT（不是 POST）
- 必需 header：`label`（唯一）、`Expect: 100-continue`、`format: json`、`read_json_by_line: true`
- sqlx 与 Doris 3.0 不兼容（SET 语句 + Nereids 优化器 prepared statement），DDL 需手动建

### 6. ClickHouse HTTP 协议细节（实测）
- 修改语句（CREATE/TRUNCATE）必须 POST + 非零 body（GET 强制 readonly，空 body POST 返 411）
- 表名必须带库名前缀（CH 默认库 ≠ 连接的 default_database）

## 测试覆盖

### 单元测试（cargo test --workspace，228 个）
- scheduler：is_due / cron 解析 / InFlightTasks
- config：标识符校验 / ON 条件白名单 / ConfigError
- sql：url_encode
- runner：cursor 解析 / advance_cursor / cursor_gt

### e2e 真实库测试（cargo test --test e2e_data_sync_test -- --ignored，7 个）
| # | 测试 | 验证 |
|---|---|---|
| 1 | MySQL→PG + JOIN | 宽表 5 行 + JOIN 字段正确 |
| 2 | upsert 幂等 | `{"upsert":"id"}` + 二次同步不重复 |
| 3 | MySQL→MySQL + truncate | same-driver + 清脏数据 |
| 4 | 增量同步（start cursor） | 只同步 >= start 的行 |
| 5 | cron 调度 dispatch | scan_and_dispatch 发现 due 任务 |
| 6 | MySQL→ClickHouse | HTTP JSONEachRow + 5 行 |
| 7 | MySQL→Doris Stream Load | PUT + JSON stream + NumberLoadedRows |

运行方式：
```bash
cd dbmaster-server
cargo test --test e2e_data_sync_test -- --ignored --nocapture --test-threads=1
```
（`--test-threads=1` 避免 MySQL CREATE DATABASE 并行冲突；`--ignored` 因依赖内网 192.168.x.x 测试库）

## 文件清单

### Server 端
| 文件 | 说明 |
|---|---|
| `crates/data_sync/src/config.rs` | DataSyncTaskConfig 强类型模型 + 标识符校验 |
| `crates/data_sync/src/runner.rs` | ETL 执行器（分批 JOIN + 断点续传 + 取消 + 多目标分发） |
| `crates/data_sync/src/scheduler.rs` | cron 调度器 |
| `crates/data_sync/src/clickhouse.rs` | ClickHouse HTTP 客户端 |
| `crates/data_sync/src/doris_stream_load.rs` | Doris Stream Load 客户端 |
| `crates/data_sync/src/sql.rs` | 标识符引用（Dialect 感知） |
| `crates/data_sync/src/lib.rs` | crate 入口 + trait bridge |
| `migrations/006_data_sync_v1.sql` | data_sync_runs 表 |
| `crates/core/src/server/mod.rs` | DataSyncRunner trait + AppState |
| `crates/automation/src/handler.rs` | cancel/patch/progress 端点 + run_task_now 分发 |

### Flutter 端
| 文件 | 说明 |
|---|---|
| `lib/pro/data_sync/data_sync_dialog.dart` | 配置/进度/结果三态对话框（JOIN UI + 执行位置 + 调度） |
| `lib/pro/data_sync/data_sync_service.dart` | 本地即时同步引擎（客户端直连） |
| `lib/pro/data_sync/data_sync_task_executor.dart` | TaskProvider 托管的执行器（预留，当前无 UI 入口） |
| `lib/services/data_sync_api_service.dart` | server 端 REST 客户端 |
| `lib/models/data_sync_api_models.dart` | DataSyncTask / DataSyncRunStatus wire 模型 |
| `lib/organisms/server/data_sync/data_sync_task_list_dialog.dart` | 任务列表面板（进度轮询） |
| `lib/organisms/server/data_sync/data_sync_run_history_dialog.dart` | 运行历史对话框 |

## 已知限制

- 本地即时模式只支持单表（JOIN 仅服务端模式）
- JOIN 限定同源同库（跨库 JOIN 留未来）
- 无 SSE 实时进度推送（用 3s 轮询）
- 列重命名 UI 未做（target 列名默认=源列名）
- Doris TRUNCATE 未实现（Stream Load 不支持 DDL，需走 9030 MySQL 协议）
- sqlx 与 Doris 3.0 不兼容（DDL 只能手动或用其他客户端）
