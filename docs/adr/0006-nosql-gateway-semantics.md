# ADR-0006: 非 SQL 库网关语义（Redis / MongoDB，TDengine 预留）

- **Status**: Accepted（2026-08-27 随 B1-B5 全批次落地转正；两个关键取舍
  2026-08-26 用户拍板——Pub/Sub 走 server 订阅转发、Pipeline 批量 + 原子
  包裹/WATCH fail-loud；§2.3/§2.4 两处实机修订见相应「修订」注记）
- **Deciders**: 用户 + 架构师
- **Context**: T29 滚动迁移（PROJECT_STATUS 待办清单 / `COMPLETED_LOG.md` T29 系列条目）；
  客户端现状 `dbmaster-flutter/lib/services/adapters/{redis_adapter,mongodb_adapter}.dart`；
  网关现状 `crates/gateway`（T27 交付）+ ADR-0005 §2.2 kind 预留
- **Supersedes**: 无（兑现 ADR-0005 §2.2「接口不堵死」的预留）
- **Related**: ADR-0005（单一 DB 能力层终局）、ADR-0003（embedded——网关的本地形态）

## 1. 背景与现状锚点

1. **ADR-0005 §2.2 预留待兑现**：Redis/Mongo/TDengine 的命令/文档语义 v1 不实现但接口
   不堵死。T29 SQL 侧已收（MySQL 族/PG/CH；SQLite 豁免），非 SQL 是最后一块存量。
2. **wire 预留双侧已就位**：`QueryBody.kind` 判别字段（v1 恒 "sql"，非 "sql" → 400
   `UNSUPPORTED_KIND`，`gw_query_sse.rs` `non_sql_kind_rejected_before_stream` 测试钉死）
   + 四个 SSE 事件 data 均带 `kind`；flutter 侧 `ExecutionChunk.kind`（`port_types.dart`）
   已预留 "redis"/"mongo"/"tdengine"。接入第一步 = 按批次放宽该校验 + 落腿实现。
3. **server 侧零实现、但有存储预留**：无 redis/mongodb crate；`DatabaseConnection.extra`
   JSON blob（migration 008）注释即「MongoDB cluster config, Redis auth mode」。
4. **客户端两适配器是重交互资产**：`RedisAdapter`（~2,363 行，RESP 命令面 + 类型化 key
   编辑 + Pub/Sub 专用连接 + pipeline/MULTI + Lua/Functions/ACL/Memory 面板）与
   `MongoDBAdapter`（~2,493 行，mongo_dart，shell/JSON 解析在客户端、断线自愈
   `_withReconnect`）；UI 经 `adapter is RedisAdapter/MongoDBAdapter` 强转消费十余面板。
5. **Rust 生态就绪**（ADR-0005 §1.4）：redis / mongodb crate 成熟；TDengine（taos）待凭据。

## 2. 决策

### 2.1 总原则：平行 kind 通道，复用网关骨架

非 SQL 库不是 SQL 的方言，是**平行执行通道**：

- `kind ∈ {sql, redis, mongo}`（`tdengine` 预留，凭据到位后另补语义）。kind 决定执行腿
  与请求/SSE 值域；连接注册、vault、取消（`X-Execution-Id` + `DELETE /executions`）、
  SSE 四事件骨架（meta/rows/complete/error）、错误码集（CONNECTION_FAILED / DB_ERROR /
  CANCELLED / TIMEOUT）、限流/审计**全部复用**，不另起 API。
- 元数据端点（databases/tables/describe）继续走 db_type 派发：`backend_for` 增
  Redis/Mongo 两腿（§2.6）。
- ADR-0005 §2.3 不变：本批迁移本身即「客户端驱动下线」。

### 2.2 连接注册 wire 扩展

- `ConnectionDraftBody`/`RegisterBody` 增 **`extra?: object`**（透传存入既有 extra 列；
  server 注册时防御性清洗：剔除 password 类键、剥 URI userinfo 再入库）。
- 字段映射（零新增专有字段，全部复用现有位）：
  - **Redis**：host/port；ACL 用户名→`username`、密码→`password`、db index→
    `defaultDatabase`（"0"/"5"…）；auth 三态（none/passwordOnly/usernamePassword）→
    `extra`。
  - **Mongo**：auth 库→`defaultDatabase`（缺省 admin）、密码→`password`；
    direct/replicaSet/sharded/advanced 四模式的 hosts/replicaSet/connectionString
    （客户端已剥离凭据）→ `extra`，server 腿据此组 ClientOptions、凭据分离注入
    （对齐客户端 `_openWithAuth` 先例）。
- 网关白名单 `SUPPORTED_DB_TYPES` 增 `redis`、`mongodb`；flutter
  `kGatewayWireDbTypes` 同步。

### 2.3 kind:"redis" 执行语义（命令通道）

**请求**：`{kind:"redis", command:["SCAN","0","MATCH","user:*","COUNT","100"],
database?, row_limit?, timeout_ms?}`——结构化参数数组（客户端已有引号感知解析，
解析留在壳内）；`database` 复用现有字段路由 SELECT；`timeout_ms` 生效；`row_limit`
钳数组展平上限。

**server 腿**（redis crate）：每执行开独立连接（AUTH+SELECT），drop 即取消——对齐
现有「专用池 max_connections(1)」锚点；订阅连接独立（§2.5）。

**命令分类与只读硬执行**：注册时拉 `ACL CAT`（write/dangerous 类）缓存，失败回退
静态表（与客户端 `validateCommand` 黑名单对齐：KEYS/FLUSHALL 等）；`read_only` 连接
拒写命令（error 事件 DB_ERROR + engineCode=READONLY）；read_only 下未知命令保守判写。
客户端本地守卫/警告保留（对齐 PG 壳先例）。

> **修订（2026-08-27，B3 实机钉定）**：「read_only 下未知命令保守判写」调整为
> **「未知按读放行」**——ACL CAT 不可得（Redis<6 / 无权限）时的兜底即静态表，
> 保守判写会连 GET 等常见读命令一并拒（静态表不可能穷举只读命令面）。
> ACL CAT 可得时分类是权威的（不在 write/dangerous 类即读）。另：redis-rs
> pipeline.atomic 覆盖 MULTI/EXEC + QUEUED 校验（不自写）；重复 query 参数
> 进 Vec 不被 serde_urlencoded 支持，订阅端点 channels/patterns 手工解析。

**SSE 映射**：白名单结构化命令（SCAN/HGETALL/ZRANGE WITHSCORES 等）给语义化
`meta.columns`；其余 fallback 单列 `["result"]`。值域为 JSON（RESP 类型自然映射：
integer→number、bulk→string、array→array、nil→null、status→string）；RESP error →
error 事件（engineCode=错误前缀，如 WRONGTYPE）。

**Pipeline / MULTI**：`{kind:"redis", pipeline:[[...],[...]], atomic?}`——单连接顺序
执行，逐条返回（rows = [序号, 结果] 两列）；`atomic:true` 由 server 包 MULTI/EXEC
（QUEUED 校验对齐客户端 `multiExec` 语义）。**WATCH/UNWATCH fail-loud**（跨请求连接
亲和；2026-08-26 用户拍板，对齐 SQL 族「事务 fail-loud」先例）；`discardTx` 同理，
恢复路径与 SQL 族事务恢复同表登记。

### 2.4 kind:"mongo" 执行语义（runCommand 单形状）

**请求**：`{kind:"mongo", database?, command:{...}, row_limit?, timeout_ms?}`——
**只有 runCommand 一个形状**，v1 不做 per-op 糖。理由：Mongo 全操作面（CRUD/聚合/
管理命令/GridFS stats/replicaSet）皆可表达为 db command；客户端
`MongoShellQueryParser` 本就解析出 find/aggregate/count/distinct 形状，翻成 command
文档成本低；server 腿最薄、覆盖最大。

**server 腿**（mongodb crate）：已知游标命令（find/aggregate/listCollections/
listIndexes…）流式展平吐 rows（firstBatch/nextBatch 文档流，批 ≤500 帧对齐）；
其余命令单文档单列 `["result"]` 返回。`row_limit` 截断文档数 + truncated 标记；
游标在流结束前 drop 即取消（对齐现有取消锚点）。

**rows 语义**：每文档一行（值域 JSON 对象）；语义列由客户端从文档推断（现有
executeQuery 行为），`columnTypes`（BSON 类型名）可选不承诺。

> **修订（2026-08-27，B2 实机钉定）**：**扩展 JSON 入向反解**——`{$oid}`/
> `{$date}`/`{$numberDecimal}` 单键子文档在 server 侧 `json_value_to_bson`
> 还原为原生 BSON 类型（畸形值放行普通 Document；`{'_id':{'$oid':…}}` 查询
> 与 Date 值写入是客户端高频用法，原「入向只接普通 JSON」边界取消）；
> `$date` 出向为 RFC3339（bson `DateTime` 的 Display 是 time 格式无 'T'，
> 实测不满足客户端 ISO 展示）。**行限**：find 族超 server `gw_query_max_rows`
> 时客户端壳侧按 `_id` 排序 skip 分页（自然序不稳定是分页正确性前提）；
> update/delete 计数经 affectedRows（n = 匹配数，nModified 不上 wire）。

**错误映射**：codeName（Unauthorized/NamespaceNotFound/…）→ `engineCode`；客户端
`_shouldReconnect`/`_withReconnect` 瞬态码表**整体作废**——网关无连接态，全部按
DB_ERROR 上抛，断线自愈代码删除。

**只读硬执行**：静态写命令集（insert/update/delete/create/drop/createIndexes/
renameCollection…）在 `read_only` 连接上拒绝；客户端 `guardReadOnlyQuery` 保留。

**集群**：extra 四模式由 server 腿组 ClientOptions（hosts/replica_set/
directConnection/uri）；Pro clusterStrategy（mongoCluster 门控）接线点在批次规划时定。

### 2.5 Pub/Sub：server 订阅转发（2026-08-26 用户拍板）

订阅长连接超出请求-响应通道，新增订阅专用 SSE 端点：

- `GET /api/gw/connections/:id/redis/subscriptions?channels=a&channels=b&patterns=p*`
  ——SSE 流，罩在既有 `auth::guard`（JWT + 限流 + 审计）下；事件 `subscribed`
  （确认回执）/ `message`（channel/pattern/payload）/ `error`；15s keep-alive 对齐
  查询流。
- server 每 SSE 流持**一条专用 redis 订阅连接**（RESP 单连接可多路
  subscribe/psubscribe）；`publish` 走命令通道（§2.3）。
- **生命周期挂 HTTP 连接**：客户端断开 SSE → server future drop → 订阅连接 drop；
  网关连接删除/心跳超时同理清理（订阅注册表挂 connection id），无需显式 DELETE。
- keyspace 通知 = `CONFIG SET notify-keyspace-events`（命令通道）+
  `psubscribe __keyevent@<db>__:*`（订阅通道），客户端现有用法不变。
- 上限：单订阅流 channel/pattern 总数钳制（默认 64）防滥用。

### 2.6 元数据语义映射（backend_for 增两腿）

| DbBackend 方法 | Redis | Mongo |
|---|---|---|
| list_databases | CONFIG GET databases / INFO keyspace（对齐 getNonEmptyDatabases） | listDatabases |
| list_tables | SCAN 全 key 按 `:` 前缀聚命名空间（对齐 getTables） | listCollectionNames |
| list_columns | 首 key 采样推类型（对齐 getTableColumns 退化实现） | 采样推 BSON 类型（`_inferBsonType` 语义） |
| list_indexes | —（空） | listIndexes |

health_check：redis db_type 已有 connectivity-only 降级路径（unsupported_db_type），
mongodb 同——不新增监控语义。

### 2.7 客户端壳形态（对齐 PG/MySQL/CH 壳先例）

- **类名/接口不变**（`RedisAdapter`/`MongoDBAdapter`），DatabaseService 工厂表、UI
  `is` 强转消费零改动。本地不持驱动连接，唯一状态 serverConnId + 本地记录位。
- **connect 三段式**：镜像复用（`connection_server_id_map` + dbType 校验）→ 草稿
  test → 现场注册（extra 透传）；凭据入 vault。
- **执行/聚合**：SSE 全量聚合 + 族异常码集对齐 c01 §4.4；
  `CONNECTION_FAILED`/`NOT_FOUND` → `onDisconnect`；stale 库自愈（redis：SELECT
  越界/NOAUTH；mongo：authSource/库不存在）；`useDatabase` record-only + database
  参数路由（对齐 PG 壳）。
- **保留/改造**：`MongoShellQueryParser`（翻成 command 文档）、`RedisResultFormatter`
  （改吃 JSON 值域）、`validateCommand` 本地警告、readonly guard 首行；
  `pubSubMessageStream` broadcast 流 API 形状保留，实现换订阅 SSE。
- **删除**：`redis`/`mongo_dart` 依赖、`_withReconnect`/`_shouldReconnect`、
  keep-alive PING 参与权、自装 `_RedisSafeParser`、Pub/Sub 本地双连接。

### 2.8 分批与验收判据

- **批次**：**Mongo 先**（纯请求-响应，无订阅/连接亲和难题，先验证 kind 派发机制与
  壳模式）→ Redis（含订阅转发端点，最重）→ TDengine（凭据到位后另立批次）。
- **判据**（ADR-0005 §2.4 同款）：客户端 `redis`/`mongo_dart` 依赖删除、全部真库
  E2E 改走网关、每库独立可发布可回滚。
- **测试**：server 腿真库单测（192.168.x.x Redis/Mongo 实例）；flutter 壳假 SSE
  回放单测（对标 mysql 壳 21 例先例）；集成套件（redis 42 例、mongo 现有套件）改
  网关全绿；订阅端点专项（断连清理/上限/keyspace 通知闭环）。

## 3. 明确不做（v1）

- TDengine 超表语义（凭据未到位，kind 判别位预留）。
- WATCH/UNWATCH 跨请求连接亲和（fail-loud，恢复路径与 SQL 族事务同表登记）。
- Redis/Mongo TLS 透传（沿用 T29 已知「TLS 透传」遗留边界）。
- MCP 的 Redis/Mongo read 工具（backend_for 腿就绪后的自然衍生，另行立项）。
- server 侧 Redis 连接池化（每执行独立连接，v1 优先简单；实测瓶颈再引入）。

## 4. 风险与对策

| 风险 | 对策 |
|---|---|
| mongodb crate 体积（tiberius 仅 +0.7MB，mongodb 可能数 MB） | 发布前实测 exe 增量并登记；必要时 feature 裁剪 |
| 订阅长连接泄漏（客户端崩溃不走优雅断开） | 生命周期挂 HTTP 断开 + 订阅注册表挂网关连接删除 + 心跳超时兜底 |
| Redis 命令分类表覆盖不全（新命令/模块命令） | ACL CAT 权威 + 静态表兜底 + read_only 下未知命令保守判写 |
| extra JSON 携带凭据（connectionString 内嵌密码） | server 注册时防御性清洗（剔 password 键/剥 URI userinfo）再入库 |
| mongo 文档异构导致列漂移 | 语义列由客户端按现有推断逻辑处理，meta 列可选不承诺 |
| 每 Redis 执行独立连接的握手开销（AUTH+SELECT 往返） | Redis 连接建立毫秒级；实测成瓶颈再引入池化（v1 不做） |

## 5. 后续行动

- ~~执行手册：`dbmaster-flutter/docs/tasks/task_t29_nosql.md`（批次分解 B1-B5 + 断点续传）。~~ ✅
- ~~首批 Mongo：server 腿 + wire → flutter 壳 → 真库 E2E；Redis 随后（含订阅端点）。~~ ✅（2026-08-27 B1-B5 全落地：Mongo `5ad4c8c`/`b5396ff3`，Redis `cf398f1`/`5db17e7e`；客户端 redis/mongo_dart 依赖已删）
- ~~本 ADR 随首批落地转 Accepted。~~ ✅（2026-08-27）
- 遗留：TDengine 超表语义（等 6041 凭据，kind 判别位预留）；WATCH 恢复
  路径与 SQL 族事务恢复同表登记；Redis/Mongo TLS 透传。

## 6. TDengine 批次兑现（2026-08-27，凭据到位后另立批次——§2.8 预告的兑现）

前提：真库 192.168.x.x:6041（taosAdapter REST，3.3.6.0 宿主原生安装，
root/<password>）。执行手册 `dbmaster-flutter/docs/tasks/task_t29_tdengine.md`。

- **通道**：TDengine 无 MySQL 协议口（CH 的 9004 先例不可复制）、原生驱动
  需 C 库——server 腿走 **taosAdapter REST + reqwest**（既有依赖，零新增
  crate；exe +112.5 KiB）。客户端旧适配器本就 REST 直连，SQL/元数据语义
  零漂移，只换发起方。
- **kind:"tdengine"**（判别位兑现）：载荷 = `sql` + `database`（REST URL
  路径路由）；单语句约束同 kind:"sql"；SSE 四事件 kind 判别随请求。
- **写通道**：TDengine 写（DML+DDL）REST 响应恒为单列 `affected_rows`
  形状（INSERT 实际行数 / DDL 0）→ affectedRows 通道（对齐 §2.4 mongo 写
  通道），无数据事件。判定 = 语句静态分类 AND 响应形状（防
  `SELECT affected_rows` 假阳性）。
- **columnTypes 原生名保真**：TDengine column_meta 自带原生类型名
  （TIMESTAMP/VARCHAR…）——CH 批次经 MySQL 口的类型名缺口在 TD 不存在；
  壳侧消费做 TIMESTAMP 格式化（RFC3339/epoch → 本地字符串）。
- **只读硬执行**：静态首词分类（INSERT/CREATE/DROP/…13 词）+ 前导注释
  剥离；read_only 连接拒写，engineCode=READONLY。
- **客户端形态**：B 批次同款——`tdengine_gateway_adapter.dart`（类名
  `TDengineAdapter` 不变）+ 旧文件 3 行 re-export shim；**事务 fail-loud**
  （旧适配器是静默 no-op 假事务，本批修正为不 implements
  TransactionalAdapter + UnsupportedError，对齐 CH）。
- **实机钉定**（3.3.6.0）：认证失败 = HTTP 200 + code **855**（非 401，
  exec_sql 集中归一连接级）；缺表引擎码 **9731**；DESCRIBE 实际 **7 列**
  （field/type/length/note/encode/compress/level），TAG 标记在 **note** 列
  （旧客户端代码读 index 4 判 TAG 是死代码——那是 encode 列，壳已修）；
  超表 ts 列 note 为空（PRIMARY KEY 标记只在普通表出现）；BINARY(16) 列
  DESCRIBE/SELECT 显示 VARCHAR；`as count` 是保留字冲突（9728 语法错，
  壳改 `AS cnt`）；TBNAME 是扫描型伪列——空子表不出行（集成断言先插数）。

### 遗留更新

- ~~TDengine 超表语义（等 6041 凭据，kind 判别位预留）~~ ✅ 2026-08-27 兑现。
- 仍遗留：WATCH 恢复路径（与 SQL 族事务同表）；Redis/Mongo/TDengine TLS
  透传（TD REST 的 https 端口同理，v1 假设内网明文）。
