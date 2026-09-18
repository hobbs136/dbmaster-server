# ADR-0001 — Server License System（签发 / 14 天试用 / 激活 API / 续费提醒 / 凭据加密）

- **Status**: **Accepted**（2026-08-05 用户打包接受 §11 全部推荐：D1=B 独立 keypair / D3=C v2 解耦 / D4=A install_uuid / D8.1=A env+fail-fast / Q5=首发手工核支付截图）
- **Date**: 2026-08-05
- **Author**: architect（首席架构师）
- **Supersedes**: 无
- **Related**: `.workflows/server-pricing-review/03-recommend.md`（路线 ③ 的硬欠债项）; `license-signing-guide.md`（桌面签发退役过渡）
- **Deciders**: 用户（§11 不可逆点已于 2026-08-05 全部拍板）

## Revision: 2026-08-12 — #3 License HTTP API（运行时 entitlement swap）

> **范围**：本 ADR §4 D7、§7.1 的「entitlement resolved once at boot; mid-run changes require restart. v1-acceptable per ADR §4 D7」经 TASKS.md #3 突破。本次修订记录现状，不撤回任何 §11 不可逆决策。

**变更**：

1. `AppState.entitlement` 字段类型从 `Arc<EntitlementState>` 改为 `Arc<arc_swap::ArcSwap<EntitlementState>>`（外层 `Arc` 保 `AppState: Clone`，axum 要求）。读路径仍是无锁的（`load()` 返 `Guard` deref 至 `Arc<EntitlementState>`）；写路径用 `store(Arc::new(state))` 原子 swap。
2. 新增 2 个 HTTP 端点（详见 `.specs/{brainstorm,requirements,design,tasks}-license-activation.md`）：
   - `GET /api/instance`（unauthenticated）— 暴露 `install_uuid` + `version` + `embedded_mode`。让 client/admin 激活前能读到实例标识。
   - `POST /api/license` — 接收 license PEM 文本，复用 `resolve_entitlement_with_text` 验签 + instance 匹配 + 过期检查；通过则原子写 `.dbmlicense`（temp + rename + Unix 0600）后 swap entitlement。**写文件成功是 swap 的前置条件**，保证 entitlement 与磁盘状态一致。
3. POST /api/license 鉴权策略：
   - **embedded 模式**：直接返 `{ok:false, error.code:"FORBIDDEN"}` 短路（embedded 已合成 lifetime Licensed，POST 无意义）。
   - **remote 模式**：env var `DBMASTER_SERVER_ADMIN_TOKEN` 配置后，POST 必须带 `X-Admin-Token` 头匹配；env 未配置则 POST 全部返 403。token 比较用 `subtle::ConstantTimeEq`（防 timing attack）。注意：**Ed25519 验签是真正的安全边界**，admin token 仅用于限流防 spam。
4. **scheduler 行为不变**：drift/data_sync/health_check 三个 scheduler 仍只在 boot 时 `!entitlement.is_gated()` spawn。POST 把 Gated→Licensed 后 HTTP gate 立即放行（automation_handler 的 `gate_blocked` 读 ArcSwap 即时反映），但**定时任务仍需重启才起**——响应里 `scheduler_note: "restart_required_for_schedulers"` 明示。

**保留的不变式**：
- license blob v2 格式不动（lib.rs:58 `LICENSE_VERSION`）。
- 私钥永不出现在 server crate（仅 tech-site env var 持有）。
- `resolve_entitlement_with_text` 验签在任何状态变更之前。
- 写文件失败时旧 entitlement 完整保留，绝不半 swap。
- 既有 `GET /api/entitlement` 响应 shape 不变。

**仍待（不在本修订范围）**：
- TASKS.md #12（P1）— Ed25519 公钥常量 `SERVER_PUBLIC_KEY_HEX` 仍是 DEV/TEST 种子，pre-release blocker。生产公钥替换是独立的不可逆发布前操作，单独立 spec。
- client 激活 UI + tech-site auto-push license 到 server（决策点 5 选 A，留后续 spec）。

---

## 1. 背景与动机

### 1.1 商业约束（已锁定，不在本 ADR 讨论范围）

- **DbMaster Server = 主收入**（¥399/年/实例，BSL 1.1），桌面端全免费（Apache 2.0，获客）。
- 自托管（Docker / 单二进制），**诚实用户模式**：离线 license、不硬防破解，付费根基 = 合规 + 更新 + 支持。license 删代码重编译可绕过，结构性接受。
- **当前零付费客户** → 决策可在干净起点上做，不必为存量重新签字。
- 单人兼职产能 → 定律 1（个人维护成本第一约束）放在所有取舍的最前面。

### 1.2 现状 ground truth（已读源码核实，**修正了脑暴文档的两条过时假设**）

| 项 | 现状 | 来源 |
|---|---|---|
| 桌面 Dart 签发+验签 | 成熟：`license_signer.dart`（CLI）/ `license_verifier.dart`（内置公钥 `5041f821…3865a`，2026-07-19 生成）/ `license_models.dart` / `machine_code.dart` | `dbmaster-server/crates/license/src/*.dart` |
| Rust `verify_license` | 仅验签；**未接入任何执行路径**（gating 不存在） | `dbmaster-server/crates/license/src/lib.rs` |
| **激活 API** | **tech-site 已实现**（脑暴文档说"没有"是过时的）：`/api/activate`、`/api/deactivate`、`/api/license/{id}`、`/api/renewal/check`（占位） | `dbmaster-tech-site/activate.go` |
| activations/deactivations 表 | **已在 tech-site SQLite 存在** | `dbmaster-tech-site/store.go` |
| 14 天试用 | **不存在**；桌面 trial 已于 2026-07-29 删除，`trial_usage` 表与端点已废弃 | `dbmaster-tech-site/main.go` |
| Server license 数据表 | **不存在**（Server SQLite 仅有 users/workspaces/connections/tasks/approvals/queries/reports/telemetry） | `dbmaster-server/migrations/00*.sql` |
| Server 实例指纹 | **未定义**；`verify_license(fingerprint, …)` 的 fingerprint 来源从未确定 | — |
| 凭据加密 | **明文**：`format!("enc:{}", password)`，挂 `// CHANGE: encrypt with AES-256-GCM in production` | `dbmaster-server/crates/automation/src/handler.rs:126` |

### 1.3 已发现的契约漂移（**问题报告，本 ADR 不擅自修改**）

> 这是脑暴文档没提到的、跨组件契约（架构师定律 2）的既有违反。本 ADR 负责给出修复方案，但修改桌面端代码须经用户拍板（定律 5）。

**三种互不兼容的 license 负载格式共存：**

| 端 | 规范化形式 | 字段命名 | 输出封装 |
|---|---|---|---|
| Dart 桌面 | 签名 = `base64url(JSON).` 的 ASCII 字节 | camelCase（`issuedAt` / `expiresAt`） | JWT 式 `payload.sig`（均 base64url） |
| Rust `verify_license` | `email:X\nmachine:Y\ntype:Z\nissued_at:I[\nexpires_at:E]` | snake_case | 入参为字段+hex sig |
| Go `signLicense` | 与 Rust 相同的 line-based canonical | snake_case | PEM-like 文本块 `-----BEGIN DBMaster LICENSE-----…signature: <hex>-----END…` |

**含义**：Rust 与 Go 在 canonical *串*上一致（line-based、字母序、snake_case），但**输出封装不同**；Dart 在 canonical *串*、字段命名、封装三方面全不同。三者签出来的 license 互不兼容。当前无功能影响仅因 Rust `verify_license` 没人调用——一旦接入就会暴露。

**修复必须做、且必须先于"接入验签"完成**（§4.3 决策 D3）。

---

## 2. 决策驱动因素（按优先级）

1. **定律 1（个人维护成本）**：能复用栈内已有件（Go signer / Dart signer / Rust verifier）则不新造；不引入新语言运行时 / 新服务。
2. **定律 5（安全/数据完整性）**：私钥永不离开签发侧；凭据加密不"以后再说"。
3. **离线优先**：license 导入后 Server 应能离线验签；但激活/签发/续费提醒须联网到 tech-site。
4. **诚实用户模式**：不与决定的破解者对抗。所有"防作弊"机制只要挡住"诚实用户的误操作"与"懒惰用户的复制粘贴"即可，挡住"删表重编译"不在目标内。
5. **定律 2（契约单向演化）**：跨组件契约只加不删；本 ADR 给出的格式定义为 v2（Server 全新产品），与桌面 v1 解耦。
6. **定律 3（依赖单向）**：`site → server`、`client → server`，反向依赖禁止。Server 不能给自己签 license（那就等于没签）。
7. **定律 4（不可逆走 ADR）**：本文件即 ADR；可逆决策（如 `trial_state` 表名）不在此赘述。

---

## 3. 范围

**IN**：Server license 系统全链——密钥归属、签发实现、负载格式、实例指纹、14 天试用、激活/换绑 API、续费提醒、凭据加密修复。

**OUT**（明确排除）：
- 桌面端 license 体系的退役细节（属 `license-signing-guide.md` 已涵盖）。
- 按席位定价（`seats` 字段）——已在前置脑暴中排除。
- 支付通道集成（PayPal/支付宝的具体对接）——属 sales/marketing 范畴。
- 支付侧的 receipt 验证（Stripe/PayPal webhook）——本 ADR 只给"激活 API 入口"约束，不规定对接实现。

---

## 4. 决策

每条决策给出 2–3 个选项 + 取舍 + 推荐。**标记 🔴 的决策需用户拍板**（定律 5）。

### 4.1 D1 — 密钥归属 🔴

**问题**：Server 用桌面端现有 Ed25519 keypair，还是独立生成一对？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. 复用桌面 keypair** | 同一 `private_key.hex`，同一已发布公钥 `5041f821…3865a` | + 单一密钥源、运维简单；− **爆炸半径耦合**：tech-site 私钥泄露 = 桌面 + Server 全部可伪造；桌面是 Apache 免费产品（低风险），Server 是付费主收入（高风险），混在一起把低风险侧的暴露面带进高风险侧 |
| **B. Server 独立 keypair** | 新生成 `server_private_key.hex`；Server 端验签内置对应公钥 | + 爆炸半径隔离；按产品线独立轮换；与"桌面 license 系统退役"方向一致；− 多一对私钥要离线备份；tech-site 多一个 env var（`DBMASTER_SERVER_LICENSE_PRIVATE_KEY`） |
| C. 多 keypair + keyId 字段 | 负载加 `keyId`，验签端按 id 选公钥，支持平滑轮换 | 过度设计（定律 1）。零客户阶段不需要。**淘汰** |

**推荐 B（Server 独立 keypair）**。理由：
- 定律 5（爆炸半径隔离）— 付费产品线不应继承免费产品线的密钥暴露面。
- 桌面 license 系统已在退役过渡（`license-signing-guide.md` 2026-07-29 note），把它的密钥带进未来是反向投资。
- Rust `verify_license` 入参为 `public_key_hex`（非内置），换公钥零代码变更。
- 成本：多一个 env var + 一份离线备份，可忽略。

**🔴 需用户拍板**：理由是它影响"已发布桌面公钥是否被视作共享信任根"这一不可逆命题（虽然现在零客户，但桌面公钥已编译进所有已发布包）。一旦 Server 用同一公钥，未来想再拆分需让桌面端重新打包发布。

---

### 4.2 D2 — 签发侧实现

**问题**：在哪、用什么语言签发 Server license？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. 复用 tech-site Go signer（status quo）** | `activate.go` 已实现 Ed25519 签发 + 存 activations + 4 个 API | + 零新代码；定律 1 / 定律 3（site→server）天然满足；− 需要把 `DBMASTER_LICENSE_PRIVATE_KEY` 换成 D1 选 B 后的 Server 私钥（一个 env var 改名级别） |
| B. Rust 重写，跑在 Server 二进制内 | Server 自己签 license | **违反定律 3**：Server 是被授权对象，自己给自己签 = 无 DRM。淘汰 |
| C. 独立签发微服务 | 新语言/新服务 | **违反定律 1**：单人维护不起，过度设计。淘汰 |

**推荐 A（复用 Go signer）**。无争议，符合所有定律。D2 不需用户拍板。

---

### 4.3 D3 — license 负载格式 🔴

**问题**：Server license 标准化为哪种格式？这是 §1.3 契约漂移的修复决策。

| 选项 | 描述 | 取舍 |
|---|---|---|
| A. 采用 Dart 桌面格式（base64url JSON、JWT 式） | Rust/Go 都改成 JSON canonical、camelCase | + 桌面代码路径"已验证"；− **JSON 规范化脆弱**：Dart `jsonEncode` 用 Map 字面量插入序保证 key 序，跨语言重实现易踩坑（Go `encoding/json` 默认字典序、Rust `serde_json` 也字典序——与 Dart 不一致）；需重写 Rust `verify_license` + Go signer |
| B. 采用 line-based canonical（现 Rust/Go 一致），让 Dart 迁移 | Server 走 line-based；桌面端改 verify + 重签存量 | + canonical 简单无歧义；Rust/Go 已对齐；− **要改桌面代码**（定律 5：跨组件契约变更，需用户拍板）；桌面虽在退役，但已发布包内置的 verifier 还会运行若干年 |
| **C. Server 全新 v2 格式，与桌面解耦** | Server license = `{v:2, product:"server", email, instance_id, type, issued_at, expires_at}`，line-based canonical；桌面 v1 冻结 | + 完全隔离（配合 D1=B）；Server 可加 `product`/`instance_id` 等领域字段不污染桌面；定律 3（组件独立交付）；桌面代码零改动；− 长期两套格式并存（但桌面那套已退役冻结，维护成本≈0） |

**推荐 C（Server v2 格式，与桌面解耦）**。理由：
- 桌面免费 + license 退役；Server 付费 + 全新。耦合两者无收益。
- 配合 D1=B（独立 keypair）形成完整的产品线隔离。
- v2 加 `product:"server"` 字段给未来"一个验证器验多个产品"留扩展位（向前兼容的契约演化，定律 2）。
- 桌面代码零改动 = 不触发定律 5 的越界上报链。

**v2 canonical 形式（提议）**：
```
email:{email}
expires_at:{iso8601 or empty}
instance_id:{instance_fingerprint}
issued_at:{iso8601}
product:server
type:yearly|lifetime
v:2
```
（行字典序、LF 分隔、无尾换行；`expires_at` lifetime 留空行——保留位置以便 canonical 稳定）

**输出封装**：建议保留 Go 现有 PEM-like 文本块（人眼可读、邮件友好），但 BEGIN 行改为 `-----BEGIN DBMASTER SERVER LICENSE-----`，并加 `product: server` 字段。

**🔴 需用户拍板**：理由是新跨组件契约（v2）的形态定义、是否接受"桌面与 Server 永久两套格式"这一长期事实。一旦发布即不可逆（已签 license 在客户手里）。

---

### 4.4 D4 — Server 实例指纹 🔴

**问题**：license 绑的"实例指纹"具体是什么？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. install_uuid**（首次启动生成，存 SQLite） | 32 字节随机 → hex；`telemetry_events` 表已有 `install_uuid` 概念，复用语义 | + 实现简单；离线可用；Docker 卷持久化即保留；迁移场景"license 跟着数据走"是 self-hoster 期望行为；− 删表即重置（诚实用户模式接受） |
| B. 宿主派生（hostname+MAC+CPU） | 仿桌面 hardware ID 路线 | + 重置成本高；− Docker 内 MAC/hostname 易变（除非显式配置），合法迁移就坏掉；多写跨平台代码；与"容器化优先"现代部署相悖 |
| C. install_uuid + epheemeral 签名挑战 | Server 用一次性密钥签 install_uuid，tech-site 验 | 过度设计。诚实用户模式不需要。**淘汰** |

**推荐 A（install_uuid）**。理由：
- 诚实用户模式明确接受"删表重置"。
- 配合 D5（14 天试用）共用同一行存储，一次重置 = 一次全新试用，**自洽**（既不放大也不缩小作弊面）。
- 自助换绑（D6）让"DB 恢复到新机"非问题：用户调 `/api/deactivate` 重绑即可。
- 与现有 `telemetry_events.install_uuid` 语义一致，不引入新标识体系。

**实现位置**：新表 `instance_meta(install_uuid TEXT PRIMARY KEY, created_at TEXT NOT NULL, trial_started_at TEXT, trial_expires_at TEXT)`，或复用现有 `telemetry_events` 的 install_uuid 来源（若已有生成逻辑）。

**🔴 需用户拍板**：定义"绑机契约"——客户买的是"一个实例"，"实例"="一个 install_uuid"。这是许可证的法律语义边界（一个 install_uuid = 一份 ¥399），需用户而非架构师代为承诺。

---

### 4.5 D5 — 14 天试用机制

**问题**：试用计时存哪？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. Server 本地 SQLite（`instance_meta.trial_started_at`）** | 首次启动若无 license 且无 trial 行 → 写入 `trial_started_at = now()`、`trial_expires_at = now()+14d` | + 离线优先；简单；与 D4 共用存储；− 删行重置（诚实用户模式接受） |
| B. license 字段（tech-site 签发"试用 license"） | 用户先访问 tech-site 拿 14 天 license | **违反离线优先**：装好 Server 第一件事是联网拿 trial，UX 差；还要收邮箱（隐私摩擦）；tech-site 要做 trial 状态权威 |
| C. 混合：本地计时 + 可选 tech-site 校验 | 默认本地；Server 在线时 ping tech-site 延长/校验 | 过度设计。诚实用户模式不需要。**淘汰** |

**推荐 A（本地 SQLite）**。理由：
- 离线优先是硬约束。
- 试用数据通过现有 `telemetry_events`（已有渠道）做漏斗分析，不靠它做强制。
- 启动顺序：`if no license and no trial_state → create trial_state(now, now+14d); if now < trial_expires_at → trial_active; else → gated`。

D5 不需用户拍板（可逆：表结构变更即可重做）。

---

### 4.6 D6 — 激活 API 模型

**问题**：`/api/activate` 与 `/api/deactivate` 走无状态重签还是存储 entitlement？

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. 存储 entitlement（status quo）** | tech-site 已实现 activations/deactivations 表 | + 审计 trail；可做换绑频次限制；已实现；− tech-site SQLite 是 entitlement SoR，丢失=审计丢失（但已签 license 离线仍有效） |
| B. 无状态重签 | 不存 activations，每次激活即重签 | 无审计、无防滥用。对付费产品不可接受。**淘汰** |
| C. 外部 entitlement（Stripe/LemonSqueezy） | 把 entitlement 交给支付提供商 | 与现有 PayPal/支付宝直销冲突；新依赖（定律 1）。**淘汰** |

**推荐 A（status quo + 加固）**。已实现的部分保留，补三个硬缺口：

1. **支付验证闸门**（**售卖前必须**）。当前 `activate` 接收 `payment_id` 字符串但**不验证**——任何有 admin token 的人可签任意 license。最小可行方案：
   - 短期（首发）：admin token 即支付证明（admin 在 entries 表看到付款截图后手工签发，已有流程）。
   - 中期：加 `/api/activate` 的 `payment_proof`（PayPal transaction ID / 支付宝订单号），admin 后台点"确认"才放行；或对接 PayPal IPN（非本 ADR 范围）。
2. **换绑频次限制**：`deactivate` 加"每邮箱每年最多 3 次换绑"软上限（合法硬件迁移够用；超过则进人工审核）。当前 `handleDeactivate` 只有 IP 级 ratelimit，缺这层。
3. **审计日志**：每次 activate/deactivate 记录 actor（admin token 标识）、IP、时间、fingerprint 变更前后。日志不包含 license 私钥/连接凭据（定律 5）。

D6 主体不需用户拍板（已实现的方向正确）；但 §1（支付验证策略：手工 vs IPN）涉及 sales 政策，**转交 sales 评估**（本 ADR 仅标"必须补"）。

---

### 4.7 D7 — 续费提醒

**问题**：30/7 天邮件提醒由谁触发？

| 选项 | 描述 | 取舍 |
|---|---|---|
| A. tech-site 定时任务 | cron 扫 activations，到期前 30/7 天发邮件 | + 数据已在 activations；集中发信；离线 Server 不影响；− tech-site 需 SMTP 配置（新依赖） |
| B. Server 自检到期后触发 | Server 启动/定时检查 license.expires_at，临近时 ping tech-site `/api/renewal/check` 发邮件 | + Server UI 可同时弹"7 天到期"横幅；− 离线 Server 发不出邮件；要 Server 主动 phone home（隐私） |
| **C. 混合：Server UI 横幅（本地） + tech-site 邮件 cron（中心）** | Server 启动检查本地 license.expires_at 显示横幅；tech-site 独立 cron 发邮件 | + 双通道覆盖；Server 离线仍有 UI 提醒；tech-site 不依赖各 Server 实例 phone home；− 两边都要实现（但都是小活） |

**推荐 C（混合）**。理由：
- Server UI 横幅 = 本地、离线、好 UX。
- tech-site 邮件 cron = 给"装了就忘"的用户兜底。
- 邮箱来源：激活时已收（`activations.email`），不新增收集点。

**实现要点**：
- tech-site 加 schema：`ALTER TABLE activations ADD COLUMN reminder_30_sent INTEGER DEFAULT 0; ADD COLUMN reminder_7_sent INTEGER DEFAULT 0;`（迁移脚本 `00X_renewal_tracking.sql`）。
- tech-site 加 cron（每日 09:00 UTC）：扫 `yearly AND revoked=0 AND reminder_X_sent=0 AND expires_at BETWEEN now() AND now()+Nd` → 发邮件 + 置位。
- Server UI：启动时读 license payload 的 `expires_at`，在剩 30/7 天时显示横幅（已有 `verify_license` 解出的 payload 字段）。
- 邮件发送使用标准 `net/smtp`；SMTP 配置 `DBMASTER_SMTP_HOST/PORT/USER/PASS/FROM` 走 env var（定律 5：凭据走 env，不入库）。

D7 不需用户拍板（可逆）。

---

### 4.8 D8 — 凭据加密修复（关联安全项）🔴

**问题**：`create_connection` 的 `format!("enc:{}", password)` 改为真 AES-256-GCM。三个子决策。

#### D8.1 主密钥来源 🔴

| 选项 | 描述 | 取舍 |
|---|---|---|
| **A. env var（运维显式提供）** | `DBMASTER_CREDENTIAL_KEY` = 32 字节 hex；运维 `openssl rand -hex 32` 生成 | + 标准实践；符合全局 CLAUDE.md "密钥通过环境变量注入"；− 运维必须设；缺失应 fail-fast |
| B. 自动生成存盘（per-install） | 首启生成随机 key 写 `<data_dir>/credential.key`（0600） | + 零配置；− 备份责任在运维（易忘 → 迁移后解密失败）；与全局规则冲突 |
| C. KMS（AWS/Vault） | 托管 KMS | 自托管单人产品不需要。**淘汰** |

**推荐 A（env var）+ 生产模式 fail-fast**。建议行为：
- `DBMASTER_CREDENTIAL_KEY` 缺失时：开发模式（`DBMASTER_DEV=1`）自动生成临时 key 并打 WARN；生产模式拒启。
- 启动时打印 key 的 sha256 前 8 字节用于运维核对（不泄露 key 本体）。

**🔴 需用户拍板**：fail-fast vs 零配置自动生成的运维体验取舍，影响首次部署的"开箱即用性"。

#### D8.2 密文格式

不复用桌面 `ConnectionEncryptionUtil`（那是 PBKDF2 用户口令派生，模型不同——Server 是 master key 直接用）。

提议格式：
```
v1:<nonce_12B_base64>:<ct+tag_base64>
```
- `v1` 前缀做版本化（避免重蹈 `enc:` 无版本覆辙）。
- 12 字节随机 nonce（GCM 标准），每次加密独立生成。
- ct + 16 字节 GCM tag 拼接后 base64。
- AES-256-GCM（Rust crate `aes-gcm`）。

#### D8.3 向后兼容 / 迁移

现有 `database_connections.password_encrypted` 中存在两类数据：
1. 真的 `enc:` 前缀的明文（开发期产生）。
2. （未来）`v1:...` 密文。

**迁移脚本**（一次性，部署时跑）：
```sql
-- 003_credential_reencrypt.sql（示意，实际由 Rust 迁移代码执行）
-- 1. 扫所有 password_encrypted LIKE 'enc:%'
-- 2. 在 Rust 内：strip "enc:" → 得明文 → 用 DBMASTER_CREDENTIAL_KEY 走 v1 加密 → 回写
-- 3. 完成后 row 计数与日志（不打印任何明文/密文）
```

**解码兼容期**（同进程内）：
```rust
fn decrypt_password(stored: &str, key: &[u8]) -> Result<String> {
    if let Some(plain) = stored.strip_prefix("enc:") {
        // DEFENSIVE-NOTE: 遗留明文格式；生产模式下记 warn 并返回，
        // 待 003 迁移完成后此分支可移除（标记 deprecated）。
        tracing::warn!("legacy plaintext credential found (enc: prefix); run 003 migration");
        return Ok(plain.to_string());
    }
    if let Some(rest) = stored.strip_prefix("v1:") {
        // 解析 nonce:ct+tag，AES-256-GCM 解密
        return decrypt_v1(rest, key);
    }
    Err("unknown credential format")
}
```

**写入路径**：`create_connection` / 任何更新密码处统一用 `encrypt_v1(plaintext, key)` 输出 `v1:...`。

**安全核对（定律 5 逐条）**：
- [x] 主密钥走 env var，不入库、不进日志。
- [x] AES-256-GCM 提供 confidentiality + integrity（GCM tag 防篡改）。
- [x] nonce 每次随机（避免 GCM nonce 重用灾难）。
- [x] 迁移脚本不打印明文/密文，仅打印行数。
- [x] 解码失败显式报错，不静默吞（`Result<String>` 上抛）。
- [x] 审计日志记录"何时何连接的密码被更新/解密"，不记录密码本体。

---

## 5. 推荐方案汇总（一条命令版）

> 假设用户在 §11 全部采纳推荐：

**密钥**：Server 独立 Ed25519 keypair（D1=B）；私钥 `server_private_key.hex` 离线备份，tech-site 通过 `DBMASTER_SERVER_LICENSE_PRIVATE_KEY` env var 加载。

**签发**：复用 tech-site Go `signLicense`，canonical 改为 v2 line-based（含 `product:server`、`instance_id`、`v:2`），输出 PEM-like（D2=A、D3=C）。

**验签**：Rust `verify_license` 重写为 v2 canonical + 内置 Server 公钥；Server 启动读 `.dbmlicense`（或 `DBMASTER_LICENSE_FILE` env）→ 解析 → 验签 → 比 `instance_meta.install_uuid` → 比 `expires_at` → 设置 `entitlement_state`。

**实例标识**：`instance_meta` 表存 `install_uuid`（首次启动随机生成）+ trial 时间戳（D4=A、D5=A）。

**试用**：首次启动无 license → 自动开 14 天 trial（本地计时，本地强制）；过期 → gates 关闭（D5=A）。

**激活**：tech-site `/api/activate`（admin token + 支付证明）→ 签 v2 license → 客户粘贴/导入到 Server。`/api/deactivate`（每邮箱每年 ≤3 次软上限）做自助换绑（D6=A + 加固）。

**续费**：Server UI 横幅（本地） + tech-site 每日 cron 邮件（30/7 天）（D7=C）。

**凭据**：`create_connection` 改 AES-256-GCM（v1 格式），主密钥 `DBMASTER_CREDENTIAL_KEY` env var（生产 fail-fast），一次性迁移脚本处理 `enc:` 遗留（D8）。

---

## 6. 安全考量（定律 5 全条对照）

| 资产 | 威胁 | 缓解 |
|---|---|---|
| license 私钥 | tech-site 被入侵 → 私钥泄露 → 任意伪造 | 独立 keypair（D1=B）隔离桌面；env var 加载（不落 tech-site 盘）；离线备份；轮换流程文档化 |
| 连接凭据 | DB 文件被偷 → 明文密码泄露 | AES-256-GCM v1（D8）；主密钥走 env var 不入库；迁移 `enc:` 遗留 |
| license 持久化 | 客户机 DB 被偷 → 无法防御（license 本来就客户持球） | 不试图防御；接受 |
| trial 重置 | 删 `instance_meta` 行 → 重获 14 天 | 诚实用户模式接受；通过 telemetry 观测频率做漏斗分析，不做强制 |
| 激活 API 滥用 | 伪造支付证明 → 骗签 license | D6.1 支付验证闸门（首发：admin 手工核截图；中期：payment_id 验证） |
| 换绑滥用 | 一份 license 给 N 台机器用 | D6.2 每邮箱每年 ≤3 次软上限，超过进人工 |
| 日志泄露 | 日志含密码/token/PII | 沿用 `dbmaster-tech-site/main.go` 的 logger（已声明不记 token/email/上传内容）；Rust 侧 tracing 同约束；迁移脚本只打 row count |
| 多步操作回滚 | license 签发/换绑/迁移多步失败留脏 | activations + deactivations 表事务化（已实现）；凭据迁移脚本 idempotent（重跑只处理仍是 `enc:` 的行） |

---

## 7. 跨组件影响

### 7.1 dbmaster-server（Rust）
- **license crate**：`verify_license` 重写为 v2 canonical + 内置 Server 公钥（替换 hex 入参为编译期常量）；新增 `parse_license(text)` 与 `entitlement_state` 模块。
- **新 crate 或 module**：`instance`（install_uuid 生成与持久化）、`trial`（试用状态机）、`entitlement`（启动时验证 + gate）。
- **automation crate**：`create_connection` 用 `aes-gcm` crate 改 v1 加密；新增 `decrypt_password` 工具；迁移脚本（编译期 `sqlx::migrate!` 自动跑）。
- **新 migration**：`003_instance_meta.sql`、`004_credential_reencrypt.sql`（后者含 Rust 处理逻辑，不只是 SQL）。
- **schema 影响**：新表 `instance_meta(install_uuid, created_at, trial_started_at, trial_expires_at)`；`database_connections.password_encrypted` 字段语义升级（值格式变化，列定义不变）。

### 7.2 dbmaster-tech-site（Go）
- **signLicense**：canonical 改 v2 line-based（加 `product:server`、`v:2`、字段名对齐 `instance_id`）。
- **env var**：`DBMASTER_LICENSE_PRIVATE_KEY` → `DBMASTER_SERVER_LICENSE_PRIVATE_KEY`（语义更清晰，配合 D1=B）。
- **新表/列**：`activations` 加 `reminder_30_sent`、`reminder_7_sent` 列；cron goroutine 跑续费扫描。
- **SMTP**：新增 `net/smtp` 邮件发送 + env 配置组（`DBMASTER_SMTP_*`）。
- **D6 加固**：`handleDeactivate` 加每邮箱年度换绑计数；支付验证闸门（先做 admin token + 手工审，中期升级）。
- **API 文档**：把 `/api/activate`、`/api/deactivate`、`/api/renewal/check` 的请求/响应规范落到 `dbmaster-tech-site/docs/`（**契约显式化，定律 2**）。

### 7.3 dbmaster-flutter（Dart 桌面）
- **本 ADR 不改桌面代码**（D3=C 的前提）。
- 桌面继续用 v1（`LicenseVerifier`、`license_signer.dart`）走退役过渡，按 `license-signing-guide.md` 处理存量订单。
- 若 §11 用户选 D3=A 或 B（强制统一格式），则需更新桌面 verifier + 重签存量——本 ADR 默认不推荐。

---

## 8. 售卖就绪清单（DoD — Definition of Done for charging ¥399）

按优先级排序，**任一未完成则不可正式售卖**：

### P0（安全 / 数据完整性 — 定律 5 一票否决）
- [ ] **C-1**. `create_connection` 改 AES-256-GCM v1；`enc:` 遗留迁移完成（D8）。
- [ ] **C-2**. `DBMASTER_CREDENTIAL_KEY` env var 在生产部署文档中强制（fail-fast 拒启）。
- [ ] **C-3**. Server 独立 Ed25519 keypair 生成 + 私钥离线备份 + env var 加载（D1=B）。
- [ ] **C-4**. 私钥不出签发侧审计：grep 全代码库 + 日志路径，确认无私钥/明文密码/token/PII 落盘或入日志。

### P1（license 链路闭环）
- [ ] **C-5**. Server v2 license 格式定义落地（D3=C），Rust `verify_license` 重写 + 单测覆盖（normal / 篡改 / 过期 / fingerprint 不符 / v1 拒绝）。
- [ ] **C-6**. `instance_meta.install_uuid` 生成与持久化；Server 启动读、验签、比 fingerprint、比 expires_at、设 entitlement_state（D4=A）。
- [ ] **C-7**. 14 天试用状态机 + gate（D5=A）；过期后付费功能关闭、UI 引导激活。
- [ ] **C-8**. `/api/activate`、`/api/deactivate`、`/api/license/{id}` 端到端跑通（手工 curl + 真实 Server 接收 license 验证）。
- [ ] **C-9**. D6.1 支付验证闸门（首发版：admin 手工核验流程文档化 + 自动化代码位就位）。
- [ ] **C-10**. D6.2 换绑频次限制 + 审计日志。

### P2（运营 / 体验）
- [ ] **C-11**. tech-site 续费邮件 cron + `reminder_30/7_sent` 列（D7=C）。
- [ ] **C-12**. Server UI 到期横幅（剩 30/7 天）。
- [ ] **C-13**. tech-site API 契约文档（请求/响应/错误码）落到 `dbmaster-tech-site/docs/api.md`（定律 2）。
- [ ] **C-14**.license 系统端到端验证脚本（QA 用例：激活 → 试用 → 过期 → 换绑 → 续费邮件）。

### P3（可延后到首个付费客户后）
- [ ] C-15. PayPal IPN / 支付宝回调的自动支付验证（替代 admin 手工）。
- [ ] C-16.license key rotation 流程演练（生成新 keypair → 客户端如何过渡）。
- [ ] C-17. 多产品支持（keyId 字段、按 product 路由 verifier）。

---

## 9. 验证计划（落地后）

按全局 verify.md 分级（本 ADR 属"跨组件/核心链路"→ 全 5 层）：

1. **静态**：`cargo clippy --workspace -- -D warnings`；`go vet ./...`；新增模块单测覆盖 ≥80%。
2. **模块单测**：
   - Rust：`verify_license` v2（normal / 篡改 / 过期 / fingerprint 不符 / 错版本 / 错 product）。
   - Rust：`encrypt_v1` / `decrypt_v1` 往返 + 错 key 失败 + 错格式失败。
   - Rust：trial 状态机（首启 / 已激活 / 过期 / 删行重置）。
   - Go：signLicense v2 canonical 字节稳定（与 Rust verifier 互验）。
3. **全量回归**：`cargo test --workspace`；tech-site `go test ./...`。
4. **行为验证**：
   - 手工：`./dbmaster-server`（无 license）→ 14 天 trial 启动 → 重启仍 trial → 调快时钟过 trial → gates 关闭 → admin token 调 `/api/activate` 拿 license → 粘贴 → 重启 → license 验签通过 → 调快时钟到到期前 30 天 → UI 横幅 → tech-site cron 邮件发出。
   - 手工：`create_connection` 存一条 → grep DB 文件确认无明文密码（只看到 `v1:...`）→ 重启 Server → 连接仍可用（解密路径通）。
5. **差异自审**：`git diff` 逐行，确认每处变更对应本 ADR 某条决策。

---

## 10. 后续 ADR（本 ADR 不解决、但已识别）

- **ADR-0002（候选）**：多产品 license（keyId 字段、按 product 路由 verifier）— 当第二款付费产品出现时立项。
- **ADR-0003（候选）**：license key 轮换流程 — 当首次需要轮换时立项（本 ADR 给出 env var 加载机制，轮换流程延后）。
- **ADR-0004（候选）**：自动支付验证（PayPal IPN / 支付宝回调）— 首个付费客户后由 sales + architect 共同立项。

---

## 11. 开放问题 — 需用户拍板（🔴 不可逆）

> 每条给出 architect 推荐 + 一句话理由。用户拍板后本 ADR Status → Accepted。

### Q1. Server 是否独立 Ed25519 keypair（D1）？
- **推荐 B（独立 keypair）**。
- **理由**：付费主收入产品不应继承免费产品线的密钥暴露面，爆炸半径隔离成本低。
- **若用户选 A（复用）的额外后果**：tech-site 私钥泄露 = 桌面 + Server 全部可伪造；桌面退役后该密钥仍需无限期保管。

### Q2. Server license 走 v2 全新格式还是改用桌面 v1 格式（D3）？
- **推荐 C（v2 与桌面解耦）**。
- **理由**：桌面代码零改动；Server 可加领域字段（product/instance_id）；符合定律 3（组件独立交付）。
- **若用户选 A/B（统一格式）的额外后果**：需改桌面 Dart verifier + 重签存量桌面 license（虽然零客户，但桌面已发布包内置 verifier 仍会运行）。

### Q3. Server 实例指纹定义（D4）？
- **推荐 A（install_uuid）**。
- **理由**：诚实用户模式接受重置；自托管者期望"license 跟着数据走"配合自助换绑即可。
- **若用户选 B（宿主派生）的额外后果**：Docker 部署需额外配置 hostname/MAC；合法迁移会破坏 license，UX 差。

### Q4. 凭据主密钥 fail-fast 还是零配置（D8.1）？
- **推荐 A（env var + 生产 fail-fast）**。
- **理由**：符合全局"密钥通过环境变量注入"；fail-fast 比"自动生成后忘备份"更安全。
- **若用户选 B（自动生成）的额外后果**：首次部署丝滑，但迁移时易因忘备份 credential.key 导致历史连接密码全部失解。

### Q5.（可选）激活首发版本走"admin 手工核支付截图"还是先做 PayPal IPN？
- **推荐前者（手工）**。
- **理由**：零客户阶段人工成本可接受；自动支付验证可延后到首个付费客户后（C-15）。
- **若用户选后者的额外后果**：发售时间延后 2–4 周（IPN 对接 + 测试）。

---

## 12. 附录：被淘汰的选项（备查）

- **D1-C 多 keypair + keyId**：过度设计，零客户不需要。
- **D2-B Server 自签**：违反依赖单向（定律 3）。
- **D2-C 独立签发微服务**：违反个人维护成本第一（定律 1）。
- **D5-B license 字段 trial**：违反离线优先。
- **D6-B 无状态重签**：无审计、无防滥用。
- **D6-C 外部 entitlement**：与现有支付通道冲突，新依赖。
- **D8.1-C KMS**：自托管单人产品过度设计。

---

**本 ADR 是设计文档，不修改任何代码。** 实现由后续 senior-backend-engineer / senior-desktop-engineer（按 §7 影响域）在用户拍板 §11 后接手。
