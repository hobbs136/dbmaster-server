# ADR-0007: 周报 AI 分析走客户端侧（server 零 AI 外呼面）

- **Status**: Accepted（2026-08-27 用户「开始M3」授权按推荐口径先行；实现随 #29 reports 管道 M3）
- **Deciders**: 用户（授权推荐口径）+ 工程
- **Context**: `#29` reports 管道 M1+M2 已交付（慢查询捕获 + 周报 writer + 报告中心）；
  brainstorm 遗留开放问题 2 明言「周报是否引入 AI 摘要需先过 ADR」，且需回答与
  `aiAgent` Pro 功能门控的关系。现状锚点：**server 是自托管自动化引擎，没有任何
  AI 集成**（无外呼、无密钥管理）；桌面客户端有成熟 AI 面板（多 provider、用户
  自配 key、skill 体系、`AppProvider.sendAiAnalysis` 等四个送 AI 入口先例）。
- **Related**: ADR-0003（embedded——本地形态）、tech-site Pro 功能面（`aiAgent`）

## 1. 决策

**周报的 AI 摘要/建议在客户端侧完成**：报告中心详情加「AI 分析」入口，把 typed
周报内容（`SlowQueryWeeklyReport` content v1：窗口/汇总/Top/按天/按连接）序列化
为提示词，经**现有 AI 面板**（用户自配 provider/key）发送。**server 不引入任何
AI 依赖**。

## 2. 备选与取舍

| 方案 | 弃用原因 |
|---|---|
| server 端调 LLM API 生成摘要并写回 content | 新增外呼面：实例级密钥管理（env 配置、泄露面）、按 token 计费归集、慢查数据默认外发第三方的隐私问题；embedded 免费本地形态被打破（无 key 即无功能）；全部为客户端面板已解决问题 |
| 周报 writer 内嵌 AI（生成期摘要） | 同上，且把 AI 可用性耦合进幂等 writer（AI 失败影响报告生成确定性） |

## 3. 与 aiAgent 门控的关系（开放问题 2 的回答）

`aiAgent`（tech-site Pro 功能面）管的是 **server 实例的 MCP agent 能力**；本决策
的 AI 分析用的是**客户端 AI 面板**（桌面端既有能力，用户自己的 key），两者不同
面。因此：周报 AI 分析**不新增任何门控点**，与 M1/M2 一致（Gated 态只拦 server
mutation，报告读面与客户端行为不受影响）。若未来 server 端引入任何 AI 能力，
再按 D1 商业化讨论统一拍板。

## 4. 后果

- 正面：server 保持零 AI 外呼/密钥/计费；embedded 与远程同体验；隐私边界清晰
  （用户主动把周报内容送给自己选的 provider）；实现量小（复用发送骨架）。
- 负面/接受：AI 摘要不持久化（每次分析即时生成，不进 content JSON）——分析是
  交互行为而非报告事实，持久化反而引入版本/模型漂移问题；无 key 用户没有该
  功能（与客户端所有 AI 功能一致的既有语义）。
