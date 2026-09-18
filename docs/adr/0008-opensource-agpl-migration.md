# ADR-0008: server 仓库全面开源迁移（AGPL-3.0-only）

- **Status**: Accepted（2026-09-18 用户拍板）
- **Deciders**: 用户
- **Related**: ADR-0001（license 体系与官方签发）、ADR-0003（embedded——免费本地形态）、桌面客户端仓库（[github.com/hobbs136/dbmaster](https://github.com/hobbs136/dbmaster)）、tech-site（闭源，付费服务承载）

## 1. 背景

dbmaster-server 原为 GitHub 私有仓库，采用双许可结构：`core` crate（认证 / 用户 / 工作空间 / 存储等基础设施）为 Apache-2.0；`automation` 及其余业务 crates（data_sync / drift / health_check / gateway / license / mcp）为 BSL 1.1（每版发布 4 年后自动转宽松许可）。商业化路径建立在 BSL 的商用限制条款上：源码公开可查，但商用需购买许可（¥399/年/实例）。

该结构存在两个问题：其一，BSL 属 source-available 而非 OSI 认证的开源许可证，社区传播、贡献与集成意愿受限；其二，产品的门控逻辑位于可自行编译的客户端进程内，自编译即可移除，许可条款的实际约束力弱于预期。用户决策：**全面开源，防止闭源转卖**。

## 2. 方案与取舍

**决策：两仓库（dbmaster-server 与桌面客户端 dbmaster）统一迁移为 AGPL-3.0-only**（SPDX：`AGPL-3.0-only`；仓库根放置官方许可证全文，Cargo.toml 包元数据统一标注）。

防闭源转卖的法理链条：AGPL 是主流许可证中 copyleft 最强的一档——修改版无论是二进制分发还是仅经网络对外提供服务，都必须以同一协议向接收者提供完整对应源码。闭源改装后售卖即构成版权侵权，无需依赖合同条款或技术门控。

| 备选 | 否决理由 |
|---|---|
| 维持 BSL 1.1 | source-available 非正统开源，社区接受度低；且自编译即可删除门控代码，使 BSL 的实际约束力弱于预期 |
| Apache-2.0 | 宽松许可，无 copyleft，无法防闭源转卖 |

**商业模式迁移**：收费点从许可证条款迁移到官方服务——代码开源免费；**官方 license 激活签发（实例指纹绑定）、更新与支持由 dbmaster.tech 提供**（¥399/年/实例订阅）。自编译者可用全部功能，但拿不到官方签发。生产签名私钥与测试种子已解耦（迁移时核实）；签发流程属内部文档，不入库。tech-site（购买站：支付与签发编排）保持闭源，是付费服务的承载点。

## 3. 影响面

- **许可证元数据**：server 工作区 9 个包（根二进制 + 8 个 crates）`license` 字段统一为 `AGPL-3.0-only`，仓库根替换为官方许可证全文，启动 banner 与 `--version` 版权行同步；桌面客户端仓库（github.com/hobbs136/dbmaster）许可证元数据同步迁移。
- **测试凭据 env 化**：测试与脚本不再携带任何真实部署地址或凭据，全部改为 `*_E2E_*` 环境变量门控（未设置时打印 SKIP 并通过，离线恒绿），并新增仓库根 `.env.example` 作为完整变量清单。
- **内部文档出库**：含内网拓扑与部署细节的内部文档移出仓库，内网 IP 完成清洗。
- **tech-site 保持闭源**：购买站的支付与签发编排不随本决策开源。
- **git 历史处理**：历史处理方案由维护者另行决定。

## 4. 验收标准

- **泄露清扫门**：对入库文本执行敏感串扫描——内网测试库地址、测试口令字面量、现行双许可声明残留——零命中；本 ADR §1/§2 中"曾用许可"的历史叙述除外。
- **验证阶梯全绿**：`cargo clippy` → `cargo test -p <crate>` → 全 workspace `cargo test`；env 门控 e2e 在变量未设置时 SKIP 通过。
