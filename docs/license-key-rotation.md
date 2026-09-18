# License Key Rotation Playbook（Ed25519 Server License）

> 操作对象：签发方（issuer / 签发方内部）。本文档**勿提交私钥**。
>
> 对应任务：#12（替换 DEV/TEST 公钥为生产信任根）。架构依据：ADR-0001 §4.1 D1=B。

## 0. 安全铁律（不可逾越）

- **私钥（seed）是命门**：离线备份、永不外泄、永不进 git / 日志 / 客户端 / 测试 / golden JSON。
- 生产公钥编译进二进制（`crates/license/src/lib.rs::SERVER_PUBLIC_KEY_HEX`）；生产私钥以 env var 注入 tech-site 签发端，**不落盘、不进仓**。
- 我（AI 助手）/ 任何非签发方**绝不生成或接触生产私钥**。私钥只在签发方的离线/安全环境生成。
- 换 keypair = 所有**已签发的旧 license 失效**（签名方变了）。当前无真实付费用户时是最佳轮换时机。

## 1. 生成生产密钥对（离线环境，只做一次）

在**离线/气隙**机器上运行（推荐 Go——与 tech-site 生产签名器用同一原语 `ed25519.NewKeyFromSeed`，保证跨语言逐字节对齐）：

```bash
mkdir ~/dbmaster-keygen && cd ~/dbmaster-keygen
go mod init keygen
# 粘贴 keygen.go（见下）
go run .
```

`keygen.go`：
```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	seed := make([]byte, ed25519.SeedSize) // 32 字节
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	priv := ed25519.NewKeyFromSeed(seed) // 与 tech-site activate.go 完全一致
	pub := priv.Public().(ed25519.PublicKey)

	fmt.Println("===== PRIVATE KEY (seed) — 仅离线保管，永不提交/粘贴/分享 =====")
	fmt.Println(hex.EncodeToString(seed))
	fmt.Println()
	fmt.Println("===== PUBLIC KEY — 可公开，交给代码替换 =====")
	fmt.Println(hex.EncodeToString(pub))
}
```

备选（Python，等价 `ed25519.NewKeyFromSeed`）：
```bash
pip install cryptography
python -c "import os; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from cryptography.hazmat.primitives import serialization; s=os.urandom(32); k=Ed25519PrivateKey.from_private_bytes(s); print('SEED:',s.hex()); print('PUB :',k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex())"
```

## 2. 保管私钥

- **离线备份** seed（加密 U 盘 / 密码管理器 / 纸质，多处冗余）。丢失 = 无法续签/重签 license。
- **注入 tech-site 部署**：在 dbmaster.tech 运行环境设
  `DBMASTER_SERVER_LICENSE_PRIVATE_KEY=<seed-hex>`（64 位 hex，不是文件路径）。
  tech-site `loadSigner()`（`activate.go`）在启动时读取；未设则激活 API 返回 503。
- **永不**把 seed 贴进聊天 / issue / 日志 / 任何仓库。

## 3. 自检（确认 seed↔pubkey 配对正确）

Ed25519 派生是确定性的——用 seed 再派生一次 pubkey，结果应**完全一致**：
```go
// verify.go: go run verify.go <seed-hex>
priv := ed25519.NewKeyFromSeed(seedBytes)
fmt.Println(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
```
两次一致 = 配对正确。tech-site 用同 seed 注入就能签出 server 能验证的 license。

## 4. 替换公钥常量（代码侧）

把第 1 步产出的 **PUBLIC KEY** 替换进 `crates/license/src/lib.rs`：
```rust
pub const SERVER_PUBLIC_KEY_HEX: &str = "<PUBLIC KEY hex>";
```
然后跑测试（已解耦，换常量零破坏）：
```bash
cargo test -p dbmaster-license        # 单元 + golden（用 dev key，不碰生产常量）
cargo test --test license_api_test    # 集成（debug build 经 override 用 dev key）
cargo test --workspace                # 全量回归
```

两条守卫测试会校验：
- `server_public_key_const_is_valid_ed25519_key`——常量是合法 32 字节 Ed25519 公钥（防手滑写坏）。
- `server_public_key_const_is_not_the_dev_key`——常量**不是** DEV 种子派生的公钥（回退即 build 红）。

## 5. 测试如何与生产常量解耦（#12 的核心架构改动）

旧设计里所有 verify 测试用 DEV seed 签名 + 用 `SERVER_PUBLIC_KEY_HEX` 验证（仅因 seed→pubkey 一致才过），导致换常量 = 全测崩 = 唯一修法是把生产私钥塞进 git（泄露）。#12 改为：

- **单元测试**（`lib.rs` / `entitlement.rs`）调 `verify_license_with_pk(parsed, &dev_verifying_key())`——显式传 dev 公钥，与生产常量无关。
- **集成测试**（`tests/license_api_test.rs`）必须走真 handler（用生产常量），故在 debug build 经 `DBMASTER_LICENSE_VERIFY_PUBKEY_OVERRIDE_HEX` env 把验证密钥重定向到 dev 公钥。
- **release 构建** `cfg(debug_assertions)` 关闭 → override 代码编译期剔除 → 发布二进制只信任编译期常量，**零运行时攻击面**（operator/attacker 无法在发布构建重定向验证）。
- `tests/golden_license.json` 的 `dev_only: true` 守卫拒绝加载生产 key 进 golden。

## 6. 作废旧 license

换 keypair 后，旧签名方签发的 license 全部失效（server 验签失败 → Gated）。处理：
- 无在用付费 license：无需动作（当前状态）。
- 有在用付费 license：用新私钥重签发给受影响客户（tech-site 重新走激活流程即可，因为 tech-site 已注入新 seed）。

## 7. 应急：私钥泄露

立即轮换：重跑第 1 步生成新 keypair → 替换公钥常量 + 重部署 tech-site（新 seed）→ 重签所有在用 license。泄露的旧 keypair 签发的 license 全部作废。

## 参考

- ADR-0001（Server License Activation）§4.1 D1=B、§4.3、C-3、C-8。
- 跨语言契约（Go sign ↔ Rust verify）：`crates/license/tests/golden_license.json`（与 `dbmaster-tech-site/testdata/golden_license.json` 镜像，同改）。
- tech-site 签发端：`dbmaster-tech-site/activate.go` `loadSigner` / `signLicense`。
