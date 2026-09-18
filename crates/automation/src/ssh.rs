//! 网关 server 侧 SSH 隧道（SSH 隧道 + TLS 透传批次，2026-08-29）。
//!
//! 设计取舍：
//! - **进程级单例**：`LazyLock<DashMap<key, TunnelEntry>>` 复用隧道。key =
//!   sha256(规范化 ssh 配置 + 秘密 + 目标 host:port)——凭据轮换 / 目标库
//!   变更会派生新 key（旧隧道条目留给惰性淘汰），同一逻辑连接重复 resolve
//!   零成本命中。
//! - **本地转发**：每隧道一条 `127.0.0.1:0` TcpListener；accept 循环对每个
//!   入连接开一个 `direct-tcpip` channel，双向 pump。resolve 返回监听地址，
//!   调用方（`load_connection` 收口）把行 host/port 改写为它——TLS over
//!   tunnel 天然成立（TLS 端到端到目标库）。
//! - **懒重连**：缓存命中先做一次 500ms TCP 探活（accept 循环死掉即重建，
//!   SSH 会话断开 → channel open 失败 → 循环退出）。SSH 会话靠 russh
//!   `keepalive_interval` 心跳保活。
//! - **host key 校验**：TOFU 变体——接受任意 host key，但把指纹打进日志
//!   （SHA-256 of wire-format public key）。网关场景 server 无法交互确认
//!   指纹，严格 pinning 留待后续按行持久化首见指纹后再做。
//! - **纪律**：秘密（password/privateKey/passphrase）只进内存；日志与错误
//!   消息只携带指纹与「认证失败」级别的归一文案，绝不回传秘密本体。

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// ── wire / 存储形态 ──

/// 网关 wire 的 ssh 配置块（`POST /api/gw/connections` / `/test` 的
/// `ssh` 字段）。字段存在即启用隧道；authMode=password 带 password，
/// privateKey 带 privateKey + 可选 passphrase。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshWire {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: i64,
    pub username: String,
    /// "password" | "privateKey"。
    pub auth_mode: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
}

fn default_ssh_port() -> i64 {
    22
}

impl SshWire {
    /// 校验 + 投影到运行时参数（错误消息不含秘密）。
    pub fn validate(&self) -> Result<SshTunnelParams, String> {
        let auth_mode = match self.auth_mode.as_str() {
            "password" => "password",
            "privateKey" => "privateKey",
            other => return Err(format!("unsupported ssh authMode: {other}")),
        };
        if self.host.trim().is_empty() || self.username.trim().is_empty() {
            return Err("ssh host and username are required".to_string());
        }
        if auth_mode == "password" && self.password.as_deref().unwrap_or("").is_empty() {
            return Err("ssh authMode=password requires a password".to_string());
        }
        if auth_mode == "privateKey" && self.private_key.as_deref().unwrap_or("").is_empty() {
            return Err("ssh authMode=privateKey requires a private key".to_string());
        }
        Ok(SshTunnelParams {
            config: SshConfig {
                host: self.host.trim().to_string(),
                port: if self.port > 0 { self.port } else { 22 },
                username: self.username.trim().to_string(),
                auth_mode: auth_mode.to_string(),
            },
            secrets: SshSecrets {
                password: self.password.clone().unwrap_or_default(),
                private_key: self.private_key.clone().unwrap_or_default(),
                passphrase: self.passphrase.clone().unwrap_or_default(),
            },
        })
    }
}

/// 隧道非秘密配置（落 extra JSON：sshHost/sshPort/sshUsername/sshAuthMode）。
#[derive(Debug, Clone, PartialEq)]
pub struct SshConfig {
    pub host: String,
    pub port: i64,
    pub username: String,
    /// "password" | "privateKey"。
    pub auth_mode: String,
}

/// 隧道秘密（encrypt_v1 整体加密后落 `ssh_secret_encrypted` 列；解密只在
/// `load_connection` 层，明文只进内存传递）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshSecrets {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub passphrase: String,
}

impl SshSecrets {
    /// 全空（编辑删掉隧道的形态）。
    pub fn is_empty(&self) -> bool {
        self.password.is_empty() && self.private_key.is_empty() && self.passphrase.is_empty()
    }
}

/// 运行时隧道参数 = 非秘密配置 + 秘密（草稿测试路径内存直传）。
#[derive(Debug, Clone)]
pub struct SshTunnelParams {
    pub config: SshConfig,
    pub secrets: SshSecrets,
}

/// extra JSON → 非秘密 ssh 配置（四键齐全才认；缺任一视为未启用——
/// 与注册侧写入路径对称）。
pub(crate) fn config_from_extra(extra: Option<&str>) -> Option<SshConfig> {
    let raw = extra?;
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(raw)
    else {
        return None;
    };
    Some(SshConfig {
        host: map.get("sshHost")?.as_str()?.trim().to_string(),
        port: map.get("sshPort").and_then(serde_json::Value::as_i64).unwrap_or(22),
        username: map.get("sshUsername")?.as_str()?.trim().to_string(),
        auth_mode: map.get("sshAuthMode")?.as_str()?.to_string(),
    })
    .filter(|c| !c.host.is_empty() && !c.username.is_empty())
}

/// 非秘密配置 → extra JSON 键（注册侧合并进 extra map 再 sanitize）。
pub fn extra_keys(config: &SshConfig) -> [(&'static str, serde_json::Value); 4] {
    [
        ("sshHost", serde_json::Value::String(config.host.clone())),
        ("sshPort", serde_json::json!(config.port)),
        ("sshUsername", serde_json::Value::String(config.username.clone())),
        ("sshAuthMode", serde_json::Value::String(config.auth_mode.clone())),
    ]
}

// ── 隧道管理器 ──

struct TunnelEntry {
    /// 本地转发监听地址（resolve 返回值）。
    local_port: u16,
}

/// 进程级隧道表（LazyLock 单例；见模块文档）。
static TUNNELS: LazyLock<DashMap<String, TunnelEntry>> = LazyLock::new(DashMap::new);

/// 缓存命中的探活超时——accept 循环死掉时端口不再可连，触发懒重建。
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// 解析（或复用）一条到 `target_host:target_port` 的隧道。
///
/// 返回 `(host, port)`——恒为 `("127.0.0.1", local_port)`；调用方把连接行
/// 的 host/port 改写为它并在 extra 注入 `tunneled:true`。失败错误消息已
/// 归一（不含秘密 / 目标细节按需由调用方再归一）。
pub async fn resolve(
    target_host: &str,
    target_port: i64,
    config: &SshConfig,
    secrets: &SshSecrets,
) -> anyhow::Result<(String, u16)> {
    let key = tunnel_key(target_host, target_port, config, secrets);
    // 命中 + 探活 → 直接复用。
    if let Some(entry) = TUNNELS.get(&key) {
        if probe(entry.local_port).await {
            return Ok(("127.0.0.1".to_string(), entry.local_port));
        }
    }
    // 未命中 / 已死：重建（先移除旧条目防并发双建堆叠——窗口极小，重建
    // 幂等，双建仅浪费一个本地端口）。
    TUNNELS.remove(&key);
    let local_port = spawn_tunnel(target_host, target_port, config, secrets).await?;
    TUNNELS.insert(key, TunnelEntry { local_port });
    Ok(("127.0.0.1".to_string(), local_port))
}

/// 规范化 key：sha256(ssh 非秘密配置 | 秘密 | 目标 host:port)。秘密参与
/// 哈希但不落日志（key 本身即哈希摘要）。
fn tunnel_key(target_host: &str, target_port: i64, config: &SshConfig, secrets: &SshSecrets) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        config.host, config.port, config.username, config.auth_mode,
        secrets.password, secrets.private_key, secrets.passphrase,
        target_host, target_port,
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// 本地端口探活（同步 TCP 连一次即断）。
async fn probe(port: u16) -> bool {
    tokio::time::timeout(
        PROBE_TIMEOUT,
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// TOFU host key handler：接受任意 host key，打指纹日志（见模块文档取舍）。
struct TofuHandler;

impl russh::client::Handler for TofuHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        use russh::keys::PublicKeyBase64;
        let fingerprint = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                let digest = Sha256::digest(key.public_key_bytes().as_slice());
                base64_std(&digest)
            }
            russh::keys::PublicKeyOrCertificate::Certificate(_) => "certificate".to_string(),
        };
        // TOFU：接受并留痕（指纹非秘密；host/user 是连接定位信息）。
        tracing::info!(fingerprint = %fingerprint, "ssh tunnel: accepting server host key (TOFU)");
        Ok(true)
    }
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 建立 SSH 会话并起本地转发监听。返回本地端口。
async fn spawn_tunnel(
    target_host: &str,
    target_port: i64,
    config: &SshConfig,
    secrets: &SshSecrets,
) -> anyhow::Result<u16> {
    let ssh_config = Arc::new(russh::client::Config {
        // 会话保活心跳：3 次无回复判死（连接由 keepalive_max 缺省处理）。
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    });
    let mut session = russh::client::connect(
        ssh_config,
        (config.host.as_str(), config.port as u16),
        TofuHandler,
    )
    .await
    .map_err(|e| anyhow::anyhow!("ssh tunnel connect failed: {}", redact_ssh(&e.to_string())))?;

    // 认证（错误归一：只报认证失败，不带服务器细节里的敏感回显）。
    let auth_ok = match config.auth_mode.as_str() {
        "password" => {
            session
                .authenticate_password(&config.username, &secrets.password)
                .await
                .map_err(|e| anyhow::anyhow!("ssh tunnel auth error: {}", redact_ssh(&e.to_string())))?
                .success()
        }
        "privateKey" => {
            let key = russh::keys::decode_secret_key(&secrets.private_key, secrets_passphrase(secrets))
                .map_err(|_| anyhow::anyhow!("ssh tunnel private key decode failed"))?;
            let hash = session.best_supported_rsa_hash().await.ok().flatten().flatten();
            session
                .authenticate_publickey(&config.username, russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(|e| anyhow::anyhow!("ssh tunnel auth error: {}", redact_ssh(&e.to_string())))?
                .success()
        }
        other => anyhow::bail!("unsupported ssh authMode: {other}"),
    };
    if !auth_ok {
        anyhow::bail!("ssh tunnel authentication failed");
    }

    // 目标可达性验证 + 监听。
    let probe_channel = session
        .channel_open_direct_tcpip(target_host, target_port as u32, "127.0.0.1", 0)
        .await
        .map_err(|_| anyhow::anyhow!("ssh tunnel target unreachable"))?;
    drop(probe_channel);

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let local_port = listener.local_addr()?.port();
    // Handle 非 Clone（内含独占 Reply 接收端）→ Mutex 串行化 channel open
    //（仅控制面，pump 在锁外全双工，无吞吐影响）。
    let session = Arc::new(Mutex::new(session));
    let pump_target = target_host.to_string();
    let pump_port = target_port as u32;
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { break };
            let session = session.clone();
            let target = pump_target.clone();
            tokio::spawn(async move {
                let channel = {
                    let s = session.lock().await;
                    s.channel_open_direct_tcpip(target, pump_port, "127.0.0.1", 0).await
                };
                match channel {
                    Ok(channel) => {
                        // 双向 pump：ChannelStream 全双工，copy_bidirectional
                        // 收发一体；任一方向 EOF/出错即结束（channel drop 关闭）。
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
                    }
                    Err(_) => {
                        // 目标不可达：单连接失败，不影响 accept 循环。
                        let _ = socket.shutdown().await;
                    }
                }
            });
        }
        // accept 循环退出（监听被系统回收等）→ 主动断 SSH 会话，探活将失败
        // 触发懒重建。
        let s = session.lock().await;
        let _ = s
            .disconnect(russh::Disconnect::ByApplication, "", "dbmaster")
            .await;
    });
    Ok(local_port)
}

/// 秘密 passphrase（空串 → None：russh 把空串当密码试解密，会误伤无口令
/// 的明文私钥）。
fn secrets_passphrase(secrets: &SshSecrets) -> Option<&str> {
    if secrets.passphrase.is_empty() { None } else { Some(secrets.passphrase.as_str()) }
}

/// SSH 错误消息脱敏：只保留错误类别首段，剥可能携带的服务器回显细节。
fn redact_ssh(msg: &str) -> String {
    msg.lines().next().unwrap_or("ssh error").chars().take(120).collect()
}

/// 收口：解析行的隧道并改写 host/port + 注入 `tunneled` 标记。
/// sqlite 无 host（file_path 即凭据）——调用方保证不进此函数。
pub(crate) async fn apply_tunnel(
    row_host: &str,
    row_port: i64,
    extra: Option<&str>,
    config: &SshConfig,
    secrets: &SshSecrets,
) -> anyhow::Result<(String, i64, Option<String>)> {
    let (host, port) = resolve(row_host, row_port, config, secrets).await?;
    let extra = crate::net_flags::inject_flag(extra, "tunneled", true);
    Ok((host, port as i64, extra))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SshConfig {
        SshConfig {
            host: "jump.example.com".into(),
            port: 22,
            username: "deploy".into(),
            auth_mode: "password".into(),
        }
    }

    #[test]
    fn tunnel_key_is_stable_and_secret_sensitive() {
        let secrets = SshSecrets { password: "pw".into(), ..Default::default() };
        let a = tunnel_key("db.local", 3306, &config(), &secrets);
        let b = tunnel_key("db.local", 3306, &config(), &secrets);
        assert_eq!(a, b);
        // 目标 / 秘密 / 配置任一变化 → 新 key。
        assert_ne!(a, tunnel_key("db2.local", 3306, &config(), &secrets));
        assert_ne!(a, tunnel_key("db.local", 3307, &config(), &secrets));
        assert_ne!(
            a,
            tunnel_key("db.local", 3306, &config(), &SshSecrets { password: "pw2".into(), ..Default::default() })
        );
        assert_ne!(a, tunnel_key("db.local", 3306, &SshConfig { port: 2222, ..config() }, &secrets));
    }

    #[test]
    fn config_extra_roundtrip() {
        let c = config();
        let keys = extra_keys(&c);
        let mut map = serde_json::Map::new();
        for (k, v) in keys {
            map.insert(k.to_string(), v);
        }
        let json = serde_json::Value::Object(map).to_string();
        assert_eq!(config_from_extra(Some(&json)), Some(c));
        // 缺键 / 空 host / 非 JSON → None。
        assert_eq!(config_from_extra(Some(r#"{"sshHost":"h"}"#)), None);
        assert_eq!(config_from_extra(Some(r#"{"sshHost":"","sshPort":22,"sshUsername":"u","sshAuthMode":"password"}"#)), None);
        assert_eq!(config_from_extra(None), None);
        assert_eq!(config_from_extra(Some("bad")), None);
    }

    #[test]
    fn ssh_wire_validation() {
        let wire = |auth_mode: &str, password: Option<&str>, key: Option<&str>| SshWire {
            host: "h".into(),
            port: 0,
            username: "u".into(),
            auth_mode: auth_mode.into(),
            password: password.map(str::to_string),
            private_key: key.map(str::to_string),
            passphrase: None,
        };
        // port 缺省/非法回落 22。
        assert_eq!(wire("password", Some("pw"), None).validate().unwrap().config.port, 22);
        assert_eq!(
            wire("privateKey", None, Some("KEY")).validate().unwrap().config.auth_mode,
            "privateKey"
        );
        assert!(wire("bad", None, None).validate().is_err());
        assert!(wire("password", None, None).validate().is_err());
        assert!(wire("privateKey", None, None).validate().is_err());
    }

    #[test]
    fn secrets_json_camel_case_roundtrip() {
        let s = SshSecrets {
            password: "p".into(),
            private_key: "k".into(),
            passphrase: String::new(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"password":"p","privateKey":"k"}"#);
        let back: SshSecrets = serde_json::from_str(&json).unwrap();
        assert_eq!(back.private_key, "k");
        assert!(back.passphrase.is_empty());
        assert!(!s.is_empty());
        assert!(SshSecrets::default().is_empty());
    }

    /// 真实 SSH 隧道集成测试（本机无 SSH 服务时跳过——阶段二人工对真库
    /// 验证，见任务手册）。
    #[tokio::test]
    #[ignore = "requires a reachable SSH server; run manually with env-tweaked config"]
    async fn resolve_builds_tunnel() {
        use crate::net_flags::tunneled;
        let extra = apply_tunnel("db.local", 3306, Some(r#"{"useTls":true}"#), &config(), &SshSecrets {
            password: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(extra.0, "127.0.0.1");
        assert!(extra.1 > 0);
        assert!(tunneled(extra.2.as_deref()));
    }
}
