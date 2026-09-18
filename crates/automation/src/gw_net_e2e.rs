//! 网络层批次（2026-08-29）— SSH 隧道 + TLS 透传的**真网络**集成验证。
//!
//! 与 hermetic 单测互补，本模块验证「线上真的会发生」的三段链路：
//! 1. **SSH 隧道端到端**：进程内 russh server（password 认证 + direct-tcpip
//!    转发）+ `ssh::resolve` 真隧道 + 真实 Redis（`GW_E2E_REDIS` /
//!    `GW_E2E_REDIS_PASSWORD` env 注入，自备测试库）——SSH 协议、转发泵、
//!    Redis 协议三层全真。
//! 2. **Redis TLS 真握手**：进程内 rustls TLS 桩（RESP `+PONG`），验证
//!    redis 腿 `TcpTls` 分支：`tlsInsecure=true` 握手成功、`false` 证书
//!    校验拒绝（证明校验真实生效）、`tunneled+useTls` 强制 insecure。
//! 3. **TDengine https 真握手**：进程内 TLS HTTP 桩（TD JSON 应答），验证
//!    tdengine 腿 https 分支 + `danger_accept_invalid_certs` 开/关。
//!
//! **跳过纪律**：测试目标不可达（离线 CI / 测试服关机）时打印 SKIP 并
//! 通过——`cargo test` 离线恒绿；目标可达时真跑。Mongo TLS 不在本模块
//! （驱动握手需完整 wire 协议桩，成本不成比例——由单测钉 TlsOptions 注入）。
//!
//! 密钥均为一次性测试 fixture（2026-08-29 生成，2 天有效期，非真实凭据）：
//! ed25519 OpenSSH host key + RSA 自签证书。

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::db_handler::DbConnectionRow;

// ── 一次性测试密钥 fixture（见模块文档）──

/// 进程内 SSH server 的 host key（OpenSSH ed25519，无口令）。
const SSH_HOST_KEY_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAMRgCPmk7qJfSwEDar+r642xaZCqFmXk6v0A+u4xjnEQAAAJi9nQmavZ0J\nmgAAAAtzc2gtZWQyNTUxOQAAACAMRgCPmk7qJfSwEDar+r642xaZCqFmXk6v0A+u4xjnEQ\nAAAEDckERfuCQDmvK6XsiAJMe39PtIZjG4WRTjQCkGCiWlxAxGAI+aTuol9LAQNqv6vrjb\nFpkKoWZeTq/QD67jGOcRAAAAFWRibWFzdGVyLXRlc3QtaG9zdGtleQ==\n-----END OPENSSH PRIVATE KEY-----\n";

/// TLS 桩的自签证书（CN=127.0.0.1，不在任何信任库——正是校验拒绝用例所需）。
const TLS_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDCTCCAfGgAwIBAgIUBhm99xykNkUUsYZ9zceHwYu/y9QwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDgyOTAyNDYwNFoXDTI2MDgz\nMTAyNDYwNFowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAj3ecujFrV+gzEDXC5n+W9+cLibBnLIi4R45OxuW9eHpl\nusVE01RX6u8cSad9QBm3Y0f0qb9vocdVNpOPEhDuMTTACEZDmUQ9Nhvb/X+roIAI\n5m3pp4CdUi04N11fTlMMfdXsB79HyCv3arGG77PNYk9fq6OOc1iYtJcziyOg5rle\n8jNNLRWr7K11bRX4VEbSJXtnzF4lCsT4UHqdMveSk9hni++hM/Gt/R/y/NKJDIUd\nFP31oyYy35WCN6N82LYOzJG6U3qsZoHCxKWq5oSnNsVoJ+Bu+dfn5Ieti/txxcK4\nJCawGqByinYqRPmDjTlcCQInIREdpDP2samM90Sb3wIDAQABo1MwUTAdBgNVHQ4E\nFgQU2wX0t+/fk3TJ/gXJyTHlj1f/xEYwHwYDVR0jBBgwFoAU2wX0t+/fk3TJ/gXJ\nyTHlj1f/xEYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAct/9\nuYoDg69DY5tuO7YhKRE4xnxOLr++aR/ZONuZEZbUCR8KV94jSSNaxqSKw5TeSr6S\nmLsilpZjtU4JMWCqINT495uY7DJvRWDxqeotjMBJRkntEw6Tm67W+C639DVJdW9x\n/S27h5qQufCNPFUrxb0Ff+mxglLoVZZdLkvBKFSFL83ta/74qgX1qUzDi8h1lrlV\nCvBeJAdOk8nZtl4YKrNh1PrghHTfPwqHjV9xuhowfYOsGZApe9xku6xaZZr4nvuc\nWi26ruze114F+i2+TcIYvWauCchFFnHMGxt3Cno5w7W9iyeI167t1iHVSPi889jC\nYwUAakruM0z5Okc1kw==\n-----END CERTIFICATE-----\n";

const TLS_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCPd5y6MWtX6DMQ\nNcLmf5b35wuJsGcsiLhHjk7G5b14emW6xUTTVFfq7xxJp31AGbdjR/Spv2+hx1U2\nk48SEO4xNMAIRkOZRD02G9v9f6uggAjmbemngJ1SLTg3XV9OUwx91ewHv0fIK/dq\nsYbvs81iT1+ro45zWJi0lzOLI6DmuV7yM00tFavsrXVtFfhURtIle2fMXiUKxPhQ\nep0y95KT2GeL76Ez8a39H/L80okMhR0U/fWjJjLflYI3o3zYtg7MkbpTeqxmgcLE\nparmhKc2xWgn4G751+fkh62L+3HFwrgkJrAaoHKKdipE+YONOVwJAichER2kM/ax\nqYz3RJvfAgMBAAECggEAApavasKig7MKXNQDgMIzmKSAFktrCSgsXwonzLnvecGH\nnV+a1s9SSMhos8GEZogwQWfWd8ue+YXNuU7fSX2ptpSTlHKkHJtZGWVWSlQn5hz5\nTCMWkLGm5Qkw1vrl0dV4x7p46EjgxDFa5P9wBloxrgDtonywgM9L7hI+WVfaut79\ndpSb5VMOAHqLqwUUsWuRR3KRwznG1MlrhT77lObJ6EVK1Yv9eiskiE18esMDUQ7V\nFW51VqIPzDusA0wkhblXIU8EgVidc4uTV/dzlAnp4xTMX9McHYouwZyjrTcMU50i\nF2YW7H+FIHIZJBVArIFcoXAg8fNUAwv56tJJiME9bQKBgQDGTdMi0AHmrdOz1G+4\naakvLS/GisBQM7ABwOREniGzb8j2MD2tbjaBJVLnm9iZMAExkqz0bu0sbnkBPgCV\nID8ATS+OJjLGW6UMhns50m5uAbHsXsVFzwMn+4Mrz7C9z9qRSyJl0uvvDB2bYsqE\n/2XAmoDjv/ehA02XFoNh1x4czQKBgQC5NWidHjKMu/jKdU69zjL4zhzSjWEzpjV6\nedRMsxBdjvahx1Q05tQHL3m+JXFsOEZn7xgCX/m3d5zUVKMNazUqt6OXzVl6aXZx\ntudR5+ysYaINWUrNPBX1GmZoATIDmBEh3Iy3snJ0/wA2FUxhpptmAHi8tH9aju8K\ndfoJIKHbWwKBgQCCCo0XujJU9M7skbYFx/xzfH1lBJ5iudKFA9ptiQluozK1ByOb\nNLg3bqN0UMX0hv9xY89Zp9iOl49wmhlFsdS+vN8fp7sKSxTsJtBuNanHKANmjyts\nwPk/4fa95z/u6XxaZVwUTAH+TAKqYFmQZ+9xI6C8OaoJA6KBHvlfUvNjTQKBgGXx\nYODCo15VhM6jnTDaU7IheTnnue38+YitkE6bbVGiBFzt44qu11wRJLil0XWY0CAb\nOaLtAv2aaAdzgsA7F2uo4vIGhM7dR+W1oEO0HdCQeOtSD9tBzHA6FM4Agm/5/swd\nopLmNRvy1EHwnTdOxlBxyANOcp7899RRNcxaWtzrAoGAOVVeYRDDorsOh/e8QoRC\njVF+9Z/kZzkwIzhjnxwiZjJE377dwtye9GB5kcoBNiyeOd4d4RdZRKanV9XeDdwt\nXveBo4ARH3jPmFF73TTb+T8WX8BXPNsb73AygrSyXe/awxdvbD3GTbRNfeVHtA+H\nmgYHnwlIqqFRT4Li9vXqAZQ=\n-----END PRIVATE KEY-----\n";

/// 测试 SSH 账号（进程内 server 只认这一组）。
const SSH_USER: &str = "deploy";
const SSH_PASSWORD: &str = "tunnel-test-pw";

// ── 进程内 SSH server（russh server 侧最小 direct-tcpip 转发器）──

struct SshStubServer;

impl russh::server::Server for SshStubServer {
    type Handler = SshStubHandler;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Self::Handler {
        SshStubHandler
    }

    fn handle_session_error(&mut self, _error: russh::Error) {}
}

struct SshStubHandler;

impl russh::server::Handler for SshStubHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(if user == SSH_USER && password == SSH_PASSWORD {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
    }

    /// direct-tcpip：连到请求的目标地址并双向泵（真实 SSH 跳板的转发语义）。
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let Ok(mut target) =
            TcpStream::connect((host_to_connect, port_to_connect as u16)).await
        else {
            return Ok(()); // 目标不可达：关 channel（drop 即拒）即模拟真实跳板行为
        };
        let mut stream = channel.into_stream();
        tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut target, &mut stream).await;
        });
        Ok(())
    }
}

/// 起进程内 SSH server，返回 (port, 绑定句柄任务)。
async fn spawn_ssh_stub() -> anyhow::Result<u16> {
    let key = russh::keys::decode_secret_key(SSH_HOST_KEY_PEM, None)?;
    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let mut server = SshStubServer;
    use russh::server::Server as _;
    tokio::spawn(async move {
        let _ = server.run_on_socket(config, &listener).await;
    });
    Ok(port)
}

// ── 进程内 TLS 桩 ──

/// 装配 rustls server config（自签 fixture；ring provider，进程级安装幂等）。
fn tls_server_config() -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cert_rd = std::io::BufReader::new(TLS_CERT_PEM.as_bytes());
    let mut key_rd = std::io::BufReader::new(TLS_KEY_PEM.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_rd)?
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    // pemfile 1.x 无统一 private_key()：PKCS8 段取第一个（fixture 即一把）。
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_rd)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("tls key pem missing"))?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key));
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

/// TLS + RESP 桩：握手后读到任意字节即回 `+PONG`。返回监听端口。
async fn spawn_tls_resp_stub() -> anyhow::Result<u16> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_server_config()?);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else { return };
                let mut pending = Vec::new();
                let mut chunk = [0u8; 512];
                // redis-rs 建连 pipeline（CLIENT SETINFO×2）会合并在一次
                // TCP 写里且逐条读应答——按「行首 * 开头的 RESP 数组命令数」
                // 回等量 +PONG，并保持连接（multiplexed 驱动常驻读循环，
                // 过早 drop 无 close_notify 会报 UnexpectedEof）。
                loop {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            pending.extend_from_slice(&chunk[..n]);
                            let mut commands = 0usize;
                            for (i, b) in pending.iter().enumerate() {
                                if *b == b'*' && (i == 0 || pending[i - 1] == b'\n') {
                                    commands += 1;
                                }
                            }
                            let resp = "+PONG\r\n".repeat(commands);
                            if !resp.is_empty() && tls.write_all(resp.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(port)
}

/// TLS + HTTP 桩：读完整请求（头 + Content-Length body）后回 TD JSON。返回端口。
async fn spawn_tls_http_stub(body: &'static str) -> anyhow::Result<u16> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_server_config()?);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 512];
                // 读到头结束 + Content-Length 指示的 body（TD SQL 是请求体）。
                loop {
                    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
                    let Ok(n) = tls.read(&mut chunk).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(h) = head_end.or_else(|| buf.windows(4).position(|w| w == b"\r\n\r\n")) {
                        let content_len = std::str::from_utf8(&buf[..h])
                            .ok()
                            .and_then(|head| {
                                head.lines().find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())?
                                })
                            })
                            .unwrap_or(0);
                        if buf.len() >= h + 4 + content_len {
                            break;
                        }
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(resp.as_bytes()).await;
            });
        }
    });
    Ok(port)
}

// ── 测试行构造 ──

fn row(host: &str, port: i64, extra: Option<&str>) -> DbConnectionRow {
    DbConnectionRow {
        db_type: "redis".into(),
        host: host.into(),
        port,
        username: String::new(),
        password_encrypted: String::new(),
        default_database: None,
        file_path: None,
        charset: None,
        timezone: None,
        extra: extra.map(str::to_string),
        read_only: 0,
        ssh_secret_encrypted: None,
    }
}

/// Redis 目标 env：`GW_E2E_REDIS=host:port` + `GW_E2E_REDIS_PASSWORD`。
/// 任一缺失/格式非法 = None（SKIP 语义，凭据不进代码）。
fn redis_env() -> Option<(String, u16, String)> {
    let target = std::env::var("GW_E2E_REDIS").ok().filter(|v| !v.is_empty())?;
    let password = std::env::var("GW_E2E_REDIS_PASSWORD").ok().filter(|v| !v.is_empty())?;
    let (host, port) = target.split_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), port, password))
}

/// 目标 Redis 可达性（1.5s；不可达 = SKIP 语义）。
async fn redis_target() -> Option<(String, i64, String)> {
    let (host, port, password) = redis_env()?;
    let ok = tokio::time::timeout(
        Duration::from_millis(1500),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    if !ok {
        return None;
    }
    Some((host, port as i64, password))
}

/// 真实 SSH 跳板参数（env 注入，无内置部署地址/凭据——开源仓库不携带）。
/// `GW_E2E_SSH` 两种形式：`user:password@host:port`（password 认证，密码
/// 含 '@'/':' → 右侧拆）或 `user@host:port`（privateKey 认证——真实场景
/// 跳板只收公钥；私钥 = `GW_E2E_SSH_KEY`，缺省 `~/.ssh/id_ed25519` 无口令）。
/// 未设置 / 格式非法 / 不可达 / 私钥缺失 = SKIP。
async fn real_jump_host() -> Option<crate::ssh::SshTunnelParams> {
    let raw = std::env::var("GW_E2E_SSH").ok().filter(|v| !v.is_empty())?;
    let (userpass, hostport) = raw.rsplit_once('@')?;
    let (host, port) = hostport.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let (user, password) = match userpass.split_once(':') {
        Some((user, password)) => (user, Some(password.to_string())),
        None => (userpass, None),
    };
    if user.is_empty() {
        return None;
    }
    match password {
        Some(password) => {
            ssh_params(host, port, user, "password", &Some(password), &None).await
        }
        None => {
            let key_path = std::env::var("GW_E2E_SSH_KEY").unwrap_or_else(|_| {
                format!("{}/.ssh/id_ed25519", std::env::var("USERPROFILE").unwrap_or_default())
            });
            ssh_params(host, port, user, "privateKey", &None, &Some(key_path)).await
        }
    }
}

/// 组装 + 可达性探测（host:port 连不上 = None → SKIP）。
async fn ssh_params(
    host: &str,
    port: &str,
    user: &str,
    auth_mode: &str,
    password: &Option<String>,
    key_path: &Option<String>,
) -> Option<crate::ssh::SshTunnelParams> {
    let port_num = port.parse::<u16>().ok()?;
    let ok = tokio::time::timeout(
        Duration::from_millis(2000),
        TcpStream::connect((host, port_num)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    if !ok {
        return None;
    }
    let private_key = match key_path {
        Some(p) => std::fs::read_to_string(p).ok().filter(|s| !s.is_empty()),
        None => None,
    };
    if auth_mode == "privateKey" && private_key.is_none() {
        return None; // 私钥缺失（非开发机）= SKIP
    }
    Some(crate::ssh::SshTunnelParams {
        config: crate::ssh::SshConfig {
            host: host.to_string(),
            port: port_num as i64,
            username: user.to_string(),
            auth_mode: auth_mode.to_string(),
        },
        secrets: crate::ssh::SshSecrets {
            password: password.clone().unwrap_or_default(),
            private_key: private_key.unwrap_or_default(),
            passphrase: String::new(),
        },
    })
}

/// 真实 SSH 跳板（OpenSSH，非进程内桩）→ 重配后只对内监听的 Redis。
/// 与 `ssh_tunnel_forwards_real_redis`（进程内 server 桩）互补：验证 russh
/// 客户端对真实 OpenSSH 服务端的握手/认证/direct-tcpip 兼容性。
#[tokio::test]
async fn ssh_tunnel_via_real_jump_host() {
    let Some(redis) = redis_env() else {
        eprintln!("SKIP: GW_E2E_REDIS / GW_E2E_REDIS_PASSWORD not set");
        return;
    };
    let Some(ssh) = real_jump_host().await else {
        eprintln!("SKIP: GW_E2E_SSH not set or unreachable");
        return;
    };
    // 目标用 env 提供的地址（该 Redis 对外可能不可直连——正是本用例的前提）。
    let (rhost, rport, rpassword) = match redis_target().await {
        Some(t) => t,
        // 直连探测失败不 SKIP：重配拓扑下 6379 本就不对外，隧道内可达即可。
        None => (redis.0, redis.1 as i64, redis.2),
    };
    let (local_host, local_port, extra) = crate::ssh::apply_tunnel(
        &rhost,
        rport,
        None,
        &ssh.config,
        &ssh.secrets,
    )
    .await
    .expect("tunnel via real jump host");

    assert_eq!(local_host, "127.0.0.1");
    assert!(crate::net_flags::tunneled(extra.as_deref()));
    let conn = row(&local_host, local_port, extra.as_deref());
    let mut redis = crate::redis_leg::open_redis(&conn, &rpassword, 0)
        .await
        .expect("redis via real ssh jump host");
    let pong: String = redis::cmd("PING")
        .query_async(&mut redis)
        .await
        .expect("PING via real jump host");
    assert_eq!(pong, "PONG");
    // 走隧道的 SET/GET 回环验证（写目标库的 dbmaster_e2e 专用 key，幂等）。
    redis::cmd("SET")
        .arg("dbmaster_e2e:ssh_tunnel_probe")
        .arg("ok")
        .query_async::<redis::Value>(&mut redis)
        .await
        .expect("SET via tunnel");
    let v: String = redis::cmd("GET")
        .arg("dbmaster_e2e:ssh_tunnel_probe")
        .query_async(&mut redis)
        .await
        .expect("GET via tunnel");
    assert_eq!(v, "ok");
}

// ── 用例 ──

/// SSH 隧道端到端：进程内 SSH server → 真实 Redis PING。
#[tokio::test]
async fn ssh_tunnel_forwards_real_redis() {
    let Some((rhost, rport, rpassword)) = redis_target().await else {
        eprintln!("SKIP: GW_E2E_REDIS / GW_E2E_REDIS_PASSWORD not set or unreachable");
        return;
    };
    let ssh_port = spawn_ssh_stub().await.expect("ssh stub");
    let (local_host, local_port, extra) = crate::ssh::apply_tunnel(
        &rhost,
        rport,
        None,
        &crate::ssh::SshConfig {
            host: "127.0.0.1".into(),
            port: ssh_port as i64,
            username: SSH_USER.into(),
            auth_mode: "password".into(),
        },
        &crate::ssh::SshSecrets {
            password: SSH_PASSWORD.into(),
            ..Default::default()
        },
    )
    .await
    .expect("tunnel resolve");

    assert_eq!(local_host, "127.0.0.1");
    assert!(crate::net_flags::tunneled(extra.as_deref()));
    let conn = row(&local_host, local_port, extra.as_deref());
    let mut redis = crate::redis_leg::open_redis(&conn, &rpassword, 0)
        .await
        .expect("redis via tunnel");
    let pong: String = redis::cmd("PING")
        .query_async(&mut redis)
        .await
        .expect("PING via tunnel");
    assert_eq!(pong, "PONG");
    // 二次 resolve 走缓存复用路径。
    let (_, p2, _) = crate::ssh::apply_tunnel(
        &rhost,
        rport,
        None,
        &crate::ssh::SshConfig {
            host: "127.0.0.1".into(),
            port: ssh_port as i64,
            username: SSH_USER.into(),
            auth_mode: "password".into(),
        },
        &crate::ssh::SshSecrets {
            password: SSH_PASSWORD.into(),
            ..Default::default()
        },
    )
    .await
    .expect("tunnel re-resolve");
    assert_eq!(p2, local_port);
}

/// Redis TLS 真握手：insecure 放行 / 非 insecure 校验拒绝 / tunneled 强制放行。
#[tokio::test]
async fn redis_tls_handshake_insecure_and_verified() {
    let port = spawn_tls_resp_stub().await.expect("tls stub");
    // ① tlsInsecure=true：自签证书放行，PING 通。
    let conn = row("127.0.0.1", port as i64, Some(r#"{"useTls":true,"tlsInsecure":true}"#));
    let mut redis = crate::redis_leg::open_redis(&conn, "", 0)
        .await
        .expect("insecure tls connect");
    let pong: String = redis::cmd("PING").query_async(&mut redis).await.expect("PING");
    assert_eq!(pong, "PONG");
    // ② useTls 且不 insecure：自签证书必须被拒（校验真实生效）。
    let conn = row("127.0.0.1", port as i64, Some(r#"{"useTls":true}"#));
    let err = crate::redis_leg::open_redis(&conn, "", 0)
        .await
        .expect_err("verified tls must reject self-signed");
    assert!(
        crate::redis_leg::is_connection_level_error(&err),
        "cert rejection should be connection-level: {err}"
    );
    // ③ tunneled + useTls（无 tlsInsecure）：隧道组合强制 insecure → 放行。
    let conn = row("127.0.0.1", port as i64, Some(r#"{"useTls":true,"tunneled":true}"#));
    let mut redis = crate::redis_leg::open_redis(&conn, "", 0)
        .await
        .expect("tunneled tls forced insecure");
    let pong: String = redis::cmd("PING").query_async(&mut redis).await.expect("PING");
    assert_eq!(pong, "PONG");
}

/// TDengine https 真握手：insecure 放行并解析 TD JSON / 非 insecure 拒绝 /
/// tunneled 强制放行。
#[tokio::test]
async fn tdengine_https_handshake() {
    let port = spawn_tls_http_stub(
        r#"{"code":0,"column_meta":[["server_version()","VARCHAR",16]],"data":[["3.3.6.6"]],"rows":1}"#,
    )
    .await
    .expect("tls http stub");
    // ① tlsInsecure=true：https 放行 + 应答解析。
    let conn = DbConnectionRow {
        db_type: "tdengine".into(),
        username: "root".into(),
        ..row("127.0.0.1", port as i64, Some(r#"{"useTls":true,"tlsInsecure":true}"#))
    };
    let out = crate::tdengine_leg::exec_sql(&conn, "taosdata", None, "SELECT SERVER_VERSION()", Duration::from_secs(5))
        .await
        .expect("https insecure exec");
    assert_eq!(out.columns[0].0, "server_version()");
    assert_eq!(out.rows[0][0], serde_json::json!("3.3.6.6"));
    // ② useTls 不 insecure：自签证书 → 传输层失败。
    let conn = DbConnectionRow {
        db_type: "tdengine".into(),
        username: "root".into(),
        ..row("127.0.0.1", port as i64, Some(r#"{"useTls":true}"#))
    };
    assert!(matches!(
        crate::tdengine_leg::exec_sql(&conn, "taosdata", None, "SELECT 1", Duration::from_secs(5)).await,
        Err(crate::tdengine_leg::TdError::Transport)
    ));
    // ③ tunneled + useTls：强制放行。
    let conn = DbConnectionRow {
        db_type: "tdengine".into(),
        username: "root".into(),
        ..row("127.0.0.1", port as i64, Some(r#"{"useTls":true,"tunneled":true}"#))
    };
    let out = crate::tdengine_leg::exec_sql(&conn, "taosdata", None, "SELECT SERVER_VERSION()", Duration::from_secs(5))
        .await
        .expect("https tunneled exec");
    assert_eq!(out.rows[0][0], serde_json::json!("3.3.6.6"));
}
