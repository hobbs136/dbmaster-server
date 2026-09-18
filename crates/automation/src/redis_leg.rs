//! T29 非 SQL 批次（B3，ADR-0006 §2.3/§2.5/§2.6）— Redis 网关腿基建。
//!
//! - **连接**：`ConnectionInfo` 程序化组装（凭据分离不进 URL，对齐 mongo
//!   腿纪律）；db 路由解析 `'db0'`/`'0'` 双格式（客户端表单存纯数字）；
//!   每执行 `Client::open` + 独立连接，drop 即取消（对齐「专用池
//!   max_connections(1)」锚点）；订阅连接独立（§2.5）。
//! - **命令分类**：静态写集 + 危险集兜底，`ACL CAT`（write/dangerous）
//!   按连接懒加载缓存（DashMap）为权威；`read_only` 连接拒 Write 与
//!   Unknown（未知保守判写，ADR §2.3），engineCode=READONLY。危险集对齐
//!   客户端 `validateCommand` 语义（riskLevel != safe 即拦：KEYS/FLUSHALL…）。
//! - **RESP → JSON 值域**：integer→number、bulk→string（utf8 lossy）、
//!   array→array、nil→null、status/OK→string、Map（RESP3）→object。
//! - **白名单语义列**：SCAN/KEYS/HGETALL/HSCAN/ZRANGE WITHSCORES/ZSCAN/
//!   SMEMBERS 族/LRANGE/CONFIG GET/MGET 展平为多列表格；其余 fallback
//!   单列 `["result"]`（数组/嵌套为 JSON 值单格）。

use std::collections::HashSet;
use std::sync::LazyLock;

use dashmap::DashMap;
use redis::aio::MultiplexedConnection;
use redis::{Client, ConnectionAddr, ConnectionInfo, IntoConnectionInfo, RedisConnectionInfo, Value as Resp};
use serde_json::Value;

use crate::db_handler::DbConnectionRow;

// ── 连接 ──

/// db index 解析：请求 database 参数 → default_database；兼容 `'db0'`/`'0'`
/// 双格式（客户端历史约定）；非数字回落 0。
pub(crate) fn db_index(conn: &DbConnectionRow, db: Option<&str>) -> i64 {
    let raw = db
        .filter(|d| !d.is_empty())
        .or(conn.default_database.as_deref())
        .unwrap_or("0");
    let digits = raw.strip_prefix("db").unwrap_or(raw);
    digits.parse::<i64>().unwrap_or(0)
}

/// 凭据分离的连接信息（用户名非空 = ACL 双参认证，与客户端 auth 三态推导
/// 一致：username+password / password-only / none）。
///
/// 网络层批次（2026-08-29）— extra `useTls` → TcpTls 透传。TcpTls 的 host
/// 字段同时是 TLS SNI/证书校验名：走隧道时行 host 已被收口改写为
/// 127.0.0.1，证书域名校验必败 → 该组合强制 insecure（tlsInsecure 用户
/// 自担 + 隧道场景技术必需，见 net_flags 模块文档）。
pub(crate) fn connection_info(
    conn: &DbConnectionRow,
    password: &str,
    db: i64,
) -> ConnectionInfo {
    let mut info = RedisConnectionInfo::default().set_db(db);
    if !conn.username.is_empty() {
        info = info.set_username(&conn.username);
    }
    if !password.is_empty() {
        info = info.set_password(password);
    }
    let (use_tls, tls_insecure) = crate::net_flags::tls_flags(conn.extra.as_deref());
    let tunneled = crate::net_flags::tunneled(conn.extra.as_deref());
    let addr = if use_tls {
        ConnectionAddr::TcpTls {
            host: conn.host.clone(),
            port: conn.port as u16,
            insecure: tls_insecure || tunneled,
            tls_params: None,
        }
    } else {
        ConnectionAddr::Tcp(conn.host.clone(), conn.port as u16)
    };
    // ConnectionAddr::into_connection_info 按 redis 1.6 实现恒 Ok（见其源）。
    addr.into_connection_info()
        .expect("ConnectionAddr into ConnectionInfo is infallible")
        .set_redis_settings(info)
}

/// 开一条独立连接（每执行一条；drop 即取消在途命令）。
pub(crate) async fn open_redis(
    conn: &DbConnectionRow,
    password: &str,
    db: i64,
) -> Result<MultiplexedConnection, redis::RedisError> {
    let client = Client::open(connection_info(conn, password, db))?;
    client.get_multiplexed_async_connection().await
}

/// 开订阅专用连接（每 SSE 流一条，§2.5；订阅与 db 无关，固定 db 0）。
pub(crate) async fn open_pubsub(
    conn: &DbConnectionRow,
    password: &str,
) -> Result<redis::aio::PubSub, redis::RedisError> {
    let client = Client::open(connection_info(conn, password, 0))?;
    client.get_async_pubsub().await
}

/// 连接级错误判定（非服务端响应错误即归连接级：IO/认证/超时——调用方映射
/// CONNECTION_FAILED 固定文案）。
pub(crate) fn is_connection_level_error(e: &redis::RedisError) -> bool {
    e.code().is_none()
}

// ── 命令分类（只读硬执行）──

/// 数据/状态变更命令（read_only 连接拒绝；ACL CAT 之外的兜底集）。子命令
/// 级写（SCRIPT FLUSH / CONFIG SET / FUNCTION LOAD 等）经首词归并。
const WRITE_COMMANDS: &[&str] = &[
    // String
    "SET", "SETNX", "SETEX", "PSETEX", "MSET", "MSETNX", "GETSET", "GETDEL",
    "SETRANGE", "SETBIT", "APPEND",
    // Key / TTL
    "DEL", "UNLINK", "RENAME", "RENAMENX", "EXPIRE", "PEXPIRE", "EXPIREAT",
    "PEXPIREAT", "PERSIST", "COPY", "MOVE", "RESTORE", "MIGRATE",
    // Counter
    "INCR", "INCRBY", "INCRBYFLOAT", "DECR", "DECRBY",
    // List
    "LPUSH", "LPUSHX", "RPUSH", "RPUSHX", "LPOP", "RPOP", "LINSERT", "LSET",
    "LTRIM", "RPOPLPUSH", "LMOVE", "LMPOP", "BLPOP", "BRPOP", "BLMOVE",
    "BRPOPLPUSH",
    // Set
    "SADD", "SPOP", "SREM", "SMOVE", "SINTERSTORE", "SUNIONSTORE",
    "SDIFFSTORE",
    // ZSet
    "ZADD", "ZINCRBY", "ZPOPMIN", "ZPOPMAX", "ZPOPCOUNT", "ZREM",
    "ZREMRANGEBYRANK", "ZREMRANGEBYSCORE", "ZREMRANGEBYLEX", "ZMPOP",
    "BZPOPMIN", "BZPOPMAX",
    // Hash
    "HSET", "HSETNX", "HMSET", "HDEL", "HINCRBY", "HINCRBYFLOAT",
    // Bitmap / HyperLogLog / Geo
    "BITOP", "PFADD", "PFMERGE", "GEOADD",
    // Stream
    "XADD", "XDEL", "XTRIM", "XGROUP", "XSETID", "XACK",
    // Script / Function / 管理（含子命令：FLUSH/LOAD/SET…）
    "EVAL", "EVALSHA", "FUNCTION", "SCRIPT", "CONFIG", "ACL",
    "FLUSHALL", "FLUSHDB", "SWAPDB", "SORT",
];

/// 危险命令（对齐客户端 validateCommand 的黑名单语义——read_only 下同样
/// 拒绝；非 read_only 放行）。
const DANGEROUS_COMMANDS: &[&str] = &[
    "KEYS", "FLUSHALL", "FLUSHDB", "SHUTDOWN", "DEBUG", "MONITOR",
    "SLAVEOF", "REPLICAOF", "FAILOVER", "CLIENT", "CLUSTER", "SYNC",
    "PSYNC", "RESET", "LOLWUT",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RedisCommandClass {
    Write,
    Read,
}

/// 静态分类（大小写不敏感）。命中写/危险集 → Write；其余 → Read。
/// 注意 ACL CAT 不可得（Redis<6 / 无权限）时的 fallback 即本表：未列写
/// 的命令按读放行（含 GET 等常见读——比 ADR 初稿的「未知保守判写」更
/// 宽松，否则无 ACL 服务器连 GET 都被拒；ADR-0006 §2.3 修订记录此偏差）。
pub(crate) fn classify_static(name: &str) -> RedisCommandClass {
    let upper = name.to_ascii_uppercase();
    if WRITE_COMMANDS.contains(&upper.as_str())
        || DANGEROUS_COMMANDS.contains(&upper.as_str())
    {
        return RedisCommandClass::Write;
    }
    RedisCommandClass::Read
}

/// ACL CAT 分类缓存：conn_id → 类集合（注册凭据绑定，重注册即换 id，
/// 天然失效）。`ACL CAT` 拉取失败（无权限/老版本）返回 None → 静态表兜底。
struct AclClasses {
    write: HashSet<String>,
    dangerous: HashSet<String>,
}

static ACL_CACHE: LazyLock<DashMap<String, Option<AclClasses>>> =
    LazyLock::new(DashMap::new);

/// 权威分类：静态表命中写集即 Write；否则查 ACL CAT 缓存（懒加载）——
/// write/dangerous 类命中 → Write，其余已知命令 → Read；ACL 不可得回落
/// 静态表（Read）。调用方：read_only 时 Write 拒。
pub(crate) async fn classify(
    conn_id: &str,
    conn: &mut MultiplexedConnection,
    name: &str,
) -> RedisCommandClass {
    if classify_static(name) == RedisCommandClass::Write {
        return RedisCommandClass::Write;
    }
    let upper = name.to_ascii_uppercase();
    if let Some(cached) = ACL_CACHE.get(conn_id) {
        if let Some(classes) = cached.value().as_ref() {
            if classes.write.contains(&upper) || classes.dangerous.contains(&upper) {
                return RedisCommandClass::Write;
            }
        }
        return RedisCommandClass::Read;
    }
    let fetched = fetch_acl_classes(conn).await;
    let class = if let Some(classes) = &fetched {
        if classes.write.contains(&upper) || classes.dangerous.contains(&upper) {
            RedisCommandClass::Write
        } else {
            RedisCommandClass::Read
        }
    } else {
        // ACL CAT 不可得：静态表兜底（未列写 = 读，见 classify_static 文档）。
        RedisCommandClass::Read
    };
    ACL_CACHE.insert(conn_id.to_string(), fetched);
    class
}

async fn fetch_acl_classes(conn: &mut MultiplexedConnection) -> Option<AclClasses> {
    let write: Vec<String> = redis::cmd("ACL")
        .arg("CAT")
        .arg("write")
        .query_async(conn)
        .await
        .ok()?;
    let dangerous: Vec<String> = redis::cmd("ACL")
        .arg("CAT")
        .arg("dangerous")
        .query_async(conn)
        .await
        .ok()?;
    Some(AclClasses {
        write: write.into_iter().map(|c| c.to_ascii_uppercase()).collect(),
        dangerous: dangerous
            .into_iter()
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    })
}

// ── RESP → JSON 值域 ──

pub(crate) fn resp_to_json(v: Resp) -> Value {
    match v {
        Resp::Nil => Value::Null,
        Resp::Int(i) => Value::Number(i.into()),
        Resp::BulkString(bytes) => {
            Value::String(String::from_utf8_lossy(&bytes).into_owned())
        }
        Resp::SimpleString(s) => Value::String(s),
        Resp::Okay => Value::String("OK".to_string()),
        Resp::Array(items) | Resp::Set(items) => {
            Value::Array(items.into_iter().map(resp_to_json).collect())
        }
        // RESP3 无序键值对（HELLO 3 下 HGETALL 等的到达形态）。
        Resp::Map(pairs) => Value::Object(
            pairs
                .into_iter()
                .map(|(k, v)| {
                    (
                        resp_to_json(k).as_str().unwrap_or_default().to_string(),
                        resp_to_json(v),
                    )
                })
                .collect(),
        ),
        Resp::Attribute { data, .. } => resp_to_json(*data),
        Resp::Push { data, .. } => {
            Value::Array(data.into_iter().map(resp_to_json).collect())
        }
        Resp::Double(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Resp::Boolean(b) => Value::Bool(b),
        Resp::VerbatimString { text, .. } => Value::String(text),
        // BigNumber（feature 双形态）/ ServerError 等奇异形态——Debug 文本
        // 兜底（正常命令面不出现）。
        other => Value::String(format!("{other:?}")),
    }
}

fn resp_string(v: &Resp) -> Option<String> {
    match v {
        Resp::BulkString(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        Resp::SimpleString(s) => Some(s.clone()),
        Resp::Okay => Some("OK".to_string()),
        Resp::Int(i) => Some(i.to_string()),
        Resp::Double(f) => Some(f.to_string()),
        _ => None,
    }
}

/// 语义列展平的单元格：字符串保真、i64/f64 可解析为 number、其余 JSON 值
///（ZRANGE WITHSCORES 的 score 经 bulk 到达，需数字保真）。
fn cell(v: &Resp) -> Value {
    match v {
        Resp::Int(i) => Value::Number((*i).into()),
        Resp::BulkString(bytes) => {
            let s = String::from_utf8_lossy(bytes);
            if let Ok(n) = s.parse::<i64>() {
                Value::Number(n.into())
            } else if let Some(f) = s.parse::<f64>().ok().and_then(serde_json::Number::from_f64)
            {
                Value::Number(f)
            } else {
                Value::String(s.into_owned())
            }
        }
        other => resp_to_json(other.clone()),
    }
}

/// 白名单结构化命令 → (语义列, 展平行)。返回 None = fallback 单列。
pub(crate) fn semantic_rows(
    name: &str,
    args: &[String],
    result: &Resp,
) -> Option<(Vec<String>, Vec<Vec<Value>>)> {
    let upper = name.to_ascii_uppercase();
    let arg_upper: Vec<String> =
        args.iter().map(|a| a.to_ascii_uppercase()).collect();

    // SCAN/HSCAN/ZSCAN：[cursor, [items...]]。**空批回落 fallback**（返回
    // None）——语义行形状下 0 行会把 cursor 丢在 wire 外，客户端大库 SCAN
    // 迭代会因空批（SCAN 允许中途空批）提前终止；fallback 单列整值
    // [cursor, []] 保真。
    let scan_like = |item_cols: &[&str]| -> Option<(Vec<String>, Vec<Vec<Value>>)> {
        let Resp::Array(outer) = result else { return None };
        if outer.len() != 2 {
            return None;
        }
        let cursor = resp_string(&outer[0])?;
        let Resp::Array(items) = &outer[1] else { return None };
        if items.is_empty() {
            return None;
        }
        let mut cols = vec!["cursor".to_string()];
        cols.extend(item_cols.iter().map(|s| s.to_string()));
        let rows = items
            .iter()
            .map(|item| {
                let mut row = vec![Value::String(cursor.clone())];
                row.push(cell(item));
                row
            })
            .collect();
        Some((cols, rows))
    };

    match upper.as_str() {
        "SCAN" => scan_like(&["key"]),
        "HSCAN" | "SSCAN" => {
            // HSCAN 内层是 [f,v,f,v,...] 平铺对；SSCAN 是 [m,m,...]。
            let cols: Vec<String> = if upper == "HSCAN" {
                ["cursor", "field", "value"].as_slice()
            } else {
                ["cursor", "member"].as_slice()
            }
            .iter()
            .map(|s| s.to_string())
            .collect();
            let Resp::Array(outer) = result else { return None };
            if outer.len() != 2 {
                return None;
            }
            let cursor = resp_string(&outer[0])?;
            let Resp::Array(items) = &outer[1] else {
                return None;
            };
            // 空批回落 fallback（cursor 保真，见 scan_like 注释）。
            if items.is_empty() {
                return None;
            }
            let rows = if upper == "HSCAN" {
                items
                    .chunks(2)
                    .map(|pair| {
                        vec![
                            Value::String(cursor.clone()),
                            cell(pair.first().unwrap_or(&Resp::Nil)),
                            cell(pair.get(1).unwrap_or(&Resp::Nil)),
                        ]
                    })
                    .collect()
            } else {
                items
                    .iter()
                    .map(|m| vec![Value::String(cursor.clone()), cell(m)])
                    .collect()
            };
            Some((cols, rows))
        }
        "ZSCAN" => {
            let Resp::Array(outer) = result else { return None };
            if outer.len() != 2 {
                return None;
            }
            let cursor = resp_string(&outer[0])?;
            let Resp::Array(items) = &outer[1] else { return None };
            // 空批回落 fallback（cursor 保真，见 scan_like 注释）。
            if items.is_empty() {
                return None;
            }
            let rows = items
                .chunks(2)
                .map(|pair| {
                    vec![
                        Value::String(cursor.clone()),
                        cell(pair.first().unwrap_or(&Resp::Nil)),
                        cell(pair.get(1).unwrap_or(&Resp::Nil)),
                    ]
                })
                .collect();
            Some((vec!["cursor".to_string(), "member".to_string(), "score".to_string()], rows))
        }
        "KEYS" | "SMEMBERS" | "SINTER" | "SUNION" | "SDIFF" | "LRANGE" => {
            let Resp::Array(items) = result else { return None };
            let col = match upper.as_str() {
                "LRANGE" => "element",
                _ => {
                    if upper == "KEYS" {
                        "key"
                    } else {
                        "member"
                    }
                }
            };
            let rows = items
                .iter()
                .map(|item| vec![cell(item)])
                .collect::<Vec<_>>();
            Some((vec![col.to_string()], rows))
        }
        "HGETALL" | "CONFIG" => {
            // HGETALL 平铺对 / RESP3 Map；CONFIG GET 平铺对。
            let (cols, pairs): (Vec<&str>, Vec<(Resp, Resp)>) = match result {
                Resp::Array(items) => {
                    if upper == "CONFIG" {
                        (
                            vec!["parameter", "value"],
                            items.chunks(2).filter_map(|c| match c {
                                [k, v] => Some((k.clone(), v.clone())),
                                _ => None,
                            }).collect(),
                        )
                    } else {
                        (
                            vec!["field", "value"],
                            items.chunks(2).filter_map(|c| match c {
                                [k, v] => Some((k.clone(), v.clone())),
                                _ => None,
                            }).collect(),
                        )
                    }
                }
                Resp::Map(pairs) => (
                    if upper == "CONFIG" {
                        vec!["parameter", "value"]
                    } else {
                        vec!["field", "value"]
                    },
                    pairs.clone(),
                ),
                _ => return None,
            };
            let rows = pairs
                .into_iter()
                .map(|(k, v)| vec![cell(&k), cell(&v)])
                .collect();
            Some((cols.into_iter().map(String::from).collect(), rows))
        }
        "ZRANGE" | "ZRANGESTORE" => {
            if !arg_upper.iter().any(|a| a == "WITHSCORES") {
                return None;
            }
            let Resp::Array(items) = result else { return None };
            let rows = items
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|pair| vec![cell(&pair[0]), cell(&pair[1])])
                .collect();
            Some((vec!["member".to_string(), "score".to_string()], rows))
        }
        "MGET" => {
            let Resp::Array(items) = result else { return None };
            let rows = items
                .iter()
                .map(|item| vec![cell(item)])
                .collect::<Vec<_>>();
            Some((vec!["value".to_string()], rows))
        }
        _ => None,
    }
}

/// fallback 单列行：结果整值为一个 JSON 单元格（数组/嵌套保持 JSON 形态）。
pub(crate) fn fallback_row(result: &Resp) -> Vec<Value> {
    vec![resp_to_json(result.clone())]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_row(db: Option<&str>) -> DbConnectionRow {
        DbConnectionRow {
            db_type: "redis".into(),
            host: "h1".into(),
            port: 6379,
            username: "u".into(),
            password_encrypted: String::new(),
            default_database: db.map(str::to_string),
            file_path: None,
            charset: None,
            timezone: None,
            extra: None,
            read_only: 0,
            ssh_secret_encrypted: None,
        }
    }

    #[test]
    fn db_index_parses_dual_format_and_defaults() {
        assert_eq!(db_index(&conn_row(None), None), 0);
        assert_eq!(db_index(&conn_row(Some("5")), None), 5);
        assert_eq!(db_index(&conn_row(Some("db3")), None), 3);
        assert_eq!(db_index(&conn_row(Some("db0")), Some("db7")), 7);
        assert_eq!(db_index(&conn_row(Some("db0")), Some("")), 0);
        assert_eq!(db_index(&conn_row(Some("abc")), None), 0);
    }

    #[test]
    fn connection_info_carries_credentials_and_db() {
        let info = connection_info(&conn_row(Some("2")), "pw", 2);
        assert_eq!(info.redis_settings().db(), 2);
        assert_eq!(info.redis_settings().username(), Some("u"));
        assert_eq!(info.redis_settings().password(), Some("pw"));
        match info.addr() {
            redis::ConnectionAddr::Tcp(host, port) => {
                assert_eq!(host, "h1");
                assert_eq!(*port, 6379);
            }
            other => panic!("unexpected addr: {other:?}"),
        }
    }

    #[test]
    fn connection_info_tls_branches_and_tunnel_forces_insecure() {
        let row = |extra: Option<&str>| DbConnectionRow { extra: extra.map(str::to_string), ..conn_row(None) };
        // 直连 TLS：host 原值 + insecure 跟随 tlsInsecure。
        let info = connection_info(&row(Some(r#"{"useTls":true}"#)), "", 0);
        match info.addr() {
            redis::ConnectionAddr::TcpTls { host, port, insecure, .. } => {
                assert_eq!(host, "h1");
                assert_eq!(*port, 6379);
                assert!(!insecure);
            }
            other => panic!("unexpected addr: {other:?}"),
        }
        let info = connection_info(&row(Some(r#"{"useTls":true,"tlsInsecure":true}"#)), "", 0);
        match info.addr() {
            redis::ConnectionAddr::TcpTls { insecure, .. } => assert!(insecure),
            other => panic!("unexpected addr: {other:?}"),
        }
        // 隧道 + TLS：host 已被收口改写为 127.0.0.1 → 强制 insecure（证书
        // 域名对不上本地地址，见 connection_info 文档）。
        // 隧道 + TLS：收口已把行 host 改写为 127.0.0.1（extra 带 tunneled）
        // → host 原值透传 + 强制 insecure（证书域名对不上本地地址）。
        let tun = DbConnectionRow { host: "127.0.0.1".into(), ..row(Some(r#"{"useTls":true,"tunneled":true}"#)) };
        let info = connection_info(&tun, "", 0);
        match info.addr() {
            redis::ConnectionAddr::TcpTls { host, insecure, .. } => {
                assert_eq!(host, "127.0.0.1");
                assert!(insecure);
            }
            other => panic!("unexpected addr: {other:?}"),
        }
        // 无 useTls（含仅 tunneled）→ Tcp。
        for extra in [None, Some(r#"{"tunneled":true}"#), Some(r#"{"tlsInsecure":true}"#)] {
            assert!(matches!(connection_info(&row(extra), "", 0).addr(), redis::ConnectionAddr::Tcp(..)));
        }
    }

    #[test]
    fn static_classification_covers_write_dangerous_read() {
        assert_eq!(classify_static("SET"), RedisCommandClass::Write);
        assert_eq!(classify_static("flushall"), RedisCommandClass::Write);
        assert_eq!(classify_static("KEYS"), RedisCommandClass::Write);
        // 未列写的命令按读放行（ACL 不可得时的兜底语义，见 classify_static
        // 文档——GET 不能被静态表拒）。
        assert_eq!(classify_static("GET"), RedisCommandClass::Read);
        assert_eq!(classify_static("SOMEFUTURECMD"), RedisCommandClass::Read);
    }

    #[test]
    fn resp_to_json_covers_resp2_shapes() {
        assert_eq!(resp_to_json(Resp::Nil), serde_json::json!(null));
        assert_eq!(resp_to_json(Resp::Int(7)), serde_json::json!(7));
        assert_eq!(resp_to_json(Resp::Okay), serde_json::json!("OK"));
        assert_eq!(
            resp_to_json(Resp::SimpleString("PONG".into())),
            serde_json::json!("PONG")
        );
        assert_eq!(
            resp_to_json(Resp::BulkString(b"hello".to_vec())),
            serde_json::json!("hello")
        );
        assert_eq!(
            resp_to_json(Resp::Array(vec![Resp::Int(1), Resp::Nil])),
            serde_json::json!([1, null])
        );
    }

    #[test]
    fn semantic_rows_scan_hgetall_zrange_withscores() {
        // SCAN：[cursor, [k1, k2]] → 每键一行，cursor 重复列。
        let resp = Resp::Array(vec![
            Resp::BulkString(b"17".to_vec()),
            Resp::Array(vec![
                Resp::BulkString(b"user:1".to_vec()),
                Resp::BulkString(b"user:2".to_vec()),
            ]),
        ]);
        let (cols, rows) = semantic_rows("SCAN", &[], &resp).unwrap();
        assert_eq!(cols, vec!["cursor", "key"]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec![serde_json::json!("17"), serde_json::json!("user:1")]);

        // HGETALL 平铺对 → field/value 两列。
        let resp = Resp::Array(vec![
            Resp::BulkString(b"a".to_vec()),
            Resp::BulkString(b"1".to_vec()),
            Resp::BulkString(b"b".to_vec()),
            Resp::BulkString(b"2".to_vec()),
        ]);
        let (cols, rows) = semantic_rows("HGETALL", &[], &resp).unwrap();
        assert_eq!(cols, vec!["field", "value"]);
        assert_eq!(rows[1], vec![serde_json::json!("b"), serde_json::json!(2)]);

        // ZRANGE 不带 WITHSCORES → 无语义列（fallback）。
        let resp = Resp::Array(vec![Resp::BulkString(b"m1".to_vec())]);
        assert!(semantic_rows("ZRANGE", &[], &resp).is_none());
        // 带 WITHSCORES → member/score 对。
        let args = vec!["myzset".to_string(), "0".to_string(), "-1".to_string(), "WITHSCORES".to_string()];
        let resp = Resp::Array(vec![
            Resp::BulkString(b"m1".to_vec()),
            Resp::BulkString(b"1.5".to_vec()),
        ]);
        let (cols, rows) = semantic_rows("ZRANGE", &args, &resp).unwrap();
        assert_eq!(cols, vec!["member", "score"]);
        // score 经 bulk 到达，i64→f64 双解析臂保真为 number（e2e 钉定）。
        assert_eq!(rows[0], vec![serde_json::json!("m1"), serde_json::json!(1.5)]);

        // SCAN 空批 → 回落 fallback（cursor 经整值保真，见 scan_like 注释）。
        let resp = Resp::Array(vec![
            Resp::BulkString(b"42".to_vec()),
            Resp::Array(vec![]),
        ]);
        assert!(semantic_rows("SCAN", &[], &resp).is_none());
        assert_eq!(
            fallback_row(&resp),
            vec![serde_json::json!(["42", []])]
        );

        // GET（单值）→ fallback 单列。
        let resp = Resp::BulkString(b"v".to_vec());
        assert!(semantic_rows("GET", &[], &resp).is_none());
        assert_eq!(fallback_row(&resp), vec![serde_json::json!("v")]);
    }
}
