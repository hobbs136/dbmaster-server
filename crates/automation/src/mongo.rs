//! T29 非 SQL 批次（B1，ADR-0006 §2.4/§2.2）— MongoDB 网关腿基建。
//!
//! 语义 = **runCommand 单形状**：客户端把 shell/JSON 翻译成 db command
//! 文档（解析留在客户端壳的 `MongoShellQueryParser`），server 侧只做四件事：
//! - 连接：`extra` 集群四模式（direct/replicaSet/sharded/advanced，键名对齐
//!   客户端 ConnectionExtraKeys）→ ClientOptions，**凭据分离注入**（密码绝不
//!   进 URI，对齐客户端 `_openWithAuth` 先例）；
//! - 执行：`run_command` + 游标命令（find/aggregate/listCollections/
//!   listIndexes 等）的 firstBatch/getMore **手工展平**——不依赖驱动的
//!   run_cursor_command，getMore 语义自己钉（coll 名取自响应 ns）；
//! - 只读硬执行：静态写命令集 + aggregate $out/$merge 检查（read_only 连接
//!   上拒绝，engineCode=READONLY；未知命令默认按读放行——与 SQL 族
//!   is_select_statement 前缀判据同等强度的取舍，ADR-0006 §2.4）；
//! - BSON ↔ JSON 值域转换：出向扩展 JSON 子文档形态（$oid/$date/...，
//!   mongo_dart 时代 map 展示兼容），入向只接普通 JSON（$oid 等扩展类型的
//!   反向解析归客户端 shell 层，v1 明确边界）。
//!
//! 错误纪律：连接阶段失败（ping 前）由调用方归一 CONNECTION_FAILED 固定
//! 文案；命令错误经 `engine_code` 透传 codeName（Unauthorized/
//! NamespaceNotFound/…）。

use bson::{doc, Bson, Document};
use mongodb::options::Credential;
use mongodb::Client;
use mongodb::options::ClientOptions;
use serde_json::Value;

use crate::db_handler::DbConnectionRow;

pub(crate) const APP_NAME: &str = "dbmaster-gw";

// ── extra 集群配置（migration 008 JSON blob 消费侧）──

/// `database_connections.extra` 中 MongoDB 集群字段的投影（键名对齐客户端
/// `ConnectionExtraKeys`：mongoConnectionMode / mongoHosts / mongoReplicaSet /
/// mongoConnectionString——后者已在网关注册时剥除 userinfo）。
#[derive(Debug, Default)]
pub(crate) struct MongoCluster {
    /// direct | replicaSet | sharded | advanced（缺省 direct）。
    pub mode: String,
    /// "host" 或 "host:port" 列表（缺省回落行内 host/port）。
    pub hosts: Vec<String>,
    pub replica_set: Option<String>,
    pub connection_string: Option<String>,
}

pub(crate) fn parse_extra(extra: Option<&str>) -> MongoCluster {
    let mut cluster = MongoCluster::default();
    let Some(raw) = extra else { return cluster };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return cluster;
    };
    if let Some(mode) = map.get("mongoConnectionMode").and_then(Value::as_str) {
        cluster.mode = mode.to_string();
    }
    if let Some(hosts) = map.get("mongoHosts").and_then(Value::as_array) {
        cluster.hosts = hosts
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .filter(|h| !h.is_empty())
            .collect();
    }
    if let Some(rs) = map.get("mongoReplicaSet").and_then(Value::as_str) {
        cluster.replica_set = Some(rs.to_string());
    }
    if let Some(cs) = map.get("mongoConnectionString").and_then(Value::as_str) {
        cluster.connection_string = Some(cs.to_string());
    }
    cluster
}

/// 主机列表 → 连接 URI（host 项缺端口补 27017；含 userinfo/scheme 的项
/// 整体丢弃——凭据只走 Credential 注入，URI 永不带密码）。
fn hosts_uri(conn: &DbConnectionRow, cluster: &MongoCluster) -> String {
    let mut hosts: Vec<String> = cluster
        .hosts
        .iter()
        .filter(|h| !h.contains('@') && !h.contains("://") && !h.contains('/'))
        .cloned()
        .collect();
    if hosts.is_empty() {
        hosts.push(format!("{}:{}", conn.host, conn.port));
    }
    let joined = hosts
        .into_iter()
        .map(|h| if h.contains(':') { h } else { format!("{h}:27017") })
        .collect::<Vec<_>>()
        .join(",");
    let query = match cluster.mode.as_str() {
        // 缺省（未配置 mode）= direct——客户端连接表单的缺省语义。
        "direct" | "" => "?directConnection=true".to_string(),
        "replicaSet" => match &cluster.replica_set {
            Some(rs) if !rs.is_empty() => format!("?replicaSet={rs}"),
            _ => String::new(),
        },
        // sharded：多主机直连 mongos 集，无附加参数。
        _ => String::new(),
    };
    format!("mongodb://{joined}{query}")
}

/// extra 的 TLS 透传投影（网络层批次 2026-08-29）：`useTls` → Tls::Enabled；
/// 隧道 + TLS 组合强制 `allow_invalid_certificates`（经隧道时连接地址已被
/// 收口改写为 127.0.0.1，对它做证书域名校验必败——技术必需，见
/// net_flags 模块文档）。URI 不拼 ssl 参数（程序化注入，对齐凭据分离纪律）。
pub(crate) fn tls_option(extra: Option<&str>) -> Option<mongodb::options::Tls> {
    let (use_tls, insecure) = crate::net_flags::tls_flags(extra);
    if !use_tls {
        return None;
    }
    let tunneled = crate::net_flags::tunneled(extra);
    let mut tls_opts = mongodb::options::TlsOptions::default();
    tls_opts.allow_invalid_certificates = Some(insecure || tunneled);
    Some(mongodb::options::Tls::Enabled(tls_opts))
}

/// 开 MongoDB 客户端。advanced 模式优先 connectionString（注册时已剥除
/// userinfo）；否则行内 host/port 或 extra mongoHosts 组 URI。凭据经
/// Credential 注入（username/password 任一存在才设置；authSource =
/// default_database 缺省 admin——对齐客户端「auth 库 = database 字段」）。
pub(crate) async fn open_mongo(
    conn: &DbConnectionRow,
    password: &str,
) -> Result<Client, mongodb::error::Error> {
    let cluster = parse_extra(conn.extra.as_deref());
    let base = match cluster.connection_string.as_deref().filter(|s| !s.is_empty()) {
        Some(uri) => uri.to_string(),
        None => hosts_uri(conn, &cluster),
    };
    let mut opts = ClientOptions::parse(base).await?;
    opts.tls = tls_option(conn.extra.as_deref());
    let mut cred = Credential::default();
    if !conn.username.is_empty() {
        cred.username = Some(conn.username.clone());
    }
    if !password.is_empty() {
        cred.password = Some(password.to_string());
    }
    if let Some(auth_db) = conn.default_database.as_deref().filter(|d| !d.is_empty()) {
        cred.source = Some(auth_db.to_string());
    }
    if cred.username.is_some() || cred.password.is_some() {
        opts.credential = Some(cred);
    }
    opts.app_name = Some(APP_NAME.to_string());
    Client::with_options(opts)
}

/// 执行目标库解析：请求 database 参数 → default_database（= auth 库）→
/// "admin"。客户端壳对 mongo 查询恒传显式 database（useDatabase record-only
/// + 参数路由，对齐 PG 壳）；此缺省链只兜未传的边角。
pub(crate) fn resolve_db<'a>(conn: &'a DbConnectionRow, db: Option<&'a str>) -> &'a str {
    db.filter(|d| !d.is_empty())
        .unwrap_or_else(|| {
            conn.default_database.as_deref().filter(|d| !d.is_empty()).unwrap_or("admin")
        })
}

/// buildInfo.version（尽力而为：失败返回空串——版本是展示性信息）。
pub(crate) async fn server_version(conn: &DbConnectionRow, password: &str) -> String {
    let Ok(client) = open_mongo(conn, password).await else { return String::new() };
    let Ok(resp) = client.database("admin").run_command(doc! {"buildInfo": 1}).await else {
        return String::new();
    };
    resp.get_str("version").unwrap_or_default().to_string()
}

// ── 命令分类（只读硬执行 + affectedRows 语义）──

/// 静态写命令集（首键名判据；Mongo 命令名恒小写）。覆盖 CRUD/DDL/用户
/// 管理 + 两个「看似读实为写」的保守项（mapReduce 可写集合、eval 任意
///副作用）。explain 包装不执行写，按读放行。
const WRITE_COMMANDS: &[&str] = &[
    "insert", "update", "delete", "findandmodify", "findAndModify",
    "create", "createindexes", "createIndexes", "drop", "dropdatabase", "dropDatabase",
    "dropindexes", "dropIndexes", "renamecollection", "renameCollection",
    "collmod", "collMod",
];

/// 命令名（文档首键；空文档 None——键序保真依赖 preserve_order）。
pub(crate) fn command_name_of(doc: &Document) -> Option<String> {
    doc.iter().next().map(|(k, _)| k.to_string())
}

/// 响应计数字段读取（insert/update/delete 的 "n" 实机为 Int32；Int64 →
/// Int32 → Double 依次尝试——同 metadata::mysql_row_count 解码链先例）。
pub(crate) fn doc_count(doc: &Document, key: &str) -> Option<i64> {
    doc.get_i64(key)
        .ok()
        .or_else(|| doc.get_i32(key).ok().map(i64::from))
        .or_else(|| doc.get_f64(key).ok().map(|f| f as i64))
}

/// 命令是否写语义（read_only 连接拒 + SSE 走 affectedRows 通道）。
/// aggregate 特判：pipeline 含 $out/$merge 才算写。
pub(crate) fn is_write_command(name: &str, doc: &Document) -> bool {
    if name == "aggregate" {
        return doc
            .get_array("pipeline")
            .ok()
            .map(|stages| {
                stages.iter().any(|s| {
                    matches!(s, Bson::Document(d)
                        if d.contains_key("$out") || d.contains_key("$merge"))
                })
            })
            .unwrap_or(false);
    }
    if name == "mapreduce" || name == "mapReduce" || name == "eval" {
        return true;
    }
    WRITE_COMMANDS.contains(&name)
}

// ── BSON ↔ JSON ──

/// JSON 命令对象 → BSON Document（键序保真——preserve_order；数值 i64→
/// Int64 / 小数→Double）。非对象 / 非法嵌套返回 Err（网关层 4xx）。
pub(crate) fn json_to_command_doc(v: &Value) -> Result<Document, String> {
    match v {
        Value::Object(map) => json_map_to_doc(map),
        _ => Err("command must be a JSON object".to_string()),
    }
}

fn json_map_to_doc(map: &serde_json::Map<String, Value>) -> Result<Document, String> {
    let mut doc = Document::new();
    for (k, v) in map {
        // 扩展 JSON 单键子文档先尝试反解（$oid/$date/$numberDecimal）。
        let bson = match v {
            Value::Object(inner) => extended_json_to_bson(inner)
                .map(Ok)
                .unwrap_or_else(|| json_value_to_bson(v)),
            _ => json_value_to_bson(v),
        }?;
        doc.insert(k, bson);
    }
    Ok(doc)
}

fn json_value_to_bson(v: &Value) -> Result<Bson, String> {
    match v {
        Value::Null => Ok(Bson::Null),
        Value::Bool(b) => Ok(Bson::Boolean(*b)),
        Value::Number(n) => n
            .as_i64()
            .map(Bson::Int64)
            .or_else(|| n.as_f64().map(Bson::Double))
            .ok_or_else(|| "number out of representable range".to_string()),
        Value::String(s) => Ok(Bson::String(s.clone())),
        Value::Array(items) => Ok(Bson::Array(
            items.iter().map(json_value_to_bson).collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Object(map) => Ok(Bson::Document(json_map_to_doc(map)?)),
    }
}

/// 扩展 JSON 入向反解（与出向 `bson_to_json` 对称）：`{$oid}`/`{$date}`/
/// `{$numberDecimal}` 单键子文档还原为原生 BSON 类型——`{'_id': {'$oid':…}}`
/// 查询与 Date 值写入是客户端高频用法（测试/AI 导入直传 DateTime → 壳预
/// 编码为 `$date`）。其余子文档按普通 Document 通过；畸形值（非法 hex/
/// 非法日期/非单键）同样放行为普通 Document（宽松语义，与 mongo shell 的
/// 严格模式不同——宽松失败面小）。
fn extended_json_to_bson(map: &serde_json::Map<String, Value>) -> Option<Bson> {
    if map.len() != 1 {
        return None;
    }
    if let Some(Value::String(oid)) = map.get("$oid") {
        let bytes = hex::decode(oid).ok()?;
        if bytes.len() == 12 {
            return Some(Bson::ObjectId(bson::oid::ObjectId::from_bytes(
                bytes.try_into().ok()?,
            )));
        }
        return None;
    }
    if let Some(date_val) = map.get("$date") {
        if let Value::String(date) = date_val {
            if let Ok(dt) = bson::DateTime::parse_rfc3339_str(date) {
                return Some(Bson::DateTime(dt));
            }
            return None;
        }
        // 数字毫秒形态（{$date: 1759270400000}）。
        if let Some(ms) = date_val.as_i64() {
            return Some(Bson::DateTime(bson::DateTime::from_millis(ms)));
        }
        return None;
    }
    if let Some(Value::String(dec)) = map.get("$numberDecimal") {
        if let Ok(d) = dec.parse::<bson::Decimal128>() {
            return Some(Bson::Decimal128(d));
        }
        return None;
    }
    None
}

/// BSON 值 → 网关 JSON 值。扩展类型以扩展 JSON 子文档形态表达（$oid/
/// $date/…——与客户端 mongo_dart 时代 map 展示兼容）；奇异类型回落
/// Display 字符串。
pub(crate) fn bson_to_json(b: Bson) -> Value {
    match b {
        Bson::Double(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Bson::String(s) => Value::String(s),
        Bson::Boolean(v) => Value::Bool(v),
        Bson::Null => Value::Null,
        Bson::Int32(i) => Value::Number(i.into()),
        Bson::Int64(i) => Value::Number(i.into()),
        Bson::ObjectId(oid) => serde_json::json!({ "$oid": oid.to_hex() }),
        // RFC3339（ISO8601 带 T）——对齐客户端 toIso8601String 展示语义；
        // bson DateTime 的 Display 是 time crate 格式（"2026-01-01 00:00:00
        // UTC"，空格分隔无 T），实测不满足。
        Bson::DateTime(dt) => serde_json::json!({
            "$date": dt.try_to_rfc3339_string().unwrap_or_else(|_| dt.to_string())
        }),
        Bson::Timestamp(ts) => {
            serde_json::json!({ "$timestamp": { "t": ts.time, "i": ts.increment } })
        }
        Bson::Decimal128(d) => serde_json::json!({ "$numberDecimal": d.to_string() }),
        Bson::Binary(bin) => serde_json::json!({
            "$binary": {
                "base64": base64_encode(&bin.bytes),
                "subType": format!("{:02x}", u8::from(bin.subtype)),
            }
        }),
        Bson::RegularExpression(re) => {
            serde_json::json!({ "$regex": re.pattern, "$options": re.options })
        }
        Bson::JavaScriptCode(code) => serde_json::json!({ "$code": code }),
        Bson::Symbol(s) => Value::String(s),
        Bson::Array(items) => Value::Array(items.into_iter().map(bson_to_json).collect()),
        Bson::Document(doc) => Value::Object(
            doc.into_iter().map(|(k, v)| (k, bson_to_json(v))).collect(),
        ),
        // Undefined/MinKey/MaxKey/DbPointer/CodeWithScope 等奇异类型。
        other => Value::String(other.to_string()),
    }
}

pub(crate) fn document_to_json(doc: Document) -> Value {
    Value::Object(doc.into_iter().map(|(k, v)| (k, bson_to_json(v))).collect())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// describe 采样列的 BSON 类型名（对齐客户端 `_inferBsonType` 语义面）。
pub(crate) fn bson_type_name(b: &Bson) -> &'static str {
    match b {
        Bson::Double(_) => "double",
        Bson::String(_) => "string",
        Bson::Array(_) => "array",
        Bson::Document(_) => "object",
        Bson::Boolean(_) => "bool",
        Bson::Null => "null",
        Bson::Int32(_) => "int32",
        Bson::Int64(_) => "int64",
        Bson::ObjectId(_) => "objectId",
        Bson::DateTime(_) => "date",
        Bson::Timestamp(_) => "timestamp",
        Bson::Decimal128(_) => "decimal128",
        Bson::Binary(_) => "binData",
        Bson::RegularExpression(_) => "regex",
        _ => "other",
    }
}

// ── 错误分类（供 stream_query / metadata 归一）──

/// 连接级错误判定（mongodb 3.x 无公开 is_network_error；连接池被清/IO/
/// 认证/选服失败都归「连接失败」——调用方映射 CONNECTION_FAILED 固定文案）。
pub(crate) fn is_connection_level_error(e: &mongodb::error::Error) -> bool {
    use mongodb::error::ErrorKind;
    matches!(
        e.kind.as_ref(),
        ErrorKind::Io(_)
            | ErrorKind::ConnectionPoolCleared { .. }
            | ErrorKind::Authentication { .. }
            | ErrorKind::ServerSelection { .. }
    )
}

/// 命令错误的 codeName（Unauthorized/NamespaceNotFound/…）透传位。
pub(crate) fn engine_code(e: &mongodb::error::Error) -> Option<String> {
    if let mongodb::error::ErrorKind::Command(ce) = e.kind.as_ref() {
        Some(ce.code_name.clone())
    } else {
        None
    }
}

// ── 游标展平（firstBatch + getMore 手工循环）──

/// 响应文档是否携带游标（find/aggregate/listCollections/listIndexes 等的
/// 返回形态）：`{cursor: {firstBatch: [...], id: <long>, ns: "db.coll"}, ok}`。
/// 返回 (首批文档, 游标 id, ns)。
pub(crate) fn cursor_first_batch(resp: &Document) -> Option<(Vec<Document>, i64, String)> {
    let cursor = resp.get_document("cursor").ok()?;
    let batch = cursor
        .get_array("firstBatch")
        .ok()?
        .iter()
        .filter_map(|b| match b {
            Bson::Document(d) => Some(d.clone()),
            _ => None,
        })
        .collect();
    let id = cursor.get_i64("id").unwrap_or(0);
    let ns = cursor.get_str("ns").unwrap_or_default().to_string();
    Some((batch, id, ns))
}

struct CursorState {
    db: mongodb::Database,
    id: i64,
    coll: String,
    buf: std::vec::IntoIter<Document>,
}

/// 游标文档流：缓冲耗尽且 id ≠ 0 时发 getMore（coll 取自 ns 后缀）。
/// 错误只吐一次（吐后置 id=0 终结）。
pub(crate) fn cursor_stream(
    db: mongodb::Database,
    first_batch: Vec<Document>,
    cursor_id: i64,
    ns: &str,
) -> impl futures::Stream<Item = Result<Document, mongodb::error::Error>> {
    let coll = ns.rsplit('.').next().unwrap_or_default().to_string();
    futures::stream::unfold(
        CursorState { db, id: cursor_id, coll, buf: first_batch.into_iter() },
        |mut st| async move {
            loop {
                if let Some(doc) = st.buf.next() {
                    return Some((Ok(doc), st));
                }
                if st.id == 0 || st.coll.is_empty() {
                    return None;
                }
                let resp = match st
                    .db
                    .run_command(doc! {"getMore": st.id, "collection": st.coll.clone()})
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        st.id = 0;
                        return Some((Err(e), st));
                    }
                };
                let cursor = resp.get_document("cursor").cloned().unwrap_or_default();
                st.id = cursor.get_i64("id").unwrap_or(0);
                st.buf = cursor
                    .get_array("nextBatch")
                    .map(Clone::clone)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|b| match b {
                        Bson::Document(d) => Some(d),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .into_iter();
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn conn_row(extra: Option<&str>) -> DbConnectionRow {
        DbConnectionRow {
            db_type: "mongodb".into(),
            host: "h1".into(),
            port: 27017,
            username: "u".into(),
            password_encrypted: String::new(),
            default_database: Some("admin".into()),
            file_path: None,
            charset: None,
            timezone: None,
            extra: extra.map(str::to_string),
            read_only: 0,
            ssh_secret_encrypted: None,
        }
    }

    #[test]
    fn parse_extra_reads_client_cluster_keys_and_tolerates_garbage() {
        let c = parse_extra(Some(
            r#"{"mongoConnectionMode":"replicaSet","mongoHosts":["a:27017","b"],
                "mongoReplicaSet":"rs0","other":"ignored"}"#,
        ));
        assert_eq!(c.mode, "replicaSet");
        assert_eq!(c.hosts, vec!["a:27017", "b"]);
        assert_eq!(c.replica_set.as_deref(), Some("rs0"));
        assert!(c.connection_string.is_none());

        assert_eq!(parse_extra(None).mode, "");
        assert_eq!(parse_extra(Some("not json")).mode, "");
        assert_eq!(parse_extra(Some(r#"{"x":1}"#)).hosts, Vec::<String>::new());
    }

    #[test]
    fn hosts_uri_appends_port_query_and_drops_credential_like_entries() {
        // 缺省：行内 host/port，direct 模式补 directConnection。
        assert_eq!(
            hosts_uri(&conn_row(None), &parse_extra(None)),
            "mongodb://h1:27017?directConnection=true"
        );
        // 列表主机缺端口补 27017；replicaSet 模式带 rs 名。
        let c = parse_extra(Some(r#"{"mongoConnectionMode":"replicaSet",
            "mongoHosts":["a","b:28000"],"mongoReplicaSet":"rs0"}"#));
        assert_eq!(
            hosts_uri(&conn_row(Some("")), &c),
            "mongodb://a:27017,b:28000?replicaSet=rs0"
        );
        // sharded：多主机无附加参数。
        let c = parse_extra(Some(r#"{"mongoConnectionMode":"sharded","mongoHosts":["m1","m2"]}"#));
        assert_eq!(hosts_uri(&conn_row(Some("")), &c), "mongodb://m1:27017,m2:27017");
        // 带 userinfo/scheme 的主机项整体丢弃（凭据只走 Credential）；无
        // mode → direct 缺省。
        let c = parse_extra(Some(r#"{"mongoHosts":["u:p@evil:1","mongodb://x:2","ok:3"]}"#));
        assert_eq!(hosts_uri(&conn_row(Some("")), &c), "mongodb://ok:3?directConnection=true");
    }

    #[test]
    fn json_command_doc_preserves_first_key_order() {
        // "filter" 字母序在 "find" 前——preserve_order 必须保住命令名首键。
        let doc = json_to_command_doc(&json!({"find": "c", "filter": {"a": 1}, "limit": 5}))
            .expect("valid command");
        assert_eq!(doc.iter().next().unwrap().0, "find");
        assert_eq!(doc.get_str("find").unwrap(), "c");
        assert_eq!(doc.get_i64("limit").unwrap(), 5);
        assert!(json_to_command_doc(&json!([1])).is_err());
        // 嵌套文档/数组保序递归。
        let doc = json_to_command_doc(&json!({"aggregate": "c", "pipeline": [
            {"$match": {"a": 1}}, {"$out": "sink"}
        ]})).unwrap();
        let stages = doc.get_array("pipeline").unwrap();
        assert_eq!(stages.len(), 2);
        assert!(matches!(&stages[1], Bson::Document(d) if d.contains_key("$out")));
    }

    #[test]
    fn bson_to_json_covers_common_and_extended_types() {
        use bson::doc;
        assert_eq!(bson_to_json(Bson::Int32(7)), json!(7));
        assert_eq!(bson_to_json(Bson::Int64(i64::MAX)), json!(i64::MAX));
        assert_eq!(bson_to_json(Bson::Double(1.5)), json!(1.5));
        assert_eq!(bson_to_json(Bson::Null), json!(null));
        // 嵌套文档保序（_id 在前）。
        let d = doc! {"_id": bson::oid::ObjectId::from_bytes([1u8; 12]), "n": Bson::Int32(1)};
        let v = document_to_json(d);
        let obj = v.as_object().unwrap();
        assert_eq!(obj.keys().collect::<Vec<_>>(), vec!["_id", "n"]);
        assert_eq!(obj["_id"]["$oid"], "010101010101010101010101");
        // DateTime → {$date: RFC3339}（ISO 带 T；Display 是 time 格式无 T，
        // 见 bson_to_json 的 DateTime 臂注释）。
        let dt = mongodb::bson::DateTime::from_millis(1759270400000);
        assert_eq!(
            bson_to_json(Bson::DateTime(dt))["$date"],
            dt.try_to_rfc3339_string().unwrap()
        );
    }

    #[test]
    fn write_command_classification() {
        use bson::doc;
        assert!(is_write_command("insert", &doc! {"insert": "c", "documents": []}));
        assert!(is_write_command("dropDatabase", &doc! {"dropDatabase": 1}));
        // 大小写变体（客户端可能送驼峰别名）。
        assert!(is_write_command("findAndModify", &doc! {"findAndModify": "c"}));
        // 读命令放行。
        assert!(!is_write_command("find", &doc! {"find": "c"}));
        assert!(!is_write_command("aggregate", &doc! {"aggregate": "c", "pipeline": []}));
        assert!(!is_write_command("listCollections", &doc! {"listCollections": 1}));
        // aggregate $out/$merge = 写。
        assert!(is_write_command(
            "aggregate",
            &doc! {"aggregate": "c", "pipeline": [{"$out": "sink"}]}
        ));
        assert!(is_write_command(
            "aggregate",
            &doc! {"aggregate": "c", "pipeline": [{"$merge": {"into": "sink"}}]}
        ));
        // 保守写（mapReduce/eval）。
        assert!(is_write_command("mapReduce", &doc! {"mapReduce": "c"}));
        // 未知命令按读放行（ADR-0006 §2.4 取舍）。
        assert!(!is_write_command("someFutureCommand", &doc! {"someFutureCommand": 1}));
    }

    #[test]
    fn cursor_first_batch_extracts_batch_id_ns() {
        use bson::doc;
        let resp = doc! {
            "cursor": {"firstBatch": [doc! {"a": 1}], "id": Bson::Int64(42), "ns": "db.coll"},
            "ok": 1.0
        };
        let (batch, id, ns) = cursor_first_batch(&resp).expect("cursor response");
        assert_eq!(batch.len(), 1);
        assert_eq!(id, 42);
        assert_eq!(ns, "db.coll");
        // 游标耗尽：id 0；非游标响应：None。
        let resp = doc! {"cursor": {"firstBatch": [], "id": Bson::Int64(0), "ns": "db.c"}};
        assert_eq!(cursor_first_batch(&resp).unwrap().1, 0);
        assert!(cursor_first_batch(&doc! {"ok": 1.0}).is_none());
    }

    #[test]
    fn extended_json_input_restores_native_bson_types() {
        let doc = json_to_command_doc(&json!({
            "find": "c",
            "filter": {"_id": {"$oid": "010101010101010101010101"}},
            "when": {"$date": "2026-01-01T00:00:00.000Z"},
            "ms": {"$date": 1759270400000i64},
            "price": {"$numberDecimal": "3.14"},
        }))
        .expect("valid command");
        assert!(matches!(
            doc.get_document("filter").unwrap().get("_id"),
            Some(Bson::ObjectId(_))
        ));
        assert!(matches!(doc.get("when"), Some(Bson::DateTime(_))));
        assert!(matches!(doc.get("ms"), Some(Bson::DateTime(_))));
        assert!(matches!(doc.get("price"), Some(Bson::Decimal128(_))));

        // 畸形值放行为普通 Document（宽松语义）。
        let doc = json_to_command_doc(&json!({"q": {"$oid": "not-hex"}})).unwrap();
        assert!(matches!(doc.get("q"), Some(Bson::Document(_))));

        // 查询操作符子文档不受影响（单键但键名不在扩展集）。
        let doc = json_to_command_doc(&json!({"f": {"$gt": 5}})).unwrap();
        let inner = doc.get_document("f").unwrap();
        assert_eq!(inner.get_i64("$gt").unwrap(), 5);
    }

    #[test]
    fn tls_option_follows_extra_flags_and_tunnel_forces_insecure() {
        use mongodb::options::Tls;
        // 无 useTls（含仅 tunneled / 仅 insecure）→ None（不启用）。
        assert!(tls_option(None).is_none());
        assert!(tls_option(Some(r#"{"tunneled":true}"#)).is_none());
        assert!(tls_option(Some(r#"{"tlsInsecure":true}"#)).is_none());
        // 直连 TLS：校验开启。
        match tls_option(Some(r#"{"useTls":true}"#)) {
            Some(Tls::Enabled(o)) => assert_eq!(o.allow_invalid_certificates, Some(false)),
            other => panic!("unexpected tls option: {other:?}"),
        }
        // 用户显式 insecure / 隧道 + TLS → 放宽证书校验。
        for extra in [r#"{"useTls":true,"tlsInsecure":true}"#, r#"{"useTls":true,"tunneled":true}"#] {
            match tls_option(Some(extra)) {
                Some(Tls::Enabled(o)) => assert_eq!(o.allow_invalid_certificates, Some(true)),
                other => panic!("unexpected tls option: {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_db_prefers_request_param_then_auth_db() {
        let conn = conn_row(None);
        assert_eq!(resolve_db(&conn, Some("sales")), "sales");
        assert_eq!(resolve_db(&conn, Some("")), "admin");
        assert_eq!(resolve_db(&conn, None), "admin");
        let bare = DbConnectionRow { default_database: None, ..conn_row(None) };
        assert_eq!(resolve_db(&bare, None), "admin");
    }
}
