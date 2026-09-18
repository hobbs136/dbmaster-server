//! 网关连接的网络层开关（SSH 隧道 + TLS 透传批次，2026-08-29）。
//!
//! extra JSON 两类非凭据开关的统一解析处：
//! - `useTls` / `tlsInsecure`：客户端 TLS 透传意图（redis TcpTls / mongo
//!   TlsOptions / tdengine https）。非凭据，可过 `sanitize_extra`。
//! - `tunneled`：**server 侧注入**的运行时标记——`load_connection` / 草稿
//!   测试把行 host/port 改写为本地转发端口时写入，各腿读它判定「走了
//!   隧道」，组合 TLS 时强制 insecure（本地端口上做证书域名校验必败）。
//!
//! 解析容错：extra 非 JSON / 键缺失 / 类型不符一律回落缺省（false）——
//! 与 mongo `parse_extra` 同一宽松取向。

/// 解析 extra 的 TLS 开关：`(use_tls, insecure)`。
pub(crate) fn tls_flags(extra: Option<&str>) -> (bool, bool) {
    let use_tls = flag(extra, "useTls", false);
    let insecure = use_tls && flag(extra, "tlsInsecure", false);
    (use_tls, insecure)
}

/// 行是否经 SSH 隧道改写（server 侧注入的 `tunneled` 标记）。
pub(crate) fn tunneled(extra: Option<&str>) -> bool {
    flag(extra, "tunneled", false)
}

/// extra JSON 单布尔键读取（缺失/类型不符/extra 非 JSON → 缺省值）。
fn flag(extra: Option<&str>, key: &str, default: bool) -> bool {
    let Some(raw) = extra else { return default };
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(raw)
    else {
        return default;
    };
    map.get(key).and_then(serde_json::Value::as_bool).unwrap_or(default)
}

/// 向 extra JSON 注入布尔标记（原值非对象/None → 新对象）。返回新 JSON 串。
/// 隧道收口用它写 `tunneled:true`（各行原 extra 语义保留）。
pub(crate) fn inject_flag(extra: Option<&str>, key: &str, value: bool) -> Option<String> {
    let mut map = match extra {
        Some(raw) => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        },
        None => serde_json::Map::new(),
    };
    map.insert(key.to_string(), serde_json::Value::Bool(value));
    Some(serde_json::Value::Object(map).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_flags_parses_and_defaults() {
        // 显式组合。
        assert_eq!(tls_flags(Some(r#"{"useTls":true}"#)), (true, false));
        assert_eq!(tls_flags(Some(r#"{"useTls":true,"tlsInsecure":true}"#)), (true, true));
        assert_eq!(tls_flags(Some(r#"{"useTls":false,"tlsInsecure":true}"#)), (false, false));
        assert_eq!(tls_flags(Some(r#"{"other":1}"#)), (false, false));
        // 容错：None / 非 JSON / 类型不符 / 键缺失。
        assert_eq!(tls_flags(None), (false, false));
        assert_eq!(tls_flags(Some("not json")), (false, false));
        assert_eq!(tls_flags(Some(r#"{"useTls":"yes"}"#)), (false, false));
    }

    #[test]
    fn tunneled_reads_injected_marker() {
        assert!(!tunneled(None));
        assert!(!tunneled(Some(r#"{"useTls":true}"#)));
        assert!(tunneled(Some(r#"{"tunneled":true}"#)));
    }

    #[test]
    fn inject_flag_preserves_and_creates() {
        assert_eq!(
            inject_flag(Some(r#"{"useTls":true}"#), "tunneled", true).as_deref(),
            Some(r#"{"useTls":true,"tunneled":true}"#)
        );
        assert_eq!(inject_flag(None, "tunneled", true).as_deref(), Some(r#"{"tunneled":true}"#));
        // 原 extra 非 JSON → 丢弃重建（与各腿的宽松解析一致）。
        assert_eq!(inject_flag(Some("bad"), "tunneled", true).as_deref(), Some(r#"{"tunneled":true}"#));
    }
}
