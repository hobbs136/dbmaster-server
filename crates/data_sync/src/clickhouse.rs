//! ClickHouse HTTP 客户端（8123 端口）— data_sync 三期目标库写入引擎。
//!
//! 协议：HTTP POST `/?query=INSERT+INTO+{db}.{table}+FORMAT+JSONEachRow`，
//! body = 每行一个 JSON 对象（`{"col":val,...}\n`）。CH 官方推荐的大批量
//! 写入方式，简单稳定。
//!
//! 认证：HTTP Basic（user:password）。密码来自 database_connections.password_encrypted
//! 解密后的明文（runner 已统一解密）。
//!
//! 安全：表名/库名经 config.validate 标识符白名单校验后才到达这里（防注入）。
//! 失败时错误消息含 "connect" 字样 → redact_error 走笼统分支，不泄露 host/SQL/响应体。

use anyhow::{anyhow, Result};

/// ClickHouse HTTP 写入客户端。无状态（每次请求新建连接，reqwest 内部池化）。
pub struct ClickHouseClient {
    http: reqwest::Client,
    base_url: String,
    auth_header: String,
    database: String,
}

impl ClickHouseClient {
    /// 构造客户端。`database` 是默认库（连接的 default_database）。
    pub fn new(host: &str, port: u16, username: &str, password: &str, database: &str) -> Self {
        // reqwest Client 复用连接池（keep-alive），适合多批次写入。
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        use base64::{engine::general_purpose, Engine};
        let auth_header = format!(
            "Basic {}",
            general_purpose::STANDARD.encode(format!("{username}:{password}"))
        );
        Self {
            http,
            base_url: format!("http://{host}:{port}"),
            auth_header,
            database: database.to_string(),
        }
    }

    /// 批量写入：POST INSERT ... FORMAT JSONEachRow。
    /// `rows` 是已转换好的 JSON 对象（列名→值）。返回写入行数。
    pub async fn insert_batch(
        &self,
        table: &str,
        rows: &[serde_json::Map<String, serde_json::Value>],
    ) -> Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        // SQL 走 query param（URL-encoded），body 传数据。表名已校验为安全标识符。
        let query = format!(
            "INSERT INTO {}.{table} FORMAT JSONEachRow",
            crate::sql::quote(&self.database, crate::sql::Dialect::ClickHouse)
        );
        let url = format!("{}/?query={}", self.base_url, url_encode(&query));

        // body：每行一个紧凑 JSON + 换行
        let mut body = String::with_capacity(rows.len() * 128);
        for row in rows {
            body.push_str(&serde_json::to_string(row).unwrap_or_else(|_| "{}".to_string()));
            body.push('\n');
        }

        let resp = self
            .http
            .post(&url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow!("clickhouse insert connect failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!(status = %status, body_len = text.len(), "clickhouse insert returned non-2xx");
            return Err(anyhow!("clickhouse insert connect failed"));
        }

        Ok(rows.len())
    }

    /// TRUNCATE TABLE（truncate 策略 + 全量同步时调用）。
    pub async fn truncate(&self, table: &str) -> Result<()> {
        let query = format!(
            "TRUNCATE TABLE {}.{table}",
            crate::sql::quote(&self.database, crate::sql::Dialect::ClickHouse)
        );
        let url = format!("{}/?query={}", self.base_url, url_encode(&query));
        // CH HTTP: GET 强制 readonly；无 body POST 返回 411。
        // TRUNCATE 是修改语句，必须 POST + 非零 body（一个空格）。
        let resp = self
            .http
            .post(&url)
            .header("Authorization", &self.auth_header)
            .body(" ")
            .send()
            .await
            .map_err(|e| anyhow!("clickhouse truncate connect failed: {e}"))?;
        if !resp.status().is_success() {
            tracing::warn!(status = %resp.status(), "clickhouse truncate returned non-2xx");
        }
        Ok(())
    }

    /// 执行任意查询并返回文本结果（e2e 测试用于 SELECT COUNT(*) 验证）。
    pub async fn query_text(&self, sql: &str) -> Result<String> {
        let url = format!("{}/?query={}", self.base_url, url_encode(sql));
        let resp = self
            .http
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await
            .map_err(|e| anyhow!("clickhouse query connect failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!("clickhouse query connect failed"));
        }
        resp.text().await.map_err(|e| anyhow!("clickhouse read body failed: {e}"))
    }
}

/// 简单的 URL query 值编码（空格→+，特殊字符转义）。
/// reqwest 的 query! 宏会对值编码，但这里我们直接拼 URL，手动编码更可控。
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_spaces_and_special() {
        assert_eq!(url_encode("INSERT INTO db.t FORMAT JSONEachRow"), "INSERT+INTO+db.t+FORMAT+JSONEachRow");
        assert_eq!(url_encode("a;b"), "a%3Bb");
        assert_eq!(url_encode("a-b_c.d~e"), "a-b_c.d~e");
    }
}
