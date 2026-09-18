//! Doris Stream Load 客户端（BE 8040 端口）— data_sync 高性能写入引擎。
//!
//! 协议：HTTP PUT 到 `/api/{db}/{table}/_load`，body = 每行一个 JSON 对象。
//! Doris 官方推荐的大批量导入方式，比走 MySQL 协议逐行 INSERT 快几十倍。
//!
//! 关键协议细节（Doris 3.0 实测）：
//! - 端口：**BE 8040**（不是 FE 8030；FE 的 mini_load 默认禁用且配置项已移除）
//! - 方法：PUT（不是 POST）
//! - 必需 header：`label`（每次导入唯一，幂等去重）、`Expect: 100-continue`
//! - 认证：HTTP Basic（user:password）
//! - body：JSON stream（每行一个紧凑 JSON 对象，不是 JSON 数组）
//! - 响应：JSON，`{"Status":"Success","NumberLoadedRows":N,...}`；失败 `Status:"Fail"`
//!
//! 安全：表名/库名经 config.validate 标识符白名单校验。失败错误含 "connect"
//! 字样 → redact_error 走笼统分支。

use anyhow::{anyhow, Result};

/// Doris Stream Load 写入客户端。无状态。
pub struct DorisStreamLoadClient {
    http: reqwest::Client,
    base_url: String,       // http://host:8040
    auth_header: String,    // Basic {base64(user:pass)}
    database: String,
    /// 自增计数器，保证 label 唯一（同 label 的重复导入会被 Doris 拒绝）。
    label_seq: std::sync::atomic::AtomicU64,
}

impl DorisStreamLoadClient {
    pub fn new(host: &str, port: u16, username: &str, password: &str, database: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300)) // Stream Load 大批量可能慢
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
            label_seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 批量写入：PUT /api/{db}/{table}/_load，body = JSON stream。
    pub async fn insert_batch(
        &self,
        table: &str,
        rows: &[serde_json::Map<String, serde_json::Value>],
    ) -> Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }

        // label 每次唯一（时间戳 + 自增序号），Doris 用它做幂等去重。
        let seq = self.label_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let label = format!("dbmaster_sync_{}_{}", chrono::Utc::now().timestamp_millis(), seq);
        let url = format!(
            "{}/api/{}/{}/_load",
            self.base_url,
            self.database,
            table
        );

        // body：每行一个紧凑 JSON 对象（Doris JSON stream 格式）
        let mut body = String::with_capacity(rows.len() * 128);
        for row in rows {
            body.push_str(&serde_json::to_string(row).unwrap_or_else(|_| "{}".to_string()));
            body.push('\n');
        }

        let resp = self
            .http
            .put(&url)
            .header("Authorization", &self.auth_header)
            .header("Expect", "100-continue")
            .header("label", &label)
            // Doris Stream Load 必须声明 format=json 才能解析 JSON body（默认 CSV）。
            .header("format", "json")
            // body 是 JSON stream（每行一个对象），需 read_json_by_line=true。
            .header("read_json_by_line", "true")
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow!("doris stream load connect failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();

            tracing::warn!(status = %status, body_len = text.len(), "doris stream load returned non-2xx");
            return Err(anyhow!("doris stream load connect failed"));
        }

        // 解析 Doris 响应 JSON，确认 Status: Success
        let resp_text = resp.text().await.map_err(|e| anyhow!("doris read response failed: {e}"))?;
        let resp_json: serde_json::Value = serde_json::from_str(&resp_text)
            .map_err(|_| anyhow!("doris stream load connect failed: non-JSON response"))?;
        let doris_status = resp_json.get("Status").and_then(|v| v.as_str()).unwrap_or("");
        if doris_status != "Success" {
            let msg = resp_json.get("Message").and_then(|v| v.as_str()).unwrap_or("unknown");

            tracing::warn!(doris_status = %doris_status, msg = %msg, "doris stream load failed");
            return Err(anyhow!("doris stream load connect failed"));
        }

        let loaded = resp_json
            .get("NumberLoadedRows")
            .and_then(|v| v.as_u64())
            .unwrap_or(rows.len() as u64);
        Ok(loaded as usize)
    }

    /// TRUNCATE TABLE（走 Doris FE 9030 MySQL 协议，不是 Stream Load）。
    /// 这里用 sqlx 连 9030 执行。注意：需要 FE 端口，不是 BE 8040。
    /// 简化：truncate 由 runner 通过 sqlx 单独处理（如果源是 Doris 时），
    /// 但 Doris 只做目标，且 truncate 用 MySQL 协议更直接。
    /// 这里提供 HTTP 方式（Doris FE 8030 的 query 端点，但 mini_load disabled），
    /// 所以实际 truncate 走 sqlx mysql pool 在 runner 侧处理。
    pub async fn truncate(&self, _table: &str) -> Result<()> {
        // Doris TRUNCATE 不能走 Stream Load（那是数据导入），也不能走 FE HTTP（mini_load disabled）。
        // runner 侧用 sqlx 连 9030 执行 TRUNCATE TABLE。这里留空，由 runner 处理。
        Ok(())
    }
}
