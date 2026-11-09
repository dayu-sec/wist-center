//! 证据读口（`[evidence]`）：按 `command_id` 取调查报告的元数据与正文。
//!
//! ## 走 BFF，不直连证据服务
//!
//! 证据服务的读监听（`/internal/evidence/*`）**故意只在计算区 compose 网络内**，
//! 对外面是 `wist-field-api`（BFF）：浏览器 / 其它组件都只跟它说话。中心也一样：
//!
//! ```text
//! GET {endpoint}/api/evidence/{cmd_id}           → 元数据（Artifact 原样透传）
//! GET {endpoint}/api/evidence/{cmd_id}/content   → 正文
//! ```
//!
//! `{endpoint}` = 计算区对外入口（field 栈的 web，HTTPS）。鉴权是 **wist-cred 操作员令牌**
//! （`Authorization: Bearer wcr_…`），来自栈的 `.wist/sec-value.yml` → `${SEC_EVIDENCE_READ_TOKEN}`，
//! 不落日志、不进 URL。
//!
//! BFF 的响应是**原样透传**：状态码与正文都不改写，所以这里仍按证据服务的形状解析；
//! 404 依旧是「不可见 / 不存在」，401/403 是「令牌不对或没权限」——两者页面处置不同。

use std::time::Duration;

use crate::config::EvidenceConfig;

/// 读证据的错误：**分清楚**「没有这份报告」「令牌不对」与「服务不可用」。
///
/// 页面上这三件事的处置完全不同：等同步 / 换凭据 / 查服务。
#[derive(Debug)]
pub enum EvidenceReadError {
    /// 不可见 / 不存在（BFF 对不可见统一透传 404，不泄露存在性）。
    NotFound,
    /// 401 / 403：令牌错、过期或没有该租户/角色。
    Unauthorized(String),
    /// 未配置 / 连不上 / 5xx —— 说清楚是哪一种。
    Unavailable(String),
}

/// 证据元数据（证据库 `Artifact` 的一个裁剪投影；BFF 原样透传）。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EvidenceArtifact {
    pub artifact_id: String,
    pub kind: String,
    #[serde(default)]
    pub verdict: Option<String>,
    pub size_bytes: i64,
    pub sensitivity: String,
    /// RFC3339；中心据此算「还能看几天」。
    pub retention_until: String,
    #[serde(default)]
    pub command_id: Option<String>,
}

/// BFF 读客户端。
#[derive(Debug, Clone)]
pub struct EvidenceClient {
    endpoint: String,
    token: String,
    http: reqwest::Client,
}

impl EvidenceClient {
    pub fn new(config: &EvidenceConfig) -> Result<Self, EvidenceReadError> {
        Ok(Self {
            endpoint: config.endpoint.trim_end_matches('/').to_string(),
            token: config.read_token.clone(),
            http: build_http(config)?,
        })
    }

    /// 元数据。`verbose` 是给日志的：错误里带上状态码与响应体。
    pub async fn metadata(&self, command_id: &str) -> Result<EvidenceArtifact, EvidenceReadError> {
        let url = format!("{}/api/evidence/{}", self.endpoint, encode(command_id));
        let response = self
            .authorized(self.http.get(url))
            .send()
            .await
            .map_err(|err| {
                EvidenceReadError::Unavailable(format!("evidence request failed: {err}"))
            })?;
        let status = response.status();
        if status.as_u16() == 404 {
            return Err(EvidenceReadError::NotFound);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(classify(status.as_u16(), &body));
        }
        response
            .json::<EvidenceArtifact>()
            .await
            .map_err(|err| EvidenceReadError::Unavailable(format!("evidence decode failed: {err}")))
    }

    /// 正文（原样文本）。中心边读边转，不落盘。
    pub async fn content(&self, command_id: &str) -> Result<String, EvidenceReadError> {
        let url = format!(
            "{}/api/evidence/{}/content",
            self.endpoint,
            encode(command_id)
        );
        let response = self
            .authorized(self.http.get(url))
            .send()
            .await
            .map_err(|err| {
                EvidenceReadError::Unavailable(format!("evidence request failed: {err}"))
            })?;
        let status = response.status();
        if status.as_u16() == 404 {
            return Err(EvidenceReadError::NotFound);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(classify(status.as_u16(), &body));
        }
        response
            .text()
            .await
            .map_err(|err| EvidenceReadError::Unavailable(format!("evidence body failed: {err}")))
    }

    fn authorized(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .bearer_auth(&self.token)
            .header("accept", "application/json")
    }
}

/// 非 2xx 归类：4xx 是「凭据 / 权限」，5xx 是「服务本身」。
fn classify(status: u16, body: &str) -> EvidenceReadError {
    if (400..500).contains(&status) {
        EvidenceReadError::Unauthorized(format!("evidence returned {status}: {body}"))
    } else {
        EvidenceReadError::Unavailable(format!("evidence returned {status}: {body}"))
    }
}

/// 构造 HTTP 客户端；`ca_file` 用于计算区自签站点（信任锚只加不替换系统根）。
fn build_http(config: &EvidenceConfig) -> Result<reqwest::Client, EvidenceReadError> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds))
        .connect_timeout(Duration::from_secs(3));
    if let Some(path) = config.ca_file.as_ref() {
        let pem = std::fs::read(path).map_err(|err| {
            EvidenceReadError::Unavailable(format!(
                "读取证据服务信任锚失败 {}: {err}",
                path.display()
            ))
        })?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|err| {
            EvidenceReadError::Unavailable(format!(
                "解析证据服务信任锚失败 {}: {err}",
                path.display()
            ))
        })?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|err| EvidenceReadError::Unavailable(format!("http client init failed: {err}")))
}

/// `command_id` 只允许 `[A-Za-z0-9_.:-]`：它会被拼进 URL 路径。
///
/// 不合法就替换成 `_`——不把控制字符 / 分隔符交给 reqwest 拼路径。
fn encode(command_id: &str) -> String {
    command_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn one_shot(
        status: &'static str,
        body: &'static str,
    ) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0_u8; 8192];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buffer[..read]).to_string());
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });
        (format!("http://{addr}"), rx)
    }

    fn config(endpoint: String) -> EvidenceConfig {
        EvidenceConfig {
            endpoint,
            read_token: "wcr_test".to_string(),
            timeout_seconds: 5,
            ca_file: None,
        }
    }

    #[tokio::test]
    async fn metadata_goes_through_the_bff_with_a_bearer_token() {
        let body = r#"{"artifact_id":"art_1","kind":"investigation_report","verdict":"warn","size_bytes":42,"sensitivity":"paths","retention_until":"2026-11-16T00:00:00Z","command_id":"cmd_1"}"#;
        let (endpoint, captured) = one_shot("200 OK", body).await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        let artifact = client.metadata("cmd_1").await.expect("metadata");
        assert_eq!(artifact.verdict.as_deref(), Some("warn"));
        assert_eq!(artifact.size_bytes, 42);

        let request = captured.await.expect("request");
        // 走 BFF 的对外面，不碰证据服务的 `/internal/*`。
        assert!(request.starts_with("GET /api/evidence/cmd_1 "), "{request}");
        assert!(
            request
                .to_lowercase()
                .contains("authorization: bearer wcr_test"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn content_goes_through_the_bff() {
        let (endpoint, captured) = one_shot("200 OK", r#"{"a":1}"#).await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        let body = client.content("cmd_1").await.expect("content");
        assert_eq!(body, r#"{"a":1}"#);
        let request = captured.await.expect("request");
        assert!(
            request.starts_with("GET /api/evidence/cmd_1/content "),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_404_is_not_an_outage() {
        let (endpoint, _captured) = one_shot("404 Not Found", "{}").await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        assert!(matches!(
            client.metadata("cmd_1").await,
            Err(EvidenceReadError::NotFound)
        ));
    }

    /// 401/403 是「令牌不对或没权限」，不是「报告没有」也不是「服务挂了」。
    #[tokio::test]
    async fn a_401_is_reported_as_unauthorized() {
        let (endpoint, _captured) = one_shot("401 Unauthorized", r#"{"error":"bad token"}"#).await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        match client.metadata("cmd_1").await {
            Err(EvidenceReadError::Unauthorized(message)) => {
                assert!(message.contains("401"), "{message}")
            }
            other => panic!("401 必须归类成 Unauthorized：{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_500_is_an_outage_with_the_body() {
        let (endpoint, _captured) = one_shot("500 Internal Server Error", "boom").await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        match client.content("cmd_1").await {
            Err(EvidenceReadError::Unavailable(message)) => {
                assert!(message.contains("500"), "{message}")
            }
            other => panic!("5xx 必须归类成 Unavailable：{other:?}"),
        }
    }

    #[test]
    fn command_ids_are_path_safe() {
        assert_eq!(encode("cmd_abc:1-2.3"), "cmd_abc:1-2.3");
        assert_eq!(encode("cmd/../x"), "cmd_.._x");
    }
}
