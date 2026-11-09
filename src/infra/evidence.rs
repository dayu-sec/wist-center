//! 证据库读口（`[evidence]`）：按 `command_id` 取调查报告的元数据与正文。
//!
//! 中心**只读**证据库：写入者是数据面（wparse sink），中心拿到报告是「下发的副作用」。
//! 因此这里没有上传 / 删除，只有两条 GET：
//!
//! ```text
//! GET {endpoint}/internal/evidence/{cmd_id}           → 元数据
//! GET {endpoint}/internal/evidence/{cmd_id}/content   → 正文
//! ```
//!
//! 鉴权：`x-evidence-service-token`（证据库配了 `[read] service_token` 时**必须**带），
//! 身份头 `x-evidence-tenant` / `x-evidence-scopes` / `x-evidence-max-sensitivity`。
//! token 来自栈的 `${SEC_EVIDENCE_READ_TOKEN}`（`.wist/sec-value.yml`），不落日志。

use std::time::Duration;

use crate::config::EvidenceConfig;

/// 读证据的错误：**分清楚**「没有这份报告」与「证据服务不可用」。
///
/// 页面上这两件事的处置完全不同：前者是「报告同步中」，后者要说「证据服务不可达」。
#[derive(Debug)]
pub enum EvidenceReadError {
    /// 不可见 / 不存在（证据库对所有不可见统一回 404，不泄露存在性）。
    NotFound,
    /// 未配置 / 连不上 / 5xx —— 说清楚是哪一种。
    Unavailable(String),
}

/// 证据元数据（证据库 `Artifact` 的一个裁剪投影）。
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

/// 证据库读客户端。
#[derive(Debug, Clone)]
pub struct EvidenceClient {
    endpoint: String,
    token: String,
    http: reqwest::Client,
}

impl EvidenceClient {
    pub fn new(config: &EvidenceConfig) -> Result<Self, EvidenceReadError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|err| {
                EvidenceReadError::Unavailable(format!("http client init failed: {err}"))
            })?;
        Ok(Self {
            endpoint: config.endpoint.trim_end_matches('/').to_string(),
            token: config.read_token.clone(),
            http,
        })
    }

    /// 元数据。`tenant` 是证据库的对象键第一段（业务客户 id）。
    pub async fn metadata(
        &self,
        command_id: &str,
        tenant: &str,
        max_sensitivity: &str,
    ) -> Result<EvidenceArtifact, EvidenceReadError> {
        let url = format!("{}/internal/evidence/{}", self.endpoint, encode(command_id));
        let response = self
            .authorized(self.http.get(url))
            .header("x-evidence-tenant", tenant)
            .header("x-evidence-scopes", "evidence:read")
            .header("x-evidence-max-sensitivity", max_sensitivity)
            .send()
            .await
            .map_err(|err| {
                EvidenceReadError::Unavailable(format!("evidence request failed: {err}"))
            })?;
        match response.status().as_u16() {
            200 => response.json::<EvidenceArtifact>().await.map_err(|err| {
                EvidenceReadError::Unavailable(format!("evidence decode failed: {err}"))
            }),
            404 => Err(EvidenceReadError::NotFound),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(EvidenceReadError::Unavailable(format!(
                    "evidence returned {status}: {body}"
                )))
            }
        }
    }

    /// 正文（原样字节）。中心边读边转，不落盘。
    pub async fn content(
        &self,
        command_id: &str,
        tenant: &str,
        max_sensitivity: &str,
    ) -> Result<String, EvidenceReadError> {
        let url = format!(
            "{}/internal/evidence/{}/content",
            self.endpoint,
            encode(command_id)
        );
        let response = self
            .authorized(self.http.get(url))
            .header("x-evidence-tenant", tenant)
            .header("x-evidence-scopes", "evidence:read")
            .header("x-evidence-max-sensitivity", max_sensitivity)
            .send()
            .await
            .map_err(|err| {
                EvidenceReadError::Unavailable(format!("evidence request failed: {err}"))
            })?;
        match response.status().as_u16() {
            200 => response.text().await.map_err(|err| {
                EvidenceReadError::Unavailable(format!("evidence body failed: {err}"))
            }),
            404 => Err(EvidenceReadError::NotFound),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(EvidenceReadError::Unavailable(format!(
                    "evidence returned {status}: {body}"
                )))
            }
        }
    }

    fn authorized(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .header("x-evidence-service-token", &self.token)
            .header("accept", "application/json")
    }
}

/// `command_id` 只允许 `[A-Za-z0-9_.:-]`：它会被拼进 URL 路径。
///
/// 不合法就当成「没有这份证据」——不把非法字符交给 reqwest 去拼路径。
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
            read_token: "read-secret".to_string(),
            timeout_seconds: 5,
            tenant: None,
            max_sensitivity: "identities".to_string(),
        }
    }

    #[tokio::test]
    async fn metadata_sends_the_service_token_and_tenant_headers() {
        let body = r#"{"artifact_id":"art_1","kind":"investigation_report","verdict":"warn","size_bytes":42,"sensitivity":"paths","retention_until":"2026-11-16T00:00:00Z","command_id":"cmd_1"}"#;
        let (endpoint, captured) = one_shot("200 OK", body).await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        let artifact = client
            .metadata("cmd_1", "cust-a", "paths")
            .await
            .expect("metadata");
        assert_eq!(artifact.verdict.as_deref(), Some("warn"));
        assert_eq!(artifact.size_bytes, 42);

        let request = captured.await.expect("request");
        assert!(
            request.starts_with("GET /internal/evidence/cmd_1 "),
            "{request}"
        );
        assert!(
            request.contains("x-evidence-service-token: read-secret"),
            "{request}"
        );
        assert!(request.contains("x-evidence-tenant: cust-a"), "{request}");
    }

    #[tokio::test]
    async fn a_404_is_not_an_outage() {
        let (endpoint, _captured) = one_shot("404 Not Found", "{}").await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        assert!(matches!(
            client.metadata("cmd_1", "cust-a", "paths").await,
            Err(EvidenceReadError::NotFound)
        ));
    }

    #[tokio::test]
    async fn a_500_is_an_outage_with_the_body() {
        let (endpoint, _captured) = one_shot("500 Internal Server Error", "boom").await;
        let client = EvidenceClient::new(&config(endpoint)).expect("client");
        let error = client
            .content("cmd_1", "cust-a", "paths")
            .await
            .expect_err("must fail");
        match error {
            EvidenceReadError::Unavailable(message) => {
                assert!(message.contains("500"), "{message}")
            }
            EvidenceReadError::NotFound => panic!("5xx 不是“没有这份报告”"),
        }
    }

    #[test]
    fn command_ids_are_path_safe() {
        assert_eq!(encode("cmd_abc:1-2.3"), "cmd_abc:1-2.3");
        assert_eq!(encode("cmd/../x"), "cmd_.._x");
    }
}
