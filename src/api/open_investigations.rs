//! 第三方（开放面）下发调查：`POST /api/v1/open/investigations` + 任务状态查询。
//!
//! ## 契约形状（刻意只有一个）
//!
//! 寻址只有一种：`customer_id + host_ip`，三个业务字段全部必填。
//! 没有 `target` 包装、没有二选一、没有题面参数 —— 能通过 schema 的报文就是能执行的报文。
//! 按 `agent_id` 下发是内部动作，走管理面路径参数
//! （`POST /api/v1/admin/gateways/{gw}/agents/{agent}/investigations`）。
//!
//! ## 结果在哪
//!
//! 中心只负责**下发**与**任务状态**；报告正文按 `command_id` 落在 `wist-field` 的证据库里
//! （数据面 `IVSREP → wparse → evidence`）。响应里的 `evidence.cmd_id` 就是去 field 查报告的键，
//! 中心不转存、也不代理正文。
//!
//! ## 幂等
//!
//! 外部系统重试是常态：`Idempotency-Key` 必填，同一个 key 的同参数重试返回**原 `command_id`**，
//! 不会在网关队列里多出一行。

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use wist_control::types::DateTime;

use super::{
    ApiState, PeerConnectInfo,
    agent_investigations::task_state,
    codes,
    commands::{
        INVESTIGATE_MIN_GWLINKD, create_and_dispatch_idempotent, gwlinkd_supports_investigate,
        idempotency_key,
    },
    error::ApiError,
    extract::ApiJson,
    open_auth::require_investigation_credential,
    open_lookup::{known_topics, resolve_launch_agent},
    rate_limit,
};

/// 指令种类（与管理面 / 网关同一字符串）。
const INVESTIGATE_KIND: &str = "gateway.agent-investigate";
/// `external_ref` 的上限：它只进中心审计 / 回显，不随 wire 下发。
const MAX_EXTERNAL_REF_CHARS: usize = 200;

// ── 请求 / 响应 ──────────────────────────────────────────────────────────

/// 第三方发起一次调查。
///
/// 三个业务字段全部必填，另有一个可选的工单号：
///
/// - `customer_id`：客户 id，与网关绑定一致（租户隔离，不能省）；
/// - `host_ip`：agent 上报的地址之一；
/// - `topic`：题面闭集（见 `GET /api/v1/open/capabilities`）；
/// - `external_ref`：调用方自己的工单号，纯审计，不随 wire 下发。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenLaunchInvestigationRequest {
    pub customer_id: String,
    pub host_ip: String,
    pub topic: String,
    #[serde(default)]
    pub external_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvidencePointer {
    service: &'static str,
    cmd_id: String,
}

#[derive(Debug, Serialize)]
struct TaskView {
    state: &'static str,
    requested_at: DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_at: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acked_at: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct DispatchView {
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_error: Option<String>,
}

// ── 处理器 ───────────────────────────────────────────────────────────────

/// `POST /api/v1/open/investigations`
pub async fn open_launch_investigation(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    ApiJson(request): ApiJson<OpenLaunchInvestigationRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    let credential = match require_investigation_credential(&state, &headers, &client_key) {
        Ok(credential) => credential,
        Err(response) => return response,
    };
    let Some(request_id) = idempotency_key(&headers) else {
        return ApiError::bad_request(
            codes::IDEMPOTENCY_KEY_REQUIRED,
            "Idempotency-Key header is required",
        )
        .into_response();
    };
    // 幂等键按调用方命名空间：两个第三方都用 `case-1` 时不能互相命中（否则会拿到别人的 command_id）。
    let request_id = scoped_request_id(&credential.subject, &request_id);

    let topic = request.topic.trim();
    if !super::open_lookup::is_known_topic(topic) {
        return ApiError::bad_request(
            codes::COMMAND_PAYLOAD_INVALID,
            format!(
                "unknown investigation topic {topic:?} (known: {})",
                known_topics().join(", ")
            ),
        )
        .into_response();
    }
    let external_ref = request
        .external_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(value) = external_ref
        && value.chars().count() > MAX_EXTERNAL_REF_CHARS
    {
        return ApiError::bad_request(
            codes::COMMAND_PAYLOAD_INVALID,
            format!("external_ref exceeds {MAX_EXTERNAL_REF_CHARS} characters"),
        )
        .into_response();
    }

    // 寻址只有一种：`customer_id + host_ip`；客户绑定、IP 匹配与唯一性在 resolver 里判。
    let agent =
        match resolve_launch_agent(&state, &credential, &request.customer_id, &request.host_ip)
            .await
        {
            Ok(agent) => agent,
            Err(response) => return response,
        };
    let agent_id = agent.agent_id.as_str();
    let gateway_id = agent.gateway_id.clone();

    // 旧 gwlinkd 不认识 `investigate-agent`：能提前判定就提前拒。
    if let Ok(Some(gateway)) = state.store.get_gateway(&gateway_id).await
        && gwlinkd_supports_investigate(gateway.gwlinkd_version.as_deref()) == Some(false)
    {
        return ApiError::conflict(
            codes::AGENT_INVESTIGATE_UNSUPPORTED,
            format!(
                "gwlinkd {} 不支持下发调查（需要 >= {}）",
                gateway.gwlinkd_version.as_deref().unwrap_or("?"),
                INVESTIGATE_MIN_GWLINKD
            ),
        )
        .into_response();
    }

    // payload 只留「查什么」：`external_ref` 是中心侧对账字段，`wire_for` 不会把它带进网关 wire。
    let mut payload = Map::new();
    payload.insert("agent_id".to_string(), Value::String(agent_id.to_string()));
    payload.insert("topic".to_string(), Value::String(topic.to_string()));
    if let Some(value) = external_ref {
        payload.insert("external_ref".to_string(), Value::String(value.to_string()));
    }

    match create_and_dispatch_idempotent(
        &state,
        &request_id,
        INVESTIGATE_KIND,
        vec![gateway_id.clone()],
        Value::Object(payload),
        None,
        Some(credential.subject.clone()),
    )
    .await
    {
        Ok(command) => {
            log::info!(
                "event=OpenInvestigationDispatched subject={} agent_id={} gateway_id={} command_id={} topic={}",
                credential.subject,
                agent_id,
                gateway_id,
                command.command_id,
                topic
            );
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "command_id": command.command_id,
                    "agent_id": agent_id,
                    "gateway_id": gateway_id,
                    "topic": topic,
                    "external_ref": external_ref,
                    "state": command.state,
                    "target": { "type": "gateway", "ids": [gateway_id] },
                    "evidence": evidence_pointer(&command.command_id),
                })),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

/// `GET /api/v1/open/investigations/{command_id}`
///
/// 任务状态来自随 `AgentRuntimeStatus` 上来的 `investigations`（≤60s 新鲜度）；
/// 下发回执来自中心自己的 `target_commands`。报告正文请按 `evidence.cmd_id` 去 `wist-field` 取。
pub async fn open_show_investigation(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(command_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    let credential = match require_investigation_credential(&state, &headers, &client_key) {
        Ok(credential) => credential,
        Err(response) => return response,
    };

    let command = match state.store.get_command(&command_id).await {
        Ok(Some(command)) => command,
        Ok(None) => {
            return ApiError::not_found(
                codes::COMMAND_NOT_FOUND,
                format!("command `{command_id}` not found"),
            )
            .into_response();
        }
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::COMMAND_STORE_UNAVAILABLE,
                "failed to load command",
                err.display_chain(),
            )
            .into_response();
        }
    };
    let Some(agent_id) = command
        .payload
        .get("agent_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        // 不是本入口创建的命令（或形状不认识）：不对第三方暴露。
        return ApiError::not_found(
            codes::COMMAND_NOT_FOUND,
            format!("command `{command_id}` not found"),
        )
        .into_response();
    };
    if command.kind != INVESTIGATE_KIND {
        return ApiError::not_found(
            codes::COMMAND_NOT_FOUND,
            format!("command `{command_id}` not found"),
        )
        .into_response();
    }
    let gateway_id = command
        .target_ids
        .first()
        .cloned()
        .unwrap_or_else(|| "?".to_string());
    if !super::open_auth::allows_agent(&credential, agent_id, &gateway_id) {
        // 不区分「不存在」与「无权看」：与证据服务的口径一致。
        return ApiError::not_found(
            codes::COMMAND_NOT_FOUND,
            format!("command `{command_id}` not found"),
        )
        .into_response();
    }

    let task = match state.store.list_agents_by_gateway(&gateway_id).await {
        Ok(agents) => agents
            .into_iter()
            .find(|agent| agent.agent_id == agent_id)
            .and_then(|agent| {
                agent
                    .investigations
                    .into_iter()
                    .find(|task| task.command_id == command.command_id)
            })
            .map(|task| {
                let state = task_state(&task);
                TaskView {
                    state,
                    requested_at: task.requested_at,
                    claimed_at: task.claimed_at,
                    acked_at: task.acked_at,
                    outcome: task.outcome,
                    detail: task.detail,
                }
            }),
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::AGENT_STATUS_LOAD_FAILED,
                "failed to load agent status",
                err.display_chain(),
            )
            .into_response();
        }
    };
    let target = match state.store.list_target_commands(&command.command_id).await {
        Ok(targets) => targets
            .into_iter()
            .find(|target| target.target_id == gateway_id)
            .map(|target| DispatchView {
                state: target.state,
                result_status: target.result_status,
                result_error: target.result_error,
            }),
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::COMMAND_STORE_UNAVAILABLE,
                "failed to load target command",
                err.display_chain(),
            )
            .into_response();
        }
    };

    Json(json!({
        "command_id": command.command_id,
        "agent_id": agent_id,
        "gateway_id": gateway_id,
        "topic": command.payload.get("topic").cloned().unwrap_or(Value::Null),
        "external_ref": command.payload.get("external_ref").cloned().unwrap_or(Value::Null),
        "state": command.state,
        "requested_at": command.created_at,
        "dispatched_at": command.dispatched_at,
        "target": target,
        "task": task,
        "evidence": evidence_pointer(&command.command_id),
    }))
    .into_response()
}

// ── 内部 ─────────────────────────────────────────────────────────────────

/// 幂等键的调用方命名空间。
///
/// `request_id` 在中心是全局唯一键；多个第三方都用 `case-1` 这类常见值时不加命名空间就会
/// 互相命中（一个调用方会拿到另一个调用方的 `command_id` 与目标信息）。
/// 用 subject 的短摘要而不是原值：subject 可能很长，而键只用于去重与审计。
fn scoped_request_id(subject: &str, key: &str) -> String {
    let digest = crate::infra::sha256_hex(subject);
    format!("open:{}:{key}", &digest[..16])
}

/// 报告在 `wist-field` 的定位：第三方拿 `cmd_id` 去 field 的证据接口取正文。
fn evidence_pointer(command_id: &str) -> EvidencePointer {
    EvidencePointer {
        service: "wist-field",
        cmd_id: command_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use wist_cred_peer::{Config as PeerConfig, Peer};

    use crate::config::{
        CenterConfig, CredentialsConfig, GatewayCredentialSeed, WparseProxyConfig,
    };
    use crate::credentials::CredentialVerifier;
    use crate::infra::{FileStore, LocalArtifactStore, Store, StoredAgent};
    use wist_control::types::DateTime;

    use super::super::{ApiState, router_for};
    use super::scoped_request_id;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wic-open-{tag}-{}-{seq}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    /// 造一个带 `investigation:run` 凭据的验证器：直接写摘要表文件，
    /// `Peer::open` 启动时加载（只存 sha256，不依赖 cred 推送）。
    fn verifier_with(token: &str, agents: &[&str]) -> CredentialVerifier {
        let store_path = temp_path("credentials");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs() as i64;
        let entry = json!({
            "revision": 1,
            "credentials": [{
                "credential_id": "cred_open_1",
                "digest": format!("sha256:{}", crate::infra::sha256_hex(token)),
                "subject": "svc-siem",
                "roles": ["investigation:run"],
                "resources": { "agents": agents },
                "audience": "wist-center",
                "issued_at": now,
                "expires_at": now + 3600,
                "revision": 1
            }]
        });
        std::fs::write(&store_path, entry.to_string()).expect("write credential store");
        let peer = Peer::open(PeerConfig::new("wist-center", store_path).known_roles([
            "investigation:run",
            "admin",
            "read",
        ]))
        .expect("open peer");
        CredentialVerifier::new(peer)
    }

    fn test_state(verifier: CredentialVerifier) -> ApiState {
        let path = temp_path("store");
        let store = FileStore::new(&path);
        store
            .seed(&[GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "tok-a".to_string(),
                expires_at: None,
            }])
            .expect("seed");
        let store: std::sync::Arc<dyn Store> = std::sync::Arc::new(store);
        let artifact_store: std::sync::Arc<dyn crate::infra::ArtifactStore> =
            std::sync::Arc::new(LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            ));
        ApiState {
            config: CenterConfig {
                evidence: None,
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                open_addr: None,
                open_public_url: None,
                store_path: path,
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: None,
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                gateway_project_repo: "https://example.test/gateway.git".to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                package_sources: Vec::new(),
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
                wparse_proxy: WparseProxyConfig {
                    enabled: false,
                    listen_addr: "0.0.0.0:3101".to_string(),
                },
                wparse_release: Default::default(),
                log: Default::default(),
                credentials: CredentialsConfig::default(),
            },
            store: store.clone(),
            artifact_store,
            gateway_ca: std::sync::Arc::new(
                crate::infra::gateway_ca::GatewayCa::generate("Wist Test Gateway CA")
                    .expect("gateway ca")
                    .0,
            ),
            proxy: None,
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
            jobs: crate::infra::release_job_queue(
                store,
                std::sync::Arc::new(LocalArtifactStore::new(
                    std::env::temp_dir().join("wic-artifacts"),
                    "http://127.0.0.1:3100",
                )),
            ),
            credentials: Some(verifier),
        }
    }

    /// 一台绑定到 `cust-a`、上报了 `192.168.1.5` 的 Agent。
    async fn seed_agent(state: &ApiState) {
        seed_agent_with(state, None).await;
    }

    async fn seed_agent_with(
        state: &ApiState,
        data_manifest: Option<wist_control::AgentDataManifest>,
    ) {
        state
            .store
            .bind_gateway_customer("gw-001", "cust-a", "admin")
            .await
            .expect("bind customer");
        state
            .store
            .upsert_agent_status(
                "gw-001",
                &[StoredAgent {
                    investigations: Vec::new(),
                    agent_id: "agent-1".to_string(),
                    gateway_id: "gw-001".to_string(),
                    instance_id: "inst-1".to_string(),
                    version: "0.31.0".to_string(),
                    status: "online".to_string(),
                    health: "healthy".to_string(),
                    memory_bytes: None,
                    cpu_percent: None,
                    admin_latency_ms: None,
                    last_seen_at: DateTime::now(),
                    node_id: None,
                    hostname: Some("host-1".to_string()),
                    ip_addresses: Some(vec!["en0 192.168.1.5/24".to_string()]),
                    data_manifest,
                }],
            )
            .await
            .expect("seed agent");
    }

    async fn send(
        state: &ApiState,
        token: Option<&str>,
        idempotency_key: Option<&str>,
        method: &str,
        uri: &str,
        body: &str,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(key) = idempotency_key {
            request = request.header("idempotency-key", key);
        }
        let response = router_for(state.clone())
            .oneshot(request.body(Body::from(body.to_string())).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    const BASE: &str = "/api/v1/open/investigations";

    fn launch_body() -> String {
        json!({
            "customer_id": "cust-a",
            "host_ip": "192.168.1.5",
            "topic": "disk"
        })
        .to_string()
    }

    /// 两个调用方用同一个 `Idempotency-Key` 不能互相命中。
    #[test]
    fn idempotency_keys_are_namespaced_per_caller() {
        assert_ne!(
            scoped_request_id("svc-a", "case-1"),
            scoped_request_id("svc-b", "case-1")
        );
        assert_eq!(
            scoped_request_id("svc-a", "case-1"),
            scoped_request_id("svc-a", "case-1")
        );
        assert!(scoped_request_id("svc-a", "case-1").ends_with(":case-1"));
    }

    #[tokio::test]
    async fn missing_token_and_wrong_role_are_rejected() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        let (status, body) = send(&state, None, Some("k1"), "POST", BASE, &launch_body()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "missing_open_bearer_token");

        let (status, body) = send(
            &state,
            Some("wcr_wrong"),
            Some("k1"),
            "POST",
            BASE,
            &launch_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "invalid_open_bearer_token");
    }

    /// 开放面是公网入口：无效令牌必须计入失败桶，连续尝试会被封（429）。
    #[tokio::test]
    async fn repeated_invalid_tokens_are_rate_limited() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        for _ in 0..5 {
            let (status, _) = send(
                &state,
                Some("wcr_not_registered"),
                Some("k"),
                "POST",
                BASE,
                &launch_body(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, body) = send(
            &state,
            Some("wcr_not_registered"),
            Some("k"),
            "POST",
            BASE,
            &launch_body(),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn tokens_without_the_investigation_role_get_403() {
        let store_path = temp_path("credentials-read-only");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs() as i64;
        std::fs::write(
            &store_path,
            json!({
                "revision": 1,
                "credentials": [{
                    "credential_id": "cred_read",
                    "digest": format!("sha256:{}", crate::infra::sha256_hex("wcr_read")),
                    "subject": "svc-reader",
                    "roles": ["read"],
                    "resources": { "agents": ["agent-1"] },
                    "audience": "wist-center",
                    "issued_at": now,
                    "expires_at": now + 3600,
                    "revision": 1
                }]
            })
            .to_string(),
        )
        .expect("write store");
        let peer = Peer::open(
            PeerConfig::new("wist-center", store_path).known_roles(["investigation:run", "read"]),
        )
        .expect("peer");
        let state = test_state(CredentialVerifier::new(peer));
        let (status, body) = send(
            &state,
            Some("wcr_read"),
            Some("k1"),
            "POST",
            BASE,
            &launch_body(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "investigation_role_required");
    }

    #[tokio::test]
    async fn idempotency_key_is_required() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        seed_agent(&state).await;
        let (status, body) =
            send(&state, Some("wcr_open"), None, "POST", BASE, &launch_body()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "idempotency_key_required");
    }

    #[tokio::test]
    async fn agents_outside_the_credential_scope_are_denied() {
        let state = test_state(verifier_with("wcr_open", &["agent-2"]));
        seed_agent(&state).await;
        let (status, body) = send(
            &state,
            Some("wcr_open"),
            Some("k1"),
            "POST",
            BASE,
            &launch_body(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "investigation_scope_denied");
    }

    #[tokio::test]
    async fn unknown_topics_and_unknown_ips_are_rejected() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        seed_agent(&state).await;

        let (status, body) = send(
            &state,
            Some("wcr_open"),
            Some("k1"),
            "POST",
            BASE,
            &json!({"customer_id": "cust-a", "host_ip": "192.168.1.5", "topic": "memory"})
                .to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "command_payload_invalid");

        let (status, body) = send(
            &state,
            Some("wcr_open"),
            Some("k2"),
            "POST",
            BASE,
            &json!({"customer_id": "cust-a", "host_ip": "10.0.0.9", "topic": "disk"}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "agent_not_found");
    }

    #[tokio::test]
    async fn path_is_still_not_accepted_on_the_open_face() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        seed_agent(&state).await;
        let (status, body) = send(
            &state,
            Some("wcr_open"),
            Some("k1"),
            "POST",
            BASE,
            &json!({
                "customer_id": "cust-a",
                "host_ip": "192.168.1.5",
                "topic": "disk",
                "path": "/var/log"
            })
            .to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }

    /// 缺少必填字段是**形状错误**（422），不是「少带一个可选字段」。
    #[tokio::test]
    async fn missing_required_fields_are_shape_errors() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        seed_agent(&state).await;
        for payload in [
            json!({}),
            json!({"customer_id": "cust-a"}),
            json!({"customer_id": "cust-a", "host_ip": "192.168.1.5"}),
        ] {
            let (status, _body) = send(
                &state,
                Some("wcr_open"),
                Some("shape"),
                "POST",
                BASE,
                &payload.to_string(),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    /// 授权全部通过后走到下发：测试环境没有命令队列（需要 PostgreSQL），
    /// 应明确回 503，而不是“看起来成功了”。
    #[tokio::test]
    async fn a_valid_request_reaches_the_queue_and_reports_it_disabled() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        seed_agent(&state).await;
        let (status, body) = send(
            &state,
            Some("wcr_open"),
            Some("case-1"),
            "POST",
            BASE,
            &json!({
                "customer_id": "cust-a",
                "host_ip": "192.168.1.5",
                "topic": "disk",
                "external_ref": "case-1"
            })
            .to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error"]["code"], "command_store_unavailable");
    }

    /// 状态读口把「下发回执」和「网关上来的任务状态」拼在一起，
    /// 并明确告诉调用方正文去 `wist-field` 按 `cmd_id` 取。
    #[tokio::test]
    async fn status_returns_the_task_and_the_field_pointer() {
        use crate::infra::{COMMAND_STATE_QUEUED, CommandRecord};

        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        let now = DateTime::now();
        state
            .store
            .upsert_agent_status(
                "gw-001",
                &[StoredAgent {
                    investigations: vec![wist_control::AgentInvestigationTask {
                        command_id: "cmd_open_1".to_string(),
                        topic: "disk".to_string(),
                        requested_at: now.clone(),
                        claimed_at: Some(now.clone()),
                        acked_at: None,
                        outcome: None,
                        detail: Some("已取走，扫描中".to_string()),
                    }],
                    agent_id: "agent-1".to_string(),
                    gateway_id: "gw-001".to_string(),
                    instance_id: "inst-1".to_string(),
                    version: "0.31.0".to_string(),
                    status: "online".to_string(),
                    health: "healthy".to_string(),
                    memory_bytes: None,
                    cpu_percent: None,
                    admin_latency_ms: None,
                    last_seen_at: now.clone(),
                    node_id: None,
                    hostname: None,
                    ip_addresses: None,
                    data_manifest: None,
                }],
            )
            .await
            .expect("seed agent");
        state
            .store
            .insert_command(
                &CommandRecord {
                    command_id: "cmd_open_1".to_string(),
                    request_id: "case-1".to_string(),
                    kind: "gateway.agent-investigate".to_string(),
                    target_type: "gateway".to_string(),
                    target_ids: vec!["gw-001".to_string()],
                    payload: json!({
                        "agent_id": "agent-1",
                        "topic": "disk",
                        "external_ref": "case-1"
                    }),
                    reason: None,
                    requested_by: Some("svc-siem".to_string()),
                    state: COMMAND_STATE_QUEUED.to_string(),
                    created_by: "svc-siem".to_string(),
                    created_at: now.clone(),
                    dispatched_at: Some(now.clone()),
                    dispatched_by: Some("svc-siem".to_string()),
                    expires_at: None,
                    cancelled_at: None,
                    last_error: None,
                },
                &[],
            )
            .await
            .expect("insert command");

        let (status, body) = send(
            &state,
            Some("wcr_open"),
            None,
            "GET",
            &format!("{BASE}/cmd_open_1"),
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["command_id"], "cmd_open_1");
        assert_eq!(body["external_ref"], "case-1");
        assert_eq!(body["task"]["state"], "claimed");
        assert_eq!(body["task"]["detail"], "已取走，扫描中");
        assert_eq!(body["evidence"]["service"], "wist-field");
        assert_eq!(body["evidence"]["cmd_id"], "cmd_open_1");
    }

    #[tokio::test]
    async fn status_is_scoped_and_unknown_commands_look_missing() {
        let state = test_state(verifier_with("wcr_open", &["agent-2"]));
        seed_agent(&state).await;
        let (status, body) = send(
            &state,
            Some("wcr_open"),
            None,
            "GET",
            &format!("{BASE}/cmd_unknown"),
            "",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "command_not_found");
    }

    fn manifest(
        granted: Option<Vec<&str>>,
        capabilities: Option<Vec<&str>>,
    ) -> wist_control::AgentDataManifest {
        wist_control::AgentDataManifest {
            collected_at: DateTime::now(),
            collection: Vec::new(),
            investigations: Vec::new(),
            investigation_granted: granted
                .map(|values| values.into_iter().map(str::to_string).collect()),
            investigation_capabilities: capabilities
                .map(|values| values.into_iter().map(str::to_string).collect()),
        }
    }

    #[tokio::test]
    async fn capabilities_lists_the_closed_topic_set() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        let (status, body) = send(
            &state,
            Some("wcr_open"),
            None,
            "GET",
            "/api/v1/open/capabilities",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let ids: Vec<&str> = body["topics"]
            .as_array()
            .expect("topics")
            .iter()
            .map(|topic| topic["id"].as_str().expect("id"))
            .collect();
        assert_eq!(
            ids,
            [
                "disk",
                "load",
                "accounts",
                "persistence",
                "exposure",
                "telemetry-health"
            ]
        );
        // 题面参数不开放，capabilities 里也不该出现 parameters（否则是误导）。
        assert!(body["topics"][0].get("parameters").is_none());
    }

    #[tokio::test]
    async fn grants_resolve_customer_and_ip_and_intersect_capabilities() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        seed_agent_with(
            &state,
            Some(manifest(
                Some(vec!["disk", "load"]),
                Some(vec!["disk", "accounts"]),
            )),
        )
        .await;

        let (status, body) = send(
            &state,
            Some("wcr_open"),
            None,
            "GET",
            "/api/v1/open/investigation-grants?customer_id=cust-a&host_ip=192.168.1.5",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let agent = &body["agents"][0];
        assert_eq!(agent["agent_id"], "agent-1");
        assert_eq!(agent["grant_reported"], true);
        assert_eq!(agent["granted_topics"], json!(["disk", "load"]));
        assert_eq!(agent["capabilities"], json!(["disk", "accounts"]));
        assert_eq!(agent["usable_topics"], json!(["disk"]));
        assert_eq!(body["denied"], 0);
    }

    #[tokio::test]
    async fn grants_say_unreported_instead_of_pretending_all_off() {
        let state = test_state(verifier_with("wcr_open", &["agent-1"]));
        seed_agent_with(&state, Some(manifest(None, None))).await;
        let (status, body) = send(
            &state,
            Some("wcr_open"),
            None,
            "GET",
            "/api/v1/open/investigation-grants?customer_id=cust-a&host_ip=192.168.1.5",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let agent = &body["agents"][0];
        assert_eq!(agent["grant_reported"], false);
        assert_eq!(
            agent["reason"],
            "gateway_has_not_reported_investigation_grants"
        );
    }

    #[tokio::test]
    async fn grants_are_filtered_by_credential_scope() {
        let state = test_state(verifier_with("wcr_open", &["agent-2"]));
        seed_agent_with(&state, Some(manifest(Some(vec!["disk"]), None))).await;
        let (status, body) = send(
            &state,
            Some("wcr_open"),
            None,
            "GET",
            "/api/v1/open/investigation-grants?customer_id=cust-a&host_ip=192.168.1.5",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "investigation_scope_denied");
    }
}
