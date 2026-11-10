//! 中心下发调查（`gateway.agent-investigate`）：发起 / 看任务状态 / 取报告正文。
//!
//! 链路（设计 `doc/design/center/investigation-center-relay.md`）：
//!
//! ```text
//! POST /admin/gateways/{gid}/agents/{aid}/investigations
//!   → commands（中心铸 command_id）
//!     → gateway_commands（wire kind = investigate-agent，body 带 command_id + agent_id + topic）
//!       → gwlinkd 环回 POST 网关 gateway-plane 端点
//!         → agentd 执行 → IVSREP → 证据库（键 = cmd_id）
//! ```
//!
//! 三条读口分工：
//!
//! | 端点 | 数据源 | 说明 |
//! | --- | --- | --- |
//! | GET `…/investigations` | 中心自己的 `agent_status.investigations` | 任务跑到哪了（≤60s 新鲜度） |
//! | GET `…/investigations/{cmd}/content` | 证据库 `/content` | 报告正文（边读边转，不落盘） |
//!
//! **两个来源分开说**：证据服务不可达 ≠ 没有报告；任务状态里没见过这个 id ≠ 命令没下发。

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use wist_control::types::DateTime;

use crate::infra::{EvidenceClient, EvidenceReadError, StoredAgent};

use super::{
    ApiState, PeerConnectInfo,
    admin_auth::require_admin_bearer,
    codes,
    commands::{
        INVESTIGATE_MIN_GWLINKD, INVESTIGATE_TOPICS, create_and_dispatch,
        gwlinkd_supports_investigate,
    },
    error::ApiError,
    extract::ApiJson,
    rate_limit,
    wparse_proxy_api::ensure_gateway_exists,
};

/// Agent 调查任务的可见期：与网关侧同口径（7 天 / 最近 3 条）。
const TASK_RETENTION_DAYS: i64 = 7;
const MAX_TASKS: usize = 3;
/// 指令种类的调用方词表（与 `commands::KINDS` 同一个字符串）。
const INVESTIGATE_KIND: &str = "gateway.agent-investigate";

// ── 请求 / 响应 ──────────────────────────────────────────────────────────

/// 发起一次调查。**不接受 `path`**（`deny_unknown_fields` 会把带 `path` 的请求打成 400）：
/// 扫描根由题目在客户机上自己挑 —— 目录名本身就是情报。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchInvestigationRequest {
    pub topic: String,
    #[serde(default)]
    pub top: Option<u32>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub depth: Option<u32>,
    #[serde(default)]
    pub max_seconds: Option<u64>,
    /// 为什么查（审计与页面回显）；可省。
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvidenceView {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitivity: Option<String>,
    /// 还剩几天可读（证据库的保留期到期时刻减去现在）。
    #[serde(skip_serializing_if = "Option::is_none")]
    retention_days: Option<i64>,
}

impl EvidenceView {
    fn unavailable(reason: &'static str) -> Self {
        Self {
            available: false,
            reason: Some(reason),
            kind: None,
            verdict: None,
            size_bytes: None,
            sensitivity: None,
            retention_days: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct InvestigationTaskView {
    command_id: String,
    topic: String,
    /// `queued`（还没被 agentd 取走）/ `claimed`（在扫）/ `acked`（已回执，成功或失败）/\n    /// `expired`（过期未执行）/ `superseded`（被新命令取代）—— 后两者写了 `acked_at`，\n    /// 但**没跑过**，不能当「已完成」。
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
    evidence: EvidenceView,
}

/// 最近一次**下发**的回执（中心自己的命令队列）。
///
/// 为什么任务状态之外还要它：网关拒绝（未授权 / 能力不支持 / 在飞）时**不会有任务**
/// 上来 —— 只有 `target_commands.result_error` 说真话。不把它带出来，运维看到的就是
/// 「点了没反应」。
#[derive(Debug, Serialize)]
struct DispatchResultView {
    command_id: String,
    state: String,
    requested_at: DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_error: Option<String>,
}

// ── 处理器 ───────────────────────────────────────────────────────────────

/// `POST /api/v1/admin/gateways/{gateway_id}/agents/{agent_id}/investigations`
pub async fn admin_launch_agent_investigation(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path((gateway_id, agent_id)): Path<(String, String)>,
    ApiJson(request): ApiJson<LaunchInvestigationRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = ensure_gateway_exists(&state, &gateway_id).await {
        return response;
    }
    let topic = request.topic.trim();
    if !INVESTIGATE_TOPICS.contains(&topic) {
        return ApiError::bad_request(
            codes::COMMAND_PAYLOAD_INVALID,
            format!(
                "unknown investigation topic {topic:?} (known: {})",
                INVESTIGATE_TOPICS.join(", ")
            ),
        )
        .into_response();
    }
    // 目标存在性：中心只知道上报过的 agent（没有 `agent_status` 行 = 没见过这台机器）。
    match find_agent(&state, &gateway_id, &agent_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return ApiError::not_found(
                codes::AGENT_NOT_FOUND,
                format!("unknown agent `{agent_id}` on gateway `{gateway_id}`"),
            )
            .into_response();
        }
        Err(response) => return response,
    }
    // 旧 gwlinkd 不认识 `investigate-agent`，会在执行时回 400：能提前判定就提前拒。
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

    // payload 只留「查什么」：`path` 不在词表里（见上方文档）。
    let mut payload = serde_json::Map::new();
    payload.insert("agent_id".to_string(), Value::String(agent_id.clone()));
    payload.insert("topic".to_string(), Value::String(topic.to_string()));
    for (key, value) in [
        ("top", request.top.map(Value::from)),
        ("min_size", request.min_size.map(Value::from)),
        ("depth", request.depth.map(Value::from)),
        ("max_seconds", request.max_seconds.map(Value::from)),
    ] {
        if let Some(value) = value {
            payload.insert(key.to_string(), value);
        }
    }
    match create_and_dispatch(
        &state,
        INVESTIGATE_KIND,
        vec![gateway_id.clone()],
        Value::Object(payload),
        request.reason.filter(|value| !value.trim().is_empty()),
        Some("admin".to_string()),
    )
    .await
    {
        Ok(command) => {
            log::info!(
                "event=AgentInvestigateDispatched gateway_id={} agent_id={} command_id={} topic={}",
                gateway_id,
                agent_id,
                command.command_id,
                topic
            );
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "gateway_id": gateway_id,
                    "agent_id": agent_id,
                    "command_id": command.command_id,
                    "topic": topic,
                    "target": { "type": "gateway", "ids": [gateway_id] },
                    "state": command.state,
                    "last_error": command.last_error,
                })),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

/// `GET /api/v1/admin/gateways/{gateway_id}/agents/{agent_id}/investigations`
///
/// 任务状态来自随 `AgentRuntimeStatus` 上来的 `investigations`（≤60s 新鲜度）；
/// 每一行再现场问一次证据库「报告到了没有」——两者都不假装对方的数据。
pub async fn admin_show_agent_investigations(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path((gateway_id, agent_id)): Path<(String, String)>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = ensure_gateway_exists(&state, &gateway_id).await {
        return response;
    }
    let agent = match find_agent(&state, &gateway_id, &agent_id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return ApiError::not_found(
                codes::AGENT_NOT_FOUND,
                format!("unknown agent `{agent_id}` on gateway `{gateway_id}`"),
            )
            .into_response();
        }
        Err(response) => return response,
    };

    let evidence = match evidence_context(&state, &gateway_id).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let cutoff = DateTime::now().to_chrono() - chrono::Duration::days(TASK_RETENTION_DAYS);
    let tasks: Vec<&wist_control::AgentInvestigationTask> = agent
        .investigations
        .iter()
        .filter(|task| task.requested_at.to_chrono() >= cutoff)
        .take(MAX_TASKS)
        .collect();
    let mut evidence_by_id = look_up_evidence(&evidence, &tasks).await;
    let mut views = Vec::with_capacity(tasks.len());
    for task in tasks {
        let evidence = evidence_by_id
            .remove(&task.command_id)
            .unwrap_or_else(|| EvidenceView::unavailable("evidence_unavailable"));
        views.push(InvestigationTaskView {
            command_id: task.command_id.clone(),
            topic: task.topic.clone(),
            state: task_state(task),
            requested_at: task.requested_at.clone(),
            claimed_at: task.claimed_at.clone(),
            acked_at: task.acked_at.clone(),
            outcome: task.outcome.clone(),
            detail: task.detail.clone(),
            evidence,
        });
    }
    let last_dispatch = match last_dispatch(&state, &gateway_id, &agent_id).await {
        Ok(view) => view,
        Err(response) => return response,
    };
    Json(json!({
        "gateway_id": gateway_id,
        "agent_id": agent_id,
        "reported_at": agent.last_seen_at,
        "last_dispatch": last_dispatch,
        "tasks": views,
    }))
    .into_response()
}

/// `GET /api/v1/admin/gateways/{gateway_id}/agents/{agent_id}/investigations/{command_id}/content`
///
/// 代理证据库的 `/content`（边读边转，不落盘）。
pub async fn admin_read_investigation_content(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path((gateway_id, agent_id, command_id)): Path<(String, String, String)>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = ensure_gateway_exists(&state, &gateway_id).await {
        return response;
    }
    // 只代理**这次调查**的证据：command_id 必须是中心为这台 Agent 发过的命令。
    // 否则这个端点就成了「随便拿一个证据 id 让中心替你取」的代理（跨租户泄露面）。
    match state.store.get_command(&command_id).await {
        Ok(Some(command)) if command_matches(&command, &gateway_id, &agent_id) => {}
        Ok(_) => {
            return ApiError::not_found(
                codes::COMMAND_NOT_FOUND,
                format!("no investigation `{command_id}` for agent `{agent_id}`"),
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
    }
    let client = match evidence_context(&state, &gateway_id).await {
        Ok(EvidenceLookup::Ready(client)) => client,
        Ok(EvidenceLookup::Unavailable(reason)) => return evidence_unavailable(reason),
        Err(response) => return response,
    };
    match client.content(&command_id).await {
        Ok(body) => (
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                ),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(EvidenceReadError::NotFound) => ApiError::not_found(
            codes::INVESTIGATION_REPORT_NOT_FOUND,
            "报告还没同步到证据库（可稍后重试）",
        )
        .into_response(),
        Err(EvidenceReadError::Unauthorized(err)) => {
            log::warn!(
                "event=InvestigationContentUnauthorized command_id={} err={}",
                command_id,
                err
            );
            evidence_unauthorized()
        }
        Err(EvidenceReadError::Unavailable(err)) => {
            log::warn!(
                "event=InvestigationContentUnavailable command_id={} err={}",
                command_id,
                err
            );
            evidence_unavailable("evidence_unavailable")
        }
    }
}

// ── 内部 ─────────────────────────────────────────────────────────────────

enum EvidenceLookup {
    Ready(EvidenceClient),
    /// 未配置 —— 页面显示「证据服务不可用」，而不是「没有报告」。
    Unavailable(&'static str),
}

/// 并发问证据库：一条任务一份元数据。
///
/// 为什么并发：证据服务不可达时每次调用都要等到超时（默认 10s），串行三条就是三倍等待。
/// 结果按 `command_id` 收回来 —— 并发完成顺序不可靠，不能拿它排序。
async fn look_up_evidence(
    lookup: &EvidenceLookup,
    tasks: &[&wist_control::AgentInvestigationTask],
) -> HashMap<String, EvidenceView> {
    let client = match lookup {
        EvidenceLookup::Ready(client) => client,
        EvidenceLookup::Unavailable(reason) => {
            return tasks
                .iter()
                .map(|task| (task.command_id.clone(), EvidenceView::unavailable(reason)))
                .collect();
        }
    };

    let mut set = tokio::task::JoinSet::new();
    for task in tasks {
        let client = client.clone();
        let command_id = task.command_id.clone();
        set.spawn(async move {
            let result = client.metadata(&command_id).await;
            (command_id, result)
        });
    }

    let mut views = HashMap::with_capacity(tasks.len());
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((command_id, Ok(artifact))) => {
                views.insert(
                    command_id,
                    EvidenceView {
                        available: true,
                        reason: None,
                        kind: Some(artifact.kind),
                        verdict: artifact.verdict,
                        size_bytes: Some(artifact.size_bytes),
                        sensitivity: Some(artifact.sensitivity),
                        retention_days: retention_days(&artifact.retention_until),
                    },
                );
            }
            Ok((command_id, Err(EvidenceReadError::NotFound))) => {
                views.insert(command_id, EvidenceView::unavailable("not_yet_available"));
            }
            Ok((command_id, Err(EvidenceReadError::Unauthorized(err)))) => {
                // 令牌错 / 过期 / 没该租户权限：与「服务挂了」分开，处置是换凭据。
                log::warn!(
                    "event=InvestigationEvidenceUnauthorized command_id={} err={}",
                    command_id,
                    err
                );
                views.insert(
                    command_id,
                    EvidenceView::unavailable("evidence_unauthorized"),
                );
            }
            Ok((command_id, Err(EvidenceReadError::Unavailable(err)))) => {
                log::warn!(
                    "event=InvestigationEvidenceUnavailable command_id={} err={}",
                    command_id,
                    err
                );
                views.insert(
                    command_id,
                    EvidenceView::unavailable("evidence_unavailable"),
                );
            }
            // 任务 panic：这个 id 没有结果，调用方会回落成「不可用」——不影响其它行。
            Err(err) => log::warn!("event=InvestigationEvidenceJoinFailed err={err}"),
        }
    }
    views
}

#[allow(clippy::result_large_err)]
async fn evidence_context(state: &ApiState, _gateway_id: &str) -> Result<EvidenceLookup, Response> {
    let Some(config) = state.config.evidence.as_ref() else {
        return Ok(EvidenceLookup::Unavailable("evidence_not_configured"));
    };
    let client = EvidenceClient::new(config).map_err(|err| {
        log::warn!("evidence client init failed: {err:?}");
        evidence_unavailable("evidence_unavailable")
    })?;
    Ok(EvidenceLookup::Ready(client))
}

fn evidence_unavailable(reason: &'static str) -> Response {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        codes::EVIDENCE_UNAVAILABLE,
        match reason {
            "evidence_not_configured" => "证据服务未配置：中心只能显示任务状态，看不到报告正文",
            _ => "证据服务不可达（不是“没有报告”：稍后重试）",
        },
    )
    .into_response()
}

/// 令牌错 / 过期 / 没权限：处置是换凭据，不是「等一下」。
fn evidence_unauthorized() -> Response {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        codes::EVIDENCE_UNAUTHORIZED,
        "读取证据的令牌无效或已过期（检查 [evidence].read_token / .wist/sec-value.yml）",
    )
    .into_response()
}

fn task_state(task: &wist_control::AgentInvestigationTask) -> &'static str {
    // `expired` / `superseded` 也写了 `acked_at`，但它们**没执行过** —— 并进 `acked`
    // 会把「命令丢了」显示成「做完了」（与网关队列页同一口径）。
    match task.outcome.as_deref() {
        Some("expired") => "expired",
        Some("superseded") => "superseded",
        _ if task.outcome.is_some() || task.acked_at.is_some() => "acked",
        _ if task.claimed_at.is_some() => "claimed",
        _ => "queued",
    }
}

fn retention_days(retention_until: &str) -> Option<i64> {
    let until = DateTime::from_rfc3339(retention_until)?;
    let seconds = DateTime::now().seconds_until(&until);
    Some((seconds + 86_399) / 86_400)
}

/// 最近一次为这台 Agent 下发的调查指令 + 它的投递回执。
///
/// 读中心自己的命令队列（`commands` + `target_commands`）：网关拒绝时不会有任务上报，
/// 只有这里能说清「为什么没反应」。
#[allow(clippy::result_large_err)]
async fn last_dispatch(
    state: &ApiState,
    gateway_id: &str,
    agent_id: &str,
) -> Result<Option<DispatchResultView>, Response> {
    let commands = match state
        .store
        .list_commands(None, Some(INVESTIGATE_KIND), 200)
        .await
    {
        Ok(commands) => commands,
        Err(err) => {
            return Err(ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::COMMAND_STORE_UNAVAILABLE,
                "failed to list investigation commands",
                err.display_chain(),
            )
            .into_response());
        }
    };
    let Some(command) = commands
        .into_iter()
        .find(|command| command_matches(command, gateway_id, agent_id))
    else {
        return Ok(None);
    };
    let target = state
        .store
        .list_target_commands(&command.command_id)
        .await
        .ok()
        .and_then(|targets| {
            targets
                .into_iter()
                .find(|target| target.target_id == gateway_id)
        });
    Ok(Some(DispatchResultView {
        command_id: command.command_id,
        state: command.state,
        requested_at: command.created_at,
        result_status: target.as_ref().and_then(|target| target.result_status),
        result_error: target.and_then(|target| target.result_error),
    }))
}

fn command_matches(
    command: &crate::infra::CommandRecord,
    gateway_id: &str,
    agent_id: &str,
) -> bool {
    command.kind == INVESTIGATE_KIND
        && command.target_ids.iter().any(|id| id == gateway_id)
        && command
            .payload
            .get("agent_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value == agent_id)
}

#[allow(clippy::result_large_err)]
async fn find_agent(
    state: &ApiState,
    gateway_id: &str,
    agent_id: &str,
) -> Result<Option<StoredAgent>, Response> {
    match state.store.list_agents_by_gateway(gateway_id).await {
        Ok(agents) => Ok(agents.into_iter().find(|agent| agent.agent_id == agent_id)),
        Err(err) => Err(ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::AGENT_STATUS_LOAD_FAILED,
            "failed to load agent status",
            err.display_chain(),
        )
        .into_response()),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use crate::config::{CenterConfig, GatewayCredentialSeed, WparseProxyConfig};
    use crate::infra::{FileStore, LocalArtifactStore, Store, StoredAgent, sha256_hex};
    use wist_control::types::DateTime;

    use super::super::{ApiState, router_for};

    fn test_state() -> ApiState {
        let path = std::env::temp_dir().join(format!(
            "wic-investigation-test-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
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
                store_path: path,
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(sha256_hex("admin-tok")),
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
                credentials: Default::default(),
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
            credentials: None,
        }
    }

    async fn seed_agent(state: &ApiState) {
        let now = DateTime::now();
        state
            .store
            .upsert_agent_status(
                "gw-001",
                &[StoredAgent {
                    investigations: vec![wist_control::AgentInvestigationTask {
                        command_id: "cmd_live_1".to_string(),
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
                    last_seen_at: now,
                    node_id: None,
                    hostname: None,
                    ip_addresses: None,
                    data_manifest: None,
                }],
            )
            .await
            .expect("seed agent");
    }

    async fn send(state: &ApiState, method: &str, uri: &str, body: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", "Bearer admin-tok")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = router_for(state.clone())
            .oneshot(request)
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

    const BASE: &str = "/api/v1/admin/gateways/gw-001/agents/agent-1/investigations";

    /// 题面闭集 + `path` 不接受：中心侧的下发面只允许「查什么」，不允许指定扫描根。
    #[tokio::test]
    async fn launch_rejects_unknown_topics_and_paths() {
        let state = test_state();
        seed_agent(&state).await;

        let (status, body) = send(
            &state,
            "POST",
            BASE,
            &json!({"topic": "memory"}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "command_payload_invalid");

        // `path` 在词表外 → 请求体被拒（deny_unknown_fields）。
        let (status, body) = send(
            &state,
            "POST",
            BASE,
            &json!({"topic": "disk", "path": "/var/log"}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }

    /// 没上报过的 Agent 一律 404（中心不猜目标）。
    #[tokio::test]
    async fn launch_rejects_unknown_agents() {
        let state = test_state();
        let (status, body) = send(
            &state,
            "POST",
            "/api/v1/admin/gateways/gw-001/agents/agent-x/investigations",
            &json!({"topic": "disk"}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "agent_not_found");
    }

    /// 状态读口：任务来自网关上来的 `investigations`；证据未配置时**说清楚原因**，
    /// 不能让页面把「看不到」读成「没有报告」。
    #[tokio::test]
    async fn show_reports_task_state_and_says_evidence_is_not_configured() {
        let state = test_state();
        seed_agent(&state).await;
        let (status, body) = send(&state, "GET", BASE, "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let tasks = body["tasks"].as_array().expect("tasks");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["command_id"], "cmd_live_1");
        assert_eq!(tasks[0]["state"], "claimed");
        assert_eq!(tasks[0]["evidence"]["available"], false);
        assert_eq!(
            tasks[0]["evidence"]["reason"], "evidence_not_configured",
            "未配置证据服务 ≠ 没有报告"
        );
    }

    /// 正文读口只代理**本次调查**：没为这台 Agent 发过这个命令，就不替你取证据。
    #[tokio::test]
    async fn content_refuses_commands_that_were_never_dispatched() {
        let state = test_state();
        seed_agent(&state).await;
        let (status, body) = send(&state, "GET", &format!("{BASE}/cmd_unknown/content"), "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], "command_not_found");
    }

    /// 网关拒绝（未授权等）时不会有任务上报 —— 只有中心命令回执能说清「为什么没反应」。
    #[tokio::test]
    async fn show_surfaces_the_last_dispatch_result() {
        use crate::infra::{
            COMMAND_STATE_FAILED, CommandRecord, TARGET_STATE_FAILED, TargetCommandRecord,
        };

        let state = test_state();
        seed_agent(&state).await;
        let now = DateTime::now();
        let command = CommandRecord {
            command_id: "cmd_dispatch_1".to_string(),
            request_id: "req_1".to_string(),
            kind: "gateway.agent-investigate".to_string(),
            target_type: "gateway".to_string(),
            target_ids: vec!["gw-001".to_string()],
            payload: json!({"agent_id": "agent-1", "topic": "disk"}),
            reason: None,
            requested_by: Some("admin".to_string()),
            state: COMMAND_STATE_FAILED.to_string(),
            created_by: "admin".to_string(),
            created_at: now.clone(),
            dispatched_at: Some(now.clone()),
            dispatched_by: Some("admin".to_string()),
            expires_at: None,
            cancelled_at: None,
            last_error: Some("investigation_not_granted".to_string()),
        };
        let target = TargetCommandRecord {
            target_command_id: "tcmd_1".to_string(),
            command_id: "cmd_dispatch_1".to_string(),
            target_id: "gw-001".to_string(),
            gateway_id: "gw-001".to_string(),
            wire_kind: "investigate-agent".to_string(),
            state: TARGET_STATE_FAILED.to_string(),
            attempts: 1,
            result_status: Some(403),
            result_error: Some(
                "investigation_not_granted: topic \"disk\" is not granted to agent agent-1"
                    .to_string(),
            ),
            result_body: None,
            created_at: now.clone(),
            updated_at: now,
        };
        state
            .store
            .insert_command(&command, &[target])
            .await
            .expect("insert command");

        let (status, body) = send(&state, "GET", BASE, "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["last_dispatch"]["command_id"], "cmd_dispatch_1");
        assert_eq!(body["last_dispatch"]["result_status"], 403);
        assert!(
            body["last_dispatch"]["result_error"]
                .as_str()
                .is_some_and(|value| value.contains("investigation_not_granted")),
            "拒绝原因要带出来：{}",
            body["last_dispatch"]
        );
    }

    /// 旧 gwlinkd 不认识 `investigate-agent`：中心**提前**拒（不让页面看到“已下发”却没反应）。
    #[tokio::test]
    async fn launch_refuses_a_too_old_gwlinkd() {
        use crate::infra::GatewayStatusUpdate;

        let state = test_state();
        seed_agent(&state).await;
        state
            .store
            .upsert_gateway_status(&GatewayStatusUpdate {
                gateway_id: "gw-001".to_string(),
                instance_id: "i".to_string(),
                version: "0.42.0".to_string(),
                gops_version: None,
                gx_version: None,
                gwlinkd_version: Some("0.21.0".to_string()),
                status: "online".to_string(),
                health: "ok".to_string(),
                memory_bytes: None,
                cpu_percent: None,
                public_base_url: None,
                last_seen_at: DateTime::now(),
                uptime_seconds: None,
                agent_count: None,
                online_agents: None,
                offline_agents: None,
                last_seen_lag_seconds: None,
                store_bytes: None,
                ingest_accepted_total: None,
                ingest_rejected_total: None,
                last_ingest_at: None,
                memory_total_bytes: None,
                load_1m: None,
                load_5m: None,
                load_15m: None,
                disk_usage_percent: None,
                disk_total_bytes: None,
                disk_available_bytes: None,
            })
            .await
            .expect("gateway status");

        let (status, body) =
            send(&state, "POST", BASE, &json!({"topic": "disk"}).to_string()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "agent_investigate_unsupported");
    }

    /// 正文读口在证据服务未接入时回 503（而不是 404「没有报告」）。
    #[tokio::test]
    async fn content_reports_unavailable_when_evidence_is_not_configured() {
        use crate::infra::CommandRecord;

        let state = test_state();
        seed_agent(&state).await;
        let now = DateTime::now();
        state
            .store
            .insert_command(
                &CommandRecord {
                    command_id: "cmd_content_1".to_string(),
                    request_id: "req_content_1".to_string(),
                    kind: "gateway.agent-investigate".to_string(),
                    target_type: "gateway".to_string(),
                    target_ids: vec!["gw-001".to_string()],
                    payload: json!({"agent_id": "agent-1", "topic": "disk"}),
                    reason: None,
                    requested_by: Some("admin".to_string()),
                    state: "queued".to_string(),
                    created_by: "admin".to_string(),
                    created_at: now.clone(),
                    dispatched_at: None,
                    dispatched_by: None,
                    expires_at: None,
                    cancelled_at: None,
                    last_error: None,
                },
                &[],
            )
            .await
            .expect("insert command");

        let (status, body) =
            send(&state, "GET", &format!("{BASE}/cmd_content_1/content"), "").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error"]["code"], "evidence_unavailable");
    }

    /// 令牌错（BFF 401）要和「服务挂了」「没有报告」分开：页面处置是换凭据。
    #[tokio::test]
    async fn show_reports_unauthorized_evidence_with_its_own_reason() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0_u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let body = r#"{"error":{"code":"invalid_access_token","message":"bad token"}}"#;
                let response = format!(
                    "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });

        let mut state = test_state();
        state.config.evidence = Some(crate::config::EvidenceConfig {
            endpoint: format!("http://{addr}"),
            read_token: "wcr_bad".to_string(),
            timeout_seconds: 5,
            ca_file: None,
        });
        seed_agent(&state).await;

        let (status, body) = send(&state, "GET", BASE, "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let task = &body["tasks"][0];
        assert_eq!(task["evidence"]["available"], false);
        assert_eq!(
            task["evidence"]["reason"], "evidence_unauthorized",
            "401 不能写成「不可达」或「还没有报告」：{:?}",
            task["evidence"]
        );
    }

    /// 原文读口只认「中心为这台 Agent 发过的命令」：别的 agent / 别的 kind 都 404。
    #[test]
    fn content_authorization_matches_kind_target_and_agent() {
        let command = crate::infra::CommandRecord {
            command_id: "cmd_1".to_string(),
            request_id: "req_1".to_string(),
            kind: "gateway.agent-investigate".to_string(),
            target_type: "gateway".to_string(),
            target_ids: vec!["gw-001".to_string()],
            payload: json!({"agent_id": "agent-1", "topic": "disk"}),
            reason: None,
            requested_by: None,
            state: "queued".to_string(),
            created_by: "admin".to_string(),
            created_at: DateTime::now(),
            dispatched_at: None,
            dispatched_by: None,
            expires_at: None,
            cancelled_at: None,
            last_error: None,
        };
        assert!(super::command_matches(&command, "gw-001", "agent-1"));
        assert!(!super::command_matches(&command, "gw-002", "agent-1"));
        assert!(!super::command_matches(&command, "gw-001", "agent-2"));

        let mut other_kind = command.clone();
        other_kind.kind = "gateway.diagnose".to_string();
        assert!(!super::command_matches(&other_kind, "gw-001", "agent-1"));
    }

    /// 保留期向上取整：到期时刻还剩 1 小时也算「还有 1 天」，不显示成 0。
    #[test]
    fn retention_days_rounds_up_and_never_goes_negative() {
        let soon = DateTime::from_rfc3339(
            &(DateTime::now().to_chrono() + chrono::Duration::hours(1)).to_rfc3339(),
        )
        .expect("parse");
        assert_eq!(
            super::retention_days(&soon.to_chrono().to_rfc3339()),
            Some(1)
        );

        let past = DateTime::from_rfc3339(
            &(DateTime::now().to_chrono() - chrono::Duration::hours(5)).to_rfc3339(),
        )
        .expect("parse");
        assert_eq!(
            super::retention_days(&past.to_chrono().to_rfc3339()),
            Some(0)
        );
        assert_eq!(super::retention_days("not a timestamp"), None);
    }

    #[test]
    fn task_state_is_derived_from_timestamps() {
        let mut task = wist_control::AgentInvestigationTask {
            command_id: "c".to_string(),
            topic: "disk".to_string(),
            requested_at: DateTime::now(),
            claimed_at: None,
            acked_at: None,
            outcome: None,
            detail: None,
        };
        assert_eq!(super::task_state(&task), "queued");
        task.claimed_at = Some(DateTime::now());
        assert_eq!(super::task_state(&task), "claimed");
        task.outcome = Some("succeeded".to_string());
        assert_eq!(super::task_state(&task), "acked");
        // 终态但没执行：不能算「已回执」。
        task.outcome = Some("expired".to_string());
        task.acked_at = Some(DateTime::now());
        assert_eq!(super::task_state(&task), "expired");
        task.outcome = Some("superseded".to_string());
        assert_eq!(super::task_state(&task), "superseded");
        // 失败仍然是「跑过了」：状态是 acked，结论在 outcome 里。
        task.outcome = Some("failed".to_string());
        assert_eq!(super::task_state(&task), "acked");
    }
}
