//! 开放面的**发现能力**：全局调查题面、按客户 + 主机 IP 找 Agent、读调查授权。
//!
//! 为什么单独一层：第三方不知道中心的 `agent_id`，只知道「客户 + 主机 IP」；
//! 而授权（grant）与能力（capabilities）是网关按机器判的，中心只把它们**如实转述**。
//! 解析与授权判定放在这里，`open_investigations` 只负责下发 / 查状态。

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use wist_auth::credential::VerifiedCredential;

use crate::infra::{GatewayCustomerBindingRecord, StoredAgent};

use super::{
    ApiState, PeerConnectInfo, codes,
    error::ApiError,
    extract::ApiQuery,
    open_auth::{allows_agent, require_investigation_credential},
    rate_limit,
};

/// 全局调查题面（与 agentd `TOPICS` / 网关 `[investigations] allowed_topics` 同一闭集）。
///
/// 只放**题面本身的说明**；具体能跑哪些要看 agent 自报能力与网关 grant（见 `/investigation-grants`）。
struct TopicSpec {
    id: &'static str,
    label: &'static str,
    summary: &'static str,
    platforms: &'static [&'static str],
}

const TOPIC_SPECS: &[TopicSpec] = &[
    TopicSpec {
        id: "disk",
        label: "磁盘",
        summary: "哪些文件 / 目录占空间、文件系统是否快满",
        platforms: &["linux", "macos"],
    },
    TopicSpec {
        id: "load",
        label: "负载",
        summary: "谁在吃 CPU / 内存 / IO",
        platforms: &["linux", "macos"],
    },
    TopicSpec {
        id: "accounts",
        label: "账号与授权",
        summary: "谁能登录本机、谁能提权（Linux）",
        platforms: &["linux"],
    },
    TopicSpec {
        id: "persistence",
        label: "持久化",
        summary: "重启后还有什么会自己跑起来（Linux）",
        platforms: &["linux"],
    },
    TopicSpec {
        id: "exposure",
        label: "暴露面",
        summary: "谁在监听、绑在哪个地址（只出证据，不做安全判定；Linux）",
        platforms: &["linux"],
    },
    TopicSpec {
        id: "telemetry-health",
        label: "遥测健康",
        summary: "配好的安全日志源还活着吗（“我们瞎了多久”）",
        platforms: &["linux", "macos"],
    },
];

/// 题面 id 是否在闭集里（下发接口用同一个词表）。
pub(super) fn is_known_topic(topic: &str) -> bool {
    TOPIC_SPECS.iter().any(|spec| spec.id == topic)
}

/// 题面 id 列表（错误信息里列出可选值）。
pub(super) fn known_topics() -> Vec<&'static str> {
    TOPIC_SPECS.iter().map(|spec| spec.id).collect()
}

/// `GET /api/v1/open/capabilities`
///
/// 全局题面清单。它回答「平台**提供**哪些调查能力」，不回答「这台机器开了哪些」；
/// 后者用 `/investigation-grants`。
pub async fn open_capabilities(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_investigation_credential(&state, &headers, &client_key) {
        return response;
    }
    let topics: Vec<Value> = TOPIC_SPECS
        .iter()
        .map(|topic| {
            json!({
                "id": topic.id,
                "label": topic.label,
                "summary": topic.summary,
                "platforms": topic.platforms,
            })
        })
        .collect();
    Json(json!({
        "source": "center",
        "version": env!("CARGO_PKG_VERSION"),
        "topics": topics,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct InvestigationGrantsQuery {
    pub customer_id: String,
    pub host_ip: String,
}

/// `GET /api/v1/open/investigation-grants?customer_id=…&host_ip=…`
///
/// 按「客户 + 主机 IP」找 Agent，并转述网关上报的调查授权与能力：
/// `granted_topics`（实际开的面）、`capabilities`（agent 认得的题）、`usable_topics`（两者交集）。
///
/// `granted_topics` 为空且 `grant_reported=false` 表示**旧网关还没上报**，不是「全关」；
/// 这是中心与网关版本差最常见的误读，响应里单独说清楚。
pub async fn open_investigation_grants(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<InvestigationGrantsQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    let credential = match require_investigation_credential(&state, &headers, &client_key) {
        Ok(credential) => credential,
        Err(response) => return response,
    };
    let customer_id = query.customer_id.trim();
    let host_ip = query.host_ip.trim();
    if customer_id.is_empty() || host_ip.is_empty() {
        return ApiError::bad_request(codes::INVALID_QUERY, "customer_id and host_ip are required")
            .into_response();
    }

    let agents = match agents_by_customer_ip(&state, customer_id, host_ip).await {
        Ok(agents) => agents,
        Err(response) => return response,
    };
    if agents.is_empty() {
        return ApiError::not_found(
            codes::AGENT_NOT_FOUND,
            format!("no agent for customer `{customer_id}` with ip `{host_ip}`"),
        )
        .into_response();
    }

    let bindings = match state.store.list_customer_bindings().await {
        Ok(bindings) => bindings,
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load customer bindings",
                err.display_chain(),
            )
            .into_response();
        }
    };
    let binding_for = |gateway_id: &str| {
        bindings
            .iter()
            .find(|binding| binding.gateway_id == gateway_id)
    };

    let mut allowed = Vec::new();
    let mut denied = 0;
    for agent in &agents {
        if !allows_agent(&credential, &agent.agent_id, &agent.gateway_id) {
            denied += 1;
            continue;
        }
        allowed.push(grant_view(agent, binding_for(&agent.gateway_id)));
    }
    if allowed.is_empty() {
        log::warn!(
            "event=OpenGrantScopeDenied subject={} customer_id={} host_ip={} matched={}",
            credential.subject,
            customer_id,
            host_ip,
            agents.len()
        );
        return ApiError::forbidden(
            codes::INVESTIGATION_SCOPE_DENIED,
            "credential is not scoped to any agent matching this customer / host ip",
        )
        .into_response();
    }

    Json(json!({
        "customer_id": customer_id,
        "host_ip": host_ip,
        "agents": allowed,
        "denied": denied,
    }))
    .into_response()
}

/// 按客户 + 主机 IP 找 Agent。
///
/// 客户绑定是网关级的（`gateway.customer_id`），IP 是 Agent 级的（`agent.ip_addresses`）；
/// 两者都必须命中。一个 IP 可能对应多台 Agent（同一主机的多个实例），调用方自己决定怎么用。
#[allow(clippy::result_large_err)]
pub(super) async fn agents_by_customer_ip(
    state: &ApiState,
    customer_id: &str,
    host_ip: &str,
) -> Result<Vec<StoredAgent>, Response> {
    let bindings = state.store.list_customer_bindings().await.map_err(|err| {
        ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::GATEWAY_STORE_UNAVAILABLE,
            "failed to load customer bindings",
            err.display_chain(),
        )
        .into_response()
    })?;
    let gateways: Vec<&str> = bindings
        .iter()
        .filter(|binding| binding.customer_id == customer_id)
        .map(|binding| binding.gateway_id.as_str())
        .collect();
    if gateways.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for gateway_id in gateways {
        let agents = state
            .store
            .list_agents_by_gateway(gateway_id)
            .await
            .map_err(|err| {
                ApiError::internal_with(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    codes::AGENT_STATUS_LOAD_FAILED,
                    "failed to load agent status",
                    err.display_chain(),
                )
                .into_response()
            })?;
        out.extend(
            agents
                .into_iter()
                .filter(|agent| agent_matches_ip(agent, host_ip)),
        );
    }
    out.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    out.dedup_by(|left, right| left.agent_id == right.agent_id);
    Ok(out)
}

/// Agent 的 `ip_addresses` 形如 `en0 192.168.1.5/24`，也可能只是裸 IP。
///
/// 比较时去掉前缀长度（`/24`）与网卡名，按文本比较；IPv6 不在这里做规范化——
/// 中心只做「同一串地址」的匹配，不做网段判断。
pub(super) fn agent_matches_ip(agent: &StoredAgent, requested: &str) -> bool {
    let requested = requested.trim();
    let requested = requested.split('/').next().unwrap_or(requested);
    agent.ip_addresses.as_ref().is_some_and(|addresses| {
        addresses
            .iter()
            .any(|entry| ip_part(entry).eq_ignore_ascii_case(requested))
    })
}

fn ip_part(entry: &str) -> &str {
    let token = entry.split_whitespace().last().unwrap_or(entry);
    token.split('/').next().unwrap_or(token)
}

/// 网关上报的授权 + agent 自报能力 → 一条对第三方的视图。
fn grant_view(agent: &StoredAgent, binding: Option<&GatewayCustomerBindingRecord>) -> Value {
    let manifest = agent.data_manifest.as_ref();
    let granted = manifest.and_then(|manifest| manifest.investigation_granted.clone());
    let capabilities = manifest.and_then(|manifest| manifest.investigation_capabilities.clone());
    let usable = match (&granted, &capabilities) {
        (Some(granted), Some(capabilities)) => Some(
            granted
                .iter()
                .filter(|topic| capabilities.iter().any(|capability| capability == *topic))
                .cloned()
                .collect::<Vec<_>>(),
        ),
        _ => None,
    };
    let reason = if granted.is_none() {
        Some("gateway_has_not_reported_investigation_grants")
    } else if capabilities.is_none() {
        Some("agent_has_not_reported_investigation_capabilities")
    } else {
        None
    };
    json!({
        "agent_id": agent.agent_id,
        "gateway_id": agent.gateway_id,
        "hostname": agent.hostname,
        "ip_addresses": agent.ip_addresses,
        "reported_at": agent.last_seen_at,
        "binding_status": binding.map(|binding| binding.status.clone()),
        "binding_revision": binding.map(|binding| binding.revision),
        "grant_reported": granted.is_some(),
        "granted_topics": granted.unwrap_or_default(),
        "capabilities_reported": capabilities.is_some(),
        "capabilities": capabilities.unwrap_or_default(),
        "usable_topics": usable.unwrap_or_default(),
        "reason": reason,
    })
}

/// 下发入口的寻址：`customer_id + host_ip`，必须唯一命中且都在凭据范围内。
#[allow(clippy::result_large_err)]
pub(super) async fn resolve_launch_agent(
    state: &ApiState,
    credential: &VerifiedCredential,
    customer_id: &str,
    host_ip: &str,
) -> Result<StoredAgent, Response> {
    let customer_id = customer_id.trim();
    let host_ip = host_ip.trim();
    if customer_id.is_empty() || host_ip.is_empty() {
        return Err(ApiError::bad_request(
            codes::COMMAND_PAYLOAD_INVALID,
            "customer_id and host_ip are required",
        )
        .into_response());
    }

    let agents = agents_by_customer_ip(state, customer_id, host_ip).await?;
    let matched = agents.len();
    let mut allowed: Vec<StoredAgent> = agents
        .into_iter()
        .filter(|agent| allows_agent(credential, &agent.agent_id, &agent.gateway_id))
        .collect();
    match allowed.len() {
        0 if matched > 0 => Err(ApiError::forbidden(
            codes::INVESTIGATION_SCOPE_DENIED,
            "credential is not scoped to any agent matching this customer / host ip",
        )
        .into_response()),
        0 => Err(ApiError::not_found(
            codes::AGENT_NOT_FOUND,
            format!("no agent for customer `{customer_id}` with ip `{host_ip}`"),
        )
        .into_response()),
        1 => Ok(allowed.remove(0)),
        _ => {
            let ids: Vec<&str> = allowed
                .iter()
                .map(|agent| agent.agent_id.as_str())
                .collect();
            Err(ApiError::conflict(
                codes::INVESTIGATION_AGENT_AMBIGUOUS,
                format!(
                    "multiple agents match customer `{customer_id}` / ip `{host_ip}`: {}",
                    ids.join(", ")
                ),
            )
            .with_field("agents", ids.join(","))
            .into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_control::types::DateTime;

    fn agent(ips: Option<Vec<&str>>) -> StoredAgent {
        StoredAgent {
            agent_id: "agent-1".to_string(),
            gateway_id: "gw-1".to_string(),
            instance_id: "inst-1".to_string(),
            version: "1".to_string(),
            status: "online".to_string(),
            health: "healthy".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            admin_latency_ms: None,
            last_seen_at: DateTime::now(),
            node_id: None,
            hostname: Some("host-1".to_string()),
            ip_addresses: ips.map(|values| values.into_iter().map(str::to_string).collect()),
            data_manifest: None,
            investigations: Vec::new(),
        }
    }

    #[test]
    fn ip_matching_strips_interface_and_prefix() {
        let machine = agent(Some(vec!["en0 192.168.1.5/24", "fe80::1/64"]));
        assert!(agent_matches_ip(&machine, "192.168.1.5"));
        assert!(agent_matches_ip(&machine, " 192.168.1.5/24 "));
        assert!(agent_matches_ip(&machine, "FE80::1"));
        assert!(!agent_matches_ip(&machine, "192.168.1.6"));
        assert!(!agent_matches_ip(&agent(Some(vec![])), "192.168.1.5"));
        assert!(!agent_matches_ip(&agent(None), "192.168.1.5"));
    }

    #[test]
    fn topic_catalog_is_the_closed_set() {
        let ids: Vec<&str> = TOPIC_SPECS.iter().map(|spec| spec.id).collect();
        assert_eq!(
            ids,
            vec![
                "disk",
                "load",
                "accounts",
                "persistence",
                "exposure",
                "telemetry-health"
            ]
        );
        assert!(is_known_topic("disk"));
        assert!(!is_known_topic("memory"));
    }

    /// capabilities 对外广告的题面必须与下发校验用的是同一份词表：
    /// 两份拷贝一旦漂移，会出现「页面能选、下发 422」或反过来。
    #[test]
    fn topic_catalog_matches_the_dispatch_vocabulary() {
        let mut advertised = known_topics();
        let mut dispatch = crate::api::commands::INVESTIGATE_TOPICS.to_vec();
        advertised.sort_unstable();
        dispatch.sort_unstable();
        assert_eq!(advertised, dispatch, "capabilities 与下发词表漂移了");
    }
}
