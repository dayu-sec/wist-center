// 管理面接口：网关创建 + 列表聚合 / 状态卡片列表 / 单网关状态。
// 数据来自 center store（ReceiveGatewayStatusReport 落库的最新状态）。

use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use wist_control::types::DateTime;
use wist_control::{
    AdminDispatchGlobalPolicy, AdminGatewayListReturned, AdminGatewayStatusListReturned,
    AdminGatewayStatusReturned, AgentFleetDispatchReceipt, AgentRuntimeStatus,
    DispatchAgentFleetCommand, GatewayCustomerBinding, GatewayInitialConfig, GatewayInstance,
    GatewayInstanceLifecycleState, GatewayListView, GatewayRuntimeStatus, GlobalPolicyDispatch,
};

use crate::infra::{GatewayCustomerBindingRecord, StoreReason, StoredGateway};

use super::{
    ApiState, PeerConnectInfo,
    admin_auth::require_admin_bearer,
    build_control_center_trust_bundle, control_center_tls_required,
    extract::{ApiJson, ApiQuery},
    rate_limit, rollout,
};

/// 创建网关实例请求体：对齐模型 `AdminCreateGatewayInstanceRequest`（gateway_name/requested_by）。
/// **不含接入凭据**：接入券由「生成/轮换」端点产出（设计 §8）。
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCreateGatewayInstanceRequest {
    pub gateway_name: String,
    pub requested_by: String,
}

/// 网关实例安装指引（api 层交付信息，不模型化）：docker 安装命令 + 云镜像地址 + 初始化 URL + 接入券。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GatewayInstallInfo {
    pub install_command: String,
    pub cloud_image: String,
    pub init_url: String,
    /// 一次性接入券（LINK_TOKEN）明文：**仅「生成/轮换」响应交付一次**，
    /// 供 admin 页面展示；中心只存 hash（带短 TTL），一次性、过期即废。
    pub link_token: String,
    /// 控制中心 CA 证书内容（control-center.pem 信任根），供安装时写入 trust_bundle 路径。
    pub trust_bundle_pem: Option<String>,
    /// 服务端生成的 curl 验证命令：Bearer 用接入 token + 网关自生成身份调 init_url。
    pub init_curl: String,
    /// 全量安装命令（`curl ... | bash`）：在目标主机上装 gops/gx 并拉起 gateway-stack。
    /// URL 里带同一张一次性接入券（回执交付后 s 刷新即丢，可随时重新生成/轮换）。
    pub install_all_command: String,
    /// 前置环境准备命令（`curl ... | bash`）：补 tar/docker/docker compose 等；无需令牌，可先于安装单独跑。
    pub prepare_command: String,
    /// 「只装 gwlinkd」命令（`curl ... | bash`）：**网关已部署**时只补装宿主侧 `wist-gwlinkd`
    /// （不装 gops/gx/gateway-stack）。URL 里带同一张一次性接入券（短命，刷新即丢）。
    pub install_linkd_command: String,
}

/// 创建网关实例返回：**仅实例视图**。接入凭据不在 create 响应里交付（设计 §6/§8），
/// 由「生成/轮换」端点产出。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AdminCreateGatewayInstanceReturned {
    pub instance: GatewayInstance,
}

/// 管理端实例列表项：在生命周期信息之外公开不含凭证的初始化入口。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AdminGatewayInstanceView {
    pub gateway_id: String,
    pub instance_id: String,
    pub lifecycle_state: GatewayInstanceLifecycleState,
    pub created_at: DateTime,
    pub initialized_at: Option<DateTime>,
    pub init_url: String,
    /// 归档时刻；`None` = 未归档。归档是**标记**（默认视图隐藏、历史保留、可恢复），不是删除 ——
    /// 页面据此显示「已归档」与「取消归档」。
    #[serde(default)]
    pub archived_at: Option<DateTime>,
    /// 业务身份绑定（与 Center 管理面字段 `customer_id` 同名；数据面称 `tenant_id`）。
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub binding_status: Option<String>,
    #[serde(default)]
    pub binding_revision: Option<i64>,
    #[serde(default)]
    pub applied_revision: Option<i64>,
    #[serde(default)]
    pub applied_at: Option<DateTime>,
    #[serde(default)]
    pub binding_last_error: Option<String>,
    /// 网关**自报**的 tenant_id（只作漂移证据；`customer_id` 才是权威值）。
    /// 页面用它告诉操作员「网关实际报了什么」，免得只能上机查。
    #[serde(default)]
    pub reported_tenant_id: Option<String>,
}

/// 实例视图（列表与归档回执共用一份）：`init_url` 由中心对外地址派生。
fn gateway_instance_view(
    state: &ApiState,
    gateway: StoredGateway,
    binding: Option<&GatewayCustomerBindingRecord>,
) -> AdminGatewayInstanceView {
    let init_url = format!(
        "{}/api/v1/gateway/link-upstream?gateway_id={}",
        state.config.public_url.trim_end_matches('/'),
        gateway.gateway_id
    );
    AdminGatewayInstanceView {
        gateway_id: gateway.gateway_id,
        instance_id: gateway.instance_id,
        lifecycle_state: gateway
            .lifecycle_state
            .unwrap_or(GatewayInstanceLifecycleState::Provisioned),
        created_at: gateway.created_at.unwrap_or_else(DateTime::now),
        initialized_at: gateway.initialized_at,
        init_url,
        archived_at: gateway.archived_at,
        customer_id: binding.map(|binding| binding.customer_id.clone()),
        binding_status: binding.map(|binding| binding.status.clone()),
        binding_revision: binding.map(|binding| binding.revision),
        applied_revision: binding.and_then(|binding| binding.applied_revision),
        applied_at: binding.and_then(|binding| binding.applied_at.clone()),
        binding_last_error: binding.and_then(|binding| binding.last_error.clone()),
        reported_tenant_id: binding.and_then(|binding| binding.reported_tenant_id.clone()),
    }
}

/// 列表类查询的共用开关：是否把**已归档**的记录（网关 / 执行计划）也带上（默认不带）。
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct IncludeArchivedQuery {
    #[serde(default)]
    pub include_archived: bool,
}

/// 归档 / 取消归档的请求体（`POST /api/v1/admin/gateways/{gateway_id}/archive`）。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SetGatewayArchivedRequest {
    /// `true` = 归档（默认视图不再显示这台网关）；`false` = 取消归档。
    pub archived: bool,
}

/// 注册 Token 管理视图：只公开状态/限量/有效期，不暴露 token_hash。
/// 创建网关实例：POST /api/v1/admin/gateways/instances。
/// gateway_id 由 gateway_name 派生；重复 → 409。
pub async fn admin_create_gateway_instance(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<AdminCreateGatewayInstanceRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateway_id = request.gateway_name.trim();
    if gateway_id.is_empty() || request.requested_by.trim().is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::GATEWAY_NAME_AND_REQUESTED_BY_REQUIRED,
            "gateway_name and requested_by must not be empty",
        )
        .into_response();
    }
    // 设计 §8：接入凭据**不在 create 响应里交付** —— create 只建实例；明文接入券由
    // 「生成/轮换」（POST .../link-token）产出、页面一次性展示（短 TTL）。
    match state.store.create_gateway(gateway_id, "").await {
        Ok(stored) => (
            StatusCode::CREATED,
            Json(AdminCreateGatewayInstanceReturned {
                instance: GatewayInstance {
                    gateway_id: stored.gateway_id,
                    instance_id: stored.instance_id,
                    lifecycle_state: GatewayInstanceLifecycleState::Provisioned,
                    created_at: DateTime::now(),
                    initialized_at: None,
                },
            }),
        )
            .into_response(),
        Err(err) if err.reason() == &StoreReason::Conflict => super::error::ApiError::conflict(
            super::codes::GATEWAY_ALREADY_EXISTS,
            format!("gateway {gateway_id} already exists"),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::GATEWAY_CREATE_FAILED,
            "failed to create gateway",
            err.display_chain(),
        ),
    }
}

/// 构造安装指引：init_url（不携带凭证）+ docker 安装命令 + 信任根挂载 + curl 验证命令。
/// 由「生成/轮换」（link-token）端点使用；`link_token` 以明文随响应一次性交付。
fn build_install_info(state: &ApiState, gateway_id: &str, link_token: &str) -> GatewayInstallInfo {
    let init_endpoint = format!(
        "{}/api/v1/gateway/link-upstream?gateway_id={}",
        state.config.public_url.trim_end_matches('/'),
        gateway_id
    );
    // init_url 不携带凭证：link token 不进 URL（避免泄露到历史/分享链接）。
    let init_url = init_endpoint.clone();
    // 信任根：config.toml 引用 /etc/wist-gateway/ca/control-center.pem，需把
    // control-center.pem（trust_bundle_pem 内容落盘为 ./control-center.pem）挂载到该路径，
    // 网关访问 HTTPS init_url 时才能校验中心 TLS 服务器证书。未配置 CA → 不挂载（无 TLS 回退）。
    let trust_bundle_mount = if state.config.ca_cert.is_some() {
        " -v ./control-center.pem:/etc/wist-gateway/ca/control-center.pem:ro".to_string()
    } else {
        String::new()
    };
    // 服务端生成 curl 验证命令：Bearer 用接入 token + 网关自生成身份调 init_url。
    let init_curl = format!(
        "curl -H \"Authorization: Bearer {link_token}\" -H \"X-Gateway-Identity-Token: <gateway-identity>\" \"{init_endpoint}\""
    );
    // 安装命令只负责把网关镜像拉起来（含信任根挂载）—— **不再向容器注入接入券/初始化 URL**：
    // 首跑接入由宿主侧 `wist-gwlinkd` 承载（设计 `gateway-secure-registration.md` §6「集成发起方」），
    // 容器启动本身不需要接入券。
    GatewayInstallInfo {
        install_command: format!(
            "docker run -d --name wist-gateway-{gw}{trust_mount} {image}",
            gw = gateway_id,
            trust_mount = trust_bundle_mount,
            image = state.config.gateway_image
        ),
        cloud_image: state.config.gateway_image.clone(),
        init_url,
        link_token: link_token.to_string(),
        trust_bundle_pem: state.config.ca_cert.clone(),
        init_curl,
        install_all_command: super::install::build_install_all_command(
            &state.config.public_url,
            gateway_id,
            link_token,
        ),
        prepare_command: super::install::build_prepare_script_command(&state.config.public_url),
        install_linkd_command: super::install::build_install_linkd_command(
            &state.config.public_url,
            gateway_id,
            link_token,
        ),
    }
}

/// 轮换接入券 请求体：`requested_by` 记录操作人（审计）。
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRotateGatewayLinkTokenRequest {
    pub requested_by: String,
}

/// 轮换/生成接入券 返回：新的安装指引（含一次性明文 `link_token`）+ 到期时刻。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AdminRotateGatewayLinkTokenReturned {
    pub gateway_id: String,
    pub install: GatewayInstallInfo,
    /// 接入券到期时刻（RFC3339）——**短 TTL**，过期即不可用（需重新轮换）。
    #[serde(default)]
    pub link_expires_at: Option<String>,
}

/// 计算接入券到期时刻（RFC3339）：`security.link_ttl_seconds`（默认 15 分钟）。
fn link_expires_at(ttl_seconds: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(ttl_seconds)).to_rfc3339()
}

/// 生成/轮换一次性接入券：POST /api/v1/admin/gateways/{gateway_id}/link-token。
/// 生成新 LINK_TOKEN 并覆盖中心存的 hash + 短 TTL（旧券立即失效），明文仅随本次响应交付一次。
pub async fn admin_rotate_gateway_link_token(
    State(state): State<ApiState>,
    Path(gateway_id): Path<String>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<AdminRotateGatewayLinkTokenRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateway_id = gateway_id.trim();
    if gateway_id.is_empty() || request.requested_by.trim().is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::GATEWAY_ID_AND_REQUESTED_BY_REQUIRED,
            "gateway_id and requested_by must not be empty",
        )
        .into_response();
    }
    let token = match crate::infra::new_secret_token("link") {
        Ok(token) => token,
        Err(reason) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::LINK_TOKEN_GENERATION_FAILED,
                "failed to generate link token",
                reason,
            );
        }
    };
    let expires_at = link_expires_at(state.config.link_ttl_seconds);
    match state
        .store
        .rotate_link_token(
            gateway_id,
            &crate::infra::sha256_hex(&token),
            Some(expires_at.clone()),
        )
        .await
    {
        Ok(true) => {
            let install = build_install_info(&state, gateway_id, &token);
            // 含一次性明文接入券 → `no-store`。
            super::error::json_no_store(AdminRotateGatewayLinkTokenReturned {
                gateway_id: gateway_id.to_string(),
                install,
                link_expires_at: Some(expires_at),
            })
        }
        Ok(false) => super::error::ApiError::not_found(
            super::codes::GATEWAY_NOT_FOUND,
            format!("gateway {gateway_id} not found"),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::SETUP_TOKEN_ROTATE_FAILED,
            "failed to rotate setup token",
            err.display_chain(),
        ),
    }
}

/// 网关在线率查询参数（默认 1h 窗口）。
#[derive(serde::Deserialize)]
pub struct GatewayUptimeQueryParams {
    pub window: Option<String>,
}

/// 网关在线率返回（0..1；无历史数据或 VM 不可达 → None）。
#[derive(serde::Serialize)]
pub struct GatewayUptimeReturned {
    pub gateway_id: String,
    pub window: String,
    pub uptime: Option<f64>,
}

/// 网关历史查询参数；当前控制台使用 1h，保留 6h/24h 供后续切换。
#[derive(serde::Deserialize)]
pub struct GatewayHistoryQueryParams {
    pub window: Option<String>,
}

/// 网关历史接口返回，采样来自 VictoriaMetrics range query。
#[derive(serde::Serialize)]
pub struct GatewayHistoryReturned {
    pub gateway_id: String,
    pub window: String,
    pub step_seconds: i64,
    pub samples: Vec<crate::infra::vm::GatewayMetricSample>,
}

/// 单个 Agent 历史接口返回。
#[derive(serde::Serialize)]
pub struct AgentHistoryReturned {
    pub gateway_id: String,
    pub agent_id: String,
    pub window: String,
    pub step_seconds: i64,
    pub samples: Vec<crate::infra::vm::AgentMetricSample>,
}

/// 查询网关在线率：GET /api/v1/admin/gateways/:gateway_id/status/uptime。
/// 转发 VM `avg_over_time(gateway_up{gateway_id="X"}[window])`；
/// VM 未配置 / 查询失败 / 无历史样本 → uptime None（HTTP 200，列表页平滑显示"—"）。
pub async fn admin_get_gateway_uptime(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
    ApiQuery(params): ApiQuery<GatewayUptimeQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let window = params.window.as_deref().unwrap_or("1h");
    let uptime = match &state.config.victoriametrics_url {
        Some(vm_url) => {
            match crate::infra::vm::query_uptime(
                crate::infra::vm::shared_vm_client(),
                vm_url,
                &gateway_id,
                window,
            )
            .await
            {
                Ok(uptime) => uptime,
                Err(err) => {
                    log::warn!("gateway uptime vm query failed: {err}");
                    None
                }
            }
        }
        None => None,
    };
    Json(GatewayUptimeReturned {
        gateway_id,
        window: window.to_string(),
        uptime,
    })
    .into_response()
}

/// 查询网关最近一段时间的在线、内存和 CPU 历史。
///
/// VM 未配置或暂时不可用时返回空 samples，页面保留快照并显示历史空态。
pub async fn admin_get_gateway_history(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
    ApiQuery(params): ApiQuery<GatewayHistoryQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let window = params.window.as_deref().unwrap_or("1h");
    let Some((window_seconds, step_seconds)) = history_window_config(window) else {
        return super::error::ApiError::bad_request(
            super::codes::INVALID_WINDOW,
            "window must be one of: 1h, 6h, 24h",
        )
        .into_response();
    };
    let now = chrono::Utc::now().timestamp();
    let end = now - now.rem_euclid(step_seconds);
    let start = end - window_seconds;
    let samples = match &state.config.victoriametrics_url {
        Some(vm_url) => match crate::infra::vm::query_gateway_history(
            crate::infra::vm::shared_vm_client(),
            vm_url,
            &gateway_id,
            start,
            end,
            step_seconds,
        )
        .await
        {
            Ok(samples) => samples,
            Err(err) => {
                log::warn!("gateway history vm query failed: {err}");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    Json(GatewayHistoryReturned {
        gateway_id,
        window: window.to_string(),
        step_seconds,
        samples,
    })
    .into_response()
}

/// 查询单个 Agent 最近一段时间的在线、内存、CPU 和管理时延历史。
pub async fn admin_get_agent_history(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path((gateway_id, agent_id)): Path<(String, String)>,
    ApiQuery(params): ApiQuery<GatewayHistoryQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let window = params.window.as_deref().unwrap_or("1h");
    let Some((window_seconds, step_seconds)) = history_window_config(window) else {
        return super::error::ApiError::bad_request(
            super::codes::INVALID_WINDOW,
            "window must be one of: 1h, 6h, 24h",
        )
        .into_response();
    };
    let now = chrono::Utc::now().timestamp();
    let end = now - now.rem_euclid(step_seconds);
    let start = end - window_seconds;
    let samples = match &state.config.victoriametrics_url {
        Some(vm_url) => match crate::infra::vm::query_agent_history(
            crate::infra::vm::shared_vm_client(),
            vm_url,
            &gateway_id,
            &agent_id,
            start,
            end,
            step_seconds,
        )
        .await
        {
            Ok(samples) => samples,
            Err(err) => {
                log::warn!("agent history vm query failed: {err}");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    Json(AgentHistoryReturned {
        gateway_id,
        agent_id,
        window: window.to_string(),
        step_seconds,
        samples,
    })
    .into_response()
}

/// 将公开窗口收敛为固定秒数和采样步长，避免把任意字符串带入 PromQL。
fn history_window_config(window: &str) -> Option<(i64, i64)> {
    match window {
        "1h" => Some((60 * 60, 60)),
        "6h" => Some((6 * 60 * 60, 5 * 60)),
        "24h" => Some((24 * 60 * 60, 15 * 60)),
        _ => None,
    }
}

/// TOML 基础字符串转义（镜像 wist-gateway 的 toml_escape）：
/// 保证任意 token / 端点字符串嵌入 config.toml 双引号字符串后仍是合法 TOML。
#[cfg(test)]
fn toml_basic_string_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04X}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

/// 对 URL fragment 值做百分号编码，确保任意凭证不会截断或改写初始化 URL。
/// 实例列表：GET /api/v1/admin/gateways/instances（含生命周期状态）。
///
/// 默认**不带**已归档的实例（`?include_archived=true` 才带）—— 归档就是为了把死掉的网关从日常
/// 视图里收起来；要看/恢复它们时再显式带上。
pub async fn admin_list_gateway_instances(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<IncludeArchivedQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateways = match state.store.list_gateways().await {
        Ok(gateways) => gateways,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_INSTANCES_LOAD_FAILED,
                "failed to load gateway instances",
                err.display_chain(),
            );
        }
    };
    let instances: Vec<AdminGatewayInstanceView> = {
        let bindings = match state.store.list_customer_bindings().await {
            Ok(bindings) => bindings
                .into_iter()
                .map(|binding| (binding.gateway_id.clone(), binding))
                .collect::<std::collections::HashMap<_, _>>(),
            Err(err) => {
                log::warn!("load customer bindings failed: {}", err.display_chain());
                std::collections::HashMap::new()
            }
        };
        gateways
            .into_iter()
            .filter(|gateway| query.include_archived || gateway.archived_at.is_none())
            .map(|gateway| {
                let binding = bindings.get(&gateway.gateway_id);
                gateway_instance_view(&state, gateway, binding)
            })
            .collect()
    };
    Json(instances).into_response()
}

/// 归档 / 取消归档一台网关：`POST /api/v1/admin/gateways/{gateway_id}/archive`。
///
/// 归档是**标记**（`archived_at`）：默认视图不再显示这台网关，状态、历史、生命周期记录全留；
/// `{"archived": false}` 随时恢复。**只允许归档离线网关** —— 在线的不该被藏起来（要停就先在网关上
/// 停掉）；网关重新上线（换证注册，或重新上报 online）时归档会自动清空（见 `infra::store`）。
pub async fn admin_set_gateway_archived(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
    ApiJson(request): ApiJson<SetGatewayArchivedRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateway_id = gateway_id.trim().to_string();
    let stored = match state.store.get_gateway(&gateway_id).await {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return super::error::ApiError::not_found(
                super::codes::GATEWAY_NOT_FOUND,
                format!("unknown gateway {gateway_id}"),
            )
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_LOAD_FAILED,
                "failed to load gateway",
                err.display_chain(),
            );
        }
    };
    if request.archived && gateway_is_online(&stored) {
        return super::error::ApiError::conflict(
            super::codes::GATEWAY_ONLINE_CANNOT_ARCHIVE,
            format!("gateway {gateway_id} is online; only an offline gateway can be archived"),
        )
        .into_response();
    }
    // 取消归档时清成 `None`；归档时落当下时刻（重复点归档不刷新时刻：幂等，便于审计「什么时候收的」）。
    let archived_at = if request.archived {
        stored.archived_at.clone().or_else(|| Some(DateTime::now()))
    } else {
        None
    };
    match state
        .store
        .set_gateway_archived(&gateway_id, archived_at.clone())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return super::error::ApiError::not_found(
                super::codes::GATEWAY_NOT_FOUND,
                format!("unknown gateway {gateway_id}"),
            )
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_ARCHIVE_FAILED,
                "failed to archive gateway",
                err.display_chain(),
            );
        }
    }
    // 回执带上这台实例的最新视图（页面据此就地显示「已归档 / 取消归档」）。
    match state.store.get_gateway(&gateway_id).await {
        Ok(Some(stored)) => {
            let binding = match state.store.get_customer_binding(&stored.gateway_id).await {
                Ok(binding) => binding,
                Err(err) => {
                    log::warn!("load customer binding failed: {}", err.display_chain());
                    None
                }
            };
            Json(gateway_instance_view(&state, stored, binding.as_ref())).into_response()
        }
        _ => Json(serde_json::json!({
            "gateway_id": gateway_id,
            "archived_at": archived_at,
        }))
        .into_response(),
    }
}

/// 版本发布请求体：**来源**（本机绝对路径 或 https URL；中心读进本地/对象存储镜像）。
///
/// `artifact_url` 沿用原名以兼容既有调用方，但其语义是**来源**（与 gateway 的 agent 包来源同口径）：
/// 可以是 `/abs/path`，也可以是外部 URL。
/// `expected_sha256`（**必填**）：核对读到的内容摘要，不符即拒 —— 包没有可校验的摘要就不收。
/// `version`（可选）：**不填**就由包地址（文件名 / 包内目录名）自动解析，见 `infra/package.rs`；
/// 填了会与解析出的版本**核对**（不一致 → 400）。
/// 镜像后落库 / 下发用**来源原名**（URL 末段）；内容寻址靠 `package_sha256` + 幂等。
#[derive(serde::Deserialize)]
pub struct PublishReleaseRequest {
    #[serde(default)]
    pub version: Option<String>,
    pub artifact_url: String,
    pub expected_sha256: String,
    pub requested_by: String,
}

// 制品落盘 / 下发文件名（取来源末段原名，危险名 / 取不到就回落 `{component}-{version}.bin`）
// 已收进共享 crate `wist-release`，经 `crate::infra::artifact_filename` 转出 —— 本文件直接调它，
// 不再自留一份（原先这里的副本是抽取时漏删的）。

/// 发布版本：POST /api/v1/admin/releases/:component（wist-agentd / wist-gateway-stack / galaxy-ops / galaxy-flow）。
///
/// **异步**：这里只做不需要下载的入参校验，随即落一条下载任务并返回 `202 Accepted` +
/// [`crate::infra::ReleaseJobPayload`]；真正的「取包 → 核对摘要 → 镜像 → 落库」由
/// [`crate::infra::JobQueue`] 的 `release-download` handler 串行完成。调用方用
/// `GET /api/v1/admin/release-jobs/{job_id}` 查进度。
pub async fn admin_publish_release(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(component): Path<String>,
    ApiJson(request): ApiJson<PublishReleaseRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 组件名要拼进制品目录（`{artifact_dir}/{component}/{version}/{filename}`）与下发 URL：
    // 必须是**真的只有一段**，否则 `..` / 绝对路径会逃出制品目录。
    if !crate::infra::is_safe_path_segment(&component) {
        return super::error::ApiError::bad_request(
            super::codes::INVALID_COMPONENT,
            "component must be a single safe path segment",
        )
        .into_response();
    }
    let expected_sha256 = request.expected_sha256.trim();
    if request.artifact_url.trim().is_empty()
        || request.requested_by.trim().is_empty()
        || expected_sha256.is_empty()
    {
        return super::error::ApiError::bad_request(
            super::codes::ARTIFACT_FIELDS_REQUIRED,
            "artifact_url, expected_sha256 and requested_by must not be empty",
        )
        .into_response();
    }
    // 「组件 ↔ 包」的来源侧预检：来源文件名就能看出是别的组件 → 立刻拒，**不排队**。
    if let Some(detail) = crate::infra::source_component_mismatch(&component, &request.artifact_url)
    {
        return super::error::ApiError::bad_request(
            super::codes::ARTIFACT_COMPONENT_MISMATCH,
            detail,
        )
        .into_response();
    }
    let declared_version = request
        .version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let job = match build_release_job(crate::infra::ReleaseJobPayload {
        mode: crate::infra::RELEASE_JOB_PUBLISH.to_string(),
        component: component.clone(),
        requested_by: request.requested_by.trim().to_string(),
        declared_version,
        artifacts: vec![crate::infra::ReleaseJobArtifact {
            artifact_url: request.artifact_url.clone(),
            expected_sha256: expected_sha256.to_string(),
        }],
    }) {
        Ok(job) => job,
        Err(response) => return response,
    };
    enqueue_release_job(&state, job, !prefers_async(&headers)).await
}

/// 批量录入请求体：多平台组件（galaxy-ops / galaxy-flow）一次覆盖三个平台。
/// 平台由包自身解析，不由请求声明。
#[derive(serde::Deserialize)]
pub struct BatchPublishReleaseRequest {
    pub requested_by: String,
    pub artifacts: Vec<BatchArtifact>,
}

/// 批量录入里的单个制品。
#[derive(serde::Deserialize)]
pub struct BatchArtifact {
    pub artifact_url: String,
    pub expected_sha256: String,
}

/// 批量录入某组件的多平台制品：POST /api/v1/admin/releases/:component/batch。
///
/// 一次请求覆盖**同一版本**的多个平台（wist-agentd / galaxy-ops / galaxy-flow 必须
/// macOS-ARM / Linux-ARM / Linux-X86 三平台齐备）。所有制品先**下载 + 校验摘要 + 解析身份**，
/// 任一不合格即整体拒绝（**不落任何记录**）；全部通过后再逐个镜像落库。
/// 批量录入某组件的多平台制品：POST /api/v1/admin/releases/:component/batch。
///
/// **异步**：与单制品发布同一套下载队列。这里只校验入参（组件 / 平台来源预检 / 摘要必填），
/// 落一条 `publish_batch` 任务后立即返回 `202 Accepted`；worker 会先全部下载 + 校验 + 解析身份，
/// 任一不合格即整体失败（不落任何发布记录），全部通过后再逐个镜像落库。
pub async fn admin_publish_release_batch(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(component): Path<String>,
    ApiJson(request): ApiJson<BatchPublishReleaseRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if !crate::infra::is_safe_path_segment(&component) {
        return super::error::ApiError::bad_request(
            super::codes::INVALID_COMPONENT,
            "component must be a single safe path segment",
        )
        .into_response();
    }
    if request.requested_by.trim().is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::REQUESTED_BY_REQUIRED,
            "requested_by must not be empty",
        )
        .into_response();
    }
    if request.artifacts.is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::ARTIFACTS_REQUIRED,
            "artifacts must not be empty",
        )
        .into_response();
    }

    let mut jobs = Vec::with_capacity(request.artifacts.len());
    for artifact in &request.artifacts {
        let expected = artifact.expected_sha256.trim();
        if artifact.artifact_url.trim().is_empty() || expected.is_empty() {
            return super::error::ApiError::bad_request(
                super::codes::ARTIFACT_URL_AND_SHA256_REQUIRED,
                "artifact_url and expected_sha256 must not be empty",
            )
            .into_response();
        }
        // 下载前先按**来源文件名**扫一遍「组件 ↔ 包」：任一个明显是别的组件即整体拒，**不排队**。
        if let Some(detail) =
            crate::infra::source_component_mismatch(&component, &artifact.artifact_url)
        {
            return super::error::ApiError::bad_request(
                super::codes::ARTIFACT_COMPONENT_MISMATCH,
                detail,
            )
            .into_response();
        }
        jobs.push(crate::infra::ReleaseJobArtifact {
            artifact_url: artifact.artifact_url.clone(),
            expected_sha256: expected.to_string(),
        });
    }

    let job = match build_release_job(crate::infra::ReleaseJobPayload {
        mode: crate::infra::RELEASE_JOB_PUBLISH_BATCH.to_string(),
        component: component.clone(),
        requested_by: request.requested_by.trim().to_string(),
        declared_version: None,
        artifacts: jobs,
    }) {
        Ok(job) => job,
        Err(response) => return response,
    };
    enqueue_release_job(&state, job, !prefers_async(&headers)).await
}

/// 把业务载荷包成通用任务（序列化失败也是入队失败）。
#[allow(clippy::result_large_err)]
fn build_release_job(
    payload: crate::infra::ReleaseJobPayload,
) -> Result<crate::infra::JobRecord, Response> {
    crate::infra::release_job(payload).map_err(|err| {
        super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::RELEASE_JOB_CREATE_FAILED,
            "failed to build release job",
            err.display_chain(),
        )
    })
}

/// `Prefer: respond-async` → 只入队并回 `202`（中心前端用这个）。
///
/// 不带该头的老调用方走**兼容等待**：同样入队、由 worker 执行，但请求会等到任务终态再把
/// 结果折回旧形状（成功 = 安装包，失败 = 原来的状态码 / 错误码）—— 下载仍然走队列，只是旧
/// 客户端不必改。
fn prefers_async(headers: &HeaderMap) -> bool {
    headers
        .get("prefer")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("respond-async"))
}

/// 同步兼容模式最长等多久（批量三平台 × 取包超时也要留余量）。
const RELEASE_JOB_SYNC_WAIT: Duration = Duration::from_secs(15 * 60);

/// 落一条下载任务并返回：异步模式 `202 + job`；兼容模式等终态后折回旧形状。
async fn enqueue_release_job(
    state: &ApiState,
    job: crate::infra::JobRecord,
    wait: bool,
) -> Response {
    let job = match state.jobs.enqueue(job).await {
        Ok(job) => job,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::RELEASE_JOB_CREATE_FAILED,
                "failed to enqueue release job",
                err.display_chain(),
            );
        }
    };
    if !wait {
        return match crate::infra::ReleaseJobView::from_job(&job) {
            Some(view) => (StatusCode::ACCEPTED, Json(view)).into_response(),
            None => super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::RELEASE_JOB_CREATE_FAILED,
                "enqueued release job is not readable",
                job.job_id,
            ),
        };
    }
    match state
        .jobs
        .wait_for_terminal(&job.job_id, RELEASE_JOB_SYNC_WAIT)
        .await
    {
        Ok(Some(done)) if done.state == crate::infra::JOB_SUCCEEDED => {
            match done.result.as_ref().and_then(|value| {
                serde_json::from_value::<crate::infra::ReleasePackageRecord>(value.clone()).ok()
            }) {
                Some(package) => Json(package).into_response(),
                None => super::error::internal_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    super::codes::RELEASE_NOT_FOUND_AFTER_WRITE,
                    "release job succeeded without a package",
                    done.job_id,
                ),
            }
        }
        Ok(Some(done)) if done.state == crate::infra::JOB_CANCELED => {
            super::error::ApiError::conflict(
                super::codes::JOB_CANCELED,
                format!("release job {} was canceled", done.job_id),
            )
            .into_response()
        }
        Ok(Some(done)) => {
            let status = done
                .error_status
                .and_then(|value| StatusCode::from_u16(value).ok())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let code = done
                .error_code
                .clone()
                .unwrap_or_else(|| super::codes::ARTIFACT_FETCH_FAILED.to_string());
            let message = done.error_detail.clone().unwrap_or_default();
            super::error::ApiError::new(status, code, message).into_response()
        }
        Ok(None) => super::error::ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            super::codes::RELEASE_JOB_TIMEOUT,
            format!(
                "release job {} is still running; poll GET /api/v1/admin/release-jobs/{}",
                job.job_id, job.job_id
            ),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::RELEASE_JOBS_LOAD_FAILED,
            "failed to load release job",
            err.display_chain(),
        ),
    }
}

/// 查一条下载任务：`GET /api/v1/admin/release-jobs/{job_id}`。
///
/// `state` = `queued` / `running` / `succeeded` / `failed`；成功回执带发布后的安装包视图，
/// 失败回执带 `error_code` / `error_detail`。
pub async fn admin_get_release_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(job_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let job_id = job_id.trim().to_string();
    match state.jobs.get(&job_id).await {
        Ok(Some(job)) => match crate::infra::ReleaseJobView::from_job(&job) {
            Some(view) if job.queue == crate::infra::RELEASE_JOB_QUEUE => {
                Json(view).into_response()
            }
            _ => super::error::ApiError::not_found(
                super::codes::RELEASE_JOB_NOT_FOUND,
                format!("unknown release job {job_id}"),
            )
            .into_response(),
        },
        Ok(None) => super::error::ApiError::not_found(
            super::codes::RELEASE_JOB_NOT_FOUND,
            format!("unknown release job {job_id}"),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::RELEASE_JOBS_LOAD_FAILED,
            "failed to load release job",
            err.display_chain(),
        ),
    }
}

/// 下载任务列表的查询参数。
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ReleaseJobsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    /// 只看某个组件（录入页按当前 tab 取）。
    #[serde(default)]
    pub component: Option<String>,
}

/// 最近的下载任务：`GET /api/v1/admin/release-jobs?limit=&component=`（新→旧）。
///
/// 任务列表是「队列进度」的主要视图：页面刷新后也能看到在飞 / 失败的下载，不必守着提交时的
/// 那一次请求。默认 20 条，最多 200 条。
pub async fn admin_list_release_jobs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<ReleaseJobsQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let limit = query.limit.unwrap_or(20).clamp(1, 200);
    let component = query
        .component
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match state
        .store
        .list_jobs_filtered(
            Some(crate::infra::RELEASE_JOB_QUEUE),
            None,
            None,
            component,
            limit,
        )
        .await
    {
        Ok(jobs) => Json(
            jobs.iter()
                .filter_map(crate::infra::ReleaseJobView::from_job)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::RELEASE_JOBS_LOAD_FAILED,
            "failed to load release jobs",
            err.display_chain(),
        ),
    }
}
/// 通用任务列表的查询参数。
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct JobsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    /// 按队列过滤（如 `release-download`）。
    #[serde(default)]
    pub queue: Option<String>,
    /// 按 handler kind 过滤。
    #[serde(default)]
    pub kind: Option<String>,
    /// 按状态过滤（`queued` / `running` / `succeeded` / `failed` / `canceled`）。
    #[serde(default)]
    pub state: Option<String>,
    /// 按业务主体过滤（release 任务的主体是 component）。
    #[serde(default)]
    pub subject: Option<String>,
}

/// 通用任务读面：`GET /api/v1/admin/jobs?queue=&kind=&state=&limit=`（新→旧）。
///
/// 只读、只暴露任务本身（`payload` / `result` / `progress` / `error_*`）；各域自己的
/// 形状（如 `/release-jobs`）仍由领域端点提供。默认 20 条，最多 200 条。
pub async fn admin_list_jobs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<JobsQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let limit = query.limit.unwrap_or(20).clamp(1, 200);
    let normalized = |value: Option<String>| {
        value
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let queue = normalized(query.queue);
    let kind = normalized(query.kind);
    let state_filter = normalized(query.state);
    let subject = normalized(query.subject);
    match state
        .store
        .list_jobs_filtered(
            queue.as_deref(),
            kind.as_deref(),
            state_filter.as_deref(),
            subject.as_deref(),
            limit,
        )
        .await
    {
        Ok(jobs) => Json(jobs).into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::JOBS_LOAD_FAILED,
            "failed to load jobs",
            err.display_chain(),
        ),
    }
}

/// 通用任务详情：`GET /api/v1/admin/jobs/{job_id}`。
pub async fn admin_get_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(job_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let job_id = job_id.trim().to_string();
    match state.jobs.get(&job_id).await {
        Ok(Some(job)) => Json(job).into_response(),
        Ok(None) => super::error::ApiError::not_found(
            super::codes::JOB_NOT_FOUND,
            format!("unknown job {job_id}"),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::JOBS_LOAD_FAILED,
            "failed to load job",
            err.display_chain(),
        ),
    }
}

/// 取消一条**排队中**的任务：`POST /api/v1/admin/jobs/{job_id}/cancel`。
///
/// 只受理 `queued`：已开始执行 / 已终结的任务回 409（带回当前状态），不会影响正在跑的工作。
pub async fn admin_cancel_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(job_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let job_id = job_id.trim().to_string();
    match state.jobs.cancel(&job_id).await {
        Ok(crate::infra::CancelOutcome::Canceled(job)) => Json(job).into_response(),
        Ok(crate::infra::CancelOutcome::NotCancelable(job)) => super::error::ApiError::conflict(
            super::codes::JOB_NOT_CANCELABLE,
            format!(
                "job {job_id} is {}, only a queued job can be canceled",
                job.state
            ),
        )
        .into_response(),
        Ok(crate::infra::CancelOutcome::NotFound) => super::error::ApiError::not_found(
            super::codes::JOB_NOT_FOUND,
            format!("unknown job {job_id}"),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::JOB_CANCEL_FAILED,
            "failed to cancel job",
            err.display_chain(),
        ),
    }
}

/// GitHub Release 解析请求体。
#[derive(serde::Deserialize)]
pub struct ResolveGitHubReleaseRequest {
    pub release_url: String,
}

/// 「自动探测最新版本」的查询参数。
#[derive(Debug, serde::Deserialize)]
pub struct PackageSourceLatestQuery {
    pub component: String,
    /// 已知版本（缺省取该组件最近一次录入的版本）。COS 侧从这里往后探测。
    #[serde(default)]
    pub base_version: Option<String>,
    /// 只查某个来源（`github` / `cos`）；缺省先 GitHub、再 COS。
    #[serde(default)]
    pub source: Option<String>,
}

/// 自动探测某组件的最新版本：GitHub 列 releases；只有 COS 时从已知版本往后探测。
///
/// 录入页不再要求每次都填版本号：第一次可以用 GitHub 的最新 release（或手工指定），
/// 之后用「已录入的最新版本」作为基准自动往前找。返回解析好的 assets，页面直接填表。
pub async fn admin_package_source_latest(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<PackageSourceLatestQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(source) = state
        .config
        .package_sources
        .iter()
        .find(|source| source.component == query.component)
    else {
        return super::error::ApiError::not_found(
            super::codes::PACKAGE_SOURCE_NOT_FOUND,
            "no package source configured for this component",
        )
        .into_response();
    };

    // `source` 只接受 github / cos；非法值 / 该来源未配置 → 400（而不是 502 让人以为网络问题）。
    let prefer = query
        .source
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (want_github, want_cos) = match prefer {
        None => (true, true),
        Some("github") => (true, false),
        Some("cos") => (false, true),
        Some(other) => {
            return super::error::ApiError::bad_request(
                super::codes::PACKAGE_SOURCE_NOT_CONFIGURED,
                format!("source must be `github` or `cos`: {other}"),
            )
            .into_response();
        }
    };
    if want_github && source.github_repo.is_none() {
        return super::error::ApiError::bad_request(
            super::codes::PACKAGE_SOURCE_NOT_CONFIGURED,
            "github source is not configured for this component",
        )
        .into_response();
    }
    if want_cos && (source.cos_bucket.is_none() || source.cos_prefix.is_none()) {
        return super::error::ApiError::bad_request(
            super::codes::PACKAGE_SOURCE_NOT_CONFIGURED,
            "cos source is not configured for this component",
        )
        .into_response();
    }

    let releases = match state.store.list_releases(&query.component).await {
        Ok(releases) => releases,
        Err(err) => {
            return super::error::ApiError::internal(
                super::codes::PACKAGE_SOURCE_CHECK_FAILED,
                "failed to load recorded releases",
                err,
            )
            .into_response();
        }
    };
    let recorded_latest = releases
        .iter()
        .max_by(|left, right| left.published_at.cmp(&right.published_at))
        .map(|release| release.version.clone());
    let base = query
        .base_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| recorded_latest.clone());
    let is_imported = |version: &str| {
        let version = version.trim().trim_start_matches('v');
        releases
            .iter()
            .any(|release| release.version.trim().trim_start_matches('v') == version)
    };

    let token = std::env::var("WIST_CENTER_GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok());
    // 记下 GitHub 侧的失败原因：到最后兜底 502 时带上，别只回一句泛泛的 “failed to check”。
    let mut github_error: Option<String> = None;

    // GitHub 优先：一次 API 请求就能拿到最新 tag，比 COS 逐个探测准。
    if want_github && let Some(repo) = source.github_repo.as_deref() {
        match crate::infra::list_github_releases(repo, token.as_deref(), 20).await {
            Ok(items) => {
                if let Some(latest) = items.first() {
                    let version = latest.tag.clone();
                    let up_to_date = base.as_deref().is_some_and(|base| {
                        base.trim().trim_start_matches('v')
                            == version.trim().trim_start_matches('v')
                    });
                    if up_to_date {
                        return Json(serde_json::json!({
                            "component": query.component,
                            "source": "github",
                            "base_version": base,
                            "version": version,
                            "imported": is_imported(&version),
                            "up_to_date": true,
                            "assets": [],
                        }))
                        .into_response();
                    }
                    let url = format!("https://github.com/{repo}/releases/tag/{version}");
                    match crate::infra::resolve_github_release(&url, token.as_deref()).await {
                        Ok(resolved) => {
                            return Json(serde_json::json!({
                                "component": query.component,
                                "source": "github",
                                "base_version": base,
                                "version": resolved.version,
                                "imported": is_imported(&resolved.version),
                                "up_to_date": false,
                                "assets": resolved.assets,
                            }))
                            .into_response();
                        }
                        Err(err) => {
                            github_error = Some(format!("resolve {url}: {err}"));
                            log::warn!("auto-detect latest: resolve {url} failed: {err}");
                        }
                    }
                }
            }
            Err(err) => {
                github_error = Some(format!("list {repo}: {err}"));
                log::warn!("auto-detect latest: list {repo} failed: {err}");
            }
        }
    }

    // COS 兜底：从已知版本往后逐个试（没有 List，只能按命名约定探测）。
    if want_cos
        && let (Some(bucket), Some(prefix)) =
            (source.cos_bucket.as_deref(), source.cos_prefix.as_deref())
    {
        let Some(base) = base else {
            return super::error::ApiError::bad_request(
                super::codes::PACKAGE_SOURCE_BASE_REQUIRED,
                "the first import needs a version: no recorded release to probe from",
            )
            .into_response();
        };
        let base_path = match source.cos_region.as_deref() {
            Some(region) => format!("https://{bucket}.cos.{region}.myqcloud.com/{prefix}"),
            None => format!("{bucket}/{prefix}"),
        };
        // 录入的版本号可能带/不带 `v`（知识库的包身份去掉了 v，COS 前缀仍带 v），两种都试；
        // 命中的那种前缀就是后续候选的写法。**基准不在 COS 上也要继续探**：COS 可能只保留了
        // 更新的版本（如录入的 v0.3.0 已不在，但 v0.4.0 / v0.5.0 在），此时靠 minor 探测找到。
        let mut base_variants = vec![base.clone()];
        if let Some(stripped) = base.strip_prefix('v') {
            if !stripped.is_empty() {
                base_variants.push(stripped.to_string());
            }
        } else {
            base_variants.push(format!("v{base}"));
        }
        let mut probe_base = base.clone();
        let mut base_found = false;
        for variant in &base_variants {
            if crate::infra::resolve_cos_path(&format!("{base_path}/{variant}"))
                .await
                .is_ok()
            {
                probe_base = variant.clone();
                base_found = true;
                break;
            }
        }
        // patch 优先，再 minor（跳版），最后 major；全部试完取最后一个命中（候选按版本递增）。
        let candidates = crate::infra::version_probe_candidates(&probe_base, 6, 4, 2);
        let mut found: Option<crate::infra::ResolvedRelease> = None;
        for candidate in &candidates {
            if let Ok(resolved) =
                crate::infra::resolve_cos_path(&format!("{base_path}/{candidate}")).await
            {
                found = Some(resolved);
            }
        }
        if let Some(resolved) = found {
            let imported = is_imported(&resolved.version);
            return Json(serde_json::json!({
                "component": query.component,
                "source": "cos",
                "base_version": base,
                "version": resolved.version,
                "imported": imported,
                "up_to_date": false,
                "assets": resolved.assets,
            }))
            .into_response();
        }
        if base_found {
            return Json(serde_json::json!({
                "component": query.component,
                "source": "cos",
                "base_version": base,
                "version": probe_base,
                "imported": is_imported(&probe_base),
                "up_to_date": true,
                "assets": [],
            }))
            .into_response();
        }
        return super::error::ApiError::handled(
            StatusCode::BAD_GATEWAY,
            super::codes::PACKAGE_SOURCE_CHECK_FAILED,
            "the recorded version was not found under the configured COS path and no newer candidate matched; check cos_bucket / cos_prefix",
        )
        .into_response();
    }

    let message = match github_error {
        Some(err) => format!("failed to check the latest package version: {err}"),
        None => "failed to check the latest package version".to_string(),
    };
    super::error::ApiError::handled(
        StatusCode::BAD_GATEWAY,
        super::codes::PACKAGE_SOURCE_CHECK_FAILED,
        message,
    )
    .into_response()
}

/// 安装包来源（`[packages.sources]`）：录入页据此把「版本号」拼成 GitHub Release 地址 / COS 路径。
///
/// 只返回位置，不返回任何凭据；没有配置时返回空数组（页面回落到手工粘贴地址）。
pub async fn admin_list_package_sources(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let sources: Vec<serde_json::Value> = state
        .config
        .package_sources
        .iter()
        .map(|source| {
            serde_json::json!({
                "component": source.component,
                "github_repo": source.github_repo,
                "cos_bucket": source.cos_bucket,
                "cos_prefix": source.cos_prefix,
                "cos_region": source.cos_region,
            })
        })
        .collect();
    Json(serde_json::json!({ "sources": sources })).into_response()
}

/// 解析 GitHub Release：POST /api/v1/admin/github-release/resolve。
/// 从 `https://github.com/<owner>/<repo>/releases/tag/<tag>` 拉出 tag（版本）与各平台制品地址（含 sha256）。
pub async fn admin_resolve_github_release(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<ResolveGitHubReleaseRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let release_url = request.release_url.trim();
    if release_url.is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::RELEASE_URL_REQUIRED,
            "release_url must not be empty",
        )
        .into_response();
    }
    // 可选 token：私有仓 / 提高匿名限流。优先专用名，其次通用名。
    let token = std::env::var("WIST_CENTER_GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok());
    match crate::infra::resolve_github_release(release_url, token.as_deref()).await {
        Ok(resolved) => Json(resolved).into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::BAD_GATEWAY,
            super::codes::RELEASE_RESOLVE_FAILED,
            "failed to resolve release",
            err,
        ),
    }
}

/// 腾讯 COS 路径解析请求体。
#[derive(serde::Deserialize)]
pub struct ResolveCosRequest {
    pub cos_path: String,
}

/// 解析腾讯 COS 路径：POST /api/v1/admin/cos/resolve。
/// 从 `github-1347593047/wist-gwlinkd/v0.9.3-alpha`（bucket + `component/version` 前缀）列出对象，
/// 返回每个制品的下载地址 / sha256 / 平台；镜像 GitHub resolver，供录入页一键填充多平台制品。
pub async fn admin_resolve_cos(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<ResolveCosRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let cos_path = request.cos_path.trim();
    if cos_path.is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::COS_PATH_REQUIRED,
            "cos_path must not be empty",
        )
        .into_response();
    }
    // 制品桶公有读：解析不需凭据，也不依赖中心的对象存储配置（见 `infra::cos`）。
    match crate::infra::resolve_cos_path(cos_path).await {
        Ok(resolved) => Json(resolved).into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::BAD_GATEWAY,
            super::codes::COS_RESOLVE_FAILED,
            "failed to resolve cos path",
            err,
        ),
    }
}

/// 查询某组件的发布记录：GET /api/v1/admin/releases/:component（新→旧）。
pub async fn admin_list_releases(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(component): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 与发布侧同一套口径：写不进去的组件名（不是单一段），也不该能被查到。
    if !crate::infra::is_safe_path_segment(&component) {
        return super::error::ApiError::bad_request(
            super::codes::INVALID_COMPONENT,
            "component must be a single safe path segment",
        )
        .into_response();
    }
    let releases = match state.store.list_releases(&component).await {
        Ok(releases) => releases,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::RELEASE_LIST_FAILED,
                "failed to load releases",
                err.display_chain(),
            );
        }
    };
    let mut packages = crate::infra::group_release_packages(&component, releases);
    // 列表读投影：按**当前中心版本**给每个包算一份兼容报告。网关侧的最终校验仍在
    // 包入库 / 计划批准时做（那里才知道每台网关的 version / gwlinkd_version）。
    let current = std::collections::BTreeMap::from([(
        "wist-center".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    )]);
    let checked_at = chrono::Utc::now().to_rfc3339();
    for package in &mut packages {
        package.compatibility = Some(wist_release::compat::check(
            package.compat.as_ref(),
            &package.component,
            &package.package.version,
            &current,
            &checked_at,
        ));
    }
    Json(packages).into_response()
}

/// 改托管状态请求体：`status` ∈ {published, expired}。
#[derive(serde::Deserialize)]
pub struct SetReleaseStatusRequest {
    pub status: String,
}

/// 更新某组件某版本的托管状态：
/// POST /api/v1/admin/releases/:component/:version/status（`published` = 已录入 / 在用；`expired` = 已过期 / 停用）。
pub async fn admin_set_release_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path((component, version)): Path<(String, String)>,
    ApiJson(request): ApiJson<SetReleaseStatusRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 与发布 / 查询同口径：组件名必须是单一段。版本号同样要进 where 条件，顺手挡掉异常值。
    if !crate::infra::is_safe_path_segment(&component) {
        return super::error::ApiError::bad_request(
            super::codes::INVALID_COMPONENT,
            "component must be a single safe path segment",
        )
        .into_response();
    }
    let status = request.status.trim();
    if status != "published" && status != "expired" {
        return super::error::ApiError::bad_request(
            super::codes::INVALID_RELEASE_STATUS,
            "status must be `published` or `expired`",
        )
        .into_response();
    }
    match state
        .store
        .set_release_status(&component, &version, status)
        .await
    {
        Ok(0) => {
            super::error::ApiError::not_found(super::codes::RELEASE_NOT_FOUND, "release not found")
                .into_response()
        }
        Ok(_) => {
            match crate::infra::load_release_package(state.store.as_ref(), &component, &version)
                .await
            {
                Ok(Some(package)) => Json(package).into_response(),
                Ok(None) => super::error::ApiError::not_found(
                    super::codes::RELEASE_NOT_FOUND,
                    "release not found",
                )
                .into_response(),
                Err(err) => super::error::internal_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    super::codes::RELEASE_LIST_FAILED,
                    "failed to load releases",
                    err.display_chain(),
                ),
            }
        }
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::RELEASE_STATUS_UPDATE_FAILED,
            "failed to update release status",
            err.display_chain(),
        ),
    }
}

/// 绑定客户请求体：对齐模型 AdminBindGatewayCustomer。
#[derive(serde::Deserialize)]
pub struct BindGatewayCustomerRequest {
    pub gateway_id: String,
    pub customer_id: String,
    pub requested_by: String,
}

/// 绑定网关到客户：POST /api/v1/admin/gateways/bind。
///
/// 绑定成功后：已初始化网关入队 `bind-tenant`（gwlinkd 落盘并上报生效）；
/// 未初始化网关不入队，由 `link-upstream` 的初始配置携带。
/// 审计（`requested_by`）在 store 的同一次原子写里完成，读旧值不再有竞态。
pub async fn admin_bind_gateway_customer(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<BindGatewayCustomerRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateway_id = request.gateway_id.trim();
    let customer_id = request.customer_id.trim();
    if gateway_id.is_empty() || customer_id.is_empty() || request.requested_by.trim().is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::GATEWAY_ID_CUSTOMER_ID_REQUESTED_BY_REQUIRED,
            "gateway_id, customer_id and requested_by must not be empty",
        )
        .into_response();
    }
    if !super::is_tag_safe(customer_id) {
        return super::error::ApiError::bad_request(
            super::codes::CUSTOMER_ID_NOT_TAG_SAFE,
            "customer_id must be 1..=64 chars of [A-Za-z0-9_.:/=@+,-] (it becomes a wparse tag value)",
        )
        .into_response();
    }
    // 不存在的网关不允许绑定（先创建实例）。
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            return super::error::ApiError::not_found(
                super::codes::GATEWAY_NOT_FOUND,
                format!("unknown gateway {gateway_id}"),
            )
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_LOAD_FAILED,
                "failed to load gateway",
                err.display_chain(),
            );
        }
    };
    let binding = match state
        .store
        .bind_gateway_customer(gateway_id, customer_id, request.requested_by.trim())
        .await
    {
        Ok(binding) => binding,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_BIND_FAILED,
                "failed to bind gateway customer",
                err.display_chain(),
            );
        }
    };
    // 已初始化才下发；未初始化由 link-upstream 的初始配置携带。下发失败不回滚绑定
    // （绑定是权威事实；网关可在下次绑定/重试时补偿）。
    if !gateway.credential_token_hash.is_empty() {
        match state.proxy.as_ref() {
            Some(proxy) => {
                let payload = serde_json::json!({
                    "tenant_id": binding.customer_id,
                    "revision": binding.revision,
                })
                .to_string();
                match proxy
                    .enqueue_control_with_body(
                        gateway_id,
                        crate::wparse_proxy::KIND_BIND_TENANT,
                        Some(&payload),
                    )
                    .await
                {
                    Ok((command_id, reused)) => log::info!(
                        "event=GatewayTenantBindEnqueued gateway_id={} customer_id={} revision={} command_id={} reused={}",
                        gateway_id,
                        binding.customer_id,
                        binding.revision,
                        command_id,
                        reused
                    ),
                    Err(err) => log::warn!(
                        "event=GatewayTenantBindEnqueueFailed gateway_id={} customer_id={} revision={} error={}",
                        gateway_id,
                        binding.customer_id,
                        binding.revision,
                        err
                    ),
                }
            }
            None => log::warn!(
                "event=GatewayTenantBindNotDispatched gateway_id={} reason=proxy_unavailable",
                gateway_id
            ),
        }
    }
    log::info!(
        "event=GatewayCustomerBound gateway_id={} customer_id={} requested_by={} revision={}",
        gateway_id,
        binding.customer_id,
        request.requested_by.trim(),
        binding.revision
    );
    Json(GatewayCustomerBinding {
        gateway_id: binding.gateway_id,
        customer_id: binding.customer_id,
        status: binding.status,
        bound_at: binding.bound_at,
        revision: binding.revision,
        applied_revision: binding.applied_revision,
        applied_at: binding.applied_at,
        last_error: binding.last_error,
    })
    .into_response()
}

/// 查询某网关最近一次 `bind-tenant` 命令：GET /api/v1/admin/gateways/:gateway_id/bind-command。
///
/// 绑定是**异步远程命令**：POST /bind 只返回绑定事实与“已下发/已生效”，命令本身的状态
/// （有没有被取走、回执是什么、数据面是否真生效）以前无处可看。
/// 页面用这个接口展示“下发记录”；`command` 为 `null` = 从未下发过。
pub async fn admin_latest_bind_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) =
        super::wparse_proxy_api::ensure_gateway_exists(&state, &gateway_id).await
    {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return super::wparse_proxy_api::proxy_unavailable();
    };
    match proxy.latest_bind_command(&gateway_id).await {
        Ok(command) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "gateway_id": gateway_id,
                "command": command,
            })),
        )
            .into_response(),
        Err(err) => super::error::ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::COMMAND_STORE_UNAVAILABLE,
            "failed to load bind command",
            err,
        )
        .into_response(),
    }
}

/// 查询网关初始配置（admin 侧）：GET /api/v1/admin/gateways/:gateway_id/config。
pub async fn admin_get_gateway_initial_config(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 配置引用该网关最近签发的一个注册 Token（config.toml [enrollment] token_id）。
    let enrollment_token_id = state
        .store
        .get_enrollment_token_for_gateway(&gateway_id)
        .await
        .ok()
        .flatten()
        .map(|token| token.token_id)
        .unwrap_or_default();
    let server_tls_required = control_center_tls_required(&state.config);
    let trust_bundle = build_control_center_trust_bundle(&state.config, &gateway_id);
    // 安全 #1（fail-closed）：TLS 开启但未配置信任根 → 拒绝服务。
    if server_tls_required && trust_bundle.is_none() {
        return super::error::ApiError::unavailable(
            super::codes::TLS_TRUST_ROOT_MISSING,
            "TLS is required but the control center trust root is not configured",
        )
        .into_response();
    }
    // 配置类响应（信任包 / 端点）→ `no-store`。
    let binding = match state.store.get_customer_binding(&gateway_id).await {
        Ok(binding) => binding,
        Err(err) => {
            log::warn!("load customer binding failed: {}", err.display_chain());
            None
        }
    };
    super::error::json_no_store(GatewayInitialConfig {
        gateway_id: gateway_id.clone(),
        control_center_endpoint: state.config.public_url.clone(),
        trust_bundle,
        server_tls_required,
        protocol_version: state.config.protocol_version.clone(),
        enrollment_token_id,
        tenant_id: binding.as_ref().map(|binding| binding.customer_id.clone()),
        binding_revision: binding.as_ref().map(|binding| binding.revision),
    })
}

/// 创建灰度发布计划：`POST /api/v1/admin/rollout-plans`（模型 `AdminCreateUpgradePlan`）。
///
/// 阶段由**服务端**按阶梯切（共享 crate `wist-release::rollout`），闸门固定：首段人工、其后全成功。
/// 入参形状的单一真源是模型 `Control.RolloutApp.AdminInterface`（与网关**同形**）。
pub async fn admin_create_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<rollout::CreateRolloutPlanRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 阶段切分：服务端权威。目标为空 / 阶段数为 0 / 阶段数大于台数都在这里被拒（具体 error 自带 code）。
    let record = match rollout::build_plan(&request) {
        Ok(record) => record,
        Err(error) => return error.into_response(),
    };
    // 目标存在性校验：与网关同款 —— 物化到不存在的网关只会静默落库、永不命中。
    let known = match state.store.list_gateways().await {
        Ok(gateways) => gateways
            .into_iter()
            .map(|gateway| gateway.gateway_id)
            .collect::<std::collections::HashSet<_>>(),
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_LIST_FAILED,
                "failed to list gateways",
                err.display_chain(),
            );
        }
    };
    let unknown: Vec<&str> = record
        .entries
        .iter()
        .map(|entry| entry.gateway_id.as_str())
        .filter(|gateway_id| !known.contains(*gateway_id))
        .collect();
    if !unknown.is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::UNKNOWN_TARGETS,
            format!("unknown target(s): {}", unknown.join(", ")),
        )
        .into_response();
    }
    // 逐台按它上报的 version / gwlinkd_version 检查包内 `compat.json`：
    // 不兼容就在**建计划时**拒绝，并点名是哪台、要先升哪个组件。
    match rollout::target_compatibility_errors(&state, &record).await {
        Ok(errors) if errors.is_empty() => {}
        Ok(errors) => {
            return super::error::ApiError::conflict(
                super::codes::ROLLOUT_TARGET_INCOMPATIBLE,
                errors.join("; "),
            )
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to check target compatibility",
                err,
            );
        }
    }
    match state.store.create_upgrade_plan(&record).await {
        Ok(plan) => (StatusCode::CREATED, Json(rollout::plan_view(&plan))).into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::ROLLOUT_CREATE_FAILED,
            "failed to create rollout plan",
            err.display_chain(),
        ),
    }
}

/// 列出灰度发布计划：`GET /api/v1/admin/rollout-plans`（模型 `AdminListUpgradePlans`）。
///
/// 默认**不带**已归档的执行记录（`?include_archived=true` 才带）—— 归档就是为了把历史计划
/// 从发布执行页收起来；要看/恢复它们时再显式带上。
pub async fn admin_list_upgrade_plans(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<IncludeArchivedQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_upgrade_plans().await {
        Ok(plans) => Json(
            plans
                .into_iter()
                .filter(|plan| query.include_archived || plan.archived_at.is_none())
                .map(|plan| rollout::plan_view(&plan))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::ROLLOUT_PLANS_LOAD_FAILED,
            "failed to load rollout plans",
            err.display_chain(),
        ),
    }
}

/// 归档 / 取消归档一份灰度发布计划（执行记录）：
/// `POST /api/v1/admin/rollout-plans/{plan_id}/archive`。
///
/// 归档是**标记**（`archived_at`）：默认列表不再显示它，计划与逐目标条目全留；
/// `{"archived": false}` 随时恢复。**只允许归档终结态**（completed / failed / canceled）——
/// draft / rolling 还在推进，藏起来会让人找不到「批准 / 推进」入口。
pub async fn admin_set_upgrade_plan_archived(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(plan_id): Path<String>,
    ApiJson(request): ApiJson<rollout::ArchiveRolloutPlanRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = plan_id.trim().to_string();
    let Some(mut plan) = (match state.store.get_upgrade_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err.display_chain(),
            );
        }
    }) else {
        return super::error::ApiError::not_found(
            super::codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    if request.archived && !rollout::is_terminal(&plan.status) {
        return super::error::ApiError::conflict(
            super::codes::PLAN_NOT_ARCHIVABLE,
            format!(
                "rollout plan {plan_id} is {}, only a finished plan can be archived",
                plan.status
            ),
        )
        .into_response();
    }
    // 重复归档不刷新时刻（幂等，便于审计「什么时候收的」）；取消归档清空标记。
    plan.archived_at = if request.archived {
        plan.archived_at.clone().or_else(|| Some(DateTime::now()))
    } else {
        None
    };
    if let Err(err) = state.store.save_upgrade_plan(&plan).await {
        return super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::ROLLOUT_PLAN_ARCHIVE_FAILED,
            "failed to archive rollout plan",
            err.display_chain(),
        );
    }
    Json(rollout::plan_view(&plan)).into_response()
}

/// **删除**一份执行记录：`DELETE /api/v1/admin/rollout-plans/{plan_id}`。
///
/// 与归档不同，删除是**物理删除**（计划 + 逐目标条目，不可恢复）—— 想留证据的请用归档。
/// 只受理**终结态**（completed / failed / canceled）：draft / rolling 还在推进，删掉会丢在飞的工作。
/// 回执是**被删前**的计划视图，便于调用方确认删的是哪一份。
pub async fn admin_delete_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(plan_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = plan_id.trim().to_string();
    let plan = match state.store.get_upgrade_plan(&plan_id).await {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            return super::error::ApiError::not_found(
                super::codes::ROLLOUT_PLAN_NOT_FOUND,
                format!("unknown rollout plan {plan_id}"),
            )
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err.display_chain(),
            );
        }
    };
    // 与归档同口径：只删终结态，执行中的计划还有在飞的工作。
    if !rollout::is_terminal(&plan.status) {
        return super::error::ApiError::conflict(
            super::codes::PLAN_NOT_DELETABLE,
            format!(
                "rollout plan {plan_id} is {}, only a finished plan can be deleted",
                plan.status
            ),
        )
        .into_response();
    }
    match state.store.delete_upgrade_plan(&plan_id).await {
        // 视图在删除**前**拍好：回执说的是「刚被删掉的那一份」。
        Ok(true) => Json(rollout::plan_view(&plan)).into_response(),
        // 读到之后被并发删掉：按不存在处理（幂等语义对调用方一致）。
        Ok(false) => super::error::ApiError::not_found(
            super::codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::ROLLOUT_PLAN_DELETE_FAILED,
            "failed to delete rollout plan",
            err.display_chain(),
        ),
    }
}

/// 批准灰度发布计划：`POST /api/v1/admin/rollout-plans/approve`（模型 `AdminApproveUpgradePlan`）。
/// `draft → rolling` 进入第一阶段（中心不物化工作，只开阶段闸门）。
pub async fn admin_approve_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<rollout::PlanRefRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = request.plan_id.trim().to_string();
    let Some(mut plan) = (match state.store.get_upgrade_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err.display_chain(),
            );
        }
    }) else {
        return super::error::ApiError::not_found(
            super::codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    if plan.status != "draft" {
        return super::error::ApiError::conflict(
            super::codes::PLAN_NOT_APPROVABLE,
            format!(
                "rollout plan {plan_id} is {}, only draft can be approved",
                plan.status
            ),
        )
        .into_response();
    }
    // 批准前再按**当前**上报版本校验一次：计划创建后网关可能升级/降级过。
    if plan.action != rollout::ACTION_WPARSE_RELEASE {
        match rollout::target_compatibility_errors(&state, &plan).await {
            Ok(errors) if errors.is_empty() => {}
            Ok(errors) => {
                return super::error::ApiError::conflict(
                    super::codes::ROLLOUT_TARGET_INCOMPATIBLE,
                    errors.join("; "),
                )
                .into_response();
            }
            Err(err) => {
                return super::error::internal_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    super::codes::ROLLOUT_PLAN_LOAD_FAILED,
                    "failed to check target compatibility",
                    err,
                );
            }
        }
    }
    if !rollout::approve_plan(&mut plan) {
        return super::error::ApiError::conflict(
            super::codes::PLAN_NO_PHASE,
            format!("rollout plan {plan_id} has no phase"),
        )
        .into_response();
    }
    plan.approved_by = Some("admin".to_string());
    plan.approved_at = Some(DateTime::now());
    if plan.action == rollout::ACTION_WPARSE_RELEASE {
        // `wparse-release` 的计划只当**审批闸门**：批准这一刻由中心自己把命令投进
        // wparse-proxy 队列（网关不会去拉这个动作的计划，见 `rollout::active_plan_for_gateway`），
        // 落库顺序（先 rolling 再入队）由 [`rollout::persist_and_dispatch_wparse`] 负责。
        if let Err(error) = rollout::persist_and_dispatch_wparse(&state, &mut plan).await {
            return error.into_response();
        }
        return Json(rollout::plan_view(&plan)).into_response();
    }
    if let Err(err) = state.store.save_upgrade_plan(&plan).await {
        return super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::ROLLOUT_PLAN_STORE_FAILED,
            "failed to store rollout plan",
            err.display_chain(),
        );
    }
    Json(rollout::plan_view(&plan)).into_response()
}

/// 人工推进到下一阶段：`POST /api/v1/admin/rollout-plans/advance`（模型 `AdminAdvanceUpgradePlan`）。
pub async fn admin_advance_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<rollout::PlanRefRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = request.plan_id.trim().to_string();
    let Some(mut plan) = (match state.store.get_upgrade_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err.display_chain(),
            );
        }
    }) else {
        return super::error::ApiError::not_found(
            super::codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    // 人工闸门：当前阶段须**已全部了结**（金丝雀确认无问题再推下一批）；与网关同一口径。
    if let Some(reason) = rollout::advance_gate_blocker(&plan) {
        return super::error::ApiError::conflict(
            super::codes::PLAN_NOT_ADVANCABLE,
            format!("cannot advance rollout plan {plan_id}: {reason}"),
        )
        .into_response();
    }
    rollout::advance_plan(&mut plan);
    if plan.action == rollout::ACTION_WPARSE_RELEASE {
        // 进入新阶段后同样由中心入队（其余动作由网关自己拉）；末阶段收尾后这里是个空操作。
        if let Err(error) = rollout::persist_and_dispatch_wparse(&state, &mut plan).await {
            return error.into_response();
        }
        return Json(rollout::plan_view(&plan)).into_response();
    }
    if let Err(err) = state.store.save_upgrade_plan(&plan).await {
        return super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::ROLLOUT_PLAN_STORE_FAILED,
            "failed to store rollout plan",
            err.display_chain(),
        );
    }
    Json(rollout::plan_view(&plan)).into_response()
}

/// 重派失败目标：`POST /api/v1/admin/rollout-plans/retry`（模型 `AdminRetryUpgradePlan`）。
///
/// body `{ plan_id, target_ids?: [...] }`；`target_ids` 省略 / 为空 = 该计划里**所有**失败目标。
/// 落地方式是**新建一份补跑计划**（新 `plan_id`、单阶段、直接放行），理由见
/// [`rollout::build_retry_plan`]：网关按 `plan_id` 去重（落盘游标 `last_plan_id`），
/// 同一份计划改状态是假重试。原计划原样留作历史。
///
/// **只受理 `failed`（已终结且失败）的计划**：滚动中的计划若已被网关驱过，重派后它仍可能被网关
/// 回头再驱一次 —— 滚动态请先用「推进」把当前阶段了结（失败也算了结），到终态再重试。
pub async fn admin_retry_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<rollout::RetryRolloutPlanRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = request.plan_id.trim().to_string();
    let Some(plan) = (match state.store.get_upgrade_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err.display_chain(),
            );
        }
    }) else {
        return super::error::ApiError::not_found(
            super::codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    if plan.status != "failed" {
        return super::error::ApiError::conflict(
            super::codes::PLAN_NOT_RETRYABLE,
            format!(
                "rollout plan {plan_id} is {}, only a failed plan can be retried（滚动态先「推进」把当前阶段了结）",
                plan.status
            ),
        )
        .into_response();
    }
    let requested: Option<std::collections::HashSet<String>> = {
        let set: std::collections::HashSet<String> = request
            .target_ids
            .iter()
            .map(|target| target.trim().to_string())
            .filter(|target| !target.is_empty())
            .collect();
        (!set.is_empty()).then_some(set)
    };
    let failed: Vec<String> = plan
        .entries
        .iter()
        .filter(|entry| entry.status == "failed")
        .map(|entry| entry.gateway_id.clone())
        .filter(|gateway_id| {
            requested
                .as_ref()
                .is_none_or(|set| set.contains(gateway_id))
        })
        .collect();
    if failed.is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::NO_FAILED_TARGETS,
            format!("rollout plan {plan_id} has no failed target to retry"),
        )
        .into_response();
    }
    // 目标存在性校验：与建计划同款 —— 物化到不存在的网关只会永不命中，把补跑计划挂在滚动里等不到了结。
    let known = match state.store.list_gateways().await {
        Ok(gateways) => gateways
            .into_iter()
            .map(|gateway| gateway.gateway_id)
            .collect::<std::collections::HashSet<_>>(),
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_LIST_FAILED,
                "failed to list gateways",
                err.display_chain(),
            );
        }
    };
    let unknown: Vec<&str> = failed
        .iter()
        .map(String::as_str)
        .filter(|gateway_id| !known.contains(*gateway_id))
        .collect();
    if !unknown.is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::UNKNOWN_TARGETS,
            format!("unknown target(s): {}", unknown.join(", ")),
        )
        .into_response();
    }
    let retry = match rollout::build_retry_plan(&plan, &failed) {
        Ok(retry) => retry,
        Err(error) => return error.into_response(),
    };
    // 补跑计划已经是 `rolling`（重试就是「现在就重派」）；`wparse-release` 建完就要入队。
    let mut created = match state.store.create_upgrade_plan(&retry).await {
        Ok(plan) => plan,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ROLLOUT_RETRY_CREATE_FAILED,
                "failed to create retry rollout plan",
                err.display_chain(),
            );
        }
    };
    if created.action == rollout::ACTION_WPARSE_RELEASE
        && let Err(error) = rollout::persist_and_dispatch_wparse(&state, &mut created).await
    {
        // 计划已经建出来了：单台入队失败只会把那条标 `failed`（不会走到这里）；
        // 走到这里说明 proxy 已关或仓库已被删 —— 把错误冒出来，计划留作 `rolling` 等人工处置。
        return error.into_response();
    }
    (StatusCode::CREATED, Json(rollout::plan_view(&created))).into_response()
}

/// 查看某份计划及其逐目标进度：`GET /api/v1/admin/rollout-plans/{plan_id}`（模型 `AdminViewUpgradePlan`）。
pub async fn admin_view_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(plan_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = plan_id.trim().to_string();
    match state.store.get_upgrade_plan(&plan_id).await {
        Ok(Some(plan)) => Json(rollout::detail_view(&plan)).into_response(),
        Ok(None) => super::error::ApiError::not_found(
            super::codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::ROLLOUT_PLAN_LOAD_FAILED,
            "failed to load rollout plan",
            err.display_chain(),
        ),
    }
}

/// 查询某 gateway 的生命周期转变历史：GET /api/v1/admin/gateways/:gateway_id/lifecycle。
pub async fn admin_list_gateway_lifecycle(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let events = match state.store.list_lifecycle_events(&gateway_id).await {
        Ok(events) => events,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_LIFECYCLE_LOAD_FAILED,
                "failed to load gateway lifecycle",
                err.display_chain(),
            );
        }
    };
    Json(events).into_response()
}

/// 查询某 gateway 的换绑审计（bind / 换绑历史，升序）：
/// `GET /api/v1/admin/gateways/:gateway_id/bindings`。
///
/// 与同组子资源（`lifecycle` / `agents`）同口径：网关不存在时返回 `200 []`（不泄露存在性，
/// 也不把「没有历史」和「网关不存在」分成两个错误码）；绑定入口 `POST /bind` 才做 404。
pub async fn admin_list_gateway_binding_history(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let events = match state.store.list_binding_audit(&gateway_id).await {
        Ok(events) => events,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_BINDING_HISTORY_LOAD_FAILED,
                "failed to load gateway binding history",
                err.display_chain(),
            );
        }
    };
    Json(events).into_response()
}

/// 查询某 gateway 下的 Agent 状态：GET /api/v1/admin/gateways/:gateway_id/agents。
pub async fn admin_list_gateway_agents(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let agents = match state.store.list_agents_by_gateway(&gateway_id).await {
        Ok(agents) => agents,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_AGENTS_LOAD_FAILED,
                "failed to load gateway agents",
                err.display_chain(),
            );
        }
    };
    let views: Vec<AgentRuntimeStatus> = agents
        .into_iter()
        .map(|agent| AgentRuntimeStatus {
            agent_id: agent.agent_id,
            instance_id: agent.instance_id,
            version: agent.version,
            status: agent.status,
            health: agent.health,
            memory_bytes: agent.memory_bytes,
            cpu_percent: agent.cpu_percent,
            admin_latency_ms: agent.admin_latency_ms,
            last_seen_at: agent.last_seen_at,
        })
        .collect();
    Json(views).into_response()
}

pub async fn admin_view_gateway_list(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<IncludeArchivedQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateways: Vec<StoredGateway> = match state.store.list_gateways().await {
        Ok(gateways) => gateways,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            );
        }
    };
    // 计数与「默认视图可见的网关」同一口径：已归档的不计入（要看它们用 `include_archived=true`）。
    let gateways: Vec<&StoredGateway> = gateways
        .iter()
        .filter(|stored| query.include_archived || stored.archived_at.is_none())
        .collect();
    let (online_count, offline_count, degraded_count) = gateways.iter().fold(
        (0_i64, 0_i64, 0_i64),
        |(online, offline, degraded), stored| {
            // 在线 = **新鲜**（`last_seen_at` 在窗口内）**且** 上报状态为 online。
            // 只看状态字符串会让掉线的网关永远「在线」（gwlinkd 只在活着时上报、从不发 offline）。
            let is_online = gateway_is_online(stored);
            let online = online + i64::from(is_online);
            // 离线 = 不在线（含已上报离线与从未上报的已接入网关），保证 online + offline = gateway_count。
            let offline = offline + i64::from(!is_online);
            let degraded = degraded + i64::from(stored.health.as_deref() == Some("degraded"));
            (online, offline, degraded)
        },
    );
    Json(AdminGatewayListReturned {
        list: GatewayListView {
            gateway_count: gateways.len() as i64,
            online_count,
            offline_count,
            degraded_count,
            updated_at: DateTime::now(),
        },
    })
    .into_response()
}

pub async fn admin_list_gateway_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<IncludeArchivedQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateways = match state.store.list_gateways().await {
        Ok(gateways) => gateways,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            );
        }
    };
    // 状态视图只展示「已上报过」的网关；从未上报的网关无状态可展示（聚合 gateway_count 仍计入）。
    // 已归档的默认不展示（`?include_archived=true` 才带）—— 归档就是为了把它们从态势里收起来。
    let mut views: Vec<GatewayRuntimeStatus> = gateways
        .iter()
        .filter(|stored| stored.last_seen_at.is_some())
        .filter(|stored| query.include_archived || stored.archived_at.is_none())
        .map(gateway_runtime_status)
        .collect();
    views.sort_by(|left, right| left.gateway_id.cmp(&right.gateway_id));
    Json(AdminGatewayStatusListReturned { statuses: views }).into_response()
}

pub async fn admin_show_gateway_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let stored = match state.store.get_gateway(&gateway_id).await {
        Ok(stored) => stored,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            );
        }
    };
    let Some(stored) = stored else {
        return super::error::ApiError::not_found(
            super::codes::GATEWAY_NOT_FOUND,
            format!("unknown gateway {gateway_id}"),
        )
        .into_response();
    };
    if stored.last_seen_at.is_none() {
        // 已接入但从未上报：无状态可返回（与列表端点一致）。
        return super::error::ApiError::not_found(
            super::codes::GATEWAY_NOT_REPORTED,
            format!("gateway {gateway_id} has not reported yet"),
        )
        .into_response();
    }
    Json(AdminGatewayStatusReturned {
        status: gateway_runtime_status(&stored),
    })
    .into_response()
}

/// 在线判定窗口（秒）：= 3×gwlinkd 上报节奏（30s），与网关侧 linkd-status 的失联阈值**同口径**。
pub const GATEWAY_ONLINE_WINDOW_SECONDS: i64 = 90;

/// 网关是否在线：上报状态为 `online` **且** 最近上报在窗口内。
///
/// 为什么需要「新鲜度」：gwlinkd 只在**活着时**上报（每 30s）、**从不发 `offline`**；只看存的
/// `status` 字符串的话，它一死（崩溃 / 停服）中心就永远显示「在线」—— 与网关侧（linkd-status
/// 90s 失联判定）口径不一致。这里按 `last_seen_at` 补上陈旧度。
fn gateway_is_online(stored: &StoredGateway) -> bool {
    if stored.status.as_deref() != Some("online") {
        return false;
    }
    let Some(last_seen) = stored.last_seen_at.as_ref() else {
        return false;
    };
    let age_seconds = DateTime::now()
        .to_chrono()
        .signed_duration_since(last_seen.to_chrono())
        .num_seconds();
    (0..=GATEWAY_ONLINE_WINDOW_SECONDS).contains(&age_seconds)
}

/// StoredGateway → GatewayRuntimeStatus。仅对已上报网关调用（列表/单查已过滤）；
/// Option 缺省值保留为防御性兜底。
fn gateway_runtime_status(stored: &StoredGateway) -> GatewayRuntimeStatus {
    // 视图里的 `status` 交出**归一的在线/离线**（按新鲜度派生），徽标与计数才会一致。
    GatewayRuntimeStatus {
        status: if gateway_is_online(stored) {
            "online".to_string()
        } else {
            "offline".to_string()
        },
        gateway_id: stored.gateway_id.clone(),
        instance_id: stored.instance_id.clone(),
        version: stored.version.clone().unwrap_or_default(),
        gops_version: stored.gops_version.clone(),
        gx_version: stored.gx_version.clone(),
        gwlinkd_version: stored.gwlinkd_version.clone(),
        // 注意：`status` 已在上面按新鲜度归一，这里不再回退原始字符串。
        health: stored
            .health
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        memory_bytes: stored.memory_bytes,
        cpu_percent: stored.cpu_percent,
        public_base_url: stored.public_base_url.clone(),
        last_seen_at: stored.last_seen_at.clone().unwrap_or_else(DateTime::now),
        uptime_seconds: stored.uptime_seconds,
        agent_count: stored.agent_count,
        online_agents: stored.online_agents,
        offline_agents: stored.offline_agents,
        last_seen_lag_seconds: stored.last_seen_lag_seconds,
        store_bytes: stored.store_bytes,
        ingest_accepted_total: stored.ingest_accepted_total,
        ingest_rejected_total: stored.ingest_rejected_total,
        last_ingest_at: stored.last_ingest_at.clone(),
        memory_total_bytes: stored.memory_total_bytes,
        load_1m: stored.load_1m,
        load_5m: stored.load_5m,
        load_15m: stored.load_15m,
        disk_usage_percent: stored.disk_usage_percent,
        disk_total_bytes: stored.disk_total_bytes,
        disk_available_bytes: stored.disk_available_bytes,
    }
}

/// 下发全局策略（DispatchGlobalPolicyFlow）：记录一次全局策略下发回执。
pub async fn admin_dispatch_global_policy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(input): ApiJson<AdminDispatchGlobalPolicy>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    Json(GlobalPolicyDispatch {
        dispatch_id: format!(
            "policy-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ),
        policy_version: input.policy_version,
        target_count: input.gateway_ids.len() as i64,
        status: "accepted".to_string(),
        dispatched_at: DateTime::now(),
    })
    .into_response()
}

/// 下发 Agent 舰队指令（DispatchAgentFleetCommandFlow）：记录一次舰队指令下发回执。
pub async fn admin_dispatch_agent_fleet_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(input): ApiJson<DispatchAgentFleetCommand>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    Json(AgentFleetDispatchReceipt {
        dispatch_id: format!(
            "fleet-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ),
        command_kind: input.command_kind,
        target_count: input.agent_ids.len() as i64,
        status: "accepted".to_string(),
        created_at: DateTime::now(),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    // 包身份 / 组件一致性判定已下沉到 `infra::release_jobs`（下载 worker 也用同一份口径）。
    use crate::infra::{component_package_mismatch, source_component_mismatch};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        config::{CenterConfig, GatewayCredentialSeed, PackageSourceConfig},
        infra::FileStore,
    };

    fn test_gateway_ca() -> std::sync::Arc<crate::infra::gateway_ca::GatewayCa> {
        std::sync::Arc::new(
            crate::infra::gateway_ca::GatewayCa::generate("Wist Test Gateway CA")
                .expect("gateway ca")
                .0,
        )
    }

    fn test_store() -> FileStore {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-admin-test-{nanos}.json"));
        let store = FileStore::new(&path);
        store
            .seed(&[
                GatewayCredentialSeed {
                    gateway_id: "gw-001".to_string(),
                    token: "tok-a".to_string(),
                    expires_at: None,
                },
                GatewayCredentialSeed {
                    gateway_id: "gw-002".to_string(),
                    token: "tok-b".to_string(),
                    expires_at: None,
                },
            ])
            .expect("seed");
        store
            .update(|snapshot| {
                if let Some(gw) = snapshot.gateways.get_mut("gw-001") {
                    gw.instance_id = "inst-1".to_string();
                    gw.version = Some("v2.4.1".to_string());
                    gw.status = Some("online".to_string());
                    gw.health = Some("healthy".to_string());
                    gw.last_seen_at = Some(DateTime::now());
                }
                if let Some(gw) = snapshot.gateways.get_mut("gw-002") {
                    gw.status = Some("offline".to_string());
                    gw.health = Some("degraded".to_string());
                    gw.last_seen_at = Some(DateTime::now());
                }
            })
            .expect("status update");
        store
    }

    /// 以给定 store 拼一个 ApiState（其余配置与 `test_state` 相同）。
    fn state_with_store(store: FileStore) -> ApiState {
        let store: std::sync::Arc<dyn crate::infra::Store> = std::sync::Arc::new(store);
        let artifact_store: std::sync::Arc<dyn crate::infra::ArtifactStore> =
            std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            ));
        let jobs = crate::infra::release_job_queue(store.clone(), artifact_store.clone());
        ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                store_path: std::env::temp_dir().join("unused.json"),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                gateway_project_repo: "https://wgc-git.beta.jingang.cloud/gateway-tx.git"
                    .to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                package_sources: Vec::new(),
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
                wparse_proxy: crate::config::WparseProxyConfig {
                    enabled: false,
                    listen_addr: "0.0.0.0:3101".to_string(),
                },
                wparse_release: Default::default(),
                log: Default::default(),
            },
            store,
            artifact_store,
            gateway_ca: test_gateway_ca(),
            proxy: None,
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
            jobs,
        }
    }

    fn test_state() -> ApiState {
        state_with_store(test_store())
    }

    /// 建 N 个**已登记**网关（`gw-001..gw-00N`）的 store —— 建计划的目标存在性校验要用。
    fn gateway_store(count: usize) -> FileStore {
        // 文件名要**进程内唯一**：只用纳秒会在并行测试里撞同一份 store
        // （撞上就会把别的用例造的网关读进来，报“默认视图多出 gw-003”这种假失败）。
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let seq = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("wic-rollout-test-{nanos}-{seq}.json"));
        let store = FileStore::new(&path);
        let seeds: Vec<GatewayCredentialSeed> = (1..=count)
            .map(|i| GatewayCredentialSeed {
                gateway_id: format!("gw-{i:03}"),
                token: format!("tok-{i:03}"),
                expires_at: None,
            })
            .collect();
        store.seed(&seeds).expect("seed");
        store
    }

    /// 目标都存在的管理面 state（`gw-001..gw-00N`）。
    fn rollout_state(count: usize) -> ApiState {
        state_with_store(gateway_store(count))
    }

    /// 建计划请求体（与网关**同形**：action/spec/target_ids/phase_count/deadline_at/timeout/batch）。
    fn create_body(targets: &[&str], phase_count: i64) -> serde_json::Value {
        serde_json::json!({
            "action": "upgrade",
            "spec": "{\"targets\":[{\"component\":\"wist-gateway-stack\",\"target_version\":\"0.1.28\"}]}",
            "target_ids": targets,
            "phase_count": phase_count,
            "deadline_at": "2027-01-01T00:00:00Z",
            "timeout_seconds": 600,
            "batch_size": 0,
        })
    }

    fn gateway_refs(count: usize) -> Vec<String> {
        (1..=count).map(|i| format!("gw-{i:03}")).collect()
    }

    async fn post_json(
        app: &axum::Router,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("authorization", "Bearer admin-tok")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
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
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
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
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn delete_json(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(uri)
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
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
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// 绑定业务身份：校验 tag-safe、存在性、revision 幂等/递增。
    #[tokio::test]
    async fn bind_customer_validates_and_returns_revision() {
        let state = state_with_store(gateway_store(1));
        let app = super::super::router_for(state.clone());

        let (status, body) = post_json(
            &app,
            "/api/v1/admin/gateways/bind",
            serde_json::json!({
                "gateway_id": "gw-001",
                "customer_id": "tenant-acme",
                "requested_by": "admin",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["customer_id"], "tenant-acme");
        assert_eq!(body["revision"], 1);
        assert_eq!(body["status"], "bound");

        // 同客户重复绑定：revision 不递增。
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/gateways/bind",
            serde_json::json!({
                "gateway_id": "gw-001",
                "customer_id": "tenant-acme",
                "requested_by": "admin",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["revision"], 1);

        // 换绑：revision 递增。
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/gateways/bind",
            serde_json::json!({
                "gateway_id": "gw-001",
                "customer_id": "tenant-b",
                "requested_by": "admin",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["revision"], 2);

        // tag-safe 校验：空格直接 400。
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/gateways/bind",
            serde_json::json!({
                "gateway_id": "gw-001",
                "customer_id": "tenant acme",
                "requested_by": "admin",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["error"]["code"],
            super::super::codes::CUSTOMER_ID_NOT_TAG_SAFE
        );

        // 不存在的网关：404。
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/gateways/bind",
            serde_json::json!({
                "gateway_id": "gw-999",
                "customer_id": "tenant-acme",
                "requested_by": "admin",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(
            body["error"]["code"],
            super::super::codes::GATEWAY_NOT_FOUND
        );

        // 换绑审计：只记**归属变化**（首绑 + 换绑），同客户重复绑定不入库。
        let events = state
            .store
            .list_binding_audit("gw-001")
            .await
            .expect("audit");
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0].customer_id, "tenant-acme");
        assert!(events[0].previous_customer_id.is_none());
        assert_eq!(events[0].requested_by, "admin");
        assert_eq!(events[1].customer_id, "tenant-b");
        assert_eq!(
            events[1].previous_customer_id.as_deref(),
            Some("tenant-acme")
        );
        assert_eq!(events[1].revision, 2);
        assert_eq!(events[1].requested_by, "admin");

        // 管理面可查：GET .../bindings（升序）。
        let (status, history) = get_json(&app, "/api/v1/admin/gateways/gw-001/bindings").await;
        assert_eq!(status, StatusCode::OK, "{history}");
        let history = history.as_array().expect("array");
        assert_eq!(history.len(), 2);
        assert_eq!(history[1]["customer_id"], "tenant-b");
        assert_eq!(history[1]["previous_customer_id"], "tenant-acme");
    }

    /// 建一份计划（目标都已在册），返回 (state, app, plan_id)。
    async fn create_plan(count: usize, phase_count: i64) -> (ApiState, axum::Router, String) {
        let state = rollout_state(count);
        let app = super::super::router_for(state.clone());
        let ids = gateway_refs(count);
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let (status, plan) = post_json(
            &app,
            "/api/v1/admin/rollout-plans",
            create_body(&refs, phase_count),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create plan");
        let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
        (state, app, plan_id)
    }

    /// 把计划里**全部**条目改成 `succeeded`（绕过网关回执，直接造出「本段已了结」）。
    async fn settle_all(state: &ApiState, plan_id: &str) {
        let mut plan = state
            .store
            .get_upgrade_plan(plan_id)
            .await
            .expect("load plan")
            .expect("plan exists");
        for entry in plan.entries.iter_mut() {
            entry.status = "succeeded".to_string();
        }
        state
            .store
            .save_upgrade_plan(&plan)
            .await
            .expect("save plan");
    }

    /// 阶段由**服务端**按阶梯切：客户端只给目标与阶段数，不自己切。
    #[tokio::test]
    async fn create_upgrade_plan_rejects_a_target_whose_gateway_is_too_old() {
        let store = gateway_store(1);
        store
            .update(|snapshot| {
                if let Some(gateway) = snapshot.gateways.get_mut("gw-001") {
                    gateway.version = Some("0.8.2".to_string());
                    gateway.gwlinkd_version = Some("0.18.0".to_string());
                }
            })
            .expect("seed versions");
        let manifest: wist_release::compat::CompatManifest =
            serde_json::from_str(r#"{"requires":{"wist-gateway":">=9.0.0"}}"#).expect("manifest");
        store
            .publish_release_with_compat(
                "wist-gateway-stack",
                "0.1.28",
                "https://example/stack.tar.gz",
                None,
                None,
                Some(manifest),
            )
            .expect("release");
        let refs = ["gw-001"];
        let (status, body) = post_json(
            &super::super::router_for(state_with_store(store)),
            "/api/v1/admin/rollout-plans",
            create_body(&refs, 1),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "rollout_target_incompatible");
        assert!(
            body["error"]["message"]
                .as_str()
                .expect("message")
                .contains("请先升级"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn create_upgrade_plan_allows_a_compatible_target() {
        let store = gateway_store(1);
        store
            .update(|snapshot| {
                if let Some(gateway) = snapshot.gateways.get_mut("gw-001") {
                    gateway.version = Some("0.25.0".to_string());
                    gateway.gwlinkd_version = Some("0.20.0".to_string());
                }
            })
            .expect("seed versions");
        let manifest: wist_release::compat::CompatManifest =
            serde_json::from_str(r#"{"requires":{"wist-gateway":">=0.0.1"}}"#).expect("manifest");
        store
            .publish_release_with_compat(
                "wist-gateway-stack",
                "0.1.28",
                "https://example/stack.tar.gz",
                None,
                None,
                Some(manifest),
            )
            .expect("release");
        let refs = ["gw-001"];
        let (status, body) = post_json(
            &super::super::router_for(state_with_store(store)),
            "/api/v1/admin/rollout-plans",
            create_body(&refs, 1),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    #[tokio::test]
    async fn approve_upgrade_plan_rechecks_the_current_gateway_version() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-approve-compat-{nanos}.json"));
        let store = FileStore::new(&path);
        store
            .seed(&[GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "tok-a".to_string(),
                expires_at: None,
            }])
            .expect("seed");
        store
            .update(|snapshot| {
                if let Some(gateway) = snapshot.gateways.get_mut("gw-001") {
                    gateway.version = Some("0.25.0".to_string());
                    gateway.gwlinkd_version = Some("0.20.0".to_string());
                }
            })
            .expect("versions");
        let manifest: wist_release::compat::CompatManifest =
            serde_json::from_str(r#"{"requires":{"wist-gateway":">=0.9.0"}}"#).expect("manifest");
        store
            .publish_release_with_compat(
                "wist-gateway-stack",
                "0.1.28",
                "https://example/stack.tar.gz",
                None,
                None,
                Some(manifest),
            )
            .expect("release");
        let state = state_with_store(store);
        let refs = ["gw-001"];
        let (status, plan) = post_json(
            &super::super::router_for(state.clone()),
            "/api/v1/admin/rollout-plans",
            create_body(&refs, 1),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{plan}");
        let plan_id = plan["plan_id"].as_str().expect("plan_id").to_string();

        // 创建后网关被降级：批准时必须重新发现“现在不兼容”。
        FileStore::new(&path)
            .update(|snapshot| {
                if let Some(gateway) = snapshot.gateways.get_mut("gw-001") {
                    gateway.version = Some("0.8.2".to_string());
                }
            })
            .expect("downgrade");

        let (status, body) = post_json(
            &super::super::router_for(state),
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "rollout_target_incompatible");
    }

    #[tokio::test]
    async fn list_releases_reports_compatibility_against_the_current_center() {
        let store = test_store();
        let compatible: wist_release::compat::CompatManifest =
            serde_json::from_str(r#"{"requires":{"wist-center":">=0.0.1"}}"#)
                .expect("compatible manifest");
        let incompatible: wist_release::compat::CompatManifest =
            serde_json::from_str(r#"{"requires":{"wist-center":">=99.0.0"}}"#)
                .expect("incompatible manifest");
        store
            .publish_release_with_compat(
                "wist-gateway-stack",
                "0.1.27",
                "https://example/stack-0.1.27.tar.gz",
                None,
                None,
                Some(compatible),
            )
            .expect("compatible release");
        store
            .publish_release_with_compat(
                "wist-gateway-stack",
                "0.1.28",
                "https://example/stack-0.1.28.tar.gz",
                None,
                None,
                Some(incompatible),
            )
            .expect("incompatible release");
        let (status, body) = get_json(
            &super::super::router_for(state_with_store(store)),
            "/api/v1/admin/releases/wist-gateway-stack",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let packages = body.as_array().expect("packages");
        let package = |version: &str| {
            packages
                .iter()
                .find(|package| package["version"] == version)
                .unwrap_or_else(|| panic!("missing {version}: {body}"))
        };
        assert_eq!(package("0.1.27")["compatibility"]["status"], "ok");
        assert_eq!(package("0.1.28")["compatibility"]["status"], "error");
        assert_eq!(
            package("0.1.28")["compatibility"]["checks"][0]["peer"],
            "wist-center"
        );
    }

    #[tokio::test]
    async fn create_upgrade_plan_splits_phases_on_the_server() {
        let ids = gateway_refs(10);
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let (status, plan) = post_json(
            &super::super::router_for(rollout_state(10)),
            "/api/v1/admin/rollout-plans",
            create_body(&refs, 3),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        // 计划本体：`draft` + 尚未开始（current_phase 0）。
        assert_eq!(plan["status"], "draft");
        assert_eq!(plan["current_phase"], 0);
        assert_eq!(plan["action"], "upgrade");
        let phases = plan["phases"].as_array().expect("phases");
        let sizes: Vec<usize> = phases
            .iter()
            .map(|phase| phase["target_ids"].as_array().expect("ids").len())
            .collect();
        // 10 台 × 3 阶段：金丝雀 1 → 到 10% 再 1 → 余 8。
        assert_eq!(sizes, vec![1, 1, 8]);
        assert_eq!(phases[0]["phase_index"], 1);
        assert_eq!(phases[0]["status"], "pending");
        // 固定闸门：首段人工、其后全成功。
        assert_eq!(phases[0]["advance_rule"], "manual");
        assert_eq!(phases[1]["advance_rule"], "all_succeeded");
        // 阶段之间互不重叠，且一把铺满。
        let mut all: Vec<String> = phases
            .iter()
            .flat_map(|phase| {
                phase["target_ids"]
                    .as_array()
                    .expect("ids")
                    .iter()
                    .map(|id| id.as_str().expect("id").to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 10);
    }

    /// 阶段数不可用（0 / 大于台数）→ **400**，而不是给一个空阶段。
    #[tokio::test]
    async fn create_upgrade_plan_rejects_impossible_phase_counts() {
        let app = super::super::router_for(test_state());
        let ids = gateway_refs(10);
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        for phase_count in [0_i64, 11] {
            let (status, _) = post_json(
                &app,
                "/api/v1/admin/rollout-plans",
                create_body(&refs, phase_count),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "phase_count {phase_count}");
        }
    }

    /// 截止时间非 RFC3339 / 预算为负 → **400**（缺省 / 0 则允许：中心不物化）。
    #[tokio::test]
    async fn create_upgrade_plan_rejects_bad_deadline_and_timeout() {
        let app = super::super::router_for(rollout_state(1));
        let mut body = create_body(&["gw-001"], 1);
        body["deadline_at"] = serde_json::json!("2027-01-01 00:00:00");
        let (status, _) = post_json(&app, "/api/v1/admin/rollout-plans", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "bad deadline");

        let mut body = create_body(&["gw-001"], 1);
        body["timeout_seconds"] = serde_json::json!(-1);
        let (status, _) = post_json(&app, "/api/v1/admin/rollout-plans", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "negative timeout");

        // 未知目标 → 400（与网关同款：不存在就拒，不静默落库）。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans",
            create_body(&["gw-001", "gw-ghost"], 1),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unknown target");
    }

    /// 批准：`draft → rolling` 进入第一阶段；重复批准 → **409**。
    #[tokio::test]
    async fn approve_opens_the_first_phase_then_conflicts() {
        let (_state, app, plan_id) = create_plan(10, 3).await;
        let (status, plan) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(plan["status"], "rolling");
        assert_eq!(plan["current_phase"], 1);
        assert_eq!(plan["phases"][0]["status"], "rolling");
        assert!(plan["approved_at"].is_string());

        // 二次批准：不是 draft 了 → 409。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    /// 未知计划：批准/推进/查看 → **404**。
    #[tokio::test]
    async fn rollout_actions_on_unknown_plan_are_404() {
        let app = super::super::router_for(test_state());
        for uri in [
            "/api/v1/admin/rollout-plans/approve",
            "/api/v1/admin/rollout-plans/advance",
        ] {
            let (status, _) =
                post_json(&app, uri, serde_json::json!({ "plan_id": "plan-nope" })).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
        let (status, _) = get_json(&app, "/api/v1/admin/rollout-plans/plan-nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// 推进：逐阶段 `rolling`，末阶段推进后收敛 `completed`。
    #[tokio::test]
    async fn advance_walks_to_the_last_phase_then_completes() {
        let (state, app, plan_id) = create_plan(4, 2).await;
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // 两段的条目都了结（
        settle_all(&state, &plan_id).await;

        // 第一次推进：进第二阶段（尚在 rolling）。
        let (status, plan) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/advance",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(plan["current_phase"], 2);
        assert_eq!(plan["status"], "rolling");
        assert_eq!(plan["phases"][0]["status"], "completed");
        assert_eq!(plan["phases"][1]["status"], "rolling");

        // 第二次推进：已是末阶段 → 收敛 completed。
        let (status, plan) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/advance",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(plan["status"], "completed");
        assert_eq!(plan["phases"][1]["status"], "completed");

        // 已完成再推进 → 409。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/advance",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    /// 推进闸门：当前阶段未全部了结 → **409**（金丝雀确认无问题再推下一批）。
    #[tokio::test]
    async fn advance_is_blocked_until_the_phase_is_settled() {
        let (_state, app, plan_id) = create_plan(4, 2).await;
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // 第一阶段条目还是 pending/dispatched → 不可推进。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/advance",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // 本段了结后可推进。
        settle_all(&_state, &plan_id).await;
        let (status, plan) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/advance",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(plan["current_phase"], 2);
    }

    /// 归档一台**离线**网关：默认视图（实例列表 / 态势 / 计数）不再有它，`include_archived=true`
    /// 能看回来并恢复；**在线**网关拒绝归档（不能把活着的东西藏起来）；未知网关 404。
    #[tokio::test]
    async fn archive_hides_an_offline_gateway_from_the_default_views() {
        let state = rollout_state(2);
        // gw-001：刚上报过 → 在线；gw-002：上报过但**陈旧** → 掉线（在线判定看新鲜度，不看状态串）。
        for (gateway_id, last_seen) in [
            ("gw-001", DateTime::now()),
            (
                "gw-002",
                DateTime::from_rfc3339("2020-01-01T00:00:00Z").expect("ts"),
            ),
        ] {
            state
                .store
                .upsert_gateway_status(&crate::infra::GatewayStatusUpdate {
                    gateway_id: gateway_id.to_string(),
                    instance_id: format!("inst-{gateway_id}"),
                    version: "0.6.0".to_string(),
                    gops_version: None,
                    gx_version: None,
                    gwlinkd_version: None,
                    status: "online".to_string(),
                    health: "ok".to_string(),
                    memory_bytes: None,
                    cpu_percent: None,
                    public_base_url: None,
                    last_seen_at: last_seen,
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
                .expect("status");
        }
        let app = super::super::router_for(state.clone());

        // 在线 → **409**（要停就先在网关上停掉）。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-001/archive",
            serde_json::json!({ "archived": true }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "在线网关不可归档");

        // 离线 → 200，回执带 archived_at。
        let (status, view) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-002/archive",
            serde_json::json!({ "archived": true }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(view["archived_at"].is_string(), "回执要带归档时刻：{view}");

        // 实例列表：默认没有 gw-002；带上 include_archived 才有。
        let (_, list) = get_json(&app, "/api/v1/admin/gateways/instances").await;
        assert_eq!(
            gateway_ids(&list),
            vec!["gw-001".to_string()],
            "默认视图不该显示已归档实例"
        );
        let (_, list) = get_json(
            &app,
            "/api/v1/admin/gateways/instances?include_archived=true",
        )
        .await;
        assert_eq!(
            gateway_ids(&list),
            vec!["gw-001".to_string(), "gw-002".to_string()]
        );

        // 态势（状态视图）：默认没有 gw-002。
        let (_, statuses) = get_json(&app, "/api/v1/admin/gateways/status").await;
        assert_eq!(
            gateway_ids(&statuses["statuses"]),
            vec!["gw-001".to_string()],
            "态势默认不该显示已归档网关"
        );
        let (_, statuses) =
            get_json(&app, "/api/v1/admin/gateways/status?include_archived=true").await;
        assert_eq!(
            gateway_ids(&statuses["statuses"]),
            vec!["gw-001".to_string(), "gw-002".to_string()]
        );

        // 计数与可见集合同口径：归档后只剩 1 台。
        let (_, list_view) = get_json(&app, "/api/v1/admin/gateways").await;
        assert_eq!(list_view["list"]["gateway_count"], 1);
        assert_eq!(list_view["list"]["offline_count"], 0);

        // 取消归档 → 回到默认视图。
        let (status, view) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-002/archive",
            serde_json::json!({ "archived": false }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(view["archived_at"].is_null());
        let (_, list) = get_json(&app, "/api/v1/admin/gateways/instances").await;
        assert_eq!(
            gateway_ids(&list),
            vec!["gw-001".to_string(), "gw-002".to_string()]
        );
        let (_, list_view) = get_json(&app, "/api/v1/admin/gateways").await;
        assert_eq!(list_view["list"]["gateway_count"], 2);

        // 未知网关 → 404（归档与取消归档都一样）。
        for archived in [true, false] {
            let (status, _) = post_json(
                &app,
                "/api/v1/admin/gateways/gw-404/archive",
                serde_json::json!({ "archived": archived }),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }

    /// 从实例 / 态势列表里取 gateway_id（顺序按响应原样，用来断言可见集合）。
    fn gateway_ids(list: &serde_json::Value) -> Vec<String> {
        list.as_array()
            .expect("list")
            .iter()
            .map(|item| item["gateway_id"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// 重试 = **重派补跑计划**：只带失败目标、新 `plan_id`、单阶段直接放行；原计划原样留作历史。
    ///
    /// 「新 id」是这套东西的关键：gwlinkd 只记住 `last_plan_id`，同一份计划改状态会被静默跳过
    /// （看着成功、其实没重跑）。
    #[tokio::test]
    async fn retry_redispatches_failed_targets_as_a_new_plan() {
        let (state, app, plan_id) = create_plan(3, 1).await;
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // 造出「一段三台：一成一败一待派，计划已终结为 failed」的现场（绕过网关回执）。
        {
            let mut plan = state
                .store
                .get_upgrade_plan(&plan_id)
                .await
                .expect("load plan")
                .expect("plan exists");
            plan.status = "failed".to_string();
            for entry in plan.entries.iter_mut() {
                entry.status = match entry.gateway_id.as_str() {
                    "gw-002" => "failed",
                    "gw-003" => "succeeded",
                    _ => "pending",
                }
                .to_string();
                if entry.gateway_id == "gw-002" {
                    entry.detail = "agent-package 失败（502 Bad Gateway）".to_string();
                }
            }
            state.store.save_upgrade_plan(&plan).await.expect("save");
        }

        // 不带 target_ids = 重试**所有**失败目标。
        let (status, retry) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let retry_id = retry["plan_id"]
            .as_str()
            .expect("retry plan id")
            .to_string();
        assert_ne!(retry_id, plan_id, "补跑计划必须是新 id");
        assert!(
            retry_id.ends_with("-retry"),
            "补跑计划 id 要可辨：{retry_id}"
        );
        assert_eq!(retry["status"], "rolling");
        assert_eq!(retry["current_phase"], 1);
        assert_eq!(retry["phases"].as_array().expect("phases").len(), 1);
        assert_eq!(
            retry["phases"][0]["target_ids"],
            serde_json::json!(["gw-002"])
        );
        assert_eq!(retry["action"], "upgrade", "同一动作面");
        assert!(retry["approved_at"].is_string());

        // 条目只有失败那台，且回到 pending（网关下次轮询即可取走）。
        let (status, detail) =
            get_json(&app, &format!("/api/v1/admin/rollout-plans/{retry_id}")).await;
        assert_eq!(status, StatusCode::OK);
        let entries = detail["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["target_id"], "gw-002");
        assert_eq!(entries[0]["status"], "pending");
        assert_eq!(entries[0]["detail"], "");

        // 原计划**不动**：那个失败原因就是那次尝试的记录。
        let (_, original) = get_json(&app, &format!("/api/v1/admin/rollout-plans/{plan_id}")).await;
        assert_eq!(original["plan"]["status"], "failed");
        assert_eq!(
            original["entries"].as_array().expect("entries")[1]["detail"],
            "agent-package 失败（502 Bad Gateway）"
        );

        // 再点一次：每次点击都是一次重派，得到又一份新计划（两次重派各自可被网关重驱）。
        let (status, again) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_ne!(again["plan_id"], retry_id, "两次重派不能撞 id");
    }

    /// 重试的门槛与筛选：滚动态 / 已完成不受理（**409**），没有失败目标（**400**），未知计划（**404**）。
    #[tokio::test]
    async fn retry_only_accepts_a_failed_plan_and_needs_a_failed_target() {
        let (state, app, plan_id) = create_plan(2, 1).await;
        // 还没批准（draft）/ 批准后（rolling）都不受理 —— 滚动态先「推进」把当前阶段了结。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "draft 不受理");
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "rolling 不受理");

        // `failed` 但**没有**失败条目（条目全成）→ 400。
        {
            let mut plan = state
                .store
                .get_upgrade_plan(&plan_id)
                .await
                .expect("load plan")
                .expect("plan exists");
            plan.status = "failed".to_string();
            for entry in plan.entries.iter_mut() {
                entry.status = "succeeded".to_string();
            }
            state.store.save_upgrade_plan(&plan).await.expect("save");
        }
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "没有失败目标");

        // 有失败目标，但 `target_ids` 点了一台没失败/不存在的 → 同样 400。
        {
            let mut plan = state
                .store
                .get_upgrade_plan(&plan_id)
                .await
                .expect("load plan")
                .expect("plan exists");
            plan.entries[0].status = "failed".to_string();
            state.store.save_upgrade_plan(&plan).await.expect("save");
        }
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": plan_id, "target_ids": ["gw-002", "gw-ghost"] }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "指名的目标里没有失败项");

        // 只重试指名的失败目标 → 201，且补跑计划里只有它。
        let (status, retry) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": plan_id, "target_ids": ["gw-001"] }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            retry["phases"][0]["target_ids"],
            serde_json::json!(["gw-001"])
        );

        // 未知计划 → 404。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/retry",
            serde_json::json!({ "plan_id": "plan-nope" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// 归档是**标记**：只受理终结态；默认列表不再带它，`include_archived=true` 才带；
    /// 取消归档回到默认视图；重复归档不刷新时刻（幂等）。
    #[tokio::test]
    async fn archive_hides_a_finished_plan_from_the_default_list() {
        let (state, app, plan_id) = create_plan(2, 1).await;
        let archive_path = format!("/api/v1/admin/rollout-plans/{plan_id}/archive");

        // draft / rolling 都不能归档：还在推进，藏起来会让人找不到批准 / 推进入口。
        let (status, _) =
            post_json(&app, &archive_path, serde_json::json!({ "archived": true })).await;
        assert_eq!(status, StatusCode::CONFLICT, "draft 不受理归档");
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) =
            post_json(&app, &archive_path, serde_json::json!({ "archived": true })).await;
        assert_eq!(status, StatusCode::CONFLICT, "rolling 不受理归档");

        // 造一份终结态（completed）再归档：回执带 archived_at。
        {
            let mut plan = state
                .store
                .get_upgrade_plan(&plan_id)
                .await
                .expect("load plan")
                .expect("plan exists");
            plan.status = "completed".to_string();
            for entry in plan.entries.iter_mut() {
                entry.status = "succeeded".to_string();
            }
            state.store.save_upgrade_plan(&plan).await.expect("save");
        }
        let (status, view) =
            post_json(&app, &archive_path, serde_json::json!({ "archived": true })).await;
        assert_eq!(status, StatusCode::OK);
        let archived_at = view["archived_at"]
            .as_str()
            .expect("归档回执带时刻")
            .to_string();

        // 默认列表不收；显式 include_archived=true 才收。
        let (_, list) = get_json(&app, "/api/v1/admin/rollout-plans").await;
        assert!(
            !plan_ids(&list).contains(&plan_id),
            "默认列表不应有已归档计划"
        );
        let (_, list) = get_json(&app, "/api/v1/admin/rollout-plans?include_archived=true").await;
        assert!(
            plan_ids(&list).contains(&plan_id),
            "include_archived=true 才可见"
        );

        // 重复归档不刷新时刻（幂等，审计「什么时候收的」不会变）。
        let (status, again) =
            post_json(&app, &archive_path, serde_json::json!({ "archived": true })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["archived_at"], archived_at);

        // 取消归档 → 回到默认列表。
        let (status, view) = post_json(
            &app,
            &archive_path,
            serde_json::json!({ "archived": false }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(view["archived_at"].is_null());
        let (_, list) = get_json(&app, "/api/v1/admin/rollout-plans").await;
        assert!(plan_ids(&list).contains(&plan_id));

        // 未知计划 → 404（归档与取消归档都一样）。
        for archived in [true, false] {
            let (status, _) = post_json(
                &app,
                "/api/v1/admin/rollout-plans/plan-nope/archive",
                serde_json::json!({ "archived": archived }),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }

    /// 从计划列表响应里取 plan_id（用来断言归档后的可见集合）。
    fn plan_ids(list: &serde_json::Value) -> Vec<String> {
        list.as_array()
            .expect("list")
            .iter()
            .map(|item| item["plan_id"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// 删除是**物理删除**，只受理终结态：draft / rolling → 409；删掉后列表与详情都看不到，
    /// 再删同一份 → 404（幂等语义对调用方一致）。
    #[tokio::test]
    async fn delete_only_accepts_finished_plans() {
        let (state, app, plan_id) = create_plan(2, 1).await;
        let path = format!("/api/v1/admin/rollout-plans/{plan_id}");

        // draft / rolling 都不能删：还在推进，删掉会丢在飞的工作。
        let (status, body) = delete_json(&app, &path).await;
        assert_eq!(status, StatusCode::CONFLICT, "draft 不受理删除");
        assert_eq!(
            body["error"]["code"],
            super::super::codes::PLAN_NOT_DELETABLE
        );
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/rollout-plans/approve",
            serde_json::json!({ "plan_id": plan_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = delete_json(&app, &path).await;
        assert_eq!(status, StatusCode::CONFLICT, "rolling 不受理删除");

        // 造一份终结态（completed）再删：回执带被删前那一份的计划视图。
        {
            let mut plan = state
                .store
                .get_upgrade_plan(&plan_id)
                .await
                .expect("load plan")
                .expect("plan exists");
            plan.status = "completed".to_string();
            for entry in plan.entries.iter_mut() {
                entry.status = "succeeded".to_string();
            }
            state.store.save_upgrade_plan(&plan).await.expect("save");
        }
        let (status, view) = delete_json(&app, &path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["plan_id"], plan_id.as_str());
        assert_eq!(view["status"], "completed");

        // 真删了：列表里没有，详情 404，再删一次也是 404。
        let (_, list) = get_json(&app, "/api/v1/admin/rollout-plans").await;
        assert!(!plan_ids(&list).contains(&plan_id), "删除后列表不应再有它");
        let (status, _) = get_json(&app, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = delete_json(&app, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // 未知计划 → 404。
        let (status, _) = delete_json(&app, "/api/v1/admin/rollout-plans/plan-nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// 查看：返回计划 + 逐目标条目（建计划时按全量目标落 `pending`）。
    #[tokio::test]
    async fn view_returns_plan_with_entries() {
        let (_state, app, plan_id) = create_plan(3, 1).await;
        let (status, detail) =
            get_json(&app, &format!("/api/v1/admin/rollout-plans/{plan_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail["plan"]["plan_id"], plan_id.as_str());
        let entries = detail["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|entry| entry["status"] == "pending"));
        assert_eq!(entries[0]["work_id"], serde_json::Value::Null);
    }

    #[test]
    fn history_windows_use_bounded_steps() {
        assert_eq!(history_window_config("1h"), Some((3600, 60)));
        assert_eq!(history_window_config("6h"), Some((21_600, 300)));
        assert_eq!(history_window_config("24h"), Some((86_400, 900)));
        assert_eq!(history_window_config("7d"), None);
    }

    #[test]
    fn toml_basic_string_escape_handles_special_chars() {
        // 普通 token（base64url/hex）无需转义。
        assert_eq!(toml_basic_string_escape("g7Q3abc_-XYZ"), "g7Q3abc_-XYZ");
        // 引号 / 反斜杠 / 换行 / 控制字符需转义，保证仍是合法 TOML 基础字符串。
        assert_eq!(
            toml_basic_string_escape("a\"b\\c\nd\te\u{0001}f"),
            "a\\\"b\\\\c\\nd\\te\\u0001f"
        );
    }

    #[tokio::test]
    async fn history_without_vm_returns_empty_samples() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways/gw-001/status/history?window=1h")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let returned: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(returned["gateway_id"], "gw-001");
        assert_eq!(returned["window"], "1h");
        assert_eq!(returned["step_seconds"], 60);
        assert_eq!(returned["samples"], serde_json::json!([]));
    }

    /// 组件名 / 版本号会拼进制品目录（`{artifact_dir}/{component}/{version}/{filename}`）：
    /// 不是「安全路径段」就 400，不许把 `..` 写到目录外。
    #[tokio::test]
    async fn publish_release_rejects_escaping_component_and_version() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let pkg = std::env::temp_dir().join(format!("wic-escape-{nanos}.tar.gz"));
        std::fs::write(&pkg, b"escape-bytes").expect("write");
        let source = pkg.to_string_lossy().to_string();
        let sha = crate::infra::sha256_hex_bytes(b"escape-bytes");

        let publish = |component: &str, version: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/releases/{component}"))
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "artifact_url": source,
                        "expected_sha256": sha,
                        "version": version,
                        "requested_by": "tester",
                    })
                    .to_string(),
                ))
                .expect("request")
        };

        let app = super::super::router_for(test_state());
        // 版本号带路径分隔符（body 里不会被路径解析吃掉，这条是硬的）→ 400。
        let bad_version = app
            .clone()
            .oneshot(publish("wist-gateway-stack", serde_json::json!("../../0")))
            .await
            .expect("response");
        assert_eq!(bad_version.status(), StatusCode::BAD_REQUEST);

        // 组件名就是 `..`（路由段，不经解码）→ 400。
        let bad_component = app
            .oneshot(publish("..", serde_json::json!(null)))
            .await
            .expect("response");
        assert_eq!(bad_component.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&pkg);
    }

    /// 发布可以拿**本机绝对路径**当来源（与 gateway 的 agent 包同口径）；期望摘要一致则落记录，
    /// 不符则 502 且不落记录。
    #[tokio::test]
    async fn publish_release_accepts_a_local_path_and_verifies_the_expected_digest() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-rel-{nanos}"));
        std::fs::create_dir_all(&dir).expect("dir");
        // 包名要与组件一致（`wist-gateway-stack-…`），否则会被 `artifact_component_mismatch` 拒。
        let pkg = dir.join("wist-gateway-stack-0.1.27.tar.gz");
        std::fs::write(&pkg, b"artifact-bytes").expect("write");
        let source = pkg.to_string_lossy().to_string();
        let sha = crate::infra::sha256_hex_bytes(b"artifact-bytes");

        let publish = |version: &str, expected: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/releases/wist-gateway-stack")
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "version": version,
                        "artifact_url": source,
                        "expected_sha256": expected,
                        "requested_by": "tester",
                    })
                    .to_string(),
                ))
                .expect("request")
        };

        let app = super::super::router_for(test_state());
        let response = app
            .clone()
            .oneshot(publish("0.1.27", &sha))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let record: serde_json::Value = serde_json::from_slice(&body).expect("json");
        // 回执是「安装包」：版本 + 制品列表（每个制品带 `sha256` / `source` / `platform`）。
        assert_eq!(record["version"], serde_json::json!("0.1.27"));
        assert_eq!(record["artifacts"][0]["sha256"], serde_json::json!(sha));
        assert_eq!(record["status"], serde_json::json!("published"));
        // 下发 URL 末段 = **来源原名**（内容寻址在 DB 的 `package_sha256`）。
        let expected_leaf = pkg.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            record["artifacts"][0]["source"]
                .as_str()
                .unwrap_or_default()
                .ends_with(&format!(
                    "/api/v1/releases/artifact/wist-gateway-stack/0.1.27/{expected_leaf}"
                )),
            "{record}"
        );

        // 期望摘要不符 → 502，且**不落**记录。
        let bad = app
            .oneshot(publish("0.1.28", "deadbeef"))
            .await
            .expect("response");
        assert_eq!(bad.status(), StatusCode::BAD_GATEWAY);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 异步契约：`Prefer: respond-async` 只入队（`202` + job），worker 完成后可按 job 轮询到
    /// 结果；失败也落在 job 上（状态码 / 错误码 / 原因），不再靠一次长连接。
    #[tokio::test]
    async fn async_publish_returns_a_job_and_exposes_the_result() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-async-{nanos}"));
        std::fs::create_dir_all(&dir).expect("dir");
        let pkg = dir.join("wist-gateway-stack-9.9.9.tar.gz");
        std::fs::write(&pkg, b"async-artifact-bytes").expect("write");
        let source = pkg.to_string_lossy().to_string();
        let sha = crate::infra::sha256_hex_bytes(b"async-artifact-bytes");

        let state = test_state();
        let app = super::super::router_for(state.clone());
        let publish = |artifact_url: String, expected: String| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/releases/wist-gateway-stack")
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .header("prefer", "respond-async")
                .body(Body::from(
                    serde_json::json!({
                        "artifact_url": artifact_url,
                        "expected_sha256": expected,
                        "requested_by": "tester",
                    })
                    .to_string(),
                ))
                .expect("request")
        };

        let response = app
            .clone()
            .oneshot(publish(source, sha.clone()))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let job: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let job_id = job["job_id"].as_str().expect("job id").to_string();
        assert_eq!(job["kind"], crate::infra::RELEASE_JOB_PUBLISH);

        // worker 可能已经执行完（入队即唤醒）；等到终态再看结果。
        let done = state
            .jobs
            .wait_for_terminal(&job_id, Duration::from_secs(10))
            .await
            .expect("wait")
            .expect("terminal");
        assert_eq!(done.state, crate::infra::JOB_SUCCEEDED);
        assert_eq!(done.progress.completed, 1);
        let package: crate::infra::ReleasePackageRecord =
            serde_json::from_value(done.result.clone().expect("result")).expect("package");
        assert_eq!(package.package.version, "9.9.9");

        // 任务查询 / 列表都可见（列表按组件筛）。
        let (status, one) = get_json(&app, &format!("/api/v1/admin/release-jobs/{job_id}")).await;
        assert_eq!(status, StatusCode::OK, "{one}");
        assert_eq!(one["state"], crate::infra::JOB_SUCCEEDED);
        assert_eq!(one["package"]["version"], "9.9.9");
        let (status, list) = get_json(
            &app,
            "/api/v1/admin/release-jobs?component=wist-gateway-stack",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(
            list.as_array()
                .expect("list")
                .iter()
                .any(|item| item["job_id"] == job_id.as_str()),
            "{list}"
        );

        // 取包失败：同样 202 入队，失败原因落在 job 上（状态码 + 错误码）。
        let response = app
            .clone()
            .oneshot(publish(
                format!("{}/missing-pkg.tar.gz", dir.display()),
                sha,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let failed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let failed_id = failed["job_id"].as_str().expect("job id").to_string();
        let done = state
            .jobs
            .wait_for_terminal(&failed_id, Duration::from_secs(10))
            .await
            .expect("wait")
            .expect("terminal");
        assert_eq!(done.state, crate::infra::JOB_FAILED);
        assert_eq!(done.error_status, Some(502));
        assert_eq!(
            done.error_code.as_deref(),
            Some(super::super::codes::ARTIFACT_FETCH_FAILED)
        );

        // 未知任务 → 404。
        let (status, _) = get_json(&app, "/api/v1/admin/release-jobs/rel-nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 通用任务读面 + 取消：排队中的任务可取消，取消后 release 视图也显示 `canceled`；
    /// 已终结的任务再取消回 409。
    #[tokio::test]
    async fn generic_jobs_can_be_listed_and_queued_jobs_canceled() {
        let state = test_state();
        let app = super::super::router_for(state.clone());
        let job = crate::infra::release_job(crate::infra::ReleaseJobPayload {
            mode: crate::infra::RELEASE_JOB_PUBLISH.to_string(),
            component: "wist-agentd".to_string(),
            requested_by: "admin".to_string(),
            declared_version: None,
            artifacts: vec![crate::infra::ReleaseJobArtifact {
                artifact_url: "https://example/pkg.tar.gz".to_string(),
                expected_sha256: "0".repeat(64),
            }],
        })
        .expect("job");
        let job_id = job.job_id.clone();
        // 直接落库（不启动 worker），保证任务停在 `queued`。
        state.store.create_job(&job).await.expect("create job");
        // 再落一条更新、但主体不同的任务：按组件过滤必须在 limit 之前生效。
        let mut other = crate::infra::release_job(crate::infra::ReleaseJobPayload {
            mode: crate::infra::RELEASE_JOB_PUBLISH.to_string(),
            component: "wist-gateway-stack".to_string(),
            requested_by: "admin".to_string(),
            declared_version: None,
            artifacts: vec![crate::infra::ReleaseJobArtifact {
                artifact_url: "https://example/other.tar.gz".to_string(),
                expected_sha256: "1".repeat(64),
            }],
        })
        .expect("other job");
        other.job_id = "job-newer-other".to_string();
        state.store.create_job(&other).await.expect("create other");

        let (status, filtered) = get_json(
            &app,
            "/api/v1/admin/jobs?queue=release-download&subject=wist-agentd&limit=1",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{filtered}");
        let filtered = filtered.as_array().expect("list");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["job_id"], job_id.as_str());

        let (status, release_list) = get_json(
            &app,
            "/api/v1/admin/release-jobs?component=wist-agentd&limit=1",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{release_list}");
        assert_eq!(release_list.as_array().expect("list").len(), 1);
        assert_eq!(release_list[0]["job_id"], job_id.as_str());

        let (status, list) = get_json(
            &app,
            "/api/v1/admin/jobs?queue=release-download&state=queued",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(
            list.as_array()
                .expect("list")
                .iter()
                .any(|item| item["job_id"] == job_id.as_str()),
            "{list}"
        );

        let (status, one) = get_json(&app, &format!("/api/v1/admin/jobs/{job_id}")).await;
        assert_eq!(status, StatusCode::OK, "{one}");
        assert_eq!(one["state"], crate::infra::JOB_QUEUED);

        let (status, canceled) = post_json(
            &app,
            &format!("/api/v1/admin/jobs/{job_id}/cancel"),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{canceled}");
        assert_eq!(canceled["state"], crate::infra::JOB_CANCELED);

        // release 领域视图同步显示已取消。
        let (status, view) = get_json(&app, &format!("/api/v1/admin/release-jobs/{job_id}")).await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["state"], crate::infra::JOB_CANCELED);

        // 已是终态 → 不能再取消。
        let (status, body) = post_json(
            &app,
            &format!("/api/v1/admin/jobs/{job_id}/cancel"),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            body["error"]["code"],
            super::super::codes::JOB_NOT_CANCELABLE
        );

        // 未知任务 → 404。
        let (status, _) = get_json(&app, "/api/v1/admin/jobs/job-nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/jobs/job-nope/cancel",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// 单条录入：来源文件名就能看出是别的组件 → **下载前**即拒（不碰网络 / 磁盘）。
    ///
    /// 用**不存在**的本地路径：若走到取件步会得到 502；预检在下载前拦下 → 必是 400。
    #[tokio::test]
    async fn publish_release_rejects_a_wrong_component_before_downloading() {
        let app = super::super::router_for(test_state());
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd",
            serde_json::json!({
                "version": "0.7.1",
                "artifact_url":
                    "/nonexistent/wist-gwlinkd-v0.7.1-alpha-aarch64-apple-darwin.tar.gz",
                "expected_sha256": "0".repeat(64),
                "requested_by": "tester",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::ARTIFACT_COMPONENT_MISMATCH
        );
        // 不落记录。
        let (_, none_yet) = get_json(&app, "/api/v1/admin/releases/wist-agentd").await;
        assert_eq!(none_yet, serde_json::json!([]));
    }

    /// 单条录入：来源**读不出包名**（哈希名 / 临时名）→ 预检放行，权威判定仍在下载之后。
    ///
    /// 同样用不存在的路径：既然放行到取件步，就会得到 502（取件失败）而**不是** 400 ——
    /// 证明预检没有误拒。
    #[tokio::test]
    async fn publish_release_defers_the_component_check_when_the_source_has_no_name() {
        let app = super::super::router_for(test_state());
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd",
            serde_json::json!({
                "version": "0.1.0",
                "artifact_url": "/nonexistent/pkg-955e0dc75215c3a6",
                "expected_sha256": "0".repeat(64),
                "requested_by": "tester",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::ARTIFACT_FETCH_FAILED
        );
    }

    #[test]
    fn component_package_mismatch_rejects_a_package_of_another_component() {
        // 把 gwlinkd 包录成 wist-agentd → 拒，并指出该发到哪个组件。
        let detail = component_package_mismatch(
            "wist-agentd",
            "wist-gwlinkd-v0.7.1-alpha-aarch64-apple-darwin.tar.gz",
            b"not-a-tarball",
        )
        .expect("must flag the mismatch");
        assert!(detail.contains("wist-gwlinkd"), "{detail}");
        // 组件对得上 → 放行。
        assert!(
            component_package_mismatch(
                "wist-agentd",
                "wist-agentd-v0.2.1-alpha-aarch64-apple-darwin.tar.gz",
                b"x"
            )
            .is_none()
        );
        // 部署栈包（包内顶层是 `sys/…`）：包名回落文件名 → 仍能对上组件。
        assert!(
            component_package_mismatch(
                "wist-gateway-stack",
                "wist-gateway-stack-v0.1.26-alpha.tar.gz",
                b"x"
            )
            .is_none()
        );
        // 取不出包名（`pkg-<hash>` / 临时名）→ 也拒（fail-closed）。
        assert!(component_package_mismatch("wist-agentd", "pkg-955e0dc75215c3a6", b"x").is_some());
        // 包名是别的（哪怕不是「已知组件」）→ 拒。
        assert!(
            component_package_mismatch("galaxy-ops", "some-tool-v1.2.3-linux.tar.gz", b"x")
                .is_some()
        );
    }

    #[test]
    fn source_component_mismatch_flags_a_wrong_component_before_any_download() {
        // 来源文件名就能看出是别的组件 → 预检直接拒（**不需下载字节**）。
        let detail = source_component_mismatch(
            "wist-agentd",
            "https://github.com/dayu-sec/wist-gwlinkd/releases/download/v0.7.1-alpha/wist-gwlinkd-v0.7.1-alpha-aarch64-apple-darwin.tar.gz",
        )
        .expect("must flag the mismatch from the source name alone");
        assert!(detail.contains("wist-gwlinkd"), "{detail}");
        // 组件对得上 → 放行。
        assert!(
            source_component_mismatch(
                "wist-agentd",
                "https://github.com/dayu-sec/wist-agentd/releases/download/v0.2.1-alpha/wist-agentd-v0.2.1-alpha-aarch64-apple-darwin.tar.gz",
            )
            .is_none()
        );
        // 来源读不出包名（只有版本 / 哈希名 / 临时名）→ 放行，交给下载后的完整校验定夺。
        for source in [
            "https://artifacts.example.com/wist-agentd/v2.4.1-aarch64-apple-darwin.tar.gz",
            "pkg-955e0dc75215c3a6",
            "/tmp/wic-rel-1728.tar.gz",
        ] {
            assert!(
                source_component_mismatch("wist-agentd", source).is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn source_component_mismatch_ignores_query_and_fragment() {
        // GitHub Release / 对象存储签名链常带查询串、fragment：只取末段，不受影响。
        assert!(
            source_component_mismatch(
                "wist-agentd",
                "https://x.example/wist-agentd-v0.2.1-alpha-aarch64-apple-darwin.tar.gz?token=abc#frag",
            )
            .is_none()
        );
        let detail = source_component_mismatch(
            "wist-agentd",
            "https://x.example/wist-gwlinkd-v0.7.1-alpha-x86_64-unknown-linux-musl.tar.gz?token=abc",
        )
        .expect("must flag the mismatch despite the query string");
        assert!(detail.contains("wist-gwlinkd"), "{detail}");
    }

    /// 平台落库（二进制包从顶层目录名切 target-triple）+ 托管状态管理（published ↔ expired）。
    #[tokio::test]
    async fn publish_records_platform_and_release_status_is_manageable() {
        let bytes = tar_gz_with_entry(
            "wist-agentd-0.1.9-aarch64-apple-darwin/wist-agentd",
            b"agentd-bin",
        );
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let pkg = std::env::temp_dir().join(format!("wic-platform-{nanos}.tar.gz"));
        std::fs::write(&pkg, &bytes).expect("write");
        let source = pkg.to_string_lossy().to_string();
        let sha = crate::infra::sha256_hex_bytes(&bytes);

        let app = super::super::router_for(test_state());

        // 发布：版本自报 `0.1.9`，平台从目录名切出。
        let (status, record) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd",
            serde_json::json!({
                "artifact_url": source,
                "expected_sha256": sha,
                "requested_by": "tester",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(record["version"], "0.1.9");
        assert_eq!(record["artifacts"][0]["platform"], "aarch64-apple-darwin");
        assert_eq!(record["status"], "published");

        // 标记过期 → 200，回执状态同步。
        let (status, expired) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd/0.1.9/status",
            serde_json::json!({ "status": "expired" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(expired["status"], "expired");

        // 列表接口随之看到过期态。
        let (list_status, list) = get_json(&app, "/api/v1/admin/releases/wist-agentd").await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(list[0]["status"], "expired");
        assert_eq!(list[0]["artifacts"][0]["platform"], "aarch64-apple-darwin");

        // 恢复在用。
        let (status, restored) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd/0.1.9/status",
            serde_json::json!({ "status": "published" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(restored["status"], "published");

        // 非法状态 → 400；不存在的版本 → 404。
        let (bad_status, _) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd/0.1.9/status",
            serde_json::json!({ "status": "bogus" }),
        )
        .await;
        assert_eq!(bad_status, StatusCode::BAD_REQUEST);
        let (missing, _) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd/9.9.9/status",
            serde_json::json!({ "status": "expired" }),
        )
        .await;
        assert_eq!(missing, StatusCode::NOT_FOUND);

        let _ = std::fs::remove_file(pkg);
    }

    /// 顶层目录只有 `<name>-<version>`（无 target-triple）时，**平台回落来源文件名** ——
    /// galaxy-ops 实例（`galaxy-ops-v2.2.1-alpha-aarch64-apple-darwin.tar.gz`）。
    #[tokio::test]
    async fn publish_recovers_platform_from_the_source_name_when_dir_has_none() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-galaxy-ops-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // 包内顶层目录名不带 triple（真实 galaxy-ops 包的形态）；平台只在文件名里。
        let pkg = dir.join("galaxy-ops-v2.2.1-alpha-aarch64-apple-darwin.tar.gz");
        let bytes = tar_gz_with_entry("galaxy-ops-v2.2.1-alpha/galaxy-ops", b"gops-bin");
        std::fs::write(&pkg, &bytes).expect("write");
        let source = pkg.to_string_lossy().to_string();
        let sha = crate::infra::sha256_hex_bytes(&bytes);

        let app = super::super::router_for(test_state());
        let (status, record) = post_json(
            &app,
            "/api/v1/admin/releases/galaxy-ops",
            serde_json::json!({
                "artifact_url": source,
                "expected_sha256": sha,
                "requested_by": "tester",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(record["version"], "v2.2.1-alpha");
        assert_eq!(record["artifacts"][0]["platform"], "aarch64-apple-darwin");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 幂等命中时补齐历史记录缺失的平台（同一份内容重复发布不重复下副本，只补平台）。
    #[tokio::test]
    async fn republish_backfills_platform_on_an_existing_record() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-heal-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let pkg = dir.join("galaxy-ops-v2.2.1-alpha-aarch64-apple-darwin.tar.gz");
        let bytes = tar_gz_with_entry("galaxy-ops-v2.2.1-alpha/galaxy-ops", b"gops-bin");
        std::fs::write(&pkg, &bytes).expect("write");
        let source = pkg.to_string_lossy().to_string();
        let sha = crate::infra::sha256_hex_bytes(&bytes);

        let state = test_state();
        // 预置一条「旧」记录：同一版本 + 同一 sha，但平台为空（模拟身份解析改好前录的）。
        let seeded = state
            .store
            .publish_release("galaxy-ops", "v2.2.1-alpha", &source, Some(&sha), None)
            .await
            .expect("seed");
        assert!(seeded.platform.is_none());

        let app = super::super::router_for(state);
        // 重复发布同一份内容 → 幂等命中，但平台被补齐。
        let (status, record) = post_json(
            &app,
            "/api/v1/admin/releases/galaxy-ops",
            serde_json::json!({
                "artifact_url": source,
                "expected_sha256": sha,
                "requested_by": "tester",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(record["version"], "v2.2.1-alpha");
        assert_eq!(record["artifacts"][0]["platform"], "aarch64-apple-darwin");

        // 列表接口也看到补齐后的平台。
        let (_, list) = get_json(&app, "/api/v1/admin/releases/galaxy-ops").await;
        assert_eq!(list[0]["artifacts"][0]["platform"], "aarch64-apple-darwin");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 补齐平台只在**该内容所在的那一行**发生：同版本其它平台的制品行不受影响
    /// （否则旧的无平台记录一旦重发其中一个平台，会把整包都写成同一个平台）。
    #[tokio::test]
    async fn backfill_platform_touches_only_the_matching_artifact_row() {
        let mac = tar_gz_with_entry("galaxy-ops-v2.2.1-alpha/galaxy-ops", b"mac-bin");
        let linux = tar_gz_with_entry("galaxy-ops-v2.2.1-alpha/galaxy-ops", b"linux-bin");
        let mac_sha = crate::infra::sha256_hex_bytes(&mac);
        let linux_sha = crate::infra::sha256_hex_bytes(&linux);
        assert_ne!(mac_sha, linux_sha);

        let state = test_state();
        // 预置两条同版本、不同内容的「旧」记录，平台都为空。
        state
            .store
            .publish_release(
                "galaxy-ops",
                "v2.2.1-alpha",
                "src-mac",
                Some(&mac_sha),
                None,
            )
            .await
            .expect("seed mac");
        state
            .store
            .publish_release(
                "galaxy-ops",
                "v2.2.1-alpha",
                "src-linux",
                Some(&linux_sha),
                None,
            )
            .await
            .expect("seed linux");

        // 只补 mac 那一行。
        let updated = state
            .store
            .set_release_platform(
                "galaxy-ops",
                "v2.2.1-alpha",
                &mac_sha,
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("backfill")
            .expect("row");
        assert_eq!(updated.platform.as_deref(), Some("aarch64-apple-darwin"));

        let records = state.store.list_releases("galaxy-ops").await.expect("list");
        let find = |sha: &str| {
            records
                .iter()
                .find(|record| record.package_sha256.as_deref() == Some(sha))
                .expect("record")
        };
        assert_eq!(
            find(&mac_sha).platform.as_deref(),
            Some("aarch64-apple-darwin")
        );
        assert!(
            find(&linux_sha).platform.is_none(),
            "同版本其它平台行不该被覆盖"
        );
    }

    /// 多平台批量录入：galaxy-ops / galaxy-flow 必须三平台（macOS-ARM / Linux-ARM / Linux-X86）齐备，
    /// 缺一即整体拒绝且不落记录；齐备则一次落三条（同版本）。
    #[tokio::test]
    async fn batch_publish_requires_and_records_all_three_platforms() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-batch-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mk = |triple: &str, payload: &[u8]| -> (String, String) {
            let bytes = tar_gz_with_entry(
                &format!("galaxy-ops-v2.2.1-alpha-{triple}/galaxy-ops"),
                payload,
            );
            let path = dir.join(format!("galaxy-ops-v2.2.1-alpha-{triple}.tar.gz"));
            std::fs::write(&path, &bytes).expect("write");
            (
                path.to_string_lossy().to_string(),
                crate::infra::sha256_hex_bytes(&bytes),
            )
        };
        let (macos, macos_sha) = mk("aarch64-apple-darwin", b"mac-bin");
        let (linux_x86, lx_sha) = mk("x86_64-unknown-linux-musl", b"lx-bin");
        let (linux_arm, la_sha) = mk("aarch64-unknown-linux-musl", b"la-bin");

        let app = super::super::router_for(test_state());

        // 缺一个平台（只给两个）→ 400，且**不落**记录。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/releases/galaxy-ops/batch",
            serde_json::json!({
                "requested_by": "tester",
                "artifacts": [
                    { "artifact_url": macos, "expected_sha256": macos_sha },
                    { "artifact_url": linux_x86, "expected_sha256": lx_sha },
                ],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (_, none_yet) = get_json(&app, "/api/v1/admin/releases/galaxy-ops").await;
        assert_eq!(none_yet, serde_json::json!([]));

        // 三平台齐备 → 200，回**一个安装包**（同版本、三个平台制品各一）。
        let artifacts = serde_json::json!([
            { "artifact_url": macos, "expected_sha256": macos_sha },
            { "artifact_url": linux_x86, "expected_sha256": lx_sha },
            { "artifact_url": linux_arm, "expected_sha256": la_sha },
        ]);
        let (status, package) = post_json(
            &app,
            "/api/v1/admin/releases/galaxy-ops/batch",
            serde_json::json!({ "requested_by": "tester", "artifacts": artifacts.clone() }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(package["version"], "v2.2.1-alpha");
        let package_artifacts = package["artifacts"].as_array().expect("artifacts");
        assert_eq!(package_artifacts.len(), 3);
        let mut platforms: Vec<String> = package_artifacts
            .iter()
            .map(|artifact| {
                artifact["platform"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        platforms.sort();
        assert_eq!(
            platforms,
            vec![
                "aarch64-apple-darwin",
                "aarch64-unknown-linux-musl",
                "x86_64-unknown-linux-musl",
            ]
        );

        // 同一批重复提 → 幂等，仍是一个包（三个平台各一，不重复）。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/releases/galaxy-ops/batch",
            serde_json::json!({ "requested_by": "tester", "artifacts": artifacts }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, list) = get_json(&app, "/api/v1/admin/releases/galaxy-ops").await;
        let list = list.as_array().expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["artifacts"].as_array().expect("artifacts").len(), 3);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// agentd 与 galaxy-ops / galaxy-flow 共用同一份发布矩阵（macOS-ARM + Linux x86_64 / ARM64 的
    /// musl 版）—— 网关按平台分别托管 agent 安装包，少一个平台就有主机装不上。
    /// 批量录入时缺平台即整体拒绝，齐备则一次落三条（同版本）。
    #[tokio::test]
    async fn batch_publish_requires_all_three_platforms_for_agentd() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-batch-agentd-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // agentd 包名带 target-triple：`wist-agentd-<version>-<triple>.tar.gz`，顶层一层同名目录。
        let mk = |triple: &str, payload: &[u8]| -> (String, String) {
            let bytes =
                tar_gz_with_entry(&format!("wist-agentd-0.2.1-{triple}/wist-agentd"), payload);
            let path = dir.join(format!("wist-agentd-0.2.1-{triple}.tar.gz"));
            std::fs::write(&path, &bytes).expect("write");
            (
                path.to_string_lossy().to_string(),
                crate::infra::sha256_hex_bytes(&bytes),
            )
        };
        let (macos, macos_sha) = mk("aarch64-apple-darwin", b"agentd-mac");
        let (linux_x86, lx_sha) = mk("x86_64-unknown-linux-musl", b"agentd-lx");
        let (linux_arm, la_sha) = mk("aarch64-unknown-linux-musl", b"agentd-la");

        let app = super::super::router_for(test_state());

        // 只给两个平台 → 400，且不落记录（拒绝原因是纯文本，故只看状态码与落库结果）。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd/batch",
            serde_json::json!({
                "requested_by": "tester",
                "artifacts": [
                    { "artifact_url": macos, "expected_sha256": macos_sha },
                    { "artifact_url": linux_x86, "expected_sha256": lx_sha },
                ],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (_, none_yet) = get_json(&app, "/api/v1/admin/releases/wist-agentd").await;
        assert_eq!(none_yet, serde_json::json!([]));

        // 三平台齐备 → 200，回一个包（同版本、三个平台制品各一）。
        let (status, package) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd/batch",
            serde_json::json!({
                "requested_by": "tester",
                "artifacts": [
                    { "artifact_url": macos, "expected_sha256": macos_sha },
                    { "artifact_url": linux_x86, "expected_sha256": lx_sha },
                    { "artifact_url": linux_arm, "expected_sha256": la_sha },
                ],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(package["version"], "0.2.1");
        let mut platforms: Vec<String> = package["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .map(|artifact| {
                artifact["platform"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        platforms.sort();
        assert_eq!(
            platforms,
            vec![
                "aarch64-apple-darwin",
                "aarch64-unknown-linux-musl",
                "x86_64-unknown-linux-musl",
            ]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 批量录入时若某个制品的**来源文件名**明显是别的组件 → 下载前就整体拒。
    ///
    /// 用**不存在**的本地路径做锯齿：若走到取件步会得到 502（取件失败）；预检在下载前拦下 →
    /// 必是 400 且错误码为 `artifact_component_mismatch`（而非缺平台的 `artifact_invalid`）。
    #[tokio::test]
    async fn batch_publish_rejects_a_wrong_component_before_downloading() {
        let app = super::super::router_for(test_state());
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/releases/wist-agentd/batch",
            serde_json::json!({
                "requested_by": "tester",
                "artifacts": [
                    {
                        "artifact_url":
                            "/nonexistent/wist-gwlinkd-v0.7.1-alpha-aarch64-apple-darwin.tar.gz",
                        "expected_sha256": "0".repeat(64),
                    },
                ],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::ARTIFACT_COMPONENT_MISMATCH
        );
        // 不落记录。
        let (_, none_yet) = get_json(&app, "/api/v1/admin/releases/wist-agentd").await;
        assert_eq!(none_yet, serde_json::json!([]));
    }

    /// gateway-stack 包（顶层 `sys/…`，无包装目录）：身份来自**文件名**，版本核对同样生效。
    #[tokio::test]
    async fn publish_release_reads_gateway_stack_identity_from_the_filename() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-stack-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let pkg = dir.join("wist-gateway-stack-v0.1.17.tar.gz");
        let bytes = tar_gz_with_entry("sys/sys_model.yml", b"model");
        let sha = crate::infra::sha256_hex_bytes(&bytes);
        std::fs::write(&pkg, &bytes).expect("write");
        let source = pkg.to_string_lossy().to_string();

        let publish = |version: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/releases/wist-gateway-stack")
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "version": version,
                        "artifact_url": source,
                        "expected_sha256": sha,
                        "requested_by": "tester",
                    })
                    .to_string(),
                ))
                .expect("request")
        };

        let app = super::super::router_for(test_state());
        // 声明 0.1.18，文件名说 v0.1.17 → 400。
        let mismatched = app
            .clone()
            .oneshot(publish("0.1.18"))
            .await
            .expect("response");
        assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);

        // 声明 0.1.17（与文件名归一化后一致）→ 放行。
        let ok = app.oneshot(publish("0.1.17")).await.expect("response");
        assert_eq!(ok.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 不传 `version`：从**文件名**自动解析（例：galaxy-flow 的发布包）。
    #[tokio::test]
    async fn publish_release_derives_version_from_the_artifact_name() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-derive-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let pkg = dir.join("galaxy-flow-v0.16.1-alpha-x86_64-unknown-linux-musl.tar.gz");
        std::fs::write(&pkg, b"flow-bytes").expect("write");
        let source = pkg.to_string_lossy().to_string();

        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/releases/galaxy-flow")
                    .header("authorization", "Bearer admin-tok")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "artifact_url": source,
                            "expected_sha256": crate::infra::sha256_hex_bytes(b"flow-bytes"),
                            "requested_by": "tester",
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let record: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(record["version"], serde_json::json!("v0.16.1-alpha"));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 既不传 `version`、文件名又没有版本号 → 400（不静默落一个空版本）。
    #[tokio::test]
    async fn publish_release_rejects_when_version_cannot_be_derived() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let pkg = std::env::temp_dir().join(format!("wic-novers-{nanos}.tar.gz"));
        std::fs::write(&pkg, b"payload").expect("write");

        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/releases/galaxy-flow")
                    .header("authorization", "Bearer admin-tok")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "artifact_url": pkg.to_string_lossy(),
                            "expected_sha256": crate::infra::sha256_hex_bytes(b"payload"),
                            "requested_by": "tester",
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_file(pkg);
    }

    /// 同一 `(component, version)` 的**同一份内容**（哪怕来源文件名不同）→ 幂等：返回同一条记录。
    /// 内容寻址不在文件名上（文件名用来源原名），而在 `package_sha256` + `(component, version, sha)`。
    #[tokio::test]
    async fn publish_release_dedups_identical_content_by_digest() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wic-rel-dedup-{nanos}"));
        std::fs::create_dir_all(&dir).expect("dir");
        // 包名要与组件一致（`wist-agentd-…`）：两条来源文件名不同、但同组件同版本、同内容。
        let first = dir.join("wist-agentd-0.1.32-aarch64-apple-darwin.tar.gz");
        let second = dir.join("wist-agentd-0.1.32-x86_64-unknown-linux-musl.tar.gz");
        std::fs::write(&first, b"same-content").expect("write a");
        std::fs::write(&second, b"same-content").expect("write b");

        let publish = |source: &std::path::Path, version: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/releases/wist-agentd")
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "version": version,
                        "artifact_url": source.to_string_lossy(),
                        "expected_sha256": crate::infra::sha256_hex_bytes(b"same-content"),
                        "requested_by": "tester",
                    })
                    .to_string(),
                ))
                .expect("request")
        };

        let app = super::super::router_for(test_state());
        let json_of = |response: axum::response::Response| async move {
            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            serde_json::from_slice::<serde_json::Value>(&body).expect("json")
        };

        let response = app
            .clone()
            .oneshot(publish(&first, "0.1.32"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let first_record = json_of(response).await;
        // 文件名用来源原名。
        let first_name = first.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            first_record["artifacts"][0]["source"]
                .as_str()
                .unwrap_or_default()
                .ends_with(&first_name),
            "{first_record}"
        );

        // 同一内容换一个来源文件名再发（同版本）→ 命中幂等，回同一条记录。
        let response = app
            .oneshot(publish(&second, "0.1.32"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let second_record = json_of(response).await;
        assert_eq!(
            first_record["artifacts"][0]["source"], second_record["artifacts"][0]["source"],
            "同内容同版本 → 幂等，不落第二份"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 包内自报版本与声明版本不符 → 400 拒录；归一化后一致（带 `v`）→ 放行。
    #[tokio::test]
    async fn publish_release_cross_checks_the_declared_version_against_the_package() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let pkg = std::env::temp_dir().join(format!("wic-rel-id-{nanos}.tar.gz"));
        let bytes = tar_gz_with_entry(
            "wist-agentd-0.1.32-x86_64-unknown-linux-gnu/wist-agentd",
            b"agentd-0.1.32",
        );
        let sha = crate::infra::sha256_hex_bytes(&bytes);
        std::fs::write(&pkg, &bytes).expect("write");
        let source = pkg.to_string_lossy().to_string();

        let publish = |version: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/releases/wist-agentd")
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "version": version,
                        "artifact_url": source,
                        "expected_sha256": sha,
                        "requested_by": "tester",
                    })
                    .to_string(),
                ))
                .expect("request")
        };

        let app = super::super::router_for(test_state());
        // 声明 0.1.99，包内自报 0.1.32 → 400，且不落记录。
        let mismatched = app
            .clone()
            .oneshot(publish("0.1.99"))
            .await
            .expect("response");
        assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);

        // 带 `v` 前缀、与包内自报归一化后一致 → 放行。
        let ok = app.oneshot(publish("v0.1.32")).await.expect("response");
        assert_eq!(ok.status(), StatusCode::OK);

        let _ = std::fs::remove_file(pkg);
    }

    /// 造一个只含单条目的 gzip+tar（顶层目录名 + 一个文件），用于验包身份解析。
    fn tar_gz_with_entry(entry: &str, payload: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, entry, payload)
                .expect("append tar entry");
            builder.finish().expect("finish tar");
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar_bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    #[tokio::test]
    async fn agent_history_without_vm_returns_empty_samples() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways/gw-001/agents/agent-1/history?window=1h")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let returned: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(returned["gateway_id"], "gw-001");
        assert_eq!(returned["agent_id"], "agent-1");
        assert_eq!(returned["samples"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn never_reported_gateway_is_offline_not_listed() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-never-{nanos}.json"));
        let store = FileStore::new(&path);
        store
            .seed(&[
                GatewayCredentialSeed {
                    gateway_id: "gw-001".to_string(),
                    token: "tok-a".to_string(),
                    expires_at: None,
                },
                // gw-002 从未上报
                GatewayCredentialSeed {
                    gateway_id: "gw-002".to_string(),
                    token: "tok-b".to_string(),
                    expires_at: None,
                },
            ])
            .expect("seed");
        store
            .update(|snapshot| {
                if let Some(gw) = snapshot.gateways.get_mut("gw-001") {
                    gw.status = Some("online".to_string());
                    gw.health = Some("healthy".to_string());
                    gw.last_seen_at = Some(DateTime::now());
                }
            })
            .expect("update");
        let store: std::sync::Arc<dyn crate::infra::Store> = std::sync::Arc::new(store);
        let artifact_store: std::sync::Arc<dyn crate::infra::ArtifactStore> =
            std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            ));
        let jobs = crate::infra::release_job_queue(store.clone(), artifact_store.clone());
        let state = ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                store_path: std::env::temp_dir().join(format!("wic-never-{nanos}.json")),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                gateway_project_repo: "https://wgc-git.beta.jingang.cloud/gateway-tx.git"
                    .to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                package_sources: Vec::new(),
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
                wparse_proxy: crate::config::WparseProxyConfig {
                    enabled: false,
                    listen_addr: "0.0.0.0:3101".to_string(),
                },
                wparse_release: Default::default(),
                log: Default::default(),
            },
            store,
            artifact_store,
            gateway_ca: test_gateway_ca(),
            proxy: None,
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
            jobs,
        };
        let app = super::super::router_for(state);

        // 聚合：gw-002（未上报）计入 offline，online + offline = gateway_count。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let list: AdminGatewayListReturned = serde_json::from_slice(&body).expect("json");
        assert_eq!(list.list.gateway_count, 2);
        assert_eq!(list.list.online_count, 1);
        assert_eq!(list.list.offline_count, 1);

        // 列表：只含已上报的 gw-001。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways/status")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let list: AdminGatewayStatusListReturned = serde_json::from_slice(&body).expect("json");
        assert_eq!(list.statuses.len(), 1);
        assert_eq!(list.statuses[0].gateway_id, "gw-001");

        // 单查：未上报的 gw-002 → 404。
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways/gw-002/status")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_aggregates_from_store() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let state = test_state();
        let app = super::super::router_for(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let returned: AdminGatewayListReturned = serde_json::from_slice(&body).expect("json");
        assert_eq!(returned.list.gateway_count, 2);
        assert_eq!(returned.list.online_count, 1);
        assert_eq!(returned.list.offline_count, 1);
        assert_eq!(returned.list.degraded_count, 1);
    }

    /// F2 回归：在线判定必须**新鲜** —— 只看状态字符串会让掉线的网关永远「在线」。
    #[test]
    fn gateway_is_online_requires_a_fresh_last_seen() {
        let mut gw =
            StoredGateway::provisioned("gw-1".into(), "inst-1".into(), String::new(), None);
        // 从未上报 → 不在线。
        assert!(!super::gateway_is_online(&gw));

        // 上报 online + 新鲜 → 在线。
        gw.status = Some("online".into());
        gw.last_seen_at = Some(DateTime::now());
        assert!(super::gateway_is_online(&gw));

        // 上报 online 但**陈旧**（远超窗口）→ 掉线，不算在线。
        gw.last_seen_at = Some(DateTime::from_rfc3339("2020-01-01T00:00:00Z").expect("ts"));
        assert!(
            !super::gateway_is_online(&gw),
            "陈旧的上报不算在线（F2：gwlinkd 停报后不能永远在线）"
        );

        // 新鲜但状态非 online → 不在线。
        gw.last_seen_at = Some(DateTime::now());
        gw.status = Some("offline".into());
        assert!(!super::gateway_is_online(&gw));
    }

    #[tokio::test]
    async fn admin_auth_failures_are_rate_limited() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let state = test_state();
        let app = super::super::router_for(state);
        for _ in 0..5 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/admin/gateways/status")
                        .header("authorization", "Bearer wrong-token")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        // 第 6 次即使带正确 token 也被限流（测试环境共享 "unknown" 桶）。
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways/status")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn removed_list_alias_route_is_gone() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let state = test_state();
        let app = super::super::router_for(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways/list")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn create_state_with_store(store: FileStore) -> ApiState {
        let store: std::sync::Arc<dyn crate::infra::Store> = std::sync::Arc::new(store);
        let artifact_store: std::sync::Arc<dyn crate::infra::ArtifactStore> =
            std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            ));
        let jobs = crate::infra::release_job_queue(store.clone(), artifact_store.clone());
        ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                store_path: std::env::temp_dir().join("unused.json"),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                // 刻意不用产品默认值：install-all 的断言据此证明脚本里的仓库来自配置（而非硬编码）。
                gateway_project_repo: "https://git.example.test/gateway-tx.git".to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                package_sources: Vec::new(),
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
                wparse_proxy: crate::config::WparseProxyConfig {
                    enabled: false,
                    listen_addr: "0.0.0.0:3101".to_string(),
                },
                wparse_release: Default::default(),
                log: Default::default(),
            },
            store,
            artifact_store,
            gateway_ca: test_gateway_ca(),
            proxy: None,
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
            jobs,
        }
    }

    fn create_payload(gateway_name: &str) -> String {
        format!(r#"{{"gateway_name":"{gateway_name}","requested_by":"test"}}"#)
    }

    /// POST 生成/轮换接入券，返回解析后的响应。
    async fn rotate_link_token(
        app: &axum::Router,
        gateway_id: &str,
    ) -> AdminRotateGatewayLinkTokenReturned {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/admin/gateways/{gateway_id}/link-token"))
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(r#"{"requested_by":"test"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        serde_json::from_slice(&body).expect("json")
    }

    #[tokio::test]
    async fn create_gateway_instance_creates_and_conflicts() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-create-{nanos}.json"));
        let state = create_state_with_store(FileStore::new(&path));
        let app = super::super::router_for(state);

        // 创建 → 201 + instance。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(create_payload("gw-create")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let returned: AdminCreateGatewayInstanceReturned =
            serde_json::from_slice(&body).expect("json");
        assert_eq!(returned.instance.gateway_id, "gw-create");
        assert_eq!(
            returned.instance.lifecycle_state,
            GatewayInstanceLifecycleState::Provisioned
        );
        // 设计 §8：create 响应**不含**安装指引/接入凭据（券由「生成/轮换」产出）。

        // 实例列表公开可重复获取的初始化 URL，但不重复返回安装命令或凭证。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/gateways/instances")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let listed = json
            .as_array()
            .and_then(|items| items.iter().find(|item| item["gateway_id"] == "gw-create"))
            .expect("created instance json");
        assert!(listed.get("init_url").is_some());
        assert!(listed.get("install").is_none());
        assert!(listed.get("install_command").is_none());
        assert!(listed.get("token").is_none());
        let instances: Vec<AdminGatewayInstanceView> = serde_json::from_slice(&body).expect("json");
        let created = instances
            .iter()
            .find(|instance| instance.gateway_id == "gw-create")
            .expect("created instance");
        assert_eq!(
            created.init_url,
            "http://127.0.0.1:3100/api/v1/gateway/link-upstream?gateway_id=gw-create"
        );

        // 重复创建同一 gateway_id → 409。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(create_payload("gw-create")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // 引导 token 不是运行期凭据：create 后立即用它调 /status → 401
        // （运行期凭据须在 /register 消费 RegistToken 后签发，见 gateway_ops register 测试）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer tok-create")
                    .body(Body::from(
                        r#"{"gateway_id":"gw-create","instance_id":"inst-1","version":"v2.4.1","status":"online","health":"healthy","reported_at":"2026-08-08T12:00:00Z"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn rotate_gateway_link_token_replaces_and_delivers_once() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-rotate-{nanos}.json"));
        let state = create_state_with_store(FileStore::new(&path));
        let app = super::super::router_for(state);

        // create 只建实例（**不签发/不交付券**）；接入券一律由「生成/轮换」产出。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(create_payload("gw-rot")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);

        // 首次「生成/轮换」→ 券1（一次性明文 + 到期时刻）。
        let first = rotate_link_token(&app, "gw-rot").await;
        assert_eq!(first.gateway_id, "gw-rot");
        assert!(!first.install.link_token.is_empty());
        assert!(first.link_expires_at.is_some(), "应带短 TTL 到期时刻");
        assert_eq!(
            first.install.init_url,
            "http://127.0.0.1:3100/api/v1/gateway/link-upstream?gateway_id=gw-rot"
        );

        // 再次轮换 → 券2 ≠ 券1（旧券作废）。
        let second = rotate_link_token(&app, "gw-rot").await;
        assert_ne!(second.install.link_token, first.install.link_token);

        // store 侧：券1 被覆盖（失效），券2 可消费（初始化置备用）。
        let store = FileStore::new(&path);
        assert!(
            !store
                .consume_link_token("gw-rot", &first.install.link_token)
                .expect("consume old")
        );
        assert!(
            store
                .consume_link_token("gw-rot", &second.install.link_token)
                .expect("consume new")
        );

        // 未知网关：不签发、返回 404。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/gw-missing/link-token")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(r#"{"requested_by":"test"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_gateway_instance_rejects_empty_name() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-create-empty-{nanos}.json"));
        let state = create_state_with_store(FileStore::new(&path));
        let app = super::super::router_for(state);

        for payload in [
            r#"{"gateway_name":"  ","requested_by":"test"}"#,
            r#"{"gateway_name":"gw-x","requested_by":"  "}"#,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/admin/gateways/instances")
                        .header("content-type", "application/json")
                        .header("authorization", "Bearer admin-tok")
                        .body(Body::from(payload))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_gateway_instance_mounts_trust_bundle_when_ca_configured() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-create-tb-{nanos}.json"));
        let store = FileStore::new(&path);
        let store: std::sync::Arc<dyn crate::infra::Store> = std::sync::Arc::new(store);
        let artifact_store: std::sync::Arc<dyn crate::infra::ArtifactStore> =
            std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            ));
        let jobs = crate::infra::release_job_queue(store.clone(), artifact_store.clone());
        let state = ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                store_path: std::env::temp_dir().join(format!("wic-create-tb-{nanos}.json")),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                gateway_project_repo: "https://wgc-git.beta.jingang.cloud/gateway-tx.git"
                    .to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                package_sources: Vec::new(),
                ca_cert: Some(
                    "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----".to_string(),
                ),
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
                wparse_proxy: crate::config::WparseProxyConfig {
                    enabled: false,
                    listen_addr: "0.0.0.0:3101".to_string(),
                },
                wparse_release: Default::default(),
                log: Default::default(),
            },
            store,
            artifact_store,
            gateway_ca: test_gateway_ca(),
            proxy: None,
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
            jobs,
        };
        let app = super::super::router_for(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(create_payload("gw-tb")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let created: AdminCreateGatewayInstanceReturned =
            serde_json::from_slice(&body).expect("json");
        assert_eq!(created.instance.gateway_id, "gw-tb");
        // 安装指引（含 CA 挂载 + 接入券）现在随「生成/轮换」交付，不在 create 响应里。
        let rotated = rotate_link_token(&app, "gw-tb").await;
        assert!(rotated.install.trust_bundle_pem.is_some());
        assert!(
            rotated
                .install
                .install_command
                .contains("-v ./control-center.pem:/etc/wist-gateway/ca/control-center.pem:ro")
        );
        assert!(!rotated.install.link_token.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn read_endpoints_require_admin_token() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let state = test_state();
        let app = super::super::router_for(state);
        for uri in [
            "/api/v1/admin/gateways",
            "/api/v1/admin/gateways/status",
            "/api/v1/admin/gateways/gw-001/status",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "uri {uri} should require admin token"
            );
        }
    }

    /// 全量安装：一次性接入券有效 → 返回 shell 脚本（含 gops/gx/gateway-stack 地址与六步流程）；
    /// 券无效 → 401。
    #[tokio::test]
    async fn install_all_serves_script_for_a_valid_one_time_token() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-install-all-{nanos}.json"));
        let state = create_state_with_store(FileStore::new(&path));

        // 预置三个组件的最新「已发布」制品（脚本会据此填下载地址）。
        let base = "http://127.0.0.1:3100/api/v1/releases/artifact";
        state
            .store
            .publish_release(
                "galaxy-ops",
                "1.2.3",
                &format!("{base}/galaxy-ops/1.2.3/gops-aarch64-apple-darwin.tar.gz"),
                Some("deadbeef"),
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("publish gops");
        state
            .store
            .publish_release(
                "galaxy-flow",
                "0.14.0",
                &format!("{base}/galaxy-flow/0.14.0/gx-aarch64-apple-darwin.tar.gz"),
                Some("deadbeef"),
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("publish gx");
        state
            .store
            .publish_release(
                "wist-gateway-stack",
                "0.1.17",
                &format!("{base}/wist-gateway-stack/0.1.17/wist-gateway-stack-0.1.17.tar.gz"),
                Some("deadbeef"),
                None,
            )
            .await
            .expect("publish stack");
        state
            .store
            .publish_release(
                "wist-gwlinkd",
                "0.6.1",
                &format!(
                    "{base}/wist-gwlinkd/0.6.1/wist-gwlinkd-0.6.1-aarch64-apple-darwin.tar.gz"
                ),
                Some("cafe"),
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("publish gwlinkd");

        let app = super::super::router_for(state);

        // 建实例（Provisioned）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(create_payload("gw-script")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);

        // 生成/轮换接入券：回执里带脚本安装命令（curl ... | bash）。
        let rotated = rotate_link_token(&app, "gw-script").await;
        let token = rotated.install.link_token.clone();
        assert!(
            rotated.install.install_all_command.contains("curl -fsSLk"),
            "command: {}",
            rotated.install.install_all_command
        );
        assert!(
            rotated
                .install
                .install_all_command
                .contains("/api/v1/gateway/install-all"),
            "command: {}",
            rotated.install.install_all_command
        );
        assert!(rotated.install.install_all_command.contains("token="));

        // 取脚本（正确 token）→ 200 + shell 脚本。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/gateway/install-all?gateway_id=gw-script&token={token}&domain=gw.example.com"
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.contains("shellscript"), "ct: {content_type}");
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .to_vec(),
        )
        .expect("utf8");
        for needle in [
            "git clone",
            // 仓库地址来自配置 `[artifacts] gateway_project_repo`（部署栈里由 vars 渲染）。
            "https://git.example.test/gateway-tx.git",
            "gops prj import",
            "gops sys localize",
            "gops run download",
            "gops run start",
            "aarch64-apple-darwin",
            "gw-script",
            "WEB_DOMAIN",
            "gw.example.com",
            // 宿主侧接入器：安装段 + 系统服务托管（主配置 + **现场态**两条路径都要显式给）。
            "wist-gwlinkd",
            "service install --system",
            "GWLINKD_GATEWAY_ID",
            "GWLINKD_IDENTITY_DIR",
            // 执行器写**绝对路径**：gwlinkd 服务 PATH 不含 $HOME/bin，相对名会在 spawn 时 ENOENT。
            "set_value \"$VALUES_FILE\" GWLINKD_UPGRADER_PROGRAM \"$INSTALL_DIR/gops\"",
            "configs/gwlinkd/gwlinkd.toml",
            "identity/gwlinkd/gwlinkd-pub.toml",
            "--pub-config",
            // 自更新：真实二进制放在运行用户可写的目录，PATH 上留符号链接。
            "/usr/local/lib/wist-gwlinkd",
            "GWLINKD_REAL_DIR=\"/usr/local/lib/wist-gwlinkd\"",
            "chown \"$DEPLOY_USER\" \"$GWLINKD_REAL_DIR\" \"$GWLINKD_REAL\"",
            "ln -sfn \"$GWLINKD_REAL\" \"$GWLINKD_BIN\"",
            "--bin \"$GWLINKD_BIN\"",
        ] {
            assert!(body.contains(needle), "script missing `{needle}`:\n{body}");
        }
        // `//` 不是 bash 注释：它会被当成命令执行（`//: is a directory`）。模板里别再写。
        assert!(
            !body.lines().any(|line| line.trim_start().starts_with("//")),
            "生成的脚本里不能有 `//` 注释：\n{body}"
        );

        // 券无效 → 401。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/gateway/install-all?gateway_id=gw-script&token=wrong")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// 必需组件不齐时的 503 要**点名**：缺哪个组件、是「没录过」还是「被标过期」。
    /// （旧文案把三个组件一并列出来，现场只能靠翻「包管理」自己找。）
    #[tokio::test]
    async fn install_all_names_the_component_that_is_missing_or_expired() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-install-missing-{nanos}.json"));
        let state = create_state_with_store(FileStore::new(&path));

        let base = "http://127.0.0.1:3100/api/v1/releases/artifact";
        state
            .store
            .publish_release(
                "galaxy-ops",
                "1.2.3",
                &format!("{base}/galaxy-ops/1.2.3/gops-aarch64-apple-darwin.tar.gz"),
                Some("deadbeef"),
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("publish gops");
        // galaxy-flow 根本不录 → 文案应写 `no release recorded`；
        // 栈录了但被标过期 → 文案应写 `expired`（而不是笼统让人去 publish）。
        state
            .store
            .publish_release(
                "wist-gateway-stack",
                "0.1.17",
                &format!("{base}/wist-gateway-stack/0.1.17/wist-gateway-stack-0.1.17.tar.gz"),
                Some("deadbeef"),
                None,
            )
            .await
            .expect("publish stack");
        state
            .store
            .set_release_status("wist-gateway-stack", "0.1.17", "expired")
            .await
            .expect("expire stack");

        let app = super::super::router_for(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(create_payload("gw-missing")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let token = rotate_link_token(&app, "gw-missing")
            .await
            .install
            .link_token;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/gateway/install-all?gateway_id=gw-missing&token={token}"
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .to_vec(),
        )
        .expect("utf8");
        assert!(body.contains("galaxy-flow (no release recorded)"), "{body}");
        assert!(
            body.contains("wist-gateway-stack (newest 0.1.17 is expired"),
            "{body}"
        );
        // 已就绪的组件不该被点名。
        assert!(!body.contains("galaxy-ops ("), "{body}");
    }

    /// 「只装 gwlinkd」：一次性接入券有效 → 返回只装宿主接入器的 shell 脚本；
    /// 该端点**只**需 wist-gwlinkd 已发布（不依赖 gops/gx/gateway-stack）；券无效 → 401。
    #[tokio::test]
    async fn install_linkd_serves_script_without_gateway_packages() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-install-linkd-{nanos}.json"));
        let state = create_state_with_store(FileStore::new(&path));

        // 只发布宿主接入器：install-linkd 不应依赖 gops/gx/gateway-stack。
        let base = "http://127.0.0.1:3100/api/v1/releases/artifact";
        state
            .store
            .publish_release(
                "wist-gwlinkd",
                "0.9.3",
                &format!(
                    "{base}/wist-gwlinkd/0.9.3/wist-gwlinkd-0.9.3-aarch64-apple-darwin.tar.gz"
                ),
                Some("cafe"),
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("publish gwlinkd");

        let app = super::super::router_for(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer admin-tok")
                    .body(Body::from(create_payload("gw-linkd")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let rotated = rotate_link_token(&app, "gw-linkd").await;
        let token = rotated.install.link_token.clone();
        assert!(
            rotated
                .install
                .install_linkd_command
                .contains("curl -fsSLk")
                && rotated
                    .install
                    .install_linkd_command
                    .contains("/api/v1/gateway/install-linkd")
                && rotated.install.install_linkd_command.contains("token="),
            "command: {}",
            rotated.install.install_linkd_command
        );

        // 取脚本（正确 token）→ 200 + shell 脚本。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/gateway/install-linkd?gateway_id=gw-linkd&token={token}"
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .to_vec(),
        )
        .expect("utf8");
        for needle in [
            "gops sys localize",
            "wist-gwlinkd",
            "service install --system",
            "--pub-config",
            "configs/gwlinkd/gwlinkd.toml",
            "identity/gwlinkd/gwlinkd-pub.toml",
            // 执行器写**绝对路径**：gwlinkd 服务 PATH 不含 $HOME/bin，相对名会在 spawn 时 ENOENT。
            "GOPS_BIN=\"$(type -P gops || true)\"",
            "set_value \"$VALUES_FILE\" GWLINKD_UPGRADER_PROGRAM \"$GOPS_BIN\"",
            "STACK_DIR",
            "gw-linkd",
            "aarch64-apple-darwin",
            // 自更新：真实二进制放在运行用户可写的目录，PATH 上留符号链接。
            "/usr/local/lib/wist-gwlinkd",
            "GWLINKD_REAL_DIR='/usr/local/lib/wist-gwlinkd'",
            "chown \"$DEPLOY_USER\" \"$GWLINKD_REAL_DIR\" \"$GWLINKD_REAL\"",
            "ln -sfn \"$GWLINKD_REAL\" \"$GWLINKD_BIN\"",
            "--bin \"$GWLINKD_BIN\"",
        ] {
            assert!(body.contains(needle), "script missing `{needle}`:\n{body}");
        }
        // `//` 不是 bash 注释：它会被当成命令执行（`//: is a directory`）。模板里别再写。
        assert!(
            !body.lines().any(|line| line.trim_start().starts_with("//")),
            "生成的脚本里不能有 `//` 注释：\n{body}"
        );

        // 券无效 → 401。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/gateway/install-linkd?gateway_id=gw-linkd&token=wrong")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// shell 语法门禁：把渲染出的脚本交给 `bash -n`，防模板改动（引号 / heredoc）把命令弄坏。
    fn assert_bash_syntax(name: &str, script: &str) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-{name}-{nanos}.sh"));
        std::fs::write(&path, script).expect("write script");
        let output = std::process::Command::new("bash")
            .arg("-n")
            .arg(&path)
            .output()
            .expect("run bash -n");
        let _ = std::fs::remove_file(&path);
        assert!(
            output.status.success(),
            "bash -n 失败（{name}）：{}\n---\n{script}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// 手动升级脚本：只生成脚本、不建计划；按**指定版本**渲染（不是最新），并支持
    /// `gwlink` / `gateway-stack` 命名。
    #[tokio::test]
    async fn upgrade_script_pins_the_requested_version_and_accepts_names() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-upgrade-script-{nanos}.json"));
        let store = FileStore::new(&path);
        store
            .create_gateway("gw-script", "tok-script")
            .expect("create gateway");
        let state = create_state_with_store(store);

        let base = "http://127.0.0.1:3100/api/v1/releases/artifact";
        // 同一组件放两个版本：脚本必须取请求里的 0.12.0，而不是最新/旧版。
        state
            .store
            .publish_release(
                "wist-gwlinkd",
                "v0.11.0",
                &format!(
                    "{base}/wist-gwlinkd/v0.11.0/wist-gwlinkd-v0.11.0-x86_64-unknown-linux-musl.tar.gz"
                ),
                Some("old"),
                Some("x86_64-unknown-linux-musl"),
            )
            .await
            .expect("publish old gwlinkd");
        for (platform, sha) in [
            ("x86_64-unknown-linux-musl", "sha-x86"),
            ("aarch64-unknown-linux-musl", "sha-arm64"),
            ("aarch64-apple-darwin", "sha-mac"),
        ] {
            state
                .store
                .publish_release(
                    "wist-gwlinkd",
                    "v0.12.0",
                    &format!("{base}/wist-gwlinkd/v0.12.0/wist-gwlinkd-v0.12.0-{platform}.tar.gz"),
                    Some(sha),
                    Some(platform),
                )
                .await
                .expect("publish gwlinkd");
        }
        state
            .store
            .publish_release(
                "wist-gateway-stack",
                "v0.14.0",
                &format!("{base}/wist-gateway-stack/v0.14.0/wist-gateway-stack-v0.14.0.tar.gz"),
                Some("sha-stack"),
                None,
            )
            .await
            .expect("publish stack");

        let app = super::super::router_for(state);

        // gwlink 命名 + `v` 前缀 → 归一到 0.12.0；三平台 + 安装/重启逻辑都在脚本里。
        let (status, view) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-script/upgrade-script",
            serde_json::json!({ "component": "gwlink", "version": "v0.12.0" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["component"], "wist-gwlinkd");
        assert_eq!(view["version"], "v0.12.0");
        let script = view["script"].as_str().expect("script");
        assert!(script.contains("wist-gwlinkd-v0.12.0-x86_64-unknown-linux-musl.tar.gz"));
        assert!(script.contains("wist-gwlinkd-v0.12.0-aarch64-apple-darwin.tar.gz"));
        assert!(script.contains("sha-mac"));
        assert!(
            !script.contains("wist-gwlinkd-v0.11.0"),
            "脚本必须使用请求的版本，不能拿最新/旧版：{script}"
        );
        assert!(script.contains("--bin \"$GWLINKD_BIN\""));
        // 与首次安装同一套逻辑：先按现场值渲染配置，再装二进制 / 系统服务。
        assert!(script.contains("gops sys localize"));
        assert_bash_syntax("upgrade-gwlinkd", script);
        // 页面只给一行命令：短命签名 + 不出现 admin token。
        let command = view["command"].as_str().expect("command");
        assert!(command.starts_with("curl -fsSLk '"), "{command}");
        assert!(
            command.contains("/api/v1/gateway/upgrade-script?"),
            "{command}"
        );
        assert!(command.contains("signature="), "{command}");
        assert!(command.contains("expires="), "{command}");
        assert!(
            !command.contains("admin-tok"),
            "命令不能把 admin token 塞进 URL：{command}"
        );
        assert!(view["expires_at"].is_string(), "{view}");

        // 按命令里的 URL 真打一次（网关面）：验签后回脚本。
        let url = command
            .trim_start_matches("curl -fsSLk '")
            .trim_end_matches("' | bash");
        let path = &url[url.find("/api/v1/gateway/upgrade-script").expect("path")..];
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .to_vec(),
        )
        .expect("utf8");
        assert!(body.contains("wist-gwlinkd-v0.12.0-x86_64-unknown-linux-musl.tar.gz"));

        // 改一个查询参数 → 签名失效（401），不能生成别的版本。
        let tampered = path.replace("version=v0.12.0", "version=v0.13.0");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(tampered)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = response.into_body().collect().await;

        // 过期（签名本身合法，但 expires 已过）→ 401，且不生成脚本。
        let expired = chrono::Utc::now().timestamp() - 10;
        let signature = crate::infra::derive_upgrade_script_token(
            "test-hmac-secret",
            "gw-script",
            "wist-gwlinkd",
            "v0.12.0",
            expired,
        );
        let uri = format!(
            "/api/v1/gateway/upgrade-script?gateway_id=gw-script&component=wist-gwlinkd&version=v0.12.0&expires={expired}&signature={signature}"
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = response.into_body().collect().await;

        // gateway-stack 命名：单制品 + gops 升级命令。
        let (status, view) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-script/upgrade-script",
            serde_json::json!({ "component": "gateway-stack", "version": "0.14.0" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["component"], "wist-gateway-stack");
        assert_eq!(view["version"], "v0.14.0");
        let script = view["script"].as_str().expect("script");
        assert!(script.contains("wist-gateway-stack-v0.14.0.tar.gz"));
        assert!(script.contains("sha-stack"));
        assert!(script.contains("gops prj upgrade --to"));
        assert!(script.contains("--on-failure rollback-all"));
        // `curl | bash` 的 stdin 是脚本管道：必须跳过交互确认。
        assert!(script.contains("--force 1"));
        // 健康检查沿用本机 gwlinkd 的配置（有则传，没配不加）。
        assert!(script.contains("--health-cmd"));
        assert!(script.contains("--health-timeout"));
        assert_bash_syntax("upgrade-stack", script);

        // 不支持的组件 / 未知版本 / 未知网关都是可读错误。
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-script/upgrade-script",
            serde_json::json!({ "component": "wist-agentd", "version": "0.1.0" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-script/upgrade-script",
            serde_json::json!({ "component": "gwlink", "version": "9.9.9" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = post_json(
            &app,
            "/api/v1/admin/gateways/gw-ghost/upgrade-script",
            serde_json::json!({ "component": "gwlink", "version": "0.12.0" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // 无管理令牌 → 401（不返回脚本）。
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/gw-script/upgrade-script")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"component":"gwlink","version":"0.12.0"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let _ = response.into_body().collect().await;
    }

    // ── 错误信封的 wire 契约：所有错误都应是 `{ "error": { code, message } }` ──────────

    async fn read_json(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
        use http_body_util::BodyExt;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// 冲突（409）也走信封，`code` 用词表常量（两边都钉死，防漂移）。
    #[tokio::test]
    async fn conflict_errors_carry_the_error_envelope() {
        let app = super::super::router_for(test_state());
        let (status, body) = post_json(
            &app,
            "/api/v1/admin/gateways/instances",
            serde_json::json!({ "gateway_name": "gw-001", "requested_by": "tester" }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::GATEWAY_ALREADY_EXISTS
        );
        assert!(body["error"]["message"].is_string());
        assert!(body["error"]["severity"].is_string());
    }

    /// 未命中路由 → 404 也折成信封（默认 axum 是空体）。
    #[tokio::test]
    async fn unknown_route_returns_the_error_envelope() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/does-not-exist")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let (status, body) = read_json(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], super::super::codes::ROUTE_NOT_FOUND);
    }

    /// 方法不允许 → 405 也折成信封。
    #[tokio::test]
    async fn wrong_method_returns_the_error_envelope() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let app = super::super::router_for(test_state());
        // `/register` 只收 POST。
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/register")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let (status, body) = read_json(response).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::METHOD_NOT_ALLOWED
        );
    }

    /// 请求体不是合法 JSON → `invalid_request_body`（ApiJson 折成的信封，而不是 axum 纯文本）。
    #[tokio::test]
    async fn malformed_body_returns_the_error_envelope() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/instances")
                    .header("authorization", "Bearer admin-tok")
                    .header("content-type", "application/json")
                    .body(Body::from("{ not valid json"))
                    .expect("request"),
            )
            .await
            .expect("response");
        let (status, body) = read_json(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::INVALID_REQUEST_BODY
        );
    }

    /// 查询参数非法 → `invalid_query`（ApiQuery 折成的信封）。
    #[tokio::test]
    async fn malformed_query_returns_the_error_envelope() {
        let app = super::super::router_for(test_state());
        let (status, body) =
            get_json(&app, "/api/v1/admin/gateways?include_archived=not-a-bool").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], super::super::codes::INVALID_QUERY);
    }

    /// 一次性接入券响应必须 `Cache-Control: no-store`（含明文凭据，不得被缓存）。
    #[tokio::test]
    async fn link_token_response_is_not_cacheable() {
        use axum::{body::Body, http::Request, http::header};
        use tower::ServiceExt;

        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/gateways/gw-001/link-token")
                    .header("authorization", "Bearer admin-tok")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "requested_by": "tester" }).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let (_, body) = read_json(response).await;
        assert!(
            body["install"]["link_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty()),
            "响应应含一次性明文接入券：{body}"
        );
    }

    fn package_source_state() -> ApiState {
        let mut state = state_with_store(test_store());
        state.config.package_sources = vec![
            PackageSourceConfig {
                component: "wist-agentd".into(),
                github_repo: Some("dayu-sec/wist-agentd".into()),
                cos_bucket: Some("github-1347593047".into()),
                cos_prefix: Some("wist-agentd".into()),
                cos_region: Some("ap-hongkong".into()),
            },
            PackageSourceConfig {
                component: "cos-only".into(),
                github_repo: None,
                cos_bucket: Some("github-1347593047".into()),
                cos_prefix: Some("cos-only".into()),
                cos_region: None,
            },
        ];
        state
    }

    /// 配置里的来源要原样返回（页面据此拼 URL），且缺少 GitHub 的组件必须返回 null。
    #[tokio::test]
    async fn lists_configured_package_sources() {
        let app = super::super::router_for(package_source_state());
        let (status, body) = get_json(&app, "/api/v1/admin/package-sources").await;
        assert_eq!(status, StatusCode::OK);
        let sources = body["sources"].as_array().expect("sources array");
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0]["component"], "wist-agentd");
        assert_eq!(sources[0]["github_repo"], "dayu-sec/wist-agentd");
        assert_eq!(sources[0]["cos_region"], "ap-hongkong");
        assert_eq!(sources[1]["component"], "cos-only");
        assert!(sources[1]["github_repo"].is_null());
    }

    /// 安装包来源也是管理面：没有 admin bearer 不能读。
    #[tokio::test]
    async fn package_sources_require_admin_bearer() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let app = super::super::router_for(package_source_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/admin/package-sources")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// 非法 / 未配置的 `source` 要在**发网络请求之前**返回 400，而不是 502。
    #[tokio::test]
    async fn package_source_latest_validates_source_before_probing() {
        let app = super::super::router_for(package_source_state());

        let (status, body) = get_json(
            &app,
            "/api/v1/admin/package-sources/latest?component=wist-agentd&source=bogus",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::PACKAGE_SOURCE_NOT_CONFIGURED
        );

        // cos-only 组件被要求查 github → 400，而不是拿空 repo 去请求 GitHub。
        let (status, body) = get_json(
            &app,
            "/api/v1/admin/package-sources/latest?component=cos-only&source=github",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"]["code"],
            super::super::codes::PACKAGE_SOURCE_NOT_CONFIGURED
        );

        // 未配置来源的组件仍然 404（先判组件，再判 source）。
        let (status, _) =
            get_json(&app, "/api/v1/admin/package-sources/latest?component=ghost").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
