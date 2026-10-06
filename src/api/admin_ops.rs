// 管理面接口：网关创建 + 列表聚合 / 状态卡片列表 / 单网关状态。
// 数据来自 center store（ReceiveGatewayStatusReport 落库的最新状态）。

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use wist_control::types::DateTime;
use wist_control::{
    AdminDispatchGlobalPolicy, AdminGatewayListReturned, AdminGatewayStatusListReturned,
    AdminGatewayStatusReturned, AgentFleetDispatchReceipt, AgentRuntimeStatus,
    DispatchAgentFleetCommand, GatewayCustomerBinding, GatewayInitialConfig, GatewayInstance,
    GatewayInstanceLifecycleState, GatewayListView, GatewayRuntimeStatus, GlobalPolicyDispatch,
    UpgradeStep, UpgradeTarget,
};

use crate::infra::{StoreReason, StoredGateway, UpgradePlanRecord};

use super::{
    ApiState, PeerConnectInfo, admin_auth::require_admin_bearer, build_control_center_trust_bundle,
    control_center_tls_required, rate_limit,
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
}

/// 注册 Token 管理视图：只公开状态/限量/有效期，不暴露 token_hash。
/// 创建网关实例：POST /api/v1/admin/gateways/instances。
/// gateway_id 由 gateway_name 派生；重复 → 409。
pub async fn admin_create_gateway_instance(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Json(request): Json<AdminCreateGatewayInstanceRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateway_id = request.gateway_name.trim();
    if gateway_id.is_empty() || request.requested_by.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
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
        Err(err) if err.reason() == &StoreReason::Conflict => (
            StatusCode::CONFLICT,
            format!("gateway {gateway_id} already exists"),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create gateway: {err}"),
        )
            .into_response(),
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
    Json(request): Json<AdminRotateGatewayLinkTokenRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateway_id = gateway_id.trim();
    if gateway_id.is_empty() || request.requested_by.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "gateway_id and requested_by must not be empty",
        )
            .into_response();
    }
    let token = match crate::infra::new_secret_token("link") {
        Ok(token) => token,
        Err(reason) => return (StatusCode::INTERNAL_SERVER_ERROR, reason).into_response(),
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
            (
                StatusCode::OK,
                Json(AdminRotateGatewayLinkTokenReturned {
                    gateway_id: gateway_id.to_string(),
                    install,
                    link_expires_at: Some(expires_at),
                }),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            format!("gateway {gateway_id} not found"),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to rotate setup token: {err}"),
        )
            .into_response(),
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
    Query(params): Query<GatewayUptimeQueryParams>,
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
                    eprintln!("warn gateway uptime vm query failed: {err}");
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
    Query(params): Query<GatewayHistoryQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let window = params.window.as_deref().unwrap_or("1h");
    let Some((window_seconds, step_seconds)) = history_window_config(window) else {
        return (
            StatusCode::BAD_REQUEST,
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
                eprintln!("warn gateway history vm query failed: {err}");
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
    Query(params): Query<GatewayHistoryQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let window = params.window.as_deref().unwrap_or("1h");
    let Some((window_seconds, step_seconds)) = history_window_config(window) else {
        return (
            StatusCode::BAD_REQUEST,
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
                eprintln!("warn agent history vm query failed: {err}");
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
pub async fn admin_list_gateway_instances(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateways = match state.store.list_gateways().await {
        Ok(gateways) => gateways,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway instances: {err}"),
            )
                .into_response();
        }
    };
    let instances: Vec<AdminGatewayInstanceView> = gateways
        .into_iter()
        .map(|gateway| {
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
            }
        })
        .collect();
    Json(instances).into_response()
}

/// 版本发布请求体：**来源**（本机绝对路径 或 https URL；中心读进本地/对象存储镜像）。
///
/// `artifact_url` 沿用原名以兼容既有调用方，但其语义是**来源**（与 gateway 的 agent 包来源同口径）：
/// 可以是 `/abs/path`，也可以是外部 URL。
/// `expected_sha256`（可选）：核对读到的内容摘要，不符即拒；不给则只记录算出的摘要。
/// `version`（可选）：**不填**就由包地址（文件名 / 包内目录名）自动解析，见 `infra/package.rs`；
/// 填了会与解析出的版本**核对**（不一致 → 400）。
/// 镜像后落库 / 下发用**来源原名**（URL 末段）；内容寻址靠 `package_sha256` + 幂等。
#[derive(serde::Deserialize)]
pub struct PublishReleaseRequest {
    #[serde(default)]
    pub version: Option<String>,
    pub artifact_url: String,
    #[serde(default)]
    pub expected_sha256: Option<String>,
    pub requested_by: String,
}

// 制品落盘 / 下发文件名（取来源末段原名，危险名 / 取不到就回落 `{component}-{version}.bin`）
// 已收进共享 crate `wist-release`，经 `crate::infra::artifact_filename` 转出 —— 本文件直接调它，
// 不再自留一份（原先这里的副本是抽取时漏删的）。

/// 发布版本：POST /api/v1/admin/releases/:component（wist-agentd / wist-gateway-stack / galaxy-ops / galaxy-flow）。
/// 从外部 artifact_url 下载制品 → 镜像到本地文件/对象存储 → 返回快的下载地址。
pub async fn admin_publish_release(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(component): Path<String>,
    Json(request): Json<PublishReleaseRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 组件名要拼进制品目录（`{artifact_dir}/{component}/{version}/{filename}`）与下发 URL：
    // 必须是**真的只有一段**，否则 `..` / 绝对路径会逃出制品目录。
    if !crate::infra::is_safe_path_segment(&component) {
        return (
            StatusCode::BAD_REQUEST,
            "component must be a single safe path segment",
        )
            .into_response();
    }
    if request.artifact_url.trim().is_empty() || request.requested_by.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "artifact_url and requested_by must not be empty",
        )
            .into_response();
    }
    // 读来源（本机绝对路径 / https URL）+ 校验期望摘要（空串视同未给）。
    let expected_sha256 = request
        .expected_sha256
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (bytes, package_sha256) =
        match crate::infra::read_verified_package(&request.artifact_url, expected_sha256).await {
            Ok(verified) => verified,
            Err(err) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("failed to fetch artifact: {err}"),
                )
                    .into_response();
            }
        };
    // 从包里读身份：包内目录名，读不出再回落来源文件名。
    // 覆盖 agentd 包（目录名带身份）与 gateway-stack / galaxy-ops / galaxy-flow 包（文件名带版本）。
    let (package_version, _arch) =
        crate::infra::read_package_identity(&request.artifact_url, &bytes);
    // 版本以**包自报为准**，不让运维手输：
    // - 请求带了 version → 与自报版本**核对**（不一致 → 400）；
    // - 请求没带 version → 直接用自报版本；
    // - 两边都没有 → 400（包名里没版本号，请用带版本的文件名）。
    let declared_version = request
        .version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let version = match declared_version {
        Some(declared) => {
            if !package_version.is_empty()
                && crate::infra::normalize_version(declared)
                    != crate::infra::normalize_version(&package_version)
            {
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "version mismatch: request declares {declared} but the package self-reports {package_version}"
                    ),
                )
                    .into_response();
            }
            declared.to_string()
        }
        None if !package_version.is_empty() => package_version,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "cannot derive version from the package: use an artifact whose name carries a version, or pass `version` explicitly",
            )
                .into_response();
        }
    };
    // 同一 (component, version) 已镜像过**同一份内容** → 幂等返回，不重复下副本。
    if let Ok(existing) = state.store.list_releases(&component).await
        && let Some(record) = existing.iter().find(|record| {
            record.version == version
                && record.package_sha256.as_deref() == Some(package_sha256.as_str())
        })
    {
        return Json(record.clone()).into_response();
    }
    // 落盘 / 下发文件名：**用来源原名**（URL 末段就是原名，人看着清楚）；
    // 内容寻址不再靠文件名，而在 DB 的 `package_sha256` + `(component, version, sha)` 幂等。
    // 版本号同样会拼进目录 —— 手输的那份也要过同一道关。
    if !crate::infra::is_safe_path_segment(&version) {
        return (
            StatusCode::BAD_REQUEST,
            "version must be a single safe path segment",
        )
            .into_response();
    }
    let filename = crate::infra::artifact_filename(&request.artifact_url, &component, &version);
    let mirrored_url = match state
        .artifact_store
        .store(&component, &version, &filename, bytes)
        .await
    {
        Ok(url) => url,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store artifact: {err}"),
            )
                .into_response();
        }
    };
    let record = match state
        .store
        .publish_release(&component, &version, &mirrored_url, Some(&package_sha256))
        .await
    {
        Ok(record) => record,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to record release: {err}"),
            )
                .into_response();
        }
    };
    Json(record).into_response()
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
        return (
            StatusCode::BAD_REQUEST,
            "component must be a single safe path segment",
        )
            .into_response();
    }
    let releases = match state.store.list_releases(&component).await {
        Ok(releases) => releases,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load releases: {err}"),
            )
                .into_response();
        }
    };
    Json(releases).into_response()
}

/// 绑定客户请求体：对齐模型 AdminBindGatewayCustomer。
#[derive(serde::Deserialize)]
pub struct BindGatewayCustomerRequest {
    pub gateway_id: String,
    pub customer_id: String,
    pub requested_by: String,
}

/// 绑定网关到客户：POST /api/v1/admin/gateways/bind。
pub async fn admin_bind_gateway_customer(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Json(request): Json<BindGatewayCustomerRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if request.gateway_id.trim().is_empty()
        || request.customer_id.trim().is_empty()
        || request.requested_by.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            "gateway_id, customer_id and requested_by must not be empty",
        )
            .into_response();
    }
    let binding = match state
        .store
        .bind_gateway_customer(&request.gateway_id, &request.customer_id)
        .await
    {
        Ok(binding) => binding,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to bind gateway customer: {err}"),
            )
                .into_response();
        }
    };
    Json(GatewayCustomerBinding {
        gateway_id: binding.gateway_id,
        customer_id: binding.customer_id,
        status: binding.status,
        bound_at: binding.bound_at,
    })
    .into_response()
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
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "TLS is required but the control center trust root is not configured",
        )
            .into_response();
    }
    Json(GatewayInitialConfig {
        gateway_id: gateway_id.clone(),
        control_center_endpoint: state.config.public_url.clone(),
        trust_bundle,
        server_tls_required,
        protocol_version: state.config.protocol_version.clone(),
        enrollment_token_id,
    })
    .into_response()
}

/// 创建升级计划请求体：多组件目标版本 + 网关范围 + **阶段数**。
///
/// 灰度阶段由**中心服务端**按阶梯（1 个金丝雀 → 10% → 30% → 70% → 全量）自动切出，
/// 不再由前端传 `steps` —— 阶梯口径只有一份（共享 crate `wist-release::rollout`），
/// 且落在服务端才能保证「阶段互不重叠、一把铺满」不是只在界面上成立。
#[derive(serde::Deserialize)]
pub struct CreateUpgradePlanRequest {
    pub targets: Vec<UpgradeTarget>,
    pub gateway_ids: Vec<String>,
    /// 分几段灰度（1 = 不分批，一把到位）。可用段数受台数限制，见
    /// `wist_release::rollout::available_phase_counts`。
    pub phase_count: usize,
    pub requested_by: String,
}

#[derive(serde::Deserialize)]
pub struct ApproveUpgradePlanRequest {
    pub plan_id: String,
    pub approved_by: String,
}

/// 创建升级计划：POST /api/v1/admin/upgrade-plans。
pub async fn admin_create_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Json(request): Json<CreateUpgradePlanRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if request.targets.is_empty()
        || request.gateway_ids.is_empty()
        || request.requested_by.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            "targets, gateway_ids and requested_by must not be empty",
        )
            .into_response();
    }
    // 阶段切分：服务端权威。目标为空 / 阶段数为 0 / 阶段数大于台数都在这里被拒。
    let steps = match wist_release::rollout::plan_phases(&request.gateway_ids, request.phase_count)
    {
        Ok(phases) => phases
            .into_iter()
            .map(|phase| UpgradeStep {
                step_index: phase.index as i64,
                gateway_ids: phase.target_ids,
                status: "pending".to_string(),
            })
            .collect(),
        Err(reason) => return (StatusCode::BAD_REQUEST, reason).into_response(),
    };
    let plan_id = format!(
        "plan-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let record = UpgradePlanRecord {
        plan_id,
        targets: request.targets,
        target_count: request.gateway_ids.len() as i64,
        status: "pending".to_string(),
        created_at: DateTime::now(),
        steps,
        approved_by: None,
        approved_at: None,
    };
    match state.store.create_upgrade_plan(&record).await {
        Ok(plan) => (StatusCode::CREATED, Json(plan)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create upgrade plan: {err}"),
        )
            .into_response(),
    }
}

/// 查询升级计划列表：GET /api/v1/admin/upgrade-plans。
pub async fn admin_list_upgrade_plans(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_upgrade_plans().await {
        Ok(plans) => Json(plans).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load upgrade plans: {err}"),
        )
            .into_response(),
    }
}

/// 批准升级计划：POST /api/v1/admin/upgrade-plans/approve。
pub async fn admin_approve_upgrade_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Json(request): Json<ApproveUpgradePlanRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state
        .store
        .approve_upgrade_plan(&request.plan_id, &request.approved_by)
        .await
    {
        Ok(plan) => Json(plan).into_response(),
        Err(err) if err.reason() == &StoreReason::Conflict => (
            StatusCode::NOT_FOUND,
            format!("upgrade plan {} not found", request.plan_id),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to approve upgrade plan: {err}"),
        )
            .into_response(),
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway lifecycle: {err}"),
            )
                .into_response();
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway agents: {err}"),
            )
                .into_response();
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
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateways = match state.store.list_gateways().await {
        Ok(gateways) => gateways,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway store: {err}"),
            )
                .into_response();
        }
    };
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
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let gateways = match state.store.list_gateways().await {
        Ok(gateways) => gateways,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway store: {err}"),
            )
                .into_response();
        }
    };
    // 状态视图只展示「已上报过」的网关；从未上报的网关无状态可展示（聚合 gateway_count 仍计入）。
    let mut views: Vec<GatewayRuntimeStatus> = gateways
        .iter()
        .filter(|stored| stored.last_seen_at.is_some())
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway store: {err}"),
            )
                .into_response();
        }
    };
    let Some(stored) = stored else {
        return (
            StatusCode::NOT_FOUND,
            format!("unknown gateway {gateway_id}"),
        )
            .into_response();
    };
    if stored.last_seen_at.is_none() {
        // 已接入但从未上报：无状态可返回（与列表端点一致）。
        return (
            StatusCode::NOT_FOUND,
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
    Json(input): Json<AdminDispatchGlobalPolicy>,
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
    Json(input): Json<DispatchAgentFleetCommand>,
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        config::{CenterConfig, GatewayCredentialSeed},
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

    fn test_state() -> ApiState {
        ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: std::env::temp_dir().join("unused.json"),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
            },
            store: std::sync::Arc::new(test_store()),
            artifact_store: std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            )),
            gateway_ca: test_gateway_ca(),
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
        }
    }

    /// 灰度阶段由**服务端**按阶梯切：客户端只给网关范围与阶段数，不再传 `steps`。
    #[tokio::test]
    async fn create_upgrade_plan_splits_phases_on_the_server() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let gateway_ids: Vec<String> = (1..=10).map(|i| format!("gw-{i:03}")).collect();
        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/upgrade-plans")
                    .header("authorization", "Bearer admin-tok")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "targets": [{
                                "component": "wist-gateway-stack",
                                "target_version": "0.1.28",
                            }],
                            "gateway_ids": gateway_ids,
                            "phase_count": 3,
                            "requested_by": "tester",
                        })
                        .to_string(),
                    ))
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
        let plan: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let steps = plan["steps"].as_array().expect("steps");
        let sizes: Vec<usize> = steps
            .iter()
            .map(|step| step["gateway_ids"].as_array().expect("ids").len())
            .collect();
        // 10 台 × 3 阶段：金丝雀 1 → 到 10% 再 1 → 余 8。
        assert_eq!(sizes, vec![1, 1, 8]);
        assert_eq!(steps[0]["step_index"], 1);
        assert_eq!(steps[0]["status"], "pending");
        // 阶段之间互不重叠，且一把铺满。
        let mut all: Vec<String> = steps
            .iter()
            .flat_map(|step| {
                step["gateway_ids"]
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
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        for phase_count in [0, 11] {
            let app = super::super::router_for(test_state());
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/admin/upgrade-plans")
                        .header("authorization", "Bearer admin-tok")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "targets": [{
                                    "component": "wist-gateway-stack",
                                    "target_version": "0.1.28",
                                }],
                                "gateway_ids": (1..=10)
                                    .map(|i| format!("gw-{i:03}"))
                                    .collect::<Vec<_>>(),
                                "phase_count": phase_count,
                                "requested_by": "tester",
                            })
                            .to_string(),
                        ))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "phase_count {phase_count}"
            );
        }
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

        let publish = |component: &str, version: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/releases/{component}"))
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "artifact_url": source,
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
        let pkg = std::env::temp_dir().join(format!("wic-rel-{nanos}.tar.gz"));
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
        assert_eq!(record["package_sha256"], serde_json::json!(sha));
        assert_eq!(record["status"], serde_json::json!("published"));
        // 下发 URL 末段 = **来源原名**（内容寻址在 DB 的 `package_sha256`）。
        let expected_leaf = pkg.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            record["artifact_url"]
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

        let _ = std::fs::remove_file(pkg);
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
        let dir = std::env::temp_dir();
        let first = dir.join(format!("wic-rel-a-{nanos}.bin"));
        let second = dir.join(format!("wic-rel-b-{nanos}.bin"));
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
            first_record["artifact_url"]
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
            first_record["artifact_url"], second_record["artifact_url"],
            "同内容同版本 → 幂等，不落第二份"
        );

        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
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
        let state = ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: std::env::temp_dir().join(format!("wic-never-{nanos}.json")),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
            },
            store: std::sync::Arc::new(store),
            artifact_store: std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            )),
            gateway_ca: test_gateway_ca(),
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
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
        ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: std::env::temp_dir().join("unused.json"),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
            },
            store: std::sync::Arc::new(store),
            artifact_store: std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            )),
            gateway_ca: test_gateway_ca(),
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
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
        let state = ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: std::env::temp_dir().join(format!("wic-create-tb-{nanos}.json")),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: Some(super::super::super::infra::sha256_hex("admin-tok")),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                artifact_dir: std::env::temp_dir().join("wic-artifacts"),
                object_storage: None,
                ca_cert: Some(
                    "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----".to_string(),
                ),
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
            },
            store: std::sync::Arc::new(store),
            artifact_store: std::sync::Arc::new(crate::infra::LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            )),
            gateway_ca: test_gateway_ca(),
            rate_limits: std::sync::Arc::new(std::sync::Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
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
}
