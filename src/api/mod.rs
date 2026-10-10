// WarpInsightCenter 管理面 / 网关面 HTTP API。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    extract::{Extension, OriginalUri, Request, connect_info::ConnectInfo},
    http::{HeaderValue, Method, header},
    middleware::{Next, from_fn},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use wist_control::ControlCenterTrustBundle;

use crate::{config::CenterConfig, infra::ArtifactStore, infra::Store};

mod admin_auth;
mod admin_ops;
/// 稳定错误码词表（`{ "error": { "code": … } }` 里 `code` 的唯一来源）。
pub mod codes;
pub mod error;
pub use error::{ApiError, ProtocolError, ProtocolErrorEnvelope, Severity};
mod extract;
mod gateway_ops;
mod install_script;
mod rate_limit;
mod rollout;

use admin_ops::{
    admin_advance_upgrade_plan, admin_approve_upgrade_plan, admin_bind_gateway_customer,
    admin_create_gateway_instance, admin_create_upgrade_plan, admin_dispatch_agent_fleet_command,
    admin_dispatch_global_policy, admin_get_agent_history, admin_get_gateway_history,
    admin_get_gateway_initial_config, admin_get_gateway_uptime, admin_list_gateway_agents,
    admin_list_gateway_instances, admin_list_gateway_lifecycle, admin_list_gateway_status,
    admin_list_releases, admin_list_upgrade_plans, admin_publish_release,
    admin_publish_release_batch, admin_resolve_github_release, admin_retry_upgrade_plan,
    admin_rotate_gateway_link_token, admin_set_gateway_archived, admin_set_release_status,
    admin_show_gateway_status, admin_view_gateway_list, admin_view_upgrade_plan,
};
use gateway_ops::{
    download_release_artifact, get_gateway_initial_config, get_gateway_upgrade_plan,
    options_gateway_initial_config, query_gateway_initialization_status, register_gateway,
    renew_gateway_credential, report_gateway_upgrade_result, submit_agent_status,
    submit_gateway_status, verify_gateway_credential,
};

/// 提取 peer 连接信息（限流按 IP 分桶用；忽略可伪造的 `x-real-ip` / `x-forwarded-for`）。
///
/// axum 0.8 起 `Option<T>` 要求 `T: OptionalFromRequestParts`，而 `ConnectInfo<T>` 只实现了
/// `FromRequestParts`（0.8 里实现了前者的只有 `MatchedPath` / `Path` / `Extension`），
/// 因此包一层 `Extension`。语义与原来一致：取不到连接信息即 `None`（测试里 `oneshot`
/// 不带 connect info 走的就是这条）。
pub type PeerConnectInfo = Option<Extension<ConnectInfo<SocketAddr>>>;

#[derive(Debug, Clone)]
pub struct ApiState {
    pub config: CenterConfig,
    pub store: Arc<dyn Store>,
    pub artifact_store: Arc<dyn ArtifactStore>,
    pub rate_limits: Arc<Mutex<rate_limit::RateLimitState>>,
    /// 网关客户端证书 CA（CA-G）：`register` 据此按 CSR 签每网关一张客户端证书。
    pub gateway_ca: Arc<crate::infra::gateway_ca::GatewayCa>,
}

/// 控制中心是否要求 TLS：按 `public_url` scheme 推导（https → true，http → false）。
/// 避免 HTTP 演示端点被网关按"必须 TLS"连接而失败。
pub(crate) fn control_center_tls_required(config: &CenterConfig) -> bool {
    config.public_url.trim_start().starts_with("https://")
}

/// 从 center 配置构造控制中心信任包：`ca_cert`（PEM）→ `ca_bundle`（公钥），
/// `public_url` → 端点 / server_name / expected_san。未配置 CA → None。
pub(crate) fn build_control_center_trust_bundle(
    config: &CenterConfig,
    gateway_id: &str,
) -> Option<ControlCenterTrustBundle> {
    let ca_bundle = config.ca_cert.clone()?;
    let host = config
        .public_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string();
    Some(ControlCenterTrustBundle {
        trust_bundle_id: format!("trust-{gateway_id}-1"),
        control_endpoint: config.public_url.clone(),
        ca_bundle,
        server_name: host.clone(),
        expected_san: host,
        issued_at: None,
        expires_at: None,
    })
}

/// 为 Gateway 初始化相关端点统一补 CORS 响应头，确保浏览器能读取状态与认证失败。
async fn gateway_initial_config_cors(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization, accept"),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("cache-control"),
    );
    response
}

/// 未命中任何路由（`404`）：也折成统一信封 —— 默认 axum 回的是空体 `404`，绕过 `{ "error": … }` 契约。
async fn fallback_not_found(OriginalUri(uri): OriginalUri) -> Response {
    log::warn!("unmatched route: {uri}");
    ApiError::not_found(codes::ROUTE_NOT_FOUND, "route not found").into_response()
}

/// 路由存在但方法不允许（`405`）：同样折成信封（axum 默认给裸 `405`）。
async fn fallback_method_not_allowed(method: Method, OriginalUri(uri): OriginalUri) -> Response {
    log::warn!("method not allowed: {method} {uri}");
    ApiError::new(
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        codes::METHOD_NOT_ALLOWED,
        "method not allowed",
    )
    .into_response()
}

pub fn router(
    config: CenterConfig,
    store: Arc<dyn Store>,
    gateway_ca: Arc<crate::infra::gateway_ca::GatewayCa>,
) -> Router {
    let artifact_store = crate::infra::build_artifact_store(&config);
    router_for(ApiState {
        config,
        store,
        artifact_store,
        rate_limits: Arc::new(Mutex::new(rate_limit::RateLimitState::default())),
        gateway_ca,
    })
}

/// 以给定 state 构建路由（测试与运行共用）。
pub fn router_for(state: ApiState) -> Router {
    Router::new()
        // 网关面：ReceiveGatewayStatusReport
        .route("/api/v1/gateway/status", post(submit_gateway_status))
        // 网关面：Gateway 上报其下 Agent 状态
        .route("/api/v1/gateway/agents/status", post(submit_agent_status))
        // 网关面：WarpGateway 持注册 Token 注册（RegisterGatewayFlow）
        .route("/api/v1/gateway/register", post(register_gateway))
        // 网关面：前置环境准备脚本（curl ... | bash）——公开、无令牌（补 tar/docker/compose）
        .route(
            "/api/v1/gateway/prepare-script",
            get(install_script::get_gateway_prepare_script),
        )
        // 网关面：脚本安装（curl ... | bash）——一次性接入券鉴权，返回 shell 脚本
        .route(
            "/api/v1/gateway/install-script",
            get(install_script::get_gateway_install_script),
        )
        // 网关面：链接上级 link-upstream（初始化 URL 指向此端点；返回 application/json）
        .route(
            "/api/v1/gateway/link-upstream",
            get(get_gateway_initial_config)
                .options(options_gateway_initial_config)
                .layer(from_fn(gateway_initial_config_cors)),
        )
        // 网关面：轮换网关客户端证书（RenewGatewayCredential，旧证书作废）
        .route(
            "/api/v1/gateway/credentials:renew",
            post(renew_gateway_credential),
        )
        // 网关面：校验通讯凭据（VerifyGatewayCredentialFlow）。
        // 路径用斜杠形式是历史原因：axum ≤0.7 把段首 `:` 当路径参数，无法与 credentials:renew 共存。
        // axum 0.8（matchit 0.8）已把 `:` 当字面量，该限制不再存在；路径保持不变以免破坏网关侧 wire 兼容。
        .route(
            "/api/v1/gateway/credentials/verify",
            post(verify_gateway_credential),
        )
        // 网关面：查询网关初始化状态（QueryGatewayInitializationStatus）
        .route(
            "/api/v1/gateway/initialization-status",
            get(query_gateway_initialization_status)
                .options(options_gateway_initial_config)
                .layer(from_fn(gateway_initial_config_cors)),
        )
        // 网关面：取升级目标（GetGatewayUpgradePlan，CR-002 C2）
        .route(
            "/api/v1/gateway/upgrade-plan",
            get(get_gateway_upgrade_plan),
        )
        // 网关面：升级结果回执（ReportGatewayUpgradeResult，CR-002 C2）
        .route(
            "/api/v1/gateway/upgrade-result",
            post(report_gateway_upgrade_result),
        )
        // 管理面：下发全局策略（DispatchGlobalPolicyFlow）
        .route(
            "/api/v1/admin/policies/global",
            post(admin_dispatch_global_policy),
        )
        // 管理面：下发 Agent 舰队指令（DispatchAgentFleetCommandFlow）
        .route(
            "/api/v1/gateway/agents/dispatch",
            post(admin_dispatch_agent_fleet_command),
        )
        // 管理面：创建网关实例（AdminCreateGatewayInstance，POST /api/v1/admin/gateways/instances）
        .route(
            "/api/v1/admin/gateways/instances",
            post(admin_create_gateway_instance),
        )
        // 管理面：实例列表（含生命周期状态）
        .route(
            "/api/v1/admin/gateways/instances",
            get(admin_list_gateway_instances),
        )
        // 管理面：绑定网关到客户
        .route(
            "/api/v1/admin/gateways/bind",
            post(admin_bind_gateway_customer),
        )
        // 管理面：实例初始配置（admin 侧查询）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/config",
            get(admin_get_gateway_initial_config),
        )
        // 管理面：生成/轮换一次性接入券（LINK_TOKEN，明文仅返回一次）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/link-token",
            post(admin_rotate_gateway_link_token),
        )
        // 管理面：网关列表聚合（AdminViewGatewayList，GET /api/v1/admin/gateways）
        .route("/api/v1/admin/gateways", get(admin_view_gateway_list))
        // 管理面：状态卡片列表（AdminListGatewayStatus）
        .route(
            "/api/v1/admin/gateways/status",
            get(admin_list_gateway_status),
        )
        // 管理面：单网关状态（AdminShowGatewayStatus）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/status",
            get(admin_show_gateway_status),
        )
        // 管理面：网关在线率（转发 VM avg_over_time）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/status/uptime",
            get(admin_get_gateway_uptime),
        )
        // 管理面：网关历史趋势（转发 VM query_range）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/status/history",
            get(admin_get_gateway_history),
        )
        // 管理面：单 Agent 历史趋势（转发 VM query_range）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/agents/{agent_id}/history",
            get(admin_get_agent_history),
        )
        // 管理面：某 gateway 下的 Agent 状态列表
        .route(
            "/api/v1/admin/gateways/{gateway_id}/agents",
            get(admin_list_gateway_agents),
        )
        // 管理面：某 gateway 生命周期转变历史
        .route(
            "/api/v1/admin/gateways/{gateway_id}/lifecycle",
            get(admin_list_gateway_lifecycle),
        )
        // 管理面：归档 / 取消归档一台网关（标记，不删除；只允许归档离线网关）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/archive",
            post(admin_set_gateway_archived),
        )
        // 管理面：版本发布（wist-agentd / wist-gateway-stack / galaxy-ops / galaxy-flow，镜像外部制品）
        .route(
            "/api/v1/admin/releases/{component}",
            post(admin_publish_release).get(admin_list_releases),
        )
        // 管理面：多平台批量录入（galaxy-ops / galaxy-flow 一次覆盖三平台，先全校验再落库）
        .route(
            "/api/v1/admin/releases/{component}/batch",
            post(admin_publish_release_batch),
        )
        // 管理面：解析 GitHub Release（拉 tag + 多平台制品地址，供录入页一键填充）
        .route(
            "/api/v1/admin/github-release/resolve",
            post(admin_resolve_github_release),
        )
        // 管理面：改托管状态（published / expired）
        .route(
            "/api/v1/admin/releases/{component}/{version}/status",
            post(admin_set_release_status),
        )
        // 制品下载（本地镜像）
        .route(
            "/api/v1/releases/artifact/{component}/{version}/{filename}",
            get(download_release_artifact),
        )
        // 管理面：灰度发布计划（模型 `Control.Rollout`；创建/列表/批准/推进/查看，阶段由服务端切，
        // 路径与网关同一套）
        .route(
            "/api/v1/admin/rollout-plans",
            post(admin_create_upgrade_plan).get(admin_list_upgrade_plans),
        )
        .route(
            "/api/v1/admin/rollout-plans/approve",
            post(admin_approve_upgrade_plan),
        )
        .route(
            "/api/v1/admin/rollout-plans/advance",
            post(admin_advance_upgrade_plan),
        )
        // 重派失败目标：**新建**一份补跑计划（新 plan_id —— 网关按 plan_id 去重，同一份改状态是假重试）
        .route(
            "/api/v1/admin/rollout-plans/retry",
            post(admin_retry_upgrade_plan),
        )
        .route(
            "/api/v1/admin/rollout-plans/{plan_id}",
            get(admin_view_upgrade_plan),
        )
        // 兜底：未命中的路径 / 方法也回统一错误信封（默认 axum 是空体）。
        .fallback(fallback_not_found)
        .method_not_allowed_fallback(fallback_method_not_allowed)
        .with_state(state)
}
