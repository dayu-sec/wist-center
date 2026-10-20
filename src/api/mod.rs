// WistCenter 管理面 / 网关面 HTTP API。

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
mod install;
mod rate_limit;
mod rollout;
mod version;
mod wparse_proxy_api;

use admin_ops::{
    admin_advance_upgrade_plan, admin_approve_upgrade_plan, admin_bind_gateway_customer,
    admin_create_gateway_instance, admin_create_upgrade_plan, admin_dispatch_agent_fleet_command,
    admin_dispatch_global_policy, admin_get_agent_history, admin_get_gateway_history,
    admin_get_gateway_initial_config, admin_get_gateway_uptime, admin_list_gateway_agents,
    admin_list_gateway_instances, admin_list_gateway_lifecycle, admin_list_gateway_status,
    admin_list_package_sources, admin_list_releases, admin_list_upgrade_plans,
    admin_package_source_latest, admin_publish_release, admin_publish_release_batch,
    admin_resolve_cos, admin_resolve_github_release, admin_retry_upgrade_plan,
    admin_rotate_gateway_link_token, admin_set_gateway_archived, admin_set_release_status,
    admin_show_gateway_status, admin_view_gateway_list, admin_view_upgrade_plan,
};
use gateway_ops::{
    download_release_artifact, get_gateway_initial_config, get_gateway_upgrade_plan,
    options_gateway_initial_config, query_gateway_initialization_status, register_gateway,
    renew_gateway_credential, report_gateway_upgrade_result, submit_agent_status,
    submit_gateway_status, verify_gateway_credential,
};
use wparse_proxy_api::{
    issue_proxy_token, poll_command, report_command_result, revoke_proxy_token,
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
    /// 规则发布兼容入口（命令队列 + proxy token）；未启用时为 `None`。
    pub proxy: Option<Arc<crate::wparse_proxy::WparseProxy>>,
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
    proxy: Option<Arc<crate::wparse_proxy::WparseProxy>>,
) -> Router {
    router_for(state_of(config, store, gateway_ca, proxy))
}

/// 构造共享状态（两个监听面各用一份，字段都是 `Arc` / `Clone`）。
fn state_of(
    config: CenterConfig,
    store: Arc<dyn Store>,
    gateway_ca: Arc<crate::infra::gateway_ca::GatewayCa>,
    proxy: Option<Arc<crate::wparse_proxy::WparseProxy>>,
) -> ApiState {
    let artifact_store = crate::infra::build_artifact_store(&config);
    ApiState {
        config,
        store,
        artifact_store,
        rate_limits: Arc::new(Mutex::new(rate_limit::RateLimitState::default())),
        gateway_ca,
        proxy,
    }
}

/// 监听面：决定一个 listener 只允许哪些路由（**默认拒绝**）。
///
/// 公网 listener 只挂网关面，管理面永远不在公网上——即使 admin token 泄露，攻击面也不包含
/// `/api/v1/admin/**`。新增路由**不会**自动出现在任何一面，必须显式加进 [`ListenerScope::allows`]。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerScope {
    /// 公网：`/api/v1/gateway/**` + `/api/v1/releases/artifact/**` + `/api/v1/version`。
    Gateway,
    /// 内网：`/api/v1/admin/**` + `/api/v1/version`。
    Admin,
}

impl ListenerScope {
    /// 前缀白名单。`/api/v1/version` 两侧都放（页面左下角版本号，未登录也要答）。
    fn allows(self, path: &str) -> bool {
        if path == "/api/v1/version" {
            return true;
        }
        match self {
            ListenerScope::Gateway => {
                path == "/api/v1/gateway"
                    || path.starts_with("/api/v1/gateway/")
                    // 制品下载：gwlinkd 的升级流程要从中心取包
                    // （`/api/v1/releases/artifact/{component}/{version}/{filename}`）。
                    // 它不是管理面 —— 只按已发布的 component/version/filename 读文件，
                    // 且路由层自己做段校验（拒 `..`、分隔符）。
                    || path.starts_with("/api/v1/releases/artifact/")
            }
            ListenerScope::Admin => path == "/api/v1/admin" || path.starts_with("/api/v1/admin/"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ListenerScope::Gateway => "gateway",
            ListenerScope::Admin => "admin",
        }
    }
}

/// 公网面：只挂网关路由（mTLS 由调用方的 TLS 配置保证）。
pub fn gateway_router(
    config: CenterConfig,
    store: Arc<dyn Store>,
    gateway_ca: Arc<crate::infra::gateway_ca::GatewayCa>,
    proxy: Option<Arc<crate::wparse_proxy::WparseProxy>>,
) -> Router {
    scoped_router(
        state_of(config, store, gateway_ca, proxy),
        ListenerScope::Gateway,
    )
}

/// 内网面：只挂管理路由（浏览器不带客户端证书，用服务器证书 TLS + Bearer admin token）。
pub fn admin_router(
    config: CenterConfig,
    store: Arc<dyn Store>,
    gateway_ca: Arc<crate::infra::gateway_ca::GatewayCa>,
    proxy: Option<Arc<crate::wparse_proxy::WparseProxy>>,
) -> Router {
    scoped_router(
        state_of(config, store, gateway_ca, proxy),
        ListenerScope::Admin,
    )
}

/// 在完整路由外面套一层前缀闸：不在本面白名单里的路径一律 404（统一错误信封）。
fn scoped_router(state: ApiState, scope: ListenerScope) -> Router {
    router_for(state).layer(from_fn(move |req: Request, next: Next| {
        scope_guard(scope, req, next)
    }))
}

async fn scope_guard(scope: ListenerScope, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if scope.allows(&path) {
        next.run(req).await
    } else {
        log::warn!(
            "route not exposed on the {} listener: {path}",
            scope.as_str()
        );
        ApiError::not_found(codes::ROUTE_NOT_FOUND, "route not found").into_response()
    }
}

/// 以给定 state 构建路由（测试与运行共用）。
pub fn router_for(state: ApiState) -> Router {
    Router::new()
        // 中心版本（**公开、无鉴权**）：页面左下角常驻显示前后端版本，未登录也要答。见 api/version.rs。
        .route("/api/v1/version", get(version::center_version))
        // 网关面：ReceiveGatewayStatusReport
        .route("/api/v1/gateway/status", post(submit_gateway_status))
        // 网关面：Gateway 上报其下 Agent 状态
        .route("/api/v1/gateway/agents/status", post(submit_agent_status))
        // 网关面：WarpGateway 持注册 Token 注册（RegisterGatewayFlow）
        .route("/api/v1/gateway/register", post(register_gateway))
        // 网关面：前置环境准备脚本（curl ... | bash）——公开、无令牌（补 tar/docker/compose）
        .route(
            "/api/v1/gateway/prepare-script",
            get(install::get_gateway_prepare_script),
        )
        // 网关面：全量安装（curl ... | bash）——一次性接入券鉴权，返回 shell 脚本
        .route(
            "/api/v1/gateway/install-all",
            get(install::get_gateway_install_all),
        )
        // 网关面：只装宿主侧 gwlinkd（网关已部署时用；curl ... | bash）——一次性接入券鉴权
        .route(
            "/api/v1/gateway/install-linkd",
            get(install::get_gateway_install_linkd),
        )
        // 网关面：手动升级脚本（短命签名；`curl ... | bash` 打开的就是它）
        .route(
            "/api/v1/gateway/upgrade-script",
            get(install::get_gateway_upgrade_script),
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
        // 管理面：wparse-proxy token（WarpStation 设备 Token；明文仅返回一次）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/wparse-proxy-token",
            post(issue_proxy_token).delete(revoke_proxy_token),
        )
        // 网关面：规则发布命令通道（mTLS；gwlinkd 短轮询）
        .route("/api/v1/gateway/commands", get(poll_command))
        .route(
            "/api/v1/gateway/commands/{command_id}/result",
            post(report_command_result),
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
        // 管理面：生成单台网关的「手动升级」执行脚本（按组件 + 版本命名；只生成脚本，不建计划）
        .route(
            "/api/v1/admin/gateways/{gateway_id}/upgrade-script",
            post(install::admin_gateway_upgrade_script),
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
        // 管理面：安装包来源（录入页按版本号拼 URL 做探活）
        .route(
            "/api/v1/admin/package-sources",
            get(admin_list_package_sources),
        )
        // 管理面：自动探测最新版本（GitHub 列 releases；只有 COS 时从已知版本往后探测）
        .route(
            "/api/v1/admin/package-sources/latest",
            get(admin_package_source_latest),
        )
        // 管理面：解析 GitHub Release（拉 tag + 多平台制品地址，供录入页一键填充）
        .route(
            "/api/v1/admin/github-release/resolve",
            post(admin_resolve_github_release),
        )
        // 管理面：解析腾讯 COS 路径（列对象 + 每制品地址 / sha256 / 平台，供录入页一键填充）
        .route("/api/v1/admin/cos/resolve", post(admin_resolve_cos))
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

#[cfg(test)]
mod scope_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    /// 只练“面”的路由闸门，不构建完整 ApiState（store / CA 与分流无关）。
    fn probe_router(scope: ListenerScope) -> Router {
        Router::new()
            .route("/api/v1/version", get(|| async { "v" }))
            .route("/api/v1/gateway/status", post(|| async { "gw" }))
            .route("/api/v1/admin/gateways", get(|| async { "admin" }))
            .route(
                "/api/v1/releases/artifact/{component}/{version}/{filename}",
                get(|| async { "artifact" }),
            )
            .layer(from_fn(move |req: Request, next: Next| {
                scope_guard(scope, req, next)
            }))
    }

    async fn status(scope: ListenerScope, method: Method, path: &str) -> StatusCode {
        probe_router(scope)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn gateway_face_exposes_only_gateway_routes() {
        let gw = ListenerScope::Gateway;
        assert_eq!(
            status(gw, Method::POST, "/api/v1/gateway/status").await,
            StatusCode::OK
        );
        assert_eq!(
            status(gw, Method::GET, "/api/v1/version").await,
            StatusCode::OK
        );
        // 管理面在公网 listener 上必须 404（即使路径存在）。
        assert_eq!(
            status(gw, Method::GET, "/api/v1/admin/gateways").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn gateway_face_exposes_artifact_downloads() {
        let path = "/api/v1/releases/artifact/wist-gwlinkd/v0.15.0-alpha/pkg.tar.gz";
        assert_eq!(
            status(ListenerScope::Gateway, Method::GET, path).await,
            StatusCode::OK,
            "网关面必须能下载升级制品（gwlinkd 升级链路）"
        );
        assert_eq!(
            status(ListenerScope::Admin, Method::GET, path).await,
            StatusCode::NOT_FOUND,
            "制品下载按设计只在网关面"
        );
    }

    #[tokio::test]
    async fn admin_face_exposes_only_admin_routes() {
        let admin = ListenerScope::Admin;
        assert_eq!(
            status(admin, Method::GET, "/api/v1/admin/gateways").await,
            StatusCode::OK
        );
        assert_eq!(
            status(admin, Method::GET, "/api/v1/version").await,
            StatusCode::OK
        );
        // 网关面路由不在管理 listener 上（反向隔离，避免管理口被当成网关口用）。
        assert_eq!(
            status(admin, Method::POST, "/api/v1/gateway/status").await,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn scope_prefix_matching_has_no_false_positives() {
        // 只有精确前缀或 `/` 分隔的子路径算命中：`gatewayfoo` 不能被 `gateway` 放行。
        assert!(ListenerScope::Gateway.allows("/api/v1/gateway"));
        assert!(ListenerScope::Gateway.allows("/api/v1/gateway/status"));
        assert!(!ListenerScope::Gateway.allows("/api/v1/gatewayfoo"));
        assert!(!ListenerScope::Gateway.allows("/api/v1/admin/gateways"));
        assert!(ListenerScope::Admin.allows("/api/v1/admin"));
        assert!(ListenerScope::Admin.allows("/api/v1/admin/gateways"));
        assert!(!ListenerScope::Admin.allows("/api/v1/adminx"));
        assert!(!ListenerScope::Admin.allows("/api/v1/gateway/status"));
    }
}
