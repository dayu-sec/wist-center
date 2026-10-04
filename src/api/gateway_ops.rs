// ReceiveGatewayStatusReport 接收链路：POST /api/v1/gateway/status。
// 镜像 wist-gateway 的 submit_agent_status：Bearer 鉴权（sha256 常数时间比较）→
// store 落库最新状态 → 返回 GatewayStatusAccepted。

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use wist_contracts::gateway_control::{
    GatewayCredentialBundle, GatewayCredentialVerificationResult, GatewayEnrollmentResult,
    RegisterGateway, RenewGatewayCredential, VerifyGatewayCredential,
};
use wist_control::{
    GatewayInitialConfig, GatewayInitializationStatus, GatewayInstanceLifecycleState,
    GatewayStatusAccepted, GatewayUpgradePlan, GatewayUpgradeResultAccepted,
    QueryGatewayInitializationStatus, ReportGatewayStatus, ReportGatewayUpgradeResult,
};

use crate::infra::{
    EnrollmentTokenIssue, GatewayStatusUpdate, StoreReason, StoredAgent, StoredGateway,
    StoredGatewayCredentialStatus, VerifiedGatewayIdentity, derive_regist_token, new_secret_token,
    sha256_hex,
};

use super::{
    ApiState, PeerConnectInfo, build_control_center_trust_bundle, control_center_tls_required,
    rate_limit,
};

const GATEWAY_AUTH_SCOPE: &str = "gateway";
/// 注册自携带 token 鉴权，无网关身份可查，独立限流桶防 token 暴力枚举。
const GATEWAY_REGISTER_SCOPE: &str = "gateway-register";

/// 允许 Gateway Web 以 Authorization Header 直接调用初始化端点。
/// 该端点不使用 Cookie，因此使用通配来源不会扩大用户会话权限；Token 仍只在 Header 中传输。
/// 处理浏览器对 Gateway 初始化请求的 Authorization 预检。
pub async fn options_gateway_initial_config() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// Gateway 上报其下 Agent 状态（POST /api/v1/gateway/agents/status）。
#[derive(serde::Deserialize)]
pub struct AgentStatusReportRequest {
    pub gateway_id: String,
    pub agents: Vec<AgentStatusEntry>,
}

#[derive(serde::Deserialize)]
pub struct AgentStatusEntry {
    pub agent_id: String,
    pub instance_id: String,
    pub version: String,
    pub status: String,
    pub health: String,
    #[serde(default)]
    pub memory_bytes: Option<i64>,
    #[serde(default)]
    pub cpu_percent: Option<f64>,
    #[serde(default)]
    pub admin_latency_ms: Option<i64>,
    pub last_seen_at: wist_control::types::DateTime,
}

/// 接收 Gateway 上报的 Agent 状态：Bearer 按 gateway_id 凭证鉴权 → store upsert → VM 推送。
pub async fn submit_agent_status(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Json(input): Json<AgentStatusReportRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    match authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|identity| &identity.0),
        &input.gateway_id,
        &client_key,
    )
    .await
    {
        Ok(_) => {
            let stored: Vec<StoredAgent> = input
                .agents
                .iter()
                .map(|agent| StoredAgent {
                    agent_id: agent.agent_id.clone(),
                    gateway_id: input.gateway_id.clone(),
                    instance_id: agent.instance_id.clone(),
                    version: agent.version.clone(),
                    status: agent.status.clone(),
                    health: agent.health.clone(),
                    memory_bytes: agent.memory_bytes,
                    cpu_percent: agent.cpu_percent,
                    admin_latency_ms: agent.admin_latency_ms,
                    last_seen_at: agent.last_seen_at.clone(),
                })
                .collect();
            if let Err(err) = state
                .store
                .upsert_agent_status(&input.gateway_id, &stored)
                .await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to update agent status: {err}"),
                )
                    .into_response();
            }
            if let Some(vm_url) = &state.config.victoriametrics_url
                && let Err(err) = crate::infra::vm::push_agent_status(
                    vm_client(),
                    vm_url,
                    &input.gateway_id,
                    &stored,
                )
                .await
            {
                eprintln!("warn agent_status vm push failed: {err}");
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "gateway_id": input.gateway_id,
                    "agents_accepted": stored.len(),
                })),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

/// VM 推送全局 HTTP 客户端（进程内复用连接池）。
fn vm_client() -> &'static reqwest::Client {
    crate::infra::vm::shared_vm_client()
}

/// 下载本地镜像的制品：GET /api/v1/releases/artifact/:component/:version/:filename。
pub async fn download_release_artifact(
    State(state): State<ApiState>,
    Path((component, version, filename)): Path<(String, String, String)>,
) -> Response {
    let path = state
        .config
        .artifact_dir
        .join(&component)
        .join(&version)
        .join(&filename);
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "artifact not found").into_response(),
    }
}

/// 网关注册：POST /api/v1/gateway/register。
/// 对应模型 `RegisterGateway` + `RegisterGatewayFlow`：WarpGateway 持一次性
/// RegistToken（enrollment token）提交注册。消费 token（防重放/限量/吊销/过期）后
/// **签发独立运行期凭据（RUNTIME_TOKEN）**：RegistToken 只用于本次注册，
/// 运行期 Bearer（link-upstream / status）以新签发的凭据为准。
pub async fn register_gateway(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    Json(input): Json<RegisterGateway>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    // 注册自携带 token 鉴权（无网关身份可查），独立限流桶防 token 暴力枚举。
    if let Some(response) =
        rate_limit::check_rate_limit(&state, &client_key, GATEWAY_REGISTER_SCOPE)
    {
        return response;
    }
    let consumed = match state
        .store
        .consume_enrollment_token(&input.enrollment_token)
        .await
    {
        Ok(token) => token,
        Err(err) if err.reason() == &StoreReason::Enrollment => {
            rate_limit::record_auth_failure(&state, &client_key, GATEWAY_REGISTER_SCOPE);
            let reason = err
                .detail()
                .as_deref()
                .unwrap_or("enrollment token rejected");
            return (
                StatusCode::UNAUTHORIZED,
                format!("enrollment token rejected: {reason}"),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to consume enrollment token: {err}"),
            )
                .into_response();
        }
    };
    // token 绑定的网关必须已创建。
    let gateway_exists = match state.store.get_gateway(&consumed.gateway_id).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway store: {err}"),
            )
                .into_response();
        }
    };
    if !gateway_exists {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_REGISTER_SCOPE);
        return (
            StatusCode::UNAUTHORIZED,
            "enrollment token bound to unknown gateway".to_string(),
        )
            .into_response();
    }
    // 注册成功：用 **CA-G** 按网关 CSR 签一张「每网关一张」客户端证书（长期身份，取代运行期 bearer）。
    let issued = match state.gateway_ca.issue_client_certificate(
        &input.certificate_signing_request,
        &consumed.gateway_id,
        state.config.credential_ttl_seconds,
    ) {
        Ok(issued) => issued,
        Err(reason) => {
            rate_limit::record_auth_failure(&state, &client_key, GATEWAY_REGISTER_SCOPE);
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid certificate signing request: {reason}"),
            )
                .into_response();
        }
    };
    // 存证书指纹（供吊销/拒绝名单）；过期时间 = 证书 not_after。
    let updated = state
        .store
        .update_gateway_credential(
            &consumed.gateway_id,
            &issued.fingerprint_sha256_hex,
            Some(issued.not_after.clone()),
        )
        .await
        .unwrap_or(false);
    if !updated {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist gateway client certificate".to_string(),
        )
            .into_response();
    }
    let credential_id = match new_secret_token("cred") {
        Ok(id) => id,
        Err(reason) => return (StatusCode::INTERNAL_SERVER_ERROR, reason).into_response(),
    };
    let bundle = GatewayCredentialBundle {
        credential_id,
        gateway_id: consumed.gateway_id.clone(),
        instance_id: Some(input.instance_id.clone()),
        certificate: issued.certificate_pem.clone(),
        ca_bundle: None,
        issued_at: issued.not_before.clone(),
        not_before: Some(issued.not_before.clone()),
        not_after: Some(issued.not_after.clone()),
    };
    // 生命周期：Provisioned → Initializing（注册成功即进入初始化）。
    if let Err(err) = state
        .store
        .mark_gateway_initializing(&consumed.gateway_id)
        .await
    {
        eprintln!("warn mark gateway initializing failed: {err}");
    }
    rate_limit::clear_auth_failures(&state, &client_key, GATEWAY_REGISTER_SCOPE);
    Json(GatewayEnrollmentResult {
        status: "accepted".to_string(),
        gateway_id: consumed.gateway_id.clone(),
        instance_id: input.instance_id,
        credential_id: bundle.credential_id.clone(),
        initial_config: "v1".to_string(),
        credential_bundle: bundle,
    })
    .into_response()
}

/// 取升级目标：`GET /api/v1/gateway/upgrade-plan?gateway_id=`（mTLS 客户端证书鉴权）。
///
/// 解析「覆盖本网关的、最新的已批准升级计划」，给出应升到的目标；无则 `has_plan=false`。见 CR-002 C2。
pub async fn get_gateway_upgrade_plan(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Query(params): Query<InitialConfigQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    let gateway_id = params.gateway_id.as_str();
    if let Err(response) = authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|identity| &identity.0),
        gateway_id,
        &client_key,
    )
    .await
    {
        return response;
    }
    match upgrade_plan_for(&state, gateway_id).await {
        Ok(plan) => Json(plan).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err).into_response(),
    }
}

async fn upgrade_plan_for(
    state: &ApiState,
    gateway_id: &str,
) -> Result<GatewayUpgradePlan, String> {
    let plans = state
        .store
        .list_upgrade_plans()
        .await
        .map_err(|err| format!("failed to load upgrade plans: {err}"))?;
    // `list_upgrade_plans` 已按 created_at DESC：第一份覆盖本网关的 approved 即为目标。
    for plan in &plans {
        if plan.status != "approved" {
            continue;
        }
        let covered = plan
            .steps
            .iter()
            .any(|step| step.gateway_ids.iter().any(|id| id == gateway_id));
        if !covered {
            continue;
        }
        // 现模型的 `GatewayUpgradePlan` 只承载**单组件**目标；多组件计划这里取第一个
        // （要精确到组件，需把 `GatewayUpgradePlan` 扩成列表，届时同步发 `wist-control`）。
        let target = plan.targets.first();
        return Ok(GatewayUpgradePlan {
            gateway_id: gateway_id.to_string(),
            has_plan: true,
            plan_id: Some(plan.plan_id.clone()),
            component: target.map(|target| target.component.clone()),
            to_version: target.map(|target| target.target_version.clone()),
        });
    }
    Ok(GatewayUpgradePlan {
        gateway_id: gateway_id.to_string(),
        has_plan: false,
        plan_id: None,
        component: None,
        to_version: None,
    })
}

/// 升级结果回执：`POST /api/v1/gateway/upgrade-result`（mTLS 客户端证书）。见 CR-002 C2。
///
/// 现在只落结构化事件日志 + 回 ack；持久化视图待补（CR-002 C2 follow-up）。
pub async fn report_gateway_upgrade_result(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Json(input): Json<ReportGatewayUpgradeResult>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|identity| &identity.0),
        &input.gateway_id,
        &client_key,
    )
    .await
    {
        return response;
    }
    eprintln!(
        "event=GatewayUpgradeResult gateway_id={} work_id={} from={} to={} step={} status={} detail={}",
        input.gateway_id,
        input.work_id,
        input.from_version,
        input.to_version,
        input.step,
        input.status,
        input.detail
    );
    Json(GatewayUpgradeResultAccepted {
        gateway_id: input.gateway_id,
        work_id: input.work_id,
        accepted_at: wist_control::DateTime::now(),
    })
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct InitialConfigQueryParams {
    pub gateway_id: String,
}

/// 链接上级 / 拉取网关初始配置：GET /api/v1/gateway/link-upstream。
/// 对齐模型 `ProvisionGatewayFlow`；gateway 面 Bearer 鉴权。两种状态：
/// - **未初始化**（有 bootstrap、无运行期凭据）：Bearer 为一次性 BootstrapToken，
///   携带 X-Gateway-Identity-Token → 派生 RegistToken 落 enrollment → 消费 bootstrap → 出 config.toml。
/// - **已初始化**（有运行期凭据）：现有 authenticate_gateway（Bearer RUNTIME_TOKEN）→ 出同一 config.toml。
///
/// 返回 `application/json`：`config` 为 GatewayInitialConfig，置备态同时返回明文 RegistToken。
pub async fn get_gateway_initial_config(
    State(state): State<ApiState>,
    headers: HeaderMap,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Query(params): Query<InitialConfigQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    let gateway_id = params.gateway_id.as_str();
    // 安全 #1（fail-closed）：TLS 开启但未配置信任根 → 拒绝服务，
    // 避免网关在无法校验中心证书的情况下继续初始化（可被中间人）。
    if control_center_tls_required(&state.config)
        && build_control_center_trust_bundle(&state.config, gateway_id).is_none()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "TLS is required but the control center trust root is not configured",
        )
            .into_response();
    }
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            rate_limit::record_auth_failure(&state, &client_key, GATEWAY_AUTH_SCOPE);
            return (StatusCode::UNAUTHORIZED, "unknown gateway").into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway store: {err}"),
            )
                .into_response();
        }
    };
    // 未初始化 → 置备路径。
    if gateway.credential_token_hash.is_empty() && !gateway.bootstrap_token_hash.is_empty() {
        return provision_gateway_initial_config(
            &state,
            &headers,
            gateway_id,
            &gateway,
            &client_key,
        )
        .await;
    }
    // 已初始化 → 以现有 mTLS 客户端证书鉴权。
    match authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|identity| &identity.0),
        gateway_id,
        &client_key,
    )
    .await
    {
        Ok(gateway) => {
            let enrollment_token_id = state
                .store
                .get_enrollment_token_for_gateway(gateway_id)
                .await
                .ok()
                .flatten()
                .map(|token| token.token_id)
                .unwrap_or_default();
            let config =
                build_initial_config_json(&state, &gateway, gateway_id, &enrollment_token_id);
            Json(InitialConfigReturned {
                config,
                regist_token: None,
            })
            .into_response()
        }
        Err(response) => response,
    }
}

/// 置备路径：Bearer 一次性 BootstrapToken 鉴权 + X-Gateway-Identity-Token 派生
/// RegistToken → 落 enrollment token（供 /register 消费）→ 成功后消费 bootstrap → 出 config.toml。
async fn provision_gateway_initial_config(
    state: &ApiState,
    headers: &HeaderMap,
    gateway_id: &str,
    gateway: &StoredGateway,
    client_key: &str,
) -> Response {
    let Some(bootstrap_token) = bearer_token(headers) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer credential").into_response();
    };
    if sha256_hex(bootstrap_token) != gateway.bootstrap_token_hash {
        rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
        return (StatusCode::UNAUTHORIZED, "invalid bootstrap token").into_response();
    }
    let identity_token = headers
        .get("x-gateway-identity-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(identity_token) = identity_token else {
        return (
            StatusCode::BAD_REQUEST,
            "missing X-Gateway-Identity-Token".to_string(),
        )
            .into_response();
    };
    // 派生 RegistToken：HMAC(center_secret, "gateway-reg:" + gateway_id + ":" + identity_token)。
    let regist_token = derive_regist_token(&state.config.hmac_secret, gateway_id, identity_token);
    // 落 enrollment token（sha256(regist_token)，max_uses=1，Active），供 /register 一次性消费。
    let enrollment = match state
        .store
        .create_enrollment_token(
            gateway_id,
            &EnrollmentTokenIssue {
                token: regist_token.clone(),
                issued_by: "provision".to_string(),
                control_center_trust_bundle: state.config.ca_cert.clone(),
            },
        )
        .await
    {
        Ok(token) => token,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to issue regist token: {err}"),
            )
                .into_response();
        }
    };
    // 成功落库 RegistToken 后才消费 bootstrap（一次性；网络抖动可重试置备）。
    match state
        .store
        .consume_bootstrap_token(gateway_id, bootstrap_token)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                "bootstrap token already consumed or gateway initialized".to_string(),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to consume bootstrap token: {err}"),
            )
                .into_response();
        }
    }
    // 生命周期：Provisioned → Initializing。
    if let Err(err) = state.store.mark_gateway_initializing(gateway_id).await {
        eprintln!("warn mark gateway initializing failed: {err}");
    }
    rate_limit::clear_auth_failures(state, client_key, GATEWAY_AUTH_SCOPE);
    let config = build_initial_config_json(state, gateway, gateway_id, &enrollment.token_id);
    Json(InitialConfigReturned {
        config,
        regist_token: Some(regist_token),
    })
    .into_response()
}

/// initial-config 响应（JSON 契约）：中心下发的控制面连接配置 + 派生 RegistToken。
/// 网关/simulator 据此生成本地 config.toml（配置文件由网关侧落盘）。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct InitialConfigReturned {
    pub config: GatewayInitialConfig,
    /// 置备路径：RegistToken 明文（注册用）；已初始化路径：None（已用运行期凭据）。
    pub regist_token: Option<String>,
}

/// 构建 initial-config 的 config 部分（JSON 字段，网关侧据此写 config.toml）。
fn build_initial_config_json(
    state: &ApiState,
    gateway: &StoredGateway,
    gateway_id: &str,
    enrollment_token_id: &str,
) -> GatewayInitialConfig {
    GatewayInitialConfig {
        gateway_id: gateway.gateway_id.clone(),
        control_center_endpoint: state.config.public_url.trim_end_matches('/').to_string(),
        trust_bundle: build_control_center_trust_bundle(&state.config, gateway_id),
        server_tls_required: control_center_tls_required(&state.config),
        protocol_version: state.config.protocol_version.clone(),
        enrollment_token_id: enrollment_token_id.to_string(),
    }
}

pub async fn submit_gateway_status(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Json(input): Json<ReportGatewayStatus>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    match authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|identity| &identity.0),
        &input.gateway_id,
        &client_key,
    )
    .await
    {
        Ok(_) => {
            let accepted_at = input.reported_at.clone();
            let update = GatewayStatusUpdate {
                gateway_id: input.gateway_id.clone(),
                instance_id: input.instance_id.clone(),
                version: input.version.clone(),
                status: input.status.clone(),
                health: input.health.clone(),
                memory_bytes: input.memory_bytes,
                cpu_percent: input.cpu_percent,
                last_seen_at: accepted_at.clone(),
            };
            let update_result = state.store.upsert_gateway_status(&update).await;
            if let Err(err) = update_result {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to update gateway status: {err}"),
                )
                    .into_response();
            }
            // 时序历史：配置了 VictoriaMetrics 则推送指标（失败仅告警，不影响上报成功）。
            if let Some(vm_url) = &state.config.victoriametrics_url
                && let Err(err) =
                    crate::infra::vm::push_gateway_status(vm_client(), vm_url, &update).await
            {
                eprintln!("warn gateway_status vm push failed: {err}");
            }
            (
                StatusCode::OK,
                Json(GatewayStatusAccepted {
                    gateway_id: input.gateway_id,
                    instance_id: input.instance_id,
                    accepted_at,
                }),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

/// 轮换网关客户端证书：POST /api/v1/gateway/credentials:renew。
///
/// 以**当前客户端证书**（mTLS）证明身份 → 用 CA-G 按新 CSR 签一张新证书 →
/// 原子替换登记指纹 → 旧证书立即失效。镜像 wist-gateway `renew_agent_credential`（证书轮换）。
pub async fn renew_gateway_credential(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Json(input): Json<RenewGatewayCredential>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|identity| &identity.0),
        &input.gateway_id,
        &client_key,
    )
    .await
    {
        return response;
    }
    let issued = match state.gateway_ca.issue_client_certificate(
        &input.certificate_signing_request,
        &input.gateway_id,
        state.config.credential_ttl_seconds,
    ) {
        Ok(issued) => issued,
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid certificate signing request: {reason}"),
            )
                .into_response();
        }
    };
    let updated = state
        .store
        .update_gateway_credential(
            &input.gateway_id,
            &issued.fingerprint_sha256_hex,
            Some(issued.not_after.clone()),
        )
        .await
        .unwrap_or(false);
    if !updated {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist renewed gateway client certificate".to_string(),
        )
            .into_response();
    }
    eprintln!(
        "event=GatewayCredentialRenewed gateway_id={} old_serial={} new_serial={}",
        input.gateway_id, input.current_certificate_serial, issued.serial_hex
    );
    let credential_id = match new_secret_token("cred") {
        Ok(id) => id,
        Err(reason) => return (StatusCode::INTERNAL_SERVER_ERROR, reason).into_response(),
    };
    let bundle = GatewayCredentialBundle {
        credential_id,
        gateway_id: input.gateway_id,
        instance_id: None,
        certificate: issued.certificate_pem.clone(),
        ca_bundle: None,
        issued_at: issued.not_before.clone(),
        not_before: Some(issued.not_before.clone()),
        not_after: Some(issued.not_after.clone()),
    };
    rate_limit::clear_auth_failures(&state, &client_key, GATEWAY_AUTH_SCOPE);
    (StatusCode::OK, Json(bundle)).into_response()
}

/// 网关面鉴权：**由 mTLS 客户端证书认人**（不再有 bearer）。
///
/// 证书在 TLS 握手期已由 CA-G 验链（[`VerifiedGatewayIdentity`] 即其产物）；这里只判：
/// 证书身份与请求体 `gateway_id` 是否一致、登记是否 Active、指纹是否在册、是否未过期。
/// 任一不满足即 401，正文带稳定 `code`，供网关侧按码自愈（镜像网关给 agent 的口径）。
#[allow(clippy::result_large_err)]
async fn authorize_gateway_certificate(
    state: &ApiState,
    identity: Option<&VerifiedGatewayIdentity>,
    gateway_id: &str,
    client_key: &str,
) -> Result<StoredGateway, Response> {
    if let Some(response) = rate_limit::check_rate_limit(state, client_key, GATEWAY_AUTH_SCOPE) {
        return Err(response);
    }
    let Some(identity) = identity else {
        // 没带证书属未认证请求，不计入暴力尝试。
        return Err(unauthorized_code("certificate_required"));
    };
    // 证书身份是权威：不接受「证书说是 A、请求体说是 B」。
    if identity.gateway_id != gateway_id {
        rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
        return Err(unauthorized_code("certificate_mismatch"));
    }
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
            return Err(unauthorized_code("unknown_gateway"));
        }
        Err(err) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway credential store: {err}"),
            )
                .into_response());
        }
    };
    // 登记在册的凭据指纹必须与出示证书一致：轮换 / 吊销后旧证书立即失效。
    if !constant_time_eq(
        gateway.credential_token_hash.as_bytes(),
        identity.fingerprint_sha256.as_bytes(),
    ) {
        rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
        return Err(unauthorized_code("certificate_not_registered"));
    }
    if gateway.credential_status != StoredGatewayCredentialStatus::Active {
        return Err(unauthorized_code("certificate_not_active"));
    }
    if let Some(expires_at) = &gateway.credential_expires_at
        && credential_is_expired(expires_at)
    {
        return Err(unauthorized_code("certificate_expired"));
    }
    rate_limit::clear_auth_failures(state, client_key, GATEWAY_AUTH_SCOPE);
    Ok(gateway)
}

/// 401 正文里带一个稳定 `code`，网关侧按它决定要不要自愈。
fn unauthorized_code(code: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        format!("gateway identity rejected: {code}"),
    )
        .into_response()
}

/// 一次性 bootstrap 的 Bearer 解析（link-upstream 置备路径仍用引导券，非长期身份）。
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn credential_is_expired(expires_at: &str) -> bool {
    let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return true;
    };
    chrono::Utc::now() >= expires_at.with_timezone(&chrono::Utc)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }
    diff == 0
}

/// 校验网关通讯凭据（VerifyGatewayCredentialFlow）：以 mTLS 客户端证书鉴权，
/// 通过即回 valid 结果（`certificate_serial` 取自被验证书）。
pub async fn verify_gateway_credential(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Json(input): Json<VerifyGatewayCredential>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    match authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|identity| &identity.0),
        &input.gateway_id,
        &client_key,
    )
    .await
    {
        Ok(_) => Json(GatewayCredentialVerificationResult {
            gateway_id: input.gateway_id,
            certificate_serial: input.certificate_serial,
            status: "valid".to_string(),
            verified_at: chrono::Utc::now().to_rfc3339(),
        })
        .into_response(),
        Err(response) => response,
    }
}

/// 查询网关初始化状态（QueryGatewayInitializationStatus）：GET /api/v1/gateway/initialization-status。
/// 供网关/前端初始化页判断是否已初始化：initialized = lifecycle_state != Provisioned；
/// lifecycle_state 未记录（None）时按未初始化（Provisioned）处理。
pub async fn query_gateway_initialization_status(
    State(state): State<ApiState>,
    Query(params): Query<QueryGatewayInitializationStatus>,
) -> Response {
    let gateway_id = params.gateway_id.as_str();
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                format!("unknown gateway `{gateway_id}`"),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load gateway store: {err}"),
            )
                .into_response();
        }
    };
    let lifecycle_state = gateway
        .lifecycle_state
        .unwrap_or(GatewayInstanceLifecycleState::Provisioned);
    Json(GatewayInitializationStatus {
        gateway_id: gateway.gateway_id.clone(),
        instance_id: Some(gateway.instance_id.clone()),
        lifecycle_state,
        initialized: lifecycle_state != GatewayInstanceLifecycleState::Provisioned,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request};
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    use crate::{api::ApiState, config::GatewayCredentialSeed, infra::FileStore};

    fn test_gateway_ca() -> std::sync::Arc<crate::infra::gateway_ca::GatewayCa> {
        std::sync::Arc::new(
            crate::infra::gateway_ca::GatewayCa::generate("Wist Test Gateway CA")
                .expect("gateway ca")
                .0,
        )
    }

    /// 与 `test_state` 登记在册的凭据指纹一致（模拟「持本网关证书的 mTLS 对端」）。
    const TEST_FINGERPRINT: &str =
        "abababababababababababababababababababababababababababababababab";
    const OTHER_FINGERPRINT: &str =
        "00000000000000000000000000000000000000000000000000000000000000ff";
    const TEST_EXPIRES_AT: &str = "2099-01-01T00:00:00+00:00";

    /// 造一张合法 CSR（PEM）：私钥不上送，只交公钥。
    fn csr() -> String {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "gateway");
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    /// 构造 mTLS 握手后注入的网关身份（`fingerprint` 要与登记在册的一致才认）。
    fn client_identity(gateway_id: &str, fingerprint: &str) -> VerifiedGatewayIdentity {
        VerifiedGatewayIdentity {
            gateway_id: gateway_id.to_string(),
            fingerprint_sha256: fingerprint.to_string(),
            serial_hex: "01".to_string(),
            not_before: "2026-01-01T00:00:00+00:00".to_string(),
            not_after: TEST_EXPIRES_AT.to_string(),
        }
    }

    /// 把 mTLS 身份塞进请求扩展（运行期由 TLS 层注入，测试里手动注入）。
    fn with_identity(
        mut request: Request<Body>,
        identity: VerifiedGatewayIdentity,
    ) -> Request<Body> {
        request.extensions_mut().insert(identity);
        request
    }

    fn test_state() -> ApiState {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-api-test-{nanos}.json"));
        let store = FileStore::new(path);
        store
            .seed(&[GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "secret-token-1".to_string(),
                expires_at: None,
            }])
            .expect("seed");
        // 登记凭据改为「证书指纹」，与 `client_identity` 对齐（mTLS 口径）。
        store
            .update_gateway_credential(
                "gw-001",
                TEST_FINGERPRINT,
                Some(TEST_EXPIRES_AT.to_string()),
            )
            .expect("credential");
        ApiState {
            config: crate::config::CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: std::env::temp_dir().join(format!("wic-api-test-{nanos}.json")),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: None,
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

    fn router() -> Router {
        super::super::router_for(test_state())
    }

    /// 构造带 seed 网关 + 注册 Token 的完整路由（register 端点走 router_for）。
    fn register_state(enrollment_token: &str) -> ApiState {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-register-{nanos}.json"));
        let store = FileStore::new(&path);
        store
            .seed(&[GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "cred-tok".to_string(),
                expires_at: None,
            }])
            .expect("seed");
        store
            .create_enrollment_token(
                "gw-001",
                &crate::infra::EnrollmentTokenIssue {
                    token: enrollment_token.to_string(),
                    issued_by: "test".to_string(),
                    control_center_trust_bundle: None,
                },
            )
            .expect("enroll");
        ApiState {
            config: crate::config::CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: std::env::temp_dir().join(format!("wic-register-{nanos}.json")),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: None,
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

    /// 构造"已创建未置备"网关（create_gateway 存 bootstrap hash、无运行期凭据）的完整路由。
    fn provision_state(bootstrap_token: &str) -> ApiState {
        // 临时文件用「纳秒 + 原子计数器」命名，避免并发测试同纳秒撞同一路径导致 Conflict。
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("wic-provision-{nanos}-{counter}.json"));
        let store = FileStore::new(&path);
        store
            .create_gateway("gw-p", bootstrap_token)
            .expect("create");
        ApiState {
            config: crate::config::CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: path.clone(),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: None,
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

    fn status_payload(gateway_id: &str) -> String {
        format!(
            r#"{{"gateway_id":"{gateway_id}","instance_id":"inst-1","version":"v2.4.1","status":"online","health":"healthy","reported_at":"2026-08-07T12:00:00Z"}}"#
        )
    }

    #[tokio::test]
    async fn accepts_status_report_with_valid_client_certificate() {
        let response = router()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
                client_identity("gw-001", TEST_FINGERPRINT),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let returned: GatewayStatusAccepted = serde_json::from_slice(&body).expect("json");
        assert_eq!(returned.gateway_id, "gw-001");
        assert_eq!(returned.instance_id, "inst-1");
    }

    #[tokio::test]
    async fn rejects_report_without_client_certificate() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_report_with_unregistered_certificate() {
        // 身份是 gw-001，但出示证书的指纹不在册（未注册 / 已轮换作废）→ 401。
        let response = router()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
                client_identity("gw-001", OTHER_FINGERPRINT),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_report_with_unknown_gateway() {
        let response = router()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-999")))
                    .expect("request"),
                client_identity("gw-999", TEST_FINGERPRINT),
            ))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn register_payload(token: &str) -> String {
        format!(
            r#"{{"enrollment_token":"{token}","instance_id":"inst-1","certificate_signing_request":{},"requested_at":"2026-08-11T00:00:00Z"}}"#,
            serde_json::to_string(&csr()).expect("csr json")
        )
    }

    #[tokio::test]
    async fn register_consumes_token_once_then_rejects_replay() {
        let state = register_state("enroll-tok-a");
        let store = state.store.clone();
        let app = super::super::router_for(state);

        // 首次注册 → 200 accepted + 注册回执（含客户端证书）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload("enroll-tok-a")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let returned: GatewayEnrollmentResult =
            serde_json::from_slice(&response_body).expect("json");
        assert_eq!(returned.status, "accepted");
        assert_eq!(returned.gateway_id, "gw-001");
        assert_eq!(returned.instance_id, "inst-1");
        // 注册后签发**客户端证书**（mTLS 长期身份）：不再有 bearer。
        let bundle = &returned.credential_bundle;
        assert!(
            bundle.certificate.contains("BEGIN CERTIFICATE"),
            "certificate: {}",
            bundle.certificate
        );
        assert!(bundle.ca_bundle.is_none());
        assert_eq!(bundle.gateway_id, "gw-001");
        assert_eq!(bundle.instance_id.as_deref(), Some("inst-1"));
        assert!(bundle.not_after.is_some());

        // 防重放：同一 token 二次注册 → 401（Exhausted）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload("enroll-tok-a")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 注册把登记凭据换成了**签出证书的指纹**：以它为 mTLS 身份调 status → 200。
        let registered = store
            .get_gateway("gw-001")
            .await
            .expect("get")
            .expect("registered");
        let issued_fingerprint = registered.credential_token_hash.clone();
        assert_eq!(issued_fingerprint.len(), 64, "{issued_fingerprint}");
        let response = app
            .clone()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
                client_identity("gw-001", &issued_fingerprint),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        // 旧登记凭据（seed 的 cred-tok hash）不再是有效证书身份 → 401。
        let stale_fingerprint = sha256_hex("cred-tok");
        assert_ne!(stale_fingerprint, issued_fingerprint);
        let response = app
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
                client_identity("gw-001", &stale_fingerprint),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn provision_initial_config_derives_regist_and_consumes_bootstrap() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let app = super::super::router_for(provision_state("boot-tok-p"));

        // 未置备：Bearer 一次性 bootstrap + X-Gateway-Identity-Token → 200 + config.toml（含派生 RegistToken）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer boot-tok-p")
                    .header("x-gateway-identity-token", "identity-p")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.contains("application/json"),
            "content-type: {content_type}"
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let returned: InitialConfigReturned = serde_json::from_slice(&body).expect("json");
        // 派生 RegistToken 通过 JSON 响应的 regist_token 字段返回。
        let expected_regist =
            crate::infra::derive_regist_token("test-hmac-secret", "gw-p", "identity-p");
        assert_eq!(
            returned.regist_token.as_deref(),
            Some(expected_regist.as_str())
        );
        assert!(!returned.config.server_tls_required);
        assert!(
            returned
                .config
                .enrollment_token_id
                .starts_with("enroll-gw-p")
        );

        // bootstrap 一次性：置备成功后复用 → 401（已消费，且无运行期凭据）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer boot-tok-p")
                    .header("x-gateway-identity-token", "identity-p")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 错 bootstrap → 401（不落 enrollment、不消费）。
        let app2 = super::super::router_for(provision_state("boot-2"));
        let response = app2
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer wrong-boot")
                    .header("x-gateway-identity-token", "identity-p")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn renew_gateway_credential_rotates_the_client_certificate() {
        let state = register_state("enroll-r");
        let store = state.store.clone();
        let app = super::super::router_for(state);

        // 先注册，拿到第一张客户端证书（登记指纹落库）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload("enroll-r")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let old_fingerprint = store
            .get_gateway("gw-001")
            .await
            .expect("get")
            .expect("registered")
            .credential_token_hash;
        assert_eq!(old_fingerprint.len(), 64);

        // 轮换：以当前证书（mTLS 身份）+ 新 CSR → 200 新证书。
        let renew_body = format!(
            r#"{{"gateway_id":"gw-001","current_certificate_serial":"deadbeef","certificate_signing_request":{},"requested_at":"2026-08-11T00:00:00Z"}}"#,
            serde_json::to_string(&csr()).expect("csr json")
        );
        let response = app
            .clone()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/credentials:renew")
                    .header("content-type", "application/json")
                    .body(Body::from(renew_body))
                    .expect("request"),
                client_identity("gw-001", &old_fingerprint),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let renewed: GatewayCredentialBundle = serde_json::from_slice(&body).expect("json");
        assert!(
            renewed.certificate.contains("BEGIN CERTIFICATE"),
            "certificate: {}",
            renewed.certificate
        );
        assert_eq!(renewed.gateway_id, "gw-001");
        // 轮换请求体不带 instance_id（模型同口径），故回执里留空。
        assert!(renewed.instance_id.is_none());
        assert!(renewed.not_after.is_some());

        // 旧证书指纹立即失效 → 401；新登记指纹 → 200。
        let new_fingerprint = store
            .get_gateway("gw-001")
            .await
            .expect("get")
            .expect("registered")
            .credential_token_hash;
        assert_ne!(new_fingerprint, old_fingerprint);

        let response = app
            .clone()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
                client_identity("gw-001", &old_fingerprint),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
                client_identity("gw-001", &new_fingerprint),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn initial_config_preflight_allows_gateway_web_authorization_header() {
        let response = super::super::router_for(register_state("enroll-tok-c"))
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-001")
                    .header("origin", "http://127.0.0.1:5174")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert!(
            response
                .headers()
                .get("access-control-allow-headers")
                .expect("allow headers")
                .to_str()
                .expect("header value")
                .contains("authorization")
        );
    }

    #[tokio::test]
    async fn register_rejects_unknown_token() {
        let app = super::super::router_for(register_state("enroll-tok-a"));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload("enroll-tok-unknown")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_rejects_revoked_token() {
        // 构造 FileStore → seed 网关 + 签发 token → 吊销 → 再注册 → 401。
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("wic-register-revoked-{nanos}.json"));
        let file_store = FileStore::new(&path);
        file_store
            .seed(&[GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "cred-tok".to_string(),
                expires_at: None,
            }])
            .expect("seed");
        let token = file_store
            .create_enrollment_token(
                "gw-001",
                &crate::infra::EnrollmentTokenIssue {
                    token: "enroll-tok-b".to_string(),
                    issued_by: "test".to_string(),
                    control_center_trust_bundle: None,
                },
            )
            .expect("enroll");
        file_store
            .revoke_enrollment_token("gw-001", &token.token_id)
            .expect("revoke");
        let state = ApiState {
            config: crate::config::CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: std::env::temp_dir().join(format!("wic-register-revoked-{nanos}.json")),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: None,
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
            },
            store: std::sync::Arc::new(file_store),
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
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload("enroll-tok-b")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn query_initialization_status_tracks_lifecycle() {
        let state = provision_state("boot-tok");
        let store = state.store.clone();
        let app = super::super::router_for(state);
        // 未初始化：Provisioned → initialized = false。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/initialization-status?gateway_id=gw-p")
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
        let status: GatewayInitializationStatus = serde_json::from_slice(&body).expect("json");
        assert_eq!(status.gateway_id, "gw-p");
        assert_eq!(
            status.lifecycle_state,
            GatewayInstanceLifecycleState::Provisioned
        );
        assert!(!status.initialized);
        // initial-config 置备流程将 Center 侧生命周期推进到 Initializing。
        store
            .mark_gateway_initializing("gw-p")
            .await
            .expect("mark initializing");
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/initialization-status?gateway_id=gw-p")
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
        let status: GatewayInitializationStatus = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            status.lifecycle_state,
            GatewayInstanceLifecycleState::Initializing
        );
        assert!(status.initialized);
    }
}
