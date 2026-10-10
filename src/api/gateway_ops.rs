// 网关面 HTTP API：状态 / 升级 / 凭据等由 **mTLS 客户端证书**认人（authorize_gateway_certificate）；
// 唯 link-upstream 的**首次置备**用一次性 link bearer。

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use wist_control::{
    ACTION_PUSH_AGENT_PACKAGE, AgentStatusAcceptedReturned, DateTime, GatewayCredentialBundle,
    GatewayCredentialVerificationResult, GatewayEnrollmentResult, GatewayInitialConfig,
    GatewayInitializationStatus, GatewayInstanceLifecycleState, GatewayStatusAccepted,
    GatewayUpgradePlan, GatewayUpgradeResultAccepted, QueryGatewayInitializationStatus,
    RegisterGateway, RenewGatewayCredential, ReportAgentStatus, ReportGatewayStatus,
    ReportGatewayUpgradeResult, VerifyGatewayCredential,
};

use crate::infra::{
    EnrollmentTokenIssue, GatewayStatusUpdate, ReleaseRecord, StoreReason, StoredAgent,
    StoredGateway, StoredGatewayCredentialStatus, VerifiedGatewayIdentity, derive_regist_token,
    new_secret_token, normalize_platform, platform_family, sha256_hex,
};

use super::{
    ApiState, PeerConnectInfo, build_control_center_trust_bundle, control_center_tls_required,
    extract::{ApiJson, ApiQuery},
    rate_limit, rollout,
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

/// 接收 Gateway 上报的 Agent 状态（POST /api/v1/gateway/agents/status；报文体用模型生成的
/// `wist_control::ReportAgentStatus`，不再本地定义）：以 mTLS 客户端证书鉴权 → store upsert → VM 推送。
pub async fn submit_agent_status(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    ApiJson(input): ApiJson<ReportAgentStatus>,
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
                return super::error::internal_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    super::codes::AGENT_STATUS_UPDATE_FAILED,
                    "failed to update agent status",
                    err.display_chain(),
                );
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
                log::warn!("agent_status vm push failed: {err}");
            }
            (
                StatusCode::OK,
                Json(AgentStatusAcceptedReturned {
                    gateway_id: input.gateway_id.clone(),
                    agents_accepted: stored.len() as i64,
                }),
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
///
/// ⚠️ 本条路由**未鉴权**（设计文档已记），而三段都直接拼进本机路径 —— 所以这里必须把
/// 不是「安全路径段」的段（`..`、`%2F` 解出来的分隔符…）当作**找不到**：不给 400/404 的
/// 区别，免得给探测者一个 oracle。
pub async fn download_release_artifact(
    State(state): State<ApiState>,
    Path((component, version, filename)): Path<(String, String, String)>,
) -> Response {
    if !crate::infra::is_safe_path_segment(&component)
        || !crate::infra::is_safe_path_segment(&version)
        || !crate::infra::is_safe_path_segment(&filename)
    {
        return super::error::ApiError::not_found(
            super::codes::ARTIFACT_NOT_FOUND,
            "artifact not found",
        )
        .into_response();
    }
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
        Err(_) => super::error::ApiError::not_found(
            super::codes::ARTIFACT_NOT_FOUND,
            "artifact not found",
        )
        .into_response(),
    }
}

/// 网关注册：POST /api/v1/gateway/register。
/// 对应模型 `RegisterGateway` + `RegisterGatewayFlow`：WarpGateway 持一次性 RegistToken
/// （enrollment token）提交注册，中心用 CA-G 按其 CSR 签一张**网关专属客户端证书**（长期身份，mTLS）。
///
/// 先校验 CSR 可解析，再消费 token —— 坏 CSR 不白白消耗一次性注册 token。
pub async fn register_gateway(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    ApiJson(input): ApiJson<RegisterGateway>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    // 注册自携带 token 鉴权（无网关身份可查），独立限流桶防 token 暴力枚举。
    if let Some(response) =
        rate_limit::check_rate_limit(&state, &client_key, GATEWAY_REGISTER_SCOPE)
    {
        return response;
    }
    // 先校验 CSR（不签发）：坏 CSR 不应消耗一次性注册 token。
    if let Err(reason) = crate::infra::validate_csr(&input.certificate_signing_request) {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_REGISTER_SCOPE);
        return super::error::ApiError::bad_request(
            super::codes::INVALID_CSR,
            format!("invalid certificate signing request: {reason}"),
        )
        .into_response();
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
            return super::error::ApiError::unauthorized(
                super::codes::ENROLLMENT_TOKEN_REJECTED,
                format!("enrollment token rejected: {reason}"),
            )
            .with_no_store()
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::ENROLLMENT_TOKEN_CONSUME_FAILED,
                "failed to consume enrollment token",
                err.display_chain(),
            );
        }
    };
    // token 绑定的网关必须已创建。
    let gateway_exists = match state.store.get_gateway(&consumed.gateway_id).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            );
        }
    };
    if !gateway_exists {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_REGISTER_SCOPE);
        return super::error::ApiError::unauthorized(
            super::codes::ENROLLMENT_TOKEN_UNKNOWN_GATEWAY,
            "enrollment token bound to unknown gateway",
        )
        .with_no_store()
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
            return super::error::ApiError::bad_request(
                super::codes::INVALID_CSR,
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
        return super::error::ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::CLIENT_CERTIFICATE_PERSIST_FAILED,
            "failed to persist gateway client certificate",
        )
        .into_response();
    }
    let credential_id = match new_secret_token("cred") {
        Ok(id) => id,
        Err(reason) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::CREDENTIAL_ID_GENERATION_FAILED,
                "failed to generate gateway credential id",
                reason,
            );
        }
    };
    let bundle = GatewayCredentialBundle {
        credential_id,
        gateway_id: consumed.gateway_id.clone(),
        instance_id: Some(input.instance_id.clone()),
        certificate: issued.certificate_pem.clone(),
        ca_bundle: None,
        issued_at: ca_time(&issued.not_before),
        not_before: Some(ca_time(&issued.not_before)),
        not_after: Some(ca_time(&issued.not_after)),
    };
    // 生命周期：Provisioned → Initializing（注册成功即进入初始化）。
    if let Err(err) = state
        .store
        .mark_gateway_initializing(&consumed.gateway_id)
        .await
    {
        log::warn!("mark gateway initializing failed: {}", err.display_chain());
    }
    // 注册即带上网关对外域名 → 中心第一时间记下（早于第一拍状态上报）；不带则跳过。
    if let Some(public_base_url) = input.public_base_url.as_deref()
        && let Err(err) = state
            .store
            .set_gateway_public_base_url(&consumed.gateway_id, public_base_url)
            .await
    {
        log::warn!(
            "set gateway public_base_url failed: {}",
            err.display_chain()
        );
    }
    rate_limit::clear_auth_failures(&state, &client_key, GATEWAY_REGISTER_SCOPE);
    // 响应含证书凭据（bundle）→ `no-store`。
    super::error::json_no_store(GatewayEnrollmentResult {
        status: "accepted".to_string(),
        gateway_id: consumed.gateway_id.clone(),
        instance_id: input.instance_id,
        credential_id: bundle.credential_id.clone(),
        initial_config: "v1".to_string(),
        credential_bundle: bundle,
    })
}

/// 取升级目标：`GET /api/v1/gateway/upgrade-plan?gateway_id=&platform=`（mTLS 客户端证书鉴权）。
///
/// 解析「覆盖本网关的、最新的已批准升级计划」，给出应升到的目标；无则 `has_plan=false`。见 CR-002 C2。
/// `platform`（target-triple，可选）为网关自述平台：中心据此挑平台匹配的制品下发地址（多平台组件）。
pub async fn get_gateway_upgrade_plan(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    ApiQuery(params): ApiQuery<InitialConfigQueryParams>,
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
    match upgrade_plan_for(&state, gateway_id, params.platform.as_deref()).await {
        Ok(plan) => Json(plan).into_response(),
        Err(err) => super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::UPGRADE_PLAN_LOAD_FAILED,
            "failed to load gateway upgrade plan",
            err,
        ),
    }
}

async fn upgrade_plan_for(
    state: &ApiState,
    gateway_id: &str,
    platform: Option<&str>,
) -> Result<GatewayUpgradePlan, String> {
    // 该网关此刻该执行的计划：`rolling` 且它落在 `current_phase` 阶段内（阶段由服务端切，
    // 中心与网关同一套口径，见 `super::rollout`）。
    let Some((plan, _phase)) = rollout::active_plan_for_gateway(state, gateway_id).await? else {
        return Ok(GatewayUpgradePlan {
            gateway_id: gateway_id.to_string(),
            has_plan: false,
            plan_id: None,
            component: None,
            to_version: None,
            artifact_url: None,
            action: None,
            artifact_sha256: None,
            artifacts: Vec::new(),
        });
    };
    // 现模型的 `GatewayUpgradePlan` 只承载**单组件**目标；多组件计划这里取第一个
    // （要精确到组件，需把 `GatewayUpgradePlan` 扩成列表，届时同步发 `wist-control`）。
    let target = rollout::first_upgrade_target(&plan.spec);
    // 地址与摘要都取自**同一条**已发布的 release 记录（不新增存储；release 记录是唯一真源）。
    // 多平台组件（galaxy-ops / galaxy-flow 一次发三平台）还要按**网关声明的平台**挑，否则会把
    // Linux 制品派给 macOS 主机，网关侧架构护栏拒装、升级直接失败。
    let resolved = match &target {
        Some((component, version)) => {
            resolve_release_artifact(state, component, version, platform).await
        }
        None => None,
    };
    let artifact_url = resolved.as_ref().map(|record| record.artifact_url.clone());
    // 摘要**只**给「agent 包下发」（②）：① 升级路径的取件/校验另有一套（gops / 工具目录），
    // 现在给它加摘要会改变其既有行为，超出本特性范围。
    let artifact_sha256 = if plan.action == ACTION_PUSH_AGENT_PACKAGE {
        resolved
            .as_ref()
            .and_then(|record| record.package_sha256.clone())
    } else {
        None
    };
    // ②「Agent 包下发」：带该版本的**全部平台**制品 —— 网关替 **Agent 机队**托管各平台的包
    // （机队平台可能 ≠ 网关自己主机的平台）；① 升级不带（网关本机一个平台，用上面的单值 artifact_url）。
    let artifacts = if plan.action == ACTION_PUSH_AGENT_PACKAGE {
        match &target {
            Some((component, version)) => {
                resolve_release_artifacts(state, component, version).await
            }
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    // 网关已取走这份计划：把本阶段条目标 `dispatched`（幂等；失败只记日志，不影响下发）。
    if let Err(err) = rollout::mark_gateway_entry_dispatched(state, &plan.plan_id, gateway_id).await
    {
        log::warn!(
            "event=GatewayUpgradeDispatchMarkFailed gateway_id={gateway_id} plan_id={} err={err}",
            plan.plan_id
        );
    }
    Ok(GatewayUpgradePlan {
        gateway_id: gateway_id.to_string(),
        has_plan: true,
        plan_id: Some(plan.plan_id),
        action: Some(plan.action),
        component: target.as_ref().map(|(component, _)| component.clone()),
        to_version: target.map(|(_, version)| version),
        artifact_url,
        artifact_sha256,
        artifacts,
    })
}

/// 反查该组件该版本**已发布的那条 release 记录**（地址 + 摘要同源）；无匹配则 `None`
/// （执行器会回落用 `to_version`）。
///
/// 地址由中心派生，不让运维手输 —— 与 agent 包同款教训（手输的路径会漂到别的机器上）。
/// 返回**整条记录**（不只地址）：调用方既要 `artifact_url`，也要 `package_sha256`（② 必需）。
/// 见设计 `wist-design/doc/design/edge/gateway-upgrade-and-releases.md`、
/// `wist-design/doc/design/edge/agent-package-push-to-gateways.md`。
///
/// 多平台组件（同一 `(component, version)` 下多个平台制品行）必须按**网关声明的平台**
/// `wanted_platform` 挑，挑不到就**不给**：宁可让执行器回落、也绝不把错平台制品派给主机
/// （错平台二进制覆盖上去不会报错，只会让工具静默报废）。挑法优先级：
/// 完整 target-triple 精确命中 ＞ 同平台家族（忽略 gnu/musl 等 abi）＞ 无平台概念的包
/// （如 `wist-gateway-stack`，适用任意主机，仅当唯一时给）。
/// 该 release 记录此刻**可否派发**：`expired`（已下架）的不再派发 —— 新升级 / 新包下发都不该拿过期制品；
/// 其余状态（`published`，或历史缺省）视为可派发（对老数据保守：只跳过**显式** `expired`）。
fn is_dispatchable(record: &ReleaseRecord) -> bool {
    record.status != "expired"
}

/// 按平台匹配的单条解析。
async fn resolve_release_artifact(
    state: &ApiState,
    component: &str,
    version: &str,
    wanted_platform: Option<&str>,
) -> Option<ReleaseRecord> {
    let releases = state.store.list_releases(component).await.ok()?;
    let candidates: Vec<ReleaseRecord> = releases
        .into_iter()
        .filter(|release| release.version == version && is_dispatchable(release))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if let Some(wanted) = wanted_platform {
        // 1) 完整 target-triple 精确命中。
        let wanted = normalize_platform(wanted);
        if let Some(record) = candidates.iter().find(|record| {
            record
                .platform
                .as_deref()
                .is_some_and(|platform| normalize_platform(platform) == wanted)
        }) {
            return Some(record.clone());
        }
        // 2) 同一平台家族（吃下 gnu / musl 之类的 abi 差异）；同家族多于一条则视为歧义。
        if let Some(family) = platform_family(&wanted) {
            let mut matched = candidates.iter().filter(|record| {
                record.platform.as_deref().and_then(platform_family) == Some(family)
            });
            if let Some(record) = matched.next()
                && matched.next().is_none()
            {
                return Some(record.clone());
            }
        }
    }
    // 3) 无平台概念的包（如部署栈 `wist-gateway-stack`）适用任意主机；仅当唯一时才给。
    let mut agnostic = candidates.iter().filter(|record| record.platform.is_none());
    if let Some(record) = agnostic.next()
        && agnostic.next().is_none()
    {
        return Some(record.clone());
    }
    // 4) 老网关（不声明平台）：唯一候选即给，保持旧行为。
    if wanted_platform.is_none()
        && let [only] = candidates.as_slice()
    {
        return Some(only.clone());
    }
    // 5) 其余（多平台且网关没声明 / 声明对不上）→ 不给，执行器回落 `to_version`，
    //    绝不把错平台制品派给主机。
    None
}

/// ② 用：该 `(component, version)` 已发布的**全部平台**制品（平台 + 地址 + 摘要）。
///
/// 与 [`resolve_release_artifact`]（按网关平台**挑一条**，供 ①）不同：② 要的是**全平台** —— 网关替
/// Agent 机队托管各平台的包，机队平台可能 ≠ 网关自己主机的平台。按平台**归一化**（trim+小写）后去重、
/// 按平台名排序（稳定输出）；缺/空白摘要、无平台或纯空白平台的记录跳过（网关侧要校验，没摘要无法安全交付）；
/// **`expired` 的跳过**（与①同口径）；同平台多条按 `published_at` 取**最新**（不依赖 store 返回顺序）。
async fn resolve_release_artifacts(
    state: &ApiState,
    component: &str,
    version: &str,
) -> Vec<wist_control::GatewayUpgradeArtifact> {
    let Ok(releases) = state.store.list_releases(component).await else {
        return Vec::new();
    };
    artifacts_for_version(&releases, version)
}

/// 纯函数（便于按**任意顺序**单测）：从 release 记录里挑出该版本的**全平台**制品。
/// 剥去 store 依赖后，同平台取最新的判定**不依赖**输入顺序。
fn artifacts_for_version(
    records: &[ReleaseRecord],
    version: &str,
) -> Vec<wist_control::GatewayUpgradeArtifact> {
    // 值带 `published_at`：同平台取最新（幂等，不依赖 store 的排序）。
    let mut by_platform: std::collections::BTreeMap<
        String,
        (wist_control::DateTime, wist_control::GatewayUpgradeArtifact),
    > = std::collections::BTreeMap::new();
    for record in records {
        if record.version != version || !is_dispatchable(record) {
            continue;
        }
        let Some(platform) = record.platform.as_deref() else {
            continue;
        };
        // 归一化（trim + 小写）后作去重键与回带值 —— 与 ① 的 `resolve_release_artifact` 同口径
        // （同一主机类别的 `AArch64-Apple-Darwin ` / `aarch64-apple-darwin` 不该当成两个平台）；
        // **归一化后为空**（无平台 / 纯空白）→ 跳过：绝不下发空平台槽。
        let platform = normalize_platform(platform);
        if platform.is_empty() {
            continue;
        }
        let Some(artifact_sha256) = record
            .package_sha256
            .as_deref()
            .filter(|sha| !sha.trim().is_empty())
        else {
            continue;
        };
        let candidate = (
            record.published_at.clone(),
            wist_control::GatewayUpgradeArtifact {
                platform: platform.clone(),
                artifact_url: record.artifact_url.clone(),
                artifact_sha256: artifact_sha256.to_string(),
            },
        );
        match by_platform.entry(platform) {
            std::collections::btree_map::Entry::Occupied(mut occupied) => {
                if record.published_at.to_chrono() > occupied.get().0.to_chrono() {
                    occupied.insert(candidate);
                }
            }
            std::collections::btree_map::Entry::Vacant(vacant) => {
                vacant.insert(candidate);
            }
        }
    }
    by_platform
        .into_values()
        .map(|(_, artifact)| artifact)
        .collect()
}

/// 升级结果回执：`POST /api/v1/gateway/upgrade-result`（mTLS 客户端证书）。见 CR-002 C2。
///
/// 落结构化事件日志 + 回 ack，并**回填灰度发布计划的条目**（按 `gateway_id` 找到它此刻所在
/// `rolling` 计划的当前阶段，写状态/明细、按闸门推进）。
pub async fn report_gateway_upgrade_result(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    ApiJson(input): ApiJson<ReportGatewayUpgradeResult>,
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
    log::info!(
        "event=GatewayUpgradeResult gateway_id={} work_id={} from={} to={} step={} status={} detail={}",
        input.gateway_id,
        input.work_id,
        input.from_version,
        input.to_version,
        input.step,
        input.status,
        input.detail
    );
    // 回填计划的逐网关条目：状态折算 + 终态按闸门推进。回执已收到，回填失败只记日志，
    // 不影响回 ack（条目会留在原状，等下次同网关结果或人工推进对账）。
    if let Err(err) = rollout::reconcile_gateway_upgrade_result(
        &state,
        &input.gateway_id,
        &input.status,
        &input.detail,
    )
    .await
    {
        log::warn!(
            "event=GatewayUpgradeResultReconcileFailed gateway_id={} work_id={} err={err}",
            input.gateway_id,
            input.work_id
        );
    }
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
    /// 网关声明的目标平台（target-triple，如 `aarch64-apple-darwin`）。多平台组件的制品选择
    /// 据此判定；缺省 = 老网关不声明，中心只在「唯一候选 / 无平台概念的包」时才派生地址。
    #[serde(default)]
    pub platform: Option<String>,
}

/// 链接上级 / 拉取网关初始配置：GET /api/v1/gateway/link-upstream。
/// 对齐模型 `ProvisionGatewayFlow`。两种状态：
/// - **未初始化**（有 link、无客户端证书）：Bearer 为一次性 LinkToken，
///   携带 X-Gateway-Identity-Token → 派生 RegistToken 落 enrollment → 消费 link → 出 config.toml。
/// - **已初始化**（已有客户端证书）：由 mTLS 客户端证书鉴权 → 出同一 config.toml。
///
/// 返回 `application/json`：`config` 为 GatewayInitialConfig，置备态同时返回明文 RegistToken。
pub async fn get_gateway_initial_config(
    State(state): State<ApiState>,
    headers: HeaderMap,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    ApiQuery(params): ApiQuery<InitialConfigQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    let gateway_id = params.gateway_id.as_str();
    // 安全 #1（fail-closed）：TLS 开启但未配置信任根 → 拒绝服务，
    // 避免网关在无法校验中心证书的情况下继续初始化（可被中间人）。
    if control_center_tls_required(&state.config)
        && build_control_center_trust_bundle(&state.config, gateway_id).is_none()
    {
        return super::error::ApiError::unavailable(
            super::codes::TLS_TRUST_ROOT_MISSING,
            "TLS is required but the control center trust root is not configured",
        )
        .into_response();
    }
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            rate_limit::record_auth_failure(&state, &client_key, GATEWAY_AUTH_SCOPE);
            return super::error::ApiError::unauthorized(
                super::codes::UNKNOWN_GATEWAY,
                "unknown gateway",
            )
            .with_no_store()
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            );
        }
    };
    // 未初始化 → 置备路径。
    if gateway.credential_token_hash.is_empty() && !gateway.link_token_hash.is_empty() {
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
            // 配置类响应 → `no-store`（本路径无一次性明文凭据，仍不缓存）。
            super::error::json_no_store(InitialConfigReturned {
                config,
                regist_token: None,
            })
        }
        Err(response) => response,
    }
}

/// 置备路径：Bearer 一次性 LinkToken 鉴权 + X-Gateway-Identity-Token 派生
/// RegistToken → 落 enrollment token（供 /register 消费）→ 成功后消费 link → 出 config.toml。
async fn provision_gateway_initial_config(
    state: &ApiState,
    headers: &HeaderMap,
    gateway_id: &str,
    gateway: &StoredGateway,
    client_key: &str,
) -> Response {
    let Some(link_token) = bearer_token(headers) else {
        return super::error::ApiError::unauthorized(
            super::codes::MISSING_BEARER_CREDENTIAL,
            "missing bearer credential",
        )
        .with_no_store()
        .into_response();
    };
    if sha256_hex(link_token) != gateway.link_token_hash {
        rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
        return super::error::ApiError::unauthorized(
            super::codes::INVALID_LINK_TOKEN,
            "invalid link token",
        )
        .with_no_store()
        .into_response();
    }
    let identity_token = headers
        .get("x-gateway-identity-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(identity_token) = identity_token else {
        return super::error::ApiError::bad_request(
            super::codes::MISSING_GATEWAY_IDENTITY_TOKEN,
            "missing X-Gateway-Identity-Token",
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
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::REGIST_TOKEN_ISSUE_FAILED,
                "failed to issue regist token",
                err.display_chain(),
            );
        }
    };
    // 成功落库 RegistToken 后才消费 link（一次性；网络抖动可重试置备）。
    match state.store.consume_link_token(gateway_id, link_token).await {
        Ok(true) => {}
        Ok(false) => {
            return super::error::ApiError::conflict(
                super::codes::LINK_TOKEN_CONSUMED,
                "link token already consumed or gateway initialized",
            )
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::LINK_TOKEN_CONSUME_FAILED,
                "failed to consume link token",
                err.display_chain(),
            );
        }
    }
    // 生命周期：Provisioned → Initializing。
    if let Err(err) = state.store.mark_gateway_initializing(gateway_id).await {
        log::warn!("mark gateway initializing failed: {}", err.display_chain());
    }
    rate_limit::clear_auth_failures(state, client_key, GATEWAY_AUTH_SCOPE);
    let config = build_initial_config_json(state, gateway, gateway_id, &enrollment.token_id);
    // 含一次性 RegistToken 明文 → `no-store`。
    super::error::json_no_store(InitialConfigReturned {
        config,
        regist_token: Some(regist_token),
    })
}

/// initial-config 响应（JSON 契约）：中心下发的控制面连接配置 + 派生 RegistToken。
/// 网关/simulator 据此生成本地 config.toml（配置文件由网关侧落盘）。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct InitialConfigReturned {
    pub config: GatewayInitialConfig,
    /// 置备路径：RegistToken 明文（注册用）；已初始化路径：None（已有客户端证书）。
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
    ApiJson(input): ApiJson<ReportGatewayStatus>,
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
                public_base_url: input.public_base_url.clone(),
                last_seen_at: accepted_at.clone(),
                uptime_seconds: input.uptime_seconds,
                agent_count: input.agent_count,
                online_agents: input.online_agents,
                offline_agents: input.offline_agents,
                last_seen_lag_seconds: input.last_seen_lag_seconds,
                store_bytes: input.store_bytes,
                ingest_accepted_total: input.ingest_accepted_total,
                ingest_rejected_total: input.ingest_rejected_total,
                last_ingest_at: input.last_ingest_at,
                memory_total_bytes: input.memory_total_bytes,
                load_1m: input.load_1m,
                load_5m: input.load_5m,
                load_15m: input.load_15m,
                disk_usage_percent: input.disk_usage_percent,
                disk_total_bytes: input.disk_total_bytes,
                disk_available_bytes: input.disk_available_bytes,
            };
            let update_result = state.store.upsert_gateway_status(&update).await;
            if let Err(err) = update_result {
                return super::error::internal_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    super::codes::GATEWAY_STATUS_UPDATE_FAILED,
                    "failed to update gateway status",
                    err.display_chain(),
                );
            }
            // 时序历史：配置了 VictoriaMetrics 则推送指标（失败仅告警，不影响上报成功）。
            if let Some(vm_url) = &state.config.victoriametrics_url
                && let Err(err) =
                    crate::infra::vm::push_gateway_status(vm_client(), vm_url, &update).await
            {
                log::warn!("gateway_status vm push failed: {err}");
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
    ApiJson(input): ApiJson<RenewGatewayCredential>,
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
            return super::error::ApiError::bad_request(
                super::codes::INVALID_CSR,
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
        return super::error::ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::CLIENT_CERTIFICATE_PERSIST_FAILED,
            "failed to persist renewed gateway client certificate",
        )
        .into_response();
    }
    log::info!(
        "event=GatewayCredentialRenewed gateway_id={} old_serial={} new_serial={}",
        input.gateway_id,
        input.current_certificate_serial,
        issued.serial_hex
    );
    let credential_id = match new_secret_token("cred") {
        Ok(id) => id,
        Err(reason) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::CREDENTIAL_ID_GENERATION_FAILED,
                "failed to generate gateway credential id",
                reason,
            );
        }
    };
    let bundle = GatewayCredentialBundle {
        credential_id,
        gateway_id: input.gateway_id,
        instance_id: None,
        certificate: issued.certificate_pem.clone(),
        ca_bundle: None,
        issued_at: ca_time(&issued.not_before),
        not_before: Some(ca_time(&issued.not_before)),
        not_after: Some(ca_time(&issued.not_after)),
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
        return Err(unauthorized_code(super::codes::CERTIFICATE_REQUIRED));
    };
    // 证书身份是权威：不接受「证书说是 A、请求体说是 B」。
    if identity.gateway_id != gateway_id {
        rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
        return Err(unauthorized_code(super::codes::CERTIFICATE_MISMATCH));
    }
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
            return Err(unauthorized_code(super::codes::UNKNOWN_GATEWAY));
        }
        Err(err) => {
            return Err(super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_CREDENTIAL_STORE_UNAVAILABLE,
                "failed to load gateway credential store",
                err.display_chain(),
            ));
        }
    };
    // 登记在册的凭据指纹必须与出示证书一致：轮换 / 吊销后旧证书立即失效。
    if !constant_time_eq(
        gateway.credential_token_hash.as_bytes(),
        identity.fingerprint_sha256.as_bytes(),
    ) {
        rate_limit::record_auth_failure(state, client_key, GATEWAY_AUTH_SCOPE);
        return Err(unauthorized_code(super::codes::CERTIFICATE_NOT_REGISTERED));
    }
    if gateway.credential_status != StoredGatewayCredentialStatus::Active {
        return Err(unauthorized_code(super::codes::CERTIFICATE_NOT_ACTIVE));
    }
    if let Some(expires_at) = &gateway.credential_expires_at
        && credential_is_expired(expires_at)
    {
        return Err(unauthorized_code(super::codes::CERTIFICATE_EXPIRED));
    }
    rate_limit::clear_auth_failures(state, client_key, GATEWAY_AUTH_SCOPE);
    Ok(gateway)
}

/// 401 正文里带一个稳定 `code`，网关侧按它决定要不要自愈。
fn unauthorized_code(code: &'static str) -> Response {
    super::error::ApiError::unauthorized(code, format!("gateway identity rejected: {code}"))
        .with_no_store()
        .into_response()
}

/// 一次性 link 的 Bearer 解析（link-upstream 置备路径仍用接入券，非长期身份）。
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

/// CA 产出的 RFC3339 串 → 模型 `DateTime`。
///
/// `GatewayCa` 以 `to_rfc3339` 产出（必然可解析）；万一解析失败回落到「现在」，不 panic。
fn ca_time(value: &str) -> DateTime {
    DateTime::from_rfc3339(value).unwrap_or_else(DateTime::now)
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
    ApiJson(input): ApiJson<VerifyGatewayCredential>,
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
            verified_at: DateTime::now(),
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
    ApiQuery(params): ApiQuery<QueryGatewayInitializationStatus>,
) -> Response {
    let gateway_id = params.gateway_id.as_str();
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            return super::error::ApiError::not_found(
                super::codes::GATEWAY_NOT_FOUND,
                format!("unknown gateway `{gateway_id}`"),
            )
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            );
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

    /// 并发测试用临时状态文件：纳秒 + 进程内原子序号，避免同纳秒撞同一路径导致 Conflict。
    fn temp_state_path(prefix: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let sequence = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("{prefix}-{nanos}-{sequence}.json"))
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
        let path = temp_state_path("wic-api-test");
        let store = FileStore::new(&path);
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
                store_path: path,
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
                link_ttl_seconds: 900,
                log: Default::default(),
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
        let path = temp_state_path("wic-register");
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
                store_path: path,
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
                link_ttl_seconds: 900,
                log: Default::default(),
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

    /// 构造"已创建未置备"网关（create_gateway 存 link hash、无客户端证书）的完整路由。
    fn provision_state(link_token: &str) -> ApiState {
        // 临时文件用「纳秒 + 原子计数器」命名，避免并发测试同纳秒撞同一路径导致 Conflict。
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("wic-provision-{nanos}-{counter}.json"));
        let store = FileStore::new(&path);
        store.create_gateway("gw-p", link_token).expect("create");
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
                link_ttl_seconds: 900,
                log: Default::default(),
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

    #[tokio::test]
    async fn rejects_status_report_when_certificate_identity_does_not_match_body() {
        let response = router()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-001")))
                    .expect("request"),
                client_identity("gw-002", TEST_FINGERPRINT),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_status_report_when_certificate_is_expired() {
        let state = test_state();
        // 登记凭据已过期（指纹仍匹配）→ 仍拒（与身份到期两回事）。
        state
            .store
            .update_gateway_credential(
                "gw-001",
                TEST_FINGERPRINT,
                Some("2000-01-01T00:00:00+00:00".to_string()),
            )
            .await
            .expect("update");
        let response = super::super::router_for(state)
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
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_gateway_credential_accepts_a_registered_certificate() {
        let response = router()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/credentials/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"gateway_id":"gw-001","certificate_serial":"01"}"#,
                    ))
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
        let result: GatewayCredentialVerificationResult =
            serde_json::from_slice(&body).expect("json");
        assert_eq!(result.gateway_id, "gw-001");
        assert_eq!(result.certificate_serial, "01");
        assert_eq!(result.status, "valid");
    }

    #[tokio::test]
    async fn verify_gateway_credential_rejects_without_a_client_certificate() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/credentials/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"gateway_id":"gw-001","certificate_serial":"01"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_rejects_a_bad_csr_without_consuming_the_token() {
        let state = register_state("enroll-bad-csr");
        let app = super::super::router_for(state);
        let bad = r#"{"enrollment_token":"enroll-bad-csr","instance_id":"inst-1","certificate_signing_request":"not a csr","requested_at":"2026-08-11T00:00:00Z"}"#;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/register")
                    .header("content-type", "application/json")
                    .body(Body::from(bad))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // token 未被消费：同一 token + 合法 CSR 重试 → 200。
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/register")
                    .header("content-type", "application/json")
                    .body(Body::from(register_payload("enroll-bad-csr")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_status_report_for_a_gateway_without_a_registered_certificate() {
        // 网关已创建（有 link）但尚未注册（无登记指纹）→ 任何证书都不认。
        let response = super::super::router_for(provision_state("link-tok-x"))
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/status")
                    .header("content-type", "application/json")
                    .body(Body::from(status_payload("gw-p")))
                    .expect("request"),
                client_identity("gw-p", TEST_FINGERPRINT),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upgrade_plan_requires_a_client_certificate() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/upgrade-plan?gateway_id=gw-001")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upgrade_plan_returns_no_plan_for_a_registered_certificate() {
        let response = router()
            .oneshot(with_identity(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/upgrade-plan?gateway_id=gw-001")
                    .body(Body::empty())
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
        let plan: GatewayUpgradePlan = serde_json::from_slice(&body).expect("json");
        assert_eq!(plan.gateway_id, "gw-001");
        assert!(!plan.has_plan);
    }

    /// 端到端：建计划 →（未批准不下发）→ 批准 → 网关拉取（条目变 `dispatched`）→ 回执成功
    /// （条目 `succeeded`，单阶段即末阶段 → 计划自动 `completed`）。
    #[tokio::test]
    async fn upgrade_plan_is_served_for_the_active_phase_then_result_backfills() {
        let app = router();
        let pull_uri = "/api/v1/gateway/upgrade-plan?gateway_id=gw-001";
        let view_uri = |plan_id: &str| format!("/api/v1/admin/rollout-plans/{plan_id}");

        // 1) 建一份铺到 gw-001 的单阶段计划（dev 模式无 admin token，管理面无鉴权）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/rollout-plans")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "action": "upgrade",
                            "spec": "{\"targets\":[{\"component\":\"wist-gateway-stack\",\"target_version\":\"0.1.28\"}]}",
                            "target_ids": ["gw-001"],
                            "phase_count": 1,
                            "deadline_at": "2027-01-01T00:00:00Z",
                            "timeout_seconds": 600,
                            "batch_size": 0,
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let created: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let plan_id = created["plan_id"].as_str().expect("plan id").to_string();

        // 未批准（draft）：网关拉取 → 无计划。
        let response = app
            .clone()
            .oneshot(with_identity(
                Request::builder()
                    .method("GET")
                    .uri(pull_uri)
                    .body(Body::empty())
                    .expect("request"),
                client_identity("gw-001", TEST_FINGERPRINT),
            ))
            .await
            .expect("response");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let plan_view: GatewayUpgradePlan = serde_json::from_slice(&bytes).expect("json");
        assert!(!plan_view.has_plan, "draft 计划不下发");

        // 2) 批准 → rolling，进入第一阶段。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/rollout-plans/approve")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "plan_id": plan_id }).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        // 3) 网关拉取：有计划，组件/版本来自 spec。
        let response = app
            .clone()
            .oneshot(with_identity(
                Request::builder()
                    .method("GET")
                    .uri(pull_uri)
                    .body(Body::empty())
                    .expect("request"),
                client_identity("gw-001", TEST_FINGERPRINT),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let plan_view: GatewayUpgradePlan = serde_json::from_slice(&bytes).expect("json");
        assert!(plan_view.has_plan);
        assert_eq!(plan_view.plan_id.as_deref(), Some(plan_id.as_str()));
        assert_eq!(plan_view.component.as_deref(), Some("wist-gateway-stack"));
        assert_eq!(plan_view.to_version.as_deref(), Some("0.1.28"));

        // 拉走后条目应变 `dispatched`：视图里能区分「待派」与「已下发」。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(view_uri(&plan_id))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let detail: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(detail["entries"][0]["status"], "dispatched");

        // 4) 网关回执成功 → 条目 succeeded；单阶段（末阶段）不看闸门，自动收敛 completed。
        let response = app
            .clone()
            .oneshot(with_identity(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/gateway/upgrade-result")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "gateway_id": "gw-001",
                            "work_id": "work-1",
                            "from_version": "0.1.27",
                            "to_version": "0.1.28",
                            "step": "apply",
                            "status": "done",
                            "detail": "ok",
                            "reported_at": "2026-10-07T00:00:00Z",
                        })
                        .to_string(),
                    ))
                    .expect("request"),
                client_identity("gw-001", TEST_FINGERPRINT),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(view_uri(&plan_id))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let detail: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(detail["plan"]["status"], "completed");
        assert_eq!(detail["entries"][0]["status"], "succeeded");
    }

    /// 升级目标里的 `artifact_url` 由中心**反查已发布的 release** 派生；无对应记录那么为 `None`
    /// （执行器回落用 `to_version`）。无平台概念的包（`wist-gateway-stack`）不声明平台也派生。
    #[tokio::test]
    async fn release_artifact_url_is_derived_from_the_published_release() {
        let state = provision_state("link-tok-release");
        let url = "https://center.example/api/v1/releases/artifact/wist-gateway-stack/0.1.27/wist-gateway-stack-0.1.27.tar.gz";

        assert!(
            super::resolve_release_artifact(&state, "wist-gateway-stack", "0.1.27", None)
                .await
                .is_none(),
            "没发布过 → None"
        );

        state
            .store
            .publish_release("wist-gateway-stack", "0.1.27", url, None, None)
            .await
            .expect("publish release");
        // 无平台概念的包：网关（老/新）都能拿到它。
        for wanted in [
            None,
            Some("aarch64-apple-darwin"),
            Some("x86_64-unknown-linux-gnu"),
        ] {
            assert_eq!(
                super::resolve_release_artifact(&state, "wist-gateway-stack", "0.1.27", wanted)
                    .await
                    .map(|record| record.artifact_url)
                    .as_deref(),
                Some(url),
                "wanted={wanted:?}"
            );
        }
        assert!(
            super::resolve_release_artifact(&state, "wist-gateway-stack", "9.9.9", None)
                .await
                .is_none(),
            "版本不符 → None"
        );
    }

    /// 多平台组件（galaxy-ops 一次发三平台）：中心必须按**网关声明的平台**挑制品，
    /// 否则会把 Linux 制品派给 macOS 主机，网关侧架构护栏拒装、升级失败。
    #[tokio::test]
    async fn release_artifact_url_follows_the_gateway_platform() {
        let state = provision_state("link-tok-platform");
        let mac = "https://center.example/artifacts/galaxy-ops/v0/mac.tar.gz";
        let linux_x86 = "https://center.example/artifacts/galaxy-ops/v0/linux-x86.tar.gz";
        let linux_arm = "https://center.example/artifacts/galaxy-ops/v0/linux-arm.tar.gz";
        for (url, platform) in [
            (mac, "aarch64-apple-darwin"),
            (linux_x86, "x86_64-unknown-linux-musl"),
            (linux_arm, "aarch64-unknown-linux-musl"),
        ] {
            state
                .store
                .publish_release("galaxy-ops", "v0", url, None, Some(platform))
                .await
                .expect("publish release");
        }

        let resolve = |wanted: Option<&'static str>| {
            let state = state.clone();
            async move {
                super::resolve_release_artifact(&state, "galaxy-ops", "v0", wanted)
                    .await
                    .map(|record| record.artifact_url)
            }
        };

        // 精确三元组命中。
        assert_eq!(
            resolve(Some("aarch64-apple-darwin")).await.as_deref(),
            Some(mac)
        );
        // 同平台家族（gnu 主机也拿到 musl 制品）。
        assert_eq!(
            resolve(Some("x86_64-unknown-linux-gnu")).await.as_deref(),
            Some(linux_x86)
        );
        assert_eq!(
            resolve(Some("aarch64-unknown-linux-gnu")).await.as_deref(),
            Some(linux_arm)
        );
        // 声明了对不上的平台 → **不给**（绝不派错平台制品）。
        assert!(resolve(Some("x86_64-apple-darwin")).await.is_none());
        // 老网关不声明平台、多平台无从判定 → 不给（执行器回落版本）。
        assert!(resolve(None).await.is_none());

        // 组件只有单一平台制品且声明对不上 → 也不给（不派错平台）；声明对得上（含同家族）才给。
        state
            .store
            .publish_release(
                "solo-linux",
                "v0",
                "https://center.example/solo/solo-linux-v0.tar.gz",
                None,
                Some("x86_64-unknown-linux-musl"),
            )
            .await
            .expect("publish solo");
        assert!(
            super::resolve_release_artifact(
                &state,
                "solo-linux",
                "v0",
                Some("aarch64-apple-darwin"),
            )
            .await
            .is_none(),
            "单一 linux 制品不能派给 mac 主机"
        );
        assert_eq!(
            super::resolve_release_artifact(
                &state,
                "solo-linux",
                "v0",
                Some("x86_64-unknown-linux-gnu"),
            )
            .await
            .map(|record| record.artifact_url)
            .as_deref(),
            Some("https://center.example/solo/solo-linux-v0.tar.gz")
        );
        // 老网关不声明平台：唯一候选即给（旧行为）。
        assert_eq!(
            super::resolve_release_artifact(&state, "solo-linux", "v0", None)
                .await
                .map(|record| record.artifact_url)
                .as_deref(),
            Some("https://center.example/solo/solo-linux-v0.tar.gz")
        );
    }

    /// 建一份**已批准（rolling，进第一阶段）**的单阶段计划并落库（目标 `gateway_id`）。
    async fn seed_rolling_plan(state: &ApiState, action: &str, spec: &str, gateway_id: &str) {
        use super::super::rollout;

        let request = rollout::CreateRolloutPlanRequest {
            action: action.to_string(),
            spec: spec.to_string(),
            target_ids: vec![gateway_id.to_string()],
            phase_count: 1,
            deadline_at: None,
            timeout_seconds: 600,
            batch_size: 0,
        };
        let mut plan = rollout::build_plan(&request).expect("build plan");
        assert!(rollout::approve_plan(&mut plan), "enter first phase");
        state
            .store
            .create_upgrade_plan(&plan)
            .await
            .expect("store plan");
    }

    /// 发布 ②：`push-agent-package` 的下发目标带 **action** 与 **摘要**（`artifact_sha256`）；
    /// ① `upgrade` 只带地址、**不**带摘要（不改其既有取件/校验行为）。
    #[tokio::test]
    async fn push_agent_package_plan_carries_action_and_digest_but_upgrade_does_not() {
        let digest = "3f9a1c0d5e7b2a6489f0c1d2e3a4b5c6d7e8f9012345678abcdef0123456789";

        // ②：agentd 包**多平台**发布（各带摘要）→ 计划 action = push-agent-package，带**全平台**清单。
        let state = provision_state("link-tok-push-digest");
        let platforms = [
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
        ];
        for platform in platforms {
            let url = format!(
                "https://center.example/api/v1/releases/artifact/wist-agentd/0.1.9/wist-agentd-0.1.9-{platform}.tar.gz"
            );
            state
                .store
                .publish_release("wist-agentd", "0.1.9", &url, Some(digest), Some(platform))
                .await
                .expect("publish agentd release");
        }
        seed_rolling_plan(
            &state,
            ACTION_PUSH_AGENT_PACKAGE,
            r#"{"targets":[{"component":"wist-agentd","target_version":"0.1.9"}]}"#,
            "gw-p",
        )
        .await;

        let plan = super::upgrade_plan_for(&state, "gw-p", Some("aarch64-apple-darwin"))
            .await
            .expect("plan");
        assert_eq!(plan.action.as_deref(), Some(ACTION_PUSH_AGENT_PACKAGE));
        // 单值 `artifact_url` 仍按**网关平台**挑（供 ① / 兼容）；② 的多平台清单才是全平台。
        assert_eq!(
            plan.artifact_url.as_deref(),
            Some(
                "https://center.example/api/v1/releases/artifact/wist-agentd/0.1.9/wist-agentd-0.1.9-aarch64-apple-darwin.tar.gz"
            ),
        );
        assert_eq!(plan.artifact_sha256.as_deref(), Some(digest));
        let got: Vec<(String, String)> = plan
            .artifacts
            .iter()
            .map(|artifact| (artifact.platform.clone(), artifact.artifact_sha256.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("aarch64-apple-darwin".to_string(), digest.to_string()),
                ("aarch64-unknown-linux-musl".to_string(), digest.to_string()),
                ("x86_64-unknown-linux-musl".to_string(), digest.to_string()),
            ],
            "② 应带该版本**全部平台**（按平台名排序，机队平台可能 ≠ 网关本机平台）"
        );
        // 每个平台地址指向对应制品的原名。
        assert!(
            plan.artifacts
                .iter()
                .all(|artifact| artifact.artifact_url.contains(&artifact.platform)),
            "{:?}",
            plan.artifacts
        );

        // ①：同一条发布也给得出摘要，但 `upgrade` 计划**不**回带摘要（地址照旧）。
        let state = provision_state("link-tok-upgrade-no-digest");
        let stack_url = "https://center.example/api/v1/releases/artifact/wist-gateway-stack/0.1.28/wist-gateway-stack-0.1.28.tar.gz";
        state
            .store
            .publish_release(
                "wist-gateway-stack",
                "0.1.28",
                stack_url,
                Some(digest),
                None,
            )
            .await
            .expect("publish stack release");
        seed_rolling_plan(
            &state,
            "upgrade",
            r#"{"targets":[{"component":"wist-gateway-stack","target_version":"0.1.28"}]}"#,
            "gw-p",
        )
        .await;

        let plan = super::upgrade_plan_for(&state, "gw-p", None)
            .await
            .expect("plan");
        assert_eq!(plan.action.as_deref(), Some("upgrade"));
        assert_eq!(plan.artifact_url.as_deref(), Some(stack_url));
        assert_eq!(plan.artifact_sha256, None, "① upgrade 不回带摘要");
        assert!(
            plan.artifacts.is_empty(),
            "① upgrade 不带多平台清单：网关本机一个平台，用单值 artifact_url"
        );
    }

    /// 发布 ②：`resolve_release_artifacts` 取该版本**全部平台**制品（平台 + 地址 + 摘要），
    /// 平台去重、按平台名排序；**缺摘要 / 无平台**的记录跳过（网关侧要校验摘要，缺则无法安全交付）。
    #[tokio::test]
    async fn agent_package_artifacts_cover_all_platforms_and_skip_incomplete_records() {
        let state = provision_state("link-tok-artifacts-all");
        let sha = "sha256:aa";
        let publish =
            |url: &'static str, sha: Option<&'static str>, platform: Option<&'static str>| {
                state
                    .store
                    .publish_release("wist-agentd", "0.2.1", url, sha, platform)
            };
        // 三平台齐备；另一条**缺摘要**、再一条**无平台**（如部署栈类，② 不适用）。
        publish(
            "https://c/wist-agentd-aarch64-apple-darwin.tar.gz",
            Some(sha),
            Some("aarch64-apple-darwin"),
        )
        .await
        .expect("publish");
        publish(
            "https://c/wist-agentd-x86_64-unknown-linux-musl.tar.gz",
            Some(sha),
            Some("x86_64-unknown-linux-musl"),
        )
        .await
        .expect("publish");
        publish(
            "https://c/wist-agentd-aarch64-unknown-linux-musl.tar.gz",
            Some(sha),
            Some("aarch64-unknown-linux-musl"),
        )
        .await
        .expect("publish");
        publish(
            "https://c/wist-agentd-no-sha.tar.gz",
            None,
            Some("riscv64gc-unknown-linux-gnu"),
        )
        .await
        .expect("publish");
        publish("https://c/wist-agentd-platformless.tar.gz", Some(sha), None)
            .await
            .expect("publish");

        let artifacts = super::resolve_release_artifacts(&state, "wist-agentd", "0.2.1").await;
        let platforms: Vec<&str> = artifacts
            .iter()
            .map(|artifact| artifact.platform.as_str())
            .collect();
        assert_eq!(
            platforms,
            vec![
                "aarch64-apple-darwin",
                "aarch64-unknown-linux-musl",
                "x86_64-unknown-linux-musl",
            ],
            "全平台、按平台名排序；缺摘要 / 无平台的跳过"
        );
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact.artifact_sha256 == sha),
            "{artifacts:?}"
        );

        // 版本不符 → 空（不串版本）。
        assert!(
            super::resolve_release_artifacts(&state, "wist-agentd", "9.9.9")
                .await
                .is_empty(),
            "版本不符 → 空"
        );

        // 同平台重复发布 → 按平台去重，**最新一条胜出**（store 按 published_at 新→旧）。
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        publish(
            "https://c/wist-agentd-x86_64-unknown-linux-musl-dup.tar.gz",
            Some("sha256:bb"),
            Some("x86_64-unknown-linux-musl"),
        )
        .await
        .expect("publish");
        let artifacts = super::resolve_release_artifacts(&state, "wist-agentd", "0.2.1").await;
        let x86: Vec<_> = artifacts
            .iter()
            .filter(|artifact| artifact.platform == "x86_64-unknown-linux-musl")
            .collect();
        assert_eq!(x86.len(), 1, "同平台去重");
        assert_eq!(
            x86[0].artifact_url, "https://c/wist-agentd-x86_64-unknown-linux-musl-dup.tar.gz",
            "去重保留**最新**一条"
        );
        assert_eq!(x86[0].artifact_sha256, "sha256:bb");

        // 大小写 / 空白变体归一化后与规范形态同平台（去重），不出现第二个条目。
        publish(
            "https://c/wist-agentd-AArch64-Apple-Darwin.tar.gz",
            Some("sha256:cc"),
            Some("AArch64-Apple-Darwin "),
        )
        .await
        .expect("publish");
        let artifacts = super::resolve_release_artifacts(&state, "wist-agentd", "0.2.1").await;
        assert_eq!(
            artifacts
                .iter()
                .filter(|artifact| artifact.platform == "aarch64-apple-darwin")
                .count(),
            1,
            "平台归一化后同平台去重"
        );
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact.platform == artifact.platform.trim().to_ascii_lowercase()),
            "回带的平台已归一化：{artifacts:?}"
        );
    }

    /// 发布 ②：平台 / 摘要的**空串、纯空白**都要跳过（不能回带空平台槽或不可校验的摘要）；
    /// 且目标版本**未发布过**时 ② 计划仍下发（has_plan=true）但 `artifacts` 为空（不下发地址）。
    #[tokio::test]
    async fn agent_package_artifacts_skip_blank_platform_and_sha() {
        let state = provision_state("link-tok-artifacts-blank");
        // 各造一条不合格行：空平台 / 纯空白平台 / 空摘要 / 纯空白摘要。
        state
            .store
            .publish_release(
                "wist-agentd",
                "0.3.0",
                "https://c/blank-platform.tar.gz",
                Some("sha256:aa"),
                Some(""),
            )
            .await
            .expect("publish");
        state
            .store
            .publish_release(
                "wist-agentd",
                "0.3.0",
                "https://c/space-platform.tar.gz",
                Some("sha256:aa"),
                Some("   "),
            )
            .await
            .expect("publish");
        state
            .store
            .publish_release(
                "wist-agentd",
                "0.3.0",
                "https://c/blank-sha.tar.gz",
                Some(""),
                Some("x86_64-unknown-linux-musl"),
            )
            .await
            .expect("publish");
        state
            .store
            .publish_release(
                "wist-agentd",
                "0.3.0",
                "https://c/space-sha.tar.gz",
                Some("   "),
                Some("aarch64-unknown-linux-musl"),
            )
            .await
            .expect("publish");
        // 唯一合格的一条。
        state
            .store
            .publish_release(
                "wist-agentd",
                "0.3.0",
                "https://c/ok.tar.gz",
                Some("sha256:ok"),
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("publish");

        let artifacts = super::resolve_release_artifacts(&state, "wist-agentd", "0.3.0").await;
        assert_eq!(
            artifacts.len(),
            1,
            "仅合格那条留下（空/空白平台与摘要均跳过）：{artifacts:?}"
        );
        assert_eq!(artifacts[0].platform, "aarch64-apple-darwin");
        assert_eq!(artifacts[0].artifact_url, "https://c/ok.tar.gz");

        // ② 计划指向**未发布**的版本：计划照样下发（动作/目标在），但不给任何地址/摘要/清单。
        seed_rolling_plan(
            &state,
            ACTION_PUSH_AGENT_PACKAGE,
            r#"{"targets":[{"component":"wist-agentd","target_version":"9.9.9"}]}"#,
            "gw-p",
        )
        .await;
        let plan = super::upgrade_plan_for(&state, "gw-p", Some("aarch64-apple-darwin"))
            .await
            .expect("plan");
        assert!(plan.has_plan);
        assert_eq!(plan.action.as_deref(), Some(ACTION_PUSH_AGENT_PACKAGE));
        assert_eq!(plan.to_version.as_deref(), Some("9.9.9"));
        assert_eq!(plan.artifact_url, None, "未发布 → 不给地址");
        assert_eq!(plan.artifact_sha256, None, "未发布 → 不给摘要");
        assert!(plan.artifacts.is_empty(), "未发布 → 清单为空");
    }

    /// P5：同平台多条按 `published_at` 取**最新**，**不依赖输入顺序**（纯函数，直接喂乱序）。
    #[test]
    fn artifacts_for_version_picks_the_newest_per_platform_regardless_of_order() {
        let older = wist_control::DateTime::from_rfc3339("2026-10-01T00:00:00Z").expect("older");
        let newer = wist_control::DateTime::from_rfc3339("2026-10-02T00:00:00Z").expect("newer");
        let record = |url: &str, sha: &str, at: wist_control::DateTime| ReleaseRecord {
            version: "1.0.0".to_string(),
            artifact_url: url.to_string(),
            package_sha256: Some(sha.to_string()),
            platform: Some("aarch64-apple-darwin".to_string()),
            status: "published".to_string(),
            published_at: at,
        };
        // 乱序两种：新的在前 / 新的在后 —— 都必须选到新的。
        for records in [
            vec![
                record("https://c/new.tar.gz", "sha256:new", newer.clone()),
                record("https://c/old.tar.gz", "sha256:old", older.clone()),
            ],
            vec![
                record("https://c/old.tar.gz", "sha256:old", older.clone()),
                record("https://c/new.tar.gz", "sha256:new", newer.clone()),
            ],
        ] {
            let artifacts = artifacts_for_version(&records, "1.0.0");
            assert_eq!(artifacts.len(), 1);
            assert_eq!(
                artifacts[0].artifact_url, "https://c/new.tar.gz",
                "取最新（与输入顺序无关）：{artifacts:?}"
            );
            assert_eq!(artifacts[0].artifact_sha256, "sha256:new");
        }
    }

    /// P3：`expired`（下架）版本的制品不再派发 —— ② 全平台清单与 ① 单值解析都跳过。
    #[tokio::test]
    async fn expired_releases_are_not_dispatched() {
        let state = provision_state("link-tok-expired");
        state
            .store
            .publish_release(
                "wist-agentd",
                "0.4.0",
                "https://c/a.tar.gz",
                Some("sha256:aa"),
                Some("aarch64-apple-darwin"),
            )
            .await
            .expect("publish");
        state
            .store
            .publish_release(
                "wist-agentd",
                "0.4.0",
                "https://c/l.tar.gz",
                Some("sha256:ll"),
                Some("x86_64-unknown-linux-musl"),
            )
            .await
            .expect("publish");
        // 下架前：两平台都在。
        assert_eq!(
            super::resolve_release_artifacts(&state, "wist-agentd", "0.4.0")
                .await
                .len(),
            2
        );
        // 下架该版本（该版本全部制品行一起改）。
        let changed = state
            .store
            .set_release_status("wist-agentd", "0.4.0", "expired")
            .await
            .expect("set status");
        assert!(changed >= 1, "至少改到一行");
        // 下架后：② 清单空、① 单值 None。
        assert!(
            super::resolve_release_artifacts(&state, "wist-agentd", "0.4.0")
                .await
                .is_empty(),
            "downlisted → ② 不清单"
        );
        assert!(
            super::resolve_release_artifact(
                &state,
                "wist-agentd",
                "0.4.0",
                Some("aarch64-apple-darwin")
            )
            .await
            .is_none(),
            "downlisted → ① 不派"
        );
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
    async fn provision_initial_config_derives_regist_and_consumes_link() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let app = super::super::router_for(provision_state("link-tok-p"));

        // 未置备：Bearer 一次性 link + X-Gateway-Identity-Token → 200 + config.toml（含派生 RegistToken）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer link-tok-p")
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

        // link 一次性：置备成功后复用 → 401（已消费，且无运行期凭据）。
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer link-tok-p")
                    .header("x-gateway-identity-token", "identity-p")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 错 link → 401（不落 enrollment、不消费）。
        let app2 = super::super::router_for(provision_state("link-2"));
        let response = app2
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer wrong-link")
                    .header("x-gateway-identity-token", "identity-p")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn provision_rejects_missing_bearer() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        // 置备态网关 + 带身份头但**不带** Bearer → 401（缺接入凭据）。
        let response = super::super::router_for(provision_state("link-1"))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("x-gateway-identity-token", "identity-p")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn provision_rejects_missing_identity_token() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        // 接入券正确但**缺** X-Gateway-Identity-Token（RegistToken 的派生输入）→ 400。
        let response = super::super::router_for(provision_state("link-1"))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer link-1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn initialized_gateway_returns_config_without_a_regist_token() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        // 已置备（有客户端证书）→ 走 mTLS 路径，只回配置、regist_token 为 None。
        let response = router()
            .oneshot(with_identity(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-001")
                    .body(Body::empty())
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
        let returned: InitialConfigReturned = serde_json::from_slice(&body).expect("json");
        assert!(
            returned.regist_token.is_none(),
            "已置备不应再下发 RegistToken"
        );
    }

    #[tokio::test]
    async fn provision_fails_closed_when_tls_required_but_no_trust_root() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        // public_url=https → 要求 TLS；但 ca_cert=None → 无信任根 → 拒绝服务（fail-closed）。
        let mut state = provision_state("link-tls");
        state.config.public_url = "https://127.0.0.1:3100".to_string();
        state.config.ca_cert = None;
        let response = super::super::router_for(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/gateway/link-upstream?gateway_id=gw-p")
                    .header("authorization", "Bearer link-tls")
                    .header("x-gateway-identity-token", "identity-p")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
                link_ttl_seconds: 900,
                log: Default::default(),
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
        let state = provision_state("link-tok");
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

    /// 制品下载路由**未鉴权**（设计文档已记），三段直接拼本机路径 —— 必须堵住 `..`：
    /// 能下到制品目录里的真制品，但下不到目录之外的文件。
    #[tokio::test]
    async fn download_release_artifact_refuses_to_escape_the_artifact_dir() {
        let artifact_dir = std::env::temp_dir().join("wic-artifacts");
        let inside = artifact_dir.join("wist-gateway-stack/0.1.17");
        std::fs::create_dir_all(&inside).expect("create artifact dir");
        std::fs::write(inside.join("pkg.tar.gz"), b"pkg-bytes").expect("write artifact");

        // 制品目录**外**的文件：放在 `artifact_dir/../wic-secret/x.txt`（一层 `..` 就出去）。
        let outside = std::env::temp_dir().join("wic-secret");
        std::fs::create_dir_all(&outside).expect("create outside dir");
        std::fs::write(outside.join("x.txt"), b"SECRET").expect("write secret");

        let app = super::super::router_for(test_state());

        // 对照组：同形状的合法三段能正常下载（证明 404 是拦截，不是路由不匹配）。
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/releases/artifact/wist-gateway-stack/0.1.17/pkg.tar.gz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(
            &ok.into_body().collect().await.expect("body").to_bytes()[..],
            b"pkg-bytes"
        );

        // `component = ..` → 必须 404，且正文不能是那个文件的内容。
        let escaped = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/releases/artifact/../wic-secret/x.txt")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(escaped.status(), StatusCode::NOT_FOUND);
        let body = escaped
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert!(
            !body.windows(6).any(|window| window == b"SECRET"),
            "artifact download must not leak files outside the artifact dir"
        );

        let _ = std::fs::remove_dir_all(&inside);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
