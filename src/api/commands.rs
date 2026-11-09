//! 指令（Command）资源：`/api/v1/admin/commands`。
//!
//! 契约见 `wist-design/doc/design/center/center-open-api.md` §6：
//! - `create` 负责受理与冻结（只写 `commands`，不碰队列）；
//! - `dispatch` 负责展开目标并入 `gateway_commands` 队列；
//! - 网关回执由 `wparse_proxy_api::report_command_result` 回填到 `target_commands`。
//!
//! 本期只开放网关本机可执行的两个种类（`diagnose` / `restart-*`），
//! 它们在网关侧**已有实现**，不需要网关发版即可端到端验证。

use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wist_control::types::DateTime;

use crate::infra::{
    COMMAND_STATE_CANCELLED, COMMAND_STATE_VALIDATED, CommandRecord, TARGET_STATE_FAILED,
    TARGET_STATE_QUEUED, TargetCommandRecord, aggregate_state, new_secret_token,
};

use super::{
    ApiState, PeerConnectInfo,
    admin_auth::require_admin_bearer,
    codes,
    error::ApiError,
    extract::{ApiJson, ApiQuery},
    rate_limit,
};

/// 单次 create 的目标上限（与设计文档 §6.6 一致；超出请走 rollout-plans）。
pub const MAX_TARGETS: usize = 50;
/// 指令默认有效期 / 上限。
const DEFAULT_TTL_SECONDS: i64 = 24 * 60 * 60;
const MAX_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
/// `Idempotency-Key` 长度上限。
const MAX_IDEMPOTENCY_KEY: usize = 128;
/// payload 上限（序列化后字节数）。
const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
/// 身份尚未拆成多 subject（P0 的后续项）：本期审计主体固定为 `admin`。
const ADMIN_ACTOR: &str = "admin";

/// `report-agents` 需要 gwlinkd ≥ 0.21.0：它才知道这个 wire kind，并负责环回拉取 + 转报。
pub(super) const REPORT_AGENTS_MIN_GWLINKD: &str = "0.21.0";

/// gwlinkd 是否支持 `report-agents`。
///
/// `Some(true)` = 满足；`Some(false)` = 已知太旧；`None` = 版本未知 / 认不出来。
/// 调用方对 `None` 的取向：**不拦**（无法判定时不在中心制造假阴性，命令回执仍会说真话）。
pub(super) fn gwlinkd_supports_report_agents(version: Option<&str>) -> Option<bool> {
    fn core(value: &str) -> Option<Vec<u64>> {
        let normalized = wist_release::package::normalize_version(value);
        let mut parts = wist_release::package::parse_version(&normalized)?;
        // 补齐到三段：`0.21` 与 `0.21.0` 必须等价（Vec 的逐段比较会把前者当更旧）。
        while parts.len() < 3 {
            parts.push(0);
        }
        Some(parts)
    }
    let version = version?.trim();
    if version.is_empty() {
        return None;
    }
    Some(core(version)? >= core(REPORT_AGENTS_MIN_GWLINKD)?)
}

#[derive(Debug, Clone, Copy)]
struct KindSpec {
    /// 调用方词表里的种类。
    kind: &'static str,
    /// 只允许的目标类型。
    target_type: &'static str,
    /// 高危种类必须先 `create`（`dispatch_now=false`）、再显式 `dispatch`。
    requires_explicit_dispatch: bool,
}

/// 本期开放的 `kind`。新增 = 在这里加一行 + 实现 wire 映射（加性变更）。
const KINDS: &[KindSpec] = &[
    KindSpec {
        kind: "gateway.diagnose",
        target_type: "gateway",
        requires_explicit_dispatch: false,
    },
    // 立即上报 Agent 明细 / 数据清单：R0、无载荷。gwlinkd 环回拉网关机队后 mTLS 转报中心。
    KindSpec {
        kind: "gateway.report-agents",
        target_type: "gateway",
        requires_explicit_dispatch: false,
    },
    KindSpec {
        kind: "gateway.restart-process",
        target_type: "gateway",
        requires_explicit_dispatch: true,
    },
];

/// 词表里存在、但本期**未启用**的种类（明确拒绝，而不是当成未知）。
const NOT_ENABLED_KINDS: &[&str] = &[
    "gateway.refresh-policy",
    "gateway.bind-tenant",
    "gateway.publish-rules",
    "agent.refresh-facts",
    "agent.rotate-identity",
    "investigation.run",
];

fn kind_spec(kind: &str) -> Option<&'static KindSpec> {
    KINDS.iter().find(|spec| spec.kind == kind)
}

/// 把一个已受理的 kind + payload 翻译成「投给网关的 wire kind + body」。
///
/// 返回 `None` 表示 payload 不合法（调用方错误，不进队列）。
fn wire_for(kind: &str, payload: &Value) -> Option<(&'static str, Option<String>)> {
    match kind {
        // `diagnose` 的载荷固定为空：gwlinkd 自己决定体检项。
        "gateway.diagnose" => Some(("diagnose", None)),
        // 立即上报 Agent 明细：载荷固定为空（要报什么由 gwlinkd 环回面决定）。
        "gateway.report-agents" => Some((crate::wparse_proxy::KIND_REPORT_AGENTS, None)),
        "gateway.restart-process" => {
            let process = payload.get("process").and_then(Value::as_str)?;
            match process {
                "gateway" => Some(("restart-gateway", None)),
                "gwlinkd" => Some(("restart-gwlinkd", None)),
                _ => None,
            }
        }
        _ => None,
    }
}

// ── 请求 / 响应 ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CommandTargetSpec {
    #[serde(rename = "type")]
    pub target_type: String,
    pub ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCommandRequest {
    pub kind: String,
    pub target: CommandTargetSpec,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub reason: Option<String>,
    /// 报文里自报的发起人：只用于展示与审计，**不参与授权**。
    #[serde(default)]
    pub requested_by: Option<String>,
    #[serde(default)]
    pub dispatch_now: Option<bool>,
    #[serde(default)]
    pub expires_at: Option<DateTime>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DispatchCommandRequest {
    /// 只能在创建时冻结的目标集合内**收窄**；`None` = 全量。
    #[serde(default)]
    pub target_ids: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CommandListQuery {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CommandTargetView {
    #[serde(rename = "type")]
    pub target_type: String,
    pub ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TargetCommandView {
    pub target_id: String,
    pub target_command_id: String,
    pub state: String,
    pub attempts: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CommandView {
    pub command_id: String,
    pub request_id: String,
    pub kind: String,
    pub state: String,
    pub target: CommandTargetView,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    pub created_by: String,
    pub created_at: DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatched_at: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatched_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled_at: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub targets: Vec<TargetCommandView>,
}

impl CommandView {
    fn from_records(command: &CommandRecord, targets: &[TargetCommandRecord]) -> Self {
        Self {
            command_id: command.command_id.clone(),
            request_id: command.request_id.clone(),
            kind: command.kind.clone(),
            state: command.state.clone(),
            target: CommandTargetView {
                target_type: command.target_type.clone(),
                ids: command.target_ids.clone(),
            },
            payload: command.payload.clone(),
            reason: command.reason.clone(),
            requested_by: command.requested_by.clone(),
            created_by: command.created_by.clone(),
            created_at: command.created_at.clone(),
            expires_at: command.expires_at.clone(),
            dispatched_at: command.dispatched_at.clone(),
            dispatched_by: command.dispatched_by.clone(),
            cancelled_at: command.cancelled_at.clone(),
            last_error: command.last_error.clone(),
            targets: targets
                .iter()
                .map(|target| TargetCommandView {
                    target_id: target.target_id.clone(),
                    target_command_id: target.target_command_id.clone(),
                    state: target.state.clone(),
                    attempts: target.attempts,
                    result_status: target.result_status,
                    result_error: target.result_error.clone(),
                })
                .collect(),
        }
    }
}

// ── 处理器 ───────────────────────────────────────────────────────────────

/// `POST /api/v1/admin/commands`
pub async fn create_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<CreateCommandRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }

    let Some(request_id) = idempotency_key(&headers) else {
        return ApiError::bad_request(
            codes::IDEMPOTENCY_KEY_REQUIRED,
            "Idempotency-Key header is required",
        )
        .into_response();
    };

    let kind = request.kind.trim();
    let Some(spec) = kind_spec(kind) else {
        let code = if NOT_ENABLED_KINDS.contains(&kind) {
            codes::COMMAND_KIND_NOT_ALLOWED
        } else {
            codes::COMMAND_KIND_UNKNOWN
        };
        return ApiError::bad_request(code, format!("kind `{kind}` is not accepted"))
            .into_response();
    };
    if request.target.target_type.trim() != spec.target_type {
        return ApiError::bad_request(
            codes::COMMAND_PAYLOAD_INVALID,
            format!(
                "kind `{kind}` only accepts target.type={}",
                spec.target_type
            ),
        )
        .into_response();
    }

    // 目标：去重（保序）+ 非空 + 上限。
    let mut seen = HashSet::new();
    let mut target_ids = Vec::new();
    for id in &request.target.ids {
        let id = id.trim();
        if id.is_empty() {
            return ApiError::bad_request(
                codes::COMMAND_TARGET_NOT_FOUND,
                "target ids must not be empty",
            )
            .into_response();
        }
        if seen.insert(id.to_string()) {
            target_ids.push(id.to_string());
        }
    }
    if target_ids.is_empty() {
        return ApiError::bad_request(
            codes::COMMAND_TARGET_NOT_FOUND,
            "target.ids must not be empty",
        )
        .into_response();
    }
    if target_ids.len() > MAX_TARGETS {
        return ApiError::bad_request(
            codes::COMMAND_TARGET_LIMIT_EXCEEDED,
            format!(
                "at most {MAX_TARGETS} targets per command; use /api/v1/admin/rollout-plans for larger batches"
            ),
        )
        .into_response();
    }
    // 一次取全量网关（FileStore 的 `get_gateway` 每次都重读整个快照，逐个查会放大 50 次）。
    let known_gateways: HashSet<String> = match state.store.list_gateways().await {
        Ok(gateways) => gateways
            .into_iter()
            .map(|gateway| gateway.gateway_id)
            .collect(),
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::COMMAND_STORE_UNAVAILABLE,
                "failed to load targets",
                err,
            )
            .into_response();
        }
    };
    if let Some(unknown) = target_ids
        .iter()
        .find(|target_id| !known_gateways.contains(target_id.as_str()))
    {
        return ApiError::not_found(
            codes::COMMAND_TARGET_NOT_FOUND,
            format!("unknown target `{unknown}`"),
        )
        .into_response();
    }

    let payload = request.payload.unwrap_or_else(|| json!({}));
    if serde_json::to_vec(&payload)
        .map(|raw| raw.len())
        .unwrap_or(usize::MAX)
        > MAX_PAYLOAD_BYTES
    {
        return ApiError::unprocessable(
            codes::COMMAND_PAYLOAD_INVALID,
            format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes"),
        )
        .into_response();
    }
    if wire_for(kind, &payload).is_none() {
        return ApiError::unprocessable(
            codes::COMMAND_PAYLOAD_INVALID,
            format!("payload does not match kind `{kind}`"),
        )
        .into_response();
    }

    let dispatch_now = request.dispatch_now.unwrap_or(true);
    if spec.requires_explicit_dispatch && dispatch_now {
        return ApiError::bad_request(
            codes::COMMAND_KIND_NOT_ALLOWED,
            format!(
                "kind `{kind}` must be created with dispatch_now=false, then dispatched explicitly"
            ),
        )
        .into_response();
    }

    let now = DateTime::now();
    let expires_at = match request.expires_at {
        Some(value) => {
            if value <= now {
                return ApiError::bad_request(
                    codes::COMMAND_PAYLOAD_INVALID,
                    "expires_at must be in the future",
                )
                .into_response();
            }
            let max = now.clone().to_chrono() + chrono::Duration::seconds(MAX_TTL_SECONDS);
            if value.to_chrono() > max {
                return ApiError::bad_request(
                    codes::COMMAND_PAYLOAD_INVALID,
                    format!("expires_at must be within {MAX_TTL_SECONDS} seconds"),
                )
                .into_response();
            }
            value
        }
        None => DateTime::from_rfc3339(
            &(now.clone().to_chrono() + chrono::Duration::seconds(DEFAULT_TTL_SECONDS))
                .to_rfc3339(),
        )
        .unwrap_or_else(|| now.clone()),
    };

    // 幂等重放：同 key 同 body 返回原指令；异 body 冲突。
    match state.store.find_command_by_request_id(&request_id).await {
        Ok(Some(existing)) => {
            let same = existing.kind == kind
                && existing.target_type == spec.target_type
                && existing.target_ids == target_ids
                && existing.payload == payload;
            if !same {
                return ApiError::conflict(
                    codes::COMMAND_IDEMPOTENCY_CONFLICT,
                    "Idempotency-Key was already used with a different body",
                )
                .into_response();
            }
            let targets = state
                .store
                .list_target_commands(&existing.command_id)
                .await
                .unwrap_or_default();
            return Json(CommandView::from_records(&existing, &targets)).into_response();
        }
        Ok(None) => {}
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::COMMAND_STORE_UNAVAILABLE,
                "failed to check idempotency key",
                err,
            )
            .into_response();
        }
    }

    let command = CommandRecord {
        command_id: new_secret_token("cmd").unwrap_or_default(),
        request_id,
        kind: kind.to_string(),
        target_type: spec.target_type.to_string(),
        target_ids,
        payload,
        reason: request.reason.filter(|value| !value.trim().is_empty()),
        requested_by: request
            .requested_by
            .filter(|value| !value.trim().is_empty()),
        state: COMMAND_STATE_VALIDATED.to_string(),
        created_by: ADMIN_ACTOR.to_string(),
        created_at: now,
        dispatched_at: None,
        dispatched_by: None,
        expires_at: Some(expires_at),
        cancelled_at: None,
        last_error: None,
    };
    if let Err(err) = state.store.insert_command(&command, &[]).await {
        // 并发双发（同一 `Idempotency-Key`）可能同时越过了上面的重放检查：
        // 唯一约束会拒掉后到的一条，这里按“重放”再查一次，避免把正常的重试报成 500。
        if let Ok(Some(existing)) = state
            .store
            .find_command_by_request_id(&command.request_id)
            .await
        {
            let same = existing.kind == command.kind
                && existing.target_type == command.target_type
                && existing.target_ids == command.target_ids
                && existing.payload == command.payload;
            if same {
                let targets = state
                    .store
                    .list_target_commands(&existing.command_id)
                    .await
                    .unwrap_or_default();
                return Json(CommandView::from_records(&existing, &targets)).into_response();
            }
            return ApiError::conflict(
                codes::COMMAND_IDEMPOTENCY_CONFLICT,
                "Idempotency-Key was already used with a different body",
            )
            .into_response();
        }
        return store_error("failed to create command", err);
    }

    if dispatch_now {
        match dispatch_inner(&state, &command, None).await {
            Ok(updated) => {
                let targets = state
                    .store
                    .list_target_commands(&updated.command_id)
                    .await
                    .unwrap_or_default();
                (
                    StatusCode::CREATED,
                    Json(CommandView::from_records(&updated, &targets)),
                )
                    .into_response()
            }
            Err(response) => response,
        }
    } else {
        (
            StatusCode::CREATED,
            Json(CommandView::from_records(&command, &[])),
        )
            .into_response()
    }
}

/// `POST /api/v1/admin/commands/{command_id}:dispatch`
pub async fn dispatch_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(command_id): Path<String>,
    ApiJson(request): ApiJson<DispatchCommandRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let command = match load_command(&state, &command_id).await {
        Ok(Some(command)) => command,
        Ok(None) => return command_not_found(&command_id),
        Err(response) => return response,
    };
    if command.state != COMMAND_STATE_VALIDATED {
        return ApiError::conflict(
            codes::COMMAND_STATE_CONFLICT,
            format!(
                "command is {}, only validated can be dispatched",
                command.state
            ),
        )
        .into_response();
    }
    if let Some(expires_at) = &command.expires_at
        && *expires_at <= DateTime::now()
    {
        return ApiError::conflict(codes::COMMAND_STATE_CONFLICT, "command is expired")
            .into_response();
    }

    match dispatch_inner(&state, &command, request.target_ids).await {
        Ok(updated) => {
            let targets = state
                .store
                .list_target_commands(&updated.command_id)
                .await
                .unwrap_or_default();
            (
                StatusCode::ACCEPTED,
                Json(CommandView::from_records(&updated, &targets)),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

/// `POST /api/v1/admin/commands/{command_id}:cancel`
pub async fn cancel_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(command_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let mut command = match load_command(&state, &command_id).await {
        Ok(Some(command)) => command,
        Ok(None) => return command_not_found(&command_id),
        Err(response) => return response,
    };
    if command.is_terminal() {
        return ApiError::conflict(
            codes::COMMAND_STATE_CONFLICT,
            format!("command is already {}", command.state),
        )
        .into_response();
    }
    // 本期只支持「未投递」的取消：已入队的行在 `gateway_commands` 里，
    // 队列没有撤回 API（gwlinkd 仍会取走执行）。不做“以为撤了其实没撤”的假承诺。
    if command.state != COMMAND_STATE_VALIDATED {
        return ApiError::conflict(
            codes::COMMAND_STATE_CONFLICT,
            format!(
                "command is {}; only validated (not dispatched) commands can be cancelled",
                command.state
            ),
        )
        .into_response();
    }
    command.state = COMMAND_STATE_CANCELLED.to_string();
    command.cancelled_at = Some(DateTime::now());
    if let Err(err) = state.store.save_command(&command).await {
        return store_error("failed to cancel command", err);
    }
    let targets = state
        .store
        .list_target_commands(&command.command_id)
        .await
        .unwrap_or_default();
    Json(CommandView::from_records(&command, &targets)).into_response()
}

/// `GET /api/v1/admin/commands`
pub async fn list_commands(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<CommandListQuery>,
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
    let state_filter = normalized(query.state);
    let kind = normalized(query.kind);
    match state
        .store
        .list_commands(state_filter.as_deref(), kind.as_deref(), limit)
        .await
    {
        Ok(commands) => {
            let mut views = Vec::with_capacity(commands.len());
            for command in commands {
                let targets = state
                    .store
                    .list_target_commands(&command.command_id)
                    .await
                    .unwrap_or_default();
                views.push(CommandView::from_records(&command, &targets));
            }
            Json(views).into_response()
        }
        Err(err) => store_error("failed to list commands", err),
    }
}

/// `GET /api/v1/admin/commands/{command_id}`
pub async fn get_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path(command_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let command = match load_command(&state, &command_id).await {
        Ok(Some(command)) => command,
        Ok(None) => return command_not_found(&command_id),
        Err(response) => return response,
    };
    let targets = state
        .store
        .list_target_commands(&command.command_id)
        .await
        .unwrap_or_default();
    Json(CommandView::from_records(&command, &targets)).into_response()
}

/// `GET /api/v1/admin/commands/{command_id}/targets/{target_command_id}`
pub async fn get_target_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    Path((command_id, target_command_id)): Path<(String, String)>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.get_target_command(&target_command_id).await {
        Ok(Some(target)) if target.command_id == command_id => Json(json!({
            "target_id": target.target_id,
            "target_command_id": target.target_command_id,
            "state": target.state,
            "attempts": target.attempts,
            "result_status": target.result_status,
            "result_error": target.result_error,
            "result_body": target.result_body,
        }))
        .into_response(),
        Ok(_) => ApiError::not_found(codes::COMMAND_NOT_FOUND, "target command not found")
            .into_response(),
        Err(err) => store_error("failed to load target command", err),
    }
}

/// 旧入口 `POST /api/v1/gateway/agents/dispatch`：一个发布周期后删除。
pub async fn agent_fleet_dispatch_moved() -> Response {
    let mut response = ApiError::new(
        StatusCode::GONE,
        codes::COMMAND_ENDPOINT_MOVED,
        "moved to POST /api/v1/admin/commands",
    )
    .into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_static("/api/v1/admin/commands"),
    );
    response
}

/// 网关回执 → 回填逐目标记录并重算聚合状态。
///
/// 由 `wparse_proxy_api::report_command_result` 调用；对**不是**由本资源创建的队列命令
/// （如规则发布）直接忽略（查不到 target 行 → 返回）。
pub(crate) async fn reconcile_result(
    state: &ApiState,
    target_command_id: &str,
    status_code: u16,
    error: Option<String>,
    body: Option<String>,
) {
    let target = match state.store.get_target_command(target_command_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return,
        Err(err) => {
            log::warn!(
                "event=CommandResultLoadFailed target_command_id={} err={}",
                target_command_id,
                err
            );
            return;
        }
    };
    let mut target = target;
    let succeeded = error.is_none() && status_code < 400;
    target.state = if succeeded {
        crate::infra::TARGET_STATE_SUCCEEDED.to_string()
    } else {
        TARGET_STATE_FAILED.to_string()
    };
    target.result_status = Some(i32::from(status_code));
    target.result_error = error;
    target.result_body = body;
    target.updated_at = DateTime::now();
    if let Err(err) = state.store.save_target_command(&target).await {
        log::warn!(
            "event=CommandResultSaveFailed target_command_id={} err={}",
            target_command_id,
            err
        );
        return;
    }

    let parent_id = target.command_id.clone();
    let mut command = match state.store.get_command(&parent_id).await {
        Ok(Some(command)) => command,
        Ok(None) => return,
        Err(err) => {
            log::warn!(
                "event=CommandAggregateLoadFailed command_id={} err={}",
                parent_id,
                err
            );
            return;
        }
    };
    let targets = match state.store.list_target_commands(&parent_id).await {
        Ok(targets) => targets,
        Err(err) => {
            log::warn!(
                "event=CommandAggregateTargetsFailed command_id={} err={}",
                parent_id,
                err
            );
            return;
        }
    };
    command.state = aggregate_state(&targets);
    if let Err(err) = state.store.save_command(&command).await {
        log::warn!(
            "event=CommandAggregateSaveFailed command_id={} err={}",
            parent_id,
            err
        );
    }
}

// ── 内部 ─────────────────────────────────────────────────────────────────

// axum `Response` 作为 Err 载荷是刻意设计：调用方直接 `if let Err(response) = ... { return response; }`。
#[allow(clippy::result_large_err)]
async fn load_command(
    state: &ApiState,
    command_id: &str,
) -> Result<Option<CommandRecord>, Response> {
    state.store.get_command(command_id).await.map_err(|err| {
        ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::COMMAND_STORE_UNAVAILABLE,
            "failed to load command",
            err,
        )
        .into_response()
    })
}

fn command_not_found(command_id: &str) -> Response {
    ApiError::not_found(
        codes::COMMAND_NOT_FOUND,
        format!("command `{command_id}` not found"),
    )
    .into_response()
}

fn store_error(message: &str, err: wist_error::StoreError) -> Response {
    ApiError::internal_with(
        StatusCode::INTERNAL_SERVER_ERROR,
        codes::COMMAND_STORE_UNAVAILABLE,
        message,
        err,
    )
    .into_response()
}

fn idempotency_key(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())?
        .trim();
    if raw.is_empty() || raw.len() > MAX_IDEMPOTENCY_KEY {
        return None;
    }
    Some(raw.to_string())
}

/// 展开目标并入队。调用方已做「状态必须是 validated」的判定。
#[allow(clippy::result_large_err)]
async fn dispatch_inner(
    state: &ApiState,
    command: &CommandRecord,
    requested: Option<Vec<String>>,
) -> Result<CommandRecord, Response> {
    let Some(proxy) = state.proxy.as_ref() else {
        return Err(ApiError::unavailable(
            codes::COMMAND_STORE_UNAVAILABLE,
            "command queue is not enabled on this center (PostgreSQL required)",
        )
        .into_response());
    };

    // 收窄：只允许创建时冻结集合的子集，且顺序按冻结集合。
    let selected: Vec<String> = match requested {
        Some(ids) => {
            let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
            let mut out = Vec::new();
            for id in &command.target_ids {
                if wanted.contains(id.as_str()) {
                    out.push(id.clone());
                }
            }
            if out.is_empty() {
                return Err(ApiError::bad_request(
                    codes::COMMAND_TARGET_NOT_FOUND,
                    "no target selected from this command",
                )
                .into_response());
            }
            out
        }
        None => command.target_ids.clone(),
    };

    let (wire_kind, wire_body) = wire_for(&command.kind, &command.payload).ok_or_else(|| {
        ApiError::unprocessable(
            codes::COMMAND_PAYLOAD_INVALID,
            "payload does not match kind",
        )
        .into_response()
    })?;

    let now = DateTime::now();
    let mut targets = Vec::with_capacity(selected.len());
    let mut last_error = None;
    for target_id in selected {
        // 网关目标：target_id 就是 gateway_id。
        let gateway_id = target_id.clone();
        // 旧 gwlinkd 不认识 `report-agents`，会在**执行时**回 400。在中心先按上报的
        // `gwlinkd_version` 拦一道：能提前失败，就不让运维面对“已下发但没反应”。
        if wire_kind == crate::wparse_proxy::KIND_REPORT_AGENTS {
            let gwlinkd_version = state
                .store
                .get_gateway(&gateway_id)
                .await
                .ok()
                .flatten()
                .and_then(|gateway| gateway.gwlinkd_version);
            if gwlinkd_supports_report_agents(gwlinkd_version.as_deref()) == Some(false) {
                let detail = format!(
                    "gwlinkd {} 不支持 report-agents（需要 >= {}）",
                    gwlinkd_version.as_deref().unwrap_or("?"),
                    REPORT_AGENTS_MIN_GWLINKD
                );
                last_error = Some(detail.clone());
                targets.push(TargetCommandRecord {
                    target_command_id: new_secret_token("tcmd").unwrap_or_default(),
                    command_id: command.command_id.clone(),
                    target_id,
                    gateway_id,
                    wire_kind: wire_kind.to_string(),
                    state: TARGET_STATE_FAILED.to_string(),
                    attempts: 0,
                    result_status: None,
                    result_error: Some(detail),
                    result_body: None,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                });
                continue;
            }
        }
        match proxy
            .enqueue_control_with_body(&gateway_id, wire_kind, wire_body.as_deref())
            .await
        {
            Ok((target_command_id, _reused)) => targets.push(TargetCommandRecord {
                target_command_id,
                command_id: command.command_id.clone(),
                target_id,
                gateway_id,
                wire_kind: wire_kind.to_string(),
                state: TARGET_STATE_QUEUED.to_string(),
                attempts: 0,
                result_status: None,
                result_error: None,
                result_body: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            }),
            Err(err) => {
                let detail = err.to_string();
                last_error = Some(detail.clone());
                targets.push(TargetCommandRecord {
                    target_command_id: new_secret_token("tcmd").unwrap_or_default(),
                    command_id: command.command_id.clone(),
                    target_id,
                    gateway_id,
                    wire_kind: wire_kind.to_string(),
                    state: TARGET_STATE_FAILED.to_string(),
                    attempts: 0,
                    result_status: None,
                    result_error: Some(detail),
                    result_body: None,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                });
            }
        }
    }

    if let Err(err) = state.store.insert_target_commands(&targets).await {
        return Err(store_error("failed to persist targets", err));
    }

    let mut updated = command.clone();
    updated.state = aggregate_state(&targets);
    updated.dispatched_at = Some(now);
    updated.dispatched_by = Some(ADMIN_ACTOR.to_string());
    updated.last_error = last_error;
    if let Err(err) = state.store.save_command(&updated).await {
        return Err(store_error("failed to save command", err));
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnose_has_no_payload_and_maps_to_diagnose() {
        assert_eq!(
            wire_for("gateway.diagnose", &json!({})),
            Some(("diagnose", None))
        );
        assert_eq!(
            wire_for("gateway.diagnose", &Value::Null),
            Some(("diagnose", None))
        );
    }

    #[test]
    fn report_agents_requires_gwlinkd_0_21() {
        assert_eq!(gwlinkd_supports_report_agents(None), None, "未上报版本");
        assert_eq!(gwlinkd_supports_report_agents(Some("")), None);
        assert_eq!(gwlinkd_supports_report_agents(Some("dev")), None);
        assert_eq!(gwlinkd_supports_report_agents(Some("0.20.1")), Some(false));
        assert_eq!(gwlinkd_supports_report_agents(Some("0.21.0")), Some(true));
        // 两段版本要按等价处理（不能当成比 0.21.0 更旧）。
        assert_eq!(gwlinkd_supports_report_agents(Some("0.21")), Some(true));
        // 包内自报 / tag 可能带 `v` 与预发布后缀。
        assert_eq!(
            gwlinkd_supports_report_agents(Some("v0.21.0-alpha")),
            Some(true)
        );
        assert_eq!(gwlinkd_supports_report_agents(Some("0.22.0")), Some(true));
    }

    #[test]
    fn report_agents_has_no_payload_and_maps_to_the_periodic_kernel() {
        assert_eq!(
            wire_for("gateway.report-agents", &json!({})),
            Some((crate::wparse_proxy::KIND_REPORT_AGENTS, None))
        );
        assert_eq!(
            wire_for("gateway.report-agents", &Value::Null),
            Some((crate::wparse_proxy::KIND_REPORT_AGENTS, None))
        );
        // 词表里有它（R0，不需要二次 dispatch）。
        let spec = kind_spec("gateway.report-agents").expect("kind is enabled");
        assert!(!spec.requires_explicit_dispatch);
        assert_eq!(spec.target_type, "gateway");
    }

    #[test]
    fn restart_requires_a_known_process_and_maps_to_control_kinds() {
        assert_eq!(
            wire_for("gateway.restart-process", &json!({ "process": "gateway" })),
            Some(("restart-gateway", None))
        );
        assert_eq!(
            wire_for("gateway.restart-process", &json!({ "process": "gwlinkd" })),
            Some(("restart-gwlinkd", None))
        );
        assert!(wire_for("gateway.restart-process", &json!({ "process": "all" })).is_none());
        assert!(wire_for("gateway.restart-process", &json!({})).is_none());
    }

    #[test]
    fn unknown_kinds_have_no_wire_mapping() {
        assert!(wire_for("gateway.refresh-policy", &json!({})).is_none());
        assert!(wire_for("nope", &json!({})).is_none());
    }

    #[test]
    fn idempotency_key_is_trimmed_and_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert("Idempotency-Key", "  key-1  ".parse().unwrap());
        assert_eq!(idempotency_key(&headers).as_deref(), Some("key-1"));

        let mut empty = HeaderMap::new();
        empty.insert("Idempotency-Key", "   ".parse().unwrap());
        assert!(idempotency_key(&empty).is_none());

        let mut long = HeaderMap::new();
        long.insert(
            "Idempotency-Key",
            "x".repeat(MAX_IDEMPOTENCY_KEY + 1).parse().unwrap(),
        );
        assert!(idempotency_key(&long).is_none());
    }
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::config::{CenterConfig, GatewayCredentialSeed, WparseProxyConfig};
    use crate::infra::{FileStore, LocalArtifactStore, Store, release_job_queue, sha256_hex};

    fn test_state() -> ApiState {
        let store = FileStore::new(std::env::temp_dir().join(format!(
            "wic-command-test-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        )));
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
        let store: std::sync::Arc<dyn Store> = std::sync::Arc::new(store);
        let artifact_store: std::sync::Arc<dyn crate::infra::ArtifactStore> =
            std::sync::Arc::new(LocalArtifactStore::new(
                std::env::temp_dir().join("wic-artifacts"),
                "http://127.0.0.1:3100",
            ));
        let jobs = release_job_queue(store.clone(), artifact_store.clone());
        ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                store_path: std::env::temp_dir().join("unused.json"),
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
            store,
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
            jobs,
            credentials: None,
        }
    }

    async fn send(method: &str, uri: &str, key: Option<&str>, body: &str) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", "Bearer admin-tok")
            .header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("Idempotency-Key", key);
        }
        let request = builder.body(Body::from(body.to_string())).expect("request");
        let response = super::super::router_for(test_state())
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
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    const DIAGNOSE_BODY: &str = r#"{
        "kind": "gateway.diagnose",
        "target": { "type": "gateway", "ids": ["gw-001", "gw-002"] },
        "payload": {},
        "dispatch_now": false
    }"#;

    #[tokio::test]
    async fn idempotency_key_is_required() {
        let (status, body) = send("POST", "/api/v1/admin/commands", None, DIAGNOSE_BODY).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "idempotency_key_required");
    }

    #[tokio::test]
    async fn create_returns_validated_and_replays_the_same_command() {
        let app = super::super::router_for(test_state());
        let make = |key: &'static str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/commands")
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .header("Idempotency-Key", key)
                .body(Body::from(DIAGNOSE_BODY))
                .expect("request")
        };

        let first = app.clone().oneshot(make("key-1")).await.expect("first");
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body: Value =
            serde_json::from_slice(&first.into_body().collect().await.expect("body").to_bytes())
                .expect("json");
        assert_eq!(first_body["state"], "validated");
        assert_eq!(first_body["targets"].as_array().map(Vec::len), Some(0));

        let second = app.oneshot(make("key-1")).await.expect("second");
        assert_eq!(second.status(), StatusCode::OK);
        let second_body: Value =
            serde_json::from_slice(&second.into_body().collect().await.expect("body").to_bytes())
                .expect("json");
        assert_eq!(second_body["command_id"], first_body["command_id"]);
    }

    #[tokio::test]
    async fn same_key_with_a_different_body_conflicts() {
        let app = super::super::router_for(test_state());
        let make = |body: &'static str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/commands")
                .header("authorization", "Bearer admin-tok")
                .header("content-type", "application/json")
                .header("Idempotency-Key", "key-2")
                .body(Body::from(body))
                .expect("request")
        };
        assert_eq!(
            app.clone()
                .oneshot(make(DIAGNOSE_BODY))
                .await
                .expect("first")
                .status(),
            StatusCode::CREATED
        );
        let different = r#"{
            "kind": "gateway.diagnose",
            "target": { "type": "gateway", "ids": ["gw-001"] },
            "payload": {},
            "dispatch_now": false
        }"#;
        let response = app.oneshot(make(different)).await.expect("second");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
        )
        .expect("json");
        assert_eq!(body["error"]["code"], "command_idempotency_conflict");
    }

    #[tokio::test]
    async fn unknown_and_not_enabled_kinds_are_rejected() {
        let unknown = r#"{
            "kind": "gateway.nope",
            "target": { "type": "gateway", "ids": ["gw-001"] },
            "dispatch_now": false
        }"#;
        let (status, body) =
            send("POST", "/api/v1/admin/commands", Some("k-unknown"), unknown).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "command_kind_unknown");

        let not_enabled = r#"{
            "kind": "investigation.run",
            "target": { "type": "agent", "ids": ["agent-1"] },
            "dispatch_now": false
        }"#;
        let (status, body) = send(
            "POST",
            "/api/v1/admin/commands",
            Some("k-not-enabled"),
            not_enabled,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "command_kind_not_allowed");
    }

    #[tokio::test]
    async fn restart_requires_an_explicit_dispatch() {
        let body = r#"{
            "kind": "gateway.restart-process",
            "target": { "type": "gateway", "ids": ["gw-001"] },
            "payload": { "process": "gateway" },
            "dispatch_now": true
        }"#;
        let (status, value) = send("POST", "/api/v1/admin/commands", Some("k-restart"), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"]["code"], "command_kind_not_allowed");
    }

    #[tokio::test]
    async fn dispatch_without_a_queue_is_503() {
        let app = super::super::router_for(test_state());
        let create = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/commands")
            .header("authorization", "Bearer admin-tok")
            .header("content-type", "application/json")
            .header("Idempotency-Key", "k-dispatch")
            .body(Body::from(DIAGNOSE_BODY))
            .expect("request");
        let created = app.clone().oneshot(create).await.expect("create");
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body: Value = serde_json::from_slice(
            &created
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
        )
        .expect("json");
        let command_id = created_body["command_id"].as_str().expect("command_id");

        let dispatch = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/commands/{command_id}/dispatch"))
            .header("authorization", "Bearer admin-tok")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request");
        let response = app.oneshot(dispatch).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
        )
        .expect("json");
        assert_eq!(body["error"]["code"], "command_store_unavailable");
    }

    #[tokio::test]
    async fn cancel_only_accepts_validated_commands() {
        let app = super::super::router_for(test_state());
        let create = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/commands")
            .header("authorization", "Bearer admin-tok")
            .header("content-type", "application/json")
            .header("Idempotency-Key", "k-cancel")
            .body(Body::from(DIAGNOSE_BODY))
            .expect("request");
        let created = app.clone().oneshot(create).await.expect("create");
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body: Value = serde_json::from_slice(
            &created
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
        )
        .expect("json");
        let command_id = created_body["command_id"].as_str().expect("command_id");

        let cancel = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/commands/{command_id}/cancel"))
            .header("authorization", "Bearer admin-tok")
            .body(Body::empty())
            .expect("request");
        let cancelled = app.clone().oneshot(cancel).await.expect("cancel");
        assert_eq!(cancelled.status(), StatusCode::OK);
        let cancelled_body: Value = serde_json::from_slice(
            &cancelled
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
        )
        .expect("json");
        assert_eq!(cancelled_body["state"], "cancelled");

        // 取消后不能再 dispatch。
        let dispatch = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/commands/{command_id}/dispatch"))
            .header("authorization", "Bearer admin-tok")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request");
        let response = app.oneshot(dispatch).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// 只有显式配了 `WARP_INSIGHT_CENTER_DATABASE_URL` 才跑：CI 单测不依赖 PostgreSQL。
    #[tokio::test]
    async fn pg_command_round_trip_when_database_is_available() {
        let Ok(url) = std::env::var("WARP_INSIGHT_CENTER_DATABASE_URL") else {
            return;
        };
        let store = crate::infra::PgStore::connect(&url)
            .await
            .expect("connect pg");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let now = DateTime::now();
        let command = CommandRecord {
            command_id: format!("cmd-pg-{nanos}"),
            request_id: format!("req-pg-{nanos}"),
            kind: "gateway.diagnose".to_string(),
            target_type: "gateway".to_string(),
            target_ids: vec!["gw-001".to_string()],
            payload: json!({}),
            reason: None,
            requested_by: None,
            state: COMMAND_STATE_VALIDATED.to_string(),
            created_by: "admin".to_string(),
            created_at: now.clone(),
            dispatched_at: None,
            dispatched_by: None,
            expires_at: None,
            cancelled_at: None,
            last_error: None,
        };
        store.insert_command(&command, &[]).await.expect("insert");
        let loaded = store
            .get_command(&command.command_id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(loaded.request_id, command.request_id);
        let by_request = store
            .find_command_by_request_id(&command.request_id)
            .await
            .expect("by request")
            .expect("present");
        assert_eq!(by_request.command_id, command.command_id);
        // 同 request_id 再插一次 → Conflict。
        assert!(store.insert_command(&command, &[]).await.is_err());

        // list / save 也过一遍（SQL 里的 `$1::text IS NULL OR ...` 与 UPDATE 路径）。
        let listed = store
            .list_commands(Some(COMMAND_STATE_VALIDATED), None, 50)
            .await
            .expect("list by state");
        assert!(
            listed
                .iter()
                .any(|item| item.command_id == command.command_id)
        );
        let mut updated = loaded.clone();
        updated.state = "queued".to_string();
        store.save_command(&updated).await.expect("save command");
        assert_eq!(
            store
                .get_command(&command.command_id)
                .await
                .expect("get after save")
                .expect("present")
                .state,
            "queued"
        );

        let target = TargetCommandRecord {
            target_command_id: format!("tcmd-pg-{nanos}"),
            command_id: command.command_id.clone(),
            target_id: "gw-001".to_string(),
            gateway_id: "gw-001".to_string(),
            wire_kind: "diagnose".to_string(),
            state: TARGET_STATE_QUEUED.to_string(),
            attempts: 0,
            result_status: None,
            result_error: None,
            result_body: None,
            created_at: now.clone(),
            updated_at: now,
        };
        store
            .insert_target_commands(std::slice::from_ref(&target))
            .await
            .expect("insert target");
        let targets = store
            .list_target_commands(&command.command_id)
            .await
            .expect("list targets");
        assert_eq!(targets.len(), 1);
        assert_eq!(
            store
                .get_target_command(&target.target_command_id)
                .await
                .expect("get target")
                .expect("present")
                .target_id,
            "gw-001"
        );
        let mut saved = target.clone();
        saved.state = "succeeded".to_string();
        store
            .save_target_command(&saved)
            .await
            .expect("save target");
        assert_eq!(
            store
                .get_target_command(&target.target_command_id)
                .await
                .expect("get saved target")
                .expect("present")
                .state,
            "succeeded"
        );
    }

    #[tokio::test]
    async fn old_fleet_dispatch_route_is_gone() {
        let (status, _) = send("POST", "/api/v1/gateway/agents/dispatch", None, "{}").await;
        assert_eq!(status, StatusCode::GONE);
    }
}
