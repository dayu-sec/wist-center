//! 规则发布兼容入口：网关命令通道（mTLS）+ proxy token 管理（admin bearer）。
//!
//! 契约见设计文档 §6/§7：
//! - `GET  /api/v1/gateway/commands?gateway_id=…&limit=1`（原子租约）
//! - `POST /api/v1/gateway/commands/{command_id}/result`
//! - `POST /api/v1/admin/gateways/{gateway_id}/wparse-proxy-token`（明文只返回一次）
//! - `DELETE /api/v1/admin/gateways/{gateway_id}/wparse-proxy-token`

use crate::infra::VerifiedGatewayIdentity;
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::wparse_proxy::CommandResult;

use super::{
    ApiState, PeerConnectInfo, codes,
    error::ApiError,
    extract::{ApiJson, ApiQuery},
    gateway_ops, rate_limit,
};

#[derive(Debug, Deserialize)]
pub struct CommandsQuery {
    pub gateway_id: String,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CommandResultBody {
    pub status_code: u16,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// 本次任务 ID；老 gwlinkd 不带。
    #[serde(default)]
    pub task_id: Option<String>,
    /// 任务执行记录目录（网关本机）；老 gwlinkd 不带。
    #[serde(default)]
    pub log_dir: Option<String>,
    /// 任务执行记录摘要（网关侧已脱敏、已截断）；老 gwlinkd 不带。
    #[serde(default)]
    pub log_excerpt: Option<String>,
}

fn proxy_unavailable() -> Response {
    ApiError::unavailable(
        codes::WPARSE_PROXY_UNAVAILABLE,
        "wparse proxy is not enabled on this center",
    )
    .into_response()
}

/// 管理面公共前置：网关必须存在。
///
/// 返回 `Some(response)` = 直接回给调用方（404/500）；`None` = 前置通过。
/// 用 `Option` 而不是 `Result<(), Response>`：后者会让 clippy 报 `result_large_err`。
pub(super) async fn ensure_gateway_exists(state: &ApiState, gateway_id: &str) -> Option<Response> {
    match state.store.get_gateway(gateway_id).await {
        Ok(Some(_)) => None,
        Ok(None) => {
            Some(ApiError::not_found(codes::GATEWAY_NOT_FOUND, "gateway not found").into_response())
        }
        Err(err) => Some(
            ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway",
                err.display_chain(),
            )
            .into_response(),
        ),
    }
}

/// 网关轮询：租一条 pending 命令。没有命令 → `204 No Content`。
pub async fn poll_command(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    ApiQuery(query): ApiQuery<CommandsQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = gateway_ops::authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|extension| &extension.0),
        &query.gateway_id,
        &client_key,
    )
    .await
    {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    // 本期固定 limit=1：命令都是小请求，逐条执行便于回传与定位。
    let _ = query.limit;
    match proxy.lease_command(&query.gateway_id).await {
        Ok(Some(command)) => {
            let body: Option<serde_json::Value> = command
                .body
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok());
            (
                StatusCode::OK,
                Json(json!({
                    "command_id": command.command_id,
                    "kind": command.kind,
                    "method": command.method,
                    "path": command.path,
                    "body": body,
                    "lease_expires_at": command.lease_expires_at.to_rfc3339(),
                })),
            )
                .into_response()
        }
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::COMMAND_STORE_UNAVAILABLE,
            "failed to lease gateway command",
            err,
        )
        .into_response(),
    }
}

/// 网关回传命令结果（状态码 + 上游 body + 错误）。
pub async fn report_command_result(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedGatewayIdentity>>,
    client: PeerConnectInfo,
    Path(command_id): Path<String>,
    ApiJson(input): ApiJson<CommandResultBody>,
) -> Response {
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    let owner = match proxy.command_gateway_id(&command_id).await {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return ApiError::not_found(codes::COMMAND_NOT_FOUND, "command not found")
                .into_response();
        }
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::COMMAND_STORE_UNAVAILABLE,
                "failed to load command",
                err,
            )
            .into_response();
        }
    };
    // 命令归属校验：证书身份必须与命令的 gateway_id 一致。
    let client_key = rate_limit::client_key(client);
    if let Err(response) = gateway_ops::authorize_gateway_certificate(
        &state,
        identity.as_ref().map(|extension| &extension.0),
        &owner,
        &client_key,
    )
    .await
    {
        return response;
    }

    let result = CommandResult {
        status_code: input.status_code,
        body: crate::wparse_proxy::bounded_result_body(input.body.unwrap_or_default()),
        error: input.error,
        task_id: input.task_id,
        log_dir: input.log_dir,
        log_excerpt: crate::api::bounded_log_excerpt(input.log_excerpt),
    };
    // 回填发布计划之前先拿一份快照：`complete_command` 会吃掉 `result`。
    let snapshot = result.clone();
    match proxy.complete_command(&command_id, result).await {
        Ok(true) => {
            // 规则 / 配置发布：命令是计划批准时由中心入队的，这里把结果回填到那份计划的条目。
            // 只认 `wparse-release` 计划，不影响网关自己执行的三种动作。
            let outcome = if snapshot.error.is_some() {
                "failed"
            } else {
                "done"
            };
            let detail = snapshot
                .error
                .clone()
                .or_else(|| crate::api::bounded_log_excerpt(Some(snapshot.body.clone())))
                .unwrap_or_default();
            if let Err(err) = crate::api::rollout::reconcile_wparse_result(
                &state,
                &owner,
                outcome,
                &detail,
                Some(&command_id),
                snapshot.log_dir.as_deref(),
                snapshot.log_excerpt.as_deref(),
            )
            .await
            {
                // 回填失败不该把「命令已经完成」这件事退回去：网关侧确实做完了。
                log::warn!("event=WparsePlanReconcileFailed command_id={command_id} err={err}");
            }
            // `bind-tenant` 失败（写 `.env` / 重启 wparse）→ 把原因写回绑定记录。
            // 网关只在**已生效**时上报 `binding_revision`，不在这里回写的话，「失败」在管理面不可见。
            if let Some(error) = snapshot.error.as_deref()
                && let Ok(Some((kind, body))) = proxy.command_meta(&command_id).await
                && kind == crate::wparse_proxy::KIND_BIND_TENANT
            {
                let revision = body
                    .as_deref()
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
                    .and_then(|body| body.get("revision").and_then(|value| value.as_i64()));
                if let Some(revision) = revision
                    && let Err(err) = state
                        .store
                        .mark_binding_failed(&owner, revision, error)
                        .await
                {
                    log::warn!(
                        "event=GatewayBindingFailedMarkFailed gateway_id={owner} err={}",
                        err.display_chain()
                    );
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => ApiError::conflict(
            codes::COMMAND_NOT_FOUND,
            "command is not leased (already completed or expired)",
        )
        .into_response(),
        Err(err) => ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::COMMAND_STORE_UNAVAILABLE,
            "failed to store command result",
            err,
        )
        .into_response(),
    }
}

/// 管理面：让某网关跑一次体检（`gops run diagnose --json`）。
///
/// 走同一条命令队列：gwlinkd 短轮询取走、在本机执行、把报告作为 body 回执。
/// 返回 202 + `command_id`；页面用 `GET .../diagnose` 取最近一次报告。
/// 幂等：该网关已有在飞的体检命令时直接复用，不会重复跑。
pub async fn admin_run_diagnose(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = ensure_gateway_exists(&state, &gateway_id).await {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    match proxy
        .enqueue_control(&gateway_id, crate::wparse_proxy::KIND_DIAGNOSE)
        .await
    {
        Ok((command_id, reused)) => {
            log::info!(
                "event=GatewayDiagnoseEnqueued gateway_id={} command_id={} reused={}",
                gateway_id,
                command_id,
                reused
            );
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "gateway_id": gateway_id,
                    "command_id": command_id,
                    "kind": "diagnose",
                    "reused": reused,
                    "state": "pending",
                })),
            )
                .into_response()
        }
        Err(err) => crate::wparse_proxy::enqueue_error(err).into_response(),
    }
}

/// 管理面：最近一次体检（含报告原文）。
///
/// `report` 是 gwlinkd 回传的 `gops run diagnose --json`（已解析）；
/// `state` 是队列状态，区分“没跑”（pending/leased）、“跑了”（done）与“执行失败”（failed/expired）。
pub async fn admin_latest_diagnose(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    match proxy.latest_diagnose(&gateway_id).await {
        Ok(Some(record)) => Json(diagnose_record_json(&gateway_id, &record)).into_response(),
        Ok(None) => {
            ApiError::not_found(codes::COMMAND_NOT_FOUND, "no diagnose report").into_response()
        }
        Err(err) => ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::COMMAND_STORE_UNAVAILABLE,
            "failed to load diagnose report",
            err,
        )
        .into_response(),
    }
}

/// 体检记录的对外形状（纯函数：便于单测，不碰 DB）。
fn diagnose_record_json(
    gateway_id: &str,
    record: &crate::wparse_proxy::DiagnoseRecord,
) -> serde_json::Value {
    json!({
        "gateway_id": gateway_id,
        "command_id": record.command_id,
        "state": record.state,
        "response_status": record.response_status,
        "report": record.report,
        "error": record.error,
        "requested_at": record.requested_at.to_rfc3339(),
        "updated_at": record.updated_at.to_rfc3339(),
    })
}

/// 管理面：下发重启指令（`gateway` 容器 / `gwlinkd` 宿主常驻）。
///
/// 走同一条命令队列：gwlinkd 用 mTLS 短轮询取走并执行，结果写回 `gateway_commands`。
/// **不在这里等结果**（重启会断掉执行者本身）：返回 202 + `command_id`，页面轮询
/// `GET .../commands/{command_id}` 看状态。
#[derive(Debug, Deserialize)]
pub struct RestartRequest {
    /// `gateway` | `gwlinkd`
    pub target: String,
}

/// `target` → 命令 kind（纯函数，便于单测；大小写不敏感）。
fn restart_kind_for(target: &str) -> Option<&'static str> {
    match target.trim().to_ascii_lowercase().as_str() {
        "gateway" => Some(crate::wparse_proxy::KIND_RESTART_GATEWAY),
        "gwlinkd" => Some(crate::wparse_proxy::KIND_RESTART_GWLINKD),
        _ => None,
    }
}

pub async fn admin_restart_gateway(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
    ApiJson(input): ApiJson<RestartRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(kind) = restart_kind_for(&input.target) else {
        return ApiError::bad_request(
            codes::INVALID_REQUEST_BODY,
            format!(
                "unknown target `{}` (expected `gateway` or `gwlinkd`)",
                input.target
            ),
        )
        .into_response();
    };
    if let Some(response) = ensure_gateway_exists(&state, &gateway_id).await {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    match proxy.enqueue_control(&gateway_id, kind).await {
        Ok((command_id, reused)) => {
            log::info!(
                "event=GatewayRestartEnqueued gateway_id={} kind={} command_id={} reused={}",
                gateway_id,
                kind,
                command_id,
                reused
            );
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "gateway_id": gateway_id,
                    "command_id": command_id,
                    "kind": kind,
                    "reused": reused,
                    "state": "pending",
                })),
            )
                .into_response()
        }
        Err(err) => crate::wparse_proxy::enqueue_error(err).into_response(),
    }
}

/// 管理面：查一条控制命令的状态（页面轮询重启结果用）。
pub async fn admin_command_status(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path((gateway_id, command_id)): Path<(String, String)>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    match proxy.control_status(&gateway_id, &command_id).await {
        Ok(Some(status)) => Json(json!({
            "gateway_id": gateway_id,
            "command_id": status.command_id,
            "kind": status.kind,
            "state": status.state,
            "response_status": status.response_status,
            "error": status.error,
            "updated_at": status.updated_at.to_rfc3339(),
        }))
        .into_response(),
        Ok(None) => {
            ApiError::not_found(codes::COMMAND_NOT_FOUND, "command not found").into_response()
        }
        Err(err) => ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::COMMAND_STORE_UNAVAILABLE,
            "failed to load command status",
            err,
        )
        .into_response(),
    }
}

/// 管理面：签发 / 轮换某网关的 proxy token（明文只返回一次）。
pub async fn issue_proxy_token(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = ensure_gateway_exists(&state, &gateway_id).await {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    match proxy.issue_token(&gateway_id).await {
        Ok(token) => (StatusCode::OK, Json(json!({ "token": token }))).into_response(),
        Err(err) => ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::WPARSE_PROXY_TOKEN_ISSUE_FAILED,
            "failed to issue proxy token",
            err,
        )
        .into_response(),
    }
}

/// 管理面：撤销某网关的 proxy token。
pub async fn revoke_proxy_token(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return proxy_unavailable();
    };
    match proxy.revoke_token(&gateway_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            ApiError::not_found(codes::WPARSE_PROXY_TOKEN_NOT_FOUND, "proxy token not found")
                .into_response()
        }
        Err(err) => ApiError::internal_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::COMMAND_STORE_UNAVAILABLE,
            "failed to revoke proxy token",
            err,
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wparse_proxy::DiagnoseRecord;
    use chrono::{TimeZone, Utc};

    fn record(report: Option<serde_json::Value>) -> DiagnoseRecord {
        DiagnoseRecord {
            command_id: "cmd_1".to_string(),
            state: "done".to_string(),
            response_status: Some(1),
            report,
            error: None,
            requested_at: Utc.with_ymd_and_hms(2026, 10, 21, 10, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 10, 21, 10, 0, 5).unwrap(),
        }
    }

    #[test]
    fn restart_targets_map_to_control_kinds() {
        assert_eq!(restart_kind_for("gateway"), Some("restart-gateway"));
        assert_eq!(restart_kind_for(" GWLinkd "), Some("restart-gwlinkd"));
        assert_eq!(restart_kind_for("all"), None, "不支持批量重启");
        assert_eq!(restart_kind_for(""), None);
    }

    #[test]
    fn diagnose_record_json_passes_the_report_through_verbatim() {
        let report = json!({
            "schema_version": "1",
            "summary": {"ok": 1, "warn": 0, "fail": 1, "exit_code": 1},
            "checks": [{"code": "wparse.work_drift", "status": "fail"}]
        });
        let out = diagnose_record_json("gw-1", &record(Some(report.clone())));
        assert_eq!(out["gateway_id"], json!("gw-1"));
        assert_eq!(out["state"], json!("done"));
        assert_eq!(out["response_status"], json!(1));
        assert_eq!(out["report"], report, "报告不能被改写");
        assert_eq!(out["requested_at"], json!("2026-10-21T10:00:00+00:00"));
    }

    #[test]
    fn diagnose_record_json_keeps_a_missing_report_null() {
        // 还在飞 / 执行失败时没有报告：占位 null，前端好判。
        let out = diagnose_record_json("gw-1", &record(None));
        assert!(out["report"].is_null());
    }
}
