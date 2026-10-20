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
        body: input.body.unwrap_or_default(),
        error: input.error,
        task_id: input.task_id,
        log_dir: input.log_dir,
        log_excerpt: crate::api::bounded_log_excerpt(input.log_excerpt),
    };
    match proxy.complete_command(&command_id, result).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
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
    match state.store.get_gateway(&gateway_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return ApiError::not_found(codes::GATEWAY_NOT_FOUND, "gateway not found")
                .into_response();
        }
        Err(err) => {
            return ApiError::internal_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway",
                err.display_chain(),
            )
            .into_response();
        }
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
