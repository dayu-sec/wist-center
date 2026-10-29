// 管理面鉴权：Admin Token（Bearer，sha256 常数时间比较）+ 鉴权失败限流。
//
// token 原语（Bearer 提取 / sha256 / 常数时间比较）与限流桶都来自共享 crate `wist-auth`，
// 与 wist-gateway / wist-ingest-ctrl 是同一份实现；这里只保留本服务的"允许空 token（= 不鉴权）"
// 策略与错误码。

use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{ApiState, rate_limit};

const ADMIN_AUTH_SCOPE: &str = "admin";

// axum `Response` 作为 Err 载荷是刻意设计：调用方直接 `if let Err(response) = ... { return response; }`。
#[allow(clippy::result_large_err)]
pub(super) fn require_admin_bearer(
    state: &ApiState,
    headers: &HeaderMap,
    client_key: &str,
) -> Result<(), Response> {
    if let Some(response) = rate_limit::check_rate_limit(state, client_key, ADMIN_AUTH_SCOPE) {
        return Err(response);
    }
    let Some(expected_hash) = &state.config.admin_token_hash else {
        // dev 模式：未配置 admin token（`server.admin_token` 为空）时不要求鉴权，
        // 便于前端/联调直接查看真实数据；生产必须配置 token。
        return Ok(());
    };
    let Some(token) = wist_auth::bearer_token(headers) else {
        // 缺 token 属未认证请求，不计入暴力尝试（否则无 token 的轮询会锁死客户端）。
        log::warn!(
            "event=AdminAuthMissingBearer scope={} client={client_key}",
            ADMIN_AUTH_SCOPE
        );
        return Err(super::error::ApiError::unauthorized(
            super::codes::MISSING_ADMIN_BEARER_TOKEN,
            "missing admin bearer token",
        )
        .with_no_store()
        .into_response());
    };
    if !wist_auth::token_matches(token, expected_hash) {
        // 错 token：计入暴力尝试（`record_auth_failure` 会记 `event=AuthFailure` / `event=AuthBlocked`）。
        rate_limit::record_auth_failure(state, client_key, ADMIN_AUTH_SCOPE);
        return Err(super::error::ApiError::unauthorized(
            super::codes::INVALID_ADMIN_BEARER_TOKEN,
            "invalid admin bearer token",
        )
        .with_no_store()
        .into_response());
    }
    rate_limit::clear_auth_failures(state, client_key, ADMIN_AUTH_SCOPE);
    Ok(())
}
