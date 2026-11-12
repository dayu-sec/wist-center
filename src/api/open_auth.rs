//! 开放面鉴权：`Authorization: Bearer wcr_…` + 角色 `investigation:run` + 对象级授权。
//!
//! 与 `admin_auth.rs` 的差别：
//!
//! | | 管理面 | 开放面 |
//! |---|---|---|
//! | 身份来源 | cred 凭据 **或** break-glass 口令 | **只有** cred 凭据 |
//! | 角色 | `credentials.admin_roles`（默认 `admin`） | 固定 `investigation:run` |
//! | 授权粒度 | 无（管理员看全量） | `resources.agents` / `resources.gateways` |
//!
//! **空集合 = 无权限**，不是「全量」：开放面绝不能因为漏配 `resources` 就变成全机队可见。

use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use wist_auth::credential::{CredentialError, VerifiedCredential};

use super::{ApiState, codes, error::ApiError, rate_limit};

const OPEN_AUTH_SCOPE: &str = "open";
/// 开放面唯一需要的角色（与 `wist-cred` 的示例口径一致）。
const INVESTIGATION_ROLE: &str = "investigation:run";

/// 认证 + 角色闸。返回的凭据供调用方再做对象级授权（[`allows_agent`]）。
// 与 `admin_auth` 同口径：`Err` 直接就是可返回的 axum 响应。
#[allow(clippy::result_large_err)]
pub(super) fn require_investigation_credential(
    state: &ApiState,
    headers: &HeaderMap,
    client_key: &str,
) -> Result<VerifiedCredential, Response> {
    if let Some(response) = rate_limit::check_rate_limit(state, client_key, OPEN_AUTH_SCOPE) {
        return Err(response);
    }

    let Some(verifier) = state.credentials.as_ref() else {
        // 配置层要求「配了 open_addr 就必须开 credentials」，这里是兜底：
        // 宁可明确报 503，也不要让所有请求都伪装成「token 不对」。
        return Err(ApiError::unavailable(
            codes::OPEN_API_DISABLED,
            "open API has no credential verifier configured",
        )
        .into_response());
    };

    let Some(token) = wist_auth::bearer_token(headers) else {
        // 缺 token 不算暴力尝试：否则无 token 的轮询会把客户端锁死。
        log::warn!("event=OpenAuthMissingBearer client={client_key}");
        return Err(ApiError::unauthorized(
            codes::MISSING_OPEN_BEARER_TOKEN,
            "missing bearer token",
        )
        .with_no_store()
        .into_response());
    };

    let credential = match verifier.peer().verify(token) {
        Ok(credential) => credential,
        Err(error) => {
            // 过期 / 已撤销是真实签发过的凭据：不计入暴力尝试（客户端会按 TTL 续期）。
            // 其它原因（不认识 / 受众不符 / 被改过）都计入 —— 开放面是公网入口。
            if !matches!(error, CredentialError::Expired | CredentialError::Revoked) {
                rate_limit::record_auth_failure(state, client_key, OPEN_AUTH_SCOPE);
            }
            log::warn!(
                "event=OpenAuthRejected reason={} client={client_key}",
                error.code()
            );
            return Err(ApiError::unauthorized(
                codes::INVALID_OPEN_BEARER_TOKEN,
                format!("invalid bearer token ({})", error.code()),
            )
            .with_no_store()
            .into_response());
        }
    };

    if !credential
        .roles
        .iter()
        .any(|role| role == INVESTIGATION_ROLE)
    {
        log::warn!(
            "event=OpenAuthForbidden subject={} credential_id={} roles={:?} required={INVESTIGATION_ROLE}",
            credential.subject,
            credential.credential_id,
            credential.roles,
        );
        return Err(ApiError::forbidden(
            codes::INVESTIGATION_ROLE_REQUIRED,
            format!("credential must carry the `{INVESTIGATION_ROLE}` role"),
        )
        .with_no_store()
        .into_response());
    }

    rate_limit::clear_auth_failures(state, client_key, OPEN_AUTH_SCOPE);
    Ok(credential)
}

/// 对象级授权：凭据的 `resources` 是否覆盖这台 Agent。
///
/// `resources.agents` 或 `resources.gateways` 任一命中即放行；**两者都没有 = 拒绝**。
/// 不把「空集合」解释成「全量」——开放面没有管理员那种「看全机队」的身份。
pub(super) fn allows_agent(
    credential: &VerifiedCredential,
    agent_id: &str,
    gateway_id: &str,
) -> bool {
    let listed = |kind: &str| -> &[String] {
        credential
            .resources
            .get(kind)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    };
    listed("agents").iter().any(|value| value == agent_id)
        || listed("gateways").iter().any(|value| value == gateway_id)
}
