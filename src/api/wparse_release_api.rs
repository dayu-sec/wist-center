//! 规则 / 配置发布入口（管理面）。
//!
//! 两个入口（`wparse-rules` / `wparse-infra`）都以 **repo 配置** 驱动：
//! - `GET  /api/v1/admin/wparse/repos`：列出入口与可用状态；
//! - `GET  /api/v1/admin/wparse/repos/{name}/tags`：读 tag 候选（CNB / GitHub / manual）；
//! - `POST /api/v1/admin/wparse/repos/{name}/publish`：选中 tag + 目标网关 → **建一份待审批的发布计划**。
//!
//! 审批与 ①②③ 同一套：计划先落 `draft`，到「发布执行」页批准（`rollout-plans/approve`）后
//! 才由中心经 wparse-proxy 入队（[`crate::wparse_proxy::WparseProxy::publish_reload`]），
//! gwlinkd 的 `wparse_relay` 原样执行，不需要任何 gateway / gwlinkd 改动。

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::config::{TagProviderKind, WparseRepoConfig};
use crate::infra::vcs_tags::{self, TagSourceError};

use super::{
    ApiState, PeerConnectInfo, admin_auth, codes,
    error::ApiError,
    extract::{ApiJson, ApiQuery},
    rate_limit,
    wparse_proxy_api::ensure_gateway_exists,
};

/// `GET /api/v1/admin/wparse/repos`。
pub async fn admin_list_wparse_repos(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let config = &state.config.wparse_release;
    let repos: Vec<_> = config
        .repos
        .iter()
        .map(|repo| {
            json!({
                "name": repo.name,
                "group": repo.group,
                "provider": repo.provider.as_str(),
                "repo": repo.repo,
                "tag_source": repo.provider.as_str(),
                "token_configured": repo
                    .token
                    .as_deref()
                    .map(|token| !token.trim().is_empty())
                    .unwrap_or(false),
                "tags_limit": repo.tags_limit,
            })
        })
        .collect();
    Json(json!({
        "enabled": config.enabled,
        // 真正能“发布”还要求 proxy 已启用（PG + [wparse_proxy].enabled）。
        "available": config.enabled && state.proxy.is_some(),
        "allow_manual_tag": config.allow_manual_tag,
        "max_targets": config.max_targets,
        "repos": repos,
    }))
    .into_response()
}

/// `GET /api/v1/admin/wparse/repos/{name}/tags`。
#[derive(Debug, Deserialize)]
pub struct TagsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub refresh: Option<bool>,
}

pub async fn admin_list_wparse_tags(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(name): Path<String>,
    ApiQuery(query): ApiQuery<TagsQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(repo) = find_repo(&state, &name) else {
        return ApiError::not_found(
            codes::WPARSE_REPO_NOT_FOUND,
            format!("unknown wparse release repo {name}"),
        )
        .into_response();
    };
    let requested = query
        .limit
        .unwrap_or(repo.tags_limit)
        .clamp(1, repo.tags_limit.max(1));
    // `list_tags` 内部按配置上限取满并缓存，只按 `requested` 截断本次返回；
    // 因此 `?limit=10` 不会把缓存写短，后续默认请求仍能看到完整候选。
    match vcs_tags::list_tags(
        repo,
        requested,
        query.refresh.unwrap_or(false),
        state.config.wparse_release.tag_cache_seconds,
    )
    .await
    {
        Ok(list) => Json(json!({
            "name": repo.name,
            "group": repo.group,
            "repo": repo.repo,
            "provider": repo.provider.as_str(),
            "source": list.source,
            "stale": list.stale,
            "cached_at": list.cached_at.map(|at| at.to_rfc3339()),
            "tags": list.tags,
        }))
        .into_response(),
        Err(err) => tag_source_error(err).into_response(),
    }
}

/// `POST /api/v1/admin/wparse/repos/{name}/publish`。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    /// 选中的 tag（来自候选列表；服务端仍会再校验一次）。
    pub tag: String,
    pub gateway_ids: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// 默认 `true`：向 repo 校验 tag 存在并记录 commit。`false` 仅在 `allow_manual_tag` 时可用。
    #[serde(default)]
    pub verify_tag: Option<bool>,
}

pub async fn admin_publish_wparse_release(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
    Path(name): Path<String>,
    ApiJson(input): ApiJson<PublishRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let config = &state.config.wparse_release;
    if !config.enabled {
        return ApiError::unavailable(
            codes::WPARSE_RELEASE_DISABLED,
            "wparse release entries are disabled on this center",
        )
        .into_response();
    }
    let Some(repo) = find_repo(&state, &name) else {
        return ApiError::not_found(
            codes::WPARSE_REPO_NOT_FOUND,
            format!("unknown wparse release repo {name}"),
        )
        .into_response();
    };
    if state.proxy.is_none() {
        return ApiError::unavailable(
            codes::WPARSE_PROXY_UNAVAILABLE,
            "wparse proxy is not enabled on this center",
        )
        .into_response();
    }

    let tag = input.tag.trim();
    if !crate::wparse_proxy::valid_release_tag(tag) {
        return ApiError::bad_request(
            codes::WPARSE_TAG_INVALID,
            "tag must match ^[A-Za-z0-9._-]{1,64}$",
        )
        .into_response();
    }
    let targets = match normalize_targets(&input.gateway_ids, config.max_targets) {
        Ok(targets) => targets,
        Err(response) => return response,
    };
    for gateway_id in &targets {
        if let Some(response) = ensure_gateway_exists(&state, gateway_id).await {
            return response;
        }
    }

    // 发布前再校验一次 tag：列表可能过期，手填也可能打错。
    let verify = input.verify_tag.unwrap_or(true);
    let mut commit = None;
    let mut tag_verified = false;
    if verify {
        match vcs_tags::get_tag(repo, tag).await {
            Ok(Some(found)) => {
                commit = found.commit;
                tag_verified = true;
            }
            Ok(None) => {
                if repo.provider != TagProviderKind::Manual {
                    return ApiError::bad_request(
                        codes::WPARSE_TAG_NOT_FOUND,
                        format!(
                            "tag {tag} not found in {} (or the repo/token scope is unavailable)",
                            repo.repo
                        ),
                    )
                    .into_response();
                }
                if !config.allow_manual_tag {
                    return ApiError::bad_request(
                        codes::WPARSE_TAG_VERIFICATION_REQUIRED,
                        "manual tag input is disabled; pick a tag from the list",
                    )
                    .into_response();
                }
            }
            Err(err) => {
                let degradable = matches!(
                    err,
                    TagSourceError::RateLimited { .. } | TagSourceError::Unavailable(_)
                );
                if degradable && config.allow_manual_tag {
                    log::warn!(
                        "event=WparseTagVerifySkipped repo={} tag={} err={}",
                        repo.name,
                        tag,
                        err.message()
                    );
                } else {
                    return tag_source_error(err).into_response();
                }
            }
        }
    } else if !config.allow_manual_tag {
        return ApiError::bad_request(
            codes::WPARSE_TAG_VERIFICATION_REQUIRED,
            "tag verification is required; pick a tag from the list",
        )
        .into_response();
    }

    let reason = input
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("center publish");
    if reason.chars().count() > 200 {
        return ApiError::bad_request(
            codes::INVALID_REQUEST_BODY,
            "reason must be at most 200 characters",
        )
        .into_response();
    }

    // 与 ①②③ 一致：先落一份 **`draft` 发布计划**，到「发布执行」页批准后才真正下发。
    // 单阶段：规则 / 配置重载是幂等的，不需要灰度阶梯；批准即全量入队。
    let plan_request = super::rollout::CreateRolloutPlanRequest {
        action: super::rollout::ACTION_WPARSE_RELEASE.to_string(),
        spec: super::rollout::wparse_release_spec(
            repo.name.as_str(),
            tag,
            commit.as_deref(),
            reason,
        ),
        target_ids: targets.clone(),
        phase_count: 1,
        deadline_at: None,
        timeout_seconds: 0,
        batch_size: 0,
    };
    let record = match super::rollout::build_plan(&plan_request) {
        Ok(record) => record,
        Err(error) => return error.into_response(),
    };
    let plan = match state.store.create_upgrade_plan(&record).await {
        Ok(plan) => plan,
        Err(err) => {
            return ApiError::internal(
                codes::ROLLOUT_CREATE_FAILED,
                "failed to create wparse release plan",
                err.display_chain(),
            )
            .into_response();
        }
    };

    log::info!(
        "event=WparseReleasePlanCreated plan_id={} repo={} group={} tag={} verified={} targets={}",
        plan.plan_id,
        repo.name,
        repo.group,
        tag,
        tag_verified,
        targets.len()
    );

    (
        StatusCode::CREATED,
        Json(json!({
            "plan": super::rollout::plan_view(&plan),
            "repo": repo.name,
            "group": repo.group,
            "tag": tag,
            "commit": commit,
            "tag_verified": tag_verified,
        })),
    )
        .into_response()
}

fn find_repo<'a>(state: &'a ApiState, name: &str) -> Option<&'a WparseRepoConfig> {
    state
        .config
        .wparse_release
        .repos
        .iter()
        .find(|repo| repo.name == name)
}

#[allow(clippy::result_large_err)] // 与全仓一致：错误直接是可响应的 `Response`。
fn normalize_targets(raw: &[String], max_targets: usize) -> Result<Vec<String>, Response> {
    let mut targets = Vec::new();
    for gateway_id in raw {
        let gateway_id = gateway_id.trim();
        if gateway_id.is_empty() {
            continue;
        }
        if !targets.iter().any(|item| item == gateway_id) {
            targets.push(gateway_id.to_string());
        }
    }
    if targets.is_empty() {
        return Err(ApiError::bad_request(
            codes::WPARSE_RELEASE_TARGETS_INVALID,
            "gateway_ids must name at least one gateway",
        )
        .into_response());
    }
    if targets.len() > max_targets {
        return Err(ApiError::bad_request(
            codes::WPARSE_RELEASE_TARGETS_INVALID,
            format!("too many targets: {} (max {max_targets})", targets.len()),
        )
        .into_response());
    }
    Ok(targets)
}

fn tag_source_error(err: TagSourceError) -> Response {
    // 错误码只有一个来源（[`TagSourceError::code`]），避免这里再维护一份字符串。
    let code = err.code();
    let message = err.message().to_string();
    match err {
        TagSourceError::Unauthorized(_) => ApiError::bad_gateway(code, message).into_response(),
        TagSourceError::NotFound(_) => ApiError::not_found(code, message).into_response(),
        TagSourceError::RateLimited { retry_after, .. } => {
            let mut error = ApiError::new(StatusCode::TOO_MANY_REQUESTS, code, message);
            if let Some(seconds) = retry_after
                && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
            {
                error = error.with_header(header::RETRY_AFTER, value);
            }
            error.into_response()
        }
        TagSourceError::Unavailable(_) => ApiError::bad_gateway(code, message).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_dedupes_targets() {
        let targets = normalize_targets(&[" X4 ".into(), "X4".into(), "".into(), "X5".into()], 10)
            .expect("targets");
        assert_eq!(targets, vec!["X4", "X5"]);
    }

    #[test]
    fn rejects_empty_targets() {
        assert!(normalize_targets(&[], 10).is_err());
        assert!(normalize_targets(&["".into()], 10).is_err());
    }

    #[test]
    fn rejects_too_many_targets() {
        assert!(normalize_targets(&["a".into(), "b".into()], 1).is_err());
    }

    #[test]
    fn tag_source_error_codes_match_contract() {
        use crate::infra::vcs_tags::TagSourceError;
        assert_eq!(
            TagSourceError::Unauthorized(String::new()).code(),
            codes::WPARSE_TAG_SOURCE_UNAUTHORIZED
        );
        assert_eq!(
            TagSourceError::NotFound(String::new()).code(),
            codes::WPARSE_REPO_NOT_FOUND
        );
        assert_eq!(
            TagSourceError::RateLimited {
                message: String::new(),
                retry_after: None,
            }
            .code(),
            codes::WPARSE_TAG_SOURCE_RATE_LIMITED
        );
        assert_eq!(
            TagSourceError::Unavailable(String::new()).code(),
            codes::WPARSE_TAG_SOURCE_UNAVAILABLE
        );
    }

    #[test]
    fn tag_shape_matches_proxy_contract() {
        assert!(crate::wparse_proxy::valid_release_tag("v1.2.3-alpha"));
        assert!(crate::wparse_proxy::valid_release_tag("1.2.3"));
        assert!(!crate::wparse_proxy::valid_release_tag(""));
        assert!(!crate::wparse_proxy::valid_release_tag("../etc"));
        assert!(!crate::wparse_proxy::valid_release_tag(&"a".repeat(65)));
    }
}
