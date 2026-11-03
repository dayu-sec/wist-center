// 管理面鉴权：程序访问凭据（wist-cred 签发）优先，break-glass 口令兜底，外加失败限流。
//
// 两级语义：
//   1. **凭据 token**：`Authorization: Bearer <token>` 与本服务登记的摘要表比对。
//      验通后还要看角色是否命中 `credentials.admin_roles`（默认 `admin`）——`read` 只读角色
//      能通过认证，但进不了管理面。
//   2. **break-glass 口令**：原有的 `admin_token_hash`。保留它只为「cred 不可用 / 轮换期」
//      这类场景；一旦命中就打 `warn`，提醒运维这条路径不该是日常入口。
//
// 两者都没配 = dev 直通（保持旧行为；生产必须配其中之一）。
//
// token 原语（Bearer 提取 / sha256 / 常数时间比较）与限流桶都来自共享 crate `wist-auth`，
// 与 wist-gateway / wist-ingest-ctrl / wist-cred-peer 是同一份实现。

use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use wist_auth::credential::CredentialError;

use super::{ApiState, codes, error::ApiError, rate_limit};

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

    let verifier = state.credentials.as_ref();
    let break_glass_hash = state.config.admin_token_hash.as_ref();

    // dev 模式：两条路都没配时不要求鉴权（旧行为；生产必须配凭据服务或 break-glass 口令）。
    if verifier.is_none() && break_glass_hash.is_none() {
        return Ok(());
    }

    let Some(token) = wist_auth::bearer_token(headers) else {
        // 缺 token 属未认证请求，不计入暴力尝试（否则无 token 的轮询会锁死客户端）。
        log::warn!(
            "event=AdminAuthMissingBearer scope={} client={client_key}",
            ADMIN_AUTH_SCOPE
        );
        return Err(ApiError::unauthorized(
            codes::MISSING_ADMIN_BEARER_TOKEN,
            "missing admin bearer token",
        )
        .with_no_store()
        .into_response());
    };

    // ── 1) 程序访问凭据（wist-cred 签发）─────────────────────────────────────
    // 记下具体失败原因：break-glass 也没命中时，要按原因分开报（续期/排障需要）。
    let mut credential_error: Option<CredentialError> = None;
    if let Some(verifier) = verifier {
        match verifier.peer().verify(token) {
            Ok(credential) => {
                if !state.config.credentials.grants_admin(&credential.roles) {
                    // 认证通过、授权不足：这是 403，不记暴力尝试（token 本身是对的）。
                    log::warn!(
                        "event=AdminAuthForbidden source=credential subject={} credential_id={} roles={:?} required={:?}",
                        credential.subject,
                        credential.credential_id,
                        credential.roles,
                        state.config.credentials.admin_roles,
                    );
                    return Err(ApiError::forbidden(
                        codes::ADMIN_ROLE_REQUIRED,
                        "credential is valid but does not grant admin access",
                    )
                    .with_no_store()
                    .into_response());
                }
                rate_limit::clear_auth_failures(state, client_key, ADMIN_AUTH_SCOPE);
                log::info!(
                    "event=AdminAuthGranted source=credential subject={} credential_id={} roles={:?} client={client_key}",
                    credential.subject,
                    credential.credential_id,
                    credential.roles,
                );
                return Ok(());
            }
            Err(error) => {
                // 不在这里记失败：同一个 token 可能还是 break-glass 口令，交给下面统一判定。
                log::debug!(
                    "credential verification did not match: {} ({})",
                    error.code(),
                    error
                );
                credential_error = Some(error);
            }
        }
    }

    // ── 2) break-glass 管理口令（原有 admin_token_hash）─────────────────────
    if let Some(expected_hash) = break_glass_hash
        && wist_auth::token_matches(token, expected_hash)
    {
        rate_limit::clear_auth_failures(state, client_key, ADMIN_AUTH_SCOPE);
        // 这条路径是应急用的：出现就说明有人在绕过凭据服务，留痕但不要刷屏。
        log::warn!(
            "event=AdminAuthGranted source=break_glass client={client_key} \
             hint=prefer-credential-tokens"
        );
        return Ok(());
    }

    // 两条路都不认：按凭据原因分开报。
    // 过期 / 已撤销是**真实签发过**的凭据：不算暴力尝试，避免客户端轮询被锁死。
    match credential_error {
        Some(CredentialError::Expired) => {
            return Err(ApiError::unauthorized(
                codes::ADMIN_CREDENTIAL_EXPIRED,
                "admin credential expired; request a new one",
            )
            .with_no_store()
            .into_response());
        }
        Some(CredentialError::Revoked) => {
            return Err(ApiError::unauthorized(
                codes::ADMIN_CREDENTIAL_REVOKED,
                "admin credential was revoked",
            )
            .with_no_store()
            .into_response());
        }
        Some(CredentialError::Unknown) => {
            rate_limit::record_auth_failure(state, client_key, ADMIN_AUTH_SCOPE);
            return Err(ApiError::unauthorized(
                codes::ADMIN_CREDENTIAL_UNKNOWN,
                "admin credential is not registered",
            )
            .with_no_store()
            .into_response());
        }
        // 其余（受众不符 / malformed / store）保持笼统，不额外泄露内部原因。
        _ => {}
    }

    // 计入暴力尝试（`record_auth_failure` 会记 `event=AuthFailure` / `event=AuthBlocked`）。
    rate_limit::record_auth_failure(state, client_key, ADMIN_AUTH_SCOPE);
    Err(ApiError::unauthorized(
        codes::INVALID_ADMIN_BEARER_TOKEN,
        "invalid admin bearer token",
    )
    .with_no_store()
    .into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::super::{ApiState, router_for};
    use super::*;
    use crate::config::{CenterConfig, WparseProxyConfig};
    use crate::credentials::CredentialVerifier;
    use crate::infra::{FileStore, LocalArtifactStore, Store, release_job_queue, sha256_hex};

    fn suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wist-center-auth-{tag}-{}", suffix()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// 打开一个空的验证方（无登记凭据）。
    fn empty_peer(tag: &str) -> Arc<wist_cred_peer::Peer> {
        let config =
            wist_cred_peer::Config::new("wist-center", temp_dir(tag).join("credentials.json"))
                .allow_issuer("wist-cred")
                .known_roles(["admin", "read"]);
        wist_cred_peer::Peer::open(config).expect("open peer")
    }

    fn identity() -> wist_pki::PeerIdentity {
        wist_pki::PeerIdentity {
            id: "wist-cred".to_string(),
            uri: None,
            cn: Some("wist-cred".to_string()),
            fingerprint_sha256: "00".repeat(32),
            serial_hex: "01".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
        }
    }

    fn entry(token: &str, subject: &str, roles: &[&str]) -> wist_auth::credential::CredentialEntry {
        let now = chrono::Utc::now().timestamp();
        wist_auth::credential::CredentialEntry {
            credential_id: format!("cred-{subject}"),
            digest: format!("sha256:{}", wist_auth::sha256_hex(token)),
            subject: subject.to_string(),
            roles: roles.iter().map(|role| role.to_string()).collect(),
            resources: Default::default(),
            audience: "wist-center".to_string(),
            issued_at: now,
            expires_at: now + 3600,
            revision: 1,
            revoked_at: None,
            signature: None,
        }
    }

    /// 通过验证方的 `register` 路由登记一条凭据（模拟 cred 推送）。
    async fn register_entry(
        peer: &Arc<wist_cred_peer::Peer>,
        entry: wist_auth::credential::CredentialEntry,
    ) {
        let mut request = Request::builder()
            .method("POST")
            .uri(wist_cred_peer::DEFAULT_BASE_PATH)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&entry).expect("json")))
            .expect("request");
        request.extensions_mut().insert(identity());
        let response = peer.router().oneshot(request).await.expect("register");
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn revoke(peer: &Arc<wist_cred_peer::Peer>, credential_id: &str) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "{}/{credential_id}/revoke",
                wist_cred_peer::DEFAULT_BASE_PATH
            ))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"revision":2}"#))
            .expect("request");
        request.extensions_mut().insert(identity());
        let response = peer.router().oneshot(request).await.expect("revoke");
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn register(
        peer: &Arc<wist_cred_peer::Peer>,
        token: &str,
        subject: &str,
        roles: &[&str],
    ) {
        register_entry(peer, entry(token, subject, roles)).await;
    }

    fn state(
        credentials: Option<Arc<wist_cred_peer::Peer>>,
        admin_token: Option<&str>,
    ) -> ApiState {
        let dir = temp_dir("state");
        let store: Arc<dyn Store> = Arc::new(FileStore::new(dir.join("store.json")));
        let artifact_store: Arc<dyn crate::infra::ArtifactStore> = Arc::new(
            LocalArtifactStore::new(dir.join("artifacts"), "http://127.0.0.1:3100"),
        );
        let jobs = release_job_queue(store.clone(), artifact_store.clone());
        ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                store_path: dir.join("unused.json"),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: admin_token.map(sha256_hex),
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                gateway_project_repo: "https://example.test/gateway.git".to_string(),
                artifact_dir: dir.join("artifacts"),
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
                credentials: Default::default(),
                log: Default::default(),
            },
            store,
            artifact_store,
            gateway_ca: Arc::new(
                crate::infra::gateway_ca::GatewayCa::generate("Wist Test Gateway CA")
                    .expect("gateway ca")
                    .0,
            ),
            proxy: None,
            rate_limits: Arc::new(Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
            jobs,
            credentials: credentials.map(CredentialVerifier::new),
        }
    }

    async fn get_admin(state: ApiState, bearer: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/gateways");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let response = router_for(state)
            .oneshot(builder.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body")
            .to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn credential_with_admin_role_reaches_the_admin_plane() {
        let peer = empty_peer("admin");
        register(&peer, "wcr-admin-token", "ci-deploy", &["admin"]).await;
        let (status, body) = get_admin(state(Some(peer), None), Some("wcr-admin-token")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn credential_with_read_role_is_forbidden() {
        let peer = empty_peer("read");
        register(&peer, "wcr-read-token", "dashboard", &["read"]).await;
        let (status, body) = get_admin(state(Some(peer), None), Some("wcr-read-token")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], codes::ADMIN_ROLE_REQUIRED);
    }

    #[tokio::test]
    async fn unknown_token_is_reported_distinctly() {
        // 配了凭据服务（但这条 token 没登记），又没有 break-glass → 401，不落到 dev 直通。
        let peer = empty_peer("unknown");
        let (status, body) = get_admin(state(Some(peer), None), Some("wcr-nobody")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], codes::ADMIN_CREDENTIAL_UNKNOWN);
    }

    #[tokio::test]
    async fn expired_credential_is_reported_distinctly() {
        let peer = empty_peer("expired");
        let mut expired = entry("wcr-expired", "expired", &["admin"]);
        let now = chrono::Utc::now().timestamp();
        expired.issued_at = now - 7_200;
        expired.expires_at = now - 3_600;
        register_entry(&peer, expired).await;

        let (status, body) = get_admin(state(Some(peer), None), Some("wcr-expired")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], codes::ADMIN_CREDENTIAL_EXPIRED);
    }

    #[tokio::test]
    async fn revoked_credential_is_reported_distinctly() {
        let peer = empty_peer("revoked");
        register(&peer, "wcr-revoked", "revoked", &["admin"]).await;
        revoke(&peer, "cred-revoked").await;

        let (status, body) = get_admin(state(Some(peer), None), Some("wcr-revoked")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], codes::ADMIN_CREDENTIAL_REVOKED);
    }

    #[tokio::test]
    async fn expired_credential_does_not_lock_out_a_valid_client() {
        // 过期是“真实签发过、只是该续期了”，不能计入暴力尝试：
        // 否则客户端轮询 5 次就被封，连新凭据也进不来。
        let peer = empty_peer("no-lockout");
        let mut expired = entry("wcr-expired-poll", "expired-poll", &["admin"]);
        let now = chrono::Utc::now().timestamp();
        expired.issued_at = now - 7_200;
        expired.expires_at = now - 3_600;
        register_entry(&peer, expired).await;
        register(&peer, "wcr-admin-token", "ci-deploy", &["admin"]).await;

        let state = state(Some(peer), None);
        for _ in 0..6 {
            let (status, body) = get_admin(state.clone(), Some("wcr-expired-poll")).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
            assert_eq!(body["error"]["code"], codes::ADMIN_CREDENTIAL_EXPIRED);
        }
        let (status, body) = get_admin(state, Some("wcr-admin-token")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn break_glass_token_still_works_as_fallback() {
        let peer = empty_peer("break-glass");
        let (status, body) = get_admin(
            state(Some(peer), Some("legacy-admin")),
            Some("legacy-admin"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn missing_token_is_unauthorized_when_any_auth_is_configured() {
        let peer = empty_peer("missing");
        let (status, body) = get_admin(state(Some(peer), None), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], codes::MISSING_ADMIN_BEARER_TOKEN);
    }

    #[tokio::test]
    async fn dev_mode_without_any_auth_still_allows() {
        let (status, body) = get_admin(state(None, None), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}
