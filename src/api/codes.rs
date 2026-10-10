//! 错误码的**稳定词表**（`{ "error": { "code": … } }` 里的 `code` 的唯一来源）。
//!
//! `code` 是对外契约（网关 / gwlinkd / 管理前端按它分支），因此**重命名 / 删除属破坏性变更**，
//! 需同步消费方；新增则向后兼容。命名 `snake_case`，按域加前缀（`gateway_` / `rollout_` /
//! `release_` / `install_` …）。
//!
//! 相关：`wist_shared::protocol` 的 `ProtocolErrorEnvelope` 是承载它跨进程的 wire 类型。

// 用宏声明：常量与测试用的 `ALL` 出自同一份清单，不会漂移。
macro_rules! codes {
    ($($name:ident => $value:literal),* $(,)?) => {
        $(pub const $name: &str = $value;)*

        /// 词表全部取值（仅测试用；供唯一性 / 命名校验）。
        #[cfg(test)]
        pub(crate) const ALL: &[&str] = &[$($value),*];
    };
}

codes! {
    AGENT_STATUS_UPDATE_FAILED => "agent_status_update_failed",
    ARTIFACT_FETCH_FAILED => "artifact_fetch_failed",
    ARTIFACT_FIELDS_REQUIRED => "artifact_fields_required",
    ARTIFACT_INVALID => "artifact_invalid",
    ARTIFACT_NOT_FOUND => "artifact_not_found",
    ARTIFACT_STORE_FAILED => "artifact_store_failed",
    ARTIFACT_URL_AND_SHA256_REQUIRED => "artifact_url_and_sha256_required",
    ARTIFACTS_REQUIRED => "artifacts_required",
    ARTIFACTS_VERSION_MISMATCH => "artifacts_version_mismatch",
    CERTIFICATE_EXPIRED => "certificate_expired",
    CERTIFICATE_MISMATCH => "certificate_mismatch",
    CERTIFICATE_NOT_ACTIVE => "certificate_not_active",
    CERTIFICATE_NOT_REGISTERED => "certificate_not_registered",
    CERTIFICATE_REQUIRED => "certificate_required",
    CLIENT_CERTIFICATE_PERSIST_FAILED => "client_certificate_persist_failed",
    CREDENTIAL_ID_GENERATION_FAILED => "credential_id_generation_failed",
    ENROLLMENT_TOKEN_CONSUME_FAILED => "enrollment_token_consume_failed",
    ENROLLMENT_TOKEN_REJECTED => "enrollment_token_rejected",
    ENROLLMENT_TOKEN_UNKNOWN_GATEWAY => "enrollment_token_unknown_gateway",
    GATEWAY_AGENTS_LOAD_FAILED => "gateway_agents_load_failed",
    GATEWAY_ALREADY_EXISTS => "gateway_already_exists",
    GATEWAY_ARCHIVE_FAILED => "gateway_archive_failed",
    GATEWAY_BIND_FAILED => "gateway_bind_failed",
    GATEWAY_CREATE_FAILED => "gateway_create_failed",
    GATEWAY_CREDENTIAL_STORE_UNAVAILABLE => "gateway_credential_store_unavailable",
    GATEWAY_ID_AND_REQUESTED_BY_REQUIRED => "gateway_id_and_requested_by_required",
    GATEWAY_ID_CUSTOMER_ID_REQUESTED_BY_REQUIRED => "gateway_id_customer_id_requested_by_required",
    GATEWAY_ID_REQUIRED => "gateway_id_required",
    GATEWAY_INSTANCES_LOAD_FAILED => "gateway_instances_load_failed",
    GATEWAY_LIFECYCLE_LOAD_FAILED => "gateway_lifecycle_load_failed",
    GATEWAY_LIST_FAILED => "gateway_list_failed",
    GATEWAY_LOAD_FAILED => "gateway_load_failed",
    GATEWAY_NAME_AND_REQUESTED_BY_REQUIRED => "gateway_name_and_requested_by_required",
    GATEWAY_NOT_FOUND => "gateway_not_found",
    GATEWAY_NOT_REPORTED => "gateway_not_reported",
    GATEWAY_ONLINE_CANNOT_ARCHIVE => "gateway_online_cannot_archive",
    GATEWAY_STATUS_UPDATE_FAILED => "gateway_status_update_failed",
    GATEWAY_STORE_UNAVAILABLE => "gateway_store_unavailable",
    INSTALL_SCRIPT_UNAVAILABLE => "install_script_unavailable",
    INSTALL_TOKEN_EXPIRED => "install_token_expired",
    INVALID_ACTION => "invalid_action",
    INVALID_ADMIN_BEARER_TOKEN => "invalid_admin_bearer_token",
    INVALID_COMPONENT => "invalid_component",
    INVALID_CSR => "invalid_csr",
    INVALID_DEADLINE => "invalid_deadline",
    INVALID_INSTALL_TOKEN => "invalid_install_token",
    INVALID_LINK_TOKEN => "invalid_link_token",
    INVALID_RELEASE_STATUS => "invalid_release_status",
    INVALID_ROLLOUT_PLAN => "invalid_rollout_plan",
    INVALID_PHASE_PLAN => "invalid_phase_plan",
    INVALID_QUERY => "invalid_query",
    INVALID_REQUEST_BODY => "invalid_request_body",
    INVALID_SPEC => "invalid_spec",
    INVALID_TIMEOUT => "invalid_timeout",
    INVALID_VERSION => "invalid_version",
    INVALID_WINDOW => "invalid_window",
    LINK_TOKEN_CONSUMED => "link_token_consumed",
    LINK_TOKEN_CONSUME_FAILED => "link_token_consume_failed",
    LINK_TOKEN_GENERATION_FAILED => "link_token_generation_failed",
    MISSING_ADMIN_BEARER_TOKEN => "missing_admin_bearer_token",
    MISSING_BEARER_CREDENTIAL => "missing_bearer_credential",
    MISSING_GATEWAY_IDENTITY_TOKEN => "missing_gateway_identity_token",
    MISSING_INSTALL_TOKEN => "missing_install_token",
    METHOD_NOT_ALLOWED => "method_not_allowed",
    NO_FAILED_TARGETS => "no_failed_targets",
    PLAN_NO_PHASE => "plan_no_phase",
    PLAN_NOT_ADVANCABLE => "plan_not_advancable",
    PLAN_NOT_APPROVABLE => "plan_not_approvable",
    PLAN_NOT_RETRYABLE => "plan_not_retryable",
    PLATFORM_UNDERIVABLE => "platform_underivable",
    RATE_LIMITED => "rate_limited",
    REGIST_TOKEN_ISSUE_FAILED => "regist_token_issue_failed",
    RELEASE_LIST_FAILED => "release_list_failed",
    RELEASE_NOT_FOUND => "release_not_found",
    RELEASE_NOT_FOUND_AFTER_WRITE => "release_not_found_after_write",
    RELEASE_PUBLISH_FAILED => "release_publish_failed",
    RELEASE_RESOLVE_FAILED => "release_resolve_failed",
    RELEASE_STATUS_UPDATE_FAILED => "release_status_update_failed",
    RELEASE_URL_REQUIRED => "release_url_required",
    REQUESTED_BY_REQUIRED => "requested_by_required",
    ROLLOUT_CREATE_FAILED => "rollout_create_failed",
    ROLLOUT_PLAN_LOAD_FAILED => "rollout_plan_load_failed",
    ROLLOUT_PLAN_NOT_FOUND => "rollout_plan_not_found",
    ROLLOUT_PLAN_STORE_FAILED => "rollout_plan_store_failed",
    ROLLOUT_PLANS_LOAD_FAILED => "rollout_plans_load_failed",
    ROLLOUT_RETRY_CREATE_FAILED => "rollout_retry_create_failed",
    ROUTE_NOT_FOUND => "route_not_found",
    SETUP_TOKEN_ROTATE_FAILED => "setup_token_rotate_failed",
    TLS_TRUST_ROOT_MISSING => "tls_trust_root_missing",
    UNKNOWN_GATEWAY => "unknown_gateway",
    UNKNOWN_TARGETS => "unknown_targets",
    UPGRADE_PLAN_LOAD_FAILED => "upgrade_plan_load_failed",
    VERSION_MISMATCH => "version_mismatch",
    VERSION_UNDERIVABLE => "version_underivable",
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 契约关键码：钉住取值（消费方按它分支）。
    #[test]
    fn contract_critical_codes_are_stable() {
        assert_eq!(GATEWAY_NOT_FOUND, "gateway_not_found");
        assert_eq!(GATEWAY_ALREADY_EXISTS, "gateway_already_exists");
        assert_eq!(RELEASE_NOT_FOUND, "release_not_found");
        assert_eq!(INVALID_LINK_TOKEN, "invalid_link_token");
        assert_eq!(GATEWAY_STORE_UNAVAILABLE, "gateway_store_unavailable");
        assert_eq!(INSTALL_SCRIPT_UNAVAILABLE, "install_script_unavailable");
    }

    /// 词表自身：全是非空 `snake_case` 且取值互不重复。
    #[test]
    fn every_code_is_nonempty_snake_case_and_unique() {
        assert!(!ALL.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for code in ALL {
            assert!(!code.is_empty(), "empty code");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "not snake_case: {code}"
            );
            assert!(!code.starts_with('_') && !code.ends_with('_'), "{code}");
            assert!(seen.insert(*code), "duplicate code value: {code}");
        }
    }
}
