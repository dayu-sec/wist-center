//! 鉴权失败限流：桶的存储与淘汰在共享 crate `wist-auth`；这里只保留 HTTP 形态、日志与 key 约定。
//!
//! 桶 key 取自 peer 地址（`ConnectInfo`），忽略可伪造的 `x-real-ip` / `x-forwarded-for`。
//! 默认阈值与 `wist-auth` 一致：5 次失败 / 60s → 封 60s。

use std::time::Duration;

use axum::{
    extract::{Extension, connect_info::ConnectInfo},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use super::{ApiState, PeerConnectInfo};

/// 与 `wist-auth` 默认封禁时长一致，仅用于日志。
const BLOCK_DURATION: Duration = Duration::from_secs(60);

/// 每作用域、每客户端的失败桶（`Default` = 5 次 / 60s → 封 60s）。
pub type RateLimitState = wist_auth::FailureLimiter<String>;

/// 从 peer 连接信息派生稳定的每客户端桶 key；无连接信息时（如测试）回退到共享桶。
pub fn client_key(client: PeerConnectInfo) -> String {
    client
        .map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn check_rate_limit(state: &ApiState, client_key: &str, scope: &str) -> Option<Response> {
    let key = rate_limit_key(client_key, scope);
    let limits = state.rate_limits.lock().ok()?;
    let retry_after = limits.blocked_for(&key)?;
    log::warn!(
        "event=AuthRateLimited scope={scope} client={client_key} retry_after_secs={retry_after}"
    );
    Some(
        super::error::ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            super::codes::RATE_LIMITED,
            "too many failed authentication attempts",
        )
        .with_header(
            header::RETRY_AFTER,
            axum::http::HeaderValue::from_str(&retry_after.to_string())
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60")),
        )
        .with_no_store()
        .into_response(),
    )
}

pub fn record_auth_failure(state: &ApiState, client_key: &str, scope: &str) {
    let key = rate_limit_key(client_key, scope);
    let Ok(limits) = state.rate_limits.lock() else {
        return;
    };
    let failures = limits.record_failure(&key);
    if limits.blocked_for(&key).is_some() {
        log::warn!(
            "event=AuthBlocked scope={scope} client={client_key} failures={failures} block_secs={}",
            BLOCK_DURATION.as_secs()
        );
    } else {
        log::warn!("event=AuthFailure scope={scope} client={client_key} failures={failures}");
    }
}

pub fn clear_auth_failures(state: &ApiState, client_key: &str, scope: &str) {
    let key = rate_limit_key(client_key, scope);
    let Ok(limits) = state.rate_limits.lock() else {
        return;
    };
    limits.clear(&key);
}

fn rate_limit_key(client_key: &str, scope: &str) -> String {
    format!("{scope}:{client_key}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_per_purpose() {
        assert_eq!(rate_limit_key("1.2.3.4", "admin"), "admin:1.2.3.4");
        assert_ne!(
            rate_limit_key("1.2.3.4", "admin"),
            rate_limit_key("1.2.3.4", "install_all")
        );
    }
}
