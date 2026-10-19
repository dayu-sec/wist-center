//! 规则发布兼容入口（WarpStation **设备面**）与命令队列。
//!
//! WarpStation v0.2.14 的设备客户端写死 `https://{ip}:{port}`，只调两个端点：
//! `GET /admin/v1/runtime/status` 与 `POST /admin/v1/reloads/model`。
//! 但 Gateway 的管理面只发布在宿主回环、且证书由 Gateway CA 签发，中心不应、也不能直连。
//!
//! 因此中心在本 listener 上实现同一组契约：
//!   WarpStation --HTTPS(Bearer proxy token)--> Center wparse-proxy
//!   Center --命令队列--> gwlinkd（mTLS 短轮询）--HTTPS(本机 admin token)--> wparse
//!
//! 设计见 `wist-design/doc/design/center/warpstation-rule-publishing.md` §6/§7。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use tokio::sync::oneshot;

use crate::infra::{new_secret_token, sha256_hex};

const STATUS_PATH: &str = "/admin/v1/runtime/status";
const RELOAD_PATH: &str = "/admin/v1/reloads/model";
const STATUS_WAIT: Duration = Duration::from_secs(5);
const RELOAD_WAIT: Duration = Duration::from_secs(15);
const LEASE_SECONDS: i64 = 30;
const MAX_ATTEMPTS: i32 = 2;
const MAX_BODY_BYTES: usize = 4096;
/// 每个 gateway 的 proxy 请求上限（固定窗口 1 分钟）。
const RATE_LIMIT_PER_MINUTE: u32 = 60;
/// `pending` 超过这个时长仍未被执行 → `expired`（设计 §6.2）。
const PENDING_TTL_SECONDS: i64 = 60;
/// 每 gateway 的 pending + leased 上限（设计 §6.5）。
const MAX_PENDING_PER_GATEWAY: i64 = 32;

/// 入队失败：队列满（429）与存储错误（500）必须区分。
#[derive(Debug)]
pub enum EnqueueError {
    QueueFull,
    Store(String),
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "queue full"),
            Self::Store(err) => write!(f, "{err}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RateWindow {
    started: Instant,
    count: u32,
}

/// 一次上游调用的结果（gwlinkd 回传）。
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub status_code: u16,
    pub body: String,
    pub error: Option<String>,
}

/// 一条已租出的命令（gwlinkd 拉取后执行）。
#[derive(Debug, Clone)]
pub struct LeasedCommand {
    pub command_id: String,
    pub method: String,
    pub path: String,
    pub body: Option<String>,
    pub lease_expires_at: DateTime<Utc>,
}

/// 代理与命令队列的共享状态。
#[derive(Clone)]
pub struct WparseProxy {
    pool: PgPool,
    /// command_id → 等待中的 HTTP 请求。一个命令可能被多个并发请求复用（幂等）。
    waiters: Arc<Mutex<HashMap<String, Vec<oneshot::Sender<CommandResult>>>>>,
    /// gateway_id → 固定窗口计数（设计 §6.5 的按 gateway 限流）。
    rate: Arc<Mutex<HashMap<String, RateWindow>>>,
}

type ProxyResult<T> = Result<T, String>;

impl std::fmt::Debug for WparseProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WparseProxy").finish_non_exhaustive()
    }
}

impl WparseProxy {
    /// 连接 PostgreSQL 并确保队列表存在。
    ///
    /// 中心的主 `PgStore` 也会应用同一份 schema；这里重复一次是幂等的，
    /// 让「单独启用 proxy」的部署（或 schema 应用失败的现场）也能尽快暴露问题。
    pub async fn connect(database_url: &str) -> ProxyResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|err| format!("connect postgres: {err}"))?;
        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .map_err(|err| format!("apply wparse-proxy schema: {err}"))?;
        Ok(Self {
            pool,
            waiters: Arc::new(Mutex::new(HashMap::new())),
            rate: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // ── proxy token（管理面签发 / 撤销） ──

    /// 为网关签发新的 proxy token，返回**明文一次**；旧 token 立即失效。
    pub async fn issue_token(&self, gateway_id: &str) -> ProxyResult<String> {
        let token = new_secret_token("wpx")?;
        let hash = sha256_hex(&token);
        sqlx::query(
            "INSERT INTO gateway_wparse_tokens
                 (gateway_id, token_sha256, created_at, rotated_at, revoked_at)
             VALUES ($1, $2, NOW(), NOW(), NULL)
             ON CONFLICT (gateway_id) DO UPDATE
                 SET token_sha256 = EXCLUDED.token_sha256,
                     rotated_at = NOW(),
                     revoked_at = NULL",
        )
        .bind(gateway_id)
        .bind(hash)
        .execute(&self.pool)
        .await
        .map_err(|err| format!("store proxy token: {err}"))?;
        Ok(token)
    }

    /// 撤销网关的 proxy token。返回是否命中。
    pub async fn revoke_token(&self, gateway_id: &str) -> ProxyResult<bool> {
        let result = sqlx::query(
            "UPDATE gateway_wparse_tokens
                SET revoked_at = NOW()
              WHERE gateway_id = $1 AND revoked_at IS NULL",
        )
        .bind(gateway_id)
        .execute(&self.pool)
        .await
        .map_err(|err| format!("revoke proxy token: {err}"))?;
        Ok(result.rows_affected() > 0)
    }

    /// Bearer → gateway_id。只存 SHA-256，命中即已认证。
    async fn authorize(&self, headers: &HeaderMap) -> Option<String> {
        let token = headers
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")?
            .trim();
        if token.is_empty() {
            return None;
        }
        let hash = sha256_hex(token);
        sqlx::query_scalar::<_, String>(
            "SELECT gateway_id
               FROM gateway_wparse_tokens
              WHERE token_sha256 = $1 AND revoked_at IS NULL",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
    }

    /// 固定窗口限流：`true` = 超限。
    fn rate_limited(&self, gateway_id: &str) -> bool {
        let Ok(mut map) = self.rate.lock() else {
            return false;
        };
        let now = Instant::now();
        let window = map.entry(gateway_id.to_string()).or_insert(RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(window.started) >= Duration::from_secs(60) {
            window.started = now;
            window.count = 0;
        }
        window.count += 1;
        window.count > RATE_LIMIT_PER_MINUTE
    }

    // ── 命令队列（Center ↔ gwlinkd） ──

    /// 原子租出最早的一条 pending 命令；过期的 leased 先回收。
    pub async fn lease_command(&self, gateway_id: &str) -> ProxyResult<Option<LeasedCommand>> {
        // `pending` 超时未执行 → expired（避免网关离线时队列无限堆积）。
        sqlx::query(
            "UPDATE gateway_commands
                SET state = 'expired', error = COALESCE(error, 'pending ttl exceeded'),
                    updated_at = NOW()
              WHERE gateway_id = $1 AND state = 'pending'
                AND created_at < NOW() - make_interval(secs => $2)",
        )
        .bind(gateway_id)
        .bind(PENDING_TTL_SECONDS)
        .execute(&self.pool)
        .await
        .map_err(|err| format!("expire pending commands: {err}"))?;

        // 过期租约：还能重试的退回 pending，超过上限的直接 failed。
        sqlx::query(
            "UPDATE gateway_commands
                SET state = 'pending', lease_expires_at = NULL, updated_at = NOW()
              WHERE gateway_id = $1 AND state = 'leased'
                AND lease_expires_at < NOW() AND attempts < $2",
        )
        .bind(gateway_id)
        .bind(MAX_ATTEMPTS)
        .execute(&self.pool)
        .await
        .map_err(|err| format!("reclaim expired leases: {err}"))?;
        sqlx::query(
            "UPDATE gateway_commands
                SET state = 'failed', error = COALESCE(error, 'lease expired'),
                    updated_at = NOW()
              WHERE gateway_id = $1 AND state = 'leased'
                AND lease_expires_at < NOW() AND attempts >= $2",
        )
        .bind(gateway_id)
        .bind(MAX_ATTEMPTS)
        .execute(&self.pool)
        .await
        .map_err(|err| format!("expire stale leases: {err}"))?;

        let row = sqlx::query(
            "UPDATE gateway_commands
                SET state = 'leased',
                    attempts = attempts + 1,
                    lease_expires_at = NOW() + make_interval(secs => $2),
                    updated_at = NOW()
              WHERE command_id = (
                    SELECT command_id
                      FROM gateway_commands
                     WHERE gateway_id = $1 AND state = 'pending'
                     ORDER BY created_at
                     LIMIT 1
                     FOR UPDATE SKIP LOCKED
              )
          RETURNING command_id, method, path, body, lease_expires_at",
        )
        .bind(gateway_id)
        .bind(LEASE_SECONDS)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| format!("lease command: {err}"))?;

        let Some(row) = row else {
            return Ok(None);
        };
        log::info!(
            "event=WparseCommandLeased gateway_id={} command_id={} method={} path={}",
            gateway_id,
            row.get::<String, _>("command_id"),
            row.get::<String, _>("method"),
            row.get::<String, _>("path"),
        );
        Ok(Some(LeasedCommand {
            command_id: row.get("command_id"),
            method: row.get("method"),
            path: row.get("path"),
            body: row.get("body"),
            lease_expires_at: row.get("lease_expires_at"),
        }))
    }

    /// 命令归属（gwlinkd 回传结果时校验身份）。
    pub async fn command_gateway_id(&self, command_id: &str) -> ProxyResult<Option<String>> {
        sqlx::query_scalar::<_, String>(
            "SELECT gateway_id FROM gateway_commands WHERE command_id = $1",
        )
        .bind(command_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| format!("load command owner: {err}"))
    }

    /// 写回结果并唤醒所有等待该命令的 HTTP 请求。
    pub async fn complete_command(
        &self,
        command_id: &str,
        result: CommandResult,
    ) -> ProxyResult<bool> {
        let state = if result.error.is_some() {
            "failed"
        } else {
            "done"
        };
        let updated = sqlx::query(
            "UPDATE gateway_commands
                SET state = $2,
                    response_status = $3,
                    response_body = $4,
                    error = $5,
                    lease_expires_at = NULL,
                    updated_at = NOW()
              WHERE command_id = $1 AND state = 'leased'",
        )
        .bind(command_id)
        .bind(state)
        .bind(i32::from(result.status_code))
        .bind(&result.body)
        .bind(&result.error)
        .execute(&self.pool)
        .await
        .map_err(|err| format!("complete command: {err}"))?
        .rows_affected()
            > 0;

        if let Some(waiters) = self
            .waiters
            .lock()
            .ok()
            .and_then(|mut map| map.remove(command_id))
        {
            for sender in waiters {
                let _ = sender.send(result.clone());
            }
        }
        log::info!(
            "event=WparseCommandCompleted command_id={} state={} status={} updated={}",
            command_id,
            state,
            result.status_code,
            updated
        );
        Ok(updated)
    }

    // ── 内部：入队 + 等待 ──

    async fn enqueue(
        &self,
        gateway_id: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<String, EnqueueError> {
        let command_id = new_secret_token("cmd").map_err(EnqueueError::Store)?;
        // 单语句完成「计数 + 插入」：计数里包含 pending/leased，超过上限就不插入。
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO gateway_commands
                 (command_id, gateway_id, method, path, body, state, created_at, updated_at)
             SELECT $1, $2, $3, $4, $5, 'pending', NOW(), NOW()
              WHERE (SELECT COUNT(*) FROM gateway_commands
                      WHERE gateway_id = $2 AND state IN ('pending', 'leased')) < $6
             RETURNING command_id",
        )
        .bind(&command_id)
        .bind(gateway_id)
        .bind(method)
        .bind(path)
        .bind(body)
        .bind(MAX_PENDING_PER_GATEWAY)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| EnqueueError::Store(format!("enqueue command: {err}")))?;
        match inserted {
            Some(id) => Ok(id),
            None => Err(EnqueueError::QueueFull),
        }
    }

    /// 幂等：同一 gateway + 同一 `(version, group)` 的 reload 复用 pending/leased 命令。
    async fn reusable_reload(&self, gateway_id: &str, body: &str) -> ProxyResult<Option<String>> {
        sqlx::query_scalar::<_, String>(
            "SELECT command_id
               FROM gateway_commands
              WHERE gateway_id = $1 AND method = 'POST' AND path = $2
                AND body = $3 AND state IN ('pending', 'leased')
              ORDER BY created_at
              LIMIT 1",
        )
        .bind(gateway_id)
        .bind(RELOAD_PATH)
        .bind(body)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| format!("lookup reusable reload: {err}"))
    }

    async fn wait_for(&self, command_id: &str, wait: Duration) -> Option<CommandResult> {
        let (sender, receiver) = oneshot::channel();
        if let Ok(mut map) = self.waiters.lock() {
            map.entry(command_id.to_string()).or_default().push(sender);
        }
        match tokio::time::timeout(wait, receiver).await {
            Ok(Ok(result)) => Some(result),
            // 超时 / 发送端被丢弃：把自己从等待表里摘掉，避免泄漏。
            _ => {
                if let Ok(mut map) = self.waiters.lock()
                    && let Some(waiters) = map.get_mut(command_id)
                {
                    waiters.retain(|sender| !sender.is_closed());
                    if waiters.is_empty() {
                        map.remove(command_id);
                    }
                }
                None
            }
        }
    }
}

/// 供 `main.rs` 起独立 HTTPS listener。
pub fn router(proxy: Arc<WparseProxy>) -> Router {
    Router::new()
        .route(STATUS_PATH, get(handle_status))
        .route(RELOAD_PATH, post(handle_reload))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(proxy)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReloadBody {
    // WarpStation 会带 `wait`；代理自己的等待窗口是固定的，不依赖它。
    #[serde(default)]
    #[allow(dead_code)]
    wait: Option<bool>,
    #[serde(default)]
    update: Option<bool>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
}

async fn handle_status(State(proxy): State<Arc<WparseProxy>>, headers: HeaderMap) -> Response {
    let Some(gateway_id) = proxy.authorize(&headers).await else {
        return proxy_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proxy_token",
            "invalid or revoked proxy token",
        );
    };
    if proxy.rate_limited(&gateway_id) {
        return proxy_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many proxy requests",
        );
    }
    let command_id = match proxy.enqueue(&gateway_id, "GET", STATUS_PATH, None).await {
        Ok(id) => id,
        Err(err) => return enqueue_error(err),
    };
    match proxy.wait_for(&command_id, STATUS_WAIT).await {
        Some(result) => upstream_response(result),
        None => proxy_error(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_timeout",
            "gateway did not answer within 5s",
        ),
    }
}

async fn handle_reload(
    State(proxy): State<Arc<WparseProxy>>,
    headers: HeaderMap,
    Json(input): Json<ReloadBody>,
) -> Response {
    let Some(gateway_id) = proxy.authorize(&headers).await else {
        return proxy_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proxy_token",
            "invalid or revoked proxy token",
        );
    };
    if proxy.rate_limited(&gateway_id) {
        return proxy_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many proxy requests",
        );
    }

    let (version, group) = match validate_reload(&input) {
        Ok(validated) => validated,
        Err((status, code, message)) => return proxy_error(status, code, message),
    };
    // 只把允许的字段转发给 gwlinkd；`wait` 固定 true、超时与代理等待上限对齐。
    let body = json!({
        "wait": true,
        "update": true,
        "version": version,
        "group": group,
        "timeout_ms": input.timeout_ms.unwrap_or(15_000).min(15_000),
        "reason": input.reason.as_deref().unwrap_or("warpstation publish"),
    })
    .to_string();

    let command_id = match proxy.reusable_reload(&gateway_id, &body).await {
        Ok(Some(existing)) => existing,
        Ok(None) => match proxy
            .enqueue(&gateway_id, "POST", RELOAD_PATH, Some(&body))
            .await
        {
            Ok(id) => id,
            Err(err) => return enqueue_error(err),
        },
        Err(err) => return proxy_error(StatusCode::INTERNAL_SERVER_ERROR, "queue_error", &err),
    };

    match proxy.wait_for(&command_id, RELOAD_WAIT).await {
        Some(result) => upstream_response(result),
        None => (
            StatusCode::ACCEPTED,
            Json(json!({
                "accepted": true,
                "request_id": command_id,
                "message": "queued",
            })),
        )
            .into_response(),
    }
}

/// 严格校验 WarpStation 发来的 reload body（字段 / 版本 / group / update）。
fn validate_reload(
    input: &ReloadBody,
) -> Result<(String, &'static str), (StatusCode, &'static str, &'static str)> {
    let group = match input.group.as_deref() {
        Some("models") => "models",
        Some("infra") => "infra",
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid_group",
                "group must be models or infra",
            ));
        }
    };
    if input.update != Some(true) {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_update",
            "update must be true (publishing must pull the tagged revision first)",
        ));
    }
    let version = input.version.as_deref().unwrap_or_default();
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_version",
            "version must match ^[A-Za-z0-9._-]{1,64}$",
        ));
    }
    Ok((version.to_string(), group))
}

/// 原样回传 wparse 的状态码与 JSON body。
fn upstream_response(result: CommandResult) -> Response {
    let status = StatusCode::from_u16(result.status_code).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = if result.body.trim().is_empty() && result.error.is_some() {
        json!({
            "success": false,
            "error": { "code": "upstream_error", "message": result.error }
        })
        .to_string()
    } else {
        result.body
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn enqueue_error(err: EnqueueError) -> Response {
    match err {
        EnqueueError::QueueFull => proxy_error(
            StatusCode::TOO_MANY_REQUESTS,
            "queue_full",
            "too many pending commands for this gateway",
        ),
        EnqueueError::Store(message) => {
            proxy_error(StatusCode::INTERNAL_SERVER_ERROR, "queue_error", &message)
        }
    }
}

fn proxy_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "success": false,
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}

/// 与中心主 schema 保持同一口径（幂等）。
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS gateway_commands (
  command_id TEXT PRIMARY KEY,
  gateway_id TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  body TEXT,
  state TEXT NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  lease_expires_at TIMESTAMPTZ,
  response_status INT,
  response_body TEXT,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gateway_commands_pending
  ON gateway_commands (gateway_id, state, created_at);
CREATE TABLE IF NOT EXISTS gateway_wparse_tokens (
  gateway_id TEXT PRIMARY KEY,
  token_sha256 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rotated_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_gateway_wparse_tokens_hash
  ON gateway_wparse_tokens (token_sha256);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn reload(group: Option<&str>, update: Option<bool>, version: Option<&str>) -> ReloadBody {
        ReloadBody {
            wait: Some(true),
            update,
            version: version.map(str::to_string),
            group: group.map(str::to_string),
            timeout_ms: None,
            reason: None,
        }
    }

    #[test]
    fn validate_reload_accepts_models_and_infra() {
        assert_eq!(
            validate_reload(&reload(Some("models"), Some(true), Some("1.0.1"))).unwrap(),
            ("1.0.1".to_string(), "models")
        );
        assert_eq!(
            validate_reload(&reload(Some("infra"), Some(true), Some("v1.0.1"))).unwrap(),
            ("v1.0.1".to_string(), "infra")
        );
    }

    #[test]
    fn validate_reload_rejects_bad_group() {
        let (status, code, _) =
            validate_reload(&reload(Some("all"), Some(true), Some("1.0.1"))).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_group");
        let (_, code, _) = validate_reload(&reload(None, Some(true), Some("1.0.1"))).unwrap_err();
        assert_eq!(code, "invalid_group");
    }

    #[test]
    fn validate_reload_requires_update_true() {
        let (_, code, _) =
            validate_reload(&reload(Some("models"), Some(false), Some("1.0.1"))).unwrap_err();
        assert_eq!(code, "invalid_update");
        let (_, code, _) =
            validate_reload(&reload(Some("models"), None, Some("1.0.1"))).unwrap_err();
        assert_eq!(code, "invalid_update");
    }

    #[test]
    fn validate_reload_rejects_bad_versions() {
        for version in ["", "1.0.1/../x", "v1.0.1 extra", &"a".repeat(65)] {
            let (_, code, _) =
                validate_reload(&reload(Some("models"), Some(true), Some(version))).unwrap_err();
            assert_eq!(code, "invalid_version", "version={version:?}");
        }
        // `None` 与空串同罪。
        let (_, code, _) = validate_reload(&reload(Some("models"), Some(true), None)).unwrap_err();
        assert_eq!(code, "invalid_version");
    }

    #[test]
    fn reload_body_rejects_unknown_fields() {
        let err = serde_json::from_str::<ReloadBody>(
            r#"{"update":true,"group":"models","version":"1.0.1","extra":1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    // ── PostgreSQL 集成测试（设 `WIST_TEST_DATABASE_URL` 才执行） ──

    async fn test_proxy() -> Option<WparseProxy> {
        let url = std::env::var("WIST_TEST_DATABASE_URL").ok()?;
        Some(
            WparseProxy::connect(&url)
                .await
                .expect("connect test database"),
        )
    }

    async fn cleanup(proxy: &WparseProxy, gateway_id: &str) {
        let _ = sqlx::query("DELETE FROM gateway_commands WHERE gateway_id = $1")
            .bind(gateway_id)
            .execute(&proxy.pool)
            .await;
        let _ = sqlx::query("DELETE FROM gateway_wparse_tokens WHERE gateway_id = $1")
            .bind(gateway_id)
            .execute(&proxy.pool)
            .await;
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    fn test_gateway(prefix: &str) -> String {
        format!("{prefix}-{}", std::process::id())
    }

    #[tokio::test]
    async fn db_token_issue_authorize_and_revoke() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-token");
        cleanup(&proxy, &gateway_id).await;

        let token = proxy.issue_token(&gateway_id).await.expect("issue");
        assert!(token.starts_with("wpx_"));
        assert_eq!(
            proxy.authorize(&bearer(&token)).await.as_deref(),
            Some(gateway_id.as_str())
        );
        // 轮换：旧 token 立即失效。
        let rotated = proxy.issue_token(&gateway_id).await.expect("rotate");
        assert!(proxy.authorize(&bearer(&token)).await.is_none());
        assert_eq!(
            proxy.authorize(&bearer(&rotated)).await.as_deref(),
            Some(gateway_id.as_str())
        );
        // 撤销。
        assert!(proxy.revoke_token(&gateway_id).await.expect("revoke"));
        assert!(proxy.authorize(&bearer(&rotated)).await.is_none());

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn db_command_lease_complete_and_wake_waiter() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-cmd");
        cleanup(&proxy, &gateway_id).await;

        let command_id = proxy
            .enqueue(
                &gateway_id,
                "POST",
                RELOAD_PATH,
                Some(r#"{"group":"models"}"#),
            )
            .await
            .expect("enqueue");

        let leased = proxy
            .lease_command(&gateway_id)
            .await
            .expect("lease")
            .expect("one command");
        assert_eq!(leased.command_id, command_id);
        assert_eq!(leased.method, "POST");
        assert_eq!(leased.path, RELOAD_PATH);
        // 同一批里只有一条，已被租走。
        assert!(
            proxy
                .lease_command(&gateway_id)
                .await
                .expect("lease")
                .is_none()
        );

        let waiter_proxy = proxy.clone();
        let waiter_id = command_id.clone();
        let waiter = tokio::spawn(async move {
            waiter_proxy
                .wait_for(&waiter_id, Duration::from_secs(2))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let result = CommandResult {
            status_code: 200,
            body: r#"{"accepted":true}"#.to_string(),
            error: None,
        };
        assert!(
            proxy
                .complete_command(&command_id, result.clone())
                .await
                .expect("complete")
        );
        let delivered = waiter.await.expect("join").expect("waiter woke");
        assert_eq!(delivered.status_code, 200);
        assert_eq!(delivered.body, result.body);

        // 重复完成：命令已不是 leased，返回 false。
        assert!(
            !proxy
                .complete_command(&command_id, result)
                .await
                .expect("complete twice")
        );

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn db_reload_dedupes_pending_and_leased_commands() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-dedupe");
        cleanup(&proxy, &gateway_id).await;

        let body = r#"{"group":"models","version":"1.0.1"}"#;
        let command_id = proxy
            .enqueue(&gateway_id, "POST", RELOAD_PATH, Some(body))
            .await
            .expect("enqueue");
        assert_eq!(
            proxy
                .reusable_reload(&gateway_id, body)
                .await
                .expect("lookup")
                .as_deref(),
            Some(command_id.as_str())
        );
        proxy.lease_command(&gateway_id).await.expect("lease");
        assert!(
            proxy
                .reusable_reload(&gateway_id, body)
                .await
                .expect("lookup leased")
                .is_some()
        );

        proxy
            .complete_command(
                &command_id,
                CommandResult {
                    status_code: 200,
                    body: "{}".to_string(),
                    error: None,
                },
            )
            .await
            .expect("complete");
        assert!(
            proxy
                .reusable_reload(&gateway_id, body)
                .await
                .expect("lookup done")
                .is_none()
        );

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn db_pending_commands_expire_after_ttl() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-expire");
        cleanup(&proxy, &gateway_id).await;

        let command_id = proxy
            .enqueue(&gateway_id, "GET", STATUS_PATH, None)
            .await
            .expect("enqueue");
        sqlx::query(
            "UPDATE gateway_commands SET created_at = NOW() - INTERVAL '120 seconds'
              WHERE command_id = $1",
        )
        .bind(&command_id)
        .execute(&proxy.pool)
        .await
        .expect("age command");

        assert!(
            proxy
                .lease_command(&gateway_id)
                .await
                .expect("lease")
                .is_none()
        );
        let state: String =
            sqlx::query_scalar("SELECT state FROM gateway_commands WHERE command_id = $1")
                .bind(&command_id)
                .fetch_one(&proxy.pool)
                .await
                .expect("state");
        assert_eq!(state, "expired");

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn db_queue_cap_rejects_the_33rd_command() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-cap");
        cleanup(&proxy, &gateway_id).await;

        for _ in 0..MAX_PENDING_PER_GATEWAY {
            proxy
                .enqueue(&gateway_id, "GET", STATUS_PATH, None)
                .await
                .expect("enqueue under the cap");
        }
        match proxy.enqueue(&gateway_id, "GET", STATUS_PATH, None).await {
            Err(EnqueueError::QueueFull) => {}
            other => panic!("expected QueueFull, got {other:?}"),
        }

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn db_rate_limit_allows_60_and_rejects_the_61st() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-rate");
        for _ in 0..RATE_LIMIT_PER_MINUTE {
            assert!(!proxy.rate_limited(&gateway_id));
        }
        assert!(proxy.rate_limited(&gateway_id));
    }

    // ── HTTP handler 级测试（axum Router + 模拟 gwlinkd） ──

    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    fn app_for(proxy: &WparseProxy) -> Router {
        super::router(Arc::new(proxy.clone()))
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body bytes");
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// 启动一个“假 gwlinkd”：轮询租约并回传固定结果。
    fn spawn_fake_gateway(
        proxy: WparseProxy,
        gateway_id: String,
        result: CommandResult,
        expect: Option<(&'static str, &'static str)>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            for _ in 0..80 {
                if let Some(command) = proxy.lease_command(&gateway_id).await.expect("lease") {
                    if let Some((method, path)) = expect {
                        assert_eq!(command.method, method);
                        assert_eq!(command.path, path);
                    }
                    proxy
                        .complete_command(&command.command_id, result)
                        .await
                        .expect("complete");
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("fake gateway never leased a command");
        })
    }

    #[tokio::test]
    async fn http_status_without_token_returns_401_envelope() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let response = app_for(&proxy)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(STATUS_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(body_text(response).await.contains("invalid_proxy_token"));
    }

    #[tokio::test]
    async fn http_status_is_relayed_through_the_command_queue() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-http-status");
        cleanup(&proxy, &gateway_id).await;
        let token = proxy.issue_token(&gateway_id).await.expect("token");

        let body = r#"{"accepting_commands":true,"version":"0.30.0"}"#;
        let fake = spawn_fake_gateway(
            proxy.clone(),
            gateway_id.clone(),
            CommandResult {
                status_code: 200,
                body: body.to_string(),
                error: None,
            },
            Some(("GET", STATUS_PATH)),
        );

        let response = app_for(&proxy)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(STATUS_PATH)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("accepting_commands"));
        fake.await.expect("fake gateway");

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn http_reload_rejects_invalid_group_before_enqueue() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-http-group");
        cleanup(&proxy, &gateway_id).await;
        let token = proxy.issue_token(&gateway_id).await.expect("token");

        let response = app_for(&proxy)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(RELOAD_PATH)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"update":true,"group":"all","version":"1.0.1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(response).await.contains("invalid_group"));

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn http_reload_rejects_unknown_fields() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-http-unknown");
        cleanup(&proxy, &gateway_id).await;
        let token = proxy.issue_token(&gateway_id).await.expect("token");

        let response = app_for(&proxy)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(RELOAD_PATH)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"update":true,"group":"models","version":"1.0.1","extra":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // axum 的 JSON 拒绝是纯文本 422；这里只钉“客户端错误 + 未被入队”。
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM gateway_commands WHERE gateway_id = $1")
                .bind(&gateway_id)
                .fetch_one(&proxy.pool)
                .await
                .expect("count");
        assert_eq!(pending, 0);

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn http_reload_returns_upstream_result() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-http-reload");
        cleanup(&proxy, &gateway_id).await;
        let token = proxy.issue_token(&gateway_id).await.expect("token");

        let upstream = r#"{"accepted":true,"request_id":"cmd_x","message":"reload_done"}"#;
        let fake = spawn_fake_gateway(
            proxy.clone(),
            gateway_id.clone(),
            CommandResult {
                status_code: 200,
                body: upstream.to_string(),
                error: None,
            },
            Some(("POST", RELOAD_PATH)),
        );

        let response = app_for(&proxy)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(RELOAD_PATH)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"wait":true,"update":true,"group":"models","version":"1.0.1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = body_text(response).await;
        assert!(text.contains("reload_done"), "{text}");
        fake.await.expect("fake gateway");

        cleanup(&proxy, &gateway_id).await;
    }

    #[tokio::test]
    async fn http_reload_returns_429_when_the_queue_is_full() {
        let Some(proxy) = test_proxy().await else {
            return;
        };
        let gateway_id = test_gateway("wpx-http-full");
        cleanup(&proxy, &gateway_id).await;
        let token = proxy.issue_token(&gateway_id).await.expect("token");

        for _ in 0..MAX_PENDING_PER_GATEWAY {
            proxy
                .enqueue(&gateway_id, "GET", STATUS_PATH, None)
                .await
                .expect("fill queue");
        }

        let response = app_for(&proxy)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(RELOAD_PATH)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"update":true,"group":"models","version":"9.9.9"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(body_text(response).await.contains("queue_full"));

        cleanup(&proxy, &gateway_id).await;
    }
}
