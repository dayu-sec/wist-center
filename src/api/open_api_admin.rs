//! 开放面的**自述**：探活 + OpenAPI 3.1 清单。
//!
//! 两个入口：
//!
//! | 入口 | 鉴权 | 用途 |
//! |---|---|---|
//! | `GET /api/v1/open/openapi.json` | 无 | 第三方生成客户端 / 核对参数 |
//! | `GET /api/v1/admin/open-api` | admin token | 控制台「接口可用性」页（探活 + spec） |
//!
//! spec 只有这一份：页面读它，第三方也读它，不维护第二份路径表。

use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::{ApiState, PeerConnectInfo, admin_auth::require_admin_bearer, codes, rate_limit};

/// 开放面唯一需要的角色（与 `open_auth` 同口径）。
const REQUIRED_ROLE: &str = "investigation:run";
/// 单条探活的超时：自我探测必须比任何调用方都短，不能把页面拖住。
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// `GET /api/v1/open/openapi.json`（公开，无需令牌）。
pub async fn open_openapi_document(State(state): State<ApiState>) -> Response {
    Json(openapi_document(state.config.open_public_url.as_deref())).into_response()
}

/// `GET /api/v1/admin/open-api`（admin token）。
///
/// 中心自己**回环**探活开放面（listener + 调查路由），并把 spec 一并返回；
/// 页面据此渲染接口清单与可用性，不依赖浏览器能直连开放面。
pub async fn admin_open_api(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    headers: HeaderMap,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }

    let checked_at_ms = chrono::Utc::now().timestamp_millis();
    let open_addr = state.config.open_addr.clone();
    let enabled = open_addr.is_some();
    let interfaces = match open_addr.as_deref() {
        Some(addr) => probe_open_face(&state, addr, checked_at_ms).await,
        None => Vec::new(),
    };

    Json(json!({
        "enabled": enabled,
        "listen_addr": open_addr,
        "base_url": state.config.open_public_url,
        "credentials_enabled": state.config.credentials.enabled,
        "required_role": REQUIRED_ROLE,
        "checked_at_ms": checked_at_ms,
        "interfaces": interfaces,
        "openapi": openapi_document(state.config.open_public_url.as_deref()),
    }))
    .into_response()
}

/// 两条探活：listener 起没起、调查路由挂没挂（并确认鉴权闸在工作）。
///
/// 探活是**回环**发起的：外部系统可能连不到开放面（防火墙 / NAT），
/// 但中心自己一定连得到本机 listener。
async fn probe_open_face(state: &ApiState, open_addr: &str, checked_at_ms: i64) -> Vec<Value> {
    let scheme =
        if state.config.server_cert_path.is_some() && state.config.server_key_path.is_some() {
            "https"
        } else {
            "http"
        };
    let host_port = loopback_host_port(open_addr);
    let base = format!("{scheme}://{host_port}");

    let client = match reqwest::Client::builder()
        // 回环自签证书：探活不承载业务数据，接受本机自签是刻意的。
        .danger_accept_invalid_certs(true)
        // 本机回环不能走系统代理（`HTTP_PROXY` 会把 127.0.0.1 发出去）。
        .no_proxy()
        .timeout(PROBE_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            log::warn!("open-api probe client failed: {err}");
            return vec![probe_entry(
                &LISTENER_PROBE,
                format!("{base}/api/v1/version"),
                ProbeOutcome {
                    status: "unavailable",
                    latency_ms: None,
                    detail: format!("probe client: {err}"),
                },
                checked_at_ms,
            )];
        }
    };

    let version = probe(&client, &format!("{base}/api/v1/version"), Expect::Ok).await;
    let investigate = probe(
        &client,
        &format!("{base}/api/v1/open/investigations/probe"),
        Expect::MissingToken,
    )
    .await;

    vec![
        probe_entry(
            &LISTENER_PROBE,
            format!("{base}/api/v1/version"),
            version,
            checked_at_ms,
        ),
        probe_entry(
            &INVESTIGATION_PROBE,
            format!("{base}/api/v1/open/investigations/probe"),
            investigate,
            checked_at_ms,
        ),
    ]
}

struct ProbeOutcome {
    status: &'static str,
    latency_ms: Option<u64>,
    detail: String,
}

enum Expect {
    Ok,
    /// 不带令牌时必须回 401 `missing_open_bearer_token`：证明路由在、鉴权闸也在。
    MissingToken,
}

async fn probe(client: &reqwest::Client, url: &str, expect: Expect) -> ProbeOutcome {
    let started = Instant::now();
    let response = client.get(url).send().await;
    let latency = started.elapsed().as_millis() as u64;
    match response {
        Ok(response) => {
            let status = response.status();
            match expect {
                Expect::Ok if status.is_success() => ProbeOutcome {
                    status: "ok",
                    latency_ms: Some(latency),
                    detail: format!(
                        "GET {} → {} {}",
                        path_of(url),
                        status.as_u16(),
                        status.canonical_reason().unwrap_or("")
                    ),
                },
                Expect::MissingToken if status == reqwest::StatusCode::UNAUTHORIZED => {
                    let code = error_code(response).await;
                    match code.as_deref() {
                        Some(codes::MISSING_OPEN_BEARER_TOKEN) => ProbeOutcome {
                            status: "ok",
                            latency_ms: Some(latency),
                            detail: format!(
                                "未带令牌 → 401 {}（符合预期）",
                                codes::MISSING_OPEN_BEARER_TOKEN
                            ),
                        },
                        // 401 但错误码不对：这条链路已经不是「缺令牌」了，不能报绿。
                        Some(other) => ProbeOutcome {
                            status: "unavailable",
                            latency_ms: Some(latency),
                            detail: format!(
                                "未带令牌 → 401 {other}（预期 missing_open_bearer_token）"
                            ),
                        },
                        None => ProbeOutcome {
                            status: "unavailable",
                            latency_ms: Some(latency),
                            detail: "未带令牌 → 401（无错误码）".to_string(),
                        },
                    }
                }
                // 429 也是「闸门在工作」：探活与真实调用共用一个按 IP 的失败桶，
                // 不能因为别人刚把本机打限流，就把健康的开放面报成故障。
                Expect::MissingToken if status == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    ProbeOutcome {
                        status: "ok",
                        latency_ms: Some(latency),
                        detail: "未带令牌 → 429（鉴权限流在生效；路由与闸门都在）".to_string(),
                    }
                }
                _ => ProbeOutcome {
                    status: "unavailable",
                    latency_ms: Some(latency),
                    detail: format!(
                        "GET {} → {} {}（不符合预期）",
                        path_of(url),
                        status.as_u16(),
                        status.canonical_reason().unwrap_or("")
                    ),
                },
            }
        }
        Err(err) => ProbeOutcome {
            status: "unavailable",
            latency_ms: Some(latency),
            detail: format!("GET {} 失败：{err}", path_of(url)),
        },
    }
}

async fn error_code(response: reqwest::Response) -> Option<String> {
    let body: Value = response.json().await.ok()?;
    body.get("error")?.get("code")?.as_str().map(str::to_string)
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|index| &rest[index..]))
        .unwrap_or(url)
}

/// 一条探活的固定描述（与每次的数据分开，避免参数堆一堆）。
struct ProbeSpec {
    id: &'static str,
    label: &'static str,
    covers: &'static str,
}

const LISTENER_PROBE: ProbeSpec = ProbeSpec {
    id: "open_listener",
    label: "开放面 listener",
    covers: "监听 / 路由前缀 / TLS 握手",
};

const INVESTIGATION_PROBE: ProbeSpec = ProbeSpec {
    id: "open_investigations",
    label: "调查下发路由",
    covers: "路由挂载 / Bearer 鉴权闸",
};

fn probe_entry(spec: &ProbeSpec, url: String, outcome: ProbeOutcome, checked_at_ms: i64) -> Value {
    json!({
        "id": spec.id,
        "label": spec.label,
        "covers": spec.covers,
        "url": url,
        "status": outcome.status,
        "latency_ms": outcome.latency_ms,
        "detail": outcome.detail,
        "checked_at_ms": checked_at_ms,
    })
}

/// 探活走本机回环：`0.0.0.0:3104` / `[::]:3104` → `127.0.0.1:3104`；
/// 已经绑具体地址的保持原样（可能是 unix socket 之外的 host name）。
fn loopback_host_port(addr: &str) -> String {
    if let Some(port) = addr.strip_prefix("0.0.0.0:") {
        return format!("127.0.0.1:{port}");
    }
    if let Some(port) = addr.strip_prefix("[::]:") {
        return format!("127.0.0.1:{port}");
    }
    addr.to_string()
}

/// 开放面的 OpenAPI 3.1 文档（四个业务接口，手写比引入生成器更可控）。
///
/// `servers[0].url` 用 `open_public_url`；没配时给占位符 —— 页面据此生成 curl，
/// 让调用方知道要替换哪一段。
fn openapi_document(base_url: Option<&str>) -> Value {
    let server = base_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("https://<开放面地址>");
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "WistCenter 第三方调查 API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "第三方系统按「客户 + 主机 IP」发起调查。报告正文不在中心：按返回的 evidence.cmd_id 去 wist-field 取。"
        },
        "servers": [{ "url": server }],
        "security": [{ "bearer": [] }],
        "paths": {
            "/api/v1/open/capabilities": {
                "get": {
                    "summary": "列出可用的调查能力",
                    "description": "平台提供的调查题面闭集（全局）。具体某台机器能不能跑，要看 /investigation-grants 返回的 granted_topics / capabilities / usable_topics。",
                    "tags": ["investigation"],
                    "responses": {
                        "200": {
                            "description": "调查题面清单",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OpenInvestigationCapabilities" } } }
                        },
                        "401": {
                            "description": "缺失 / 过期 / 撤销 / 不认识的 Bearer token",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "403": {
                            "description": "token 没有 investigation:run",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        }
                    }
                }
            },
            "/api/v1/open/investigation-grants": {
                "get": {
                    "summary": "按客户 + 主机 IP 查调查授权",
                    "description": "按客户绑定与 agent 上报的 IP 找机器，转述网关上报的 granted_topics / capabilities / usable_topics。grant_reported=false 表示旧网关还没上报，不等于全关。",
                    "tags": ["investigation"],
                    "parameters": [
                        {
                            "name": "customer_id",
                            "in": "query",
                            "required": true,
                            "description": "客户 id（与网关绑定一致）",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "host_ip",
                            "in": "query",
                            "required": true,
                            "description": "主机 IP（agent 上报的地址之一）",
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "匹配到的 agent 及其调查授权",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OpenInvestigationGrants" } } }
                        },
                        "400": {
                            "description": "缺少 customer_id / host_ip",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "401": {
                            "description": "缺失 / 过期 / 撤销 / 不认识的 Bearer token",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "403": {
                            "description": "token 没有 investigation:run，或匹配到的 Agent 都不在 resources 范围",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "404": {
                            "description": "该客户下没有匹配此 IP 的 Agent",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        }
                    }
                }
            },
            "/api/v1/open/investigations": {
                "post": {
                    "summary": "发起一次调查",
                    "description": "按「客户 + 主机 IP」寻址：三个业务字段全部必填。中心铸 command_id 并投到网关队列；必须带 Idempotency-Key，同 key 同参数重试返回原 command_id。",
                    "tags": ["investigation"],
                    "parameters": [
                        {
                            "name": "Idempotency-Key",
                            "in": "header",
                            "required": true,
                            "description": "调用方生成的幂等键（≤128 字节）",
                            "schema": { "type": "string" }
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/OpenLaunchInvestigationRequest" },
                                "example": {
                                    "customer_id": "cust-1024",
                                    "host_ip": "192.168.1.5",
                                    "topic": "disk",
                                    "external_ref": "case-2026-0001"
                                }
                            }
                        }
                    },
                    "responses": {
                        "202": {
                            "description": "已受理（只代表网关队列收到，不代表 agentd 已执行）",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OpenLaunchInvestigationResponse" } } }
                        },
                        "400": {
                            "description": "题面不合法，或缺 Idempotency-Key",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "401": {
                            "description": "缺失 / 过期 / 撤销 / 不认识的 Bearer token",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "403": {
                            "description": "token 没有 investigation:run，或 Agent 不在 resources 范围",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "404": {
                            "description": "该客户下没有匹配此 IP 的 Agent",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "409": {
                            "description": "同一客户 + IP 命中多台 Agent / gwlinkd 版本不支持 / 幂等键冲突",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "503": {
                            "description": "命令队列 / 凭据摘要表不可用",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        }
                    }
                }
            },
            "/api/v1/open/investigations/{command_id}": {
                "get": {
                    "summary": "查任务状态",
                    "description": "下发回执来自中心命令队列，任务状态来自网关每 60s 上报；两者分开呈现。报告正文按 evidence.cmd_id 去 wist-field 取。",
                    "tags": ["investigation"],
                    "parameters": [
                        {
                            "name": "command_id",
                            "in": "path",
                            "required": true,
                            "description": "发起调查时返回的 command_id",
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "任务状态",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/OpenInvestigationStatus" } } }
                        },
                        "401": {
                            "description": "缺失 / 过期 / 撤销 / 不认识的 Bearer token",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        },
                        "404": {
                            "description": "命令不存在，或不在该凭据的 resources 范围（统一 404）",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } }
                        }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "wcr_…（wist-cred 签发，audience = wist-center）"
                }
            },
            "schemas": {
                "ErrorEnvelope": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": { "type": "string" },
                                "message": { "type": "string" },
                                "retryable": { "type": "boolean" },
                                "severity": { "type": "string" },
                                "fields": { "type": ["object", "null"] }
                            }
                        }
                    }
                },
                "OpenInvestigationCapabilities": {
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "enum": ["center"] },
                        "version": { "type": "string" },
                        "topics": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/OpenInvestigationTopic" }
                        }
                    }
                },
                "OpenInvestigationTopic": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "label": { "type": "string" },
                        "summary": { "type": "string" },
                        "platforms": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "OpenInvestigationGrants": {
                    "type": "object",
                    "properties": {
                        "customer_id": { "type": "string" },
                        "host_ip": { "type": "string" },
                        "denied": {
                            "type": "integer",
                            "description": "匹配到但不在当前凭据 resources 范围的 Agent 数量"
                        },
                        "agents": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/OpenInvestigationAgentGrant" }
                        }
                    }
                },
                "OpenInvestigationAgentGrant": {
                    "type": "object",
                    "properties": {
                        "agent_id": { "type": "string" },
                        "gateway_id": { "type": "string" },
                        "hostname": { "type": ["string", "null"] },
                        "ip_addresses": { "type": ["array", "null"], "items": { "type": "string" } },
                        "reported_at": { "type": "string", "format": "date-time" },
                        "binding_status": { "type": ["string", "null"] },
                        "binding_revision": { "type": ["integer", "null"] },
                        "grant_reported": { "type": "boolean" },
                        "granted_topics": { "type": "array", "items": { "type": "string" } },
                        "capabilities_reported": { "type": "boolean" },
                        "capabilities": { "type": "array", "items": { "type": "string" } },
                        "usable_topics": { "type": "array", "items": { "type": "string" } },
                        "reason": { "type": ["string", "null"], "description": "未上报时的原因；grant_reported=false 不等于全关" }
                    }
                },
                "OpenLaunchInvestigationRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["customer_id", "host_ip", "topic"],
                    "description": "按「客户 + 主机 IP」寻址：customer_id / host_ip / topic 全部必填。",
                    "properties": {
                        "customer_id": {
                            "type": "string",
                            "minLength": 1,
                            "description": "客户 id（与网关绑定一致）"
                        },
                        "host_ip": {
                            "type": "string",
                            "minLength": 1,
                            "description": "主机 IP（agent 上报的地址之一）"
                        },
                        "topic": {
                            "type": "string",
                            "enum": ["disk", "load", "accounts", "persistence", "exposure", "telemetry-health"],
                            "description": "调查题面（闭集）"
                        },
                        "external_ref": {
                            "type": "string",
                            "maxLength": 200,
                            "description": "调用方自己的工单 / 事件号（只做对账，不随 wire 下发）"
                        }
                    }
                },
                "OpenLaunchInvestigationResponse": {
                    "type": "object",
                    "properties": {
                        "command_id": { "type": "string" },
                        "agent_id": { "type": "string" },
                        "gateway_id": { "type": "string" },
                        "topic": { "type": "string" },
                        "external_ref": { "type": ["string", "null"] },
                        "state": { "type": "string", "description": "中心命令聚合状态（如 queued）" },
                        "target": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "ids": { "type": "array", "items": { "type": "string" } }
                            }
                        },
                        "evidence": { "$ref": "#/components/schemas/EvidencePointer" }
                    }
                },
                "OpenInvestigationStatus": {
                    "type": "object",
                    "properties": {
                        "command_id": { "type": "string" },
                        "agent_id": { "type": "string" },
                        "gateway_id": { "type": "string" },
                        "topic": { "type": "string" },
                        "external_ref": { "type": ["string", "null"] },
                        "state": { "type": "string" },
                        "requested_at": { "type": "string", "format": "date-time" },
                        "dispatched_at": { "type": ["string", "null"], "format": "date-time" },
                        "target": {
                            "type": ["object", "null"],
                            "description": "下发回执（中心命令队列）",
                            "properties": {
                                "state": { "type": "string" },
                                "result_status": { "type": ["integer", "null"] },
                                "result_error": { "type": ["string", "null"] }
                            }
                        },
                        "task": {
                            "type": ["object", "null"],
                            "description": "网关上来的任务状态；null = 还没上报，不等于没下发",
                            "properties": {
                                "state": { "type": "string", "enum": ["queued", "claimed", "acked", "expired", "superseded"] },
                                "requested_at": { "type": "string", "format": "date-time" },
                                "claimed_at": { "type": ["string", "null"], "format": "date-time" },
                                "acked_at": { "type": ["string", "null"], "format": "date-time" },
                                "outcome": { "type": ["string", "null"] },
                                "detail": { "type": ["string", "null"] }
                            }
                        },
                        "evidence": { "$ref": "#/components/schemas/EvidencePointer" }
                    }
                },
                "EvidencePointer": {
                    "type": "object",
                    "properties": {
                        "service": { "type": "string", "enum": ["wist-field"] },
                        "cmd_id": { "type": "string", "description": "去 wist-field 取报告正文的键" }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_replacement_only_touches_wildcard_bindings() {
        assert_eq!(loopback_host_port("0.0.0.0:3104"), "127.0.0.1:3104");
        assert_eq!(loopback_host_port("[::]:3104"), "127.0.0.1:3104");
        assert_eq!(loopback_host_port("127.0.0.1:3104"), "127.0.0.1:3104");
        assert_eq!(
            loopback_host_port("open.internal:3104"),
            "open.internal:3104"
        );
    }

    #[test]
    fn the_spec_uses_the_configured_public_base_url() {
        let document = openapi_document(Some("https://open.example.com"));
        assert_eq!(document["servers"][0]["url"], "https://open.example.com");
        let document = openapi_document(None);
        assert_eq!(document["servers"][0]["url"], "https://<开放面地址>");
    }

    /// 下发请求体只有一个形状：三个必填字段，拒绝一切多余字段。
    #[test]
    fn the_launch_schema_has_one_shape() {
        let document = openapi_document(None);
        let request = &document["components"]["schemas"]["OpenLaunchInvestigationRequest"];
        assert_eq!(
            request["required"],
            json!(["customer_id", "host_ip", "topic"]),
            "{request}"
        );
        assert_eq!(request["additionalProperties"], json!(false));
        let properties = request["properties"].as_object().expect("properties");
        assert_eq!(
            properties.keys().cloned().collect::<Vec<_>>(),
            vec!["customer_id", "external_ref", "host_ip", "topic"]
        );
        // 旧设计的两层包装与题面参数都不该再出现。
        assert!(
            document["components"]["schemas"]
                .get("OpenInvestigationTarget")
                .is_none()
        );
        assert!(properties.get("params").is_none());
    }

    #[test]
    fn the_spec_documents_the_four_business_endpoints() {
        let document = openapi_document(None);
        let paths = document["paths"].as_object().expect("paths");
        let mut names: Vec<&str> = paths.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "/api/v1/open/capabilities",
                "/api/v1/open/investigation-grants",
                "/api/v1/open/investigations",
                "/api/v1/open/investigations/{command_id}",
            ]
        );
    }
}
