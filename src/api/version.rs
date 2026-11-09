// 中心版本端点（**公开、无鉴权**）。
//
// 为什么单开一条公开路由：页面左下角要常驻显示「前端 + 后端 + 栈」三个版本号，其中后端版本在
// **还没填 admin token 时**也该可见（运维一进来先想确认「我连的这个中心是哪版」）。挂到管理面
// bearer 之后就答不出来了，所以这条不参与任何鉴权。
//
// 两个版本号的口径刻意不同（与网关侧 `wist-gateway/src/api/version.rs` 同口径）：
//
// * `version` 取编译期烧入的 `CARGO_PKG_VERSION` —— 是「这个二进制是哪版」，与发布制品一致；
// * `stack_version` 取运行期读到的 **center-stack 的 `version.txt`** —— 是「这套部署是哪版」。
//   center 镜像与 center-stack 分开发版，二进制自己不可能知道这一点，所以由 stack 把
//   `version.txt` 只读挂进容器（默认 `/config/stack-version.txt`），或直接给
//   `WIST_CENTER_STACK_VERSION`。
//
// 读不到就**不返回该字段**（而不是编一个值）：前端据此显示 `—`。旧中心没有这个字段，新前端
// 必须仍然能工作 —— 这是加字段而不改 `version` 形状的原因。
//
// 手工扩展说明：本模块与其路由**不在** jumo 静态模型的声明里 —— 与 `install.rs` 里的
// 「公开、无令牌」运维端点同一模式。若之后重新生成控制面代码，需要手动回补本模块与下方路由。

use std::path::Path;

use axum::Json;
use serde::Serialize;

/// 直接给全栈版本的环境变量（优先于文件）。
const STACK_VERSION_ENV: &str = "WIST_CENTER_STACK_VERSION";
/// 指定全栈版本文件路径的环境变量。
const STACK_VERSION_FILE_ENV: &str = "WIST_CENTER_STACK_VERSION_FILE";
/// 默认挂载点：center-stack 的 `version.txt` 由 compose 只读挂到这里。
const DEFAULT_STACK_VERSION_FILE: &str = "/config/stack-version.txt";

/// 版本响应体（`GET /api/v1/version`）：`version` 必有，`stack_version` 可省。
#[derive(Debug, Serialize)]
pub struct CenterVersion {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_version: Option<String>,
}

/// `GET /api/v1/version`：公开、无鉴权，返回中心（后端）版本与部署的全栈版本。
pub async fn center_version() -> Json<CenterVersion> {
    Json(CenterVersion {
        version: env!("CARGO_PKG_VERSION").to_string(),
        stack_version: stack_version(),
    })
}

/// 运行期解析全栈版本：环境变量优先，其次读文件；空串一律当「没有」。
fn stack_version() -> Option<String> {
    let env_value = std::env::var(STACK_VERSION_ENV).ok();
    let path = std::env::var(STACK_VERSION_FILE_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_STACK_VERSION_FILE.to_string());
    let file_value = std::fs::read_to_string(Path::new(path.trim())).ok();
    resolve_stack_version(env_value.as_deref(), file_value.as_deref())
}

/// 纯函数形式的取值规则（便于测试）：先环境变量、后文件；trim 后为空则跳过。
fn resolve_stack_version(env_value: Option<&str>, file_value: Option<&str>) -> Option<String> {
    [env_value, file_value]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::resolve_stack_version;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{config::CenterConfig, infra::FileStore};

    /// 版本端点只读编译期常量、不碰 store / CA，故给一份最小 `ApiState` 即可过 `router_for`
    /// （沿用 `admin_ops.rs` 测试里构 state 的写法，字段按同一口径给齐）。
    fn test_state() -> super::super::ApiState {
        let store_path = std::env::temp_dir().join("wist-center-version-test.json");
        let artifact_dir = std::env::temp_dir().join("wist-center-version-artifacts");
        let store: Arc<dyn crate::infra::Store> = Arc::new(FileStore::new(&store_path));
        let artifact_store: Arc<dyn crate::infra::ArtifactStore> = Arc::new(
            crate::infra::LocalArtifactStore::new(artifact_dir.clone(), "http://127.0.0.1:3100"),
        );
        let jobs = crate::infra::release_job_queue(store.clone(), artifact_store.clone());
        super::super::ApiState {
            config: CenterConfig {
                evidence: None,
                listen_addr: "127.0.0.1:3100".to_string(),
                admin_addr: None,
                store_path: store_path.clone(),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: None,
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                gateway_project_repo: "https://wgc-git.beta.jingang.cloud/gateway-tx.git"
                    .to_string(),
                artifact_dir: artifact_dir.clone(),
                object_storage: None,
                package_sources: Vec::new(),
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
                wparse_proxy: crate::config::WparseProxyConfig {
                    enabled: false,
                    listen_addr: "0.0.0.0:3101".to_string(),
                },
                wparse_release: Default::default(),
                log: Default::default(),
                credentials: Default::default(),
            },
            store,
            artifact_store,
            gateway_ca: Arc::new(
                crate::infra::gateway_ca::GatewayCa::generate("Wist Center Version Test CA")
                    .expect("gateway ca")
                    .0,
            ),
            proxy: None,
            rate_limits: Arc::new(Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
            jobs,
            credentials: None,
        }
    }

    /// 公开端点：**不带任何凭据**也命中 200 + `{version}` 非空 —— 页面左下角在未登录时也
    /// 要显示后端版本（见本模块说明）。
    #[tokio::test]
    async fn version_route_is_public_and_reports_a_non_empty_version() {
        let app = super::super::router_for(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/version")
                    // 刻意不带 authorization：公开端点，未登录也必须答。
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let version = body["version"].as_str().unwrap_or("");
        assert!(
            !version.is_empty(),
            "缺省 `version` 必须非空（页面据此显示后端版本）：{body}"
        );
        // 全栈版本可选：center-stack 没挂 `version.txt` 时不返回；一旦返回就必须是非空字符串。
        match body.get("stack_version") {
            None => {}
            Some(value) => {
                let text = value.as_str().unwrap_or("");
                assert!(
                    !text.trim().is_empty(),
                    "`stack_version` 要么不出现，要么是非空字符串：{body}"
                );
            }
        }
    }

    #[test]
    fn stack_version_prefers_the_explicit_environment_value() {
        assert_eq!(
            resolve_stack_version(Some(" 0.11.0 \n"), Some("0.10.0")),
            Some("0.11.0".to_string())
        );
    }

    #[test]
    fn stack_version_falls_back_to_the_file() {
        assert_eq!(
            resolve_stack_version(None, Some("0.11.0\n")),
            Some("0.11.0".to_string())
        );
    }

    #[test]
    fn stack_version_treats_blank_sources_as_absent() {
        assert_eq!(resolve_stack_version(Some("  "), Some("\n")), None);
        assert_eq!(resolve_stack_version(None, None), None);
    }
}
