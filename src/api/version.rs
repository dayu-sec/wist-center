// 中心版本端点（**公开、无鉴权**）。
//
// 为什么单开一条公开路由：页面左下角要常驻显示「前端 + 后端」两个版本号，其中后端版本在
// **还没填 admin token 时**也该可见（运维一进来先想确认「我连的这个中心是哪版」）。挂到管理面
// bearer 之后就答不出来了，所以这条不参与任何鉴权。
//
// 版本号取编译期烧入的 `CARGO_PKG_VERSION`：它与发布制品一致（是「这个二进制是哪版」，
// 而不是「运行期读到了什么」）。与网关侧 `wist-gateway/src/api/version.rs` 同口径。
//
// 手工扩展说明：本模块与其路由**不在** jumo 静态模型的声明里 —— 与 `install.rs` 里的
// 「公开、无令牌」运维端点同一模式。若之后重新生成控制面代码，需要手动回补本模块与下方路由。

use axum::Json;
use serde::Serialize;

/// 版本响应体（`GET /api/v1/version`）：扁平、单字段，前端直接取 `version`。
#[derive(Debug, Serialize)]
pub struct CenterVersion {
    pub version: String,
}

/// `GET /api/v1/version`：公开、无鉴权，返回中心（后端）版本。
pub async fn center_version() -> Json<CenterVersion> {
    Json(CenterVersion {
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

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
        super::super::ApiState {
            config: CenterConfig {
                listen_addr: "127.0.0.1:3100".to_string(),
                store_path: store_path.clone(),
                server_cert_path: None,
                server_key_path: None,
                gateway_credentials: Vec::new(),
                admin_token_hash: None,
                database_url: None,
                victoriametrics_url: None,
                public_url: "http://127.0.0.1:3100".to_string(),
                gateway_image: "wist-gateway:latest".to_string(),
                artifact_dir: artifact_dir.clone(),
                object_storage: None,
                package_sources: Vec::new(),
                ca_cert: None,
                protocol_version: "1.0".to_string(),
                hmac_secret: "test-hmac-secret".to_string(),
                credential_ttl_seconds: 3600,
                link_ttl_seconds: 900,
                log: Default::default(),
            },
            store: Arc::new(FileStore::new(&store_path)),
            artifact_store: Arc::new(crate::infra::LocalArtifactStore::new(
                artifact_dir,
                "http://127.0.0.1:3100",
            )),
            gateway_ca: Arc::new(
                crate::infra::gateway_ca::GatewayCa::generate("Wist Center Version Test CA")
                    .expect("gateway ca")
                    .0,
            ),
            rate_limits: Arc::new(Mutex::new(
                super::super::rate_limit::RateLimitState::default(),
            )),
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
    }
}
