// @jumo generated
// WarpInsightCenter 上级聚合控制中心服务（crate: wist-center）：接收 WarpGateway 状态上报。

use std::{error::Error, path::PathBuf, sync::Arc};

use wist_center::infra::{FileStore, PgStore, Store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("init-config") {
        return init_config_command(args.get(1).map(String::as_str));
    }
    let config_path = wist_center::config::resolved_config_path();
    let config =
        wist_center::config::CenterConfig::load_from_env().map_err(|err| err.into_boxed_std())?;
    // 配置了 database_url → PostgreSQL；未配置 → JSON 文件回退。
    let store: Arc<dyn Store> = match &config.database_url {
        Some(database_url) => Arc::new(
            PgStore::connect(database_url)
                .await
                .map_err(|err| err.into_boxed_std())?,
        ),
        None => Arc::new(FileStore::new(config.store_path.clone())),
    };
    store
        .seed(&config.gateway_credentials)
        .await
        .map_err(|err| err.into_boxed_std())?;
    let addr = config.listen_addr.clone();
    let app = wist_center::api::router(config, store);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("wist-center config: {}", config_path.display());
    println!("wist-center listening on http://{addr}");
    // 注入真实 peer 地址供限流按 IP 分桶（忽略可伪造的 x-real-ip / x-forwarded-for）。
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// 生成一份带新随机 admin token / hmac secret 的 wist-center.toml，
/// 让开发态凭据可以持久化（不必每次启动重新粘贴 token）。
///
/// 已存在同名配置时直接报错退出：这两项是长期凭据，静默覆盖会让已发出去的
/// token 与既有网关注册凭据失效；确实要重新生成就先删掉旧文件或换个路径。
fn init_config_command(out_arg: Option<&str>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let out_path = out_arg
        .map(PathBuf::from)
        .unwrap_or_else(wist_center::config::default_config_path);
    if out_path.exists() {
        return Err(format!(
            "config already exists: {} (remove it first to regenerate)",
            out_path.display()
        )
        .into());
    }
    let admin_token = wist_center::infra::new_secret_token("adm")
        .map_err(|err| format!("failed to generate admin token: {err}"))?;
    let hmac_secret = wist_center::infra::new_secret_token("hmac")
        .map_err(|err| format!("failed to generate hmac secret: {err}"))?;
    if let Some(parent) = out_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &out_path,
        wist_center::config::default_config_text(&admin_token, &hmac_secret),
    )?;
    println!("generated center config: {}", out_path.display());
    println!("admin token: {admin_token}");
    println!("  —— 管理页面登录 token，请妥善保存（生产环境别写进仓库/工单）");
    println!("hmac secret: {hmac_secret}");
    println!("  —— RegistToken 派生密钥，请妥善保存（轮换不影响既有网关凭据）");
    Ok(())
}
