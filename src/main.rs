// @jumo generated
// WistCenter 上级聚合控制中心服务（crate: wist-center）：接收 WarpGateway 状态上报。

use std::{error::Error, net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use wist_center::infra::{FileStore, PgStore, Store, VerifiedGatewayIdentity};

#[tokio::main]
async fn main() -> ExitCode {
    match run_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let chain = render_error_chain(err.as_ref());
            if log::log_enabled!(log::Level::Error) {
                log::error!("wist-center failed: {chain}");
            } else {
                // 日志还没起来（配置就读不了）→ 退 stderr，别让启动失败静默。
                eprintln!("wist-center failed: {chain}");
            }
            ExitCode::FAILURE
        }
    }
}

/// 把 error 的 `source` 链折成多行文本（`orion-error` 的 `Caused by` 因果链在 source 里，
/// 直接 `{err}` / `Err` 默认 Debug 都看不到）。
fn render_error_chain(err: &(dyn Error + Send + Sync + 'static)) -> String {
    // 深度上限：正常因果链很短；设上限只为防病态 / 成环的 `source()` 实现把日志打爆。
    const MAX_DEPTH: usize = 16;
    let mut out = err.to_string();
    let mut source = err.source();
    let mut index = 1;
    while let Some(cause) = source {
        if index > MAX_DEPTH {
            out.push_str("\n  -> Caused by ... (chain truncated)");
            break;
        }
        out.push_str(&format!("\n  -> Caused by {index}: {cause}"));
        source = cause.source();
        index += 1;
    }
    out
}

async fn run_main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("init-config") {
        return init_config_command(args.get(1).map(String::as_str));
    }
    let config_path = wist_center::config::resolved_config_path();
    let config =
        wist_center::config::CenterConfig::load_from_env().map_err(|err| err.into_boxed_std())?;
    // 运行日志在**读到配置之后**初始化：级别 / 格式 / 落点由 `[log]` 段决定（`RUST_LOG` 优先）。
    wist_log::init(
        &config.log,
        &wist_log::Identity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
    );
    log::info!("wist-center config: {}", config_path.display());
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
    // 服务端 TLS 材料（成对配）：配了就起 HTTPS 并校网关客户端证书。
    let server_tls = config
        .server_cert_path
        .clone()
        .zip(config.server_key_path.clone());
    let (gateway_ca_cert_path, gateway_ca_key_path) =
        wist_center::config::resolved_gateway_client_ca_paths(&config_path);
    let gateway_ca = Arc::new(
        wist_center::infra::gateway_ca::load_or_create(&gateway_ca_cert_path, &gateway_ca_key_path)
            .map_err(|err| -> Box<dyn Error + Send + Sync> { err.into() })?,
    );
    let gateway_ca_pem = gateway_ca.ca_certificate_pem().to_string();

    // 规则发布兼容入口（WarpStation 设备面）。只有 PG 才能保证命令队列的原子性；
    // FileStore / 未配 database_url 时自动降级为「未启用」。
    let proxy = match (&config.database_url, config.wparse_proxy.enabled) {
        (Some(url), true) => match wist_center::wparse_proxy::WparseProxy::connect(url).await {
            Ok(proxy) => Some(Arc::new(proxy)),
            Err(err) => {
                log::warn!("wparse-proxy disabled: {err}");
                None
            }
        },
        (None, true) => {
            log::warn!("wparse-proxy disabled: [store].database_url is required");
            None
        }
        _ => None,
    };
    let proxy_tls = server_tls.clone();
    let proxy_addr = config.wparse_proxy.listen_addr.clone();

    // 管理面 listener（**内网**）：只有配了 `[server].admin_addr` 才拆。
    // 与网关面完全隔开：不同端口、不同路由白名单、**不校客户端证书**（浏览器没有网关证书）。
    // 未配置时保持旧行为（两者共用 `listen_addr`）。
    let admin_addr = config.admin_addr.clone();
    if let Some(admin_addr) = admin_addr.clone() {
        let admin_app = wist_center::api::admin_router(
            config.clone(),
            store.clone(),
            gateway_ca.clone(),
            proxy.clone(),
        );
        match server_tls.clone() {
            Some((cert_path, key_path)) => {
                let tls_config = wist_center::infra::load_server_only_config(&cert_path, &key_path)
                    .map_err(|err| -> Box<dyn Error + Send + Sync> { err.into() })?;
                let listener = TcpListener::bind(&admin_addr).await?;
                log::info!("wist-center admin API listening on https://{admin_addr}");
                tokio::spawn(async move {
                    if let Err(err) = serve_tls(listener, admin_app, tls_config).await {
                        log::error!("admin listener stopped: {err}");
                    }
                });
            }
            None => {
                let listener = TcpListener::bind(&admin_addr).await?;
                log::warn!(
                    "wist-center admin API listening on http://{admin_addr} (server TLS is not configured)"
                );
                tokio::spawn(async move {
                    if let Err(err) = axum::serve(
                        listener,
                        admin_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .await
                    {
                        log::error!("admin listener stopped: {err}");
                    }
                });
            }
        }
    }

    let app = if admin_addr.is_some() {
        // 拆了面：网关 listener 只挂 `/api/v1/gateway/**` + `/api/v1/version`。
        wist_center::api::gateway_router(config, store, gateway_ca, proxy.clone())
    } else {
        wist_center::api::router(config, store, gateway_ca, proxy.clone())
    };

    // 独立 listener：服务器证书 + **不校客户端证书**（WarpStation 持 Bearer proxy token，
    // 没有、也不应该持有网关 mTLS 客户端证书）。
    if let Some(proxy) = proxy {
        let proxy_app = wist_center::wparse_proxy::router(proxy);
        match proxy_tls {
            Some((cert_path, key_path)) => {
                let tls_config = wist_center::infra::load_server_only_config(&cert_path, &key_path)
                    .map_err(|err| -> Box<dyn Error + Send + Sync> { err.into() })?;
                let listener = TcpListener::bind(&proxy_addr).await?;
                log::info!("wparse-proxy listening on https://{proxy_addr}");
                tokio::spawn(async move {
                    if let Err(err) = serve_tls(listener, proxy_app, tls_config).await {
                        log::error!("wparse-proxy listener stopped: {err}");
                    }
                });
            }
            None => {
                let listener = TcpListener::bind(&proxy_addr).await?;
                log::warn!(
                    "wparse-proxy listening on http://{proxy_addr} (server TLS is not configured)"
                );
                tokio::spawn(async move {
                    if let Err(err) = axum::serve(
                        listener,
                        proxy_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .await
                    {
                        log::error!("wparse-proxy listener stopped: {err}");
                    }
                });
            }
        }
    }
    let listener = TcpListener::bind(&addr).await?;
    match server_tls {
        Some((cert_path, key_path)) => {
            let tls_config = wist_center::infra::load_gateway_mtls_server_config(
                &cert_path,
                &key_path,
                &gateway_ca_pem,
            )
            .map_err(|err| -> Box<dyn Error + Send + Sync> { err.into() })?;
            log::info!("wist-center listening on https://{addr}");
            serve_tls(listener, app, tls_config).await?;
        }
        None => {
            log::info!("wist-center listening on http://{addr}");
            // 注入真实 peer 地址供限流按 IP 分桶（忽略可伪造的 x-real-ip / x-forwarded-for）。
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
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
    // 一并写出**现场态**（声明 + 值骶架）：声明只写 `${VAR}`、值留空 ——
    // 现场就有一个明确要填的文件，而不会「一启动就报未定义」。两者缺失才写。
    let pub_path = wist_center::config::pub_config_path(&out_path);
    let env_path = wist_center::config::pub_env_path(&out_path);
    if let Some(parent) = pub_path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    if !pub_path.exists() {
        std::fs::write(&pub_path, wist_center::config::default_pub_config_text())?;
        println!("generated site (pub) declaration: {}", pub_path.display());
    }
    if !env_path.exists() {
        std::fs::write(&env_path, wist_center::config::default_env_text())?;
        println!("generated site (pub) values: {}", env_path.display());
    }
    println!("generated center config: {}", out_path.display());
    println!("admin token: {admin_token}");
    println!("  —— 管理页面登录 token，请妥善保存（生产环境别写进仓库/工单）");
    println!("hmac secret: {hmac_secret}");
    println!("  —— RegistToken 派生密钥，请妥善保存（轮换不影响既有网关凭据）");
    Ok(())
}

/// 每条连接注入请求扩展的东西：对端地址（限流）与 mTLS 证书身份（鉴权）。
///
/// `client_identity` 只能由本进程在握手后写入 —— 它走 `request.extensions_mut()`，
/// 客户端无法通过 HTTP 头伪造。
#[derive(Clone)]
struct ConnectionContext {
    peer: SocketAddr,
    client_identity: Option<VerifiedGatewayIdentity>,
}

async fn inject_connection_context(
    State(context): State<ConnectionContext>,
    mut request: Request,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .insert(ConnectInfo::<SocketAddr>(context.peer));
    if let Some(identity) = context.client_identity {
        request.extensions_mut().insert(identity);
    }
    next.run(request).await
}

/// HTTPS 监听：rustls 终止 TLS（服务器证书）+ 校客户端证书（CA-G），
/// 握手后从连接里取已验证的网关身份并注入每个请求（与网关侧 `serve_tls` 同构）。
async fn serve_tls(
    listener: TcpListener,
    app: axum::Router,
    tls_config: rustls::ServerConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    log::warn!("failed TLS handshake from {peer_addr}: {err}");
                    return;
                }
            };
            // 握手期已由 CA-G 验链；能解出身份就注入，解不出（缺 URI SAN / 段非法）
            // 就不当作已认证 —— 交给应用层回 401，而不是静默放行。
            let client_identity = match wist_center::infra::peer_leaf_certificate_der(
                tls_stream.get_ref().1,
            ) {
                Some(der) => match VerifiedGatewayIdentity::from_certificate_der(&der) {
                    Ok(identity) => Some(identity),
                    Err(err) => {
                        log::warn!(
                            "mTLS client certificate from {peer_addr} has no usable gateway identity: {err}"
                        );
                        None
                    }
                },
                None => None,
            };
            let io = TokioIo::new(tls_stream);
            // 注入真实 peer 地址供限流按 IP 分桶，不能靠可伪造的 x-real-ip / x-forwarded-for。
            let context = ConnectionContext {
                peer: peer_addr,
                client_identity,
            };
            let service = service.layer(from_fn_with_state(context, inject_connection_context));
            let service = TowerToHyperService::new(service);
            let builder = Builder::new(TokioExecutor::new());
            if let Err(err) = builder.serve_connection(io, service).await {
                log::warn!("failed to serve HTTPS connection from {peer_addr}: {err}");
            }
        });
    }
}
