//! 程序访问凭据（`wist-cred`）接入：接收摘要 + 本地校验。
//!
//! 中心在这里扮演 cred 的**验证方（X）**：cred 通过 mTLS 把凭据摘要推过来，中心落到本地
//! `state/credentials.json`（只存 sha256），之后管理面的 Bearer token 先在这张表里验。
//!
//! 三件事都在本模块：
//!
//! | 能力 | 实现 |
//! |---|---|
//! | 接收 `register` / `revoke` + `/healthz` | [`wist_cred_peer::serve_router`]（独立 mTLS listener） |
//! | 自己的状态（摘要表） | [`wist_cred_peer::Peer`] |
//! | 管理面鉴权用的句柄 | [`CredentialVerifier`] |
//!
//! 边界：摘要表是**验证侧私有状态**，不进 PG、不给业务读；换库 / 备份不影响认证。
//! 服务器证书必须由 **CA-S** 签（cred 的 `[push].ca` 是唯一信任锚），与网关面那张
//! `server.server_cert_path` 不是同一张（中心的 CA 不被 cred 信任）。

use std::net::SocketAddr;
use std::sync::Arc;

use wist_cred_peer::{Config as PeerConfig, Peer};

use crate::config::CenterConfig;

/// 已装配好的凭据服务：listener 地址 + 已建好的 mTLS 配置 + 摘要表。
///
/// TLS 在**启动期**就建好（而不是交给 listener 任务里做）：证书不存在 / 读不了 / 链不对，
/// 进程直接拒绝启动，不会出现「管理面只认凭据、但凭据 listener 起不来」的半启用状态。
pub struct CredentialService {
    pub peer: Arc<Peer>,
    pub listen: SocketAddr,
    pub tls: rustls::ServerConfig,
}

/// `ApiState` 里保存的验证器句柄。
///
/// 薄包装只为一件事：`Peer` 不实现 `Debug`（内部有摘要表锁），而 `ApiState` 要保持 `Debug`。
#[derive(Clone)]
pub struct CredentialVerifier(Arc<Peer>);

impl std::fmt::Debug for CredentialVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialVerifier")
            .field("audience", &self.0.config().audience)
            .field("registered", &self.0.registered())
            .finish()
    }
}

impl CredentialVerifier {
    pub fn new(peer: Arc<Peer>) -> Self {
        Self(peer)
    }

    pub fn peer(&self) -> &Peer {
        &self.0
    }
}

/// 按配置装配。未启用 → `Ok(None)`；启用但材料/地址不成立 → 启动期直接失败。
pub fn build(config: &CenterConfig) -> Result<Option<CredentialService>, String> {
    let credentials = &config.credentials;
    if !credentials.enabled {
        return Ok(None);
    }

    let listen: SocketAddr = credentials
        .listen()
        .parse()
        .map_err(|err| format!("credentials.listen_addr {:?}: {err}", credentials.listen()))?;

    let cert = require_path(
        credentials.server_cert_path.as_ref(),
        "credentials.server_cert_path",
    )?;
    let key = require_path(
        credentials.server_key_path.as_ref(),
        "credentials.server_key_path",
    )?;
    let client_ca = require_path(
        credentials.client_ca_path.as_ref(),
        "credentials.client_ca_path",
    )?;
    let client_ca_pem = std::fs::read_to_string(&client_ca)
        .map_err(|err| format!("read {}: {err}", client_ca.display()))?;
    // 严格模式（`allow_unauthenticated = false`）：cred 必须出示 CA-I 签的客户端证书。
    let tls = wist_pki::tls::server_config_mtls(&cert, &key, &client_ca_pem, false)?;

    let mut peer_config =
        PeerConfig::new(credentials.audience.clone(), credentials.store_path.clone())
            .known_roles(credentials.known_roles.clone())
            .require_signature(credentials.require_signature);
    for issuer in &credentials.allowed_issuers {
        peer_config = peer_config.allow_issuer(issuer.clone());
    }
    if let Some(path) = &credentials.issuer_public_key_path {
        for key in load_issuer_keys(path, credentials.require_signature)? {
            peer_config = peer_config.issuer_public_key(key);
        }
    }
    let peer = Peer::open(peer_config).map_err(|err| err.to_string())?;
    if peer.rejected_on_load() > 0 {
        // 非 0 意味着磁盘上的授权记录被改过（或签名密钥换过）。
        // 已经被丢弃，不会进内存表；但必须让运维看见。
        log::error!(
            "credentials: {} authorization record(s) were rejected on load \
             (invalid signature, missing key, or malformed entry)",
            peer.rejected_on_load()
        );
    }

    Ok(Some(CredentialService { peer, listen, tls }))
}

fn require_path(
    value: Option<&std::path::PathBuf>,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    value
        .cloned()
        .ok_or_else(|| format!("{label} is required when credentials.enabled = true"))
}

/// 读签发方公钥：**一行一把**（轮换期可同时信任新旧两把）。
///
/// `required = false`（灰度窗口，验签关着）时文件缺失不致命：现场可能还没重新接入。
fn load_issuer_keys(path: &std::path::Path, required: bool) -> Result<Vec<Vec<u8>>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if !required => {
            log::warn!(
                "credentials: issuer public key {} is not readable ({err}); \
                 signature verification is disabled, so this is not fatal",
                path.display()
            );
            return Ok(Vec::new());
        }
        Err(err) => return Err(format!("read {}: {err}", path.display())),
    };
    let keys = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            wist_auth::signing::parse_public_key_hex(line)
                .map_err(|err| format!("{}: {err}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        if required {
            return Err(format!("{} contains no public key", path.display()));
        }
        log::warn!(
            "credentials: issuer public key {} is empty; \
             signature verification is disabled, so this is not fatal",
            path.display()
        );
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_file(tag: &str, content: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wist-center-cred-keys-{tag}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("issuer-signing.pub");
        if let Some(content) = content {
            std::fs::write(&path, content).expect("write key file");
        }
        path
    }

    #[test]
    fn one_key_per_line_supports_rotation() {
        let path = temp_file(
            "two",
            Some(&format!("{}\n{}\n", "aa".repeat(32), "bb".repeat(32))),
        );
        let keys = load_issuer_keys(&path, true).expect("load");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], vec![0xaa; 32]);
        assert_eq!(keys[1], vec![0xbb; 32]);
    }

    #[test]
    fn an_empty_key_file_is_rejected_when_signatures_are_required() {
        let path = temp_file("empty", Some("\n\n"));
        assert!(load_issuer_keys(&path, true).is_err());
    }

    #[test]
    fn an_empty_key_file_is_tolerated_during_the_rollout_window() {
        let path = temp_file("empty-optional", Some("\n\n"));
        assert!(
            load_issuer_keys(&path, false)
                .expect("tolerated")
                .is_empty()
        );
    }

    #[test]
    fn a_missing_key_file_is_fatal_when_signatures_are_required() {
        let path = temp_file("missing-required", None);
        assert!(load_issuer_keys(&path, true).is_err());
    }

    #[test]
    fn a_missing_key_file_is_tolerated_during_the_rollout_window() {
        let path = temp_file("missing-optional", None);
        let keys = load_issuer_keys(&path, false).expect("tolerated");
        assert!(keys.is_empty());
    }
}
