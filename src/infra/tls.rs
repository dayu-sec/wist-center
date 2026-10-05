//! 中心**服务端 TLS/mTLS**：服务器证书（CA-S 签）+ 校网关客户端证书（CA-G）。
//!
//! 与网关侧 `infra/tls.rs` 同构，角色对调：那边网关验 agent，这里中心验网关。
//! 「凭甲方（网关）凭什么信中心」靠服务器证书；「中心凭什么信网关」靠客户端证书——
//! 由 rustls 的 `WebPkiClientVerifier` 在握手期验链，应用层再从连接里取叶证书认身份。

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// 构建**开启 mTLS** 的服务端 TLS 配置：以 `gateway_ca_pem`（CA-G）为客户端验证信任锚。
///
/// 客户端证书是**可选**的（`allow_unauthenticated`）：
///
/// - **首次注册**的网关还没有证书，强制要求会在握手就把它挡在外面；
/// - 「无证书」不等于「未鉴权」——注册靠一次性接入券（link token），其余网关面路由由应用层
///   `authorize_gateway_certificate` **只凭客户端证书**判定（bearer 双轨已删）。
///
/// 出示了证书就一定会被验证（链 + 有效期 + `EKU=clientAuth`）；有证书但验不过，握手仍会失败。
pub fn load_gateway_mtls_server_config(
    cert_path: &Path,
    key_path: &Path,
    gateway_ca_pem: &str,
) -> Result<ServerConfig, String> {
    install_crypto_provider();
    let certs = certificate_chain_from_pem_file(cert_path)?;
    let key = private_key_from_pem_file(key_path)?;
    let mut roots = rustls::RootCertStore::empty();
    for anchor in CertificateDer::pem_slice_iter(gateway_ca_pem.as_bytes()) {
        let anchor = anchor.map_err(|err| format!("invalid gateway CA PEM: {err}"))?;
        roots
            .add(anchor)
            .map_err(|err| format!("failed to add gateway CA trust anchor: {err}"))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|err| format!("failed to build gateway client verifier: {err}"))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| format!("invalid TLS certificate or private key: {err}"))
}

/// 从**已完成握手**的服务端连接里取出已验证的客户端叶证书 DER。
///
/// `None` = 该连接没出示客户端证书（首次注册）或没开 mTLS；「链验过了但读不出网关身份」
/// 由应用层判 401，不在这里静默放行。
pub fn peer_leaf_certificate_der(conn: &rustls::server::ServerConnection) -> Option<Vec<u8>> {
    conn.peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| leaf.as_ref().to_vec())
}

fn certificate_chain_from_pem_file(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read TLS certificate {}: {err}", path.display()))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|err| format!("invalid TLS certificate PEM {}: {err}", path.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "TLS certificate {} contains no CERTIFICATE PEM block",
            path.display()
        ));
    }
    Ok(certs)
}

fn private_key_from_pem_file(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|err| format!("invalid TLS private key {}: {err}", path.display()))
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustls::RootCertStore;
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::infra::gateway_ca::GatewayCa;
    use crate::infra::gateway_ca::VerifiedGatewayIdentity;

    fn write_temp_pem(prefix: &str, content: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "wist-center-tls-{}-{}-{prefix}.pem",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, content).expect("write temp pem");
        path
    }

    /// 服务端从已完成 mTLS 握手里读回的客户端证书，能还原出网关身份。
    #[tokio::test]
    async fn mtls_server_reports_verified_gateway_identity() {
        // CA-G + 一张它签出的网关客户端证书（客户端保留私钥）。
        let (ca, ca_pem, _ca_key) = GatewayCa::generate("Wist Test Gateway CA").expect("ca");
        let client_key = rcgen::KeyPair::generate().expect("client key");
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&client_key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        let issued = ca
            .issue_client_certificate(&csr, "gw-mtls", 3600)
            .expect("issue");
        let client_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));

        // 服务端叶证书（自签，SAN=localhost）。
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("server cert");
        let cert_path = write_temp_pem("server-cert", &cert.pem());
        let key_path = write_temp_pem("server-key", &key_pair.serialize_pem());
        let server_config =
            load_gateway_mtls_server_config(&cert_path, &key_path, &ca_pem).expect("server config");
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let (stream, _) = listener.accept().await.map_err(|err| err.to_string())?;
            let tls = acceptor
                .accept(stream)
                .await
                .map_err(|err| format!("handshake: {err}"))?;
            peer_leaf_certificate_der(tls.get_ref().1)
                .ok_or_else(|| "server saw no client certificate".to_string())
        });

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.der().to_vec()))
            .expect("server anchor");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(issued.certificate_der.clone())],
                client_key_der,
            )
            .expect("client config");
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let _tls = TlsConnector::from(Arc::new(client_config))
            .connect(
                ServerName::try_from("localhost").expect("server name"),
                stream,
            )
            .await
            .expect("client handshake");

        let leaf = server
            .await
            .expect("join")
            .expect("server must see the client cert");
        let identity = VerifiedGatewayIdentity::from_certificate_der(&leaf).expect("identity");
        assert_eq!(identity.gateway_id, "gw-mtls");
        assert_eq!(identity.fingerprint_sha256, issued.fingerprint_sha256_hex);
    }

    #[test]
    fn rejects_a_missing_certificate_file() {
        let (ca, ca_pem, _key) = GatewayCa::generate("Wist Test Gateway CA").expect("ca");
        let _ = ca;
        let missing = std::env::temp_dir().join("wist-center-does-not-exist.pem");
        assert!(load_gateway_mtls_server_config(&missing, &missing, &ca_pem).is_err());
    }
}
