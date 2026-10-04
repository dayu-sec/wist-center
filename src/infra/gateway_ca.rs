//! 网关客户端证书的签发（中心当 **CA-G**）——网关对中心做 mTLS 的长期身份。
//!
//! 与网关侧 `infra/agent_ca.rs` 同口径，只是角色对调：那边网关给 agent 签，这里中心给网关签。
//! **每网关一张**证书（`subject` / URI SAN 绑定 `gateway_id`），CA-G 与中心服务器证书的 CA **单开**。
//!
//! 证书形态：`CA:FALSE`、`keyUsage=digitalSignature`、`EKU=clientAuth`、URI SAN；
//! CSR **只贡献公钥**——其声明的 subject/扩展一律忽略，主体由中心按 `gateway_id` 填。

use std::fmt;
use std::path::Path;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// `notBefore` 回拨（容忍两端时钟偏差）。
pub const CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS: i64 = 300;

/// URI SAN 前缀：`wist://gateway/<gateway_id>`。
pub const GATEWAY_URI_PREFIX: &str = "wist://gateway/";

/// 网关在证书里的 URI SAN。
pub fn gateway_uri(gateway_id: &str) -> String {
    format!("{GATEWAY_URI_PREFIX}{gateway_id}")
}

/// 从 URI SAN 还原 `gateway_id`。
pub fn gateway_id_from_uri(uri: &str) -> Option<String> {
    uri.strip_prefix(GATEWAY_URI_PREFIX)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

/// 由 mTLS 握手带进来、并**已由 CA-G 验链通过**的网关身份。
///
/// 与 [`GatewayCa`] 签出的证书同口径：`gateway_id` 直接取自 URI SAN，指纹/序列号/有效期
/// 供「证书与登记是否一致」的判定、吊销与审计使用（见 `api::gateway_ops`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGatewayIdentity {
    pub gateway_id: String,
    /// 证书 DER 的 SHA-256（小写 hex）。
    pub fingerprint_sha256: String,
    /// 证书序列号（小写 hex，无分隔符）。
    pub serial_hex: String,
    /// 证书生效时刻（RFC3339）。
    pub not_before: String,
    /// 证书到期时刻（RFC3339）。
    pub not_after: String,
}

impl VerifiedGatewayIdentity {
    /// 从**已验证**的客户端叶证书 DER 解出身份与有效期。
    ///
    /// 证书来自 rustls 的 `WebPkiClientVerifier`：链路、有效期与 `EKU=clientAuth` 已经过关，
    /// 这里只解主体（URI SAN → `gateway_id`）。
    pub fn from_certificate_der(certificate_der: &[u8]) -> Result<Self, String> {
        let (_, certificate) = X509Certificate::from_der(certificate_der)
            .map_err(|err| format!("failed to parse client certificate: {err}"))?;
        let gateway_id = gateway_id_from_certificate(&certificate)?;
        let validity = certificate.validity();
        Ok(Self {
            gateway_id,
            fingerprint_sha256: hex_lower(digest(&SHA256, certificate_der).as_ref()),
            serial_hex: hex_lower(certificate.raw_serial()),
            not_before: rfc3339_from_unix(validity.not_before.timestamp()),
            not_after: rfc3339_from_unix(validity.not_after.timestamp()),
        })
    }
}

/// 从已解析证书的 URI SAN 还原 `gateway_id`（没有网关 URI SAN 即报错）。
fn gateway_id_from_certificate(certificate: &X509Certificate<'_>) -> Result<String, String> {
    let san = certificate
        .subject_alternative_name()
        .map_err(|err| format!("failed to read client certificate SAN: {err}"))?
        .ok_or_else(|| "client certificate has no subject alternative name".to_string())?;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name
            && let Some(gateway_id) = gateway_id_from_uri(uri)
        {
            return Ok(gateway_id);
        }
    }
    Err("client certificate has no gateway URI SAN".to_string())
}

/// x509 的 `ASN1Time` 只给 unix 秒，这里统一走 chrono 输出 RFC3339。
fn rfc3339_from_unix(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| seconds.to_string())
}

/// 签出的网关客户端证书。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedGatewayCertificate {
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    /// 序列号（小写 hex，无分隔符）。
    pub serial_hex: String,
    /// 证书 DER 的 SHA-256（小写 hex），用于拒绝名单 / 日志。
    pub fingerprint_sha256_hex: String,
    /// RFC3339，已含 `notBefore` 回拨。
    pub not_before: String,
    /// RFC3339。
    pub not_after: String,
    /// 证书里填的 URI SAN，便于回执/排查。
    pub gateway_uri: String,
}

/// 独立的网关客户端证书 CA（CA-G）：只用于签网关 **客户端证书**，与中心服务器证书的 CA 分开。
///
/// 私钥只留中心；其根**不下发**给网关（网关不需要验自己）。
pub struct GatewayCa {
    /// 签发用的 CA 句柄。rcgen 0.13 的签名接口要一个 `Certificate`，只用它的主体 DN / key-id 方法
    /// （**不用它的 DER**），所以用同一把 CA 密钥自签一次得到句柄；签出的叶证书仍能被**原始 CA 证书**验证。
    issuer: Certificate,
    issuer_key: KeyPair,
    ca_certificate_pem: String,
}

impl fmt::Debug for GatewayCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `rcgen::Certificate` / `KeyPair` 不实现 Debug（也不该把私钥打出来）。
        f.debug_struct("GatewayCa")
            .field("ca_certificate_pem_len", &self.ca_certificate_pem.len())
            .finish_non_exhaustive()
    }
}

impl GatewayCa {
    /// 从证书 PEM + 私钥 PEM 载入。
    pub fn from_pem(ca_certificate_pem: &str, ca_key_pem: &str) -> Result<Self, String> {
        let params = CertificateParams::from_ca_cert_pem(ca_certificate_pem)
            .map_err(|err| format!("failed to parse gateway CA certificate: {err}"))?;
        let issuer_key = KeyPair::from_pem(ca_key_pem)
            .map_err(|err| format!("failed to parse gateway CA private key: {err}"))?;
        let issuer = params
            .self_signed(&issuer_key)
            .map_err(|err| format!("failed to load gateway CA as an issuer: {err}"))?;
        Ok(Self {
            issuer,
            issuer_key,
            ca_certificate_pem: ca_certificate_pem.to_string(),
        })
    }

    /// 从文件载入（证书 + 私钥）。
    pub fn load(ca_certificate_path: &Path, ca_key_path: &Path) -> Result<Self, String> {
        let ca_certificate_pem = std::fs::read_to_string(ca_certificate_path).map_err(|err| {
            format!(
                "failed to read gateway CA certificate {}: {err}",
                ca_certificate_path.display()
            )
        })?;
        let ca_key_pem = std::fs::read_to_string(ca_key_path).map_err(|err| {
            format!(
                "failed to read gateway CA private key {}: {err}",
                ca_key_path.display()
            )
        })?;
        Self::from_pem(&ca_certificate_pem, &ca_key_pem)
    }

    /// 生成一把新的自签 CA-G（首次置备时用）；返回 `(实例, 证书 PEM, 私钥 PEM)`。
    pub fn generate(common_name: &str) -> Result<(Self, String, String), String> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name.to_string());
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let key = KeyPair::generate().map_err(|err| format!("failed to generate CA key: {err}"))?;
        let certificate = params
            .self_signed(&key)
            .map_err(|err| format!("failed to self-sign gateway CA: {err}"))?;
        let certificate_pem = certificate.pem();
        let key_pem = key.serialize_pem();
        let ca = Self::from_pem(&certificate_pem, &key_pem)?;
        Ok((ca, certificate_pem, key_pem))
    }

    /// CA 证书 PEM（原样，用于上链 / 回执）。
    pub fn ca_certificate_pem(&self) -> &str {
        &self.ca_certificate_pem
    }

    /// 用 CSR 里的公钥签一张**网关专属**客户端证书。
    ///
    /// **CSR 只贡献公钥**：其 subject 与请求的扩展一律忽略，主体由中心按 `gateway_id` 填。
    pub fn issue_client_certificate(
        &self,
        csr_pem: &str,
        gateway_id: &str,
        ttl_seconds: i64,
    ) -> Result<IssuedGatewayCertificate, String> {
        if ttl_seconds <= 0 {
            return Err(format!(
                "client certificate ttl must be positive, got {ttl_seconds}"
            ));
        }
        if gateway_id.is_empty() {
            return Err("gateway_id must not be empty".to_string());
        }
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|err| format!("failed to parse certificate signing request: {err}"))?;

        let uri = gateway_uri(gateway_id);
        let mut distinguished_name = DistinguishedName::new();
        // CN 只作人类可读标签，权威身份在 URI SAN。
        distinguished_name.push(DnType::CommonName, gateway_id.to_string());

        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.subject_alt_names =
            vec![SanType::URI(uri.clone().try_into().map_err(|_| {
                format!("gateway URI is not a valid IA5 string: {uri}")
            })?)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::seconds(CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS);
        params.not_after = now + Duration::seconds(ttl_seconds);
        params.serial_number = Some(SerialNumber::from_slice(&random_serial_bytes()?));
        params.use_authority_key_identifier_extension = true;

        let certificate = params
            .signed_by(&csr.public_key, &self.issuer, &self.issuer_key)
            .map_err(|err| format!("failed to sign gateway client certificate: {err}"))?;
        let certificate_der = certificate.der().to_vec();
        // 序列号以**签出证书的 DER**为准（x509-parser 读回），保证与对端出示证书时的口径一致。
        let (_, parsed) = X509Certificate::from_der(&certificate_der)
            .map_err(|err| format!("failed to re-parse signed gateway certificate: {err}"))?;
        let serial_hex = hex_lower(parsed.raw_serial());

        Ok(IssuedGatewayCertificate {
            certificate_pem: certificate.pem(),
            fingerprint_sha256_hex: hex_lower(digest(&SHA256, &certificate_der).as_ref()),
            certificate_der,
            serial_hex,
            not_before: to_rfc3339(params_not_before(certificate.params())),
            not_after: to_rfc3339(params_not_after(certificate.params())),
            gateway_uri: uri,
        })
    }
}

/// 仅**校验 CSR 可解析**（不签发）——注册的**前置**校验：坏 CSR 不应白白消耗一次性注册 token。
pub fn validate_csr(csr_pem: &str) -> Result<(), String> {
    CertificateSigningRequestParams::from_pem(csr_pem)
        .map(|_| ())
        .map_err(|err| format!("failed to parse certificate signing request: {err}"))
}

/// 从文件载入 CA-G；缺失则**生成一把新的自签 CA-G 并落盘**（证书 0644 / 私钥 0600）。
///
/// **半在场**（只有证书或只有私钥）一律报错：不自动重生，以免换 CA 使已签出的网关证书全部失效。
pub fn load_or_create(cert_path: &Path, key_path: &Path) -> Result<GatewayCa, String> {
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => GatewayCa::load(cert_path, key_path),
        (false, false) => {
            let (ca, cert_pem, key_pem) = GatewayCa::generate("Wist Gateway Client CA")?;
            write_pem(cert_path, &cert_pem, 0o644)?;
            write_pem(key_path, &key_pem, 0o600)?;
            Ok(ca)
        }
        (true, false) | (false, true) => Err(format!(
            "网关客户端 CA 不完整：{} 与 {} 必须同时存在（缺一不自动重生，以免换 CA 使已签证书全部失效）",
            cert_path.display(),
            key_path.display()
        )),
    }
}

fn write_pem(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)
        .map_err(|err| format!("failed to write {}: {err}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|err| format!("failed to chmod {}: {err}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))
}

fn random_serial_bytes() -> Result<[u8; 16], String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "failed to read system random source".to_string())?;
    // DER 的 INTEGER 不允许前导 0（否则会被当成非最小编码）；首位清零仍留 127 位熵。
    bytes[0] &= 0x7f;
    Ok(bytes)
}

fn params_not_before(params: &CertificateParams) -> OffsetDateTime {
    params.not_before
}

fn params_not_after(params: &CertificateParams) -> OffsetDateTime {
    params.not_after
}

fn to_rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| value.to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use rcgen::KeyPair;
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    fn csr() -> String {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "gw-1");
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    fn common_name(der: &[u8]) -> Option<String> {
        let (_, parsed) = X509Certificate::from_der(der).expect("parse");
        parsed
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string)
    }

    #[test]
    fn issues_a_client_certificate_with_gateway_uri_san() {
        let (ca, _ca_pem, _key) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        let issued = ca
            .issue_client_certificate(&csr(), "gw-1", 3600)
            .expect("issue");
        assert_eq!(issued.gateway_uri, "wist://gateway/gw-1");
        assert!(!issued.serial_hex.is_empty());
        assert_eq!(issued.fingerprint_sha256_hex.len(), 64);

        // 证书里能读回 URI SAN，且 CN = gateway_id（CSR 主体被忽略）。
        let (_, parsed) = X509Certificate::from_der(&issued.certificate_der).expect("parse");
        let uri = parsed
            .subject_alternative_name()
            .expect("san ext")
            .expect("san")
            .value
            .general_names
            .iter()
            .find_map(|name| match name {
                GeneralName::URI(uri) => Some(*uri),
                _ => None,
            })
            .expect("uri san");
        assert_eq!(gateway_id_from_uri(uri).as_deref(), Some("gw-1"));
        assert_eq!(
            common_name(&issued.certificate_der).as_deref(),
            Some("gw-1")
        );
    }

    #[test]
    fn rejects_empty_gateway_id_and_bad_ttl() {
        let (ca, _pem, _key) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        assert!(ca.issue_client_certificate(&csr(), "", 3600).is_err());
        assert!(ca.issue_client_certificate(&csr(), "gw-1", 0).is_err());
        assert!(
            ca.issue_client_certificate("not a csr", "gw-1", 3600)
                .is_err()
        );
    }

    #[test]
    fn ignores_the_csr_subject() {
        let (ca, _pem, _key) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        let issued = ca
            .issue_client_certificate(&csr(), "gw-2", 3600)
            .expect("issue");
        assert_eq!(
            common_name(&issued.certificate_der).as_deref(),
            Some("gw-2")
        );
    }

    /// 对端出示签出证书时，能从 DER 还原出与签发同口径的身份（指纹 / 序列号 / gateway_id）。
    #[test]
    fn verified_identity_matches_the_issued_certificate() {
        let (ca, _pem, _key) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        let issued = ca
            .issue_client_certificate(&csr(), "gw-7", 3600)
            .expect("issue");
        let identity = VerifiedGatewayIdentity::from_certificate_der(&issued.certificate_der)
            .expect("identity");
        assert_eq!(identity.gateway_id, "gw-7");
        assert_eq!(identity.fingerprint_sha256, issued.fingerprint_sha256_hex);
        assert_eq!(identity.serial_hex, issued.serial_hex);
        assert!(!identity.serial_hex.is_empty());
        assert!(identity.not_before <= identity.not_after);
    }

    #[test]
    fn verified_identity_rejects_a_certificate_without_a_gateway_uri() {
        assert!(VerifiedGatewayIdentity::from_certificate_der(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn round_trips_the_ca_pem() {
        let (ca, ca_pem, key_pem) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        let reloaded = GatewayCa::from_pem(&ca_pem, &key_pem).expect("reload");
        assert_eq!(reloaded.ca_certificate_pem(), ca.ca_certificate_pem());
    }

    #[test]
    fn validate_csr_accepts_a_real_csr_and_rejects_garbage() {
        assert!(validate_csr(&csr()).is_ok());
        assert!(validate_csr("not a csr").is_err());
        assert!(validate_csr("").is_err());
    }

    #[test]
    fn load_or_create_generates_then_reloads_and_refuses_half_present_material() {
        let dir = std::env::temp_dir().join(format!(
            "wic-gateway-ca-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let cert = dir.join("gateway-client-ca.pem");
        let key = dir.join("gateway-client-ca.key.pem");

        // 首次：两文件都生成；再次：载入同一把 CA（证书不变）。
        let first = load_or_create(&cert, &key).expect("create");
        assert!(cert.exists() && key.exists());
        let again = load_or_create(&cert, &key).expect("reload");
        assert_eq!(first.ca_certificate_pem(), again.ca_certificate_pem());

        // 半在场（只剩证书）→ 报错，且**不自动重生私钥**。
        std::fs::remove_file(&key).expect("rm key");
        assert!(load_or_create(&cert, &key).is_err());
        assert!(
            !key.exists(),
            "不得自动重生私钥（否则已签网关证书全部失效）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
