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
        params.subject_alt_names = vec![SanType::URI(
            uri.clone()
                .try_into()
                .map_err(|_| format!("gateway URI is not a valid IA5 string: {uri}"))?,
        )];
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
        let serial_bytes = certificate
            .params()
            .serial_number
            .as_ref()
            .map(SerialNumber::to_bytes)
            .unwrap_or_default();

        Ok(IssuedGatewayCertificate {
            certificate_pem: certificate.pem(),
            fingerprint_sha256_hex: hex_lower(digest(&SHA256, &certificate_der).as_ref()),
            certificate_der,
            serial_hex: hex_lower(&serial_bytes),
            not_before: to_rfc3339(params_not_before(certificate.params())),
            not_after: to_rfc3339(params_not_after(certificate.params())),
            gateway_uri: uri,
        })
    }
}

fn random_serial_bytes() -> Result<[u8; 16], String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "failed to read system random source".to_string())?;
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
        assert_eq!(common_name(&issued.certificate_der).as_deref(), Some("gw-1"));
    }

    #[test]
    fn rejects_empty_gateway_id_and_bad_ttl() {
        let (ca, _pem, _key) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        assert!(ca.issue_client_certificate(&csr(), "", 3600).is_err());
        assert!(ca.issue_client_certificate(&csr(), "gw-1", 0).is_err());
        assert!(ca.issue_client_certificate("not a csr", "gw-1", 3600).is_err());
    }

    #[test]
    fn ignores_the_csr_subject() {
        let (ca, _pem, _key) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        let issued = ca
            .issue_client_certificate(&csr(), "gw-2", 3600)
            .expect("issue");
        assert_eq!(common_name(&issued.certificate_der).as_deref(), Some("gw-2"));
    }

    #[test]
    fn round_trips_the_ca_pem() {
        let (ca, ca_pem, key_pem) = GatewayCa::generate("Wist Gateway Client CA").expect("ca");
        let reloaded = GatewayCa::from_pem(&ca_pem, &key_pem).expect("reload");
        assert_eq!(reloaded.ca_certificate_pem(), ca.ca_certificate_pem());
    }
}
