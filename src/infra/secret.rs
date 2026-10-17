// 密钥工具：sha256 / 随机 token / RegistToken 派生（与 wist-gateway 一致的实现）。

use ring::{hmac, rand as ring_rand};

pub fn sha256_hex(value: &str) -> String {
    sha256_hex_bytes(value.as_bytes())
}

/// 字节 sha256（裸 hex）—— 直接委托共享 crate（口径与网关侧同一份）。
pub fn sha256_hex_bytes(bytes: &[u8]) -> String {
    wist_release::package::sha256_hex_bytes(bytes)
}

/// 生成 32 字节随机 secret token：`"{prefix}_{hex}"`（镜像 wist-gateway）。
pub fn new_secret_token(prefix: &str) -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    let rng = ring_rand::SystemRandom::new();
    ring_rand::SecureRandom::fill(&rng, &mut bytes)
        .map_err(|_| "failed to read system random source".to_string())?;
    Ok(format!("{prefix}_{}", hex_lower(&bytes)))
}

/// 由网关身份 Token（identity_token）派生一次性注册凭据 RegistToken：
/// `HMAC-SHA256(center_secret, "gateway-reg:{gateway_id}:{identity_token}")` 的 hex。
/// 派生确定性 + 网关/身份/密钥三重绑定；中心只存结果 hash，不重算。
pub fn derive_regist_token(secret: &str, gateway_id: &str, identity_token: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut data = String::with_capacity(
        secret.len() + gateway_id.len() + identity_token.len() + "gateway-reg::".len(),
    );
    data.push_str("gateway-reg:");
    data.push_str(gateway_id);
    data.push(':');
    data.push_str(identity_token);
    hex_lower(hmac::sign(&key, data.as_bytes()).as_ref())
}

/// 手动升级脚本的**短命签名**（无状态 token）：
/// `HMAC-SHA256(center_secret, "upgrade-script:{gateway_id}:{component}:{version}:{expires}")` 的 hex。
///
/// `curl ... | bash` 的 URL 里只带它 + `expires`，**不把 admin token 塞进 URL**；
/// 网关面端点据此校验「这条命令确实是中心管理面为这台网关生成的、且没过期」。
pub fn derive_upgrade_script_token(
    secret: &str,
    gateway_id: &str,
    component: &str,
    version: &str,
    expires: i64,
) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let data = upgrade_script_payload(gateway_id, component, version, expires);
    hex_lower(hmac::sign(&key, data.as_bytes()).as_ref())
}

/// 校验短命签名（常量时间比较 hex 字符串）。
pub fn verify_upgrade_script_token(
    secret: &str,
    gateway_id: &str,
    component: &str,
    version: &str,
    expires: i64,
    signature: &str,
) -> bool {
    let expected = derive_upgrade_script_token(secret, gateway_id, component, version, expires);
    constant_time_eq(expected.as_bytes(), signature.as_bytes())
}

/// 常量时间比较（长度不等直接 false；相等长度下不提前返回）。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn upgrade_script_payload(
    gateway_id: &str,
    component: &str,
    version: &str,
    expires: i64,
) -> String {
    format!("upgrade-script:{gateway_id}:{component}:{version}:{expires}")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn new_secret_token_has_prefix_and_is_unique() {
        let token = new_secret_token("link").expect("token");
        assert!(token.starts_with("link_"), "prefix mismatch: {token}");
        assert_eq!(token.len(), "link_".len() + 64, "expected 32 bytes hex");
        assert_ne!(token, new_secret_token("link").expect("token2"));
        assert_ne!(
            new_secret_token("link").expect("a"),
            new_secret_token("reg").expect("b")
        );
    }

    #[test]
    fn derive_regist_token_matches_known_vector() {
        assert_eq!(
            derive_regist_token("center-secret", "gw-001", "identity-1"),
            "61b5cd8d58a745651723f144e06fd83f2aac9b8071c188b12108fde5f6c48c02"
        );
    }

    #[test]
    fn derive_regist_token_is_deterministic_and_bound() {
        let base = derive_regist_token("sec", "gw-001", "id-1");
        assert_eq!(base, derive_regist_token("sec", "gw-001", "id-1"));
        // 三重绑定：换密钥 / 换网关 / 换身份 → 均不同。
        assert_ne!(base, derive_regist_token("other", "gw-001", "id-1"));
        assert_ne!(base, derive_regist_token("sec", "gw-002", "id-1"));
        assert_ne!(base, derive_regist_token("sec", "gw-001", "id-2"));
    }

    #[test]
    fn upgrade_script_token_is_bound_and_verifiable() {
        let token = derive_upgrade_script_token("sec", "gw-1", "wist-gwlinkd", "v0.12.0", 100);
        assert_eq!(
            token,
            derive_upgrade_script_token("sec", "gw-1", "wist-gwlinkd", "v0.12.0", 100)
        );
        assert!(verify_upgrade_script_token(
            "sec",
            "gw-1",
            "wist-gwlinkd",
            "v0.12.0",
            100,
            &token
        ));
        // 换密钥 / 网关 / 组件 / 版本 / 过期时刻 / 签名 → 均不通过。
        for (secret, gateway, component, version, expires) in [
            ("other", "gw-1", "wist-gwlinkd", "v0.12.0", 100),
            ("sec", "gw-2", "wist-gwlinkd", "v0.12.0", 100),
            ("sec", "gw-1", "wist-gateway-stack", "v0.12.0", 100),
            ("sec", "gw-1", "wist-gwlinkd", "v0.13.0", 100),
            ("sec", "gw-1", "wist-gwlinkd", "v0.12.0", 101),
        ] {
            assert!(!verify_upgrade_script_token(
                secret, gateway, component, version, expires, &token
            ));
        }
        assert!(!verify_upgrade_script_token(
            "sec",
            "gw-1",
            "wist-gwlinkd",
            "v0.12.0",
            100,
            "deadbeef"
        ));
    }
}
