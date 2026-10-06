//! 升级包「来源 → 校验 → 内容寻址」的**纯逻辑内核**（center 侧）。
//!
//! ⚠️ 本模块与 `wist-gateway/src/api/install_package.rs` 的内核**刻意重复**：两侧要的是同一套口径
//! （来源可为本机路径 / https、读到的字节算 sha256、内容寻址 id、按期望摘要校验），但各自的
//! **存储 / 端点 / 鉴权 / 来源策略**不同 —— 抽成一个共享大模块会把两侧焊死。
//! 将来第三处也要用、或这套口径开始频繁演进时，再抽成一个小纯逻辑 crate
//! （见 `wist-design/doc/design/edge/gateway-upgrade-and-releases.md` §7）。

use std::time::Duration;

use crate::infra::secret::sha256_hex_bytes;

/// 拉取来源的超时（与网关侧同口径）。
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// 单包大小上限（与网关侧同口径，防误拉一个大文件把内存吃光）。
const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;

/// 取包失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// 来源读不到（路径不存在 / URL 拉不到 / 超限）。
    SourceUnavailable(String),
    /// 与期望摘要不符。
    DigestMismatch(String),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageError::SourceUnavailable(detail) => write!(f, "{detail}"),
            PackageError::DigestMismatch(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for PackageError {}

/// 内容寻址 id：`pkg-<sha256 前 16 位>`（裸 hex）。与网关侧同式。
pub fn package_id_for_sha256(sha256_hex: &str) -> String {
    let prefix: String = sha256_hex.chars().take(16).collect();
    format!("pkg-{prefix}")
}

/// 读来源（**本机绝对路径** 或 https URL）→ 字节。
///
/// 「本机路径」是允许且常见的：包可能就在中心机上、外网访问不到，或还在开发
/// （与网关侧 `read_source` 同一取舍；见 `agent-upgrade-and-packages.md` §2）。
pub async fn read_package_source(source: &str) -> Result<Vec<u8>, PackageError> {
    if source.starts_with('/') {
        return std::fs::read(source).map_err(|err| {
            PackageError::SourceUnavailable(format!("failed to read package from {source}: {err}"))
        });
    }
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|err| {
            PackageError::SourceUnavailable(format!("failed to build http client: {err}"))
        })?;
    let response = client.get(source).send().await.map_err(|err| {
        PackageError::SourceUnavailable(format!("failed to fetch package from {source}: {err}"))
    })?;
    if !response.status().is_success() {
        return Err(PackageError::SourceUnavailable(format!(
            "package source {source} returned HTTP {}",
            response.status()
        )));
    }
    if let Some(len) = response.content_length()
        && len > MAX_PACKAGE_BYTES
    {
        return Err(PackageError::SourceUnavailable(format!(
            "package at {source} is {len} bytes, over the {MAX_PACKAGE_BYTES} byte limit"
        )));
    }
    let bytes = response.bytes().await.map_err(|err| {
        PackageError::SourceUnavailable(format!("failed to read package body from {source}: {err}"))
    })?;
    if bytes.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(PackageError::SourceUnavailable(format!(
            "package at {source} is {} bytes, over the {MAX_PACKAGE_BYTES} byte limit",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

/// 目标三元组的已知架构前缀（与网关侧 `install_package.rs` 同表）。
/// 版本自身可能带 `-`（预发布，如 `0.2.0-beta.1`），不能简单按第一个 `-` 切。
const KNOWN_TRIPLE_ARCHES: &[&str] = &[
    "aarch64",
    "x86_64",
    "i686",
    "i586",
    "armv7",
    "armv6",
    "arm",
    "riscv64",
    "powerpc64",
    "powerpc64le",
    "s390x",
    "x86_64h",
    "loongarch64",
];

/// 从「包来源」（本机路径 / URL）与包字节里读出 `(version, arch)`，读不出返回 `("", "")`。
///
/// 覆盖当前三类安装包：
/// 1. **agentd 包**：`wist-agentd-<version>-<triple>.tar.gz`，顶层一层同名目录 → 目录名带身份。
/// 2. **gateway-stack 包**：`wist-gateway-stack-<version>.tar.gz`，顶层是 `sys/…`（git archive，无包装目录）
///    → 目录名读不出，**回落用来源文件名**。
/// 3. **gops / gx 包**：`gops-<version>-<triple>.tar.gz` 之类 → 目录名或文件名均可。
///
/// 都读不出（临时文件名、无版本号、非 gzip 字节）一律返回空串而**不报错**：
/// 这些包仍能被托管与分发，只是版本自述留空；让录入整体失败反而会阻断升级。
pub fn read_package_identity(source: &str, bytes: &[u8]) -> (String, String) {
    // 先看包内首条目目录名（正规二进制包在这里带身份）。
    if let Some(dir) = first_tar_entry_component(bytes) {
        let identity = parse_package_name(&dir);
        if !identity.0.is_empty() {
            return identity;
        }
    }
    // 回落用来源末段（部署栈包顶层不带身份，但文件名带版本）。
    parse_package_name(source_basename(source))
}

/// 版本比对用归一：忽略首尾空白与可选的 `v` 前缀（包内自报常按 git tag 带 `v`）。
pub fn normalize_version(value: &str) -> String {
    value.trim().trim_start_matches('v').to_string()
}

/// 取来源的末段（路径 / URL 的文件名），并剥掉查询串 / fragment。
fn source_basename(source: &str) -> &str {
    let without_query = source.split(['?', '#']).next().unwrap_or(source);
    without_query.rsplit('/').next().unwrap_or(without_query)
}

/// gzip + tar 解出第一个条目路径的首段（如 `wist-agentd-0.1.9-aarch64-apple-darwin`）。
/// 任何一步失败都返回 `None`，绝不 panic。
fn first_tar_entry_component(bytes: &[u8]) -> Option<String> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = archive.entries().ok()?;
    let entry = entries.next()?.ok()?;
    let path = entry.path().ok()?;
    // 跳过 `./` / `/` 之类非普通段，取第一个普通目录名。
    path.components().find_map(|component| match component {
        std::path::Component::Normal(name) => name.to_str().map(str::to_string),
        _ => None,
    })
}

/// 从形如 `<name>-<version>[-<target-triple>][<压缩后缀>]` 的串里切出 `(version, triple)`。
///
/// 不写死组件名：
/// - 先剥压缩后缀；
/// - 以「某段起头是已知架构名」定位 target-triple（版本自身可能带 `-`，如 `v0.2.0-beta.1`，
///   不能按第一个 `-` 切）；
/// - 版本取「第一个形如 `v?N.N…` 的段」到三元组之前（保留其后的预发布后缀）。
///
/// 切不出返回 `("", "")`。
fn parse_package_name(name: &str) -> (String, String) {
    let name = strip_archive_suffix(name);
    let (version_part, arch) = match triple_start(name) {
        Some(index) => (&name[..index], name[index + 1..].to_string()),
        None => (name, String::new()),
    };
    match version_start(version_part) {
        Some(index) => (version_part[index..].to_string(), arch),
        None => (String::new(), String::new()),
    }
}

/// target-triple 起始的 `-` 下标（其后即三元组）。取**最靠前**的已知架构名。
fn triple_start(name: &str) -> Option<usize> {
    for (index, _) in name.match_indices('-') {
        let candidate = &name[index + 1..];
        let arch_head = candidate.split('-').next().unwrap_or("");
        if KNOWN_TRIPLE_ARCHES.contains(&arch_head) {
            return Some(index);
        }
    }
    None
}

/// 第一个「像版本号」的段在串中的字节下标，用于跳过包名前缀。
fn version_start(name: &str) -> Option<usize> {
    let mut offset = 0;
    for segment in name.split('-') {
        if looks_like_version(segment) {
            return Some(offset);
        }
        offset += segment.len() + 1;
    }
    None
}

/// 段是否像版本号：可选 `v` 前缀 + 至少 `N.N`（`1234`、`2024-10` 这类不算）。
fn looks_like_version(segment: &str) -> bool {
    let rest = segment.strip_prefix(['v', 'V']).unwrap_or(segment);
    let mut parts = rest.split('.');
    let (Some(head), Some(second)) = (parts.next(), parts.next()) else {
        return false;
    };
    !head.is_empty()
        && head.chars().all(|ch| ch.is_ascii_digit())
        && second.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}

/// 剥掉常见压缩 / 归档后缀（只剥一层，够用）。
fn strip_archive_suffix(name: &str) -> &str {
    for suffix in [
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tar", ".gz", ".zip", ".bin",
    ] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped;
        }
    }
    name
}

/// 读来源 → 校验期望摘要（可带 `sha256:` 前缀），返回（字节, 裸 hex sha256）。
pub async fn read_verified_package(
    source: &str,
    expected_sha256: Option<&str>,
) -> Result<(Vec<u8>, String), PackageError> {
    let bytes = read_package_source(source).await?;
    let actual = sha256_hex_bytes(&bytes);
    if let Some(expected) = expected_sha256 {
        let expected_hex = expected
            .strip_prefix("sha256:")
            .unwrap_or(expected)
            .to_ascii_lowercase();
        if actual != expected_hex {
            return Err(PackageError::DigestMismatch(format!(
                "package sha256 mismatch: expected {expected_hex} got {actual}"
            )));
        }
    }
    Ok((bytes, actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一个只含单条目的 gzip+tar（顶层目录名 + 一个同名文件），用于验包身份解析。
    fn tar_gz_with_entry(entry: &str, payload: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, entry, payload)
                .expect("append tar entry");
            builder.finish().expect("finish tar");
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar_bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    #[test]
    fn package_id_is_stable_prefixed_and_digest_sized() {
        let id = package_id_for_sha256("0123456789abcdef0123");
        assert_eq!(id, "pkg-0123456789abcdef");
        assert_eq!(id, package_id_for_sha256("0123456789abcdef0123"));
    }

    #[tokio::test]
    async fn reads_a_local_path_and_verifies_the_expected_digest() {
        let path = std::env::temp_dir().join("wic-pkg-src.bin");
        std::fs::write(&path, b"payload").expect("write");
        let source = path.to_string_lossy().to_string();

        let (bytes, sha) = read_verified_package(&source, None).await.expect("read");
        assert_eq!(bytes, b"payload");
        assert_eq!(sha.len(), 64);

        // 期望摘要一致 → 通过；不一致（含带 `sha256:` 前缀的形式）→ DigestMismatch。
        read_verified_package(&source, Some(&sha))
            .await
            .expect("matching digest");
        read_verified_package(&source, Some(&format!("sha256:{sha}")))
            .await
            .expect("prefixed digest");
        let err = read_verified_package(&source, Some("deadbeef"))
            .await
            .expect_err("mismatch");
        assert!(matches!(err, PackageError::DigestMismatch(_)), "{err}");

        // 路径不存在 → SourceUnavailable。
        let err = read_package_source("/definitely/not/here.bin")
            .await
            .expect_err("missing");
        assert!(matches!(err, PackageError::SourceUnavailable(_)), "{err}");

        let _ = std::fs::remove_file(path);
    }

    /// 身份解析（目录名）：agentd 包 / 通用二进制包从**包内首条目目录名**切出 `(version, arch)`。
    /// 版本带 `v`、带预发布后缀（含 `-`）也能切。
    #[test]
    fn read_package_identity_parses_binary_package_dir() {
        let cases = [
            (
                "wist-agentd-0.1.32-aarch64-apple-darwin/wist-agentd",
                ("0.1.32", "aarch64-apple-darwin"),
            ),
            (
                "wist-agentd-v0.2.0-beta.1-x86_64-unknown-linux-gnu/wist-agentd",
                ("v0.2.0-beta.1", "x86_64-unknown-linux-gnu"),
            ),
            // gops / gx 包（工具链）——同样不写死组件名。
            (
                "gops-v0.18.2-aarch64-apple-darwin/gops",
                ("v0.18.2", "aarch64-apple-darwin"),
            ),
            (
                "gx-v0.15.1-x86_64-unknown-linux-gnu/gx",
                ("v0.15.1", "x86_64-unknown-linux-gnu"),
            ),
        ];
        for (entry, expected) in cases {
            let bytes = tar_gz_with_entry(entry, b"bin");
            assert_eq!(
                read_package_identity(entry, &bytes),
                (expected.0.to_string(), expected.1.to_string()),
                "entry {entry}"
            );
        }
    }

    /// 身份解析（来源文件名）：gateway-stack 包顶层是 `sys/…`（无包装目录），
    /// 身份只能在**文件名**里；同时也验 URL 带查询串 / 本地路径两种来源写法。
    #[test]
    fn read_package_identity_falls_back_to_the_source_name() {
        // 部署栈包：包内首条目是 sys/…，目录名读不出 → 回落文件名。
        let stack = tar_gz_with_entry("sys/sys_model.yml", b"model");
        for source in [
            "/opt/pkgs/wist-gateway-stack-v0.1.17.tar.gz",
            "https://github.com/dayu-sec/wist/releases/download/v0.1.17/wist-gateway-stack-v0.1.17.tar.gz",
        ] {
            assert_eq!(
                read_package_identity(source, &stack),
                ("v0.1.17".to_string(), String::new()),
                "source {source}"
            );
        }
        // URL 带查询串 / fragment 也要剔掉。
        assert_eq!(
            read_package_identity(
                "https://x/gops-v0.18.2-aarch64-apple-darwin.tar.gz?sig=1",
                &stack
            ),
            ("v0.18.2".to_string(), "aarch64-apple-darwin".to_string())
        );
    }

    /// 读不出身份的一律返回空串而不报错：裸目录 / 无版本号名 / 纯数字名 / 非 gzip 字节。
    #[test]
    fn read_package_identity_returns_empty_for_unreadable_packages() {
        // 包内目录名读不出、文件名也无版本号。
        let bytes = tar_gz_with_entry("sys/sys_model.yml", b"x");
        for source in [
            "/opt/pkgs/wist-gateway-stack-notes.tar.gz",
            "/tmp/wic-rel-1728000000000000000.tar.gz",
            "download-1234.bin",
        ] {
            assert_eq!(
                read_package_identity(source, &bytes),
                (String::new(), String::new()),
                "source {source}"
            );
        }
        // 非 gzip：裸二进制不应 panic，也只回空串。
        assert_eq!(
            read_package_identity("/opt/pkgs/thing.tar.gz", b"not a gzip stream"),
            (String::new(), String::new())
        );
    }

    /// 版本归一：去空白、去可选 `v` 前缀后可比对；不同版本必须不等。
    #[test]
    fn normalize_version_ignores_whitespace_and_leading_v() {
        assert_eq!(normalize_version(" v0.1.32 "), normalize_version("0.1.32"));
        assert_ne!(normalize_version("0.1.32"), normalize_version("0.1.33"));
    }
}
