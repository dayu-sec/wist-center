//! GitHub Release 解析：从 release 页面 URL 拉出 tag（版本）与各平台制品地址（含 sha256）。
//!
//! 供「录入安装包」页一键填充多平台制品：输入
//! `https://github.com/<owner>/<repo>/releases/tag/<tag>` → 返回 `{version, assets[]}`，
//! 每个 asset 带 `artifact_url`（`browser_download_url`）、`sha256`（GitHub 资产 `digest`，
//! 缺失为 `None`）与 `platform`（完整 target-triple，如 `aarch64-apple-darwin`；解析不出为 `None`）。
//!
//! 鉴权：公开仓可匿名（受 GitHub 匿名限流 60/h 约束）；私有仓 / 提高限流可设
//! `WIST_CENTER_GITHUB_TOKEN`（或回退 `GITHUB_TOKEN`）环境变量。

use std::time::Duration;

use serde::Deserialize;

const GITHUB_API: &str = "https://api.github.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 解析结果：版本（= release tag）与制品清单。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedRelease {
    pub version: String,
    pub assets: Vec<ResolvedAsset>,
}

/// 单个制品：地址 + 摘要 + 平台槽位。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedAsset {
    pub name: String,
    pub artifact_url: String,
    /// GitHub 资产摘要（`sha256:<hex>` 去掉前缀的裸小写 hex）；缺失为 `None`。
    pub sha256: Option<String>,
    /// 完整 target-triple（如 `aarch64-apple-darwin` / `x86_64-unknown-linux-musl`）；
    /// 文件名解析不出为 `None`。
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    /// 例：`sha256:3f9a…`（GitHub 2024 起为资产提供摘要；旧资产可能没有）。
    #[serde(default)]
    digest: Option<String>,
}

/// 从 release 页面 URL 解析出 `(owner, repo, tag)`；
/// 只认 `[https://]github.com/<owner>/<repo>/releases/tag/<tag>`（忽略 query / fragment / 末尾斜杠）。
fn parse_release_url(url: &str) -> Option<(String, String, String)> {
    let url = url.trim();
    let url = url.split(['?', '#']).next().unwrap_or(url);
    let url = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
        .or_else(|| url.strip_prefix("github.com/"))?;
    let url = url.trim_end_matches('/');
    let mut parts = url.splitn(3, '/');
    let owner = parts.next().filter(|value| !value.is_empty())?;
    let repo = parts.next().filter(|value| !value.is_empty())?;
    let rest = parts.next()?;
    let tag = rest.strip_prefix("releases/tag/")?;
    if tag.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string(), tag.to_string()))
}

/// release 页面 URL 对应的 `owner/repo`（认不出为 `None`）。
/// 用于把「手工粘贴的 GitHub 地址」对到 `[packages.sources]` 里的那个组件（进而拿到它的镜像通道）。
pub fn release_repo(url: &str) -> Option<String> {
    let (owner, repo, _) = parse_release_url(url)?;
    Some(format!("{owner}/{repo}"))
}

/// 一条 release 的摘要（自动探测「最新版本」用，不下载资产）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct GitHubReleaseSummary {
    pub tag: String,
    pub published_at: Option<String>,
    pub prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct GitHubReleaseListItem {
    tag_name: String,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}

/// 列 GitHub releases（API 顺序 = 最新在前，最多 `limit` 条；跳过 draft）。
///
/// 自动探测最新版本用它：一次 API 请求就能拿到最新 tag，再按 tag 拉资产。
/// 公开仓匿名即可；私有仓 / 限流用 `WIST_CENTER_GITHUB_TOKEN`。
pub async fn list_github_releases(
    repo: &str,
    token: Option<&str>,
    limit: usize,
) -> Result<Vec<GitHubReleaseSummary>, String> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| format!("not a GitHub repo (expected owner/repo): {repo}"))?;
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|err| format!("failed to build http client: {err}"))?;
    let api = format!(
        "{GITHUB_API}/repos/{owner}/{name}/releases?per_page={}",
        limit.clamp(1, 100)
    );
    let mut request = client
        .get(&api)
        .header("user-agent", "wist-center")
        .header("accept", "application/vnd.github+json");
    if let Some(token) = token.filter(|value| !value.is_empty()) {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = request
        .send()
        .await
        .map_err(|err| format!("failed to reach GitHub: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "GitHub API returned {} for {owner}/{name} releases",
            response.status()
        ));
    }
    let items: Vec<GitHubReleaseListItem> = response
        .json()
        .await
        .map_err(|err| format!("failed to parse GitHub releases payload: {err}"))?;
    Ok(items
        .into_iter()
        .filter(|item| !item.draft)
        .map(|item| GitHubReleaseSummary {
            tag: item.tag_name,
            published_at: item.published_at,
            prerelease: item.prerelease,
        })
        .collect())
}

/// 解析 GitHub release：拉 tag 与资产清单。`token` 为空则匿名请求。
///
/// `artifact_proxy` = 该组件配的镜像/加速通道（`[packages.sources].github_proxy`）：
/// 非空时每个 `artifact_url` 写成 `<通道>/<github 原地址>`（与 COS 同理：**记录进去的就是镜像地址**，
/// 安装脚本只管照 URL 下载）。`None` → 直连 github.com。
///
/// **tag 带不带 `v` 都接受**：录入页的版本号来自包身份（如知识库 `0.3.0`），而 GitHub tag
/// 通常是 `v0.3.0`。先按原样查；404 时再试另一种写法（带 v / 去 v），避免为前缀差异手工改版本。
pub async fn resolve_github_release(
    release_url: &str,
    token: Option<&str>,
    artifact_proxy: Option<&str>,
) -> Result<ResolvedRelease, String> {
    let (owner, repo, tag) = parse_release_url(release_url).ok_or_else(|| {
        "not a GitHub release URL (expected https://github.com/<owner>/<repo>/releases/tag/<tag>)"
            .to_string()
    })?;
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|err| format!("failed to build http client: {err}"))?;

    let mut last_error = None;
    for candidate in tag_candidates(&tag) {
        match fetch_github_release(&client, &owner, &repo, &candidate, token).await {
            Ok(release) => return Ok(map_release(release, artifact_proxy)),
            Err((status, message)) => {
                last_error = Some(message);
                // 只有 404 值得换一种 tag 写法；403 / 429 / 5xx 换写法也没用。
                if status.as_u16() != 404 {
                    break;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| format!("failed to resolve {owner}/{repo}@{tag}")))
}

/// tag 的候选写法：原样优先，再试带 / 去 `v`。
fn tag_candidates(tag: &str) -> Vec<String> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Vec::new();
    }
    if let Some(stripped) = tag.strip_prefix('v') {
        if stripped.is_empty() {
            vec![tag.to_string()]
        } else {
            vec![tag.to_string(), stripped.to_string()]
        }
    } else {
        vec![tag.to_string(), format!("v{tag}")]
    }
}

/// 单次按 tag 取 release；失败时带 HTTP 状态码，供调用方决定要不要换写法。
async fn fetch_github_release(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    tag: &str,
    token: Option<&str>,
) -> Result<GitHubRelease, (reqwest::StatusCode, String)> {
    let api = format!("{GITHUB_API}/repos/{owner}/{repo}/releases/tags/{tag}");
    let mut request = client
        .get(&api)
        .header("user-agent", "wist-center")
        .header("accept", "application/vnd.github+json");
    if let Some(token) = token.filter(|value| !value.is_empty()) {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = request.send().await.map_err(|err| {
        (
            reqwest::StatusCode::BAD_GATEWAY,
            format!("failed to reach GitHub: {err}"),
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err((
            status,
            format!("GitHub API returned {status} for {owner}/{repo}@{tag}"),
        ));
    }
    response.json().await.map_err(|err| {
        (
            status,
            format!("failed to parse GitHub release payload: {err}"),
        )
    })
}

/// `GitHubRelease` → 解析结果：从文件名读平台槽位、从 `digest` 读 sha256，
/// 并按需把地址套上镜像通道（`<通道>/<原地址>`）。
fn map_release(release: GitHubRelease, artifact_proxy: Option<&str>) -> ResolvedRelease {
    let assets = release
        .assets
        .into_iter()
        .map(|asset| {
            // 从**文件名**读完整 target-triple（复用宽松口径，回落文件名）；读不出即为 None。
            let (_, arch) = crate::infra::read_package_identity(&asset.name, &[]);
            let platform = (!arch.is_empty()).then_some(arch);
            // `sha256:<hex>` → 裸小写 hex。
            let sha256 = asset
                .digest
                .as_deref()
                .and_then(|digest| digest.strip_prefix("sha256:"))
                .map(|hex| hex.trim().to_ascii_lowercase())
                .filter(|hex| !hex.is_empty());
            ResolvedAsset {
                name: asset.name,
                artifact_url: proxy_artifact_url(&asset.browser_download_url, artifact_proxy),
                sha256,
                platform,
            }
        })
        .collect();
    ResolvedRelease {
        version: release.tag_name,
        assets,
    }
}

/// 给 GitHub 制品地址套镜像通道（`<通道>/<原地址>`）；非 github.com 地址或未配通道 → 原样返回。
///
/// 只换**地址**、不动内容：摘要（sha256）仍取自 GitHub 资产元数据，安装侧那份校验不受影响。
fn proxy_artifact_url(url: &str, proxy: Option<&str>) -> String {
    let Some(proxy) = proxy.map(str::trim).filter(|value| !value.is_empty()) else {
        return url.to_string();
    };
    if !(url.starts_with("https://github.com/") || url.starts_with("http://github.com/")) {
        return url.to_string();
    }
    format!("{}/{url}", proxy.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxies_github_artifact_urls_only() {
        let url = "https://github.com/dayu-sec/wist-agentd/releases/download/v0.2.1-alpha/wist-agentd-v0.2.1-alpha-aarch64-apple-darwin.tar.gz";
        // 未配通道 / 配成空串 → 直连。
        assert_eq!(proxy_artifact_url(url, None), url);
        assert_eq!(proxy_artifact_url(url, Some("  ")), url);
        // 通道末尾斜杠去掉，拼成 `<通道>/<原地址>`。
        assert_eq!(
            proxy_artifact_url(url, Some("https://githubproxy.cc/")),
            format!("https://githubproxy.cc/{url}")
        );
        // 非 github 地址（COS / 内网仓库）不动。
        let cos = "https://github-1347593047.cos.ap-hongkong.myqcloud.com/wist-agentd/v0.2.1-alpha/x.tar.gz";
        assert_eq!(proxy_artifact_url(cos, Some("https://githubproxy.cc")), cos);
    }

    /// 手工粘的 GitHub 地址要能对回 `[packages.sources]`（进而拿到该组件的通道）。
    #[test]
    fn release_repo_matches_a_configured_source() {
        assert_eq!(
            release_repo("https://github.com/dayu-sec/wist-agentd/releases/tag/v0.2.1-alpha")
                .as_deref(),
            Some("dayu-sec/wist-agentd")
        );
        assert_eq!(release_repo("https://example.com/x"), None);
    }

    /// 解析结果里的 `artifact_url` 就是录入/下发用的地址：配了通道就是镜像地址。
    #[test]
    fn map_release_applies_the_artifact_proxy() {
        let release = GitHubRelease {
            tag_name: "v1.0.0".into(),
            assets: vec![GitHubAsset {
                name: "demo-v1.0.0-aarch64-apple-darwin.tar.gz".into(),
                browser_download_url:
                    "https://github.com/o/r/releases/download/v1.0.0/demo-v1.0.0-aarch64-apple-darwin.tar.gz"
                        .into(),
                digest: Some("sha256:ABC".into()),
            }],
        };
        let mapped = map_release(release, Some("https://githubproxy.cc"));
        assert_eq!(
            mapped.assets[0].artifact_url,
            "https://githubproxy.cc/https://github.com/o/r/releases/download/v1.0.0/demo-v1.0.0-aarch64-apple-darwin.tar.gz"
        );
        // 摘要仍来自 GitHub 元数据：通道只换地址，不改变校验依据。
        assert_eq!(mapped.assets[0].sha256.as_deref(), Some("abc"));
    }

    #[test]
    fn tries_tag_with_and_without_v() {
        assert_eq!(tag_candidates("0.3.0"), vec!["0.3.0", "v0.3.0"]);
        assert_eq!(tag_candidates("v0.3.0"), vec!["v0.3.0", "0.3.0"]);
        assert_eq!(tag_candidates("  0.3.0  "), vec!["0.3.0", "v0.3.0"]);
        assert!(tag_candidates("   ").is_empty());
    }

    #[test]
    fn parses_release_urls() {
        assert_eq!(
            parse_release_url(
                "https://github.com/galaxio-labs/galaxy-ops/releases/tag/v2.2.1-alpha"
            ),
            Some((
                "galaxio-labs".to_string(),
                "galaxy-ops".to_string(),
                "v2.2.1-alpha".to_string()
            ))
        );
        // 允许末尾斜杠 / query / fragment / 无 scheme。
        assert_eq!(
            parse_release_url("github.com/a/b/releases/tag/v1.0?x=1#y"),
            Some(("a".to_string(), "b".to_string(), "v1.0".to_string()))
        );
        // tag 里带斜杠（release/1.2.3）也保留。
        assert_eq!(
            parse_release_url("https://github.com/a/b/releases/tag/release/1.2.3"),
            Some((
                "a".to_string(),
                "b".to_string(),
                "release/1.2.3".to_string()
            ))
        );
        assert_eq!(parse_release_url("https://github.com/a/b"), None);
        assert_eq!(
            parse_release_url("https://gitlab.com/a/b/releases/tag/v1"),
            None
        );
    }

    #[test]
    fn maps_asset_names_to_target_triples() {
        let (_, arch) = crate::infra::read_package_identity(
            "galaxy-ops-v2.2.1-alpha-aarch64-apple-darwin.tar.gz",
            &[],
        );
        assert_eq!(arch, "aarch64-apple-darwin");
        // gnu / musl 是**不同**的完整三元组（Linux x86_64 两份）。
        let (_, gnu) = crate::infra::read_package_identity(
            "galaxy-ops-v2.2.1-alpha-x86_64-unknown-linux-gnu.tar.gz",
            &[],
        );
        let (_, musl) = crate::infra::read_package_identity(
            "galaxy-ops-v2.2.1-alpha-x86_64-unknown-linux-musl.tar.gz",
            &[],
        );
        assert_eq!(gnu, "x86_64-unknown-linux-gnu");
        assert_eq!(musl, "x86_64-unknown-linux-musl");
        assert_ne!(gnu, musl);
        // 非制品（如 .sha256 清单）：读不出平台。
        let (_, none) = crate::infra::read_package_identity("galaxy-ops-v2.2.1-alpha.sha256", &[]);
        assert!(none.is_empty());
    }
}
