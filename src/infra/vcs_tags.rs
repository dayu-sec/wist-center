//! 规则 / 配置发布入口的 tag 候选读取。
//!
//! 只读能力：按 `[wparse_release.repos]` 的 provider 拉 tag 列表，供发布页做“候选下拉”。
//! 结果按 repo 做短 TTL 缓存，避免页面刷新把 CNB / GitHub 打到限流。
//!
//! 安全边界：
//! - token 只在这里使用，不返回给调用方、不写日志；
//! - repo 标识在配置期已归一（见 `config::normalize_repo_identifier`），这里不再接受任意 URL；
//! - 发布时的 tag 仍会再查一次（防列表过期 / 手填错误），见 [`get_tag`]。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{TagProviderKind, WparseRepoConfig};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CNB_API: &str = "https://api.cnb.cool";
const GITHUB_API: &str = "https://api.github.com";

/// 一个 tag 候选。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepoTag {
    pub tag: String,
    /// tag 指向的 commit（provider 能给时）。
    pub commit: Option<String>,
    /// commit 时间（RFC3339；provider 能给时）。
    pub committed_at: Option<String>,
}

/// 一次 tag 列表查询的结果。
#[derive(Debug, Clone)]
pub struct TagList {
    pub tags: Vec<RepoTag>,
    /// `cnb` / `github` / `manual`。
    pub source: &'static str,
    /// 外部 API 失败时回落的旧缓存。
    pub stale: bool,
    pub cached_at: Option<DateTime<Utc>>,
}

/// tag 来源错误（由 API handler 投影成稳定 `code`）。
#[derive(Debug, Clone)]
pub enum TagSourceError {
    /// token 缺失 / 无效 / scope 不足。
    Unauthorized(String),
    /// repo 不存在（也覆盖“token 作用域不含该仓库”时 CNB 返回的 404）。
    NotFound(String),
    RateLimited {
        message: String,
        retry_after: Option<u64>,
    },
    /// 网络 / 5xx / 响应解析失败。
    Unavailable(String),
}

impl TagSourceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "wparse_tag_source_unauthorized",
            Self::NotFound(_) => "wparse_repo_not_found",
            Self::RateLimited { .. } => "wparse_tag_source_rate_limited",
            Self::Unavailable(_) => "wparse_tag_source_unavailable",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Unauthorized(message)
            | Self::NotFound(message)
            | Self::RateLimited { message, .. }
            | Self::Unavailable(message) => message,
        }
    }
}

struct CachedTags {
    tags: Vec<RepoTag>,
    fetched_at: Instant,
    fetched_at_utc: DateTime<Utc>,
}

/// 进程内 tag 缓存：key 含 provider / repo / token 摘要，避免不同配置串数据。
static CACHE: LazyLock<Mutex<HashMap<String, CachedTags>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cache_key(repo: &WparseRepoConfig) -> String {
    // token 只取摘要：缓存 key 不落明文。
    let token = repo
        .token
        .as_deref()
        .map(crate::infra::sha256_hex)
        .unwrap_or_default();
    format!(
        "{}|{}|{token}|{}",
        repo.provider.as_str(),
        repo.repo,
        repo.tags_limit
    )
}

fn read_cache(key: &str) -> Option<(Vec<RepoTag>, DateTime<Utc>, Instant)> {
    let guard = CACHE.lock().ok()?;
    let cached = guard.get(key)?;
    Some((
        cached.tags.clone(),
        cached.fetched_at_utc,
        cached.fetched_at,
    ))
}

fn write_cache(key: String, tags: &[RepoTag]) -> DateTime<Utc> {
    let now = Utc::now();
    if let Ok(mut guard) = CACHE.lock() {
        guard.insert(
            key,
            CachedTags {
                tags: tags.to_vec(),
                fetched_at: Instant::now(),
                fetched_at_utc: now,
            },
        );
    }
    now
}

/// 列 tag 候选。
///
/// - `limit` 只是**本次返回**的上限；缓存始终按 `repo.tags_limit` 取满，避免 `?limit=10`
///   把缓存写短、后续默认请求只能看到 10 个；
/// - `refresh = true` 绕过缓存；
/// - 外部 API 失败但缓存里有旧数据 → 返回旧数据并标 `stale`（页面提示“可能不是最新”）；
/// - 无缓存且失败 → 返回 [`TagSourceError`]。
pub async fn list_tags(
    repo: &WparseRepoConfig,
    limit: usize,
    refresh: bool,
    cache_seconds: u64,
) -> Result<TagList, TagSourceError> {
    let source = repo.provider.as_str();
    if repo.provider == TagProviderKind::Manual {
        return Ok(TagList {
            tags: Vec::new(),
            source,
            stale: false,
            cached_at: None,
        });
    }

    let key = cache_key(repo);
    let cached = read_cache(&key);
    if !refresh
        && let Some((tags, fetched_at_utc, fetched_at)) = cached.as_ref()
        && fetched_at.elapsed() < Duration::from_secs(cache_seconds)
    {
        let mut tags = tags.clone();
        tags.truncate(limit);
        return Ok(TagList {
            tags,
            source,
            stale: false,
            cached_at: Some(*fetched_at_utc),
        });
    }

    let cache_limit = repo.tags_limit;
    match fetch_tags(repo, cache_limit).await {
        Ok(mut tags) => {
            sort_tags_desc(&mut tags);
            tags.truncate(cache_limit);
            let now = write_cache(key, &tags);
            tags.truncate(limit);
            Ok(TagList {
                tags,
                source,
                stale: false,
                cached_at: Some(now),
            })
        }
        Err(err) => match cached {
            Some((mut tags, fetched_at_utc, _)) => {
                tags.truncate(limit);
                Ok(TagList {
                    tags,
                    source,
                    stale: true,
                    cached_at: Some(fetched_at_utc),
                })
            }
            None => Err(err),
        },
    }
}

/// 单 tag 校验（发布前）：存在返回 tag 详情，不存在返回 `Ok(None)`。
pub async fn get_tag(
    repo: &WparseRepoConfig,
    tag: &str,
) -> Result<Option<RepoTag>, TagSourceError> {
    match repo.provider {
        TagProviderKind::Manual => Ok(None),
        TagProviderKind::Cnb => cnb_get_tag(repo, tag).await,
        TagProviderKind::Github => github_get_tag(repo, tag).await,
    }
}

async fn fetch_tags(repo: &WparseRepoConfig, limit: usize) -> Result<Vec<RepoTag>, TagSourceError> {
    match repo.provider {
        TagProviderKind::Cnb => cnb_list_tags(repo, limit).await,
        TagProviderKind::Github => github_list_tags(repo, limit).await,
        TagProviderKind::Manual => Ok(Vec::new()),
    }
}

fn http_client() -> Result<reqwest::Client, TagSourceError> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|err| TagSourceError::Unavailable(format!("failed to build http client: {err}")))
}

fn retry_after(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn cnb_url(repo: &WparseRepoConfig, suffix: &str) -> String {
    format!("{CNB_API}/{}/-/{suffix}", repo.repo.trim_matches('/'))
}

async fn cnb_list_tags(
    repo: &WparseRepoConfig,
    limit: usize,
) -> Result<Vec<RepoTag>, TagSourceError> {
    let url = format!(
        "{}?page=1&page_size={}",
        cnb_url(repo, "git/tags"),
        limit.clamp(1, 200)
    );
    let mut request = http_client()?
        .get(url)
        .header("accept", "application/vnd.cnb.api+json")
        .header("user-agent", "wist-center");
    if let Some(token) = repo.token.as_deref().filter(|value| !value.is_empty()) {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|err| TagSourceError::Unavailable(format!("failed to reach CNB: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(cnb_error(response, status, "list tags").await);
    }
    let items: Vec<CnbTag> = response
        .json()
        .await
        .map_err(|err| TagSourceError::Unavailable(format!("failed to parse CNB tags: {err}")))?;
    Ok(items.into_iter().map(map_cnb_tag).collect())
}

async fn cnb_get_tag(
    repo: &WparseRepoConfig,
    tag: &str,
) -> Result<Option<RepoTag>, TagSourceError> {
    let url = cnb_url(repo, &format!("git/tags/{tag}"));
    let mut request = http_client()?
        .get(url)
        .header("accept", "application/vnd.cnb.api+json")
        .header("user-agent", "wist-center");
    if let Some(token) = repo.token.as_deref().filter(|value| !value.is_empty()) {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|err| TagSourceError::Unavailable(format!("failed to reach CNB: {err}")))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(cnb_error(response, status, "get tag").await);
    }
    let item: CnbTag = response
        .json()
        .await
        .map_err(|err| TagSourceError::Unavailable(format!("failed to parse CNB tag: {err}")))?;
    Ok(Some(map_cnb_tag(item)))
}

async fn cnb_error(
    response: reqwest::Response,
    status: reqwest::StatusCode,
    action: &str,
) -> TagSourceError {
    let retry_after = retry_after(&response);
    let body = response.text().await.unwrap_or_default();
    let detail = format!("CNB {action} failed: {status} {body}");
    match status.as_u16() {
        401 | 403 => TagSourceError::Unauthorized(format!("{detail} (token needs repo-release:r)")),
        404 => TagSourceError::NotFound(detail),
        429 => TagSourceError::RateLimited {
            message: detail,
            retry_after,
        },
        _ => TagSourceError::Unavailable(detail),
    }
}

async fn github_list_tags(
    repo: &WparseRepoConfig,
    limit: usize,
) -> Result<Vec<RepoTag>, TagSourceError> {
    let url = format!(
        "{GITHUB_API}/repos/{}/tags?per_page={}",
        repo.repo,
        limit.clamp(1, 100)
    );
    let mut request = http_client()?
        .get(url)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "wist-center");
    if let Some(token) = repo.token.as_deref().filter(|value| !value.is_empty()) {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|err| TagSourceError::Unavailable(format!("failed to reach GitHub: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(github_error(response, status, "list tags").await);
    }
    let items: Vec<GhTag> = response.json().await.map_err(|err| {
        TagSourceError::Unavailable(format!("failed to parse GitHub tags: {err}"))
    })?;
    Ok(items
        .into_iter()
        .map(|item| RepoTag {
            tag: item.name,
            commit: Some(item.commit.sha),
            committed_at: None,
        })
        .collect())
}

async fn github_get_tag(
    repo: &WparseRepoConfig,
    tag: &str,
) -> Result<Option<RepoTag>, TagSourceError> {
    let url = format!("{GITHUB_API}/repos/{}/commits/{tag}", repo.repo);
    let mut request = http_client()?
        .get(url)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "wist-center");
    if let Some(token) = repo.token.as_deref().filter(|value| !value.is_empty()) {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|err| TagSourceError::Unavailable(format!("failed to reach GitHub: {err}")))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(github_error(response, status, "get tag").await);
    }
    let item: GhCommit = response.json().await.map_err(|err| {
        TagSourceError::Unavailable(format!("failed to parse GitHub commit: {err}"))
    })?;
    Ok(Some(RepoTag {
        tag: tag.to_string(),
        commit: Some(item.sha),
        committed_at: item.commit.committer.and_then(|committer| committer.date),
    }))
}

async fn github_error(
    response: reqwest::Response,
    status: reqwest::StatusCode,
    action: &str,
) -> TagSourceError {
    let retry_after = retry_after(&response);
    let body = response.text().await.unwrap_or_default();
    let detail = format!("GitHub {action} failed: {status} {body}");
    match status.as_u16() {
        401 | 403 => TagSourceError::Unauthorized(detail),
        404 => TagSourceError::NotFound(detail),
        429 => TagSourceError::RateLimited {
            message: detail,
            retry_after,
        },
        _ => TagSourceError::Unavailable(detail),
    }
}

#[derive(Debug, Deserialize)]
struct CnbTag {
    name: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    commit: Option<CnbCommit>,
}

#[derive(Debug, Deserialize)]
struct CnbCommit {
    #[serde(default)]
    sha: Option<String>,
    #[serde(default)]
    commit: Option<CnbCommitObject>,
}

#[derive(Debug, Deserialize)]
struct CnbCommitObject {
    #[serde(default)]
    committer: Option<CnbSignature>,
}

#[derive(Debug, Deserialize)]
struct CnbSignature {
    #[serde(default)]
    date: Option<String>,
}

fn map_cnb_tag(item: CnbTag) -> RepoTag {
    let (commit, committed_at) = match item.commit {
        Some(commit) => (
            commit.sha.or(item.target),
            commit
                .commit
                .and_then(|object| object.committer)
                .and_then(|signature| signature.date),
        ),
        None => (item.target, None),
    };
    RepoTag {
        tag: item.name,
        commit,
        committed_at,
    }
}

#[derive(Debug, Deserialize)]
struct GhTag {
    name: String,
    commit: GhTagCommit,
}

#[derive(Debug, Deserialize)]
struct GhTagCommit {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GhCommit {
    sha: String,
    #[serde(default)]
    commit: GhCommitObject,
}

#[derive(Debug, Default, Deserialize)]
struct GhCommitObject {
    #[serde(default)]
    committer: Option<GhSignature>,
}

#[derive(Debug, Deserialize)]
struct GhSignature {
    #[serde(default)]
    date: Option<String>,
}

// ── 排序：semver 降序；解析不出的放最后按字典序降序 ──

#[derive(Debug, PartialEq, Eq)]
struct SemverKey {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

fn parse_semver(tag: &str) -> Option<SemverKey> {
    let trimmed = tag.trim();
    let trimmed = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    let (core, prerelease) = match trimmed.split_once('-') {
        Some((core, pre)) => (core, Some(pre.to_string())),
        None => (trimmed, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(SemverKey {
        major,
        minor,
        patch,
        prerelease,
    })
}

fn compare_semver(left: &SemverKey, right: &SemverKey) -> Ordering {
    left.major
        .cmp(&right.major)
        .then(left.minor.cmp(&right.minor))
        .then(left.patch.cmp(&right.patch))
        .then_with(|| match (&left.prerelease, &right.prerelease) {
            (None, None) => Ordering::Equal,
            // 正式版 > 预发布版。
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => left.cmp(right),
        })
}

fn compare_tags(left: &RepoTag, right: &RepoTag) -> Ordering {
    match (parse_semver(&left.tag), parse_semver(&right.tag)) {
        (Some(left_key), Some(right_key)) => {
            compare_semver(&left_key, &right_key).then_with(|| left.tag.cmp(&right.tag))
        }
        // 能解析成 semver 的排在前面。
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => left.tag.cmp(&right.tag),
    }
}

fn sort_tags_desc(tags: &mut [RepoTag]) {
    tags.sort_by(|left, right| compare_tags(right, left));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(name: &str) -> RepoTag {
        RepoTag {
            tag: name.to_string(),
            commit: None,
            committed_at: None,
        }
    }

    #[test]
    fn semver_sort_is_numeric_not_lexicographic() {
        let mut tags = vec![tag("v1.9.0"), tag("v1.10.0"), tag("v2.0.0")];
        sort_tags_desc(&mut tags);
        assert_eq!(
            tags.iter()
                .map(|item| item.tag.as_str())
                .collect::<Vec<_>>(),
            vec!["v2.0.0", "v1.10.0", "v1.9.0"]
        );
    }

    #[test]
    fn release_sorts_before_prerelease() {
        let mut tags = vec![tag("v1.2.3-alpha"), tag("v1.2.3")];
        sort_tags_desc(&mut tags);
        assert_eq!(tags[0].tag, "v1.2.3");
    }

    #[test]
    fn non_semver_tags_go_last() {
        let mut tags = vec![tag("nightly"), tag("v1.2.3"), tag("latest")];
        sort_tags_desc(&mut tags);
        assert_eq!(tags[0].tag, "v1.2.3");
        assert!(tags[1].tag > tags[2].tag);
    }

    #[test]
    fn maps_cnb_tag_payload() {
        let raw: CnbTag = serde_json::from_str(
            r#"{
                "name": "v1.2.3",
                "target": "tag-object",
                "commit": {
                    "sha": "abc123",
                    "commit": { "committer": { "date": "2026-10-20T08:00:00Z" } }
                }
            }"#,
        )
        .expect("cnb tag");
        let tag = map_cnb_tag(raw);
        assert_eq!(tag.tag, "v1.2.3");
        assert_eq!(tag.commit.as_deref(), Some("abc123"));
        assert_eq!(tag.committed_at.as_deref(), Some("2026-10-20T08:00:00Z"));
    }

    #[test]
    fn maps_github_tag_payload() {
        let raw: Vec<GhTag> =
            serde_json::from_str(r#"[{ "name": "v1.2.3", "commit": { "sha": "abc123" } }]"#)
                .expect("gh tags");
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].commit.sha, "abc123");
    }
}
