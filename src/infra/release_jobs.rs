//! 远程包下载任务的**业务实现**：通用队列与 worker 在 [`crate::infra::jobs`]。
//!
//! 发布端点只负责把 [`ReleaseJobPayload`] 包成一条 `release-download` 任务入队；worker 取到
//! 任务后执行「取包 → 核对摘要 → 镜像 → 落库」，把 [`ReleasePackageRecord`] 作为任务结果，
//! 进度通过 [`JobContext::report`] 回写。管理面的读取形状由 [`ReleaseJobView`] 保持与旧
//! `/release-jobs` 回执同形。

use std::{collections::HashMap, sync::Arc};

use orion_error::prelude::*;
use serde::{Deserialize, Serialize};
use wist_control::types::DateTime;
use wist_error::StoreReason;

use super::jobs::{JobContext, JobFailure, JobHandler, JobQueue, JobRecord};
use super::store::{Store, StoreError};
use super::{
    ArtifactStore, ReleasePackage, ReleasePackageRecord, ReleaseRecord, group_release_packages,
    read_package_identity, read_package_name, read_package_source, read_verified_package,
    validate_platforms,
};

/// 队列名 / handler kind（一个队列一条串行 worker）。
pub const RELEASE_JOB_QUEUE: &str = "release-download";
/// handler kind（worker 按它找 [`ReleaseDownloadHandler`]）。
pub const RELEASE_JOB_KIND: &str = "release-download";

/// 任务模式：单制品发布。
pub const RELEASE_JOB_PUBLISH: &str = "publish";
/// 任务模式：多平台批量发布。
pub const RELEASE_JOB_PUBLISH_BATCH: &str = "publish_batch";

/// 任务里的一个待下载制品（与发布请求同形：来源 + 期望摘要）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseJobArtifact {
    pub artifact_url: String,
    pub expected_sha256: String,
}

/// 远程包下载任务的业务载荷（与 `job.payload` 一一对应）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseJobPayload {
    /// `publish` | `publish_batch`。
    pub mode: String,
    pub component: String,
    pub requested_by: String,
    /// 单制品发布时调用方声明的版本（可选；批量固定为空）。
    #[serde(default)]
    pub declared_version: Option<String>,
    pub artifacts: Vec<ReleaseJobArtifact>,
}

/// 管理面任务视图：字段与旧 `/release-jobs` 回执**保持同形**（前端无需改）。
#[derive(Debug, Clone, Serialize)]
pub struct ReleaseJobView {
    pub job_id: String,
    pub component: String,
    /// `publish` | `publish_batch`（业务模式，不是 handler kind）。
    pub kind: String,
    pub state: String,
    pub requested_by: String,
    pub declared_version: Option<String>,
    pub artifacts: Vec<ReleaseJobArtifact>,
    pub completed_artifacts: u32,
    pub total_artifacts: u32,
    pub message: Option<String>,
    pub package: Option<ReleasePackageRecord>,
    pub error_code: Option<String>,
    pub error_status: Option<u16>,
    pub error_detail: Option<String>,
    pub created_at: DateTime,
    pub started_at: Option<DateTime>,
    pub finished_at: Option<DateTime>,
}

impl ReleaseJobView {
    /// 通用任务 → 管理面视图；payload 不是 release 任务时返回 `None`（列表里跳过）。
    pub fn from_job(job: &JobRecord) -> Option<Self> {
        let payload: ReleaseJobPayload = serde_json::from_value(job.payload.clone()).ok()?;
        let package = job
            .result
            .as_ref()
            .and_then(|value| serde_json::from_value(value.clone()).ok());
        Some(Self {
            job_id: job.job_id.clone(),
            component: payload.component,
            kind: payload.mode,
            state: job.state.clone(),
            requested_by: payload.requested_by,
            declared_version: payload.declared_version,
            artifacts: payload.artifacts,
            completed_artifacts: job.progress.completed,
            total_artifacts: job.progress.total,
            message: job.progress.message.clone(),
            package,
            error_code: job.error_code.clone(),
            error_status: job.error_status,
            error_detail: job.error_detail.clone(),
            created_at: job.created_at.clone(),
            started_at: job.started_at.clone(),
            finished_at: job.finished_at.clone(),
        })
    }
}

/// 把业务载荷包装成一条待入队的通用任务。
pub fn release_job(payload: ReleaseJobPayload) -> Result<JobRecord, StoreError> {
    let value = serde_json::to_value(&payload)
        .source_err(StoreReason::Json, "serialize release job payload")?;
    let subject = payload.component.clone();
    Ok(JobRecord::queued(RELEASE_JOB_QUEUE, RELEASE_JOB_KIND, value, 0).with_subject(subject))
}

/// 构造 release 下载队列（注册 `release-download` handler）。
pub fn release_job_queue(
    store: Arc<dyn Store>,
    artifacts: Arc<dyn ArtifactStore>,
) -> Arc<JobQueue> {
    let handler: Arc<dyn JobHandler> = Arc::new(ReleaseDownloadHandler {
        store: store.clone(),
        artifacts,
    });
    let mut handlers: HashMap<String, Arc<dyn JobHandler>> = HashMap::new();
    handlers.insert(RELEASE_JOB_KIND.to_string(), handler);
    let queue = JobQueue::new(store, RELEASE_JOB_QUEUE, handlers);
    let raw = std::env::var(JOB_RETENTION_ENV).ok();
    Arc::new(queue.with_retention_days(parse_retention_days(raw.as_deref())))
}

/// 保留期环境变量名：运维不重启代码就能调终态任务的保留天数。
pub const JOB_RETENTION_ENV: &str = "WIST_CENTER_JOB_RETENTION_DAYS";

/// 解析保留期：未设置/空值 → 默认 7 天；`0` 或负数 → 不自动清理；脏值 → 不自动清理。
///
/// 脏值上刻意**不**回退到默认值：运维写错时，静默删数据比不删更危险。
fn parse_retention_days(raw: Option<&str>) -> i64 {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => super::jobs::DEFAULT_JOB_RETENTION_DAYS,
        Some(value) => value.parse::<i64>().unwrap_or(0).max(0),
    }
}

/// 下载任务的执行器：把通用任务载荷翻译成发布逻辑。
struct ReleaseDownloadHandler {
    store: Arc<dyn Store>,
    artifacts: Arc<dyn ArtifactStore>,
}

#[async_trait::async_trait]
impl JobHandler for ReleaseDownloadHandler {
    fn kind(&self) -> &'static str {
        RELEASE_JOB_KIND
    }

    async fn run(
        &self,
        ctx: &JobContext,
        job: &JobRecord,
    ) -> Result<serde_json::Value, JobFailure> {
        let payload: ReleaseJobPayload =
            serde_json::from_value(job.payload.clone()).map_err(|err| {
                JobFailure::new(
                    400,
                    crate::api::codes::ARTIFACT_INVALID,
                    format!("invalid release job payload: {err}"),
                )
            })?;
        let package = execute_release(self.store.as_ref(), self.artifacts.as_ref(), ctx, &payload)
            .await
            .map_err(|failure| JobFailure::new(failure.status, failure.code, failure.detail))?;
        serde_json::to_value(package).map_err(|err| {
            JobFailure::new(
                500,
                crate::api::codes::RELEASE_PUBLISH_FAILED,
                format!("serialize release job result: {err}"),
            )
        })
    }
}

/// 执行一条 release 任务（单制品 / 批量）。
async fn execute_release(
    store: &dyn Store,
    artifact_store: &dyn ArtifactStore,
    ctx: &JobContext,
    payload: &ReleaseJobPayload,
) -> Result<ReleasePackageRecord, ReleaseFailure> {
    match payload.mode.as_str() {
        RELEASE_JOB_PUBLISH => execute_single(store, artifact_store, ctx, payload).await,
        RELEASE_JOB_PUBLISH_BATCH => execute_batch(store, artifact_store, ctx, payload).await,
        other => Err(bad_request(
            crate::api::codes::ARTIFACT_INVALID,
            format!("unsupported release job mode `{other}`"),
        )),
    }
}

/// 执行失败（带 HTTP 语义，供任务视图 / 同步兼容端点使用）。
#[derive(Debug, Clone)]
pub struct ReleaseFailure {
    pub status: u16,
    pub code: &'static str,
    pub detail: String,
}

impl ReleaseFailure {
    fn new(status: u16, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
        }
    }
}

fn bad_request(code: &'static str, detail: impl Into<String>) -> ReleaseFailure {
    ReleaseFailure::new(400, code, detail)
}

fn bad_gateway(code: &'static str, detail: impl Into<String>) -> ReleaseFailure {
    ReleaseFailure::new(502, code, detail)
}

fn internal(code: &'static str, detail: impl Into<String>) -> ReleaseFailure {
    ReleaseFailure::new(500, code, detail)
}

async fn execute_single(
    store: &dyn Store,
    artifact_store: &dyn ArtifactStore,
    ctx: &JobContext,
    payload: &ReleaseJobPayload,
) -> Result<ReleasePackageRecord, ReleaseFailure> {
    let artifact =
        payload.artifacts.first().cloned().ok_or_else(|| {
            bad_request(crate::api::codes::ARTIFACTS_REQUIRED, "job has no artifact")
        })?;
    let expected = artifact.expected_sha256.trim();
    if artifact.artifact_url.trim().is_empty() || expected.is_empty() {
        return Err(bad_request(
            crate::api::codes::ARTIFACT_URL_AND_SHA256_REQUIRED,
            "artifact_url and expected_sha256 must not be empty",
        ));
    }
    ctx.report(|progress| {
        progress.total = 1;
        progress.message = Some("取包中（1/1）".to_string());
    })
    .await;
    let (bytes, package_sha256) = read_verified_package(&artifact.artifact_url, Some(expected))
        .await
        .map_err(|err| bad_gateway(crate::api::codes::ARTIFACT_FETCH_FAILED, err.to_string()))?;
    ctx.report(|progress| {
        progress.completed = 1;
        progress.message = Some("校验 / 镜像 / 落库中".to_string());
    })
    .await;
    let (package_version, package_arch) = read_package_identity(&artifact.artifact_url, &bytes);

    // 版本以**包自报为准**：请求带了就核对，没带就采用自报；两边都没有 → 拒。
    let declared = payload
        .declared_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let version = match declared {
        Some(declared) => {
            if !package_version.is_empty()
                && crate::infra::normalize_version(declared)
                    != crate::infra::normalize_version(&package_version)
            {
                return Err(bad_request(
                    crate::api::codes::VERSION_MISMATCH,
                    format!(
                        "version mismatch: request declares {declared} but the package self-reports {package_version}"
                    ),
                ));
            }
            declared.to_string()
        }
        None if !package_version.is_empty() => package_version,
        None => {
            return Err(bad_request(
                crate::api::codes::VERSION_UNDERIVABLE,
                "cannot derive version from the package: use an artifact whose name carries a version, or pass `version` explicitly"
                    .to_string(),
            ));
        }
    };
    if !crate::infra::is_safe_path_segment(&version) {
        return Err(bad_request(
            crate::api::codes::INVALID_VERSION,
            "version must be a single safe path segment",
        ));
    }
    let platform = (!package_arch.is_empty()).then_some(package_arch.as_str());
    record_verified_release(
        store,
        artifact_store,
        &payload.component,
        &version,
        &artifact.artifact_url,
        bytes,
        &package_sha256,
        platform,
    )
    .await?;
    // 知识库包的签名旁文件（`<来源>.sig`）一并镜像：gwlinkd 会把制品与 `.sig` 一起取到网关。
    if payload.component == KNOWLEDGE_COMPONENT {
        mirror_knowledge_signature(
            artifact_store,
            &payload.component,
            &version,
            &artifact.artifact_url,
        )
        .await;
    }
    load_release_package(store, &payload.component, &version)
        .await
        .map_err(|err| internal(crate::api::codes::RELEASE_LIST_FAILED, err.to_string()))?
        .ok_or_else(|| {
            internal(
                crate::api::codes::RELEASE_NOT_FOUND_AFTER_WRITE,
                "release recorded but not found",
            )
        })
}
async fn execute_batch(
    store: &dyn Store,
    artifact_store: &dyn ArtifactStore,
    ctx: &JobContext,
    payload: &ReleaseJobPayload,
) -> Result<ReleasePackageRecord, ReleaseFailure> {
    struct Prepared {
        version: String,
        arch: String,
        artifact_url: String,
        bytes: Vec<u8>,
        package_sha256: String,
    }

    let artifacts = payload.artifacts.clone();
    let total = artifacts.len();
    let mut prepared: Vec<Prepared> = Vec::with_capacity(total);
    for (index, artifact) in artifacts.iter().enumerate() {
        let expected = artifact.expected_sha256.trim();
        if artifact.artifact_url.trim().is_empty() || expected.is_empty() {
            return Err(bad_request(
                crate::api::codes::ARTIFACT_URL_AND_SHA256_REQUIRED,
                "artifact_url and expected_sha256 must not be empty",
            ));
        }
        ctx.report(|progress| {
            progress.total = total as u32;
            progress.message = Some(format!("取包中（{}/{}）", index + 1, total));
        })
        .await;
        let (bytes, package_sha256) = read_verified_package(&artifact.artifact_url, Some(expected))
            .await
            .map_err(|err| {
                bad_gateway(crate::api::codes::ARTIFACT_FETCH_FAILED, err.to_string())
            })?;
        ctx.report(|progress| progress.completed = (index + 1) as u32)
            .await;
        let (version, arch) = read_package_identity(&artifact.artifact_url, &bytes);
        if version.is_empty() {
            return Err(bad_request(
                crate::api::codes::VERSION_UNDERIVABLE,
                format!(
                    "cannot derive version from `{}`: use an artifact whose name carries a version",
                    artifact.artifact_url
                ),
            ));
        }
        if !crate::infra::is_safe_path_segment(&version) {
            return Err(bad_request(
                crate::api::codes::INVALID_VERSION,
                "version must be a single safe path segment",
            ));
        }
        if arch.is_empty() {
            return Err(bad_request(
                crate::api::codes::PLATFORM_UNDERIVABLE,
                format!(
                    "cannot derive platform (target-triple) from `{}`",
                    artifact.artifact_url
                ),
            ));
        }
        prepared.push(Prepared {
            version,
            arch,
            artifact_url: artifact.artifact_url.clone(),
            bytes,
            package_sha256,
        });
    }

    // 一批必须是同一版本。
    let version = prepared
        .first()
        .map(|item| item.version.clone())
        .ok_or_else(|| {
            bad_request(
                crate::api::codes::ARTIFACTS_REQUIRED,
                "artifacts must not be empty",
            )
        })?;
    if prepared.iter().any(|item| item.version != version) {
        return Err(bad_request(
            crate::api::codes::ARTIFACTS_VERSION_MISMATCH,
            "all artifacts must share the same version",
        ));
    }
    // 平台不得重复；多平台组件必须覆盖必需平台集。
    let package = ReleasePackage::new(
        version.clone(),
        prepared
            .iter()
            .map(|item| crate::infra::ReleaseArtifact {
                platform: Some(item.arch.clone()),
                sha256: item.package_sha256.clone(),
                source: item.artifact_url.clone(),
            })
            .collect(),
    );
    let required = required_platforms(&payload.component).unwrap_or(&[]);
    if let Err(err) = validate_platforms(&package, required) {
        return Err(bad_request(
            crate::api::codes::ARTIFACT_INVALID,
            format!("component `{}`: {err}", payload.component),
        ));
    }

    // 全部校验通过后再逐个镜像落库。
    // 兼容性在**落库前统一预检**：否则一台不兼容时，前面的平台已经被镜像/记库，
    // 留下一批「半套」的发布记录。
    for item in &prepared {
        ensure_release_compatible(&payload.component, &item.version, &item.bytes)?;
    }
    ctx.report(|progress| progress.message = Some("镜像 / 落库中".to_string()))
        .await;
    for item in prepared {
        let platform = (!item.arch.is_empty()).then_some(item.arch.as_str());
        record_verified_release(
            store,
            artifact_store,
            &payload.component,
            &item.version,
            &item.artifact_url,
            item.bytes,
            &item.package_sha256,
            platform,
        )
        .await?;
    }
    load_release_package(store, &payload.component, &version)
        .await
        .map_err(|err| internal(crate::api::codes::RELEASE_LIST_FAILED, err.to_string()))?
        .ok_or_else(|| {
            internal(
                crate::api::codes::RELEASE_NOT_FOUND_AFTER_WRITE,
                "release recorded but not found",
            )
        })
}
/// 兼容性检查：包声明的上游（当前节点）不满足 → 409，阻止镜像/落库。
fn ensure_release_compatible(
    component: &str,
    version: &str,
    bytes: &[u8],
) -> Result<Option<wist_release::compat::CompatManifest>, ReleaseFailure> {
    let manifest = wist_release::compat::read_manifest_from_tar(bytes);
    let current = std::collections::BTreeMap::from([(
        "wist-center".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    )]);
    let report = wist_release::compat::check(
        manifest.as_ref(),
        component,
        version,
        &current,
        &chrono::Utc::now().to_rfc3339(),
    );
    if report.is_blocking() {
        return Err(ReleaseFailure::new(
            409,
            crate::api::codes::RELEASE_INCOMPATIBLE,
            report.summary(),
        ));
    }
    if report.status != wist_release::compat::CompatStatus::Ok {
        log::warn!(
            "event=ReleaseCompatibilityWarn component={component} version={version} status={} detail={}",
            report.status.as_str(),
            report.summary()
        );
    }
    Ok(manifest)
}

/// 把一个**已验证**的制品镜像并落库（单条与批量共用）：
/// - 同一 `(component, version, sha)` 已存在 → 幂等（不重复下副本；旧记录缺平台则补齐）；
/// - 否则镜像到制品存储并写一条 `published` 记录。
#[allow(clippy::too_many_arguments)]
async fn record_verified_release(
    store: &dyn Store,
    artifact_store: &dyn ArtifactStore,
    component: &str,
    version: &str,
    artifact_url: &str,
    bytes: Vec<u8>,
    package_sha256: &str,
    platform: Option<&str>,
) -> Result<ReleaseRecord, ReleaseFailure> {
    // 「组件 ↔ 包」校验（fail-closed）：包名必须与组件一致，否则在落盘 / 记库**之前**拒。
    if let Some(detail) = component_package_mismatch(component, artifact_url, &bytes) {
        return Err(bad_request(
            crate::api::codes::ARTIFACT_COMPONENT_MISMATCH,
            detail,
        ));
    }
    // 兼容性：包内 `compat.json` 的 `requires`（上游，如 `wist-center`）不满足当前节点时，
    // 在镜像/落库**之前**拒，并明确提示“先升级当前节点”。没有声明 → 只告警。
    let compat = ensure_release_compatible(component, version, &bytes)?;
    // 同一 (component, version) 已镜像过**同一份内容** → 幂等返回，不重复下副本。
    if let Ok(existing) = store.list_releases(component).await
        && let Some(record) = existing.iter().find(|record| {
            record.version == version && record.package_sha256.as_deref() == Some(package_sha256)
        })
    {
        // 幂等命中：若旧记录缺平台而现在能解析出来，顺手补齐。
        if record.platform.is_none()
            && let Some(platform) = platform
            && let Ok(Some(updated)) = store
                .set_release_platform(component, version, package_sha256, Some(platform))
                .await
        {
            return Ok(updated);
        }
        return Ok(record.clone());
    }
    // 落盘 / 下发文件名用来源原名（URL 末段就是原名）；内容寻址靠 DB 的 `package_sha256` +
    // `(component, version, sha)` 幂等。
    let filename = crate::infra::artifact_filename(artifact_url, component, version);
    let mirrored_url = artifact_store
        .store(component, version, &filename, bytes)
        .await
        .map_err(|err| {
            internal(
                crate::api::codes::ARTIFACT_STORE_FAILED,
                format!("failed to store artifact: {err}"),
            )
        })?;
    store
        .publish_release_with_compat(
            component,
            version,
            &mirrored_url,
            Some(package_sha256),
            platform,
            compat,
        )
        .await
        .map_err(|err| {
            internal(
                crate::api::codes::RELEASE_PUBLISH_FAILED,
                format!("failed to record release: {err}"),
            )
        })
}

/// 读取某组件某版本的「安装包」视图（把该组件全部发布记录归组成包后取该版本）。
pub async fn load_release_package(
    store: &dyn Store,
    component: &str,
    version: &str,
) -> Result<Option<ReleasePackageRecord>, StoreError> {
    let records = store.list_releases(component).await?;
    Ok(group_release_packages(component, records)
        .into_iter()
        .find(|package| package.package.version == version))
}

/// 知识库包的**签名旁文件**（`<来源>.sig`）随包镜像到中心制品存储（best-effort）。
async fn mirror_knowledge_signature(
    artifact_store: &dyn ArtifactStore,
    component: &str,
    version: &str,
    artifact_url: &str,
) {
    let signature_url = format!("{artifact_url}.sig");
    let bytes = match read_package_source(&signature_url).await {
        Ok(bytes) => bytes,
        Err(err) => {
            log::warn!(
                "event=KnowledgeSignatureNotMirrored component={component} version={version} url={signature_url} err={err}"
            );
            return;
        }
    };
    let filename = format!(
        "{}.sig",
        crate::infra::artifact_filename(artifact_url, component, version)
    );
    if let Err(err) = artifact_store
        .store(component, version, &filename, bytes)
        .await
    {
        log::warn!(
            "event=KnowledgeSignatureStoreFailed component={component} version={version} err={err}"
        );
    }
}

/// 知识库组件名（与 `admin_ops` 同值；签名旁文件的镜像只对知识库包做）。
pub(crate) const KNOWLEDGE_COMPONENT: &str = "wist-knowledge";

/// 多平台组件一次录入的**必需平台集**（一次必须齐备）。`None` = 不受限（单制品组件）。
pub(crate) fn required_platforms(component: &str) -> Option<&'static [&'static str]> {
    match component {
        // Agentd / Gops / Gx / gwlinkd：一次录入必须覆盖三平台
        // （macOS-ARM + Linux x86_64 / ARM64 的 musl 静态版）。
        "wist-agentd" | "galaxy-ops" | "galaxy-flow" | "wist-gwlinkd" => Some(&[
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
        ]),
        _ => None,
    }
}

/// 「组件 ↔ 包」一致性：解析包名（包内顶层目录名 / 来源文件名），**必须与组件一致**。
///
/// 取不出包名（`pkg-<hash>`、临时名）**也拒** —— 否则「发错组件」的包会一路被派发，
/// 直到网关取到、agentd 解包时才报 `artifact_invalid`。
pub(crate) fn component_package_mismatch(
    component: &str,
    source: &str,
    bytes: &[u8],
) -> Option<String> {
    let name = read_package_name(source, bytes);
    if name == component {
        return None;
    }
    if name.is_empty() {
        return Some(format!(
            "cannot tell which component this package belongs to (source: {source}); \
             expected a package named `{component}-<version>[-<platform>]`"
        ));
    }
    Some(component_mismatch_detail(component, source, &name))
}

/// 「组件 ↔ 包」不一致的统一措辞（来源能读出包名时用）；指出该发到哪个组件。
pub(crate) fn component_mismatch_detail(component: &str, source: &str, name: &str) -> String {
    format!(
        "package looks like `{name}`, not `{component}` (source: {source}); \
         publish it under the `{name}` component"
    )
}

/// 「组件 ↔ 包」一致性的**来源侧预检**：**只看来源文件名、不下载**。
pub(crate) fn source_component_mismatch(component: &str, source: &str) -> Option<String> {
    let name = crate::infra::read_source_package_name(source);
    (!name.is_empty() && name != component)
        .then(|| component_mismatch_detail(component, source, &name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ReleaseJobArtifact {
        ReleaseJobArtifact {
            artifact_url: "https://example/pkg.tar.gz".to_string(),
            expected_sha256: "0".repeat(64),
        }
    }

    fn tar_gz_with_compat(compat: &str) -> Vec<u8> {
        use std::io::Write;
        let mut builder = tar::Builder::new(Vec::new());
        let payload = compat.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "pkg-1.0.0/compat.json", payload)
            .expect("append");
        let tar = builder.into_inner().expect("tar");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).expect("gzip");
        encoder.finish().expect("gzip finish")
    }

    #[test]
    fn release_rejects_a_package_that_requires_a_newer_center() {
        let bytes = tar_gz_with_compat(r#"{"requires":{"wist-center":">=99.0.0"}}"#);
        let err = ensure_release_compatible("wist-gateway-stack", "0.9.4", &bytes)
            .expect_err("must block");
        assert_eq!(err.status, 409);
        assert_eq!(err.code, crate::api::codes::RELEASE_INCOMPATIBLE);
        assert!(err.detail.contains("请先升级"), "{}", err.detail);
    }

    #[test]
    fn release_allows_a_package_without_a_compat_manifest() {
        // 空字节 = 没有可读的 tar.gz；兼容性按 `unknown` 处理，不阻止发布。
        assert!(ensure_release_compatible("wist-gateway-stack", "0.9.4", &[]).is_ok());
    }

    #[test]
    fn release_allows_a_compatible_package() {
        let bytes = tar_gz_with_compat(r#"{"requires":{"wist-center":">=0.0.1"}}"#);
        assert!(ensure_release_compatible("wist-gateway-stack", "0.9.4", &bytes).is_ok());
    }

    #[test]
    fn release_does_not_block_a_compat_mode_package_that_coexists() {
        let bytes = tar_gz_with_compat(
            r#"{
                "requires":{"wist-center":">=99.0.0"},
                "coexists_with":{"wist-center":">=0.0.1"},
                "compat_mode":true
            }"#,
        );
        assert!(ensure_release_compatible("wist-gateway-stack", "0.9.4", &bytes).is_ok());
    }

    #[test]
    fn release_does_not_block_on_a_downstream_supports_miss() {
        let bytes = tar_gz_with_compat(r#"{"supports":{"wist-gateway-stack":">=99.0.0"}}"#);
        assert!(ensure_release_compatible("wist-agentd", "0.1.20", &bytes).is_ok());
    }

    #[test]
    fn release_blocks_when_one_of_many_requirements_fails() {
        let bytes = tar_gz_with_compat(
            r#"{"requires":{"wist-center":">=0.0.1","wist-gwlinkd":">=99.0.0"}}"#,
        );
        // center 当前版本满足第一条；gwlinkd 不在 center 的已知版本里 → 只是 warn，不阻断。
        assert!(ensure_release_compatible("wist-gateway-stack", "0.9.4", &bytes).is_ok());

        let bytes = tar_gz_with_compat(
            r#"{"requires":{"wist-center":">=99.0.0","wist-gwlinkd":">=0.1.0"}}"#,
        );
        let err = ensure_release_compatible("wist-gateway-stack", "0.9.4", &bytes)
            .expect_err("must block");
        assert_eq!(err.code, crate::api::codes::RELEASE_INCOMPATIBLE);
    }

    #[test]
    fn release_treats_an_unparsable_manifest_as_unknown() {
        let bytes = tar_gz_with_compat(r#"{not json"#);
        assert!(ensure_release_compatible("wist-gateway-stack", "0.9.4", &bytes).is_ok());
    }

    #[test]
    fn payload_serializes_into_a_generic_release_job() {
        let job = release_job(ReleaseJobPayload {
            mode: RELEASE_JOB_PUBLISH.to_string(),
            component: "wist-agentd".to_string(),
            requested_by: "admin".to_string(),
            declared_version: None,
            artifacts: vec![artifact()],
        })
        .expect("job");
        assert_eq!(job.queue, RELEASE_JOB_QUEUE);
        assert_eq!(job.kind, RELEASE_JOB_KIND);
        assert_eq!(job.state, crate::infra::jobs::JOB_QUEUED);

        let view = ReleaseJobView::from_job(&job).expect("view");
        assert_eq!(view.kind, RELEASE_JOB_PUBLISH);
        assert_eq!(view.component, "wist-agentd");
        assert_eq!(view.artifacts.len(), 1);
        assert_eq!(view.total_artifacts, 0);
    }

    #[test]
    fn a_non_release_payload_is_not_a_release_view() {
        let job = JobRecord::queued(
            "other-queue",
            "other-kind",
            serde_json::json!({ "x": 1 }),
            0,
        );
        assert!(ReleaseJobView::from_job(&job).is_none());
    }

    /// `subject` 必须跟 `component` 一致：`/admin/jobs?subject=` 和 `/release-jobs?component=`
    /// 才能指向同一批任务。
    #[test]
    fn the_job_subject_is_the_component() {
        let job = release_job(ReleaseJobPayload {
            mode: RELEASE_JOB_PUBLISH_BATCH.to_string(),
            component: "wist-gateway-stack".to_string(),
            requested_by: "admin".to_string(),
            declared_version: None,
            artifacts: vec![artifact(), artifact()],
        })
        .expect("job");
        assert_eq!(job.subject.as_deref(), Some("wist-gateway-stack"));
        let view = ReleaseJobView::from_job(&job).expect("view");
        assert_eq!(view.kind, RELEASE_JOB_PUBLISH_BATCH);
        assert_eq!(view.component, job.subject.as_deref().unwrap_or_default());
    }

    /// 终态任务仍然能投影成 view（前端靠它渲染「失败 / 已删除」）。
    #[test]
    fn a_terminal_job_still_projects_a_view() {
        let mut job = release_job(ReleaseJobPayload {
            mode: RELEASE_JOB_PUBLISH.to_string(),
            component: "wist-agentd".to_string(),
            requested_by: "admin".to_string(),
            declared_version: Some("1.2.3".to_string()),
            artifacts: vec![artifact()],
        })
        .expect("job");
        job.state = crate::infra::jobs::JOB_FAILED.to_string();
        job.error_code = Some(crate::api::codes::RELEASE_PUBLISH_FAILED.to_string());
        job.error_status = Some(502);
        job.error_detail = Some("download failed".to_string());

        let view = ReleaseJobView::from_job(&job).expect("view");
        assert_eq!(view.state, crate::infra::jobs::JOB_FAILED);
        assert_eq!(
            view.error_code.as_deref(),
            Some(crate::api::codes::RELEASE_PUBLISH_FAILED)
        );
        assert_eq!(view.error_status, Some(502));
    }

    /// 保留期解析：未配置/空值用默认；显式 `0` 或脏值一律不清理（宁可不删）。
    #[test]
    fn retention_days_parsing_is_conservative() {
        let default = super::super::jobs::DEFAULT_JOB_RETENTION_DAYS;
        assert_eq!(parse_retention_days(None), default);
        assert_eq!(parse_retention_days(Some("")), default);
        assert_eq!(parse_retention_days(Some("   ")), default);
        assert_eq!(parse_retention_days(Some("30")), 30);
        assert_eq!(parse_retention_days(Some(" 14 ")), 14);
        assert_eq!(parse_retention_days(Some("0")), 0);
        assert_eq!(parse_retention_days(Some("-5")), 0, "负数 = 不清理");
        assert_eq!(parse_retention_days(Some("abc")), 0, "脏值不回退默认");
    }
}
