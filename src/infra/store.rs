// WistCenter 状态存储：Store trait + 双实现。
// - FileStore：JSON 文件快照（镜像 wist-gateway AdminStore），测试/无 PG 回退路径。
// - PgStore：PostgreSQL（开发期，见 pg_store.rs）。
// 持有每网关的凭证（sha256 hash）与最新上报状态（version/status/health/last_seen_at），
// 后续 GatewayRuntimeStatus / GatewayListView 从快照聚合读取。

use std::{
    collections::HashMap,
    fs,
    fs::OpenOptions,
    io,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock, Weak},
};

use orion_error::{conversion::ToStructError, prelude::*};
use serde::{Deserialize, Serialize};
use wist_control::GatewayInstanceLifecycleState;
use wist_control::types::DateTime;

use super::jobs::{CancelOutcome, JobProgress, JobRecord};
use super::{ReleaseArtifact, ReleasePackage, sha256_hex};
use crate::config::GatewayCredentialSeed;

pub use wist_error::{StoreError, StoreReason};

#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CenterStoreSnapshot {
    /// key = gateway_id。
    pub gateways: HashMap<String, StoredGateway>,
    /// key = agent_id（Gateway 上报的其下 Agent 状态快照）。
    pub agents: HashMap<String, StoredAgent>,
    /// 网关生命周期转变历史（key = gateway_id，有界保留最近 ~100 条）。
    pub lifecycle_events: HashMap<String, Vec<LifecycleEvent>>,
    /// 版本发布记录（key = component，如 wist-agentd / wist-gateway-stack）。
    pub releases: HashMap<String, Vec<ReleaseRecord>>,
    /// 升级计划（按创建顺序，新→旧）。
    pub upgrade_plans: Vec<UpgradePlanRecord>,
    /// 远程包下载任务（按创建顺序，新→旧；worker 串行执行）。
    #[serde(default)]
    pub jobs: Vec<JobRecord>,
    /// 网关-客户绑定记录。
    pub customer_bindings: Vec<GatewayCustomerBindingRecord>,
    /// 换绑审计（append-only，key = gateway_id，有界保留最近 ~100 条）。
    #[serde(default)]
    pub binding_audit: HashMap<String, Vec<GatewayBindingAuditEvent>>,
    /// 网关注册 Token（key = token_id；映射模型 GatewayEnrollmentToken）。
    #[serde(default)]
    pub enrollment_tokens: HashMap<String, StoredEnrollmentToken>,
}

/// 签发注册 Token 的入参（映射模型 GatewayEnrollmentToken 的签发侧可变字段）。
#[derive(Debug, Clone)]
pub struct EnrollmentTokenIssue {
    /// 明文 token（仅用于计算 hash 落库，不持久化明文）。
    pub token: String,
    /// 签发人（管理面 requested_by）。
    pub issued_by: String,
    /// 控制中心信任根（control-center.pem 内容），随注册 token 下发；
    /// 未配置 CA → None。
    pub control_center_trust_bundle: Option<String>,
}

/// 网关注册 Token 记录（映射模型 GatewayEnrollmentToken）：服务端只存 hash，
/// 用 max_uses/used_count/status/expiry 控制"限量、防重放、可吊销"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEnrollmentToken {
    pub token_id: String,
    pub token_hash: String,
    pub gateway_id: String,
    /// 环境绑定（模型字段；默认 "tenant-default"）。
    #[serde(default)]
    pub tenant_id: String,
    /// 环境绑定（模型字段；默认 "env-default"）。
    #[serde(default)]
    pub environment_id: String,
    /// 签发人（模型字段，admin 面的 requested_by）。
    #[serde(default)]
    pub issued_by: String,
    /// 随注册 token 下发的控制中心信任根（control-center.pem 内容）。
    #[serde(default)]
    pub control_center_trust_bundle: Option<String>,
    pub max_uses: i64,
    pub used_count: i64,
    pub status: String, // Active / Used / Exhausted / Revoked / Expired
    pub issued_at: DateTime,
    #[serde(default)]
    pub expires_at: Option<DateTime>,
    /// 吊销时间（status = Revoked 时记录）。
    #[serde(default)]
    pub revoked_at: Option<DateTime>,
}

/// 网关-客户绑定记录（映射模型 GatewayCustomerBinding）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayCustomerBindingRecord {
    pub gateway_id: String,
    pub customer_id: String,
    pub status: String,
    pub bound_at: DateTime,
    /// 绑定版本：同一客户重复绑定不递增；换绑递增。
    #[serde(default = "default_binding_revision")]
    pub revision: i64,
    /// 网关已上报生效的 revision。
    #[serde(default)]
    pub applied_revision: Option<i64>,
    #[serde(default)]
    pub applied_at: Option<DateTime>,
    /// 网关自报的 tenant_id（用于漂移检测；权威值仍是 `customer_id`）。
    #[serde(default)]
    pub reported_tenant_id: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

fn default_binding_revision() -> i64 {
    1
}

/// 换绑审计事件（映射模型 `Control.InsightCenterApp.AdminFacingInterface.GatewayBindingAuditEvent`）：
/// **谁**（`requested_by`）在**什么时候**把哪台网关绑到**哪个客户**（换绑时带旧值）。
/// 绑定表只保留最新值，历史在这里。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayBindingAuditEvent {
    pub gateway_id: String,
    pub customer_id: String,
    /// 换绑前的客户；首次绑定为 `None`。
    #[serde(default)]
    pub previous_customer_id: Option<String>,
    pub revision: i64,
    pub requested_by: String,
    pub at: DateTime,
}

/// 字符串截断（审计 / `last_error` 不该被超长输入撑大）。
fn bounded(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

/// 追加一条换绑审计（每网关有界保留最近 100 条）。
fn push_binding_audit(snapshot: &mut CenterStoreSnapshot, event: GatewayBindingAuditEvent) {
    let events = snapshot
        .binding_audit
        .entry(event.gateway_id.clone())
        .or_default();
    events.push(event);
    const MAX_EVENTS: usize = 100;
    if events.len() > MAX_EVENTS {
        let excess = events.len() - MAX_EVENTS;
        events.drain(..excess);
    }
}

/// 升级计划里的一个阶段（映射模型 `Control.Rollout.RolloutPhase`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradePhaseRecord {
    pub phase_index: i64,
    pub gateway_ids: Vec<String>,
    /// 推进闸门：manual | all_succeeded | success_rate:<NN>。
    #[serde(default)]
    pub advance_rule: String,
    /// pending | rolling | completed
    #[serde(default)]
    pub status: String,
}

/// 升级计划里逐网关的一行（映射模型 `Control.Rollout.RolloutPlanEntry`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradePlanEntryRecord {
    pub gateway_id: String,
    /// pending | dispatched | succeeded | failed
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub detail: String,
    /// 本次任务 ID（`tasks/<kind>-<task_id>-<ts>/` 里的那个；同一份计划重试会变）。
    #[serde(default)]
    pub task_id: Option<String>,
    /// 任务执行日志目录（网关本机路径）。
    #[serde(default)]
    pub log_dir: Option<String>,
    /// 任务执行日志摘要（失败回执才带；网关侧已脱敏、服务端再截一次）。
    #[serde(default)]
    pub log_excerpt: Option<String>,
    pub updated_at: DateTime,
}

/// 一次升级计划记录（映射模型 `Control.Rollout.RolloutPlan`：中心铺的是**网关**，target = gateway_id）。
///
/// 条目（`entries`）在存储上与计划同放一份：模型里 `RolloutPlanView = plan + entries` ，中心这边
/// 计划很小、又不分页，合放省掉一张表；对外的读投影仍按 `plan + entries` 出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradePlanRecord {
    pub plan_id: String,
    /// 动作：`upgrade`（升级安装）/ `push-agent-package`（Agent 包下发，见
    /// `api::rollout::PUSH_AGENT_PACKAGE_ACTION`）。
    #[serde(default = "default_upgrade_action")]
    pub action: String,
    /// 动作参数（JSON）：`{"targets":[{"component","target_version"}]}`。
    #[serde(default)]
    pub spec: String,
    /// 截止时间；中心不物化一次性工作，只做记录（可空）。
    #[serde(default)]
    pub deadline_at: Option<DateTime>,
    #[serde(default)]
    pub timeout_seconds: i64,
    #[serde(default)]
    pub phases: Vec<UpgradePhaseRecord>,
    #[serde(default)]
    pub batch_size: i64,
    /// 当前进行到第几阶段（0 = 尚未开始）。
    #[serde(default)]
    pub current_phase: i64,
    /// draft | rolling | completed | failed | canceled
    pub status: String,
    #[serde(default)]
    pub created_by: String,
    pub created_at: DateTime,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub approved_at: Option<DateTime>,
    /// 归档时刻（`None` = 未归档）。归档是**标记**：计划与逐目标条目全留，
    /// 默认列表不再展示，`{"archived": false}` 随时恢复。
    #[serde(default)]
    pub archived_at: Option<DateTime>,
    /// 逐目标条目（存储上与计划同放，见类型注释）。
    #[serde(default)]
    pub entries: Vec<UpgradePlanEntryRecord>,

    // ─— 迁移用：模型升级之前的旧字段（`steps` / `targets`），读取后由 `normalize_legacy` 折算并清空 ─—
    #[serde(rename = "steps", default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_steps: Vec<LegacyUpgradeStep>,
    #[serde(rename = "targets", default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_targets: Vec<LegacyUpgradeTarget>,
}

fn default_upgrade_action() -> String {
    wist_control::ACTION_UPGRADE.to_string()
}

/// **迁移用**：旧记录的执行步骤（`step_index` / `gateway_ids` / `status`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyUpgradeStep {
    #[serde(default)]
    pub step_index: i64,
    #[serde(default)]
    pub gateway_ids: Vec<String>,
    #[serde(default)]
    pub status: String,
}

/// **迁移用**：旧记录的升级目标（`component` / `target_version`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyUpgradeTarget {
    #[serde(default)]
    pub component: String,
    #[serde(default)]
    pub target_version: String,
}

/// 把模型升级前落下的旧记录折算成新形状（幂等，可重复跑）：
///
/// - status：`pending` → `draft`、`approved` → `rolling`；
/// - `steps`（旧：batch + 无闸门）→ `phases`（补闸门：首段 manual、其余 all_succeeded）；
/// - `targets` → `spec` 的 JSON（`{"targets":[...]}`）；
/// - 旧记录没有逐目标条目 → 按全量目标补成 `pending`（否则视图里看不到范围、结果也无处回填）。
pub fn normalize_upgrade_plan(plan: &mut UpgradePlanRecord) {
    if plan.status == "pending" {
        plan.status = "draft".to_string();
    } else if plan.status == "approved" {
        plan.status = "rolling".to_string();
    }
    if plan.spec.is_empty() && !plan.legacy_targets.is_empty() {
        let targets: Vec<serde_json::Value> = plan
            .legacy_targets
            .iter()
            .map(|target| {
                serde_json::json!({
                    "component": target.component,
                    "target_version": target.target_version,
                })
            })
            .collect();
        plan.spec = serde_json::json!({ "targets": targets }).to_string();
    }
    if plan.phases.is_empty() && !plan.legacy_steps.is_empty() {
        plan.phases = plan
            .legacy_steps
            .iter()
            .enumerate()
            .map(|(index, step)| UpgradePhaseRecord {
                phase_index: step.step_index.max(index as i64 + 1),
                gateway_ids: step.gateway_ids.clone(),
                // 旧记录没有闸门：按现行固定策略补（末段不看闸门，值不重要）。
                advance_rule: if index == 0 {
                    "manual".to_string()
                } else {
                    "all_succeeded".to_string()
                },
                status: step.status.clone(),
            })
            .collect();
        if plan.current_phase == 0 && plan.status == "rolling" {
            plan.current_phase = 1;
        }
    }
    // 补齐全量条目：新建的计划在 create 时已铺好，只有旧记录会走到这里。
    if plan.entries.is_empty() && !plan.phases.is_empty() {
        let updated_at = plan.created_at.clone();
        let entries: Vec<UpgradePlanEntryRecord> = plan
            .phases
            .iter()
            .flat_map(|phase| phase.gateway_ids.iter())
            .map(|gateway_id| UpgradePlanEntryRecord {
                gateway_id: gateway_id.clone(),
                status: "pending".to_string(),
                detail: String::new(),
                task_id: None,
                log_dir: None,
                log_excerpt: None,
                updated_at: updated_at.clone(),
            })
            .collect();
        plan.entries = entries;
    }
    plan.legacy_steps.clear();
    plan.legacy_targets.clear();
}

/// 一次版本发布记录（映射模型 WistAgentdRelease / WarpGatewayRelease）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub version: String,
    pub artifact_url: String,
    /// 制品内容的 sha256（裸 hex）。录入时算出 / 校验；老记录为 `None`。
    #[serde(default)]
    pub package_sha256: Option<String>,
    /// 目标平台（target-triple，如 `aarch64-apple-darwin` / `x86_64-unknown-linux-musl`）。
    /// 无平台概念的包（如部署栈 `wist-gateway-stack`）解析不出 → `None`（界面显示「通用」）。
    #[serde(default)]
    pub platform: Option<String>,
    /// 托管状态：`published`（已录入）/ `expired`（已过期）。
    pub status: String,
    pub published_at: DateTime,
    /// 包内 `compat.json`（升级兼容声明）；老记录/无声明为 `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat: Option<wist_release::compat::CompatManifest>,
}

/// 管理面「安装包」视图：共享的 `ReleasePackage`（version + artifacts）外挂目录字段。
///
/// JSON 形如 `{ component, version, artifacts: [...], status, published_at }`（`package` 被 flatten）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleasePackageRecord {
    /// 组件（目录键，如 `galaxy-ops`）。
    pub component: String,
    /// 包级托管状态：`published` / `expired`。
    pub status: String,
    /// 首次录入时间（组内最早）。
    pub published_at: DateTime,
    /// 包内 `compat.json`（同版本多平台行共用一份；老记录为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat: Option<wist_release::compat::CompatManifest>,
    /// 按**当前中心版本**算出的兼容性报告（列表读投影；不落库）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<wist_release::compat::CompatReport>,
    #[serde(flatten)]
    pub package: ReleasePackage,
}

/// 把某组件的扁平发布记录（一行一个制品）按 `version` 归成安装包。
///
/// - 组顺序 = 首次出现顺序（调用方一般按 `published_at` 新→旧传入）；
/// - 组内 `published_at` 取最早（包首次出现时间）；
/// - 组内制品按 `platform` 排序。
pub fn group_release_packages(
    component: &str,
    records: Vec<ReleaseRecord>,
) -> Vec<ReleasePackageRecord> {
    let mut packages: Vec<ReleasePackageRecord> = Vec::new();
    for record in records {
        let artifact = ReleaseArtifact {
            platform: record.platform,
            sha256: record.package_sha256.unwrap_or_default(),
            source: record.artifact_url,
        };
        if let Some(existing) = packages
            .iter_mut()
            .find(|existing| existing.package.version == record.version)
        {
            if record.published_at.to_chrono() < existing.published_at.to_chrono() {
                existing.published_at = record.published_at;
            }
            if existing.compat.is_none() && record.compat.is_some() {
                existing.compat = record.compat.clone();
            }
            existing.package.artifacts.push(artifact);
        } else {
            packages.push(ReleasePackageRecord {
                component: component.to_string(),
                status: record.status,
                published_at: record.published_at,
                compat: record.compat,
                compatibility: None,
                package: ReleasePackage::new(record.version, vec![artifact]),
            });
        }
    }
    for package in &mut packages {
        package
            .package
            .artifacts
            .sort_by(|left, right| left.platform.cmp(&right.platform));
    }
    packages
}

/// 网关生命周期一次状态转变记录（过程历史，append-only）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub gateway_id: String,
    pub from_state: Option<GatewayInstanceLifecycleState>,
    pub to_state: GatewayInstanceLifecycleState,
    pub at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGateway {
    pub gateway_id: String,
    pub instance_id: String,
    pub credential_token_hash: String,
    pub credential_status: StoredGatewayCredentialStatus,
    #[serde(default)]
    pub credential_expires_at: Option<String>,
    /// 一次性接入券 的 hash（LINK_TOKEN）。**由「生成/轮换」动作签发**
    /// （create 不再签发），init-url 置备成功后清空（消费）；空串 = 无/已消费。
    #[serde(default)]
    pub link_token_hash: String,
    /// 接入 token 的过期时刻（RFC3339）。**短 TTL**：过期后不可用（需重新生成/轮换）。
    #[serde(default)]
    pub link_token_expires_at: Option<String>,
    /// 最新上报状态（喂 GatewayRuntimeStatus，last_seen_at = reported_at）。
    #[serde(default)]
    pub version: Option<String>,
    /// 网关宿主侧依赖工具版本（gops / gx，装在 `$HOME/bin`；由 gwlinkd 探测上报）。
    #[serde(default)]
    pub gops_version: Option<String>,
    #[serde(default)]
    pub gx_version: Option<String>,
    /// gwlinkd（宿主侧常驻）**自身**版本（与上面 `version` 分开：那是网关容器的）。
    #[serde(default)]
    pub gwlinkd_version: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub health: Option<String>,
    #[serde(default)]
    pub memory_bytes: Option<i64>,
    #[serde(default)]
    pub cpu_percent: Option<f64>,
    /// 网关**对外基址**（对外域名，管理面「对外地址」‖`[server] public_base_url`）。
    /// 来自注册 / 状态上报，留最新一份；中心据此知道该网关对外域名。
    #[serde(default)]
    pub public_base_url: Option<String>,
    // 网关状态富化（机队聚合 + 进程运行时长）；见设计 edge/gateway-status-report.md。
    #[serde(default)]
    pub uptime_seconds: Option<i64>,
    #[serde(default)]
    pub agent_count: Option<i64>,
    #[serde(default)]
    pub online_agents: Option<i64>,
    #[serde(default)]
    pub offline_agents: Option<i64>,
    #[serde(default)]
    pub last_seen_lag_seconds: Option<i64>,
    #[serde(default)]
    pub store_bytes: Option<i64>,
    #[serde(default)]
    pub ingest_accepted_total: Option<i64>,
    #[serde(default)]
    pub ingest_rejected_total: Option<i64>,
    #[serde(default)]
    pub last_ingest_at: Option<DateTime>,
    #[serde(default)]
    pub memory_total_bytes: Option<i64>,
    #[serde(default)]
    pub load_1m: Option<f64>,
    #[serde(default)]
    pub load_5m: Option<f64>,
    #[serde(default)]
    pub load_15m: Option<f64>,
    #[serde(default)]
    pub disk_usage_percent: Option<f64>,
    #[serde(default)]
    pub disk_total_bytes: Option<i64>,
    #[serde(default)]
    pub disk_available_bytes: Option<i64>,
    #[serde(default)]
    pub lifecycle_state: Option<GatewayInstanceLifecycleState>,
    #[serde(default)]
    pub initialized_at: Option<DateTime>,
    #[serde(default)]
    pub created_at: Option<DateTime>,
    #[serde(default)]
    pub last_seen_at: Option<DateTime>,
    /// **归档**时刻；`None` = 未归档。
    ///
    /// 归档是**标记**，不是删除：默认视图（网关态势 / 实例总览）不再显示它，状态、历史、生命周期
    /// 记录全都留着；只允许归档**离线**的网关（在线的不该被藏起来）。网关重新上线（换证注册，或
    /// 重新上报 online）时自动清空 —— 「回来了就回到正常」，不用人工记得取消归档。
    #[serde(default)]
    pub archived_at: Option<DateTime>,
}

impl StoredGateway {
    pub fn provisioned(
        gateway_id: String,
        instance_id: String,
        credential_token_hash: String,
        expires_at: Option<String>,
    ) -> Self {
        Self {
            gateway_id,
            instance_id,
            credential_token_hash,
            credential_status: StoredGatewayCredentialStatus::Active,
            credential_expires_at: expires_at,
            link_token_hash: String::new(),
            link_token_expires_at: None,
            version: None,
            gops_version: None,
            gx_version: None,
            gwlinkd_version: None,
            status: None,
            health: None,
            memory_bytes: None,
            cpu_percent: None,
            public_base_url: None,
            uptime_seconds: None,
            agent_count: None,
            online_agents: None,
            offline_agents: None,
            last_seen_lag_seconds: None,
            store_bytes: None,
            ingest_accepted_total: None,
            ingest_rejected_total: None,
            last_ingest_at: None,
            memory_total_bytes: None,
            load_1m: None,
            load_5m: None,
            load_15m: None,
            disk_usage_percent: None,
            disk_total_bytes: None,
            disk_available_bytes: None,
            lifecycle_state: None,
            initialized_at: None,
            created_at: None,
            last_seen_at: None,
            archived_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredGatewayCredentialStatus {
    Active,
    Expired,
    Revoked,
}

/// Gateway 上报的其下 Agent 状态快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAgent {
    pub agent_id: String,
    pub gateway_id: String,
    pub instance_id: String,
    pub version: String,
    pub status: String,
    pub health: String,
    pub memory_bytes: Option<i64>,
    pub cpu_percent: Option<f64>,
    pub admin_latency_ms: Option<i64>,
    pub last_seen_at: DateTime,
}

/// 单次状态上报落库参数（ReceiveGatewayStatusReport → store）。
#[derive(Debug, Clone)]
pub struct GatewayStatusUpdate {
    pub gateway_id: String,
    pub instance_id: String,
    pub version: String,
    pub gops_version: Option<String>,
    pub gx_version: Option<String>,
    /// gwlinkd（宿主侧常驻）自身版本；老 gwlinkd 不带 → None。
    pub gwlinkd_version: Option<String>,
    pub status: String,
    pub health: String,
    pub memory_bytes: Option<i64>,
    pub cpu_percent: Option<f64>,
    pub public_base_url: Option<String>,
    pub last_seen_at: DateTime,
    // 富化（可选）。
    pub uptime_seconds: Option<i64>,
    pub agent_count: Option<i64>,
    pub online_agents: Option<i64>,
    pub offline_agents: Option<i64>,
    pub last_seen_lag_seconds: Option<i64>,
    pub store_bytes: Option<i64>,
    pub ingest_accepted_total: Option<i64>,
    pub ingest_rejected_total: Option<i64>,
    pub last_ingest_at: Option<DateTime>,
    pub memory_total_bytes: Option<i64>,
    pub load_1m: Option<f64>,
    pub load_5m: Option<f64>,
    pub load_15m: Option<f64>,
    pub disk_usage_percent: Option<f64>,
    pub disk_total_bytes: Option<i64>,
    pub disk_available_bytes: Option<i64>,
}

/// 网关凭证与状态的持久化抽象：FileStore（JSON 文件，测试/无 PG 回退）与
/// PgStore（PostgreSQL，开发期）双实现。
/// 原生 async fn in trait 在当前工具链下不可 dyn（E0038），故用 `#[async_trait]`
/// （内部转为 `Pin<Box<dyn Future + Send>>`，trait 保持 `Send + Sync` 可 `Arc<dyn Store>`）。
#[async_trait::async_trait]
pub trait Store: Send + Sync + std::fmt::Debug {
    /// 用 seed 凭证补齐缺失的网关（已有条目不覆盖，保留已轮换凭证）。返回是否有新增。
    async fn seed(&self, seeds: &[GatewayCredentialSeed]) -> Result<bool, StoreError>;
    /// 全部网关（含已接入未上报的），按 gateway_id 排序。
    async fn list_gateways(&self) -> Result<Vec<StoredGateway>, StoreError>;
    async fn get_gateway(&self, gateway_id: &str) -> Result<Option<StoredGateway>, StoreError>;
    /// 落库最新上报状态（仅更新已接入网关，与 FileStore 的 update 语义一致）。
    async fn upsert_gateway_status(&self, update: &GatewayStatusUpdate) -> Result<(), StoreError>;

    /// 标记 / 清除**归档**（`None` = 取消归档）。返回是否命中了这台网关。
    ///
    /// 只落一个时刻，不做删除 —— 默认视图按它过滤，历史全留。调用方负责「只归档离线网关」那条
    /// 业务约束（存储层不判定在线）。
    async fn set_gateway_archived(
        &self,
        gateway_id: &str,
        archived_at: Option<DateTime>,
    ) -> Result<bool, StoreError>;

    /// 记下/刷新网关的**对外域名**（注册时即落，早于第一拍状态上报）。
    async fn set_gateway_public_base_url(
        &self,
        gateway_id: &str,
        public_base_url: &str,
    ) -> Result<(), StoreError>;
    /// 创建网关实例：gateway_id 已存在 → `Err(Conflict)`；否则以空 instance_id 接入。
    /// token 非空则存 `sha256(token)`，空 token → 空 hash（无凭证网关无法上报）。
    async fn create_gateway(
        &self,
        gateway_id: &str,
        token: &str,
    ) -> Result<StoredGateway, StoreError>;
    /// 为网关签发注册 Token（映射模型 GatewayEnrollmentToken）：持久化 hash、
    /// 限量（默认 max_uses=1）、状态 Active、有效期。注册/初始化时消费。
    async fn create_enrollment_token(
        &self,
        gateway_id: &str,
        issue: &EnrollmentTokenIssue,
    ) -> Result<StoredEnrollmentToken, StoreError>;
    /// 校验并消费一个注册 Token：按 hash 查找；状态/有效期/用量不合法 → Err；
    /// 合法则递增 used_count，达 max_uses → Exhausted；返回 token（含 gateway_id）。
    async fn consume_enrollment_token(
        &self,
        token: &str,
    ) -> Result<StoredEnrollmentToken, StoreError>;
    /// 校验并消费一次性接入券（LINK_TOKEN）：比对 hash + 未初始化，
    /// 成功则清空 link_token_hash。返回是否消费成功。
    async fn consume_link_token(
        &self,
        gateway_id: &str,
        link_token: &str,
    ) -> Result<bool, StoreError>;
    /// 轮换/生成一次性接入券（LINK_TOKEN）：覆盖 `link_token_hash` 与
    /// `link_token_expires_at`（旧券即失效）。仅存 hash（调用方一次性交付明文）；网关不存在 → false。
    async fn rotate_link_token(
        &self,
        gateway_id: &str,
        link_hash: &str,
        expires_at: Option<String>,
    ) -> Result<bool, StoreError>;
    /// 落库运行期凭据（RUNTIME_TOKEN）：更新 credential_token_hash + Active + 过期时间。
    async fn update_gateway_credential(
        &self,
        gateway_id: &str,
        token_hash: &str,
        expires_at: Option<String>,
    ) -> Result<bool, StoreError>;
    /// 吊销注册 Token（映射模型 GatewayEnrollmentTokenStatus.Revoked）：
    /// 校验归属 gateway_id 后置 status=Revoked + revoked_at；未知 token / 归属不符 → Err。
    async fn revoke_enrollment_token(
        &self,
        gateway_id: &str,
        token_id: &str,
    ) -> Result<StoredEnrollmentToken, StoreError>;
    /// 查询某网关最近签发的一个注册 Token（初始配置的 enrollment_token_id 引用用）。
    async fn get_enrollment_token_for_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Option<StoredEnrollmentToken>, StoreError>;
    /// 落库 Gateway 上报的其下 Agent 状态（按 agent_id 幂等 upsert，记录归属 gateway_id）。
    async fn upsert_agent_status(
        &self,
        gateway_id: &str,
        agents: &[StoredAgent],
    ) -> Result<(), StoreError>;
    /// 生命周期：Provisioned → Initializing（Gateway 首次拉取初始配置时）。
    async fn mark_gateway_initializing(&self, gateway_id: &str) -> Result<(), StoreError>;
    /// 记录一次生命周期转变事件（append-only 过程历史）。
    async fn record_lifecycle_event(
        &self,
        gateway_id: &str,
        from: Option<GatewayInstanceLifecycleState>,
        to: GatewayInstanceLifecycleState,
    ) -> Result<(), StoreError>;
    /// 查询某网关的生命周期转变历史（按时间升序）。
    async fn list_lifecycle_events(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<LifecycleEvent>, StoreError>;
    /// 记录一次版本发布（component = wist-agentd / wist-gateway-stack），返回记录。
    /// `platform` 为目标平台（target-triple），无平台概念的包传 `None`。
    async fn publish_release(
        &self,
        component: &str,
        version: &str,
        artifact_url: &str,
        package_sha256: Option<&str>,
        platform: Option<&str>,
    ) -> Result<ReleaseRecord, StoreError> {
        self.publish_release_with_compat(
            component,
            version,
            artifact_url,
            package_sha256,
            platform,
            None,
        )
        .await
    }

    /// 同 [`Store::publish_release`]，但带上包内 `compat.json`（发布时已解析）。
    async fn publish_release_with_compat(
        &self,
        component: &str,
        version: &str,
        artifact_url: &str,
        package_sha256: Option<&str>,
        platform: Option<&str>,
        compat: Option<wist_release::compat::CompatManifest>,
    ) -> Result<ReleaseRecord, StoreError>;
    /// 查询某组件的历史发布记录（新→旧）。
    async fn list_releases(&self, component: &str) -> Result<Vec<ReleaseRecord>, StoreError>;
    /// 更新某组件某版本的托管状态（如 `published` → `expired`）：该版本**全部制品行**一起改。
    /// 返回受影响行数（0 = 无该版本）。
    async fn set_release_status(
        &self,
        component: &str,
        version: &str,
        status: &str,
    ) -> Result<u64, StoreError>;
    /// 补写某**制品行**的平台（身份解析改好后的历史记录缺平台时用）。
    /// 按 `(component, version, package_sha256)` 精确定位，避免把多平台包的其它平台行一并覆盖。无该行 → `None`。
    async fn set_release_platform(
        &self,
        component: &str,
        version: &str,
        package_sha256: &str,
        platform: Option<&str>,
    ) -> Result<Option<ReleaseRecord>, StoreError>;
    /// 创建升级计划（多目标 + 网关范围 + 灰度阶段），status=draft。
    async fn create_upgrade_plan(
        &self,
        plan: &UpgradePlanRecord,
    ) -> Result<UpgradePlanRecord, StoreError>;
    /// 查询全部升级计划（新→旧）。
    async fn list_upgrade_plans(&self) -> Result<Vec<UpgradePlanRecord>, StoreError>;
    /// 取一份升级计划（含逐目标条目）；无则 `None`。
    async fn get_upgrade_plan(
        &self,
        plan_id: &str,
    ) -> Result<Option<UpgradePlanRecord>, StoreError>;
    /// 覆盖保存一份升级计划（批准 / 推进 / 结果回填都走它）。
    async fn save_upgrade_plan(&self, plan: &UpgradePlanRecord) -> Result<(), StoreError>;
    /// **物理删除**一份升级计划（计划与逐目标条目同存于一条记录，随计划一并删除）。
    /// 返回是否命中（`false` = 计划不存在）。调用方负责「只删终结态」那条业务约束
    /// （执行中的计划还有在飞的工作，存储层不判定状态）。
    async fn delete_upgrade_plan(&self, plan_id: &str) -> Result<bool, StoreError>;
    /// 新建一条后台任务（`state=queued`）。
    async fn create_job(&self, job: &JobRecord) -> Result<(), StoreError>;
    /// 取一条任务；无则 `None`。
    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>, StoreError>;
    /// 某队列最近的 `limit` 条任务（新→旧）。
    async fn list_jobs(&self, queue: &str, limit: usize) -> Result<Vec<JobRecord>, StoreError>;
    /// 按可选条件列出任务（`queue` / `kind` / `state` / `subject` 都为 `None` 时等于全量最近 N 条）。
    async fn list_jobs_filtered(
        &self,
        queue: Option<&str>,
        kind: Option<&str>,
        state: Option<&str>,
        subject: Option<&str>,
        limit: usize,
    ) -> Result<Vec<JobRecord>, StoreError>;
    /// 原子认领某队列最早的一条 `queued` 任务（置 `running` 并写 `started_at`）；无则 `None`。
    async fn claim_next_job(&self, queue: &str) -> Result<Option<JobRecord>, StoreError>;
    /// 覆盖保存一条任务（状态流转 / 结果回填）。
    async fn save_job(&self, job: &JobRecord) -> Result<(), StoreError>;
    /// 只更新任务的进度（执行中高频回写，不覆盖整条记录）。
    async fn update_job_progress(
        &self,
        job_id: &str,
        progress: &JobProgress,
    ) -> Result<(), StoreError>;
    /// 把某队列上次退出时残留的 `running` 任务排回 `queued`（业务执行需幂等）。
    /// 返回被重新排队的条数。
    async fn requeue_running_jobs(&self, queue: &str) -> Result<u64, StoreError>;
    /// 取消一条**排队中**的任务（原子：与认领竞争时只有一个能成功）。
    async fn cancel_queued_job(&self, job_id: &str) -> Result<CancelOutcome, StoreError>;
    /// 删除某队列在 `before` 之前已终结（成功 / 失败 / 已取消）的任务；返回删除条数。
    async fn delete_terminal_jobs_before(
        &self,
        queue: &str,
        before: &DateTime,
    ) -> Result<u64, StoreError>;
    /// 绑定网关到客户（幂等：同网关重复绑定同一客户不递增 revision；换绑递增）。
    /// `requested_by` 在同一临界区内写进审计（归属变化时）。
    async fn bind_gateway_customer(
        &self,
        gateway_id: &str,
        customer_id: &str,
        requested_by: &str,
    ) -> Result<GatewayCustomerBindingRecord, StoreError>;
    /// 查询全部网关-客户绑定。
    async fn list_customer_bindings(&self)
    -> Result<Vec<GatewayCustomerBindingRecord>, StoreError>;
    /// 查询某网关的客户绑定；无则 `None`。
    async fn get_customer_binding(
        &self,
        gateway_id: &str,
    ) -> Result<Option<GatewayCustomerBindingRecord>, StoreError>;
    /// 记录网关上报的 tenant_id / revision：一致且版本相同 → applied；否则记漂移/落后。
    async fn record_customer_binding_report(
        &self,
        gateway_id: &str,
        reported_tenant_id: &str,
        reported_revision: i64,
    ) -> Result<Option<GatewayCustomerBindingRecord>, StoreError>;
    /// 命令回执失败（`bind-tenant`）→ 当前版本绑定标 `failed` + 原因。返回是否命中当前版本。
    async fn mark_binding_failed(
        &self,
        gateway_id: &str,
        revision: i64,
        error: &str,
    ) -> Result<bool, StoreError>;
    /// 查询某网关的换绑审计（按时间升序）。
    async fn list_binding_audit(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayBindingAuditEvent>, StoreError>;
    /// 查询某 gateway 下的全部 Agent 状态（按 agent_id 排序）。
    async fn list_agents_by_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<StoredAgent>, StoreError>;
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let lock = shared_process_lock(&path);
        Self { path, lock }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<CenterStoreSnapshot, StoreError> {
        let _guard = self.lock()?;
        self.load_snapshot()
    }

    pub fn save(&self, snapshot: &CenterStoreSnapshot) -> Result<(), StoreError> {
        let _guard = self.lock()?;
        self.save_snapshot(snapshot)
    }

    pub fn update<T>(
        &self,
        mutate: impl FnOnce(&mut CenterStoreSnapshot) -> T,
    ) -> Result<T, StoreError> {
        let _guard = self.lock()?;
        let mut snapshot = self.load_snapshot()?;
        let output = mutate(&mut snapshot);
        self.save_snapshot(&snapshot)?;
        Ok(output)
    }

    /// 用 seed 凭证补齐缺失的网关（已有条目不覆盖，保留已轮换凭证）。返回是否有新增。
    pub fn seed(&self, seeds: &[GatewayCredentialSeed]) -> Result<bool, StoreError> {
        let seeds = seeds.to_vec();
        self.update(|snapshot| {
            let mut added = false;
            for seed in &seeds {
                if snapshot.gateways.contains_key(&seed.gateway_id) {
                    continue;
                }
                snapshot.gateways.insert(
                    seed.gateway_id.clone(),
                    StoredGateway::provisioned(
                        seed.gateway_id.clone(),
                        String::new(),
                        sha256_hex(&seed.token),
                        seed.expires_at.clone(),
                    ),
                );
                added = true;
            }
            added
        })
    }

    /// 创建网关实例（同步，供测试与 trait 委托）：gateway_id 已存在 → Conflict。
    /// `token` 为一次性接入券（LINK_TOKEN），只存 sha256；
    /// 运行期凭据（credential_token_hash）留空，注册后签发 RUNTIME_TOKEN 时再落库。
    pub fn create_gateway(
        &self,
        gateway_id: &str,
        token: &str,
    ) -> Result<StoredGateway, StoreError> {
        let stored = self.update(|snapshot| {
            if snapshot.gateways.contains_key(gateway_id) {
                return Err(StoreReason::Conflict
                    .to_err()
                    .with_detail(gateway_id.to_string()));
            }
            let link_hash = if token.is_empty() {
                String::new()
            } else {
                sha256_hex(token)
            };
            let mut stored = StoredGateway::provisioned(
                gateway_id.to_string(),
                String::new(),
                String::new(),
                None,
            );
            stored.link_token_hash = link_hash;
            stored.lifecycle_state = Some(GatewayInstanceLifecycleState::Provisioned);
            stored.created_at = Some(DateTime::now());
            snapshot
                .gateways
                .insert(gateway_id.to_string(), stored.clone());
            Ok(stored)
        })??;
        FileStore::record_lifecycle_event(
            self,
            gateway_id,
            None,
            GatewayInstanceLifecycleState::Provisioned,
        )?;
        Ok(stored)
    }

    /// 签发注册 Token（同步，供测试与 trait 委托）：默认 max_uses=1、30 天有效、
    /// 环境绑定 tenant-default/env-default，携带控制中心信任根。
    pub fn create_enrollment_token(
        &self,
        gateway_id: &str,
        issue: &EnrollmentTokenIssue,
    ) -> Result<StoredEnrollmentToken, StoreError> {
        let token_hash = if issue.token.is_empty() {
            String::new()
        } else {
            sha256_hex(&issue.token)
        };
        self.update(|snapshot| {
            let now = DateTime::now();
            let serial = snapshot
                .enrollment_tokens
                .values()
                .filter(|t| t.gateway_id == gateway_id)
                .count() as i64
                + 1;
            let token = StoredEnrollmentToken {
                token_id: format!("enroll-{gateway_id}-{serial}"),
                token_hash,
                gateway_id: gateway_id.to_string(),
                tenant_id: "tenant-default".to_string(),
                environment_id: "env-default".to_string(),
                issued_by: issue.issued_by.clone(),
                control_center_trust_bundle: issue.control_center_trust_bundle.clone(),
                max_uses: 1,
                used_count: 0,
                status: "Active".to_string(),
                issued_at: now.clone(),
                expires_at: Some(DateTime::in_days(30)),
                revoked_at: None,
            };
            snapshot
                .enrollment_tokens
                .insert(token.token_id.clone(), token.clone());
            Ok(token)
        })?
    }

    /// 吊销注册 Token（同步，供测试与 trait 委托）：校验归属 gateway_id 后
    /// status → Revoked + revoked_at。已吊销再吊销视为幂等成功；未知 token / 归属不符 → Err。
    pub fn revoke_enrollment_token(
        &self,
        gateway_id: &str,
        token_id: &str,
    ) -> Result<StoredEnrollmentToken, StoreError> {
        self.update(|snapshot| {
            let Some(token) = snapshot.enrollment_tokens.get_mut(token_id) else {
                return Err(StoreReason::Enrollment
                    .to_err()
                    .with_detail("token not found"));
            };
            if token.gateway_id != gateway_id {
                return Err(StoreReason::Enrollment
                    .to_err()
                    .with_detail("token gateway mismatch"));
            }
            token.status = "Revoked".to_string();
            token.revoked_at = Some(DateTime::now());
            Ok(token.clone())
        })?
    }

    /// 查询某网关最近签发的一个注册 Token（同步，供测试与 trait 委托）：
    /// 按 issued_at 取最新，供初始配置的 enrollment_token_id 引用。
    pub fn get_enrollment_token_for_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Option<StoredEnrollmentToken>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot
            .enrollment_tokens
            .values()
            .filter(|token| token.gateway_id == gateway_id)
            .max_by(|left, right| left.issued_at.to_chrono().cmp(&right.issued_at.to_chrono()))
            .cloned())
    }

    /// 校验并消费注册 Token（同步）：按 hash 查找，校验状态/有效期/用量，
    /// 递增 used_count，达 max_uses → Exhausted；返回 token（含 gateway_id）。
    pub fn consume_enrollment_token(
        &self,
        token: &str,
    ) -> Result<StoredEnrollmentToken, StoreError> {
        let token_hash = sha256_hex(token);
        self.update(|snapshot| {
            let found = snapshot
                .enrollment_tokens
                .values_mut()
                .find(|t| !t.token_hash.is_empty() && t.token_hash == token_hash)
                .ok_or_else(|| {
                    StoreReason::Enrollment
                        .to_err()
                        .with_detail("token not found")
                })?;
            if found.status != "Active" && found.status != "Used" {
                return Err(StoreReason::Enrollment
                    .to_err()
                    .with_detail(format!("token status {}", found.status)));
            }
            if found
                .expires_at
                .as_ref()
                .is_some_and(|exp| exp.to_chrono() < chrono::Utc::now())
            {
                found.status = "Expired".to_string();
                return Err(StoreReason::Enrollment
                    .to_err()
                    .with_detail("token expired"));
            }
            if found.used_count >= found.max_uses {
                found.status = "Exhausted".to_string();
                return Err(StoreReason::Enrollment
                    .to_err()
                    .with_detail("token exhausted"));
            }
            found.used_count += 1;
            found.status = if found.used_count >= found.max_uses {
                "Exhausted".to_string()
            } else {
                "Used".to_string()
            };
            Ok(found.clone())
        })?
    }

    /// 校验并消费一次性接入券（同步）：比对 `link_token_hash`、**未过期**，网关必须
    /// 处于 Provisioned（未初始化）且 token 未消费；成功则清空 hash（消费）。
    /// 返回是否消费成功（不匹配/已消费/已过期/已初始化 → false，由 handler 映射 401）。
    pub fn consume_link_token(
        &self,
        gateway_id: &str,
        link_token: &str,
    ) -> Result<bool, StoreError> {
        let link_hash = sha256_hex(link_token);
        self.update(|snapshot| {
            let Some(gateway) = snapshot.gateways.get_mut(gateway_id) else {
                return false;
            };
            if gateway.link_token_hash.is_empty()
                || gateway.link_token_hash != link_hash
                || gateway.lifecycle_state != Some(GatewayInstanceLifecycleState::Provisioned)
            {
                return false;
            }
            // 短 TTL：过期即拒，并顺手清掉（旧券不可再用）。
            if gateway
                .link_token_expires_at
                .as_deref()
                .is_some_and(|expires| {
                    chrono::DateTime::parse_from_rfc3339(expires)
                        .map(|value| value.with_timezone(&chrono::Utc) < chrono::Utc::now())
                        .unwrap_or(false)
                })
            {
                gateway.link_token_hash.clear();
                gateway.link_token_expires_at = None;
                return false;
            }
            gateway.link_token_hash.clear();
            gateway.link_token_expires_at = None;
            true
        })
    }

    /// 轮换/生成接入券（同步）：覆盖 `link_token_hash` + 有效期（旧券即失效）。网关不存在 → false。
    pub fn rotate_link_token(
        &self,
        gateway_id: &str,
        link_hash: &str,
        expires_at: Option<String>,
    ) -> Result<bool, StoreError> {
        self.update(|snapshot| {
            let Some(gateway) = snapshot.gateways.get_mut(gateway_id) else {
                return false;
            };
            gateway.link_token_hash = link_hash.to_string();
            gateway.link_token_expires_at = expires_at;
            true
        })
    }

    /// 落库运行期凭据（RUNTIME_TOKEN，同步）：更新 credential_token_hash + Active + 过期时间。
    /// 网关注册/续期时调用；旧凭据 hash 被覆盖即失效。返回是否更新成功。
    pub fn update_gateway_credential(
        &self,
        gateway_id: &str,
        token_hash: &str,
        expires_at: Option<String>,
    ) -> Result<bool, StoreError> {
        self.update(|snapshot| {
            let Some(gateway) = snapshot.gateways.get_mut(gateway_id) else {
                return false;
            };
            gateway.credential_token_hash = token_hash.to_string();
            gateway.credential_status = StoredGatewayCredentialStatus::Active;
            gateway.credential_expires_at = expires_at;
            // 换证 = 这台网关**又活了一次**（重装后再注册，或在跑的周期性轮换）：归档自动解除，
            // 免得「回来了」的网关继续被默认视图藏着。
            gateway.archived_at = None;
            true
        })
    }

    /// 标记 / 清除归档（同步，供测试与 trait 委托）。命中返回 `true`；未接入的网关 `false`。
    pub fn set_gateway_archived(
        &self,
        gateway_id: &str,
        archived_at: Option<DateTime>,
    ) -> Result<bool, StoreError> {
        self.update(|snapshot| {
            let Some(gateway) = snapshot.gateways.get_mut(gateway_id) else {
                return false;
            };
            gateway.archived_at = archived_at;
            true
        })
    }

    /// 落库 Agent 状态（同步，供测试与 trait 委托）：按 agent_id upsert，归属以 gateway_id 参数为准。
    pub fn upsert_agent_status(
        &self,
        gateway_id: &str,
        agents: &[StoredAgent],
    ) -> Result<(), StoreError> {
        self.update(|snapshot| {
            for mut agent in agents.iter().cloned() {
                agent.gateway_id = gateway_id.to_string();
                snapshot.agents.insert(agent.agent_id.clone(), agent);
            }
        })
    }

    /// 生命周期：Provisioned → Initializing（幂等，Running 后不降级），并记录转变事件。
    pub fn mark_gateway_initializing(&self, gateway_id: &str) -> Result<(), StoreError> {
        let changed: bool = self.update(|snapshot| {
            if let Some(stored) = snapshot.gateways.get_mut(gateway_id)
                && stored.lifecycle_state == Some(GatewayInstanceLifecycleState::Provisioned)
            {
                stored.lifecycle_state = Some(GatewayInstanceLifecycleState::Initializing);
                return true;
            }
            false
        })?;
        if changed {
            FileStore::record_lifecycle_event(
                self,
                gateway_id,
                Some(GatewayInstanceLifecycleState::Provisioned),
                GatewayInstanceLifecycleState::Initializing,
            )?;
        }
        Ok(())
    }

    /// 记录一次生命周期转变事件（有界保留最近 ~100 条）。
    pub fn record_lifecycle_event(
        &self,
        gateway_id: &str,
        from: Option<GatewayInstanceLifecycleState>,
        to: GatewayInstanceLifecycleState,
    ) -> Result<(), StoreError> {
        self.update(|snapshot| {
            let events = snapshot
                .lifecycle_events
                .entry(gateway_id.to_string())
                .or_default();
            events.push(LifecycleEvent {
                gateway_id: gateway_id.to_string(),
                from_state: from,
                to_state: to,
                at: DateTime::now(),
            });
            const MAX_EVENTS: usize = 100;
            if events.len() > MAX_EVENTS {
                let excess = events.len() - MAX_EVENTS;
                events.drain(..excess);
            }
        })
    }

    pub fn list_lifecycle_events(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<LifecycleEvent>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot
            .lifecycle_events
            .get(gateway_id)
            .cloned()
            .unwrap_or_default())
    }

    /// 记录一次版本发布（同步，供测试与 trait 委托）。
    pub fn publish_release(
        &self,
        component: &str,
        version: &str,
        artifact_url: &str,
        package_sha256: Option<&str>,
        platform: Option<&str>,
    ) -> Result<ReleaseRecord, StoreError> {
        self.publish_release_with_compat(
            component,
            version,
            artifact_url,
            package_sha256,
            platform,
            None,
        )
    }

    /// 同 [`Self::publish_release`]，但带上包内 `compat.json`。
    pub fn publish_release_with_compat(
        &self,
        component: &str,
        version: &str,
        artifact_url: &str,
        package_sha256: Option<&str>,
        platform: Option<&str>,
        compat: Option<wist_release::compat::CompatManifest>,
    ) -> Result<ReleaseRecord, StoreError> {
        let record = ReleaseRecord {
            version: version.to_string(),
            artifact_url: artifact_url.to_string(),
            package_sha256: package_sha256.map(str::to_string),
            platform: platform.map(str::to_string),
            status: "published".to_string(),
            published_at: DateTime::now(),
            compat,
        };
        self.update(|snapshot| {
            snapshot
                .releases
                .entry(component.to_string())
                .or_default()
                .push(record.clone());
        })?;
        Ok(record)
    }

    pub fn list_releases(&self, component: &str) -> Result<Vec<ReleaseRecord>, StoreError> {
        let snapshot = self.load()?;
        let mut records = snapshot
            .releases
            .get(component)
            .cloned()
            .unwrap_or_default();
        records.sort_by(|left, right| {
            right
                .published_at
                .to_chrono()
                .cmp(&left.published_at.to_chrono())
        });
        Ok(records)
    }

    /// 更新某组件某版本的托管状态（同步，供测试与 trait 委托）：该版本全部制品行一起改。
    /// 返回受影响行数。
    pub fn set_release_status(
        &self,
        component: &str,
        version: &str,
        status: &str,
    ) -> Result<u64, StoreError> {
        self.update(|snapshot| {
            let Some(records) = snapshot.releases.get_mut(component) else {
                return 0;
            };
            let mut updated = 0u64;
            for record in records
                .iter_mut()
                .filter(|record| record.version == version)
            {
                record.status = status.to_string();
                updated += 1;
            }
            updated
        })
    }

    /// 补写某**制品行**的平台（同步，供测试与 trait 委托）：按内容 sha 精确定位。无该行 → `None`。
    pub fn set_release_platform(
        &self,
        component: &str,
        version: &str,
        package_sha256: &str,
        platform: Option<&str>,
    ) -> Result<Option<ReleaseRecord>, StoreError> {
        self.update(|snapshot| {
            let records = snapshot.releases.get_mut(component)?;
            let record = records.iter_mut().find(|record| {
                record.version == version
                    && record.package_sha256.as_deref() == Some(package_sha256)
            })?;
            record.platform = platform.map(str::to_string);
            Some(record.clone())
        })
    }

    /// 创建升级计划（同步，供测试与 trait 委托）：status=draft，插入最前（新→旧）。
    pub fn create_upgrade_plan(
        &self,
        plan: &UpgradePlanRecord,
    ) -> Result<UpgradePlanRecord, StoreError> {
        self.update(|snapshot| {
            snapshot.upgrade_plans.insert(0, plan.clone());
        })?;
        Ok(plan.clone())
    }

    /// 列表（新→旧）；顺手把模型升级前的旧记录折算成新形状（迁移，幂等）。
    pub fn list_upgrade_plans(&self) -> Result<Vec<UpgradePlanRecord>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot
            .upgrade_plans
            .into_iter()
            .map(|mut plan| {
                normalize_upgrade_plan(&mut plan);
                plan
            })
            .collect())
    }

    pub fn get_upgrade_plan(&self, plan_id: &str) -> Result<Option<UpgradePlanRecord>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot
            .upgrade_plans
            .into_iter()
            .find(|plan| plan.plan_id == plan_id)
            .map(|mut plan| {
                normalize_upgrade_plan(&mut plan);
                plan
            }))
    }

    pub fn save_upgrade_plan(&self, plan: &UpgradePlanRecord) -> Result<(), StoreError> {
        self.update(|snapshot| {
            let Some(slot) = snapshot
                .upgrade_plans
                .iter_mut()
                .find(|existing| existing.plan_id == plan.plan_id)
            else {
                return Err(StoreReason::Conflict
                    .to_err()
                    .with_detail(plan.plan_id.clone()));
            };
            *slot = plan.clone();
            Ok(())
        })??;
        Ok(())
    }

    /// 删除一份升级计划（同步，供测试与 trait 委托）：返回是否命中。
    pub fn delete_upgrade_plan(&self, plan_id: &str) -> Result<bool, StoreError> {
        self.update(|snapshot| {
            let before = snapshot.upgrade_plans.len();
            snapshot
                .upgrade_plans
                .retain(|plan| plan.plan_id != plan_id);
            snapshot.upgrade_plans.len() != before
        })
    }

    /// 新建一条后台任务（同步，供测试与 trait 委托）：插最前（新→旧）。
    pub fn create_job(&self, job: &JobRecord) -> Result<(), StoreError> {
        self.update(|snapshot| {
            snapshot.jobs.insert(0, job.clone());
        })
    }

    pub fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>, StoreError> {
        Ok(self
            .load()?
            .jobs
            .into_iter()
            .find(|job| job.job_id == job_id))
    }

    /// 某队列最近的 `limit` 条任务（新→旧）。
    pub fn list_jobs(&self, queue: &str, limit: usize) -> Result<Vec<JobRecord>, StoreError> {
        Ok(self
            .load()?
            .jobs
            .into_iter()
            .filter(|job| job.queue == queue)
            .take(limit)
            .collect())
    }

    /// 按可选条件列出任务（新→旧）。
    pub fn list_jobs_filtered(
        &self,
        queue: Option<&str>,
        kind: Option<&str>,
        state: Option<&str>,
        subject: Option<&str>,
        limit: usize,
    ) -> Result<Vec<JobRecord>, StoreError> {
        Ok(self
            .load()?
            .jobs
            .into_iter()
            .filter(|job| queue.is_none_or(|wanted| job.queue == wanted))
            .filter(|job| kind.is_none_or(|wanted| job.kind == wanted))
            .filter(|job| state.is_none_or(|wanted| job.state == wanted))
            .filter(|job| subject.is_none_or(|wanted| job.subject.as_deref() == Some(wanted)))
            .take(limit)
            .collect())
    }

    /// 原子认领某队列最早的一条 `queued` 任务（整个 `update` 在同一把锁里）。
    ///
    /// 顺序：`priority` 大者优先，同优先级按 `created_at` 从早到晚。
    pub fn claim_next_job(&self, queue: &str) -> Result<Option<JobRecord>, StoreError> {
        self.update(|snapshot| {
            let index = snapshot
                .jobs
                .iter()
                .enumerate()
                .filter(|(_, job)| job.queue == queue && job.state == super::jobs::JOB_QUEUED)
                .min_by(|(_, left), (_, right)| {
                    right.priority.cmp(&left.priority).then_with(|| {
                        left.created_at
                            .to_chrono()
                            .cmp(&right.created_at.to_chrono())
                    })
                })
                .map(|(index, _)| index)?;
            let job = &mut snapshot.jobs[index];
            job.state = super::jobs::JOB_RUNNING.to_string();
            job.started_at = Some(DateTime::now());
            Some(job.clone())
        })
    }

    pub fn save_job(&self, job: &JobRecord) -> Result<(), StoreError> {
        self.update(|snapshot| {
            let Some(slot) = snapshot
                .jobs
                .iter_mut()
                .find(|existing| existing.job_id == job.job_id)
            else {
                return Err(StoreReason::Conflict
                    .to_err()
                    .with_detail(job.job_id.clone()));
            };
            *slot = job.clone();
            Ok(())
        })??;
        Ok(())
    }

    /// 只更新任务的进度（找不到任务不报错：进度是 best-effort）。
    pub fn update_job_progress(
        &self,
        job_id: &str,
        progress: &JobProgress,
    ) -> Result<(), StoreError> {
        self.update(|snapshot| {
            if let Some(job) = snapshot.jobs.iter_mut().find(|job| job.job_id == job_id) {
                job.progress = progress.clone();
            }
        })
    }

    /// 把某队列残留的 `running` 任务排回 `queued`（返回重排条数）。
    pub fn requeue_running_jobs(&self, queue: &str) -> Result<u64, StoreError> {
        self.update(|snapshot| {
            let mut count = 0_u64;
            for job in snapshot.jobs.iter_mut() {
                if job.queue == queue && job.state == super::jobs::JOB_RUNNING {
                    job.state = super::jobs::JOB_QUEUED.to_string();
                    job.started_at = None;
                    // 重启后重新开始：旧的进度不能留在「排队中」的任务上。
                    job.progress = JobProgress {
                        message: Some("重新排队中".to_string()),
                        ..JobProgress::default()
                    };
                    count += 1;
                }
            }
            count
        })
    }

    /// 取消排队中的任务（同一把锁里判定，和认领互斥）。
    pub fn cancel_queued_job(&self, job_id: &str) -> Result<CancelOutcome, StoreError> {
        self.update(|snapshot| {
            let Some(job) = snapshot.jobs.iter_mut().find(|job| job.job_id == job_id) else {
                return CancelOutcome::NotFound;
            };
            if job.state != super::jobs::JOB_QUEUED {
                return CancelOutcome::NotCancelable(job.clone());
            }
            job.state = super::jobs::JOB_CANCELED.to_string();
            job.finished_at = Some(DateTime::now());
            job.progress.message = Some("已取消".to_string());
            CancelOutcome::Canceled(job.clone())
        })
    }

    /// 删除某队列在 `before` 之前已终结的任务（返回删除条数）。
    pub fn delete_terminal_jobs_before(
        &self,
        queue: &str,
        before: &DateTime,
    ) -> Result<u64, StoreError> {
        self.update(|snapshot| {
            let total = snapshot.jobs.len();
            snapshot.jobs.retain(|job| {
                let expired = job.queue == queue
                    && job.is_terminal()
                    && job
                        .finished_at
                        .as_ref()
                        .is_some_and(|finished| finished.to_chrono() < before.to_chrono());
                !expired
            });
            (total - snapshot.jobs.len()) as u64
        })
    }

    /// 绑定网关到客户（同步，供测试与 trait 委托）：同网关重复绑定同一客户不递增 revision；换绑递增。
    ///
    /// **归属变化时在同一把锁里**追加一条审计（`requested_by` 一并落库）：读旧值、改绑定、写审计
    /// 必须在同一个临界区，否则并发两次换绑会写出错的 `previous_customer_id`。
    /// 同客户重绑不记事件（不改变归属），只重置下发状态 —— 它意味着「重新下发一次」。
    pub fn bind_gateway_customer(
        &self,
        gateway_id: &str,
        customer_id: &str,
        requested_by: &str,
    ) -> Result<GatewayCustomerBindingRecord, StoreError> {
        let binding =
            self.update::<Result<GatewayCustomerBindingRecord, StoreError>>(|snapshot| {
                let now = DateTime::now();
                let (binding, previous) = match snapshot
                    .customer_bindings
                    .iter_mut()
                    .find(|binding| binding.gateway_id == gateway_id)
                {
                    Some(existing) => {
                        let previous = existing.customer_id.clone();
                        if previous != customer_id {
                            existing.customer_id = customer_id.to_string();
                            existing.revision = existing.revision.max(1) + 1;
                            existing.applied_revision = None;
                            existing.applied_at = None;
                            existing.reported_tenant_id = None;
                        }
                        // 无论首绑/重绑/换绑，下发侧都回到「待生效」，等网关下一次心跳确认。
                        existing.status = "bound".to_string();
                        existing.last_error = None;
                        existing.bound_at = now.clone();
                        (existing.clone(), Some(previous))
                    }
                    None => {
                        let binding = GatewayCustomerBindingRecord {
                            gateway_id: gateway_id.to_string(),
                            customer_id: customer_id.to_string(),
                            status: "bound".to_string(),
                            bound_at: now.clone(),
                            revision: 1,
                            applied_revision: None,
                            applied_at: None,
                            reported_tenant_id: None,
                            last_error: None,
                        };
                        snapshot.customer_bindings.push(binding.clone());
                        (binding, None)
                    }
                };
                let changed = previous.as_deref() != Some(customer_id);
                if changed {
                    push_binding_audit(
                        snapshot,
                        GatewayBindingAuditEvent {
                            gateway_id: gateway_id.to_string(),
                            customer_id: binding.customer_id.clone(),
                            previous_customer_id: previous,
                            revision: binding.revision,
                            requested_by: bounded(requested_by, 128),
                            at: now,
                        },
                    );
                }
                Ok(binding)
            })??;
        Ok(binding)
    }

    pub fn list_customer_bindings(&self) -> Result<Vec<GatewayCustomerBindingRecord>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot.customer_bindings)
    }

    pub fn get_customer_binding(
        &self,
        gateway_id: &str,
    ) -> Result<Option<GatewayCustomerBindingRecord>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot
            .customer_bindings
            .into_iter()
            .find(|binding| binding.gateway_id == gateway_id))
    }

    /// 记录网关上报的 tenant_id / revision（状态机与 PgStore **逐条对齐**）：
    ///
    /// | 输入 | status | applied_* | last_error |
    /// |---|---|---|---|
    /// | tenant 不一致 | `drift` | 不动 | `reported tenant_id mismatch` |
    /// | revision 落后 | `bound` | 不动 | `gateway reported older revision` |
    /// | revision 超前 | `bound` | 不动 | `gateway reported newer revision` |
    /// | revision 相等 | `applied` | 记该 revision（仅变化时刷新 `applied_at`） | 清空 |
    ///
    /// 无绑定时**不写盘**：FileStore 的 `update` 会重写整份 `store.json`，心跳 30s 一次，
    /// 没绑定的网关不应产生写放大。
    pub fn record_customer_binding_report(
        &self,
        gateway_id: &str,
        reported_tenant_id: &str,
        reported_revision: i64,
    ) -> Result<Option<GatewayCustomerBindingRecord>, StoreError> {
        if self.get_customer_binding(gateway_id)?.is_none() {
            return Ok(None);
        }
        let binding =
            self.update::<Result<Option<GatewayCustomerBindingRecord>, StoreError>>(|snapshot| {
                let Some(existing) = snapshot
                    .customer_bindings
                    .iter_mut()
                    .find(|binding| binding.gateway_id == gateway_id)
                else {
                    return Ok(None);
                };
                existing.reported_tenant_id = Some(reported_tenant_id.to_string());
                if existing.customer_id != reported_tenant_id {
                    existing.status = "drift".to_string();
                    existing.last_error = Some("reported tenant_id mismatch".to_string());
                } else if reported_revision < existing.revision {
                    existing.status = "bound".to_string();
                    existing.last_error = Some("gateway reported older revision".to_string());
                } else if reported_revision > existing.revision {
                    // 网关比中心新（中心库回滚 / 重建）：不冒充已生效，也不回写超前的版本。
                    existing.status = "bound".to_string();
                    existing.last_error = Some("gateway reported newer revision".to_string());
                } else {
                    // `applied_at` 是「最近一次**变为**已生效」，不是每次心跳都刷新。
                    if existing.applied_revision != Some(reported_revision) {
                        existing.applied_at = Some(DateTime::now());
                    }
                    existing.applied_revision = Some(reported_revision);
                    existing.status = "applied".to_string();
                    existing.last_error = None;
                }
                Ok(Some(existing.clone()))
            })??;
        Ok(binding)
    }

    /// 命令回执失败（`bind-tenant`）→ 绑定标 `failed` + 原因。
    ///
    /// 只对**当前绑定版本**生效：旧命令的失败不能盖掉换绑后的新状态。
    pub fn mark_binding_failed(
        &self,
        gateway_id: &str,
        revision: i64,
        error: &str,
    ) -> Result<bool, StoreError> {
        let changed = self.update::<Result<bool, StoreError>>(|snapshot| {
            let Some(existing) = snapshot
                .customer_bindings
                .iter_mut()
                .find(|binding| binding.gateway_id == gateway_id)
            else {
                return Ok(false);
            };
            if existing.revision != revision {
                return Ok(false);
            }
            existing.status = "failed".to_string();
            existing.last_error = Some(bounded(error, 300));
            Ok(true)
        })??;
        Ok(changed)
    }

    pub fn list_binding_audit(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayBindingAuditEvent>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot
            .binding_audit
            .get(gateway_id)
            .cloned()
            .unwrap_or_default())
    }

    pub fn list_agents_by_gateway(&self, gateway_id: &str) -> Result<Vec<StoredAgent>, StoreError> {
        let snapshot = self.load()?;
        let mut agents: Vec<StoredAgent> = snapshot
            .agents
            .into_values()
            .filter(|agent| agent.gateway_id == gateway_id)
            .collect();
        agents.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
        Ok(agents)
    }

    fn lock(&self) -> Result<StoreLockGuard<'_>, StoreError> {
        let process_guard = self.lock.lock().map_err(|_| {
            StoreReason::Io
                .to_err()
                .with_detail("center store lock poisoned")
        })?;
        let file_guard = FileLockGuard::lock(&lock_file_path(&self.path))?;
        Ok(StoreLockGuard {
            _process_guard: process_guard,
            _file_guard: file_guard,
        })
    }

    fn load_snapshot(&self) -> Result<CenterStoreSnapshot, StoreError> {
        if !self.path.exists() {
            return Ok(CenterStoreSnapshot::default());
        }
        let content = fs::read_to_string(&self.path).source_err(StoreReason::Io, "read store")?;
        if content.trim().is_empty() {
            return Ok(CenterStoreSnapshot::default());
        }
        serde_json::from_str(&content).source_err(StoreReason::Json, "parse store")
    }

    fn save_snapshot(&self, snapshot: &CenterStoreSnapshot) -> Result<(), StoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).source_err(StoreReason::Io, "create store dir")?;
        }
        let content = serde_json::to_string_pretty(snapshot)
            .source_err(StoreReason::Json, "serialize store")?;
        let temp_path = temp_store_path(&self.path);
        let write_result = (|| -> Result<(), StoreError> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp_path)
                .source_err(StoreReason::Io, "open temp store file")?;
            file.write_all(content.as_bytes())
                .source_err(StoreReason::Io, "write store")?;
            file.write_all(b"\n")
                .source_err(StoreReason::Io, "write store")?;
            file.sync_all().source_err(StoreReason::Io, "sync store")?;
            fs::rename(&temp_path, &self.path).source_err(StoreReason::Io, "rename store")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                    .source_err(StoreReason::Io, "set store permissions")?;
            }
            if let Some(parent) = self.path.parent() {
                sync_directory(parent).source_err(StoreReason::Io, "sync store dir")?;
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Store for FileStore {
    async fn seed(&self, seeds: &[GatewayCredentialSeed]) -> Result<bool, StoreError> {
        // 显式调用同步固有方法，避免与 trait 方法同名递归。
        FileStore::seed(self, seeds)
    }

    async fn list_gateways(&self) -> Result<Vec<StoredGateway>, StoreError> {
        let snapshot = self.load()?;
        let mut gateways: Vec<StoredGateway> = snapshot.gateways.into_values().collect();
        gateways.sort_by(|left, right| left.gateway_id.cmp(&right.gateway_id));
        Ok(gateways)
    }

    async fn get_gateway(&self, gateway_id: &str) -> Result<Option<StoredGateway>, StoreError> {
        let snapshot = self.load()?;
        Ok(snapshot.gateways.get(gateway_id).cloned())
    }

    async fn upsert_gateway_status(&self, update: &GatewayStatusUpdate) -> Result<(), StoreError> {
        let (changed, from): (bool, Option<GatewayInstanceLifecycleState>) =
            self.update(|snapshot| {
                if let Some(stored) = snapshot.gateways.get_mut(&update.gateway_id) {
                    stored.instance_id = update.instance_id.clone();
                    stored.version = Some(update.version.clone());
                    stored.gops_version = update.gops_version.clone();
                    stored.gx_version = update.gx_version.clone();
                    stored.gwlinkd_version = update.gwlinkd_version.clone();
                    stored.status = Some(update.status.clone());
                    stored.health = Some(update.health.clone());
                    stored.memory_bytes = update.memory_bytes;
                    stored.cpu_percent = update.cpu_percent;
                    // 只在新值非空时覆盖：老网关的状态上报不带域名，不该把注册时落下的抹掉。
                    if let Some(url) = update.public_base_url.clone() {
                        stored.public_base_url = Some(url);
                    }
                    stored.uptime_seconds = update.uptime_seconds;
                    stored.agent_count = update.agent_count;
                    stored.online_agents = update.online_agents;
                    stored.offline_agents = update.offline_agents;
                    stored.last_seen_lag_seconds = update.last_seen_lag_seconds;
                    stored.store_bytes = update.store_bytes;
                    stored.ingest_accepted_total = update.ingest_accepted_total;
                    stored.ingest_rejected_total = update.ingest_rejected_total;
                    stored.last_ingest_at = update.last_ingest_at.clone();
                    stored.memory_total_bytes = update.memory_total_bytes;
                    stored.load_1m = update.load_1m;
                    stored.load_5m = update.load_5m;
                    stored.load_15m = update.load_15m;
                    stored.disk_usage_percent = update.disk_usage_percent;
                    stored.disk_total_bytes = update.disk_total_bytes;
                    stored.disk_available_bytes = update.disk_available_bytes;
                    stored.last_seen_at = Some(update.last_seen_at.clone());
                    // 「回来了」就解除归档：还在上报 online 说明这台网关又活着了，不该继续被默认
                    // 视图藏着。（归档只允许离线网关，所以这里清掉的基本都是真回归；死掉的网关
                    // 不会上报，也就不会误清。）
                    if update.status == "online" {
                        stored.archived_at = None;
                    }
                    // 首次上报 → Running（初始化完成，记录 initialized_at + 转变事件）。
                    if stored.lifecycle_state != Some(GatewayInstanceLifecycleState::Running) {
                        let prev = stored.lifecycle_state;
                        stored.lifecycle_state = Some(GatewayInstanceLifecycleState::Running);
                        stored.initialized_at = Some(DateTime::now());
                        return (true, prev);
                    }
                }
                (false, None)
            })?;
        if changed {
            FileStore::record_lifecycle_event(
                self,
                &update.gateway_id,
                from,
                GatewayInstanceLifecycleState::Running,
            )?;
        }
        Ok(())
    }

    async fn create_gateway(
        &self,
        gateway_id: &str,
        token: &str,
    ) -> Result<StoredGateway, StoreError> {
        // 显式调用同步固有方法，避兔与 trait 方法同名递归。
        FileStore::create_gateway(self, gateway_id, token)
    }

    async fn set_gateway_public_base_url(
        &self,
        gateway_id: &str,
        public_base_url: &str,
    ) -> Result<(), StoreError> {
        self.update(|snapshot| {
            if let Some(stored) = snapshot.gateways.get_mut(gateway_id) {
                stored.public_base_url = Some(public_base_url.to_string());
            }
        })?;
        Ok(())
    }

    async fn set_gateway_archived(
        &self,
        gateway_id: &str,
        archived_at: Option<DateTime>,
    ) -> Result<bool, StoreError> {
        FileStore::set_gateway_archived(self, gateway_id, archived_at)
    }

    async fn create_enrollment_token(
        &self,
        gateway_id: &str,
        issue: &EnrollmentTokenIssue,
    ) -> Result<StoredEnrollmentToken, StoreError> {
        FileStore::create_enrollment_token(self, gateway_id, issue)
    }

    async fn consume_enrollment_token(
        &self,
        token: &str,
    ) -> Result<StoredEnrollmentToken, StoreError> {
        FileStore::consume_enrollment_token(self, token)
    }

    async fn consume_link_token(
        &self,
        gateway_id: &str,
        link_token: &str,
    ) -> Result<bool, StoreError> {
        FileStore::consume_link_token(self, gateway_id, link_token)
    }

    async fn rotate_link_token(
        &self,
        gateway_id: &str,
        link_hash: &str,
        expires_at: Option<String>,
    ) -> Result<bool, StoreError> {
        FileStore::rotate_link_token(self, gateway_id, link_hash, expires_at)
    }

    async fn update_gateway_credential(
        &self,
        gateway_id: &str,
        token_hash: &str,
        expires_at: Option<String>,
    ) -> Result<bool, StoreError> {
        FileStore::update_gateway_credential(self, gateway_id, token_hash, expires_at)
    }

    async fn revoke_enrollment_token(
        &self,
        gateway_id: &str,
        token_id: &str,
    ) -> Result<StoredEnrollmentToken, StoreError> {
        FileStore::revoke_enrollment_token(self, gateway_id, token_id)
    }

    async fn get_enrollment_token_for_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Option<StoredEnrollmentToken>, StoreError> {
        FileStore::get_enrollment_token_for_gateway(self, gateway_id)
    }

    async fn upsert_agent_status(
        &self,
        gateway_id: &str,
        agents: &[StoredAgent],
    ) -> Result<(), StoreError> {
        FileStore::upsert_agent_status(self, gateway_id, agents)
    }

    async fn list_agents_by_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<StoredAgent>, StoreError> {
        FileStore::list_agents_by_gateway(self, gateway_id)
    }

    async fn mark_gateway_initializing(&self, gateway_id: &str) -> Result<(), StoreError> {
        FileStore::mark_gateway_initializing(self, gateway_id)
    }

    async fn record_lifecycle_event(
        &self,
        gateway_id: &str,
        from: Option<GatewayInstanceLifecycleState>,
        to: GatewayInstanceLifecycleState,
    ) -> Result<(), StoreError> {
        FileStore::record_lifecycle_event(self, gateway_id, from, to)
    }

    async fn list_lifecycle_events(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<LifecycleEvent>, StoreError> {
        FileStore::list_lifecycle_events(self, gateway_id)
    }

    async fn publish_release_with_compat(
        &self,
        component: &str,
        version: &str,
        artifact_url: &str,
        package_sha256: Option<&str>,
        platform: Option<&str>,
        compat: Option<wist_release::compat::CompatManifest>,
    ) -> Result<ReleaseRecord, StoreError> {
        FileStore::publish_release_with_compat(
            self,
            component,
            version,
            artifact_url,
            package_sha256,
            platform,
            compat,
        )
    }

    async fn list_releases(&self, component: &str) -> Result<Vec<ReleaseRecord>, StoreError> {
        FileStore::list_releases(self, component)
    }

    async fn set_release_status(
        &self,
        component: &str,
        version: &str,
        status: &str,
    ) -> Result<u64, StoreError> {
        FileStore::set_release_status(self, component, version, status)
    }

    async fn set_release_platform(
        &self,
        component: &str,
        version: &str,
        package_sha256: &str,
        platform: Option<&str>,
    ) -> Result<Option<ReleaseRecord>, StoreError> {
        FileStore::set_release_platform(self, component, version, package_sha256, platform)
    }

    async fn create_upgrade_plan(
        &self,
        plan: &UpgradePlanRecord,
    ) -> Result<UpgradePlanRecord, StoreError> {
        FileStore::create_upgrade_plan(self, plan)
    }

    async fn list_upgrade_plans(&self) -> Result<Vec<UpgradePlanRecord>, StoreError> {
        FileStore::list_upgrade_plans(self)
    }

    async fn get_upgrade_plan(
        &self,
        plan_id: &str,
    ) -> Result<Option<UpgradePlanRecord>, StoreError> {
        FileStore::get_upgrade_plan(self, plan_id)
    }

    async fn save_upgrade_plan(&self, plan: &UpgradePlanRecord) -> Result<(), StoreError> {
        FileStore::save_upgrade_plan(self, plan)
    }

    async fn delete_upgrade_plan(&self, plan_id: &str) -> Result<bool, StoreError> {
        FileStore::delete_upgrade_plan(self, plan_id)
    }

    async fn create_job(&self, job: &JobRecord) -> Result<(), StoreError> {
        FileStore::create_job(self, job)
    }

    async fn get_job(&self, job_id: &str) -> Result<Option<JobRecord>, StoreError> {
        FileStore::get_job(self, job_id)
    }

    async fn list_jobs(&self, queue: &str, limit: usize) -> Result<Vec<JobRecord>, StoreError> {
        FileStore::list_jobs(self, queue, limit)
    }

    async fn list_jobs_filtered(
        &self,
        queue: Option<&str>,
        kind: Option<&str>,
        state: Option<&str>,
        subject: Option<&str>,
        limit: usize,
    ) -> Result<Vec<JobRecord>, StoreError> {
        FileStore::list_jobs_filtered(self, queue, kind, state, subject, limit)
    }

    async fn claim_next_job(&self, queue: &str) -> Result<Option<JobRecord>, StoreError> {
        FileStore::claim_next_job(self, queue)
    }

    async fn save_job(&self, job: &JobRecord) -> Result<(), StoreError> {
        FileStore::save_job(self, job)
    }

    async fn update_job_progress(
        &self,
        job_id: &str,
        progress: &JobProgress,
    ) -> Result<(), StoreError> {
        FileStore::update_job_progress(self, job_id, progress)
    }

    async fn requeue_running_jobs(&self, queue: &str) -> Result<u64, StoreError> {
        FileStore::requeue_running_jobs(self, queue)
    }

    async fn cancel_queued_job(&self, job_id: &str) -> Result<CancelOutcome, StoreError> {
        FileStore::cancel_queued_job(self, job_id)
    }

    async fn delete_terminal_jobs_before(
        &self,
        queue: &str,
        before: &DateTime,
    ) -> Result<u64, StoreError> {
        FileStore::delete_terminal_jobs_before(self, queue, before)
    }

    async fn bind_gateway_customer(
        &self,
        gateway_id: &str,
        customer_id: &str,
        requested_by: &str,
    ) -> Result<GatewayCustomerBindingRecord, StoreError> {
        FileStore::bind_gateway_customer(self, gateway_id, customer_id, requested_by)
    }

    async fn list_customer_bindings(
        &self,
    ) -> Result<Vec<GatewayCustomerBindingRecord>, StoreError> {
        FileStore::list_customer_bindings(self)
    }

    async fn get_customer_binding(
        &self,
        gateway_id: &str,
    ) -> Result<Option<GatewayCustomerBindingRecord>, StoreError> {
        FileStore::get_customer_binding(self, gateway_id)
    }

    async fn record_customer_binding_report(
        &self,
        gateway_id: &str,
        reported_tenant_id: &str,
        reported_revision: i64,
    ) -> Result<Option<GatewayCustomerBindingRecord>, StoreError> {
        FileStore::record_customer_binding_report(
            self,
            gateway_id,
            reported_tenant_id,
            reported_revision,
        )
    }

    async fn mark_binding_failed(
        &self,
        gateway_id: &str,
        revision: i64,
        error: &str,
    ) -> Result<bool, StoreError> {
        FileStore::mark_binding_failed(self, gateway_id, revision, error)
    }

    async fn list_binding_audit(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayBindingAuditEvent>, StoreError> {
        FileStore::list_binding_audit(self, gateway_id)
    }
}

struct StoreLockGuard<'a> {
    _process_guard: MutexGuard<'a, ()>,
    _file_guard: FileLockGuard,
}

static PROCESS_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

fn shared_process_lock(path: &Path) -> Arc<Mutex<()>> {
    let key = normalized_store_path(path);
    let locks = PROCESS_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks
        .lock()
        .expect("center store process lock map poisoned");
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn normalized_store_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn lock_file_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("center-store.json");
    path.with_file_name(format!(".{file_name}.lock"))
}

fn temp_store_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("center-store.json");
    let nanos = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| chrono::Utc::now().timestamp_micros() * 1_000);
    path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nanos))
}

#[cfg(unix)]
struct FileLockGuard {
    file: fs::File,
}

#[cfg(unix)]
impl FileLockGuard {
    fn lock(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).source_err(StoreReason::Io, "create store dir")?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .source_err(StoreReason::Io, "open lock file")?;
        lock_file_exclusive(&file).source_err(StoreReason::Io, "lock store file")?;
        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[cfg(not(unix))]
struct FileLockGuard;

#[cfg(not(unix))]
impl FileLockGuard {
    fn lock(_path: &Path) -> Result<Self, StoreError> {
        Ok(Self)
    }
}

#[cfg(unix)]
fn lock_file_exclusive(file: &fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    const LOCK_EX: std::os::raw::c_int = 2;
    if unsafe { flock(file.as_raw_fd(), LOCK_EX) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_file(file: &fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    const LOCK_UN: std::os::raw::c_int = 8;
    if unsafe { flock(file.as_raw_fd(), LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        OpenOptions::new().read(true).open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// 一次状态上报的最小更新（工具 / gwlinkd 版本、富化字段均可按需覆盖）。
    fn status_update(gateway_id: &str, status: &str) -> GatewayStatusUpdate {
        GatewayStatusUpdate {
            gateway_id: gateway_id.to_string(),
            instance_id: "i".to_string(),
            version: "0.1.26".to_string(),
            gops_version: None,
            gx_version: None,
            gwlinkd_version: None,
            status: status.to_string(),
            health: "ok".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            public_base_url: None,
            last_seen_at: DateTime::now(),
            uptime_seconds: None,
            agent_count: None,
            online_agents: None,
            offline_agents: None,
            last_seen_lag_seconds: None,
            store_bytes: None,
            ingest_accepted_total: None,
            ingest_rejected_total: None,
            last_ingest_at: None,
            memory_total_bytes: None,
            load_1m: None,
            load_5m: None,
            load_15m: None,
            disk_usage_percent: None,
            disk_total_bytes: None,
            disk_available_bytes: None,
        }
    }

    #[test]
    fn seed_provisions_missing_gateways_only() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        let seeds = vec![
            GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "tok-a".to_string(),
                expires_at: None,
            },
            GatewayCredentialSeed {
                gateway_id: "gw-002".to_string(),
                token: "tok-b".to_string(),
                expires_at: None,
            },
        ];
        assert!(store.seed(&seeds).expect("seed"));
        assert!(!store.seed(&seeds).expect("seed again"));

        let snapshot = store.load().expect("load");
        assert_eq!(snapshot.gateways.len(), 2);
        let first = &snapshot.gateways["gw-001"];
        assert_eq!(first.credential_token_hash, sha256_hex("tok-a"));
        assert_eq!(
            first.credential_status,
            StoredGatewayCredentialStatus::Active
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn update_upserts_latest_status() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        let seeds = vec![GatewayCredentialSeed {
            gateway_id: "gw-001".to_string(),
            token: "tok-a".to_string(),
            expires_at: None,
        }];
        store.seed(&seeds).expect("seed");

        store
            .update(|snapshot| {
                if let Some(stored) = snapshot.gateways.get_mut("gw-001") {
                    stored.version = Some("v2.4.1".to_string());
                    stored.status = Some("online".to_string());
                    stored.health = Some("healthy".to_string());
                    stored.last_seen_at = Some(DateTime::now());
                }
            })
            .expect("update");

        let snapshot = store.load().expect("load");
        let stored = &snapshot.gateways["gw-001"];
        assert_eq!(stored.version.as_deref(), Some("v2.4.1"));
        assert_eq!(stored.status.as_deref(), Some("online"));
        assert!(stored.last_seen_at.is_some());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rotate_link_token_replaces_the_hash() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        store.create_gateway("gw-rot", "link-old").expect("create");
        assert!(
            store
                .rotate_link_token("gw-rot", &sha256_hex("link-new"), None)
                .expect("rotate")
        );
        // 旧券作废、新券可用（一次性接入券 的“再取即轮换”）。
        assert!(!store.consume_link_token("gw-rot", "link-old").expect("old"));
        assert!(store.consume_link_token("gw-rot", "link-new").expect("new"));
        // 未知网关 → false。
        assert!(
            !store
                .rotate_link_token("gw-absent", "x", None)
                .expect("absent")
        );
    }

    #[test]
    fn expired_link_token_is_rejected() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        store.create_gateway("gw-exp", "").expect("create");
        let past = (chrono::Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
        assert!(
            store
                .rotate_link_token("gw-exp", &sha256_hex("link-exp"), Some(past))
                .expect("rotate")
        );
        // 短 TTL：过期券不可消费（需重新生成/轮换）。
        assert!(
            !store
                .consume_link_token("gw-exp", "link-exp")
                .expect("expired")
        );
    }

    #[test]
    fn create_gateway_provisions_and_conflicts_on_duplicate() {
        let path = test_store_path();
        let store = FileStore::new(&path);

        let stored = store.create_gateway("gw-100", "tok-x").expect("create");
        assert_eq!(stored.gateway_id, "gw-100");
        // create 的 token 是接入券（LINK_TOKEN）：存 link hash，
        // 运行期凭据（credential_token_hash）留空，注册后签发 RUNTIME_TOKEN 时再落库。
        assert_eq!(stored.link_token_hash, sha256_hex("tok-x"));
        assert_eq!(stored.credential_token_hash, "");
        assert_eq!(
            stored.credential_status,
            StoredGatewayCredentialStatus::Active
        );
        assert_eq!(stored.instance_id, "");

        // 重复创建同一 gateway_id → Conflict。
        let err = store
            .create_gateway("gw-100", "tok-y")
            .expect_err("conflict");
        assert_eq!(err.reason(), &StoreReason::Conflict);
        assert_eq!(err.detail().as_deref(), Some("gw-100"));

        // 空 token → link hash 也空（无接入凭据网关无法置备）。
        let stored = store
            .create_gateway("gw-nocred", "")
            .expect("create no credential");
        assert_eq!(stored.link_token_hash, "");
        assert_eq!(stored.credential_token_hash, "");

        let _ = fs::remove_file(path);
    }

    /// 归档是**标记**：落 `archived_at`、可就地清掉；网关**回来了**（换证注册，或重新上报 online）
    /// 时自动解除 —— 不用人工记得取消归档；只是掉线的那种上报（offline）不会自己冒回来。
    #[tokio::test]
    async fn archive_is_a_marker_and_clears_when_the_gateway_comes_back() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        store
            .seed(&[GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "tok-a".to_string(),
                expires_at: None,
            }])
            .expect("seed");

        // 归档：落时刻，历史别的不动。
        assert!(
            store
                .set_gateway_archived("gw-001", Some(DateTime::now()))
                .expect("archive"),
            "命中已接入的网关"
        );
        assert!(
            store
                .get_gateway("gw-001")
                .await
                .expect("get")
                .expect("exists")
                .archived_at
                .is_some()
        );
        // 未接入的网关：没命中（调用方折 404）。
        assert!(
            !store
                .set_gateway_archived("gw-404", Some(DateTime::now()))
                .expect("archive unknown")
        );

        // 只在掉线时上报 offline：**不**解除（否则一台半死的网关会把归档刷掉）。
        store
            .upsert_gateway_status(&status_update("gw-001", "offline"))
            .await
            .expect("status offline");
        assert!(
            store
                .get_gateway("gw-001")
                .await
                .expect("get")
                .expect("exists")
                .archived_at
                .is_some(),
            "offline 上报不该解除归档"
        );

        // 重新上报 online = 它又活着了 → 自动解除。
        store
            .upsert_gateway_status(&status_update("gw-001", "online"))
            .await
            .expect("status online");
        assert!(
            store
                .get_gateway("gw-001")
                .await
                .expect("get")
                .expect("exists")
                .archived_at
                .is_none(),
            "重新 online 应自动解除归档"
        );

        // 换证（重装后再注册 / 周期性轮换）同样解除。
        store
            .set_gateway_archived("gw-001", Some(DateTime::now()))
            .expect("archive again");
        store
            .update_gateway_credential("gw-001", "hash-new", None)
            .expect("credential");
        assert!(
            store
                .get_gateway("gw-001")
                .await
                .expect("get")
                .expect("exists")
                .archived_at
                .is_none(),
            "换证应自动解除归档"
        );

        // 取消归档：清成 None。
        store
            .set_gateway_archived("gw-001", Some(DateTime::now()))
            .expect("archive once more");
        store
            .set_gateway_archived("gw-001", None)
            .expect("unarchive");
        assert!(
            store
                .get_gateway("gw-001")
                .await
                .expect("get")
                .expect("exists")
                .archived_at
                .is_none()
        );
    }

    /// gwlinkd 的**自身**版本与网关（容器）版本分开落库：中心页面两个都要能显示，
    /// 老 gwlinkd 不带该键时保持 `None`（页面显示「—」，不冒充）。
    #[tokio::test]
    async fn gateway_status_keeps_the_gwlinkd_version_apart_from_the_gateway_version() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        store
            .seed(&[GatewayCredentialSeed {
                gateway_id: "gw-001".to_string(),
                token: "tok-a".to_string(),
                expires_at: None,
            }])
            .expect("seed");

        let mut update = status_update("gw-001", "online");
        update.gops_version = Some("2.4.0".to_string());
        update.gx_version = Some("0.17.0".to_string());
        update.gwlinkd_version = Some("0.16.1".to_string());
        store.upsert_gateway_status(&update).await.expect("status");

        let stored = store
            .get_gateway("gw-001")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(
            stored.version.as_deref(),
            Some("0.1.26"),
            "网关容器版本原样保留"
        );
        assert_eq!(stored.gwlinkd_version.as_deref(), Some("0.16.1"));

        // 后来的上报没带这个键（老 gwlinkd）→ 清空，不沿用旧值（版本是事实，不是累积）。
        let mut legacy = status_update("gw-001", "online");
        legacy.gwlinkd_version = None;
        store
            .upsert_gateway_status(&legacy)
            .await
            .expect("status legacy");
        assert_eq!(
            store
                .get_gateway("gw-001")
                .await
                .expect("get")
                .expect("exists")
                .gwlinkd_version,
            None
        );
    }

    /// 网关对外域名：注册时落下；状态上报带 `None`（老网关）时**保留**已落值，带值时覆盖。
    #[tokio::test]
    async fn gateway_public_base_url_set_then_preserved_and_overwritten() {
        fn update(gateway_id: &str, public_base_url: Option<&str>) -> GatewayStatusUpdate {
            GatewayStatusUpdate {
                gateway_id: gateway_id.to_string(),
                instance_id: "i".to_string(),
                version: "0.1.26".to_string(),
                gops_version: None,
                gx_version: None,
                gwlinkd_version: None,
                status: "online".to_string(),
                health: "ok".to_string(),
                memory_bytes: None,
                cpu_percent: None,
                public_base_url: public_base_url.map(str::to_string),
                last_seen_at: DateTime::now(),
                uptime_seconds: None,
                agent_count: None,
                online_agents: None,
                offline_agents: None,
                last_seen_lag_seconds: None,
                store_bytes: None,
                ingest_accepted_total: None,
                ingest_rejected_total: None,
                last_ingest_at: None,
                memory_total_bytes: None,
                load_1m: None,
                load_5m: None,
                load_15m: None,
                disk_usage_percent: None,
                disk_total_bytes: None,
                disk_available_bytes: None,
            }
        }

        let path = test_store_path();
        let store = FileStore::new(&path);
        store.create_gateway("gw-url", "link-x").expect("create");

        // 注册（早于第一拍状态上报）即落下域名。
        store
            .set_gateway_public_base_url("gw-url", "https://gw.example.com")
            .await
            .expect("set");
        let stored = store
            .get_gateway("gw-url")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(
            stored.public_base_url.as_deref(),
            Some("https://gw.example.com")
        );

        // 老网关的状态上报不带域名（None）→ 保留已落值，不抹掉。
        store
            .upsert_gateway_status(&update("gw-url", None))
            .await
            .expect("upsert without url");
        let stored = store
            .get_gateway("gw-url")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(
            stored.public_base_url.as_deref(),
            Some("https://gw.example.com"),
            "None 不该抹掉注册时落的值"
        );

        // 带域名上报 → 覆盖为新值。
        store
            .upsert_gateway_status(&update("gw-url", Some("https://new.example.com")))
            .await
            .expect("upsert with url");
        let stored = store
            .get_gateway("gw-url")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(
            stored.public_base_url.as_deref(),
            Some("https://new.example.com")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn link_token_consume_and_rotate() {
        // 消费：匹配 link + Provisioned → true，hash 清空。
        let path = test_store_path();
        let store = FileStore::new(&path);
        store.create_gateway("gw-b", "link-x").expect("create");
        assert!(store.consume_link_token("gw-b", "link-x").expect("consume"));
        assert!(
            store.load().expect("load").gateways["gw-b"]
                .link_token_hash
                .is_empty()
        );
        // 已消费 → false（防重放）。
        assert!(
            !store
                .consume_link_token("gw-b", "link-x")
                .expect("re-consume")
        );
        // 错 token → false。
        let path2 = test_store_path();
        let store2 = FileStore::new(&path2);
        store2.create_gateway("gw-b", "link-x").expect("create");
        assert!(!store2.consume_link_token("gw-b", "wrong").expect("wrong"));
        // 已初始化 → false。
        let path3 = test_store_path();
        let store3 = FileStore::new(&path3);
        store3.create_gateway("gw-b", "link-x").expect("create");
        store3.mark_gateway_initializing("gw-b").expect("init");
        assert!(
            !store3
                .consume_link_token("gw-b", "link-x")
                .expect("initialized")
        );

        for path in [path, path2, path3] {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn update_gateway_credential_replaces_runtime_credential() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        store.create_gateway("gw-c", "link-x").expect("create");
        let expires = Some("2026-09-01T00:00:00Z".to_string());
        assert!(
            store
                .update_gateway_credential("gw-c", "sha256:runtime", expires.clone())
                .expect("update")
        );
        let snapshot = store.load().expect("load");
        let stored = &snapshot.gateways["gw-c"];
        assert_eq!(stored.credential_token_hash, "sha256:runtime");
        assert_eq!(
            stored.credential_status,
            StoredGatewayCredentialStatus::Active
        );
        assert_eq!(stored.credential_expires_at, expires);
        // 未知网关 → false。
        assert!(
            !store
                .update_gateway_credential("gw-nope", "h", None)
                .expect("unknown")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn enrollment_token_single_use_anti_replay_and_revoke() {
        let path = test_store_path();
        let store = FileStore::new(&path);

        // 签发：携带环境绑定 + 签发人 + 信任根。
        let issue = EnrollmentTokenIssue {
            token: "enroll-tok-1".to_string(),
            issued_by: "admin-test".to_string(),
            control_center_trust_bundle: Some(
                "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----".to_string(),
            ),
        };
        let token = store
            .create_enrollment_token("gw-001", &issue)
            .expect("create");
        assert_eq!(token.status, "Active");
        assert_eq!(token.max_uses, 1);
        assert_eq!(token.used_count, 0);
        assert_eq!(token.tenant_id, "tenant-default");
        assert_eq!(token.environment_id, "env-default");
        assert_eq!(token.issued_by, "admin-test");
        assert!(token.control_center_trust_bundle.is_some());
        assert!(token.expires_at.is_some());
        assert!(token.revoked_at.is_none());

        // 首次消费成功 → Exhausted（max_uses=1）。
        let consumed = store
            .consume_enrollment_token("enroll-tok-1")
            .expect("consume");
        assert_eq!(consumed.status, "Exhausted");
        assert_eq!(consumed.used_count, 1);

        // 防重放：第二次消费被拒（Exhausted 状态在状态检查处被拒收）。
        let err = store
            .consume_enrollment_token("enroll-tok-1")
            .expect_err("anti-replay");
        assert_eq!(err.reason(), &StoreReason::Enrollment);

        // 吊销：Revoked 后消费被拒；归属不符拒绝吊销。
        let token2 = store
            .create_enrollment_token(
                "gw-001",
                &EnrollmentTokenIssue {
                    token: "enroll-tok-2".to_string(),
                    issued_by: "admin-test".to_string(),
                    control_center_trust_bundle: None,
                },
            )
            .expect("create2");
        let revoked = store
            .revoke_enrollment_token("gw-001", &token2.token_id)
            .expect("revoke");
        assert_eq!(revoked.status, "Revoked");
        assert!(revoked.revoked_at.is_some());
        let err = store
            .consume_enrollment_token("enroll-tok-2")
            .expect_err("revoked reject");
        assert_eq!(err.reason(), &StoreReason::Enrollment);
        assert!(
            err.detail()
                .as_deref()
                .is_some_and(|reason| reason.starts_with("token status"))
        );
        let err = store
            .revoke_enrollment_token("gw-999", &token2.token_id)
            .expect_err("gateway mismatch");
        assert_eq!(err.reason(), &StoreReason::Enrollment);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_enrollment_token_for_gateway_returns_latest_for_gateway() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        let issue = |token: &str| EnrollmentTokenIssue {
            token: token.to_string(),
            issued_by: "test".to_string(),
            control_center_trust_bundle: None,
        };
        store
            .create_enrollment_token("gw-001", &issue("tok-1"))
            .expect("t1");
        store
            .create_enrollment_token("gw-001", &issue("tok-2"))
            .expect("t2");
        store
            .create_enrollment_token("gw-002", &issue("tok-3"))
            .expect("t3");

        // 同网关取最新签发；跨网关互不可见。
        let latest = store
            .get_enrollment_token_for_gateway("gw-001")
            .expect("lookup")
            .expect("some");
        assert_eq!(latest.token_id, "enroll-gw-001-2");
        assert!(
            store
                .get_enrollment_token_for_gateway("gw-999")
                .expect("lookup")
                .is_none()
        );

        let _ = fs::remove_file(path);
    }

    /// 模型升级前的旧记录（`pending/approved` + `steps` + `targets`）在读取时折算成新形状：
    /// 状态映射、`steps`→`phases`（补闸门）、`targets`→`spec`，并补齐逐目标条目。幂等。
    #[test]
    fn normalize_upgrade_plan_migrates_legacy_records() {
        let legacy = serde_json::json!({
            "plan_id": "plan-old",
            "targets": [{"component": "wist-gateway-stack", "target_version": "0.1.27"}],
            "target_count": 2,
            "status": "approved",
            "created_at": "2026-09-01T00:00:00Z",
            "steps": [
                {"step_index": 1, "gateway_ids": ["gw-001"], "status": "completed"},
                {"step_index": 2, "gateway_ids": ["gw-002"], "status": "pending"}
            ]
        });
        let mut plan: UpgradePlanRecord =
            serde_json::from_value(legacy).expect("legacy record deserializes");
        assert!(plan.phases.is_empty(), "旧记录没有 phases");
        assert!(plan.entries.is_empty(), "旧记录没有 entries");

        normalize_upgrade_plan(&mut plan);

        // status：approved → rolling；current_phase 起在第一阶段。
        assert_eq!(plan.status, "rolling");
        assert_eq!(plan.current_phase, 1);
        // steps → phases（补闸门：首段 manual、其后 all_succeeded）。
        assert_eq!(plan.phases.len(), 2);
        assert_eq!(plan.phases[0].advance_rule, "manual");
        assert_eq!(plan.phases[1].advance_rule, "all_succeeded");
        assert_eq!(plan.phases[0].gateway_ids, vec!["gw-001".to_string()]);
        assert_eq!(plan.phases[1].gateway_ids, vec!["gw-002".to_string()]);
        // targets → spec 的 JSON。
        let spec: serde_json::Value = serde_json::from_str(&plan.spec).expect("spec json");
        assert_eq!(spec["targets"][0]["component"], "wist-gateway-stack");
        assert_eq!(spec["targets"][0]["target_version"], "0.1.27");
        // 旧记录没有条目 → 按全量目标补 pending（结果才有处回填）。
        assert_eq!(plan.entries.len(), 2);
        assert!(plan.entries.iter().all(|item| item.status == "pending"));
        // 旧字段已清空。
        assert!(plan.legacy_steps.is_empty());
        assert!(plan.legacy_targets.is_empty());

        // 幂等：再跑一次不会重复补条目。
        normalize_upgrade_plan(&mut plan);
        assert_eq!(plan.entries.len(), 2);
        assert_eq!(plan.phases.len(), 2);
    }

    fn test_store_path() -> PathBuf {
        // 纳秒 + 进程内原子序号：光靠纳秒在并行跑测试时会撞同一路径（撞上就变成随机失败）。
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let sequence = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("wist-center-store-test-{nanos}-{sequence}.json"))
    }

    #[test]
    fn customer_binding_revision_and_applied_report() {
        let path = test_store_path();
        let store = FileStore::new(&path);

        let first = store
            .bind_gateway_customer("gw-1", "tenant-a", "alice")
            .expect("bind");
        assert_eq!(first.revision, 1);
        assert_eq!(first.status, "bound");

        // 同客户重复绑定：不递增 revision（幂等），但回到「待生效」（重新下发语义）。
        let applied = store
            .record_customer_binding_report("gw-1", "tenant-a", 1)
            .expect("report")
            .expect("binding");
        assert_eq!(applied.status, "applied");
        let same = store
            .bind_gateway_customer("gw-1", "tenant-a", "bob")
            .expect("rebind");
        assert_eq!(same.revision, 1);
        assert_eq!(same.status, "bound");

        // 换绑：递增 revision，并清掉上一轮的生效状态。
        let changed = store
            .bind_gateway_customer("gw-1", "tenant-b", "bob")
            .expect("rebind");
        assert_eq!(changed.revision, 2);
        assert_eq!(changed.applied_revision, None);
        assert_eq!(changed.applied_at, None);

        // 网关上报一致且同版本 → applied。
        let applied = store
            .record_customer_binding_report("gw-1", "tenant-b", 2)
            .expect("report")
            .expect("binding");
        assert_eq!(applied.status, "applied");
        assert_eq!(applied.applied_revision, Some(2));
        let first_applied_at = applied.applied_at.clone();
        assert!(first_applied_at.is_some());
        assert!(applied.last_error.is_none());

        // 下一次心跳：状态不变，`applied_at` **不**被刷新（那是「最近一次变为已生效」）。
        let again = store
            .record_customer_binding_report("gw-1", "tenant-b", 2)
            .expect("report")
            .expect("binding");
        assert_eq!(again.status, "applied");
        assert_eq!(again.applied_at, first_applied_at);

        // 旧 revision：不覆盖已生效版本；状态回到待生效（与 PgStore 同口径）。
        let older = store
            .record_customer_binding_report("gw-1", "tenant-b", 1)
            .expect("report")
            .expect("binding");
        assert_eq!(older.status, "bound");
        assert_eq!(older.applied_revision, Some(2));
        assert_eq!(
            older.last_error.as_deref(),
            Some("gateway reported older revision")
        );

        // 超前 revision：中心不冒充已生效，也不回写超前的版本。
        let newer = store
            .record_customer_binding_report("gw-1", "tenant-b", 9)
            .expect("report")
            .expect("binding");
        assert_eq!(newer.status, "bound");
        assert_eq!(newer.applied_revision, Some(2));
        assert_eq!(
            newer.last_error.as_deref(),
            Some("gateway reported newer revision")
        );

        // 自报 tenant 与权威值不一致 → drift。
        let drift = store
            .record_customer_binding_report("gw-1", "tenant-x", 2)
            .expect("report")
            .expect("binding");
        assert_eq!(drift.status, "drift");
        assert_eq!(
            drift.last_error.as_deref(),
            Some("reported tenant_id mismatch")
        );

        let got = store
            .get_customer_binding("gw-1")
            .expect("get")
            .expect("binding");
        assert_eq!(got.customer_id, "tenant-b");
        let _ = fs::remove_file(path);
    }

    /// 换绑审计：只在**归属变化**时记（首绑 + 换绑），带 `requested_by` 与旧值。
    #[test]
    fn binding_audit_records_only_real_changes() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        assert!(store.list_binding_audit("gw-1").expect("empty").is_empty());

        let first = store
            .bind_gateway_customer("gw-1", "tenant-a", "alice")
            .expect("bind");
        assert_eq!(first.revision, 1);
        store
            .bind_gateway_customer("gw-1", "tenant-a", "bob")
            .expect("repeat");
        let changed = store
            .bind_gateway_customer("gw-1", "tenant-b", "bob")
            .expect("rebind");
        assert_eq!(changed.revision, 2);

        let events = store.list_binding_audit("gw-1").expect("audit");
        // 同客户重复绑定不产生事件（不改变归属），只剩首绑 + 换绑两条。
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0].customer_id, "tenant-a");
        assert!(events[0].previous_customer_id.is_none());
        assert_eq!(events[0].requested_by, "alice");
        assert_eq!(events[1].customer_id, "tenant-b");
        assert_eq!(events[1].previous_customer_id.as_deref(), Some("tenant-a"));
        assert_eq!(events[1].requested_by, "bob");
        assert_eq!(events[1].revision, 2);
        // 别的网关看不到这条历史。
        assert!(store.list_binding_audit("gw-2").expect("empty").is_empty());
        let _ = fs::remove_file(path);
    }

    /// 命令回执失败：只对**当前版本**生效（旧命令的失败不能盖掉新绑定）。
    #[test]
    fn mark_binding_failed_only_hits_the_current_revision() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        store
            .bind_gateway_customer("gw-1", "tenant-a", "alice")
            .expect("bind");
        store
            .bind_gateway_customer("gw-1", "tenant-b", "alice")
            .expect("rebind");

        assert!(
            !store
                .mark_binding_failed("gw-1", 1, "restart failed")
                .expect("stale failure"),
            "旧版本失败不应命中"
        );
        assert!(
            store
                .mark_binding_failed("gw-1", 2, "restart failed")
                .expect("failure"),
            "当前版本应该命中"
        );
        let binding = store
            .get_customer_binding("gw-1")
            .expect("get")
            .expect("binding");
        assert_eq!(binding.status, "failed");
        assert_eq!(binding.last_error.as_deref(), Some("restart failed"));

        // 下一次心跳（恢复后再生效）会把 failed 拉回 applied。
        let applied = store
            .record_customer_binding_report("gw-1", "tenant-b", 2)
            .expect("report")
            .expect("binding");
        assert_eq!(applied.status, "applied");
        assert!(applied.last_error.is_none());
        let _ = fs::remove_file(path);
    }

    /// 通用任务：认领按「优先级高者优先，其次最早入队」、`running` 残留可重排回
    /// `queued`，进度可单独更新，终态写回后 `get` / `list` 都能看到。
    #[test]
    fn jobs_claim_fifo_and_requeue_running() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        let payload = serde_json::json!({ "component": "wist-agentd" });
        let mut first =
            JobRecord::queued("release-download", "release-download", payload.clone(), 0);
        first.job_id = "job-first".to_string();
        let mut second = JobRecord::queued("release-download", "release-download", payload, 0);
        second.job_id = "job-second".to_string();
        store.create_job(&first).expect("create first");
        store.create_job(&second).expect("create second");

        let claimed = store
            .claim_next_job("release-download")
            .expect("claim")
            .expect("job");
        assert_eq!(claimed.job_id, "job-first", "最早入队的先跑");
        assert_eq!(claimed.state, super::super::jobs::JOB_RUNNING);
        assert!(claimed.started_at.is_some());
        assert!(
            store
                .claim_next_job("release-download")
                .expect("claim")
                .is_some(),
            "第二条也能被认领"
        );

        // 进度单独回写，不覆盖整条记录。
        store
            .update_job_progress(
                "job-first",
                &JobProgress {
                    completed: 1,
                    total: 3,
                    message: Some("取包中（2/3）".to_string()),
                },
            )
            .expect("progress");
        let progress = store
            .get_job("job-first")
            .expect("get")
            .expect("job")
            .progress;
        assert_eq!(progress.completed, 1);
        assert_eq!(progress.total, 3);

        // 模拟进程重启：两条 running 都排回 queued。
        assert_eq!(
            store
                .requeue_running_jobs("release-download")
                .expect("requeue"),
            2
        );
        let queued = store.list_jobs("release-download", 10).expect("list");
        assert_eq!(queued.len(), 2);
        assert!(
            queued
                .iter()
                .all(|job| job.state == super::super::jobs::JOB_QUEUED),
            "{queued:?}"
        );
        // 重新排队后旧进度要清掉（否则 UI 会在「排队中」显示上一次的 1/3）。
        let requeued = store.get_job("job-first").expect("get").expect("job");
        assert_eq!(requeued.progress.completed, 0);
        assert_eq!(requeued.progress.total, 0);

        // 回填终态后可按 id 取回。
        let mut done = store.get_job("job-first").expect("get").expect("job");
        done.state = super::super::jobs::JOB_SUCCEEDED.to_string();
        done.finished_at = Some(DateTime::now());
        store.save_job(&done).expect("save");
        let loaded = store.get_job("job-first").expect("get").expect("job");
        assert_eq!(loaded.state, super::super::jobs::JOB_SUCCEEDED);
        let _ = fs::remove_file(path);
    }

    /// 取消只受理排队中（运行中 / 已终结回 NotCancelable）；保留期清理只删
    /// 已终结且 `finished_at` 超期的任务。
    #[test]
    fn jobs_cancel_and_retention() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        let payload = serde_json::json!({ "component": "wist-agentd" });
        let mk = |id: &str| {
            let mut job =
                JobRecord::queued("release-download", "release-download", payload.clone(), 0);
            job.job_id = id.to_string();
            job
        };

        store.create_job(&mk("job-a")).expect("create a");
        store.create_job(&mk("job-b")).expect("create b");
        // A 已被 worker 认领 → 不能取消。
        let claimed = store
            .claim_next_job("release-download")
            .expect("claim")
            .expect("job");
        assert_eq!(claimed.job_id, "job-a");
        match store.cancel_queued_job("job-a").expect("cancel a") {
            CancelOutcome::NotCancelable(job) => {
                assert_eq!(job.state, super::super::jobs::JOB_RUNNING)
            }
            other => panic!("running job must not be cancelable: {other:?}"),
        }

        // B 仍在排队 → 取消成功。
        match store.cancel_queued_job("job-b").expect("cancel b") {
            CancelOutcome::Canceled(job) => {
                assert_eq!(job.state, super::super::jobs::JOB_CANCELED);
                assert!(job.finished_at.is_some());
            }
            other => panic!("queued job should cancel: {other:?}"),
        }
        assert!(matches!(
            store
                .cancel_queued_job("job-missing")
                .expect("cancel missing"),
            CancelOutcome::NotFound
        ));

        // 造一条 8 天前完成的终态任务 → 保留期 7 天清理把它删掉。
        store.create_job(&mk("job-old")).expect("create old");
        let old = store
            .claim_next_job("release-download")
            .expect("claim old")
            .expect("old job");
        let mut old = old;
        old.state = super::super::jobs::JOB_SUCCEEDED.to_string();
        old.finished_at = Some(DateTime::in_days(-8));
        store.save_job(&old).expect("finish old");
        assert_eq!(
            store
                .delete_terminal_jobs_before("release-download", &DateTime::in_days(-7))
                .expect("cleanup"),
            1
        );
        assert!(store.get_job("job-old").expect("get old").is_none());
        assert!(
            store.get_job("job-a").expect("get a").is_some(),
            "运行中不清理"
        );
        assert!(
            store.get_job("job-b").expect("get b").is_some(),
            "刚取消的任务未超期"
        );

        // 通用读面的状态过滤。
        let canceled = store
            .list_jobs_filtered(
                Some("release-download"),
                None,
                Some(super::super::jobs::JOB_CANCELED),
                None,
                10,
            )
            .expect("filtered");
        assert_eq!(canceled.len(), 1);
        assert_eq!(canceled[0].job_id, "job-b");
        let _ = fs::remove_file(path);
    }

    /// 主体过滤必须在 **limit 之前**生效：目标主体的任务不能被更新的其它主体挤掉。
    #[test]
    fn jobs_filter_by_subject_before_limit() {
        let path = test_store_path();
        let store = FileStore::new(&path);
        let mut target = JobRecord::queued(
            "release-download",
            "release-download",
            serde_json::json!({}),
            0,
        )
        .with_subject("component-a");
        target.job_id = "job-target".to_string();
        store.create_job(&target).expect("create target");
        for index in 0..5 {
            let mut other = JobRecord::queued(
                "release-download",
                "release-download",
                serde_json::json!({}),
                0,
            )
            .with_subject("component-b");
            other.job_id = format!("job-other-{index}");
            store.create_job(&other).expect("create other");
        }

        let found = store
            .list_jobs_filtered(Some("release-download"), None, None, Some("component-a"), 1)
            .expect("filtered");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].job_id, "job-target");
        let _ = fs::remove_file(path);
    }
}
