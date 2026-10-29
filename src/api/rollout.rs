//! 灰度发布计划（模型 `Control.Rollout`）在**中心**的编排口径。
//!
//! 与网关同一套共享口径（[`wist_release::rollout`] 的原子规则 + [`wist_release::plan`] 的编排）：
//! 阶段由服务端切、固定闸门策略、终态结果按 `advance_rule` 推进、末阶段自动收敛。差异只在
//! **物化**：网关把阶段内的目标变成 `OneShotWork`（交付走 `PollWork`）；中心铺的是**网关** —— 一次「升级」由网关自己来拉
//! （`GET /api/v1/gateway/upgrade-plan`）、执行完再回执（`POST /api/v1/gateway/upgrade-result`），
//! 中心不生成执行单元，所以这里只有「阶段闸门」，没有网关那样的 `batch_size` 节流。
//!
//! 管理面 handler 在 [`super::admin_ops`]、网关侧拉取/回执在 [`super::gateway_ops`]；
//! 本模块是两者共用的**入参形状、读投影与推进逻辑**。

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use wist_control::types::DateTime;

use crate::infra::{UpgradePhaseRecord, UpgradePlanEntryRecord, UpgradePlanRecord};

use super::{ApiState, codes, error::ApiError};

/// 「规则 / 配置 tag 发布」（`wparse-rules` / `wparse-infra`）。
///
/// 与三种运行时 / 内容动作的区别在**谁执行**：那三种由网关轮询计划自己动手（中心不物化）；
/// 本动作反过来 —— 计划只当**审批闸门**，批准后由中心经 `wparse-proxy` 命令队列下发，
/// 网关的 gwlinkd 只负责 relay。
///
/// 因此它**不放进共享 crate `wist-control`**：网关不认识这个动作，也不应该认识
/// （网关侧拉计划时会跳过它，见 [`active_plan_for_gateway`]）。
pub(super) const ACTION_WPARSE_RELEASE: &str = "wparse-release";

// ── 入参（与网关**同形**；形状的单一真源是模型 `Control.RolloutApp.AdminInterface`） ──

/// 创建灰度发布计划请求体。
///
/// 字段与网关侧 `CreateRolloutPlanRequest` **同名同义**；差在**必需性**：中心不物化执行单元，
/// `deadline_at` / `timeout_seconds` 只做记录，因此**可省**（网关物化一次性工作，这两项必需）。
/// 阶段由**服务端**按阶梯切（`wist_release::rollout::plan_phases`），客户端只给目标与阶段数。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateRolloutPlanRequest {
    /// 动作面：`upgrade`（升级安装）/ `push-agent-package`（Agent 包下发，见
    /// [`wist_control::ACTION_PUSH_AGENT_PACKAGE`]）。
    pub action: String,
    /// 动作参数（JSON）：中心铺网关 —— `{"targets":[{"component","target_version"}]}`。
    pub spec: String,
    /// 计划要铺到的目标（中心是 gateway_id；阶段切分由服务端保证互不重叠）。
    pub target_ids: Vec<String>,
    /// 灰度阶段数（1 个金丝雀 → 10% → 30% → 70% → 全量）。
    pub phase_count: i64,
    /// RFC3339 绝对截止；**可省**（中心只记录，不物化）。给了就必须合法。
    #[serde(default)]
    pub deadline_at: Option<String>,
    /// 执行预算（秒）；**可省**（0 = 未指定；给了就不能为负）。
    #[serde(default)]
    pub timeout_seconds: i64,
    /// 每个阶段内同时执行的台数（0 = 不节流）。**中心只记录、不施放**（见模块注释）。
    #[serde(default)]
    pub batch_size: i64,
}

/// 指向某份计划（批准 / 推进）。
#[derive(Debug, Clone, Deserialize)]
pub struct PlanRefRequest {
    pub plan_id: String,
}

/// 重派某份计划的失败目标（中心侧**新建补跑计划**）：`POST /api/v1/admin/rollout-plans/retry`。
///
/// 与网关侧 `RetryRolloutPlanRequest` **同名同义**（形状的单一真源是模型
/// `Control.RolloutApp.AdminInterface`）；差在落地方式 —— 网关原地重开同一份计划，中心新建一份，
/// 理由见 [`build_retry_plan`]。
#[derive(Debug, Clone, Deserialize)]
pub struct RetryRolloutPlanRequest {
    pub plan_id: String,
    /// 要重试的目标；省略 / 为空 = 该计划里**所有**失败目标。
    #[serde(default)]
    pub target_ids: Vec<String>,
}

/// 归档 / 取消归档一份执行记录：`POST /api/v1/admin/rollout-plans/{plan_id}/archive`。
///
/// 归档是**标记**（`archived_at`），计划与逐目标条目全留；默认列表不再展示，
/// `{"archived": false}` 随时恢复。
#[derive(Debug, Clone, Deserialize)]
pub struct ArchiveRolloutPlanRequest {
    /// `true` = 归档；`false` = 取消归档。
    pub archived: bool,
}

/// 只有**终结态**的计划能被归档 / 删除：`draft` / `rolling` 还在推进，藏起来或删掉会让人
/// 找不到「批准 / 推进」入口、丢在飞的工作（停用请先推进到了结）。
pub(super) fn is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "canceled")
}

// ── 读投影（模型里只到「计划」/「计划 + 条目」的形状；与网关视图同形） ──

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPhaseView {
    pub phase_index: i64,
    pub target_ids: Vec<String>,
    pub advance_rule: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPlanView {
    pub plan_id: String,
    pub action: String,
    pub spec: String,
    pub deadline_at: Option<DateTime>,
    pub timeout_seconds: i64,
    pub phases: Vec<RolloutPhaseView>,
    pub batch_size: i64,
    pub current_phase: i64,
    pub status: String,
    pub created_by: String,
    pub created_at: DateTime,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime>,
    /// 归档时刻（`None` = 未归档）。前端据此分「执行记录 / 已归档」。
    pub archived_at: Option<DateTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPlanEntryView {
    pub target_id: String,
    /// 中心不物化执行单元，恒为 `None`（网关 → agent 时才是那件一次性工作的 work_id）。
    pub work_id: Option<String>,
    pub status: String,
    pub detail: String,
    /// 本次任务 ID（网关 `tasks/<kind>-<task_id>-<ts>/` 里的那个）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// 任务执行日志目录（网关本机路径；回执里带的 `日志: <dir>`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<String>,
    /// 任务执行日志摘要（失败回执才带）。管理面直接展开看，不必去网关捞文件。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_excerpt: Option<String>,
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPlanDetailView {
    pub plan: RolloutPlanView,
    pub entries: Vec<RolloutPlanEntryView>,
}

fn phase_view(phase: &UpgradePhaseRecord) -> RolloutPhaseView {
    RolloutPhaseView {
        phase_index: phase.phase_index,
        target_ids: phase.gateway_ids.clone(),
        advance_rule: phase.advance_rule.clone(),
        status: phase.status.clone(),
    }
}

fn entry_view(entry: &UpgradePlanEntryRecord) -> RolloutPlanEntryView {
    RolloutPlanEntryView {
        target_id: entry.gateway_id.clone(),
        work_id: None,
        status: entry.status.clone(),
        detail: entry.detail.clone(),
        task_id: entry.task_id.clone(),
        log_dir: entry.log_dir.clone(),
        log_excerpt: entry.log_excerpt.clone(),
        updated_at: entry.updated_at.clone(),
    }
}

/// 从回执 `detail` 里提取任务日志目录。
///
/// P0 阶段 gwlinkd 把它以 `；日志: <dir>` 追加在 `detail` 末尾；中心在这里归一化成独立字段
/// （不改上报协议）。等 `ReportGatewayUpgradeResult.log_dir` 字段上线后，本函数降为兜底。
pub(super) fn parse_task_log_dir(detail: &str) -> Option<String> {
    let marker = "日志: ";
    let idx = detail.rfind(marker)?;
    let rest = &detail[idx + marker.len()..];
    let dir = rest
        .split_whitespace()
        .next()?
        .trim_end_matches(['；', ';', '。', ',']);
    (!dir.is_empty()).then(|| dir.to_string())
}

/// 计划本体视图（create / list / approve / advance 的返回）。
pub(super) fn plan_view(plan: &UpgradePlanRecord) -> RolloutPlanView {
    RolloutPlanView {
        plan_id: plan.plan_id.clone(),
        action: plan.action.clone(),
        spec: plan.spec.clone(),
        deadline_at: plan.deadline_at.clone(),
        timeout_seconds: plan.timeout_seconds,
        phases: plan.phases.iter().map(phase_view).collect(),
        batch_size: plan.batch_size,
        current_phase: plan.current_phase,
        status: plan.status.clone(),
        created_by: plan.created_by.clone(),
        created_at: plan.created_at.clone(),
        approved_by: plan.approved_by.clone(),
        approved_at: plan.approved_at.clone(),
        archived_at: plan.archived_at.clone(),
    }
}

/// 计划 + 逐目标条目（view 的返回）。
pub(super) fn detail_view(plan: &UpgradePlanRecord) -> RolloutPlanDetailView {
    RolloutPlanDetailView {
        plan: plan_view(plan),
        entries: plan.entries.iter().map(entry_view).collect(),
    }
}

// ── `spec` 解析（模型 `InsightCenter.PlatformRelease.UpgradeSpec`） ──

#[derive(Debug, Clone, Default, Deserialize)]
struct UpgradeSpec {
    #[serde(default)]
    targets: Vec<UpgradeSpecTarget>,
    /// 「知识库包下发」专用：录入后是否立即激活（缺省 false）。其余动作忽略。
    #[serde(default)]
    activate: bool,
    /// 「规则 / 配置 tag 发布」专用：入队时写进 wparse `reload` 的 `reason`。
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct UpgradeSpecTarget {
    #[serde(default)]
    component: String,
    #[serde(default)]
    target_version: String,
}

/// 从 `spec` 解出「升级哪个组件到哪个版本」，取第一个目标。
///
/// 现模型的 `GatewayUpgradePlan` 只承载**单组件**目标（多组件计划取第一个）；`spec` 解不出
/// 组件（缺字段 / 非 JSON）时返回 `None`，由调用方回落成「无组件」（地址也就派生不出来）。
pub(super) fn first_upgrade_target(spec: &str) -> Option<(String, String)> {
    let parsed = serde_json::from_str::<UpgradeSpec>(spec).ok()?;
    let target = parsed.targets.into_iter().next()?;
    if target.component.is_empty() {
        return None;
    }
    Some((target.component, target.target_version))
}

/// 按计划里的目标组件版本，逐台检查它上报的 `version` / `gwlinkd_version` 是否满足
/// 包内 `compat.json` 的 `requires`。返回人类可读的不兼容项；空 = 通过。
///
/// - `Err` = 读存储失败（调用方按 500 处理）；
/// - 没有 release 记录 / 没有 `compat.json` / 网关没上报版本 → 只告警，不阻断；
/// - 只有 `requires` 被明确违反才是硬阻断（`report.is_blocking()`）。
pub(super) async fn target_compatibility_errors(
    state: &ApiState,
    plan: &UpgradePlanRecord,
) -> Result<Vec<String>, String> {
    if plan.action == ACTION_WPARSE_RELEASE {
        return Ok(Vec::new());
    }
    let Some((component, version)) = first_upgrade_target(&plan.spec) else {
        return Ok(Vec::new());
    };
    let releases = state
        .store
        .list_releases(&component)
        .await
        .map_err(|err| format!("failed to load releases for {component}: {err}"))?;
    // 同版本多平台行共用同一份 compat.json；取任一仍可派发且带声明的行即可。
    let Some(compat) = releases
        .iter()
        .find(|record| {
            record.version == version && record.status != "expired" && record.compat.is_some()
        })
        .and_then(|record| record.compat.clone())
    else {
        return Ok(Vec::new());
    };

    let mut errors = Vec::new();
    let mut seen = HashSet::new();
    for entry in &plan.entries {
        if !seen.insert(entry.gateway_id.clone()) {
            continue;
        }
        let gateway = match state.store.get_gateway(&entry.gateway_id).await {
            Ok(Some(gateway)) => gateway,
            Ok(None) => continue,
            Err(err) => {
                return Err(format!(
                    "failed to load gateway {}: {err}",
                    entry.gateway_id
                ));
            }
        };
        let current = gateway_compat_current(&gateway);
        let report = wist_release::compat::check(
            Some(&compat),
            &component,
            &version,
            &current,
            &chrono::Utc::now().to_rfc3339(),
        );
        if report.is_blocking() {
            errors.push(format!(
                "gateway {}: {}",
                entry.gateway_id,
                report.summary()
            ));
        } else if report.status != wist_release::compat::CompatStatus::Ok {
            log::warn!(
                "event=RolloutCompatibilityWarn plan_id={} gateway_id={} component={component} version={version} status={} detail={}",
                plan.plan_id,
                entry.gateway_id,
                report.status.as_str(),
                report.summary()
            );
        }
    }
    Ok(errors)
}

fn gateway_compat_current(
    gateway: &crate::infra::StoredGateway,
) -> std::collections::BTreeMap<String, String> {
    let mut current = std::collections::BTreeMap::new();
    current.insert(
        "wist-center".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    if let Some(version) = gateway.version.as_deref().filter(|value| !value.is_empty()) {
        current.insert("wist-gateway".to_string(), version.to_string());
    }
    if let Some(version) = gateway
        .gwlinkd_version
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        current.insert("wist-gwlinkd".to_string(), version.to_string());
    }
    current
}

/// 「知识库包下发」的 `activate`（缺省 false）：spec 形如
/// `{"targets":[{"component":"wist-knowledge","target_version":"0.3.0"}],"activate":true}`。
/// 解不出 / 非 JSON → `false`（录入 ≠ 生效的保守默认）。
pub(super) fn knowledge_activate(spec: &str) -> bool {
    serde_json::from_str::<UpgradeSpec>(spec)
        .map(|parsed| parsed.activate)
        .unwrap_or(false)
}

/// 「规则 / 配置 tag 发布」的 `spec`：与其它动作同形（`{"targets":[{component,target_version}]}`），
/// 额外带 `reason`（写进入队命令的 wparse `reload.reason`）与 `commit`（**仅作展示 / 审计**，
/// 下发时不用它 —— wparse 自己按 tag 解析；解析侧不需要读它，所以 `UpgradeSpec` 里没有这个字段）。
pub(super) fn wparse_release_spec(
    repo: &str,
    tag: &str,
    commit: Option<&str>,
    reason: &str,
) -> String {
    let mut spec = serde_json::json!({
        "targets": [{ "component": repo, "target_version": tag }],
        "reason": reason,
    });
    if let Some(commit) = commit {
        spec["commit"] = serde_json::Value::String(commit.to_string());
    }
    spec.to_string()
}

/// 入队时用的 wparse `reload.reason`：计划里存的 `reason`，缺省回落 `plan <plan_id>`。
pub(super) fn wparse_release_reason(spec: &str) -> Option<String> {
    serde_json::from_str::<UpgradeSpec>(spec)
        .ok()?
        .reason
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn rollout_plan_id(action: &str, now: &DateTime) -> String {
    // 语义化：`plan-<action>-<yyyyMMdd-HHmmss>-<short>`（口径在共享 crate `wist-release::rollout`）。
    wist_release::rollout::plan_id(action, &now.to_chrono().to_rfc3339())
}

// ── 建计划（服务端切阶段 + 全量条目落 `pending`） ──

/// 已知动作的 `spec.targets` 校验：非空、组件非空、**目标版本必填**。
///
/// 未知动作不校验（形状可能不同，且 gwlinkd 会跳过并留痕）。
#[allow(clippy::result_large_err)] // 与全仓一致：错误直接是可响应的 `ApiError`。
fn validate_target_spec(action: &str, spec: &str) -> Result<(), ApiError> {
    if !matches!(
        action,
        wist_control::ACTION_UPGRADE
            | wist_control::ACTION_PUSH_AGENT_PACKAGE
            | wist_control::ACTION_PUSH_KNOWLEDGE_PACKAGE
            | ACTION_WPARSE_RELEASE
    ) {
        return Ok(());
    }
    let parsed: UpgradeSpec = serde_json::from_str(spec).map_err(|err| {
        ApiError::bad_request(codes::INVALID_SPEC, format!("spec must be JSON: {err}"))
    })?;
    if parsed.targets.is_empty() {
        return Err(ApiError::bad_request(
            codes::INVALID_SPEC,
            "spec.targets must not be empty",
        ));
    }
    for target in &parsed.targets {
        let component = target.component.trim();
        if component.is_empty() {
            return Err(ApiError::bad_request(
                codes::INVALID_SPEC,
                "spec.targets[].component must not be empty",
            ));
        }
        if target.target_version.trim().is_empty() {
            return Err(ApiError::bad_request(
                codes::INVALID_SPEC,
                format!(
                    "spec.targets[].target_version is required (component `{component}` has no version): \
                     the center derives the artifact by version, so an empty version can never be dispatched"
                ),
            ));
        }
    }
    Ok(())
}

/// 把请求折算成落库的计划（含按**全量**目标铺好的 `pending` 条目）。
///
/// 阶段由服务端按阶梯切（共享 `wist_release::rollout::plan_phases`），闸门固定策略：
/// 首段 `manual`（金丝雀人工确认），其后 `all_succeeded`（末段不看闸门）。
/// 校验不过 → 返回带具体 `code` 的 [`ApiError`]（均为 `400`），由 handler 直接投影。
#[allow(clippy::result_large_err)] // 与全仓一致：错误直接是可响应的 `ApiError`，不额外装箱。
pub(super) fn build_plan(input: &CreateRolloutPlanRequest) -> Result<UpgradePlanRecord, ApiError> {
    let action = input.action.trim();
    if action.is_empty() {
        return Err(ApiError::bad_request(
            codes::INVALID_ACTION,
            "action is required",
        ));
    }
    let spec = input.spec.trim();
    if spec.is_empty() {
        return Err(ApiError::bad_request(
            codes::INVALID_SPEC,
            "spec is required",
        ));
    }
    // 已知动作的目标必须带版本：中心按 `(component, target_version)` 反查制品，
    // 留空就派生不出地址 —— 计划下发后网关无事可做（旧 gwlinkd 甚至静默跳过），
    // 条目永远停在 `dispatched`。这种注定发不出去的计划，建的时候就拒。
    validate_target_spec(action, spec)?;
    // 截止时间可省；给了就要是合法 RFC3339。
    let deadline_at = match input
        .deadline_at
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        Some(raw) => Some(DateTime::from_rfc3339(raw).ok_or_else(|| {
            ApiError::bad_request(
                codes::INVALID_DEADLINE,
                format!("deadline_at must be RFC3339, got {raw:?}"),
            )
        })?),
        None => None,
    };
    if input.timeout_seconds < 0 {
        return Err(ApiError::bad_request(
            codes::INVALID_TIMEOUT,
            "timeout_seconds must not be negative",
        ));
    }
    // 目标去重、按阶梯切段、固定闸门策略 —— 口径在共享 crate `wist_release::plan`。
    let drafts = wist_release::plan::build_phase_drafts(&input.target_ids, input.phase_count)
        .map_err(|reason| ApiError::bad_request(codes::INVALID_PHASE_PLAN, reason))?;
    let phases: Vec<UpgradePhaseRecord> = drafts
        .into_iter()
        .map(|draft| UpgradePhaseRecord {
            phase_index: draft.index,
            gateway_ids: draft.target_ids,
            advance_rule: draft.advance_rule,
            status: draft.status,
        })
        .collect();
    let now = DateTime::now();
    // 条目按全量目标先落 `pending`：未到阶段前就能在视图里看到整个范围（与网关 create 一致）。
    let entries: Vec<UpgradePlanEntryRecord> = phases
        .iter()
        .flat_map(|phase| phase.gateway_ids.iter())
        .map(|gateway_id| UpgradePlanEntryRecord {
            gateway_id: gateway_id.clone(),
            status: "pending".to_string(),
            detail: String::new(),
            task_id: None,
            log_dir: None,
            log_excerpt: None,
            updated_at: now.clone(),
        })
        .collect();
    Ok(UpgradePlanRecord {
        plan_id: rollout_plan_id(action, &now),
        action: action.to_string(),
        spec: spec.to_string(),
        deadline_at,
        timeout_seconds: input.timeout_seconds,
        phases,
        batch_size: input.batch_size.max(0),
        current_phase: 0,
        status: "draft".to_string(),
        created_by: "admin".to_string(),
        created_at: now,
        approved_by: None,
        approved_at: None,
        archived_at: None,
        entries,
        legacy_steps: Vec::new(),
        legacy_targets: Vec::new(),
    })
}

/// 补跑计划的 id：在原口径上加 `-retry` 后缀 —— 计划列表里一眼看出「这是重派出来的那份」。
fn retry_plan_id(action: &str, now: &DateTime) -> String {
    format!("{}-retry", rollout_plan_id(action, now))
}

/// 「重试」的落地：把一份失败计划里的**失败目标**重派成**一份新计划**（新 `plan_id`、单阶段、
/// 直接放行 `rolling`）。
///
/// **为什么必须是新计划（不是把原计划改回 `pending`）**：gwlinkd 对每份计划**只驱一次** ——
/// 它落盘 `last_plan_id` 游标，拉到时若 `plan.plan_id == cursor.last_plan_id` 就**跳过**
/// （② Agent 包下发连失败也落游标）。所以「同一份计划、条目改回 pending」在网关看来还是那份
/// 计划 → 被静默跳过：中心显示待派、网关永不重跑，正是最难查的那种假重试。新 `plan_id` 才真的
/// 重驱；原计划**原样留作历史** —— 它是「那次尝试」的记录，不该被改写。
///
/// 单阶段 + 直接放行：重试是人工点的「现在就重派」，再要求一次「批准」只是多一次点击；单阶段也
/// 意味着**末阶段**（全部了结即收尾，不设人工闸门），重试目标全了结时这份补跑计划自动收敛。
///
/// `targets` 为空 → 返回 [`ApiError`]（`no_failed_targets`，`400`）。
#[allow(clippy::result_large_err)] // 同上。
pub(super) fn build_retry_plan(
    original: &UpgradePlanRecord,
    targets: &[String],
) -> Result<UpgradePlanRecord, ApiError> {
    if targets.is_empty() {
        return Err(ApiError::bad_request(
            codes::NO_FAILED_TARGETS,
            "no failed target to retry",
        ));
    }
    let drafts = wist_release::plan::build_phase_drafts(targets, 1)
        .map_err(|reason| ApiError::bad_request(codes::INVALID_PHASE_PLAN, reason))?;
    let phases: Vec<UpgradePhaseRecord> = drafts
        .into_iter()
        .map(|draft| UpgradePhaseRecord {
            phase_index: draft.index,
            gateway_ids: draft.target_ids,
            advance_rule: draft.advance_rule,
            status: draft.status,
        })
        .collect();
    let now = DateTime::now();
    let entries: Vec<UpgradePlanEntryRecord> = phases
        .iter()
        .flat_map(|phase| phase.gateway_ids.iter())
        .map(|gateway_id| UpgradePlanEntryRecord {
            gateway_id: gateway_id.clone(),
            status: "pending".to_string(),
            detail: String::new(),
            task_id: None,
            log_dir: None,
            log_excerpt: None,
            updated_at: now.clone(),
        })
        .collect();
    let mut plan = UpgradePlanRecord {
        plan_id: retry_plan_id(&original.action, &now),
        // 同一个动作面、同一份参数：重试的是**同一件事**，改的只是「再派一次」。
        action: original.action.clone(),
        spec: original.spec.clone(),
        deadline_at: original.deadline_at.clone(),
        timeout_seconds: original.timeout_seconds,
        phases,
        batch_size: original.batch_size,
        current_phase: 0,
        status: "draft".to_string(),
        created_by: "admin".to_string(),
        created_at: now,
        approved_by: None,
        approved_at: None,
        archived_at: None,
        entries,
        legacy_steps: Vec::new(),
        legacy_targets: Vec::new(),
    };
    if !approve_plan(&mut plan) {
        return Err(ApiError::conflict(
            codes::PLAN_NO_PHASE,
            "retry plan has no phase",
        ));
    }
    plan.approved_by = Some("admin".to_string());
    plan.approved_at = Some(DateTime::now());
    Ok(plan)
}

// ── 推进（口径在共享 crate `wist_release::plan`；中心只映射，不物化） ──

/// 把中心的阶段记录 ↔ 共享的中立 [`wist_release::plan::PhaseDraft`] 互转。
fn to_drafts(plan: &UpgradePlanRecord) -> Vec<wist_release::plan::PhaseDraft> {
    plan.phases
        .iter()
        .map(|phase| wist_release::plan::PhaseDraft {
            index: phase.phase_index,
            target_ids: phase.gateway_ids.clone(),
            advance_rule: phase.advance_rule.clone(),
            status: phase.status.clone(),
        })
        .collect()
}

fn apply_drafts(plan: &mut UpgradePlanRecord, drafts: Vec<wist_release::plan::PhaseDraft>) {
    for (phase, draft) in plan.phases.iter_mut().zip(drafts) {
        phase.phase_index = draft.index;
        phase.gateway_ids = draft.target_ids;
        phase.advance_rule = draft.advance_rule;
        phase.status = draft.status;
    }
}

/// 批准：进入第一阶段（中心不物化）。返回是否进入了（`false` = 没有阶段，调用方折 409）。
///
/// 口径在共享 crate `wist_release::plan`（与网关同一份）。
pub(super) fn approve_plan(plan: &mut UpgradePlanRecord) -> bool {
    let mut drafts = to_drafts(plan);
    let mut current_phase = plan.current_phase;
    let mut status = plan.status.clone();
    let entered = wist_release::plan::approve(&mut drafts, &mut current_phase, &mut status);
    if entered {
        apply_drafts(plan, drafts);
        plan.current_phase = current_phase;
        plan.status = status;
    }
    entered
}

/// 当前阶段各条目的状态（闸门 / 收尾只看这些）；越界 → 空。
fn current_phase_statuses(plan: &UpgradePlanRecord) -> Vec<String> {
    let idx = plan.current_phase as usize;
    if idx == 0 || idx > plan.phases.len() {
        return Vec::new();
    }
    let phase = &plan.phases[idx - 1];
    plan.entries
        .iter()
        .filter(|entry| phase.gateway_ids.contains(&entry.gateway_id))
        .map(|entry| entry.status.clone())
        .collect()
}

/// 把一份 `rolling` 计划推进一个阶段：当前阶段划 `completed`，进下一阶段或**收尾**。
///
/// 收尾（末阶段）时看本段结果：**有失败就落 `failed`**，否则 `completed`。
pub(super) fn advance_plan(plan: &mut UpgradePlanRecord) {
    let statuses = current_phase_statuses(plan);
    let refs: Vec<&str> = statuses.iter().map(String::as_str).collect();
    let mut drafts = to_drafts(plan);
    let mut current_phase = plan.current_phase;
    let mut status = plan.status.clone();
    let _ = wist_release::plan::advance(&mut drafts, &mut current_phase, &mut status, &refs);
    apply_drafts(plan, drafts);
    plan.current_phase = current_phase;
    plan.status = status;
}

/// 人工推进的**闸门**：要求当前阶段**已全部了结**（含失败）——「上一阶段确认无问题后再推下一批」。
///
/// 返回 `Some(原因)` 表示不可推进。口径在共享 crate `wist_release::plan`（与网关同一份）。
pub(super) fn advance_gate_blocker(plan: &UpgradePlanRecord) -> Option<String> {
    let statuses = current_phase_statuses(plan);
    let refs: Vec<&str> = statuses.iter().map(String::as_str).collect();
    wist_release::plan::advance_gate_blocker(
        &plan.status,
        &to_drafts(plan),
        plan.current_phase,
        &refs,
    )
}

/// 终态结果回填后按闸门推进：
/// - 末阶段没有「下一段」，全部了结就直接**收尾**（本段有失败落 `failed`、否则 `completed`，**不看闸门**）；
/// - 其余阶段：`manual` 等人工点「推进」，`all_succeeded` / `success_rate:` 满足即自动推进。
///
/// 口径在共享 crate `wist_release::plan`。
pub(super) fn progress_plan_after_terminal_result(plan: &mut UpgradePlanRecord) {
    let statuses = current_phase_statuses(plan);
    let refs: Vec<&str> = statuses.iter().map(String::as_str).collect();
    let mut drafts = to_drafts(plan);
    let mut current_phase = plan.current_phase;
    let mut status = plan.status.clone();
    let stepped = wist_release::plan::progress_after_terminal(
        &mut drafts,
        &mut current_phase,
        &mut status,
        &refs,
    )
    .is_some();
    if stepped {
        apply_drafts(plan, drafts);
        plan.current_phase = current_phase;
        plan.status = status;
    }
}

// ── 网关侧读 / 回执（供 `gateway_ops` 用） ──

/// 这份计划是否由**网关**自己执行？
///
/// `wparse-release` 由中心执行（批准那一刻直接入队），网关拉不到它；其余动作都由网关轮询执行。
fn gateway_executes(action: &str) -> bool {
    action != ACTION_WPARSE_RELEASE
}

/// 找出此刻**该网关该执行**的升级计划：`rolling` 且它落在 `current_phase` 阶段内。
///
/// 计划列表是「新→旧」，取第一份命中的（与旧实现同序）。
pub(super) async fn active_plan_for_gateway(
    state: &ApiState,
    gateway_id: &str,
) -> Result<Option<(UpgradePlanRecord, UpgradePhaseRecord)>, String> {
    let plans = state
        .store
        .list_upgrade_plans()
        .await
        .map_err(|err| format!("failed to load upgrade plans: {err}"))?;
    for plan in plans {
        if plan.status != "rolling" {
            continue;
        }
        // `wparse-release` 的执行方是**中心**（批准后直接入队），不是网关：
        // 让网关拉到会有害（gwlinkd 会把 `wparse-rules` 当成要升级的组件去处理）。
        if !gateway_executes(&plan.action) {
            continue;
        }
        let idx = plan.current_phase as usize;
        if idx == 0 || idx > plan.phases.len() {
            continue;
        }
        let phase = plan.phases[idx - 1].clone();
        if phase.gateway_ids.iter().any(|id| id == gateway_id) {
            return Ok(Some((plan, phase)));
        }
    }
    Ok(None)
}

/// 网关拉走待执行计划时，把它在本阶段的条目标 `dispatched`（仅当还是 `pending`，幂等）。
///
/// 中心不生成执行单元，`dispatched` 的唯一含义就是「网关已把这份计划取走、开始动手」——
/// 在拉取这一刻落，视图里才看得到「已下发」与「待派」的区别。
pub(super) async fn mark_gateway_entry_dispatched(
    state: &ApiState,
    plan_id: &str,
    gateway_id: &str,
) -> Result<(), String> {
    let Some(mut plan) = state
        .store
        .get_upgrade_plan(plan_id)
        .await
        .map_err(|err| format!("failed to load upgrade plan: {err}"))?
    else {
        return Ok(());
    };
    let Some(entry) = plan
        .entries
        .iter_mut()
        .find(|entry| entry.gateway_id == gateway_id)
    else {
        return Ok(());
    };
    if entry.status != "pending" {
        return Ok(());
    }
    entry.status = "dispatched".to_string();
    entry.updated_at = DateTime::now();
    state
        .store
        .save_upgrade_plan(&plan)
        .await
        .map_err(|err| format!("failed to store upgrade plan: {err}"))
}

/// 网关升级结果回填：按 `gateway_id` 找到它此刻所在 `rolling` 计划的当前阶段，回填条目状态/明细，
/// 若是终态（succeeded / failed）再按闸门推进一次。
///
/// 回执里没有中心侧的 work_id（中心不物化），但一个网关此刻最多落在一份 `rolling` 计划的
/// 当前阶段里 —— 按 `gateway_id` + 当前阶段定位就够了。找不到对应计划/条目时静默返回
/// （不是计划物化出来的结果，无条目可回填）。
///
/// **只看网关自己执行的动作**：`wparse-release` 由中心入队、经 `wparse-proxy` 回填，
/// 两个回执通道不能互相串台。
pub(super) async fn reconcile_gateway_upgrade_result(
    state: &ApiState,
    gateway_id: &str,
    status: &str,
    detail: &str,
    task_id: Option<&str>,
    log_dir: Option<&str>,
    log_excerpt: Option<&str>,
) -> Result<(), String> {
    reconcile_plan_result(
        state,
        PlanActionFilter::GatewayExecuted,
        gateway_id,
        status,
        detail,
        task_id,
        log_dir,
        log_excerpt,
    )
    .await
}

/// `wparse-proxy` 命令回执回填：只认 `wparse-release` 计划。
///
/// 命令由中心自己入队（批准时），状态措辞也是中心侧的 `done` / `failed`，
/// 归一化仍走同一份 `entry_status_for`。
pub(super) async fn reconcile_wparse_result(
    state: &ApiState,
    gateway_id: &str,
    status: &str,
    detail: &str,
    task_id: Option<&str>,
    log_dir: Option<&str>,
    log_excerpt: Option<&str>,
) -> Result<(), String> {
    reconcile_plan_result(
        state,
        PlanActionFilter::Only(ACTION_WPARSE_RELEASE),
        gateway_id,
        status,
        detail,
        task_id,
        log_dir,
        log_excerpt,
    )
    .await
}

/// 回执该匹配哪类计划：网关执行的动作（默认全部），或只看某一个动作。
#[derive(Clone, Copy)]
enum PlanActionFilter {
    /// 网关轮询执行的三种动作 —— 必须排除 `wparse-release`（它由中心执行）。
    GatewayExecuted,
    /// 只看指定动作。
    Only(&'static str),
}

#[allow(clippy::too_many_arguments)] // 与两个公开入口同形，拆结构体反而绕。
async fn reconcile_plan_result(
    state: &ApiState,
    filter: PlanActionFilter,
    gateway_id: &str,
    status: &str,
    detail: &str,
    task_id: Option<&str>,
    log_dir: Option<&str>,
    log_excerpt: Option<&str>,
) -> Result<(), String> {
    let plans = state
        .store
        .list_upgrade_plans()
        .await
        .map_err(|err| format!("failed to load upgrade plans: {err}"))?;
    for mut plan in plans {
        if plan.status != "rolling" {
            continue;
        }
        let matches_action = match filter {
            PlanActionFilter::GatewayExecuted => plan.action != ACTION_WPARSE_RELEASE,
            PlanActionFilter::Only(action) => plan.action == action,
        };
        if !matches_action {
            continue;
        }
        let idx = plan.current_phase as usize;
        if idx == 0 || idx > plan.phases.len() {
            continue;
        }
        let phase = plan.phases[idx - 1].clone();
        if !phase.gateway_ids.iter().any(|id| id == gateway_id) {
            continue;
        }
        // 有 `task_id` 时优先按它定位：同一网关可能同时落在两份 `wparse-release` 计划里
        // （刚批准一份、又重派了一份），只按 `gateway_id` 会回填到错的那份。
        let entry_index = task_id
            .and_then(|task_id| {
                plan.entries
                    .iter()
                    .position(|entry| entry.task_id.as_deref() == Some(task_id))
            })
            .or_else(|| {
                plan.entries
                    .iter()
                    .position(|entry| entry.gateway_id == gateway_id)
            });
        let Some(entry_index) = entry_index else {
            continue;
        };
        let entry = &mut plan.entries[entry_index];
        // 条目状态与「是否推进」都按**归一化后**的状态判定：上报方（gwlinkd）用 `done` 等措辞，
        // 归一化在共享 crate `wist_release::rollout::entry_status_for`（`done → succeeded` 等）。
        let entry_status = wist_release::rollout::entry_status_for(status);
        entry.status = entry_status.to_string();
        entry.detail = detail.to_string();
        if let Some(task_id) = task_id {
            entry.task_id = Some(task_id.to_string());
        }
        if let Some(log_dir) = log_dir {
            entry.log_dir = Some(log_dir.to_string());
        }
        if let Some(log_excerpt) = log_excerpt {
            entry.log_excerpt = Some(log_excerpt.to_string());
        }
        entry.updated_at = DateTime::now();
        if matches!(entry_status, "succeeded" | "failed") {
            progress_plan_after_terminal_result(&mut plan);
        }
        state
            .store
            .save_upgrade_plan(&plan)
            .await
            .map_err(|err| format!("failed to store upgrade plan: {err}"))?;
        // 网关回执：一个网关此刻只落在一份计划的当前阶段里，取第一份命中即可。
        // 命令回执不同：**同一条命令可能被多份 wparse 计划复用**（`publish_reload` 按 body 去重），
        // 所以要把所有命中这条 `task_id` 的条目都回填完，否则后批准的那份会永远停在 `dispatched`。
        if matches!(filter, PlanActionFilter::GatewayExecuted) {
            return Ok(());
        }
    }
    Ok(())
}

/// 入队前一次性备齐的东西：`None` 表示这份计划根本不需要入队（已收尾 / 无阶段）。
///
/// 拆出来是为了让调用方能把「校验」与「落库」「入队」按正确顺序编排：
/// **先校验 → 再落库成 `rolling` → 再入队 → 再回写条目**。
/// 顺序不能反：命令一旦进队列，gwlinkd 随时会取走并回执；如果那一刻计划还停在 `draft`，
/// 回执回来就找不到可回填的 `rolling` 计划（`reconcile_*` 只认 rolling），
/// 现场就成了「实际重载了，中心显示没发」。
pub(super) struct WparseDispatch {
    proxy: std::sync::Arc<crate::wparse_proxy::WparseProxy>,
    group: String,
    tag: String,
    reason: String,
}

/// 「现在能不能给这份计划入队」—— **不落库、不入队**，失败时调用方可以原地退回。
pub(super) fn prepare_wparse_dispatch(
    state: &ApiState,
    plan: &UpgradePlanRecord,
) -> Result<Option<WparseDispatch>, String> {
    // 末阶段被「推进」收尾后 `current_phase` 仍指向那一段，不挡就会把已跑完的目标再发一遍。
    if plan.status != "rolling" {
        return Ok(None);
    }
    let idx = plan.current_phase as usize;
    if idx == 0 || idx > plan.phases.len() {
        return Ok(None);
    }
    let Some(proxy) = state.proxy.as_ref() else {
        return Err("wparse proxy is not enabled on this center".to_string());
    };
    let (repo_name, tag) = first_upgrade_target(&plan.spec)
        .ok_or_else(|| format!("plan {} has no readable target", plan.plan_id))?;
    let Some(repo) = state
        .config
        .wparse_release
        .repos
        .iter()
        .find(|item| item.name == repo_name)
    else {
        return Err(format!(
            "repo {repo_name} is no longer configured on this center"
        ));
    };
    Ok(Some(WparseDispatch {
        proxy: proxy.clone(),
        group: repo.group.clone(),
        tag,
        reason: wparse_release_reason(&plan.spec)
            .unwrap_or_else(|| format!("plan {}", plan.plan_id)),
    }))
}

/// 把「当前阶段」的目标真正投进 `wparse-proxy` 命令队列（只改内存里的 `plan`，不落库、不报错）。
///
/// 单台入队失败（队列满 / 存储错）只把那一台标 `failed`：批准已经生效，不该因为一台发不出去
/// 就把整份计划退回 —— 后续用「重试」重派即可。
pub(super) async fn enqueue_wparse_phase(plan: &mut UpgradePlanRecord, dispatch: &WparseDispatch) {
    let idx = plan.current_phase as usize;
    if idx == 0 || idx > plan.phases.len() {
        return;
    }
    let gateway_ids = plan.phases[idx - 1].gateway_ids.clone();
    let mut queued = 0usize;
    let mut failed = 0usize;
    for gateway_id in gateway_ids {
        let outcome = dispatch
            .proxy
            .publish_reload(
                &gateway_id,
                &dispatch.group,
                &dispatch.tag,
                &dispatch.reason,
                15_000,
            )
            .await;
        let Some(entry) = plan
            .entries
            .iter_mut()
            .find(|entry| entry.gateway_id == gateway_id)
        else {
            continue;
        };
        entry.updated_at = DateTime::now();
        match outcome {
            Ok(enqueued) => {
                queued += 1;
                entry.status = "dispatched".to_string();
                entry.task_id = Some(enqueued.command_id);
                entry.detail = if enqueued.reused {
                    "命令已在队列中（复用）".to_string()
                } else {
                    "已入队，等待网关执行".to_string()
                };
            }
            Err(err) => {
                failed += 1;
                log::warn!(
                    "event=WparseReleaseEnqueueFailed plan_id={} gateway_id={} err={}",
                    plan.plan_id,
                    gateway_id,
                    err
                );
                entry.status = "failed".to_string();
                entry.detail = format!("入队失败：{err}");
            }
        }
    }
    log::info!(
        "event=WparseReleaseDispatched plan_id={} group={} tag={} phase={} queued={} failed={}",
        plan.plan_id,
        dispatch.group,
        dispatch.tag,
        plan.current_phase,
        queued,
        failed
    );
}

/// `wparse-release` 的批准 / 推进 / 重试落库：**先校验 → 先存 rolling → 入队 → 再存条目**。
///
/// 只在 `wparse-release` 计划上调用（其它动作由网关自己拉，中心不物化）。
#[allow(clippy::result_large_err)] // 与全仓一致：错误直接是可响应的 `ApiError`。
pub(super) async fn persist_and_dispatch_wparse(
    state: &ApiState,
    plan: &mut UpgradePlanRecord,
) -> Result<(), ApiError> {
    // 校验在**第一次落库之前**：仓库被删 / proxy 关了这类错，计划应原地留在 `draft`。
    let dispatch = prepare_wparse_dispatch(state, plan)
        .map_err(|message| ApiError::unavailable(codes::WPARSE_PLAN_DISPATCH_FAILED, message))?;
    store_plan(state, plan).await?;
    let Some(dispatch) = dispatch else {
        return Ok(());
    };
    enqueue_wparse_phase(plan, &dispatch).await;
    store_plan(state, plan).await
}

/// 计划落库（失败时统一折成 `rollout_plan_store_failed`，便于现场排障）。
#[allow(clippy::result_large_err)] // 同上。
async fn store_plan(state: &ApiState, plan: &UpgradePlanRecord) -> Result<(), ApiError> {
    state.store.save_upgrade_plan(plan).await.map_err(|err| {
        ApiError::internal(
            codes::ROLLOUT_PLAN_STORE_FAILED,
            "failed to store rollout plan",
            err.display_chain(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::{UpgradePhaseRecord, UpgradePlanEntryRecord};

    fn phase(index: i64, ids: &[&str], rule: &str, status: &str) -> UpgradePhaseRecord {
        UpgradePhaseRecord {
            phase_index: index,
            gateway_ids: ids.iter().map(|id| id.to_string()).collect(),
            advance_rule: rule.to_string(),
            status: status.to_string(),
        }
    }

    fn entry(target: &str, status: &str) -> UpgradePlanEntryRecord {
        UpgradePlanEntryRecord {
            gateway_id: target.to_string(),
            status: status.to_string(),
            detail: String::new(),
            task_id: None,
            log_dir: None,
            log_excerpt: None,
            updated_at: DateTime::now(),
        }
    }

    #[test]
    fn entry_view_exposes_the_log_excerpt() {
        let mut entry = entry("gw-1", "failed");
        entry.detail = "executor exit status: 1".to_string();
        entry.task_id = Some("upgrade-plan-1-20261020-143000".to_string());
        entry.log_dir = Some("/var/lib/gwlinkd/tasks/upgrade-p-1".to_string());
        entry.log_excerpt = Some("# output\nexit status: 1".to_string());

        let view = entry_view(&entry);
        assert_eq!(
            view.task_id.as_deref(),
            Some("upgrade-plan-1-20261020-143000")
        );
        assert_eq!(
            view.log_dir.as_deref(),
            Some("/var/lib/gwlinkd/tasks/upgrade-p-1")
        );
        assert_eq!(
            view.log_excerpt.as_deref(),
            Some("# output\nexit status: 1")
        );

        // 老网关不带：序列化里连键都不出现（管理面不会渲染空块）。
        let bare = entry_view(&self::entry("gw-2", "succeeded"));
        let json = serde_json::to_string(&bare).expect("json");
        assert!(!json.contains("log_excerpt"), "{json}");
        assert!(!json.contains("log_dir"), "{json}");
        assert!(!json.contains("task_id"), "{json}");
    }

    #[test]
    fn parses_task_log_dir_from_detail() {
        assert_eq!(
            parse_task_log_dir("取包失败；日志: /var/x/tasks/upgrade-plan-1-2026"),
            Some("/var/x/tasks/upgrade-plan-1-2026".to_string())
        );
        assert_eq!(parse_task_log_dir("日志: /a/b；"), Some("/a/b".to_string()));
        assert_eq!(parse_task_log_dir("没有日志"), None);
        assert_eq!(parse_task_log_dir("日志: "), None);
    }

    fn plan_with(
        phases: Vec<UpgradePhaseRecord>,
        entries: Vec<UpgradePlanEntryRecord>,
        current_phase: i64,
        status: &str,
    ) -> UpgradePlanRecord {
        UpgradePlanRecord {
            plan_id: "plan-test".to_string(),
            action: "upgrade".to_string(),
            spec: "{}".to_string(),
            deadline_at: Some(DateTime::now()),
            timeout_seconds: 600,
            phases,
            batch_size: 0,
            current_phase,
            status: status.to_string(),
            created_by: "admin".to_string(),
            created_at: DateTime::now(),
            approved_by: None,
            approved_at: None,
            archived_at: None,
            entries,
            legacy_steps: Vec::new(),
            legacy_targets: Vec::new(),
        }
    }

    fn request(targets: &[&str], phase_count: i64) -> CreateRolloutPlanRequest {
        CreateRolloutPlanRequest {
            action: "upgrade".to_string(),
            spec: r#"{"targets":[{"component":"wist-gateway-stack","target_version":"0.1.28"}]}"#
                .to_string(),
            target_ids: targets.iter().map(|id| id.to_string()).collect(),
            phase_count,
            deadline_at: Some("2027-01-01T00:00:00Z".to_string()),
            timeout_seconds: 600,
            batch_size: 0,
        }
    }

    #[test]
    fn first_upgrade_target_parses_the_first_component() {
        let spec = r#"{"targets":[{"component":"wist-gateway-stack","target_version":"0.1.28"}]}"#;
        assert_eq!(
            first_upgrade_target(spec),
            Some(("wist-gateway-stack".to_string(), "0.1.28".to_string()))
        );
        // 多组件计划取第一个（现模型 `GatewayUpgradePlan` 单组件）。
        let multi = r#"{"targets":[{"component":"a","target_version":"1"},{"component":"b","target_version":"2"}]}"#;
        assert_eq!(first_upgrade_target(multi), Some(("a".into(), "1".into())));
        // 非 JSON / 空组件 / 无目标 → None。
        assert_eq!(first_upgrade_target("not json"), None);
        assert_eq!(
            first_upgrade_target(r#"{"targets":[{"component":""}]}"#),
            None
        );
        assert_eq!(first_upgrade_target(r#"{"targets":[]}"#), None);
    }

    #[test]
    fn advance_plan_walks_to_completed() {
        let mut plan = plan_with(
            vec![
                phase(1, &["a"], "manual", "rolling"),
                phase(2, &["b"], "all_succeeded", "pending"),
            ],
            vec![entry("a", "succeeded"), entry("b", "pending")],
            1,
            "rolling",
        );
        advance_plan(&mut plan);
        assert_eq!(plan.current_phase, 2);
        assert_eq!(plan.status, "rolling");
        assert_eq!(plan.phases[0].status, "completed");
        assert_eq!(plan.phases[1].status, "rolling");
        advance_plan(&mut plan);
        assert_eq!(plan.status, "completed");
        assert_eq!(plan.phases[1].status, "completed");
        // 已完成后再次推进是 no-op（handler 会先以 409 拦下）。
        advance_plan(&mut plan);
        assert_eq!(plan.status, "completed");
    }

    #[test]
    fn approve_plan_opens_the_first_phase_and_rejects_an_empty_plan() {
        let mut plan = plan_with(
            vec![
                phase(1, &["a"], "manual", "pending"),
                phase(2, &["b"], "all_succeeded", "pending"),
            ],
            vec![entry("a", "pending"), entry("b", "pending")],
            0,
            "draft",
        );
        assert!(approve_plan(&mut plan));
        assert_eq!(plan.status, "rolling");
        assert_eq!(plan.current_phase, 1);
        assert_eq!(plan.phases[0].status, "rolling");
        assert_eq!(plan.phases[1].status, "pending", "未到的段仍 pending");

        // 没有阶段 → 不进入，状态不动（handler 据此折 409）。
        let mut empty = plan_with(Vec::new(), Vec::new(), 0, "draft");
        assert!(!approve_plan(&mut empty));
        assert_eq!(empty.status, "draft");
        assert_eq!(empty.current_phase, 0);
    }

    #[test]
    fn manual_phase_waits_for_a_human_but_all_succeeded_auto_advances() {
        // 非末段 `all_succeeded`：本段全部终态才推进；有在飞则不推进。
        let mut plan = plan_with(
            vec![
                phase(1, &["a"], "manual", "completed"),
                phase(2, &["b"], "all_succeeded", "rolling"),
                phase(3, &["c"], "all_succeeded", "pending"),
            ],
            vec![
                entry("a", "succeeded"),
                entry("b", "pending"),
                entry("c", "pending"),
            ],
            2,
            "rolling",
        );
        progress_plan_after_terminal_result(&mut plan);
        assert_eq!(plan.current_phase, 2, "本段还没了结，不该推进");
        plan.entries[1].status = "succeeded".to_string();
        progress_plan_after_terminal_result(&mut plan);
        assert_eq!(plan.current_phase, 3);
        assert_eq!(plan.phases[1].status, "completed");
        assert_eq!(plan.phases[2].status, "rolling");

        // `manual` 段：即使全部成功也不自动推进（等人工点）。
        let mut plan = plan_with(
            vec![
                phase(1, &["a"], "manual", "rolling"),
                phase(2, &["b"], "all_succeeded", "pending"),
            ],
            vec![entry("a", "succeeded"), entry("b", "pending")],
            1,
            "rolling",
        );
        progress_plan_after_terminal_result(&mut plan);
        assert_eq!(plan.current_phase, 1);
        assert_eq!(plan.status, "rolling");
    }

    #[test]
    fn last_phase_converges_when_settled_regardless_of_gate() {
        // 末阶段全部了结：本段**有失败就落 `failed`**（不把失败抹成「完成」）。
        let mut plan = plan_with(
            vec![phase(1, &["a"], "manual", "rolling")],
            vec![entry("a", "failed")],
            1,
            "rolling",
        );
        progress_plan_after_terminal_result(&mut plan);
        assert_eq!(plan.status, "failed");
        assert_eq!(plan.phases[0].status, "completed");

        // 全成功 → `completed`。
        let mut plan = plan_with(
            vec![phase(1, &["a"], "manual", "rolling")],
            vec![entry("a", "succeeded")],
            1,
            "rolling",
        );
        progress_plan_after_terminal_result(&mut plan);
        assert_eq!(plan.status, "completed");
    }

    /// 重试落地成**新计划**：只带失败目标、单阶段、直接放行；动作/参数从原计划继承。
    #[test]
    fn build_retry_plan_is_a_new_single_phase_plan_for_failed_targets() {
        let original = plan_with(
            vec![phase(
                1,
                &["gw-001", "gw-002", "gw-003"],
                "manual",
                "completed",
            )],
            vec![
                entry("gw-001", "succeeded"),
                entry("gw-002", "failed"),
                entry("gw-003", "pending"),
            ],
            1,
            "failed",
        );
        let retry = build_retry_plan(&original, &["gw-002".to_string()]).expect("retry plan");

        assert_ne!(
            retry.plan_id, original.plan_id,
            "必须是新 id（网关按 plan_id 去重）"
        );
        assert!(
            retry.plan_id.ends_with("-retry"),
            "id 要一眼看出是重派：{}",
            retry.plan_id
        );
        assert_eq!(retry.status, "rolling", "重试 = 现在就重派，直接放行");
        assert_eq!(retry.current_phase, 1);
        assert_eq!(retry.phases.len(), 1, "单阶段：重试目标一次铺完");
        assert_eq!(retry.phases[0].gateway_ids, vec!["gw-002".to_string()]);
        assert_eq!(retry.phases[0].status, "rolling");
        assert_eq!(retry.action, original.action);
        assert_eq!(retry.spec, original.spec);
        assert_eq!(retry.timeout_seconds, original.timeout_seconds);
        assert_eq!(retry.entries.len(), 1);
        assert_eq!(retry.entries[0].gateway_id, "gw-002");
        assert_eq!(
            retry.entries[0].status, "pending",
            "回到待派，网关下次轮询即可取走"
        );
        assert!(retry.approved_at.is_some());
    }

    #[test]
    fn build_retry_plan_rejects_an_empty_target_list() {
        let original = plan_with(
            vec![phase(1, &["gw-001"], "manual", "completed")],
            vec![entry("gw-001", "failed")],
            1,
            "failed",
        );
        assert!(build_retry_plan(&original, &[]).is_err());
    }

    #[test]
    fn build_plan_splits_phases_and_seeds_entries() {
        let ids: Vec<String> = (1..=10).map(|i| format!("gw-{i:03}")).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let plan = build_plan(&request(&refs, 3)).expect("plan");
        assert_eq!(plan.status, "draft");
        assert_eq!(plan.current_phase, 0);
        assert_eq!(plan.phases.len(), 3);
        // 固定闸门：首段人工、其余全成功。
        assert_eq!(plan.phases[0].advance_rule, "manual");
        assert_eq!(plan.phases[1].advance_rule, "all_succeeded");
        // 全量目标都落 `pending` 条目。
        assert_eq!(plan.entries.len(), 10);
        assert!(plan.entries.iter().all(|item| item.status == "pending"));
        // 阶段互不重叠、并集 = 全量。
        let mut all: Vec<&str> = plan
            .phases
            .iter()
            .flat_map(|phase| phase.gateway_ids.iter().map(String::as_str))
            .collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn build_plan_rejects_bad_input() {
        let mut r = request(&["gw-001"], 1);
        r.action = "  ".to_string();
        assert!(build_plan(&r).is_err(), "空 action");
        let mut r = request(&["gw-001"], 1);
        r.spec = String::new();
        assert!(build_plan(&r).is_err(), "空 spec");
        let mut r = request(&["gw-001"], 1);
        r.deadline_at = Some("2027-01-01 00:00:00".to_string());
        assert!(build_plan(&r).is_err(), "非法 deadline");
        let mut r = request(&["gw-001"], 1);
        r.timeout_seconds = -1;
        assert!(build_plan(&r).is_err(), "负超时");
        assert!(build_plan(&request(&[], 1)).is_err(), "空目标");
        assert!(build_plan(&request(&["gw-001"], 0)).is_err(), "阶段数为 0");
        assert!(
            build_plan(&request(&["gw-001"], 2)).is_err(),
            "阶段数大于台数"
        );
    }

    /// 目标版本必填：留空时中心派生不出制品，计划永远发不出去。
    #[test]
    fn build_plan_requires_a_target_version_for_known_actions() {
        let mut r = request(&["gw-001"], 1);
        r.spec = r#"{"targets":[{"component":"wist-gwlinkd"}]}"#.to_string();
        let err = build_plan(&r).expect_err("versionless target must be rejected");
        let message = format!("{err:?}");
        assert!(message.contains("target_version"), "{message}");
        assert!(message.contains("wist-gwlinkd"), "{message}");

        let mut r = request(&["gw-001"], 1);
        r.spec = r#"{"targets":[]}"#.to_string();
        assert!(build_plan(&r).is_err(), "空 targets");

        let mut r = request(&["gw-001"], 1);
        r.spec = "not json".to_string();
        assert!(build_plan(&r).is_err(), "非 JSON spec");

        // 未知动作不校验形状（gwlinkd 会跳过并留痕）。
        let mut r = request(&["gw-001"], 1);
        r.action = "future-action".to_string();
        r.spec = r#"{"whatever":true}"#.to_string();
        assert!(build_plan(&r).is_ok(), "未知动作保持宽容");
    }

    /// `deadline_at` / `timeout_seconds` 可省（中心不物化执行单元）。
    #[test]
    fn build_plan_allows_omitted_pacing_fields() {
        let mut r = request(&["gw-001"], 1);
        r.deadline_at = None;
        r.timeout_seconds = 0;
        let plan = build_plan(&r).expect("可省的节拍字段不应阻塞建计划");
        assert!(plan.deadline_at.is_none());
        assert_eq!(plan.timeout_seconds, 0);
    }

    #[test]
    fn build_plan_dedupes_and_trims_targets() {
        let plan = build_plan(&request(&["gw-001", "gw-001", " gw-001 "], 1)).expect("plan");
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].gateway_id, "gw-001");
    }

    #[test]
    fn advance_gate_requires_a_settled_phase() {
        // 还在飞 → 不可推进。
        let mut plan = plan_with(
            vec![
                phase(1, &["a"], "manual", "rolling"),
                phase(2, &["b"], "all_succeeded", "pending"),
            ],
            vec![entry("a", "dispatched"), entry("b", "pending")],
            1,
            "rolling",
        );
        assert!(advance_gate_blocker(&plan).is_some());
        // 全部了结（含失败）→ 可推进。
        plan.entries[0].status = "failed".to_string();
        assert!(advance_gate_blocker(&plan).is_none());
        // 非 rolling → 不可推进。
        plan.status = "completed".to_string();
        assert!(advance_gate_blocker(&plan).is_some());
    }

    #[test]
    fn gateway_never_executes_wparse_release_plans() {
        // 中心执行的动作不能让网关拉：否则 gwlinkd 会把 `wparse-rules` 当组件去装。
        assert!(!gateway_executes(ACTION_WPARSE_RELEASE));
        for action in [
            wist_control::ACTION_UPGRADE,
            wist_control::ACTION_PUSH_AGENT_PACKAGE,
            wist_control::ACTION_PUSH_KNOWLEDGE_PACKAGE,
        ] {
            assert!(gateway_executes(action), "{action} 应由网关执行");
        }
    }

    #[test]
    fn wparse_release_spec_round_trips_through_the_plan() {
        // 与其它动作同形（`targets[].component` + `target_version`），额外带 `reason`；
        // 建计划时要能过 `validate_target_spec`，下发时要能反解出 repo / tag。
        let spec = wparse_release_spec("wparse-rules", "v1.0.7", Some("8e36b594"), "plan-xyz");
        let mut request = request(&["gw-001"], 1);
        request.action = ACTION_WPARSE_RELEASE.to_string();
        request.spec = spec.clone();
        let plan = build_plan(&request).expect("wparse-release plan builds");
        assert_eq!(plan.action, ACTION_WPARSE_RELEASE);
        assert_eq!(
            first_upgrade_target(&plan.spec),
            Some(("wparse-rules".to_string(), "v1.0.7".to_string()))
        );
        assert_eq!(
            wparse_release_reason(&plan.spec).as_deref(),
            Some("plan-xyz")
        );
        // 单阶段：批准即全量，不需要灰度阶梯。
        assert_eq!(plan.phases.len(), 1);
    }

    #[test]
    fn wparse_release_refuses_an_empty_version() {
        // 与其它动作同一道门槛：没有版本就派生不出目标，建的时候就拒。
        let mut request = request(&["gw-001"], 1);
        request.action = ACTION_WPARSE_RELEASE.to_string();
        request.spec = wparse_release_spec("wparse-infra", "", None, "manual");
        assert!(build_plan(&request).is_err());
    }
}
