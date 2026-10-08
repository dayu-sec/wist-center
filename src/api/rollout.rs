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

use wist_control::types::DateTime;

use crate::infra::{UpgradePhaseRecord, UpgradePlanEntryRecord, UpgradePlanRecord};

use super::ApiState;

// ── 入参（与网关**同形**；形状的单一真源是模型 `Control.RolloutApp.AdminInterface`） ──

/// 创建灰度发布计划请求体。
///
/// 字段与网关侧 `CreateRolloutPlanRequest` **同名同义**；差在**必需性**：中心不物化执行单元，
/// `deadline_at` / `timeout_seconds` 只做记录，因此**可省**（网关物化一次性工作，这两项必需）。
/// 阶段由**服务端**按阶梯切（`wist_release::rollout::plan_phases`），客户端只给目标与阶段数。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateRolloutPlanRequest {
    /// 动作面：今天只有 `upgrade`。
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
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPlanEntryView {
    pub target_id: String,
    /// 中心不物化执行单元，恒为 `None`（网关 → agent 时才是那件一次性工作的 work_id）。
    pub work_id: Option<String>,
    pub status: String,
    pub detail: String,
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
        updated_at: entry.updated_at.clone(),
    }
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
    let parsed: UpgradeSpec = serde_json::from_str(spec).ok()?;
    let target = parsed.targets.into_iter().next()?;
    if target.component.is_empty() {
        return None;
    }
    Some((target.component, target.target_version))
}

// ── 建计划（服务端切阶段 + 全量条目落 `pending`） ──

fn rollout_plan_id(action: &str, now: &DateTime) -> String {
    // 语义化：`plan-<action>-<yyyyMMdd-HHmmss>-<short>`（口径在共享 crate `wist-release::rollout`）。
    wist_release::rollout::plan_id(action, &now.to_chrono().to_rfc3339())
}

/// 把请求折算成落库的计划（含按**全量**目标铺好的 `pending` 条目）。
///
/// 阶段由服务端按阶梯切（共享 `wist_release::rollout::plan_phases`），闸门固定策略：
/// 首段 `manual`（金丝雀人工确认），其后 `all_succeeded`（末段不看闸门）。
/// 校验不过 → 返回中性原因字符串，由 handler 折成 **400**。
pub(super) fn build_plan(input: &CreateRolloutPlanRequest) -> Result<UpgradePlanRecord, String> {
    let action = input.action.trim();
    if action.is_empty() {
        return Err("action is required".to_string());
    }
    let spec = input.spec.trim();
    if spec.is_empty() {
        return Err("spec is required".to_string());
    }
    // 截止时间可省；给了就要是合法 RFC3339。
    let deadline_at = match input
        .deadline_at
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        Some(raw) => Some(
            DateTime::from_rfc3339(raw)
                .ok_or_else(|| format!("deadline_at must be RFC3339, got {raw:?}"))?,
        ),
        None => None,
    };
    if input.timeout_seconds < 0 {
        return Err("timeout_seconds must not be negative".to_string());
    }
    // 目标去重、按阶梯切段、固定闸门策略 —— 口径在共享 crate `wist_release::plan`。
    let drafts = wist_release::plan::build_phase_drafts(&input.target_ids, input.phase_count)?;
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
        entries,
        legacy_steps: Vec::new(),
        legacy_targets: Vec::new(),
    })
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
pub(super) async fn reconcile_gateway_upgrade_result(
    state: &ApiState,
    gateway_id: &str,
    status: &str,
    detail: &str,
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
        let idx = plan.current_phase as usize;
        if idx == 0 || idx > plan.phases.len() {
            continue;
        }
        let phase = plan.phases[idx - 1].clone();
        if !phase.gateway_ids.iter().any(|id| id == gateway_id) {
            continue;
        }
        let Some(entry) = plan
            .entries
            .iter_mut()
            .find(|entry| entry.gateway_id == gateway_id)
        else {
            continue;
        };
        // 条目状态与「是否推进」都按**归一化后**的状态判定：上报方（gwlinkd）用 `done` 等措辞，
        // 归一化在共享 crate `wist_release::rollout::entry_status_for`（`done → succeeded` 等）。
        let entry_status = wist_release::rollout::entry_status_for(status);
        entry.status = entry_status.to_string();
        entry.detail = detail.to_string();
        entry.updated_at = DateTime::now();
        if matches!(entry_status, "succeeded" | "failed") {
            progress_plan_after_terminal_result(&mut plan);
        }
        state
            .store
            .save_upgrade_plan(&plan)
            .await
            .map_err(|err| format!("failed to store upgrade plan: {err}"))?;
        return Ok(());
    }
    Ok(())
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
            updated_at: DateTime::now(),
        }
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
}
