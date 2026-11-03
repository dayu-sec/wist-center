//! 指令（Command）资源：北向语义层 `commands` 与投递层 `target_commands` 的记录形状。
//!
//! 设计见 `wist-design/doc/design/center/center-open-api.md` §6：
//! - `command_id` 是调用方看到的语义主键；
//! - `target_command_id` 是网关看到的投递主键（= `gateway_commands.command_id`）；
//! - 一个指令只能有一种目标类型（`gateway` / `agent`），投递按目标独立成败。

use serde::{Deserialize, Serialize};
use wist_control::types::DateTime;

// ── 聚合状态（调用方看到的 command.state）────────────────────────────────

pub const COMMAND_STATE_VALIDATED: &str = "validated";
pub const COMMAND_STATE_QUEUED: &str = "queued";
pub const COMMAND_STATE_LEASED: &str = "leased";
pub const COMMAND_STATE_SUCCEEDED: &str = "succeeded";
pub const COMMAND_STATE_PARTIAL: &str = "partial";
pub const COMMAND_STATE_FAILED: &str = "failed";
pub const COMMAND_STATE_REJECTED: &str = "rejected";
pub const COMMAND_STATE_CANCELLED: &str = "cancelled";
pub const COMMAND_STATE_EXPIRED: &str = "expired";

// ── 单目标状态（target_command.state）────────────────────────────────────

pub const TARGET_STATE_QUEUED: &str = "queued";
pub const TARGET_STATE_LEASED: &str = "leased";
pub const TARGET_STATE_SUCCEEDED: &str = "succeeded";
pub const TARGET_STATE_FAILED: &str = "failed";
pub const TARGET_STATE_CANCELLED: &str = "cancelled";
pub const TARGET_STATE_EXPIRED: &str = "expired";
pub const TARGET_STATE_REJECTED: &str = "rejected";

/// 一条指令（调用方视角）。落库为一条记录，随解析方式不同（JSON 文件 / PG payload）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandRecord {
    pub command_id: String,
    /// 调用方给的幂等键（`Idempotency-Key`），全局唯一。
    pub request_id: String,
    /// 调用方词表里的种类（`gateway.diagnose` …）。
    pub kind: String,
    /// `gateway` | `agent`（首版只实现 `gateway`）。
    pub target_type: String,
    /// 创建时冻结的目标集合（去重后）。
    pub target_ids: Vec<String>,
    /// 已校验过的 payload（按 kind 定形状）。
    pub payload: serde_json::Value,
    #[serde(default)]
    pub reason: Option<String>,
    /// 发起人在报文里自报的值（仅审计展示；授权只认身份）。
    #[serde(default)]
    pub requested_by: Option<String>,
    pub state: String,
    pub created_by: String,
    pub created_at: DateTime,
    #[serde(default)]
    pub dispatched_at: Option<DateTime>,
    #[serde(default)]
    pub dispatched_by: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime>,
    #[serde(default)]
    pub cancelled_at: Option<DateTime>,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// 一个目标的投递记录。`target_command_id` 就是 `gateway_commands.command_id`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetCommandRecord {
    pub target_command_id: String,
    pub command_id: String,
    pub target_id: String,
    /// 目标所属网关：`gateway` 目标时 == `target_id`；`agent` 目标时是 agent 的归属网关。
    pub gateway_id: String,
    /// 投给网关的 wire kind（`diagnose` / `restart-gateway` …）。
    pub wire_kind: String,
    pub state: String,
    pub attempts: i32,
    #[serde(default)]
    pub result_status: Option<i32>,
    #[serde(default)]
    pub result_error: Option<String>,
    #[serde(default)]
    pub result_body: Option<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

impl CommandRecord {
    /// 是否已到终结态（不允许再 dispatch）。
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state.as_str(),
            COMMAND_STATE_SUCCEEDED
                | COMMAND_STATE_PARTIAL
                | COMMAND_STATE_FAILED
                | COMMAND_STATE_REJECTED
                | COMMAND_STATE_CANCELLED
                | COMMAND_STATE_EXPIRED
        )
    }
}

/// 由逐目标状态汇总出指令状态（不单独存可变聚合值，避免两处真相）。
///
/// 规则与设计文档 §6.4 一致：
/// - 有未终态 → `leased`（有租约中）/ `queued`；
/// - 全成功 → `succeeded`；全失败 → `failed`；部分成功 → `partial`。
pub fn aggregate_state(targets: &[TargetCommandRecord]) -> String {
    if targets.is_empty() {
        return COMMAND_STATE_VALIDATED.to_string();
    }
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut non_terminal = 0usize;
    let mut leased = false;
    for target in targets {
        match target.state.as_str() {
            TARGET_STATE_SUCCEEDED => succeeded += 1,
            TARGET_STATE_FAILED | TARGET_STATE_EXPIRED | TARGET_STATE_REJECTED => failed += 1,
            TARGET_STATE_CANCELLED => {}
            TARGET_STATE_LEASED => {
                leased = true;
                non_terminal += 1;
            }
            _ => non_terminal += 1,
        }
    }
    if non_terminal > 0 {
        return if leased {
            COMMAND_STATE_LEASED.to_string()
        } else {
            COMMAND_STATE_QUEUED.to_string()
        };
    }
    if failed == 0 {
        COMMAND_STATE_SUCCEEDED.to_string()
    } else if succeeded == 0 {
        COMMAND_STATE_FAILED.to_string()
    } else {
        COMMAND_STATE_PARTIAL.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: &str, state: &str) -> TargetCommandRecord {
        let now = DateTime::now();
        TargetCommandRecord {
            target_command_id: format!("tcmd-{id}"),
            command_id: "cmd-1".to_string(),
            target_id: id.to_string(),
            gateway_id: id.to_string(),
            wire_kind: "diagnose".to_string(),
            state: state.to_string(),
            attempts: 1,
            result_status: None,
            result_error: None,
            result_body: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[test]
    fn aggregate_follows_the_documented_rules() {
        assert_eq!(aggregate_state(&[]), COMMAND_STATE_VALIDATED);
        assert_eq!(
            aggregate_state(&[target("a", TARGET_STATE_SUCCEEDED)]),
            COMMAND_STATE_SUCCEEDED
        );
        assert_eq!(
            aggregate_state(&[
                target("a", TARGET_STATE_SUCCEEDED),
                target("b", TARGET_STATE_FAILED)
            ]),
            COMMAND_STATE_PARTIAL
        );
        assert_eq!(
            aggregate_state(&[
                target("a", TARGET_STATE_FAILED),
                target("b", TARGET_STATE_EXPIRED)
            ]),
            COMMAND_STATE_FAILED
        );
        assert_eq!(
            aggregate_state(&[
                target("a", TARGET_STATE_SUCCEEDED),
                target("b", TARGET_STATE_QUEUED)
            ]),
            COMMAND_STATE_QUEUED
        );
        assert_eq!(
            aggregate_state(&[
                target("a", TARGET_STATE_SUCCEEDED),
                target("b", TARGET_STATE_LEASED)
            ]),
            COMMAND_STATE_LEASED
        );
    }
}
