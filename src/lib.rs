// @jumo generated
// WarpInsightCenter 上级聚合控制中心（子系统实现）

pub use wist_control::*;

pub mod api;
pub mod config;
pub mod infra;
// NOTE(hand-added): 本进程运行日志（`[log]` 段：级别 / 格式 / 文件+轮转）。
pub mod logging;

pub type AppError = wist_error::AppError;
