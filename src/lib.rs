// @jumo generated
// WarpInsightCenter 上级聚合控制中心（子系统实现）

pub use wist_control::*;

pub mod api;
pub mod config;
pub mod infra;
// NOTE(hand-added): 本进程运行日志（`[log]` 段）已抽到共享 crate `wist-log`（见 config 里的 `wist_log::LogSection`）。

pub type AppError = wist_error::AppError;
