// @jumo generated
// WistCenter 上级聚合控制中心（子系统实现）

pub use wist_control::*;

pub mod api;
pub mod config;
/// 程序访问凭据（`wist-cred` 验证方）：接收摘要 + 管理面 token 校验。
pub mod credentials;
pub mod infra;
pub mod wparse_proxy;
// NOTE(hand-added): 本进程运行日志（`[log]` 段）已抽到共享 crate `wist-log`（见 config 里的 `wist_log::LogSection`）。

pub type AppError = wist_error::AppError;
