// 手写的 OpenAPI 文档是一个大 `json!` 字面量：`json!` 按条目递归展开，条目一多就会撞到
// 默认的 128 层宏展开上限（编译期深度，不影响运行时）。给到 256 留出加接口的余地。
#![recursion_limit = "256"]

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
