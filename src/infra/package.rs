//! 安装包内核：**薄适配**到共享 crate [`wist_release::package`]。
//!
//! 来源读取 / 摘要校验 / 身份解析 / 命名这套口径原先在本仓与
//! `wist-gateway/src/api/install_package.rs` **各写一份**（当时刻意重复）；现已收进
//! `wist-release`，中心与网关共用一份，避免漂移 —— 本模块只保留本仓用到的别名导出，
//! 让既有调用点（`crate::infra::read_verified_package` 等）与设计文档的引用继续成立。
//!
//! 本仓自己的**存储 / 端点 / 鉴权 / 来源策略**（`admin_ops::admin_publish_release`、
//! `infra::artifacts`）仍留在本仓，不进共享 crate。

pub use wist_release::package::{
    MAX_PACKAGE_BYTES, PackageError, PlatformFamily, ReleaseArtifact, ReleasePackage,
    artifact_filename, is_safe_path_segment, missing_platforms, normalize_platform,
    normalize_version, package_id_for_sha256, platform_family, read_package_identity,
    read_source as read_package_source, read_verified_source as read_verified_package,
    validate_platforms,
};
