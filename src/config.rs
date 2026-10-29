// WistCenter 运行配置（配置文件 + 环境变量，参考 wist-gateway）。
//
// 加载顺序（后者覆盖前者）：
//   1. 配置文件（默认**当前目录**的 wist-center.toml，可用 WIST_CENTER_CONFIG 指定）；
//      文件不存在则跳过这一层 —— 零配置也能跑（纯 env + 内置默认值）。
//      它是**可重渲的交付物**；站点现场事实（`[server] public_url`）另在**现场态**配置里
//      （`wist-center-pub.toml`，或 WIST_CENTER_PUB_CONFIG 指定），两份合并、**叶子键重复即拒**。
//   2. 环境变量 WARP_INSIGHT_CENTER_*（沿用既有契约）。
//   3. 代码内置默认值。
//
// 配置文件里可以写 ${VAR} / ${VAR:default} 从环境变量取值（该变量未设置且无默认值会报错）；密钥类
// 值（admin_token / hmac_secret）推荐写 ${SEC_...}，由 orion-sec 从密钥文件解析（见 SEC_FILE_ENV）。
// 相对路径（store.store_path / artifacts.dir / security.ca_cert_path）按配置文件所在目录解析。

use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
};

use orion_error::conversion::ToStructError;
use orion_sec::sec::NoSecConv;
use orion_sec::{SecFileFmt, load_sec_dict, load_secfile_by};
use orion_variate::vars::{EnvChecker, EnvDict, EnvEvaluable, ValueType};
use serde::Deserialize;
use wist_error::{ConfigError, ConfigReason};

use crate::infra::sha256_hex;

/// 默认配置文件名（相对**当前工作目录**；不再有 `~/.wist-center/` 这个隐藏默认）。
const CONFIG_FILE: &str = "wist-center.toml";
/// 指向配置文件的 env（未设置/为空 → 用 default_config_path）。
const CONFIG_ENV: &str = "WIST_CENTER_CONFIG";
/// 显式指定密钥文件（**绝对路径**）；未设则用 orion 默认
/// `./.galaxy/sec_value.yml` → `~/.galaxy/sec_value.yml`。
const SEC_FILE_ENV: &str = "WIST_CENTER_SEC_FILE";

/// 指向**现场态声明**的 env：显式设了就用它（相对路径按主配置目录解析）；
/// 未设则取**主配置同目录**的约定文件名（存在才用）。
const PUB_CONFIG_ENV: &str = "WIST_CENTER_PUB_CONFIG";
/// 现场态**声明**的约定文件名：只写 `${VAR}` 引用，**不含现场值**（⇒ 可入库、可重渲）。
const PUB_CONFIG_FILE_NAME: &str = "wist-center-pub.toml";
/// 现场态**值**文件名：与声明同目录（docker-compose 的 `.env` 口径）。
const PUB_ENV_FILE_NAME: &str = ".env";
/// 指向现场态 `.env` 的 env（`--env-file` 对应物，相对声明目录）。
const PUB_ENV_FILE_ENV: &str = "WIST_CENTER_ENV_FILE";

/// 本组件的「分层配置」约定 —— 交给共享 crate `wist-config` 干活
/// （主配置 + 现场态声明 `${VAR}` 插值 + 同目录 `.env`）。
const LAYER: wist_config::LayerSpec = wist_config::LayerSpec {
    overlay_file: PUB_CONFIG_FILE_NAME,
    overlay_env: PUB_CONFIG_ENV,
    values_file: PUB_ENV_FILE_NAME,
    values_env: PUB_ENV_FILE_ENV,
};

const DEFAULT_LISTEN: &str = "127.0.0.1:3100";
const DEFAULT_STORE_PATH: &str = "state/warp-insight-center-store.json";
const ENV_LISTEN: &str = "WARP_INSIGHT_CENTER_LISTEN";
const ENV_ADMIN_ADDR: &str = "WARP_INSIGHT_CENTER_ADMIN_ADDR";
const ENV_STORE_PATH: &str = "WARP_INSIGHT_CENTER_STORE_PATH";
const ENV_GATEWAY_CREDENTIALS: &str = "WARP_INSIGHT_CENTER_GATEWAY_CREDENTIALS";
const ENV_DATABASE_URL: &str = "WARP_INSIGHT_CENTER_DATABASE_URL";
const ENV_VICTORIAMETRICS_URL: &str = "WARP_INSIGHT_CENTER_VICTORIAMETRICS_URL";
const ENV_PUBLIC_URL: &str = "WARP_INSIGHT_CENTER_PUBLIC_URL";
const ENV_GATEWAY_IMAGE: &str = "WARP_INSIGHT_CENTER_GATEWAY_IMAGE";
const ENV_GATEWAY_PROJECT_REPO: &str = "WARP_INSIGHT_CENTER_GATEWAY_PROJECT_REPO";
const ENV_ARTIFACT_DIR: &str = "WARP_INSIGHT_CENTER_ARTIFACT_DIR";
const ENV_OBJECT_STORAGE_ENDPOINT: &str = "WARP_INSIGHT_CENTER_OBJECT_STORAGE_ENDPOINT";
const ENV_OBJECT_STORAGE_BUCKET: &str = "WARP_INSIGHT_CENTER_OBJECT_STORAGE_BUCKET";
const ENV_OBJECT_STORAGE_ACCESS_KEY: &str = "WARP_INSIGHT_CENTER_OBJECT_STORAGE_ACCESS_KEY";
const ENV_OBJECT_STORAGE_SECRET_KEY: &str = "WARP_INSIGHT_CENTER_OBJECT_STORAGE_SECRET_KEY";
const ENV_CA_CERT_PATH: &str = "WARP_INSIGHT_CENTER_CA_CERT_PATH";
const ENV_SERVER_CERT_PATH: &str = "WARP_INSIGHT_CENTER_SERVER_CERT_PATH";
const ENV_SERVER_KEY_PATH: &str = "WARP_INSIGHT_CENTER_SERVER_KEY_PATH";
const ENV_PROTOCOL_VERSION: &str = "WARP_INSIGHT_CENTER_PROTOCOL_VERSION";
const ENV_HMAC_SECRET: &str = "WARP_INSIGHT_CENTER_HMAC_SECRET";
const ENV_CREDENTIAL_TTL_SECONDS: &str = "WARP_INSIGHT_CENTER_CREDENTIAL_TTL_SECONDS";
const ENV_LINK_TTL_SECONDS: &str = "WARP_INSIGHT_CENTER_LINK_TTL_SECONDS";

/// 默认对外地址使用域名（初始化 URL / 控制中心端点需要可被 Gateway 从外网访问）。
const DEFAULT_PUBLIC_URL: &str = "https://center.warpinsight.example";
const DEFAULT_GATEWAY_IMAGE: &str = "wist-gateway:latest";
/// 网关部署工程（ops-prj）模板仓库：`install-all` 脚本 clone 它来落工程（不再用 `gops prj new`）。
/// 部署栈里由 vars 的 `GATEWAY_PRJ_TPL_REPO` 渲染进 `[artifacts] gateway_project_repo`。
const DEFAULT_GATEWAY_PROJECT_REPO: &str = "https://wgc-git.beta.jingang.cloud/gateway-tx.git";
const DEFAULT_ARTIFACT_DIR: &str = "artifacts";
/// 网关 ↔ 中心 wire 协议版本（写入网关 config.toml 的 [protocol] version）。
const DEFAULT_PROTOCOL_VERSION: &str = "1.0";
/// 仅开发态兜底：未配置 hmac_secret 时用它派生注册凭据（生产必须显式配置）。
const DEV_HMAC_SECRET: &str = "dev-center-hmac-secret-change-me";
const DEFAULT_CREDENTIAL_TTL_SECONDS: i64 = 30 * 24 * 3600;
/// 一次性接入券（link）的**短 TTL** 默认值：15 分钟（带外交付 + 现场执行的短窗口）。
const DEFAULT_LINK_TTL_SECONDS: i64 = 15 * 60;
/// 规则发布 tag 列表缓存默认值（秒）。
const DEFAULT_TAG_CACHE_SECONDS: u64 = 60;
/// 规则发布单次扇出网关数上限。
const DEFAULT_MAX_TARGETS: usize = 20;
/// 单次列 tag 的默认上限 / 硬上限。
const DEFAULT_TAGS_LIMIT: usize = 100;
const MAX_TAGS_LIMIT: usize = 200;

#[derive(Debug, Clone)]
pub struct CenterConfig {
    /// 网关面监听地址（**公网**）：只挂 `/api/v1/gateway/**` + `/api/v1/version`，mTLS。
    pub listen_addr: String,
    /// 管理面监听地址（**内网**）：只挂 `/api/v1/admin/**` + `/api/v1/version`，不校客户端证书。
    /// 缺省（`None`）= 不拆监听器（两者共用 `listen_addr`），保留旧行为。
    pub admin_addr: Option<String>,
    pub store_path: PathBuf,
    /// 服务端 TLS 证书/私钥（PEM）。**两者都配** → 起 HTTPS（服务器证书 = CA-S 签）并
    /// 校网关客户端证书（CA-G）；**都未配** → 明文 HTTP（dev / 反代兑底）。来源：
    /// `server.server_cert_path`/`server.server_key_path` 或
    /// `WARP_INSIGHT_CENTER_SERVER_CERT_PATH`/`_KEY_PATH`（必须成对配）。
    pub server_cert_path: Option<PathBuf>,
    pub server_key_path: Option<PathBuf>,
    /// seed 网关凭证：gateway_id:token 列表，启动时写入 store（缺失才写）。
    pub gateway_credentials: Vec<GatewayCredentialSeed>,
    /// 管理面 token hash（读取接口迭代用，本次未启用）。
    pub admin_token_hash: Option<String>,
    /// 开发期 PG 连接串：有值 → PgStore；未设置/为空 → FileStore。
    /// 推荐值即 compose 的 `postgres://demo:demo@127.0.0.1:55432/insight_demo`。
    pub database_url: Option<String>,
    /// 时序历史 VictoriaMetrics 基地址（如 compose 的 `http://127.0.0.1:8428`）。
    /// 有值 → 每次状态上报额外推送指标；未设置/为空 → 不启用（仅存快照）。
    pub victoriametrics_url: Option<String>,
    /// center 对外地址（生成网关初始化 URL），默认 `https://center.warpinsight.example`。
    /// **现场态**：声明在 `<主配置同目录>/wist-center-pub.toml`（或 `WIST_CENTER_PUB_CONFIG` 指定的
    /// 路径）的 `[server] public_url`，它是一个 `${VAR}` 引用；真值来自「进程环境 > 同目录 `.env`」
    /// （`.env` 落点可用 `WIST_CENTER_ENV_FILE` 指定）。`WARP_INSIGHT_CENTER_PUBLIC_URL`（env）优先。
    /// 注意：该主机名/IP 必须落在控制中心服务器证书的 SAN 内，否则 server_tls_required=true 时
    /// 网关对 init_url 的 TLS 主机名校验会失败。
    pub public_url: String,
    /// gateway 镜像名（docker 安装命令 / 云镜像地址），默认 `wist-gateway:latest`。
    pub gateway_image: String,
    /// gateway 部署工程（ops-prj）模板仓库：`install-all` 脚本 clone 它来落工程
    /// （替代早先的 `gops prj new` 现生成）。工程自带 `ops-prj.yml` 与 `values/<系统名>/sys_value.yml`。
    /// 来源：`[artifacts] gateway_project_repo` 或 env `WARP_INSIGHT_CENTER_GATEWAY_PROJECT_REPO`；
    /// 部署栈里该键由 vars 的 `GATEWAY_PRJ_TPL_REPO` 渲染（现场可在 `sys_value.yml` 覆盖）。
    pub gateway_project_repo: String,
    /// 本地制品目录（版本发布镜像制品落盘），默认 `artifacts/`。
    pub artifact_dir: PathBuf,
    /// 云对象存储（可选，S3 兼容 / MinIO）；配置了 endpoint 则发布制品存对象存储，否则本地。
    pub object_storage: Option<ObjectStorageConfig>,
    /// 安装包来源（`[packages.sources]`）：录入页据此把「版本号」拼成 GitHub Release 地址 / COS 路径，
    /// 做 URL 探测后一键填充。只存**位置**，不存凭据（COS 制品牌公有读）。
    pub package_sources: Vec<PackageSourceConfig>,
    /// 控制中心 CA 证书内容（control-center.pem，信任根）——分发给 Gateway 作为
    /// control_center.trust_bundle。来源：配置文件的 `security.ca_cert_path` 或
    /// `WARP_INSIGHT_CENTER_CA_CERT_PATH`，默认 `<配置目录>/ca/control-center.pem`；
    /// 文件不存在 → None。
    pub ca_cert: Option<String>,
    /// 网关↔中心 wire 协议版本（config.toml [protocol] version）。
    pub protocol_version: String,
    /// RegistToken 派生密钥（HMAC-SHA256）：由网关身份 Token 派生注册凭据。
    /// 派生后中心只存结果 hash、不重算，故轮换该密钥不影响既有凭据校验；
    /// 生产必须配置（配置文件的 `security.hmac_secret` 或 `WARP_INSIGHT_CENTER_HMAC_SECRET`）。
    pub hmac_secret: String,
    /// 网关**客户端证书**有效期秒数（register / renew 签出证书的 TTL）。
    /// env：`WARP_INSIGHT_CENTER_CREDENTIAL_TTL_SECONDS`。
    pub credential_ttl_seconds: i64,
    /// 一次性接入券（link）的**短 TTL**（秒）：过期即不可用，需重新「生成/轮换」。
    /// 来源：配置文件的 `security.link_ttl_seconds` 或
    /// env：`WARP_INSIGHT_CENTER_LINK_TTL_SECONDS`。默认 15 分钟。
    pub link_ttl_seconds: i64,
    /// 规则发布兼容入口（WarpStation 设备面）：独立 HTTPS listener + 命令队列。
    /// 见设计文档 §6；需要 `database_url`（FileStore 模式下自动禁用）。
    pub wparse_proxy: WparseProxyConfig,
    /// 规则 / 配置发布入口（`[wparse_release]`）：两个可配置 repo 的 tag 候选与发布。
    pub wparse_release: WparseReleaseConfig,
    /// `[log]` 段：本进程运行日志（级别 / 格式 / 落点 / 轮转）。
    pub log: wist_log::LogSection,
}

/// 规则 / 配置发布入口配置（`[wparse_release]`）。
///
/// 与 [`WparseProxyConfig`] 分开：tag 列表是只读能力，proxy 关闭时仍可展示候选；
/// 真正发布才要求 `[wparse_proxy].enabled = true` 且 `[store].database_url` 可用。
#[derive(Debug, Clone)]
pub struct WparseReleaseConfig {
    pub enabled: bool,
    /// tag 列表缓存秒数（`0` 视为非法，配置解析时拒绝）。
    pub tag_cache_seconds: u64,
    /// 是否允许绕过 tag 列表手填（默认关闭：优先从候选里选）。
    pub allow_manual_tag: bool,
    /// 单次发布最多扇出多少台网关。
    pub max_targets: usize,
    pub repos: Vec<WparseRepoConfig>,
}

impl Default for WparseReleaseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tag_cache_seconds: DEFAULT_TAG_CACHE_SECONDS,
            allow_manual_tag: false,
            max_targets: DEFAULT_MAX_TARGETS,
            repos: Vec::new(),
        }
    }
}

/// tag 来源类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagProviderKind {
    /// CNB OpenAPI（`https://api.cnb.cool/{repo}/-/git/tags`）。
    Cnb,
    /// GitHub REST API（`https://api.github.com/repos/{owner}/{repo}/tags`）。
    Github,
    /// 不联网：页面只提供手填（需要 `allow_manual_tag = true`）。
    Manual,
}

impl TagProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cnb => "cnb",
            Self::Github => "github",
            Self::Manual => "manual",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "cnb" => Some(Self::Cnb),
            "github" => Some(Self::Github),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// 一个可发布 repo 的配置。
#[derive(Clone)]
pub struct WparseRepoConfig {
    /// 入口名（路由段 / 前端标识）；固定用 `wparse-rules` / `wparse-infra`。
    pub name: String,
    /// reload 的 group：`models` / `infra`。
    pub group: String,
    pub provider: TagProviderKind,
    /// provider 原生标识：CNB 是 `group/.../repo`，GitHub 是 `owner/repo`。
    pub repo: String,
    /// 只读 token（CNB 需要 `repo-release:r`）；不返回给前端、不写日志。
    pub token: Option<String>,
    /// 单次列 tag 的上限（1..=200）。
    pub tags_limit: usize,
}

impl std::fmt::Debug for WparseRepoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WparseRepoConfig")
            .field("name", &self.name)
            .field("group", &self.group)
            .field("provider", &self.provider)
            .field("repo", &self.repo)
            .field("token", &self.token.as_ref().map(|_| "***"))
            .field("tags_limit", &self.tags_limit)
            .finish()
    }
}

/// 规则发布兼容入口配置（`[wparse_proxy]`）。
#[derive(Debug, Clone)]
pub struct WparseProxyConfig {
    pub enabled: bool,
    /// 容器内监听地址；默认 `0.0.0.0:3101`（与 compose 的 `${WPARSE_PROXY_PORT}:3101` 对应）。
    pub listen_addr: String,
}

/// S3 兼容对象存储配置（MinIO 等）。
#[derive(Debug, Clone)]
pub struct ObjectStorageConfig {
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

/// 一个安装包组件的来源位置：`component` 与 `/api/v1/admin/releases/:component` 的路径段一致。
///
/// 录入页只让操作者填**版本号**：GitHub 源拼 `https://github.com/<repo>/releases/tag/<version>`，
/// COS 源拼 `<bucket>/<prefix>/<version>`，再走既有的解析接口做 URL 探测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSourceConfig {
    pub component: String,
    /// `owner/repo`（也接受 `https://github.com/owner/repo`）。
    pub github_repo: Option<String>,
    pub cos_bucket: Option<String>,
    /// 默认取 `github_repo` 的末段（仓库名）。
    pub cos_prefix: Option<String>,
    /// 虚拟主机下载地址里能读出 region 时可留空；留空则解析器按候选区逐个探测。
    pub cos_region: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GatewayCredentialSeed {
    pub gateway_id: String,
    pub token: String,
    pub expires_at: Option<String>,
}

fn config_validation(message: impl Into<String>) -> ConfigError {
    ConfigReason::Validation.to_err().with_detail(message)
}

fn config_io(message: impl Into<String>) -> ConfigError {
    ConfigReason::Io.to_err().with_detail(message)
}

fn config_parse(message: impl Into<String>) -> ConfigError {
    ConfigReason::Parse.to_err().with_detail(message)
}

/// 配置文件的原始文档：字段全是 Option，缺字段即"未配置"，由 from_raw 落到默认值。
/// 每个段都可整段省略（`#[serde(default)]`）。
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawCenterConfig {
    server: RawServerConfig,
    store: RawStoreConfig,
    telemetry: RawTelemetryConfig,
    security: RawSecurityConfig,
    artifacts: RawArtifactsConfig,
    packages: RawPackagesConfig,
    enrollment: RawEnrollmentConfig,
    wparse_proxy: RawWparseProxyConfig,
    wparse_release: RawWparseReleaseConfig,
    log: wist_log::LogSection,
}

#[derive(Debug, Default, Deserialize)]
struct RawServerConfig {
    listen_addr: Option<String>,
    admin_addr: Option<String>,
    public_url: Option<String>,
    protocol_version: Option<String>,
    admin_token: Option<String>,
    server_cert_path: Option<String>,
    server_key_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawStoreConfig {
    database_url: Option<String>,
    store_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawTelemetryConfig {
    victoriametrics_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawSecurityConfig {
    hmac_secret: Option<String>,
    credential_ttl_seconds: Option<i64>,
    link_ttl_seconds: Option<i64>,
    ca_cert_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawArtifactsConfig {
    dir: Option<String>,
    gateway_image: Option<String>,
    gateway_project_repo: Option<String>,
    object_storage_endpoint: Option<String>,
    object_storage_bucket: Option<String>,
    object_storage_access_key: Option<String>,
    object_storage_secret_key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawPackagesConfig {
    #[serde(default)]
    sources: Vec<RawPackageSource>,
}

#[derive(Debug, Default, Deserialize)]
struct RawPackageSource {
    component: String,
    github_repo: Option<String>,
    cos_bucket: Option<String>,
    cos_prefix: Option<String>,
    cos_region: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawEnrollmentConfig {
    /// 每项 `gateway_id:token`；串成逗号列表后复用 parse_gateway_credentials。
    gateway_credentials: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawWparseProxyConfig {
    enabled: Option<bool>,
    listen_addr: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawWparseReleaseConfig {
    enabled: Option<bool>,
    tag_cache_seconds: Option<u64>,
    allow_manual_tag: Option<bool>,
    max_targets: Option<usize>,
    #[serde(default)]
    repos: Vec<RawWparseRepo>,
}

#[derive(Debug, Default, Deserialize)]
struct RawWparseRepo {
    name: String,
    group: String,
    provider: String,
    repo: String,
    token: Option<String>,
    tags_limit: Option<usize>,
}

/// 默认配置文件路径：**当前工作目录**下的 `wist-center.toml`（与 gateway 同口径）。
/// 不再有 `~/.wist-center/` 这个隐藏默认 —— 路径一律由调用方 / `WIST_CENTER_CONFIG` 显式给出。
pub fn default_config_path() -> PathBuf {
    PathBuf::from(CONFIG_FILE)
}

/// 本次启动实际读取的配置文件路径（`WIST_CENTER_CONFIG` 优先，否则默认路径）。
/// 入口用它打印"配置从哪来"，避免"改了半天没生效"的困惑。
pub fn resolved_config_path() -> PathBuf {
    match env::var(CONFIG_ENV) {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => default_config_path(),
    }
}

/// 现场态**声明**的落点（供 `init-config` / 诊断定位）。
pub fn pub_config_path(config_path: &Path) -> PathBuf {
    wist_config::overlay_path(config_path, &LAYER)
}

/// 现场态**值**（`.env`）的落点（供 `init-config` 定位）。
pub fn pub_env_path(config_path: &Path) -> PathBuf {
    wist_config::values_path(&pub_config_path(config_path), &LAYER)
}

/// 由仓库内模板（wist-center.toml）渲染默认配置文本：把两个 ${...} 占位符替换成
/// 新生成的随机值，保证 `init-config` 产出的配置不含可预测/共享的默认凭据。
/// 模板是生成配置形状的唯一来源 —— 改模板即改生成结果。
pub fn default_config_text(admin_token: &str, hmac_secret: &str) -> String {
    include_str!("../wist-center.toml")
        .replace("${WIST_CENTER_ADMIN_TOKEN}", admin_token)
        .replace("${WIST_CENTER_HMAC_SECRET}", hmac_secret)
}

/// `wist-center init-config` 一并写出的默认**现场态声明**文本（`wist-center-pub.toml` 骶架）：
/// 只有 `${VAR}` 引用、**不含现场值**（真值在同目录 `.env`）。
pub fn default_pub_config_text() -> String {
    DEFAULT_PUB_CONFIG_TEMPLATE.to_string()
}

/// `wist-center init-config` 一并写出的默认**现场态值**文本（`.env` 骶架）。
///
/// 声明里的 `${VAR}` 是 fail-closed 的（未定义即拒启）—— 先把变量名摆上、值留空，
/// 现场就有一个明确要填的文件，而不会「一启动就报未定义」。
pub fn default_env_text() -> String {
    DEFAULT_ENV_TEMPLATE.to_string()
}

/// 默认**现场态声明**骶架（由 [`default_pub_config_text`] 返回）。
const DEFAULT_PUB_CONFIG_TEMPLATE: &str = r#"# wist-center 现场态**声明** —— 只写 `${VAR}` 引用，**不含现场值**。
#
# 本文件是**模板**：由栈侧 tpl 机制（或 `init-config`）生成到 `wist-center-pub.toml`；
# 与其它交付物同一套渲染（重渲 / 升级动不到现场，因为值不在这里）。
# 真值在同目录的 `.env`（docker-compose 口径：`.env` 挨着本文件；**进程环境优先**）。
# `${VAR}` 未定义且没给 `:-默认值` → 中心拒启（fail-closed）。

[server]
# 中心对外地址：用于生成网关初始化 URL，必须落在控制中心服务器证书的 SAN 内。
public_url = "${CENTER_PUBLIC_URL:-https://center.warpinsight.example}"
"#;

/// 默认**现场态值**骶架（由 [`default_env_text`] 返回）。
const DEFAULT_ENV_TEMPLATE: &str = r#"# wist-center 现场态**值** —— 与同目录 wist-center-pub.toml 里的 ${VAR} 一一对应。
# 由 `init-config` / 栈侧 `scripts/init-center-pub.sh` 按缺写入；升级 / 重渲不动它。

CENTER_PUBLIC_URL=
"#;

impl CenterConfig {
    /// 读 resolved_config_path()：文件缺失/字段缺失时回落到环境变量与内置默认值。
    pub fn load_from_env() -> Result<Self, ConfigError> {
        Self::load_from_path(resolved_config_path())
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config_path = absolutize_config_path(path.as_ref())?;
        // 主配置 + 现场态**声明**（`${VAR}` 插值自「进程环境 > 同目录 `.env`」）+ 无重复叶子合并，
        // 全部交给共享 crate `wist-config`（与 gateway / gwlinkd 同一套口径）。
        // 主配置缺失仍可跑（零配置：纯 env + 内置默认值）。
        let doc: toml::Value = if config_path.is_file() {
            wist_config::load_layered_toml(&config_path, &LAYER)?
        } else {
            toml::Value::Table(Default::default())
        };
        let mut raw: RawCenterConfig = doc.try_into().map_err(|err| {
            config_parse(format!(
                "failed to parse config {}: {err}",
                config_path.display()
            ))
        })?;
        // 先展开文件里的 ${VAR}（含密钥文件里的 ${SEC_...}），再让 env 覆盖（env 的值是字面量，不再二次展开）。
        let env = secret_dict()?;
        expand_raw_env(&mut raw, &env)?;
        apply_env_overrides(&mut raw);
        let config_dir = config_path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let config = Self::from_raw(raw, config_dir)?;
        config.validate()?;
        Ok(config)
    }

    /// 纯解析：不做任何 env 访问（env 展开/覆盖已在调用方完成）。
    fn from_raw(raw: RawCenterConfig, config_dir: &Path) -> Result<Self, ConfigError> {
        let serve = raw.server;
        let store = raw.store;
        let security = raw.security;
        let artifacts = raw.artifacts;
        let package_sources = normalize_package_sources(raw.packages.sources)?;
        let wparse_release = normalize_wparse_release(raw.wparse_release)?;
        let admin_token = normalize_optional(serve.admin_token);
        // 对象存储：endpoint/bucket/凭据四项齐全才启用（否则用本地文件）。
        let object_storage = match (
            normalize_optional(artifacts.object_storage_endpoint),
            normalize_optional(artifacts.object_storage_bucket),
            normalize_optional(artifacts.object_storage_access_key),
            normalize_optional(artifacts.object_storage_secret_key),
        ) {
            (Some(endpoint), Some(bucket), Some(access_key), Some(secret_key)) => {
                Some(ObjectStorageConfig {
                    endpoint,
                    bucket,
                    access_key,
                    secret_key,
                })
            }
            _ => None,
        };
        // 信任根：显式配置的证书路径（按配置目录解析）→ 默认 <配置目录>/ca/control-center.pem；
        // 文件读不到 → None（不阻断启动，只是不向网关分发信任根）。
        let ca_cert_path = normalize_optional(security.ca_cert_path)
            .map(|path| absolutize_path(config_dir, Path::new(&path)))
            .unwrap_or_else(|| default_ca_cert_path(config_dir));
        // 运行日志：`[log] file` 的相对路径按**配置文件所在目录**解析（与 wist-gateway / wist-gwlinkd 同口径）。
        let mut log = raw.log;
        if let Some(file) = log.file.take() {
            log.file = Some(absolutize_path(config_dir, &file));
        }
        // 服务端 TLS：成对配（validate 会卡住只配一半）；相对路径按配置目录解析。
        let server_cert_path = normalize_optional(serve.server_cert_path)
            .map(|path| absolutize_path(config_dir, Path::new(&path)));
        let server_key_path = normalize_optional(serve.server_key_path)
            .map(|path| absolutize_path(config_dir, Path::new(&path)));
        Ok(Self {
            listen_addr: serve
                .listen_addr
                .unwrap_or_else(|| DEFAULT_LISTEN.to_string()),
            admin_addr: normalize_optional(serve.admin_addr),
            server_cert_path,
            server_key_path,
            store_path: absolutize_path(
                config_dir,
                Path::new(
                    &store
                        .store_path
                        .unwrap_or_else(|| DEFAULT_STORE_PATH.to_string()),
                ),
            ),
            gateway_credentials: parse_gateway_credentials(
                &raw.enrollment.gateway_credentials.join(","),
            )?,
            admin_token_hash: admin_token.as_deref().map(sha256_hex),
            database_url: normalize_optional(store.database_url),
            victoriametrics_url: normalize_optional(raw.telemetry.victoriametrics_url)
                .map(trim_trailing_slash),
            public_url: trim_trailing_slash(
                serve
                    .public_url
                    .unwrap_or_else(|| DEFAULT_PUBLIC_URL.to_string()),
            ),
            gateway_image: artifacts
                .gateway_image
                .unwrap_or_else(|| DEFAULT_GATEWAY_IMAGE.to_string()),
            gateway_project_repo: normalize_optional(artifacts.gateway_project_repo)
                .unwrap_or_else(|| DEFAULT_GATEWAY_PROJECT_REPO.to_string()),
            artifact_dir: absolutize_path(
                config_dir,
                Path::new(
                    &artifacts
                        .dir
                        .unwrap_or_else(|| DEFAULT_ARTIFACT_DIR.to_string()),
                ),
            ),
            object_storage,
            package_sources,
            ca_cert: fs::read_to_string(&ca_cert_path).ok(),
            protocol_version: serve
                .protocol_version
                .unwrap_or_else(|| DEFAULT_PROTOCOL_VERSION.to_string()),
            hmac_secret: security
                .hmac_secret
                .unwrap_or_else(|| DEV_HMAC_SECRET.to_string()),
            credential_ttl_seconds: security
                .credential_ttl_seconds
                .unwrap_or(DEFAULT_CREDENTIAL_TTL_SECONDS),
            link_ttl_seconds: security
                .link_ttl_seconds
                .unwrap_or(DEFAULT_LINK_TTL_SECONDS),
            wparse_proxy: WparseProxyConfig {
                enabled: raw.wparse_proxy.enabled.unwrap_or(false),
                listen_addr: raw
                    .wparse_proxy
                    .listen_addr
                    .unwrap_or_else(|| "0.0.0.0:3101".to_string()),
            },
            wparse_release,
            log,
        })
    }

    fn validate(&self) -> Result<(), ConfigError> {
        require_non_empty("server.listen_addr", &self.listen_addr)?;
        // 管理面监听器：配了就不得与网关面重叠（同一个端口无法绑定两次）。
        // 只校验形式；真正的“公网/内网”由部署侧的 bind IP 与防火墙决定。
        if let Some(admin) = self.admin_addr.as_deref() {
            require_non_empty("server.admin_addr", admin)?;
            if admin.trim() == self.listen_addr.trim() {
                return Err(config_validation(
                    "server.admin_addr must differ from server.listen_addr",
                ));
            }
        };
        require_non_empty("server.public_url", &self.public_url)?;
        require_non_empty("server.protocol_version", &self.protocol_version)?;
        require_non_empty("security.hmac_secret", &self.hmac_secret)?;
        require_positive_seconds(
            "security.credential_ttl_seconds",
            self.credential_ttl_seconds,
        )?;
        require_positive_seconds("security.link_ttl_seconds", self.link_ttl_seconds)?;
        // 服务端 TLS：证书与私钥要么都配（起 HTTPS），要么都不配（明文 HTTP）；
        // 配了就要求文件可读（fail-fast，避免启到一半才握手失败）。
        match (&self.server_cert_path, &self.server_key_path) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(config_validation(
                    "server.server_cert_path and server.server_key_path must be set together",
                ));
            }
            (Some(cert), Some(key)) => {
                for (label, path) in [
                    ("server.server_cert_path", cert),
                    ("server.server_key_path", key),
                ] {
                    if !path.exists() {
                        return Err(config_validation(format!(
                            "{label} not found: {}",
                            path.display()
                        )));
                    }
                }
            }
            (None, None) => {}
        }
        Ok(())
    }
}

/// 默认控制中心 CA 证书路径（信任根，分发给网关作 control_center.trust_bundle）：
/// **配置目录**下的 `ca/control-center.pem`（相对配置目录解析，与其它相对路径同口径）。
fn default_ca_cert_path(config_dir: &Path) -> PathBuf {
    config_dir.join("ca").join("control-center.pem")
}

/// 网关客户端证书 CA（**CA-G**）私钥/证书路径。
///
/// 默认 **配置目录**下的 `ca/gateway-client-ca.{pem,key.pem}`（与 `control-center.pem` 同处）；
/// 可用 `WARP_INSIGHT_CENTER_GATEWAY_CLIENT_CA_CERT_PATH` / `..._KEY_PATH` 覆盖。
/// 与服务器证书的 CA（control-center.pem）**单开**。
///
/// `gateway_ca::load_or_create` 的语义：两文件都在 → **只读加载**；**都缺**才生成并写盘
/// （缺一不重生，以免换 CA 使已签证书失效）。所以把这对文件放进**只读**挂载（发布态
/// `identity/center/`）即可 —— 存在就读，不写。
pub fn resolved_gateway_client_ca_paths(config_path: &Path) -> (PathBuf, PathBuf) {
    let dir = config_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("ca");
    let cert = env::var("WARP_INSIGHT_CENTER_GATEWAY_CLIENT_CA_CERT_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("gateway-client-ca.pem"));
    let key = env::var("WARP_INSIGHT_CENTER_GATEWAY_CLIENT_CA_KEY_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("gateway-client-ca.key.pem"));
    (cert, key)
}

/// 展开文件里所有 `${VAR}` / `${VAR:default}`（查 [`secret_dict`] 变量表：env 优先，其次密钥文件）。
fn expand_raw_env(raw: &mut RawCenterConfig, env: &EnvDict) -> Result<(), ConfigError> {
    for value in [
        &mut raw.server.listen_addr,
        &mut raw.server.admin_addr,
        &mut raw.server.public_url,
        &mut raw.server.protocol_version,
        &mut raw.server.admin_token,
        &mut raw.store.database_url,
        &mut raw.store.store_path,
        &mut raw.telemetry.victoriametrics_url,
        &mut raw.security.hmac_secret,
        &mut raw.security.ca_cert_path,
        &mut raw.artifacts.dir,
        &mut raw.artifacts.gateway_image,
        &mut raw.artifacts.gateway_project_repo,
        &mut raw.artifacts.object_storage_endpoint,
        &mut raw.artifacts.object_storage_bucket,
        &mut raw.artifacts.object_storage_access_key,
        &mut raw.artifacts.object_storage_secret_key,
    ] {
        if let Some(text) = value.as_ref() {
            *value = Some(expand(env, text)?);
        }
    }
    // 规则发布入口：repo 与 token 都可能写成 `${VAR}`（token 通常是 `${SEC_...}`）。
    for repo in &mut raw.wparse_release.repos {
        repo.repo = expand(env, &repo.repo)?;
        if let Some(token) = repo.token.as_ref() {
            repo.token = Some(expand(env, token)?);
        }
    }
    Ok(())
}

/// 环境变量覆盖文件值（沿用既有 `WARP_INSIGHT_CENTER_*` 契约）。
/// 注：管理 token（`server.admin_token`）**不在**此列 —— 它只有一个来源：配置文件
/// （生产/栈里写 `${SEC_CENTER_ADMIN_TOKEN}`，由密钥文件解析），避免“文件与 env 两份值”不一致。
fn apply_env_overrides(raw: &mut RawCenterConfig) {
    // 标量：env 有值（非空白）才覆盖；env 置空视为"没给"，保留文件值。
    override_scalar(&mut raw.server.listen_addr, ENV_LISTEN);
    override_scalar(&mut raw.server.admin_addr, ENV_ADMIN_ADDR);
    override_scalar(&mut raw.server.public_url, ENV_PUBLIC_URL);
    override_scalar(&mut raw.server.protocol_version, ENV_PROTOCOL_VERSION);
    override_scalar(&mut raw.artifacts.gateway_image, ENV_GATEWAY_IMAGE);
    override_scalar(
        &mut raw.artifacts.gateway_project_repo,
        ENV_GATEWAY_PROJECT_REPO,
    );
    override_scalar(&mut raw.security.hmac_secret, ENV_HMAC_SECRET);
    override_scalar(&mut raw.security.ca_cert_path, ENV_CA_CERT_PATH);
    override_scalar(&mut raw.server.server_cert_path, ENV_SERVER_CERT_PATH);
    override_scalar(&mut raw.server.server_key_path, ENV_SERVER_KEY_PATH);
    override_optional(&mut raw.store.store_path, ENV_STORE_PATH);
    override_optional(&mut raw.artifacts.dir, ENV_ARTIFACT_DIR);
    // 开关：env **显式设过** 就覆盖 —— 置空即"明确关闭"（例如关掉 PG / 时序推送）。
    override_optional(&mut raw.store.database_url, ENV_DATABASE_URL);
    override_optional(
        &mut raw.telemetry.victoriametrics_url,
        ENV_VICTORIAMETRICS_URL,
    );
    override_optional(
        &mut raw.artifacts.object_storage_endpoint,
        ENV_OBJECT_STORAGE_ENDPOINT,
    );
    override_optional(
        &mut raw.artifacts.object_storage_bucket,
        ENV_OBJECT_STORAGE_BUCKET,
    );
    override_optional(
        &mut raw.artifacts.object_storage_access_key,
        ENV_OBJECT_STORAGE_ACCESS_KEY,
    );
    override_optional(
        &mut raw.artifacts.object_storage_secret_key,
        ENV_OBJECT_STORAGE_SECRET_KEY,
    );
    override_optional_i64(
        &mut raw.security.credential_ttl_seconds,
        ENV_CREDENTIAL_TTL_SECONDS,
    );
    override_optional_i64(&mut raw.security.link_ttl_seconds, ENV_LINK_TTL_SECONDS);
    // 种子凭据：env 非空白 → 整体替换文件里的列表。
    if let Some(raw_entries) = env_non_blank(ENV_GATEWAY_CREDENTIALS) {
        raw.enrollment.gateway_credentials = raw_entries
            .split(',')
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect();
    }
}

/// env 设置了且非空白 → 覆盖。
fn override_scalar(target: &mut Option<String>, key: &str) {
    if let Some(value) = env_non_blank(key) {
        *target = Some(value);
    }
}

/// env 设置了 → 覆盖（空白归一为 None，表示"明确关闭"）。
fn override_optional(target: &mut Option<String>, key: &str) {
    if let Ok(value) = env::var(key) {
        *target = normalize_optional(Some(value));
    }
}

/// 同 override_optional，但值需能解析成整数（不能解析则忽略，保留文件值）。
fn override_optional_i64(target: &mut Option<i64>, key: &str) {
    if let Ok(value) = env::var(key)
        && let Ok(parsed) = value.trim().parse::<i64>()
    {
        *target = Some(parsed);
    }
}

/// 读 env：未设置或纯空白 → None。
fn env_non_blank(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

fn absolutize_config_path(path: &Path) -> Result<PathBuf, ConfigError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = env::current_dir()
        .map_err(|err| config_io(format!("failed to resolve current dir: {err}")))?;
    Ok(cwd.join(path))
}

fn absolutize_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    base_dir.join(path)
}

/// 构建 `${VAR}` 展开用的变量表：**进程环境变量优先**，其下是密钥文件里的 `SEC_*`
/// （`WIST_CENTER_SEC_FILE` 指定，或 orion 默认 `.galaxy/sec_value.yml`）。变量表里查不到时
/// [`expand`] 再回落到系统环境变量（orion 内建）。
fn secret_dict() -> Result<EnvDict, ConfigError> {
    let mut dict = match env::var_os(SEC_FILE_ENV).filter(|path| !path.is_empty()) {
        Some(path) => load_sec_file(Path::new(&path))?,
        None => load_sec_dict()
            .map_err(|err| config_validation(format!("failed to load secrets: {err}")))?,
    };
    // 环境变量后写入 = 优先（`EnvDict` 查表优先于系统 env，故把 env 盖进去实现 env-first）。
    for (key, value) in env::vars() {
        dict.insert(key, ValueType::from(value.as_str()));
    }
    Ok(dict)
}

/// 从指定文件载入密钥表（`WIST_CENTER_SEC_FILE`，YAML；键自动规范成 `SEC_<UPPER>`）。
/// **显式指定的文件必须存在** —— 缺了就报清楚，别让下游只报「`SEC_xxx` 未解析」。
fn load_sec_file(path: &Path) -> Result<EnvDict, ConfigError> {
    if !path.exists() {
        return Err(config_validation(format!(
            "secrets file not found: {}（WIST_CENTER_SEC_FILE）",
            path.display()
        )));
    }
    let space = load_secfile_by(path.to_path_buf(), SecFileFmt::Yaml).map_err(|err| {
        config_validation(format!("failed to load secrets {}: {err}", path.display()))
    })?;
    let mut dict = EnvDict::new();
    for (key, value) in space.no_sec() {
        dict.insert(key, value);
    }
    Ok(dict)
}

/// 展开 `${VAR}` / `${VAR:default}`：先查 [`secret_dict`] 的变量表（env 优先），再回落系统环境变量。
/// **展开后仍含占位符 → 报错**（fail-closed）—— 绝不把未解析的 `${SEC_...}` 当字面值用。
fn expand(env: &EnvDict, value: &str) -> Result<String, ConfigError> {
    let expanded: String = value.to_string().env_eval(env);
    if expanded.needs_env_eval() {
        return Err(config_validation(format!(
            "unresolved environment variable(s) in {value:?}: {}",
            expanded.list_env_vars().join(", ")
        )));
    }
    Ok(expanded)
}

/// 归一化 `[packages.sources]`：组件唯一、GitHub 仓库写成 `owner/repo`、COS 前缀缺省取仓库名。
///
/// 这里只做**位置**校验（不联网、不碰凭据）：录入页拼出来的 URL 是否可用由解析接口现测。
fn normalize_package_sources(
    raw: Vec<RawPackageSource>,
) -> Result<Vec<PackageSourceConfig>, ConfigError> {
    let mut sources = Vec::with_capacity(raw.len());
    let mut seen = HashSet::new();
    for item in raw {
        let component = item.component.trim().to_string();
        if component.is_empty() || component.contains('/') {
            return Err(config_validation(
                "packages.sources[].component must be a single non-empty path segment",
            ));
        }
        if !seen.insert(component.clone()) {
            return Err(config_validation(format!(
                "packages.sources[].component duplicated: {component}"
            )));
        }
        let github_repo = normalize_optional(item.github_repo).map(|repo| {
            repo.strip_prefix("https://github.com/")
                .or_else(|| repo.strip_prefix("http://github.com/"))
                .or_else(|| repo.strip_prefix("github.com/"))
                .unwrap_or(&repo)
                .trim_end_matches('/')
                .trim_end_matches(".git")
                .to_string()
        });
        if let Some(repo) = &github_repo {
            let parts: Vec<&str> = repo.split('/').collect();
            if parts.len() != 2 || parts.iter().any(|part| part.is_empty()) {
                return Err(config_validation(format!(
                    "packages.sources[].github_repo must be `owner/repo`: {repo}"
                )));
            }
        }
        // bucket / region / prefix 都会拼进 `https://<bucket>.cos.<region>.myqcloud.com/<prefix>/...`。
        // 这些字段来自管理员配置，但仍然不应能改变 URL 的 host / 注入 query。
        let cos_bucket = normalize_optional(item.cos_bucket);
        if let Some(bucket) = &cos_bucket
            && (bucket.contains(['/', '@', ':']) || bucket.contains(char::is_whitespace))
        {
            return Err(config_validation(format!(
                "packages.sources[].cos_bucket must be a bare bucket name: {bucket}"
            )));
        }
        let cos_region = normalize_optional(item.cos_region);
        if let Some(region) = &cos_region
            && (region.contains(['/', '@', ':']) || region.contains(char::is_whitespace))
        {
            return Err(config_validation(format!(
                "packages.sources[].cos_region must be a bare region (e.g. ap-hongkong): {region}"
            )));
        }
        let cos_prefix = normalize_optional(item.cos_prefix)
            .map(|prefix| prefix.trim_matches('/').to_string())
            .filter(|prefix| !prefix.is_empty())
            .or_else(|| {
                github_repo
                    .as_deref()
                    .and_then(|repo| repo.rsplit('/').next())
                    .map(str::to_string)
            });
        if let Some(prefix) = &cos_prefix
            && prefix.contains(['?', '#'])
        {
            return Err(config_validation(format!(
                "packages.sources[].cos_prefix must not contain '?' or '#': {prefix}"
            )));
        }
        if cos_bucket.is_some() && cos_prefix.is_none() {
            return Err(config_validation(
                "packages.sources[].cos_prefix is required when cos_bucket is set",
            ));
        }
        if github_repo.is_none() && cos_bucket.is_none() {
            return Err(config_validation(format!(
                "packages.sources[] for {component} needs github_repo and/or cos_bucket"
            )));
        }
        sources.push(PackageSourceConfig {
            component,
            github_repo,
            cos_bucket,
            cos_prefix,
            cos_region,
        });
    }
    Ok(sources)
}

fn trim_trailing_slash(value: String) -> String {
    value.trim_end_matches('/').to_string()
}

/// 归一化 `[wparse_release]`：入口名唯一、group 只允许 `models|infra`、repo 按 provider 归一。
///
/// 这里只做**配置期**校验（不联网、不碰 token）：repo 是否可读、token 是否有
/// `repo-release:r` 由运行期 tag 接口现测并给出明确错误。
fn normalize_wparse_release(
    raw: RawWparseReleaseConfig,
) -> Result<WparseReleaseConfig, ConfigError> {
    let enabled = raw.enabled.unwrap_or(false);
    let tag_cache_seconds = raw.tag_cache_seconds.unwrap_or(DEFAULT_TAG_CACHE_SECONDS);
    if tag_cache_seconds == 0 {
        return Err(config_validation(
            "wparse_release.tag_cache_seconds must be greater than 0",
        ));
    }
    let max_targets = raw.max_targets.unwrap_or(DEFAULT_MAX_TARGETS);
    if max_targets == 0 {
        return Err(config_validation(
            "wparse_release.max_targets must be greater than 0",
        ));
    }
    let allow_manual_tag = raw.allow_manual_tag.unwrap_or(false);
    let mut repos = Vec::with_capacity(raw.repos.len());
    let mut seen = HashSet::new();
    let mut groups = HashSet::new();
    for item in raw.repos {
        let name = item.name.trim().to_string();
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(config_validation(format!(
                "wparse_release.repos[].name must match ^[A-Za-z0-9._-]+$: {name:?}"
            )));
        }
        if !seen.insert(name.clone()) {
            return Err(config_validation(format!(
                "wparse_release.repos[].name duplicated: {name}"
            )));
        }
        let group = item.group.trim().to_ascii_lowercase();
        if group != "models" && group != "infra" {
            return Err(config_validation(format!(
                "wparse_release.repos[{name}].group must be `models` or `infra`, got {:?}",
                item.group
            )));
        }
        if !groups.insert(group.clone()) {
            return Err(config_validation(format!(
                "wparse_release.repos[].group duplicated: {group} (each reload group can only have one repo)"
            )));
        }
        let provider = TagProviderKind::parse(&item.provider).ok_or_else(|| {
            config_validation(format!(
                "wparse_release.repos[{name}].provider must be `cnb`, `github`, or `manual`, got {:?}",
                item.provider
            ))
        })?;
        if provider == TagProviderKind::Manual && !allow_manual_tag {
            return Err(config_validation(format!(
                "wparse_release.repos[{name}].provider = `manual` requires allow_manual_tag = true"
            )));
        }
        let repo = normalize_repo_identifier(provider, &item.repo)?;
        let tags_limit = item
            .tags_limit
            .unwrap_or(DEFAULT_TAGS_LIMIT)
            .clamp(1, MAX_TAGS_LIMIT);
        repos.push(WparseRepoConfig {
            name,
            group,
            provider,
            repo,
            token: normalize_optional(item.token),
            tags_limit,
        });
    }
    if enabled && repos.is_empty() {
        return Err(config_validation(
            "wparse_release.enabled requires at least one [[wparse_release.repos]]",
        ));
    }
    Ok(WparseReleaseConfig {
        enabled,
        tag_cache_seconds,
        allow_manual_tag,
        max_targets,
        repos,
    })
}

/// repo 标识归一：接受完整 URL，落成 provider 需要的 slug。
///
/// **只剥离匹配 provider 的 host**：`provider=cnb` 配了 GitHub URL 不会被静默接受
/// （否则后面只会得到“仓库不存在”的 404，很难查）。`manual` 不联网，只做展示用，
/// 保留原文。
fn normalize_repo_identifier(provider: TagProviderKind, raw: &str) -> Result<String, ConfigError> {
    let raw = raw.trim();
    if provider == TagProviderKind::Manual {
        if raw.is_empty() {
            return Err(config_validation(
                "wparse_release.repos[].repo must not be empty",
            ));
        }
        return Ok(raw.to_string());
    }
    let value = match provider {
        TagProviderKind::Cnb => raw
            .strip_prefix("https://cnb.cool/")
            .or_else(|| raw.strip_prefix("http://cnb.cool/")),
        TagProviderKind::Github => raw
            .strip_prefix("https://github.com/")
            .or_else(|| raw.strip_prefix("http://github.com/")),
        TagProviderKind::Manual => None,
    }
    .unwrap_or(raw)
    .trim_end_matches('/')
    .trim_end_matches(".git")
    .to_string();
    if value.is_empty()
        || value.contains(char::is_whitespace)
        || value.contains(['?', '#'])
        || value.split('/').any(|part| part == "." || part == "..")
    {
        return Err(config_validation(format!(
            "wparse_release.repos[].repo must not be empty / contain whitespace, `?`, `#`, `.` or `..`: {raw:?}"
        )));
    }
    let parts: Vec<&str> = value.split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(config_validation(format!(
            "wparse_release.repos[].repo must not contain empty path segments: {raw:?}"
        )));
    }
    // 带错了宿主（如 provider=cnb 但写 github.com/...）时明确拒绝；否则只会得到 404。
    let foreign_host = match provider {
        TagProviderKind::Cnb => {
            value.starts_with("github.com/") || value.starts_with("gitlab.com/")
        }
        TagProviderKind::Github => value.starts_with("cnb.cool/"),
        TagProviderKind::Manual => false,
    };
    if foreign_host {
        return Err(config_validation(format!(
            "wparse_release.repos[].repo host does not match provider {}: {raw:?}",
            provider.as_str()
        )));
    }
    match provider {
        TagProviderKind::Cnb => {
            if parts.len() < 2 {
                return Err(config_validation(format!(
                    "wparse_release.repos[].repo must be a CNB slug `group/.../repo`: {raw:?}"
                )));
            }
        }
        TagProviderKind::Github => {
            if parts.len() != 2 {
                return Err(config_validation(format!(
                    "wparse_release.repos[].repo must be `owner/repo` for github: {raw:?}"
                )));
            }
        }
        TagProviderKind::Manual => unreachable!("manual is handled before URL normalization"),
    }
    Ok(value)
}

/// 归一可选值：去空白后为空 → None。
fn normalize_optional(raw: Option<String>) -> Option<String> {
    raw.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(config_validation(format!("{field} must not be empty")));
    }
    Ok(())
}

fn require_positive_seconds(field: &str, value: i64) -> Result<(), ConfigError> {
    if value > 0 {
        return Ok(());
    }
    Err(config_validation(format!("{field} must be greater than 0")))
}

/// 解析 `gateway_id:token,gateway_id:token,...`。
fn parse_gateway_credentials(raw: &str) -> Result<Vec<GatewayCredentialSeed>, ConfigError> {
    let mut seeds = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((gateway_id, token)) = entry.split_once(':') else {
            return Err(config_validation(format!(
                "invalid gateway credential entry {entry:?}: expected gateway_id:token"
            )));
        };
        let gateway_id = gateway_id.trim();
        let token = token.trim();
        if gateway_id.is_empty() || token.is_empty() {
            return Err(config_validation(format!(
                "invalid gateway credential entry {entry:?}: gateway_id and token must not be empty"
            )));
        }
        seeds.push(GatewayCredentialSeed {
            gateway_id: gateway_id.to_string(),
            token: token.to_string(),
            expires_at: None,
        });
    }
    Ok(seeds)
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, time::SystemTime};

    use super::*;

    /// 环境变量是进程级全局状态：涉及 env 的测试串行执行，避免互相踩。
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn write_temp_config(content: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("wist-center-config-{}", unique_suffix()));
        fs::create_dir_all(&dir).expect("create temp config dir");
        let path = dir.join(CONFIG_FILE);
        fs::write(&path, content).expect("write temp config");
        path
    }

    fn unique_suffix() -> u128 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    }

    #[test]
    fn parses_package_sources_and_defaults_the_cos_prefix() {
        let sources = normalize_package_sources(vec![
            RawPackageSource {
                component: "wist-agentd".into(),
                github_repo: Some("https://github.com/dayu-sec/wist-agentd".into()),
                cos_bucket: Some("github-1347593047".into()),
                cos_prefix: None,
                cos_region: Some("ap-hongkong".into()),
            },
            RawPackageSource {
                component: "galaxy-ops".into(),
                github_repo: Some("galaxio-labs/galaxy-ops".into()),
                cos_bucket: None,
                ..Default::default()
            },
        ])
        .expect("sources");
        assert_eq!(sources.len(), 2);
        assert_eq!(
            sources[0].github_repo.as_deref(),
            Some("dayu-sec/wist-agentd")
        );
        // COS 前缀缺省取仓库名。
        assert_eq!(sources[0].cos_prefix.as_deref(), Some("wist-agentd"));
        assert_eq!(sources[0].cos_region.as_deref(), Some("ap-hongkong"));
        assert_eq!(sources[1].cos_prefix.as_deref(), Some("galaxy-ops"));
    }

    #[test]
    fn rejects_duplicate_or_unscoped_package_sources() {
        fn source(component: &str) -> RawPackageSource {
            RawPackageSource {
                component: component.into(),
                github_repo: Some("dayu-sec/wist-agentd".into()),
                ..Default::default()
            }
        }
        // 组件重复。
        assert!(normalize_package_sources(vec![source("a"), source("a")]).is_err());
        // 既没 GitHub 也没 COS。
        assert!(
            normalize_package_sources(vec![RawPackageSource {
                component: "a".into(),
                ..Default::default()
            }])
            .is_err()
        );
        // 仓库不是 owner/repo。
        assert!(
            normalize_package_sources(vec![RawPackageSource {
                component: "a".into(),
                github_repo: Some("not-a-repo".into()),
                ..Default::default()
            }])
            .is_err()
        );
        // 组件名不能带路径分隔符。
        assert!(
            normalize_package_sources(vec![RawPackageSource {
                component: "a/b".into(),
                github_repo: Some("x/y".into()),
                ..Default::default()
            }])
            .is_err()
        );
    }

    #[test]
    fn loads_package_sources_from_file() {
        let path = write_temp_config(
            r#"
[packages]
[[packages.sources]]
component = "wist-agentd"
github_repo = "dayu-sec/wist-agentd"
cos_bucket = "github-1347593047"
"#,
        );
        let config = CenterConfig::load_from_path(&path).expect("config loads");
        assert_eq!(config.package_sources.len(), 1);
        assert_eq!(
            config.package_sources[0].cos_prefix.as_deref(),
            Some("wist-agentd")
        );
    }

    #[test]
    fn parses_wparse_release_repos_and_normalizes_urls() {
        let config = normalize_wparse_release(RawWparseReleaseConfig {
            enabled: Some(true),
            tag_cache_seconds: None,
            allow_manual_tag: Some(true),
            max_targets: None,
            repos: vec![
                RawWparseRepo {
                    name: "wparse-rules".into(),
                    group: "MODELS".into(),
                    provider: "CNB".into(),
                    repo: "https://cnb.cool/dy-sec/jingang-cust/wist/wp-rules.git".into(),
                    token: Some("${SEC_TEST_TOKEN}".into()),
                    tags_limit: None,
                },
                RawWparseRepo {
                    name: "wparse-infra".into(),
                    group: "infra".into(),
                    provider: "cnb".into(),
                    repo: "dy-sec/jingang-cust/wist/wp-infra".into(),
                    token: None,
                    tags_limit: Some(9999),
                },
            ],
        })
        .expect("wparse release");
        assert!(config.enabled);
        assert!(config.allow_manual_tag);
        assert_eq!(config.repos.len(), 2);
        assert_eq!(config.repos[0].name, "wparse-rules");
        assert_eq!(config.repos[0].group, "models");
        assert_eq!(config.repos[0].provider, TagProviderKind::Cnb);
        // 完整 URL / `.git` 后缀都被归一成 API slug。
        assert_eq!(config.repos[0].repo, "dy-sec/jingang-cust/wist/wp-rules");
        // tags_limit 夹到硬上限。
        assert_eq!(config.repos[1].tags_limit, MAX_TAGS_LIMIT);
    }

    #[test]
    fn rejects_duplicate_wparse_release_repo_names() {
        let repo = || RawWparseRepo {
            name: "wparse-rules".into(),
            group: "models".into(),
            provider: "cnb".into(),
            repo: "a/b".into(),
            token: None,
            tags_limit: None,
        };
        assert!(
            normalize_wparse_release(RawWparseReleaseConfig {
                repos: vec![repo(), repo()],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_duplicate_wparse_release_groups() {
        let repo = |name: &str| RawWparseRepo {
            name: name.into(),
            group: "models".into(),
            provider: "cnb".into(),
            repo: "a/b".into(),
            token: None,
            tags_limit: None,
        };
        assert!(
            normalize_wparse_release(RawWparseReleaseConfig {
                repos: vec![repo("wparse-rules"), repo("wparse-rules-2")],
                ..Default::default()
            })
            .is_err(),
            "two repos must not share a reload group"
        );
    }

    #[test]
    fn rejects_unknown_group_or_provider() {
        let repo = |group: &str, provider: &str| RawWparseRepo {
            name: "wparse-rules".into(),
            group: group.into(),
            provider: provider.into(),
            repo: "a/b".into(),
            token: None,
            tags_limit: None,
        };
        for (group, provider) in [("rules", "cnb"), ("models", "svn")] {
            assert!(
                normalize_wparse_release(RawWparseReleaseConfig {
                    repos: vec![repo(group, provider)],
                    ..Default::default()
                })
                .is_err(),
                "group={group} provider={provider} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_repo_host_that_does_not_match_provider() {
        let repo = |provider: &str, repo: &str| RawWparseRepo {
            name: "wparse-rules".into(),
            group: "models".into(),
            provider: provider.into(),
            repo: repo.into(),
            token: None,
            tags_limit: None,
        };
        for (provider, repo_url) in [
            ("cnb", "github.com/dayu-sec/wp-rules"),
            ("github", "cnb.cool/dy-sec/jingang-cust/wist/wp-rules"),
        ] {
            assert!(
                normalize_wparse_release(RawWparseReleaseConfig {
                    repos: vec![repo(provider, repo_url)],
                    ..Default::default()
                })
                .is_err(),
                "provider={provider} repo={repo_url} should be rejected"
            );
        }
        // manual 只做展示：保留原文，只要求非空。
        assert!(
            normalize_wparse_release(RawWparseReleaseConfig {
                allow_manual_tag: Some(true),
                repos: vec![repo(
                    "manual",
                    "https://cnb.cool/dy-sec/jingang-cust/wist/wp-rules"
                )],
                ..Default::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn manual_provider_requires_allow_manual_tag() {
        let raw = || RawWparseReleaseConfig {
            allow_manual_tag: Some(false),
            repos: vec![RawWparseRepo {
                name: "wparse-rules".into(),
                group: "models".into(),
                provider: "manual".into(),
                repo: "dy-sec/jingang-cust/wist/wp-rules".into(),
                token: None,
                tags_limit: None,
            }],
            ..Default::default()
        };
        assert!(normalize_wparse_release(raw()).is_err());
        let mut allowed = raw();
        allowed.allow_manual_tag = Some(true);
        assert!(normalize_wparse_release(allowed).is_ok());
    }

    #[test]
    fn wparse_release_enabled_requires_repos() {
        assert!(
            normalize_wparse_release(RawWparseReleaseConfig {
                enabled: Some(true),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            normalize_wparse_release(RawWparseReleaseConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn wparse_repo_debug_redacts_token() {
        let repo = WparseRepoConfig {
            name: "wparse-rules".into(),
            group: "models".into(),
            provider: TagProviderKind::Cnb,
            repo: "a/b".into(),
            token: Some("super-secret".into()),
            tags_limit: 100,
        };
        let rendered = format!("{repo:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
    }

    #[test]
    fn loads_wparse_release_from_file() {
        let path = write_temp_config(
            r#"
[wparse_release]
enabled = true
allow_manual_tag = true

[[wparse_release.repos]]
name = "wparse-rules"
group = "models"
provider = "manual"
repo = "dy-sec/jingang-cust/wist/wp-rules"
"#,
        );
        let config = CenterConfig::load_from_path(&path).expect("config loads");
        assert!(config.wparse_release.enabled);
        assert_eq!(config.wparse_release.repos.len(), 1);
        assert_eq!(
            config.wparse_release.repos[0].provider,
            TagProviderKind::Manual
        );
    }

    #[test]
    fn parses_gateway_credential_seeds() {
        let seeds = parse_gateway_credentials("gw-001:tok-a,gw-002:tok-b").expect("seeds");
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].gateway_id, "gw-001");
        assert_eq!(seeds[0].token, "tok-a");
        assert_eq!(seeds[1].gateway_id, "gw-002");
        assert_eq!(seeds[1].token, "tok-b");
    }

    #[test]
    fn rejects_malformed_seed_entry() {
        assert!(parse_gateway_credentials("gw-001").is_err());
        assert!(parse_gateway_credentials(":tok").is_err());
        assert!(parse_gateway_credentials("gw-001:").is_err());
    }

    #[test]
    fn empty_credentials_are_fine() {
        assert!(parse_gateway_credentials("").expect("empty").is_empty());
        assert!(parse_gateway_credentials(" , ").expect("blank").is_empty());
    }

    #[test]
    fn normalize_optional_trims_blank() {
        assert_eq!(
            normalize_optional(Some("http://127.0.0.1:8428".to_string())).as_deref(),
            Some("http://127.0.0.1:8428")
        );
        assert_eq!(normalize_optional(Some("  ".to_string())), None);
        assert_eq!(normalize_optional(Some(String::new())), None);
        assert_eq!(normalize_optional(None), None);
    }

    #[test]
    fn loads_config_from_file_with_placeholder_expansion() {
        let _guard = env_guard();
        // 占位符用测试专用变量名，不吃真实环境。
        unsafe {
            env::set_var("WIST_CENTER_TEST_ADMIN_TOKEN", "test-admin-token");
            env::set_var("WIST_CENTER_TEST_HMAC_SECRET", "test-hmac-secret");
        }
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3999"
public_url = "https://center.example.com/"
protocol_version = "2.0"
admin_token = "${WIST_CENTER_TEST_ADMIN_TOKEN}"

[store]
store_path = "state/store.json"

[security]
hmac_secret = "${WIST_CENTER_TEST_HMAC_SECRET}"
credential_ttl_seconds = 60
link_ttl_seconds = 30

[artifacts]
dir = "artifacts"

[enrollment]
gateway_credentials = ["gw-001:tok-a", "gw-002:tok-b"]
"#,
        );
        let config_dir = path.parent().expect("config dir").to_path_buf();

        let config = CenterConfig::load_from_path(&path).expect("config loads");

        assert_eq!(config.listen_addr, "127.0.0.1:3999");
        assert_eq!(config.public_url, "https://center.example.com");
        assert_eq!(config.protocol_version, "2.0");
        assert_eq!(config.hmac_secret, "test-hmac-secret");
        assert_eq!(config.credential_ttl_seconds, 60);
        assert_eq!(config.link_ttl_seconds, 30);
        assert_eq!(
            config.admin_token_hash.as_deref(),
            Some(sha256_hex("test-admin-token").as_str())
        );
        assert_eq!(config.gateway_credentials.len(), 2);
        assert_eq!(config.gateway_credentials[0].gateway_id, "gw-001");
        // 相对路径按配置文件所在目录解析成绝对路径。
        assert_eq!(config.store_path, config_dir.join("state/store.json"));
        assert_eq!(config.artifact_dir, config_dir.join("artifacts"));
    }

    #[test]
    fn missing_config_file_falls_back_to_defaults() {
        let _guard = env_guard();
        let path = env::temp_dir().join(format!("wist-center-absent-{}.toml", unique_suffix()));

        let config = CenterConfig::load_from_path(&path).expect("defaults apply");

        assert_eq!(config.listen_addr, DEFAULT_LISTEN);
        assert_eq!(config.public_url, DEFAULT_PUBLIC_URL);
        assert_eq!(config.protocol_version, DEFAULT_PROTOCOL_VERSION);
        assert_eq!(config.hmac_secret, DEV_HMAC_SECRET);
        assert_eq!(
            config.credential_ttl_seconds,
            DEFAULT_CREDENTIAL_TTL_SECONDS
        );
        assert_eq!(config.link_ttl_seconds, DEFAULT_LINK_TTL_SECONDS);
        assert!(config.store_path.ends_with(DEFAULT_STORE_PATH));
    }

    #[test]
    fn env_overrides_file_values() {
        let _guard = env_guard();
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3999"
admin_token = "file-admin-token"

[store]
database_url = "postgres://file-host/example"

[telemetry]
victoriametrics_url = "http://file-vm:8428"
"#,
        );
        unsafe {
            env::set_var("WARP_INSIGHT_CENTER_LISTEN", "127.0.0.1:4111");
            // 显式置空 = 明确关闭（文件里的 DSN 被清掉 → 退回本地文件存储）。
            env::set_var("WARP_INSIGHT_CENTER_DATABASE_URL", "");
            env::set_var(
                "WARP_INSIGHT_CENTER_VICTORIAMETRICS_URL",
                "http://env-vm:8428/",
            );
            env::set_var("WARP_INSIGHT_CENTER_LINK_TTL_SECONDS", "120");
        }

        let config = CenterConfig::load_from_path(&path).expect("config loads");

        assert_eq!(config.listen_addr, "127.0.0.1:4111");
        // 管理 token 只从配置文件来（不再有 env 覆盖）：这里就是文件里的值。
        assert_eq!(
            config.admin_token_hash.as_deref(),
            Some(sha256_hex("file-admin-token").as_str())
        );
        assert_eq!(config.database_url, None);
        assert_eq!(
            config.victoriametrics_url.as_deref(),
            Some("http://env-vm:8428")
        );
        assert_eq!(config.link_ttl_seconds, 120);

        // 归还环境，别影响同进程其它测试。
        unsafe {
            env::remove_var("WARP_INSIGHT_CENTER_LISTEN");
            env::remove_var("WARP_INSIGHT_CENTER_DATABASE_URL");
            env::remove_var("WARP_INSIGHT_CENTER_VICTORIAMETRICS_URL");
            env::remove_var("WARP_INSIGHT_CENTER_LINK_TTL_SECONDS");
        }
    }

    #[test]
    fn rejects_invalid_toml_and_empty_listen_addr() {
        let _guard = env_guard();
        let broken = write_temp_config("[server]\nlisten_addr = \n");
        assert!(CenterConfig::load_from_path(&broken).is_err());

        let empty_listen = write_temp_config(
            r#"
[server]
listen_addr = ""
"#,
        );
        assert!(CenterConfig::load_from_path(&empty_listen).is_err());
    }

    #[test]
    fn rejects_non_positive_link_ttl() {
        let _guard = env_guard();
        // 接入券 TTL 必须是正整数：0（立即过期）会让「生成/轮换」形同虚设，必须在加载期拦住。
        let path = write_temp_config("[security]\nlink_ttl_seconds = 0\n");
        let err = CenterConfig::load_from_path(&path).expect_err("zero link TTL must be rejected");
        assert!(
            format!("{err}").contains("security.link_ttl_seconds"),
            "{err}"
        );
    }

    #[test]
    fn renders_default_config_text_with_generated_secrets() {
        let text = default_config_text("adm_test", "hmac_test");
        assert!(text.contains("admin_token = \"adm_test\""));
        assert!(text.contains("hmac_secret = \"hmac_test\""));
        assert!(!text.contains("${WIST_CENTER_ADMIN_TOKEN}"));
        assert!(!text.contains("${WIST_CENTER_HMAC_SECRET}"));
    }

    // ─────────── 主配置 + 现场态声明 / 值（三文件） ───────────

    /// 写一份主配置到唯一临时目录，返回主配置路径（现场态声明 / `.env` 由调用方按需写）。
    fn write_main_config(content: &str) -> PathBuf {
        write_temp_config(content)
    }

    /// 在 `dir` 里写现场态**声明**（`${VAR}`）与**值**（`.env`）——模拟栈侧 tpl + 脚本的产物。
    fn write_overlay(dir: &Path, declaration: &str, env_text: &str) {
        fs::write(dir.join(PUB_CONFIG_FILE_NAME), declaration).expect("write overlay");
        fs::write(dir.join(PUB_ENV_FILE_NAME), env_text).expect("write .env");
    }

    #[test]
    fn loads_the_public_url_through_the_overlay_and_env_file() {
        let _guard = env_guard();
        let path = write_main_config("[server]\nlisten_addr = \"127.0.0.1:3100\"\n");
        let dir = path.parent().unwrap();
        write_overlay(
            dir,
            "[server]\npublic_url = \"${WIST_CENTER_TEST_URL}\"\n",
            "WIST_CENTER_TEST_URL=https://center.example.test\n",
        );
        let config = CenterConfig::load_from_path(&path).expect("load");
        assert_eq!(config.public_url, "https://center.example.test");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn an_absent_overlay_leaves_public_url_defaulted() {
        let _guard = env_guard();
        let path = write_main_config("[server]\nlisten_addr = \"127.0.0.1:3100\"\n");
        let config = CenterConfig::load_from_path(&path).expect("load");
        assert_eq!(config.public_url, DEFAULT_PUBLIC_URL);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_same_leaf_key_in_both_files_is_rejected() {
        let _guard = env_guard();
        let path = write_main_config(
            "[server]\nlisten_addr = \"127.0.0.1:3100\"\npublic_url = \"https://a\"\n",
        );
        let dir = path.parent().unwrap();
        write_overlay(
            dir,
            "[server]\npublic_url = \"${WIST_CENTER_TEST_URL}\"\n",
            "WIST_CENTER_TEST_URL=https://b\n",
        );
        let err = CenterConfig::load_from_path(&path).expect_err("同一叶子键出现在两份里必须报错");
        assert!(format!("{err}").contains("同一个键只能有一处"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unset_overlay_var_fails_closed() {
        let _guard = env_guard();
        let path = write_main_config("[server]\nlisten_addr = \"127.0.0.1:3100\"\n");
        let dir = path.parent().unwrap();
        // 声明引用了变量，但 `.env` 没给它、也没 `:-默认值` → 拒启（不静默变空）。
        write_overlay(
            dir,
            "[server]\npublic_url = \"${WIST_CENTER_TEST_URL}\"\n",
            "",
        );
        let err = CenterConfig::load_from_path(&path).expect_err("未定义变量必须拒启");
        assert!(format!("{err}").contains("WIST_CENTER_TEST_URL"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn default_pub_config_text_declares_the_site_key() {
        let text = default_pub_config_text();
        assert!(text.contains("public_url"), "{text}");
        assert!(text.contains("${CENTER_PUBLIC_URL"), "{text}");
        let paths = config_key_paths(&text);
        assert!(paths.iter().any(|p| p == "server.public_url"), "{paths:?}");
    }

    /// 示例配置必须始终可加载：它给人复制粘贴用，键名一漂移就会误导使用者。
    /// 这里刻意不走 load_from_path 的 env 覆盖（那条路径由 env_overrides_file_values 覆盖），
    /// 断言只反映示例文件本身，不读外层 shell 导出的变量（示例里已无 `${VAR}` 占位）。
    #[test]
    fn bundled_example_config_loads() {
        // 与设环境的测试串行：secret_dict() 会读 SEC_FILE_ENV，避免踩到并发测试的临时值。
        let _guard = env_guard();
        let mut raw: RawCenterConfig =
            toml::from_str(include_str!("../examples/local-dev.toml")).expect("示例应能解析");
        // 示例里的 ${VAR}（如果有）必须能在正常环境下展开；缺失时 expand 会直接报错，这里就拦住。
        let env = secret_dict().expect("构建密钥表");
        expand_raw_env(&mut raw, &env).expect("示例里的占位符必须能在正常环境下展开");
        let config_dir = Path::new("/tmp/wist-center-example");
        let config = CenterConfig::from_raw(raw, config_dir).expect("示例应能解析成配置");
        config.validate().expect("示例应通过校验");

        assert_eq!(config.listen_addr, DEFAULT_LISTEN);
        assert_eq!(config.public_url, DEFAULT_PUBLIC_URL);
        assert_eq!(config.protocol_version, DEFAULT_PROTOCOL_VERSION);
        assert_eq!(config.gateway_image, DEFAULT_GATEWAY_IMAGE);
        assert_eq!(config.gateway_project_repo, DEFAULT_GATEWAY_PROJECT_REPO);
        assert_eq!(
            config.credential_ttl_seconds,
            DEFAULT_CREDENTIAL_TTL_SECONDS
        );
        assert_eq!(config.link_ttl_seconds, DEFAULT_LINK_TTL_SECONDS);
        assert_eq!(config.database_url, None);
        assert_eq!(config.victoriametrics_url, None);
        assert!(config.object_storage.is_none());
        assert!(config.gateway_credentials.is_empty());
        // 相对路径按配置文件所在目录解析。
        assert_eq!(
            config.store_path,
            config_dir.join("state/warp-insight-center-store.json")
        );
        assert_eq!(config.artifact_dir, config_dir.join("artifacts"));
        assert_eq!(
            config.admin_token_hash.as_deref(),
            Some(sha256_hex("dev-admin-token").as_str())
        );
    }

    /// 示例与 init-config 模板必须覆盖同一组键：两份近乎重复的文件最容易出的问题
    /// 就是"改了一份忘了另一份"。
    #[test]
    fn example_and_template_share_the_same_keys() {
        assert_eq!(
            config_key_paths(include_str!("../examples/local-dev.toml")),
            config_key_paths(include_str!("../wist-center.toml"))
        );
    }

    #[test]
    fn server_tls_paths_must_be_set_together() {
        let _guard = env_guard();
        // 只配证书、不配私钥 → 拒绝（否则会在启动时握手才失败）。
        let path =
            write_temp_config("[server]\nserver_cert_path = \"/tmp/wist-center-cert.pem\"\n");
        let err =
            CenterConfig::load_from_path(&path).expect_err("half-configured TLS must be rejected");
        assert!(format!("{err}").contains("together"), "{err}");
    }

    #[test]
    fn server_tls_paths_must_exist_when_configured() {
        let _guard = env_guard();
        let path = write_temp_config(
            "[server]\nserver_cert_path = \"/tmp/wist-center-missing-cert.pem\"\nserver_key_path = \"/tmp/wist-center-missing-key.pem\"\n",
        );
        let err =
            CenterConfig::load_from_path(&path).expect_err("missing TLS files must be rejected");
        assert!(format!("{err}").contains("not found"), "{err}");
    }

    fn config_key_paths(text: &str) -> Vec<String> {
        let value: toml::Value = toml::from_str(text).expect("toml parses");
        let mut paths = Vec::new();
        collect_key_paths("", &value, &mut paths);
        paths.sort();
        paths
    }

    fn collect_key_paths(prefix: &str, value: &toml::Value, out: &mut Vec<String>) {
        let toml::Value::Table(table) = value else {
            return;
        };
        for (key, child) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            match child {
                toml::Value::Table(_) => collect_key_paths(&path, child, out),
                _ => out.push(path),
            }
        }
    }

    #[test]
    fn log_section_parses_and_absolutizes_file() {
        // load_from_path → secret_dict() 会读 SEC_FILE_ENV，与设环境的测试串行。
        let _guard = env_guard();
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3100"
public_url = "https://center.example"
protocol_version = "1.0"

[log]
level = "warn"
format = "json"
file = "logs/center.log"
max_bytes = 1048576
"#,
        );
        let config = CenterConfig::load_from_path(&path).expect("config loads");
        assert_eq!(config.log.level.as_deref(), Some("warn"));
        assert_eq!(config.log.format, wist_log::LogFormat::Json);
        let file = config.log.file.expect("log file resolved");
        assert!(
            file.is_absolute(),
            "log file should be absolutized: {file:?}"
        );
        assert!(file.ends_with("logs/center.log"), "{file:?}");
        let _ = std::fs::remove_file(&path);
    }

    fn write_temp_file(content: &str, ext: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("wist-center-sec-{}", unique_suffix()));
        fs::create_dir_all(&dir).expect("create temp sec dir");
        let path = dir.join(format!("sec-value.{ext}"));
        fs::write(&path, content).expect("write temp sec file");
        path
    }

    /// 未解析的占位符（且无默认值）→ 拒绝启动（fail-closed），且报出缺哪个变量。
    #[test]
    fn unresolved_placeholder_fails_closed() {
        let _guard = env_guard();
        let path = write_temp_config(
            "[security]\nhmac_secret = \"${WIST_CENTER_TEST_MISSING_VAR_XYZ}\"\n",
        );
        let err = CenterConfig::load_from_path(&path).expect_err("unresolved secret must fail");
        assert!(
            err.to_string().contains("WIST_CENTER_TEST_MISSING_VAR_XYZ"),
            "{err}"
        );
    }

    /// 支持 `${VAR:default}`：查不到变量时用默认值。
    #[test]
    fn env_default_syntax_is_supported() {
        let _guard = env_guard();
        let path = write_temp_config(
            "[security]\nhmac_secret = \"${WIST_CENTER_TEST_MISSING_VAR:fallback-secret}\"\n",
        );
        let config = CenterConfig::load_from_path(&path).expect("default used");
        assert_eq!(config.hmac_secret, "fallback-secret");
    }

    /// 自定义密钥文件（`WIST_CENTER_SEC_FILE` 指向的那个）：按键规范成 `SEC_<UPPER>` 载入。
    #[test]
    fn custom_sec_file_loads_and_prefixes_keys() {
        let path = write_temp_file(
            "center_admin_token: custom-secret-token-1234567890\n",
            "yml",
        );
        let dict = load_sec_file(&path).expect("load sec file");
        assert!(
            dict.get_case_insensitive("SEC_CENTER_ADMIN_TOKEN")
                .is_some()
        );
        let _ = fs::remove_file(path);
    }

    /// 显式指定的密钥文件**缺失** → 明确报错（而不是含糊的「SEC_xxx 未解析」）。
    #[test]
    fn missing_explicit_sec_file_is_an_error() {
        let missing = env::temp_dir().join("wist-center-sec-file-that-does-not-exist.yml");
        let err = load_sec_file(&missing).expect_err("missing explicit sec file must fail");
        assert!(err.to_string().contains("secrets file not found"), "{err}");
    }

    /// 配置里的 `${SEC_...}` 由 `WIST_CENTER_SEC_FILE` 指向的密钥文件解析（值不落明文配置）。
    #[test]
    fn config_resolves_sec_placeholders_from_sec_file() {
        let _guard = env_guard();
        let sec = write_temp_file("center_admin_token: sec-file-admin-token\n", "yml");
        let path = write_temp_config("[server]\nadmin_token = \"${SEC_CENTER_ADMIN_TOKEN}\"\n");
        unsafe {
            env::set_var(SEC_FILE_ENV, &sec);
        }
        let config = CenterConfig::load_from_path(&path).expect("config loads");
        unsafe {
            env::remove_var(SEC_FILE_ENV);
        }
        assert_eq!(
            config.admin_token_hash.as_deref(),
            Some(sha256_hex("sec-file-admin-token").as_str())
        );
        let _ = fs::remove_file(sec);
    }

    /// 来源字段会拼进 URL：bucket/region 不能改 host，prefix 不能注入 query/fragment。
    #[test]
    fn package_source_fields_cannot_inject_url_parts() {
        fn cos(bucket: &str, prefix: &str, region: Option<&str>) -> RawPackageSource {
            RawPackageSource {
                component: "demo".into(),
                github_repo: None,
                cos_bucket: Some(bucket.into()),
                cos_prefix: Some(prefix.into()),
                cos_region: region.map(str::to_string),
            }
        }
        // prefix 两端斜杠归一化。
        let ok = normalize_package_sources(vec![cos("bucket", "/demo/", None)]).expect("ok");
        assert_eq!(ok[0].cos_prefix.as_deref(), Some("demo"));
        // bucket / region 不能带路径或 userinfo。
        assert!(normalize_package_sources(vec![cos("b@evil", "demo", None)]).is_err());
        assert!(normalize_package_sources(vec![cos("b/x", "demo", None)]).is_err());
        assert!(normalize_package_sources(vec![cos("b", "demo", Some("r/x"))]).is_err());
        // prefix 不能注入 query / fragment。
        assert!(normalize_package_sources(vec![cos("b", "demo?x=1", None)]).is_err());
        assert!(normalize_package_sources(vec![cos("b", "demo#frag", None)]).is_err());
    }

    #[test]
    fn parses_wparse_proxy_section() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3999"
public_url = "https://center.example.com"
admin_token = "tok"

[security]
hmac_secret = "hmac"

[wparse_proxy]
enabled = true
listen_addr = "0.0.0.0:3101"
"#,
        );
        let config = CenterConfig::load_from_path(&path).expect("config loads");
        assert!(config.wparse_proxy.enabled);
        assert_eq!(config.wparse_proxy.listen_addr, "0.0.0.0:3101");
    }

    #[test]
    fn wparse_proxy_defaults_to_disabled() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3999"
public_url = "https://center.example.com"
admin_token = "tok"

[security]
hmac_secret = "hmac"
"#,
        );
        let config = CenterConfig::load_from_path(&path).expect("config loads");
        assert!(!config.wparse_proxy.enabled);
        assert_eq!(config.wparse_proxy.listen_addr, "0.0.0.0:3101");
    }
}
