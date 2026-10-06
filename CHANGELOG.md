# 更新日志

本文件记录 `wist-center` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 说明：0.4.0 之前未单独维护本文件；自 0.4.0 起记录。

## [0.5.5-alpha] - 2026-10-06

### 变更

- **制品下发 URL 改用来源原名**（取代 0.5.4 的 `pkg-<sha16>.扩展名`）：落盘 / 下发文件名取来源末段
  （`galaxy-flow-v0.16.1-alpha-x86_64-unknown-linux-musl.tar.gz`）—— URL 末段就是原名，人看着清楚、
  下载即得可用文件。**内容寻址退回 DB**：`release_records.package_sha256` + `(component, version, sha)`
  幂等去重（不再是文件名）。名字取不到 / 危险（`.`,`..`）→ 回落 `{component}-{version}.bin`（防路径穿越）。
  相应地删掉不再用的 `infra::package_id_for_sha256`。

## [0.5.4-alpha] - 2026-10-06

### 修复

- **制品下发 URL 丢文件名**：内容寻址后文件名是 `pkg-<sha256[:16]>`、**没有扩展名** —— 点开下载得到
  一个没法用的裸文件（系统/工具不知道是 `tar.gz`）。现在叶子带上**来源的归档扩展名**
  （`pkg-<sha16>.tar.gz`）；URL 仍内容寻址（`artifact_extension()`）。

## [0.5.3-alpha] - 2026-10-06

### Added
- **记下网关对外域名**：注册（`POST /api/v1/gateway/register`）与周期状态上报
  （`POST /api/v1/gateway/status`）带来的 `public_base_url` 落库；`GatewayRuntimeStatus` 视图回带，
  网关列表据此展示「域名」。状态上报不带（老网关 `None`）时**保留**已落值，不抹掉。
- **升级计划带中心派生的制品地址**：网关拉取升级目标（`GET /api/v1/gateway/upgrade-plan`）时，
  中心按 `(component, target_version)` **反查已发布的 release**，把镜像后的绝对地址放进
  `GatewayUpgradePlan.artifact_url`；执行器据此取件。无对应 release（未发布过）则不带 → 网关回落用版本。
- **升级包管理向 gateway 的 agent 包对齐**：发布（`POST /api/v1/admin/releases/:component`）的来源
  现在既接 **https URL** 也接**本机绝对路径**；读到的内容算 **sha256** 并落库
  （`release_records.package_sha256`），可带可选 `expected_sha256` **核对**（不符 502、不落记录）；
  同一 `(component, version)` 的同一份内容重复发布按**幂等**返回（不重复下副本）。
  内核在 `src/infra/package.rs`（**刻意与 gateway 重复**，见文件头 NOTE 与设计 §7）。
- **版本号不再手输，由包地址自动解析**：发布（`POST /api/v1/admin/releases/:component`）的 `version`
  改为**可选** —— 不传就从包内目录名 / 来源文件名解析（`read_package_identity`），传了才与解析值**核对**
  （归一化 `v` 后不符 → 400）；两边都解析不出 → 400（不静默落空版本）。身份解析**不写死组件名**，
  先看包内首条目目录名、读不出再回落来源文件名 —— 覆盖 **agentd 包**（目录名带 version+triple）、
  **gateway-stack 包**（顶层 `sys/…`，只能从文件名读）、**galaxy-ops / galaxy-flow 包**。
  镜像后落库的文件名取内容寻址的 **`pkg-<sha256[:16]>`**（与网关侧同式）。依赖新增 `flate2` / `tar`。

### Changed
- **依赖**：`wist-control` `0.8` → `0.9`。`gateways` 表加列 `public_base_url`
  （`docker/initdb/01_schema.sql` 幂等补列）。

## [0.5.2-alpha] - 2026-10-06

### Changed
- **网关面注册/凭据报文体改用模型生成类型**：`POST /api/v1/gateway/register`、
  `credentials:renew`、`credentials/verify` 的请求/响应改用 `wist-control 0.8` 的
  `RegisterGateway` / `RenewGatewayCredential` / `VerifyGatewayCredential` / `GatewayEnrollmentResult` /
  `GatewayCredentialBundle` / `GatewayCredentialVerificationResult`（原 `wist-contracts::gateway_control`）。
  **线上 JSON 不变**（时间戳仍为 RFC3339 串）。
- **依赖**：`wist-control` `0.7` → `0.8`；**移除 `wist-contracts` 依赖**（本仓只用过 `gateway_control`）。

## [0.5.1-alpha] - 2026-10-06

### Changed
- **网关上报的 agent 状态报文体改用模型生成的类型**：`POST /api/v1/gateway/agents/status`
  请求/响应改用 `wist-control 0.7` 的 `ReportAgentStatus` / `AgentStatusAcceptedReturned`
  （删除本仓本地定义的 `AgentStatusReportRequest` / `AgentStatusEntry`）。**wire 不变**（字段一一对应），
  升级本制品即可，网关侧无需同步改动。
- 依赖升级：`wist-control` `0.6` → `0.7`。

## [0.5.0-alpha] - 2026-10-05

### Changed（不兼容）
- **接入券改名（bootstrap → link）**：网关一次性「置备引导券」统一更名为**接入券**（link token）。
  它只在网关**首跑接入**（`link-upstream`）时用一次 —— 容器部署/启动本身不需要它，名字不应暗示「启动引导」。
  - 管理面路由 `POST /api/v1/admin/gateways/{id}/setup-token` → `.../link-token`；
    响应字段 `setup_token` → `link_token`、`bootstrap_expires_at` → `link_expires_at`。
  - 配置项 `security.bootstrap_ttl_seconds` → `security.link_ttl_seconds`；
    env `WARP_INSIGHT_CENTER_BOOTSTRAP_TTL_SECONDS` → `WARP_INSIGHT_CENTER_LINK_TTL_SECONDS`。
  - 库列 `bootstrap_token_hash` / `bootstrap_token_expires_at` → `link_token_hash` / `link_token_expires_at`
    （该列本周期新增、尚未发布，直接改名，无迁移）。
- **接入凭据不再随 create 交付**：`POST /api/v1/admin/gateways/instances` 只建实例，响应**只含实例视图**
  （删 `install`）；一次性接入券改由 `POST /api/v1/admin/gateways/{id}/link-token`（**生成/轮换**）产出、
  页面一次性展示（设计 `gateway-secure-registration.md` §6/§8）。请求体的 `token` 字段一并移除。
- **安装命令不再向网关容器注入初始化 URL / 接入券**：这些 env（`WIST_GATEWAY_INIT_URL` /
  `WIST_GATEWAY_BOOTSTRAP_TOKEN`）在本仓无任何读取方，且接入发起方已改为宿主侧 `wist-gwlinkd`
  （设计 §6「集成发起方」）—— 容器启动本身不需要接入券。

### Added
- **接入券短 TTL（可配）**：接入券带到期时刻，**默认 15 分钟**，过期即不可用
  （`consume_link_token` 拒绝）；「生成/轮换」响应新增 `link_expires_at`。
  - 配置项 `security.link_ttl_seconds` / env `WARP_INSIGHT_CENTER_LINK_TTL_SECONDS`（须为正整数）。
- **网关状态富化**：中心视图（`gateway_runtime_status` / `GatewayStatusView`）新增
  `uptime_seconds` / 机队（`agent_count` / `online_agents` / `offline_agents` / `last_seen_lag_seconds`）/ 存储（`store_bytes`）/
  数据面（`ingest_accepted_total` / `ingest_rejected_total` / `last_ingest_at`）/ 主机（`memory_total_bytes` / `load_1m|5m|15m` /
  `disk_usage_percent` / `disk_total_bytes` / `disk_available_bytes`）（对齐 `wist-control` 0.6.1；老网关缺键 → `null`）。
- **富化指标进 VictoriaMetrics 时序**：上报时同步推送 `gateway_uptime_seconds` / `gateway_agent_count` /
  `gateway_online_agents` / `gateway_offline_agents` / `gateway_last_seen_lag_seconds` / `gateway_store_bytes` /
  `gateway_ingest_accepted_total` / `gateway_ingest_rejected_total` / `gateway_last_ingest_timestamp_seconds` /
  `gateway_memory_total_bytes` / `gateway_load1|load5|load15` / `gateway_disk_usage_percent` / `gateway_disk_total_bytes` /
  `gateway_disk_available_bytes`（除 up/info/health 外**有值才推**）；历史查询与中心 Web 趋势图同步扩展。

### 数据库
- `gateways` 表新增 `link_token_expires_at`（含 `wist-center-stack` 同源 schema 副本需同步）。

## [0.4.0-alpha] - 2026-10-04

### Changed（不兼容）
- **网关凭据改为客户端证书（mTLS）**：
  - `register` 用 **CA-G** 按网关 CSR 签「每网关一张」客户端证书（长期身份），登记指纹；
    回执 `GatewayCredentialBundle` 只带 `certificate`（删 `bearer_token` / `auth_scheme` / `expires_at`）。
  - `renew` 改为**证书轮换**（当前证书证明身份 + 新 CSR → 新证书，旧证书作废）。
  - `status` / `agents/status` / `upgrade-plan` / `upgrade-result` / **已置备的** `link-upstream`
    鉴权改为**由客户端证书认人**（删运行期 bearer）。
- `link-upstream` **首次置备**仍用一次性 bootstrap bearer —— 那是引导券，不是长期身份。

### Added
- **服务端 TLS/mTLS 监听（甲）**：配了 `server.server_cert_path` / `server.server_key_path` → 起 HTTPS，
  以 `WebPkiClientVerifier` 校网关客户端证书（信任 CA-G），握手后把网关身份注入请求；
  未配 → 明文 HTTP（dev / 反代兜底）。
- 配置项：`server.server_cert_path` / `server.server_key_path`（+ env `WARP_INSIGHT_CENTER_SERVER_CERT_PATH` / `_KEY_PATH`，须成对配）。
- 依赖：`wist-contracts`（0.2）/ `rcgen` / `x509-parser` / `rustls` / `rustls-pki-types` / `tokio-rustls` / `hyper` / `hyper-util`。

### Fixed
- 注册前先校验 CSR 可解析：坏 CSR 不再白白消耗一次性注册 token。
- CA-G 文件半在场（只有证书或只有私钥）报错，不自动重生（避免换 CA 使已签证书全部失效）。
