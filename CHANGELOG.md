# 更新日志

本文件记录 `wist-center` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 说明：0.4.0 之前未单独维护本文件；自 0.4.0 起记录。

## [未发布]

### 新增

- **发布② 「Agent 包下发」回带多平台清单**：`GET /api/v1/gateway/upgrade-plan` 在 `action=push-agent-package`
  时回带 `artifacts`（该版本**全部平台**的 `{platform, artifact_url, artifact_sha256}`；按平台名归一化去重、
  同平台取最新、跳过缺摘要/无平台的记录），供 gwlinkd 把各平台包一并交付网关托管（机队平台可 ≠ 网关主机平台）；
  ① 升级仍用单值 `artifact_url`。契约 `wist-control 0.13.0`。见设计 `edge/agent-package-push-to-gateways.md`。

### 修复

- **下架（`expired`）的版本不再派发**：① 升级与 ② 包下发的制品解析都跳过 `status == "expired"` 的 release
  记录（只跳过**显式** `expired`，历史缺省状态视为可派发）—— 避免把已下架的制品派给网关。

## [0.7.1-alpha] - 2026-10-08

### 修复

- **升级计划按平台派生制品地址**：`GET /api/v1/gateway/upgrade-plan` 新增可选 query `platform`
  （网关自述 target-triple）。多平台组件（`galaxy-ops` / `galaxy-flow` 一次发 macOS-ARM +
  Linux x86_64/ARM64）此前按 `(component, version)` 反查只取**第一条**记录 —— 会把 Linux 制品
  派给 macOS 网关，网关侧架构护栏拒装（`架构校验失败，未覆盖 gops：制品操作系统 linux 与本机 macos 不符`）。
  现在按 完整三元组 ＞ 同平台家族（忽略 gnu/musl）＞ 无平台概念的包 挑，挑不到就不带地址
  （回落版本），绝不派错平台。老网关不声明 `platform` 时只在「唯一候选 / 无平台概念的包」时派生。

### 变更

- **Linux 制品改为静态 musl**：发布矩阵从 `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu`
  收敛为 `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl`（macOS 仍 `aarch64-apple-darwin`），
  构建时装 `musl-tools` 并把 C 依赖（`ring` / rustls 的 aws-lc-rs）的 `CC`/链接器指向 `musl-gcc`，产出**静态链接**二进制。
  docker 作业（多架构镜像）随之改取 musl 制品（`staged` / 解包文件名同步）。满足控制中心「三平台、不出现 glibc」的平台集。

## [0.7.0-alpha] - 2026-10-07

### 变更

- **发布包摘要（`expected_sha256`）改为必填**：`POST /api/v1/admin/releases/:component` 缺摘要即 400
  （请求体不合契约时为 422）——不再「不给就只记算出的摘要」，包没有可校验的摘要就不收。

## [0.6.0-alpha] - 2026-10-07

### 变更

- **灰度发布计划在中心落地（`Control.Rollout`）**：管理面入口统一为 `/api/v1/admin/rollout-plans`
  （创建/列出/批准/推进/查看；阶段仍由服务端按阶梯切）。计划只存「动作 + 参数（`spec`）+ 阶段 +
  逐目标条目」；网关拉取（`GET /api/v1/gateway/upgrade-plan`）时把本阶段条目标 `dispatched`，
  结果回执回填条目并按闸门推进；末阶段有失败落 `failed`、否则 `completed`。
- **回执状态归一化**：网关上报的 `done` / `rolled_back` / `unverified` 归一为 `succeeded` / `failed`。
  此前只认 `succeeded`/`failed`，导致升级**成功后**计划卡在 `rolling`（口径在共享 crate
  `wist-release::rollout::entry_status_for`）。
- 旧记录（`pending/approved` + `steps` + `targets`）读取时自动折算成新形状（幂等）。

## [0.5.7-alpha] - 2026-10-06

### 变更

- **升级计划的灰度阶段改为服务端算**：创建计划不再由客户端传 `steps`，只传 `phase_count`，中心按
  固定阶梯（1 个金丝雀 → 10% → 30% → 70% → 全量）切出**互不重叠、一把铺满**的阶段。
  口径来自共享 crate `wist-release::rollout`（中心与网关同一份）—— 这也是该模块第一个 Rust 消费方：
  以前阶梯只活在前端预览里，「阶段互不重叠」只在界面上成立。
  - 请求体**破坏性变更**：`steps` → `phase_count`（`1` = 不分批、一把到位）。
  - 阶段数不可用（`0` / 大于台数 / 目标为空）→ **400**，不再是安静地给一个空阶段。
  - `step_index` 改为从 **1** 起（与网关侧 `phase_index` 同口径）。

## [0.5.6-alpha] - 2026-10-06

### 安全

- **堵住制品路径穿越**。`component` / `version` / `filename` 会拼进
  `{artifact_dir}/{component}/{version}/{filename}` 与对象存储 key，此前**未做任何校验**：
  `component = ..` 能逃出制品目录。现在：
  - 管理面发布对 `component` / `version` 不是「安全路径段」直接 **400**；
  - **未鉴权**的制品下载路由对三段任一不安全一律 **404**（不再区分 400/404，不给探测者 oracle；
    `%2F` 解出来的分隔符同样被拒）—— 这条最重：它等价于任意文件读；
  - 存储层再兜一道（不依赖调用方记得校验）。

  判据统一取自共享 crate 的 `is_safe_path_segment`。

### 变更

- 安装包内核改由共享 crate **`wist-release` 0.2** 提供（此前内联在本仓，与网关各一份）：取包 /
  摘要 / 身份解析 / 命名 / 路径段校验都只有一份实现。两处**修正性**行为变化：本机路径来源现在
  也受大小上限（此前只有 http 分支拦）；版本比对认大写 `V` 前缀（此前包内自报 `V1.2.3` 与手输
  `v1.2.3` 会被误判成版本不符）。

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
