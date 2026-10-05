# 更新日志

本文件记录 `wist-center` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 说明：0.4.0 之前未单独维护本文件；自 0.4.0 起记录。

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
