# 更新日志

本文件记录 `wist-center` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 说明：0.4.0 之前未单独维护本文件；自 0.4.0 起记录。

## [0.4.0] - 2026-10-04

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
