# 更新日志

本文件记录 `wist-center` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

> 说明：0.4.0 之前未单独维护本文件；自 0.4.0 起记录。

## [0.19.3-alpha] - 2026-10-20

### 新增

- **失败任务的日志内容随回执入库、并在管理面展示**（契约：`wist-control 0.16.1`）：
  - `POST /api/v1/gateway/upgrade-result` 接收 `log_dir` / `log_excerpt`（都可选）；
    `log_dir` 优先用结构化字段，老网关继续从 `detail` 里的 `日志: <dir>` 考底解析。
  - 计划条目的 `entries[]` 多一个 `log_excerpt`（空值不序列化，老数据不变形）。
  - `POST /api/v1/gateway/commands/{id}/result` 同样接收两个字段，落 `gateway_commands`
    的 `log_dir` / `log_excerpt` 列；上游没给 body 时，回给调用方（WarpStation）的
    `upstream_error` 里也会带这两个字段 —— 否则它只能看到一句错误。
- **服务端第二道闸**：上报的摘要超过 16 KiB 就按字符边界截断（不信任上报方的大小）。
- `gateway_commands` 加两列；老库由 `ALTER TABLE ... IF NOT EXISTS` 自动补。

### 测试

新增：失败响应带 `log_dir` / `log_excerpt`、成功响应**原样透传**（不往机器载荷里塞字段）、
条目视图暴露摘要且空值不出现、摘要有界且不切坏 UTF-8。全量 `223 passed`（2 ignored）。

## [0.19.2-alpha] - 2026-10-20

### 新增

- **升级任务日志目录进结构化字段**：网关回执的 `detail` 末尾（gwlinkd 以 `；日志: <dir>` 追加）
  在中心归一化成 `log_dir`，随 `GET /api/v1/admin/rollout-plans/{id}` 的 `entries[]` 返回
  （字段名 `log_dir`，`None` 时省略）。上报协议不变 —— 等 gwlinkd 的
  `ReportGatewayUpgradeResult.log_dir` 上线后，这个解析降为兜底。
- 条目记录 `UpgradePlanEntryRecord` 增加 `log_dir`（`#[serde(default)]`，旧数据兼容）。

## [0.19.1-alpha] - 2026-10-20

### 修复

- **网关面把制品下载也挡成了 404**：0.19.0 的面分离把公网 listener 收窄成
  `/api/v1/gateway/**` + `/api/v1/version`，漏掉了 `GET
  /api/v1/releases/artifact/{component}/{version}/{filename}`（gwlinkd 升级、网关侧任何制品下载
  都走它）。表现：文件确实在 `artifacts/` 里，但请求返回 `HTTP 404`，
  `gops`/gwlinkd 报「取制品失败 … returned HTTP 404 Not Found」。
  管理面同样不放行该前缀，于是两个 listener 都没人服务这条路由。
  现在把 `/api/v1/releases/artifact/` 纳入**网关面**白名单；管理面仍不暴露（浏览器不需要）。
  路径段校验仍在路由层（拒 `..`、分隔符、非法段）。

## [0.19.0-alpha] - 2026-10-20

### 新增

- **管理面与网关面拆成两个监听器**（`[server].admin_addr`）：
  - 网关面（`listen_addr`）只挂 `/api/v1/gateway/**` + `/api/v1/version`，保留 mTLS；
  - 管理面（`admin_addr`）只挂 `/api/v1/admin/**` + `/api/v1/version`，不校客户端证书；
  - 两侧路由**白名单互斥、默认拒绝**：未登记的路径在两个面都返回 404，新增路由不会自动泄露到公网；
  - 不配 `admin_addr` = 保持旧行为（单监听器），向后兼容。

### 安全

- 即使 `admin_token` 泄露，攻击面也不再包含公网 listener 上的管理 API。

## [0.18.1-alpha] - 2026-10-19

### 变更

- **发布镜像改为原生分架构构建**：amd64 / arm64 分别在对应架构的 runner 上构建，
  再用 manifest 合并，彻底去掉 QEMU 模拟。镜像阶段从约 11 分钟降到 1–2 分钟。
- **运行时镜像瘦身**：基础镜像从 `ubuntu:24.04` + `apt-get` 改为 `alpine` + `ca-certificates`，
  镜像体积约 184MB → 50MB；release 二进制开启 `strip`（约 29MB → 18MB）。
- **TCR 推送拆分**：先出 ghcr 多架构 manifest，再单独复制到腾讯云 TCR，
  单架构构建不再被跨 registry 上传拖慢。

## [0.18.0-alpha] - 2026-10-19

### 新增

- **规则发布兼容入口 `[wparse_proxy]`**：WarpStation 可以通过中心代理，把规则/配置发布到
  **不开放入站端口**的网关。中心提供独立 HTTPS listener（默认 `0.0.0.0:3101`）与命令队列，
  网关侧由 gwlinkd 短轮询取命令并调用本机 wparse 管理面。
- **proxy token 管理**：`POST/DELETE /api/v1/admin/gateways/{gateway_id}/wparse-proxy-token`；
  只存 SHA-256，签发/轮换后旧 token 立即失效，明文只在签发时返回一次。
- **网关命令通道（mTLS）**：`GET /api/v1/gateway/commands`（原子租约）、
  `POST /api/v1/gateway/commands/{command_id}/result`（结果回传），证书身份与命令归属强绑定。
- **发布请求校验与保护**：`group ∈ {models, infra}`、`update=true`、版本号白名单；
  同一 `(gateway, version, group)` 的 reload 幂等复用；每网关 60 次/分钟限流、
  最多 32 条在途命令（超限 429），pending 60s 过期、租约 30s、最多重试 1 次。

### 修复

- `packages.sources` 配置归一化改为 let-chain 写法，消除 `clippy::collapsible_if` /
  `clippy::let_and_return` 告警（行为不变）。

### 测试

- 新增 19 个测试（token 轮换/撤销、租约与唤醒、幂等、pending 过期、队列上限、限流窗口、
  HTTP handler 级 401/400/422/429/回传）。全量 212 passed / 2 ignored。

## [0.17.2-alpha] - 2026-10-18

### 新增

- **安装包来源配置 `[packages.sources]`**：每个组件可配 `github_repo` 与/或
  `cos_bucket` / `cos_prefix` / `cos_region`。录入页据此按**版本号**拼地址，不再每次填完整 URL。
  （只写位置，不写凭据；未配的组件仍可手工粘贴地址。）
- **`GET /api/v1/admin/package-sources`**：列出已配置来源（管理面）。
- **`GET /api/v1/admin/package-sources/latest?component=&base_version=&source=`**：自动探测最新版本。
  优先列 GitHub releases（前 20 条）；只有 COS 时从 `base_version` 按 patch/minor/major 生成候选探测。

### 修复

- **未配置/非法的来源不再落成 502**：先校验来源与配置（未知 `source`、未配 `github_repo` /
  COS 桶前缀直接 400 + `package_source_*` 错误码），再发起外部请求。
- **GitHub tag 兼容带/不带 `v`**：解析 release 两种写法都试（仅 404 时重试）。
- **COS 制品 key 覆盖真实命名**：`v` / 裸版本 × 平台制品 × 单制品全组合。
- **配置归一化拒绝改 URL 语义的字符**：`cos_bucket` / `cos_region` 拒 `/ @ :` 与空白，
  `cos_prefix` 去掉首尾斜杠并拒 `? #`。

### 测试

- 新增：来源列表、管理员鉴权、先校验后探测（189 → 193 passed）。

## [0.17.1-alpha] - 2026-10-18

### 修复

- **建升级计划时 `target_version` 必填**：已知动作（`upgrade` / `push-agent-package` /
  `push-knowledge-package`）的每个 target 必须带非空版本，否则返回 400（`invalid_spec`）。
  中心按 `(component, target_version)` 派生制品地址 —— 版本留空则永远发不出去：
  计划下发后网关无事可做，条目永远停在 `dispatched`（现场表现为「中心没有反馈」）。
  未知动作不校验（形状可能不同，gwlinkd 会跳过并留痕）。

### 测试

- `build_plan_requires_a_target_version_for_known_actions`：空版本 / 空 targets / 非 JSON 均拒；
  未知动作保持宽容。

## [0.17.0-alpha] - 2026-10-18

### 新增

- **网关宿主依赖工具版本可见**：`ReportGatewayStatus` 带上的 `gops_version` / `gx_version` 现在落库到
  `gateways`（幂等补列，老库自动加），并随 `GatewayRuntimeStatus` 回到管理面；
  同时出 Prometheus `gateway_gops_info` / `gateway_gx_info`（有值才推）。
  - 为什么由 gwlinkd 探：网关栈由 gops 部署/升级，但容器里看不见宿主 `$HOME/bin`；
    只有宿主侧常驻能探到。页面「网关详情」的 gops / gx 两个读数就来自这里。

### 升级顺序

- 先升 **control 0.16**（字段定义）与 **gateway 0.17**（心跳接收），再升本中心与 gwlinkd 0.14。
- 老 gwlinkd 不带这两个键 → 落 NULL，页面显示「—」，不冒充已安装。

## [0.16.0-alpha] - 2026-10-18

### 新增

- **知识库包管理与下发**：中心把 `wist-knowledge` 当**单制品发布**（复用现有 release 通道：
  `POST/GET /api/v1/admin/releases/wist-knowledge`），新增灰度计划动作
  `push-knowledge-package`。
  - 计划从**已发布的 release 记录**派生 `artifact_url` / `artifact_sha256`（不手输）；
  - `activate`（spec 里的可选字段，缺省 false）随计划下发 —— 知识库**录入 ≠ 生效**；
  - 知识库是单制品：不带多平台清单（`artifacts` 为空）。
- **知识库签名旁文件随包镜像**：发布 `wist-knowledge` 时把 `<来源>.sig` 一并存到中心制品存储，
  使 `<镜像地址>.sig` 可取 —— gwlinkd 交付时会把 `.sig` 落到网关投放目录，配了验签公钥的
  网关才能验签。取不到只告警，不阻断发布。

### 升级顺序

- **先升网关（≥ 0.16.0）与 gwlinkd（≥ 0.13.0），再升中心**：
  - 旧网关没有 `/api/v1/gateway/knowledge-package`（交付会 404，计划条目标 failed）；
  - **旧 gwlinkd 会把 `push-knowledge-package` 当 `upgrade` 执行**，把知识库包当网关包去跑 gops。
- 中心与前端升完后，在「发布计划」页创建知识库下发。

## [0.15.1-alpha] - 2026-10-17

### 修复

- **安装脚本里的升级执行器改为绝对路径**：`install-all` / `install-linkd` 生成 gwlinkd 配置时，
  `GWLINKD_UPGRADER_PROGRAM` 不再写相对名 `gops`，而是 `$INSTALL_DIR/gops` / `type -P gops` 的结果。
  修复 gwlinkd 作为 launchd / systemd 服务运行时 PATH 不含 `~/bin`，升级计划以
  `启动升级执行器 gops 失败: No such file or directory (os error 2)` 落失败。
- **「只装 gwlinkd」脚本头两行误用 `//` 注释**：`curl ... | bash` 时会执行成 `//: is a directory`。
  改成 `#`，并加契约测试禁止生成脚本里出现 `//` 注释。

### 升级注意

- 已部署的网关若要立即生效，重跑一次「只装 gwlinkd」或「全量安装」脚本即可；
  或把 `upgrader_program` 配成 `gops` 的绝对路径。

## [0.15.0-alpha] - 2026-10-17

### 新增

- **手动升级脚本端点**：`POST /api/v1/admin/gateways/{gateway_id}/upgrade-script` —— 按组件 +
  版本命名生成一条 **`curl ... | bash`** 命令（Admin Bearer；URL 带 30 分钟 HMAC 短命签名，
  不塞 admin token）。新增网关面 `GET /api/v1/gateway/upgrade-script` 验签后直接回脚本。
  支持 `gwlink` / `gateway-stack` 别名；`wist-gwlinkd` 复用首次安装逻辑并钉住请求版本，
  `wist-gateway-stack` 下载校验后执行 `gops prj upgrade`。只生成命令/脚本，不建计划、不下发任务。

## [0.14.0-alpha] - 2026-10-17

### 变更

- **gwlinkd 升级计划带摘要**：中心为 `wist-gwlinkd` 的 ① 计划带上 `artifact_sha256`（其余 ① 组件仍不带），
  供宿主侧自更新在覆盖前校验 —— 与地址同源（release 记录）。
- **`install-all` / `install-linkd` 的 gwlinkd 安装布局改为可自更新**：真实二进制落
  `/usr/local/lib/wist-gwlinkd/wist-gwlinkd`（**目录与文件都归运行用户**），
  `/usr/local/bin/wist-gwlinkd` 留符号链接。
  root 拥有的 `/usr/local/bin` 无法被非 root 常驻就地覆盖（原子 rename 需要目录可写）；
  重跑安装脚本即完成迁移。

### 升级注意

- **首次启用 gwlinkd 自更新要先重跑一次安装脚本**：旧 gwlinkd 不认识自更新组件，升级计划会失败；
  重跑后两者同时到位（新本体 + 可写布局）。

## [0.13.0-alpha] - 2026-10-15

### 新增

- **管理面「录入安装包」支持腾讯云 COS 路径一键填充**：`POST /api/v1/admin/cos/resolve` —— 输入
  `bucket/组件/版本`（或 `cos://…` / 带 region 的下载地址）即返回该版本的各平台制品地址 / sha256 / 平台。
  无凭据：按发布命名约定拼对象地址、匿名 `HEAD` 校验并读回 `x-cos-meta-artifact-sha256`（region 未指定逐个试）。
- **网关安装脚本拆出「只装宿主侧 gwlinkd」**：`GET /api/v1/gateway/install-linkd` —— 网关本体已部署时，
  只补装 / 重装宿主侧 `wist-gwlinkd`（一次性接入券鉴权）。

### 变更

- **安装脚本端点改名**：`/api/v1/gateway/install-script` → **`/api/v1/gateway/install-all`**（语义 = 全量安装）。
- **安装材料字段同步改名 / 新增**：`install_script_command` → `install_all_command`，并新增 `install_linkd_command`。
- **错误码改名**：`install_script_unavailable` → **`install_all_unavailable`**；另新增 `cos_path_required` / `cos_resolve_failed`。

### 升级注意

- **需与前端 `wist-center-web >= 0.5.0-alpha` 配套**：页面已改用新端点与新字段 —— 后端与页面不同版会出现
  「拿不到安装命令」。旧端点 / 旧错误码**不再提供**（调用方需同步改）。

## [0.12.2-alpha] - 2026-10-14

### 变更

- **制品推送到 COS 时自带 sha256**：上传的每个对象带自定义元数据 `x-cos-meta-artifact-sha256`
  （COS 只存 MD5 ETag，GitHub 资产摘要过不来）；可用 `coscli stat`（HEAD）读回。`x-cos-meta-`
  是 COS 对自定义元数据的强制前缀。

## [0.12.1-alpha] - 2026-10-13

### 变更

- **发布时可选把制品推送到腾讯云 COS**：打 tag 时新增 `upload-cos` job，把各平台 tarball 上传到
  `cos://<桶>/wist-center/<tag>/` 与 `.../latest/`（未配置 `COS_BUCKET` 时自动跳过，不影响发布）。

## [0.12.0-alpha] - 2026-10-13

### 变更

- **去掉 `~/.wist-center/` 这个隐藏默认落点**：中心配置与 CA 路径不再依赖 `$HOME/.wist-center/`。
  - 默认配置文件：`~/.wist-center/wist-center.toml` → **当前目录的 `wist-center.toml`**（与 gateway 同口径）；
  - 控制中心 CA（`security.ca_cert_path` 的默认）→ **`<配置目录>/ca/control-center.pem`**；
  - 网关客户端 CA（**CA-G** 的默认）→ **`<配置目录>/ca/gateway-client-ca.{pem,key.pem}`**。
  于是发布态只需把站点身份目录只读挂到 `<配置目录>/ca` 即可 —— CA-G **存在就只读加载、不写盘**。
  模板 / 示例的 `ca_cert_path` 改为相对写法 `ca/control-center.pem`。
- **网关安装脚本**：目标机侧存中心 CA 的 `$HOME/.wist-center/ca` → **`$HOME/.wist/ca`**。

### 修复

- **容器内 `$HOME` 不可写导致启动崩溃**：中心默认在 `$HOME/.wist-center/ca` 生成 CA-G，而镜像里
  `wist` 是系统用户、`/home/wist` 不存在且 `/home` 属 root → `failed to create /home/wist/.wist-center/ca:
  Permission denied`（容器反复重启、`/api` 拿不到）。改为「配置目录」基准后，只要把 CA-G 放进
  `<配置目录>/ca`（发布态 = 只读挂载的 `identity/center/`）就不再尝试写盘，崩溃从根上消失。

## [0.11.0-alpha] - 2026-10-13

### 新增

- **公开版本端点 `GET /api/v1/version`**（**无鉴权**）：返回编译期版本（`CARGO_PKG_VERSION`），
  供页面左下角常驻显示「前端 + 后端」两个版本号（未登录也要能看）。与网关侧同口径。

### 变更

- **网关安装脚本（`curl … | bash`）适配 gwlinkd 配置分层**（需 `wist-gwlinkd >= 0.9.0`）：
  现场选择写进 values 后由 `scripts/init-gwlinkd-pub.sh` 按缺写入 `identity/gwlinkd/pub.env`
  （**`.env` 形态**的现场态，升级 / 重渲**永不覆盖**）；新增 `GWLINKD_IDENTITY_DIR`，中心信任锚路径改为
  `identity/gwlinkd/control-center.pem`；网关环回面信任锚 `GATEWAY_SELF_CA` 随身份归位改指
  `identity/gateway/public/gateway-ca.crt.pem`（旧值指向已废弃的 `configs/gateway/state/gateway-ca.crt.pem`，
  会让 gwlinkd 启动即报「读取信任锚失败」）；`service install` 追加 `--pub-config`（否则进程拿不到现场态路径，
  会报“未接入上级”）。
- **配置分层（三文件 recipe，对齐 `foundation/layered-config-recipe.md`）**：站点事实
  `[server] public_url` 从主配置改成**现场态**，按「声明 / 值」分开：声明 `wist-center-pub.toml`
  只写 `${VAR}` 引用、不含值（可随版本重渲）；真值在同目录 `.env`（唯一写者，绝不重渲）。
  加载改用共享 crate **`wist-config`**（`LayerSpec` + `load_layered_toml`）：「进程环境 > 同目录 `.env`」
  插值 `${VAR}` → 与主配置**无重复叶子**合并；未定义且无默认 → 拒启。
  `init-config` 一并写出声明 + `.env` 骨架；`wist-center.toml` 模板与 `examples/local-dev.toml` 去掉
  `public_url`。注：旧现场若主配置仍带 `public_url`，与声明撞键会**拒启** —— 重渲一次主配置即可。
  env `WARP_INSIGHT_CENTER_PUBLIC_URL` 仍可覆盖。

## [0.10.0-alpha] - 2026-10-11

### 变更

- **运行日志改用共享 crate `wist-log`**：删掉本仓 `logging.rs`，`[log]` 段统一由 `wist_log::init`
  装配（级别 / 格式 / 落点 / 轮转），与 gateway / gwlinkd / agentd 同口径；键名规范为 `max_seconds`
  （旧名 `max_age_seconds` 以 alias 继续接受）。依赖同时收 `wist-release 0.6`（新增安装包**包名**
  解析，本仓发布校验的「组件 ↔ 包」一致性用它）。
- **配置支持从密钥文件解析 `${SEC_...}`**：引入 `orion-sec` / `orion-variate`，配置文件里的
  `${VAR}` / `${VAR:default}` 由 `secret_dict()`（进程环境变量优先，其次密钥文件）解析；密钥类值
  推荐写 `${SEC_...}`，从 `WIST_CENTER_SEC_FILE` 指向的密钥文件（YAML，键自动规范成 `SEC_<UPPER>`）
  取，默认 `./.galaxy/sec_value.yml` / `~/.galaxy/sec_value.yml`。**未解析的占位符 fail-closed**
  （拒绝启动，不把 `${SEC_...}` 当字面值用）；显式指定的密钥文件缺失 → 明确报错。
  如此 `admin_token` / `hmac_secret` 不再以明文写进配置文件。

### 移除

- **移除环境变量 `WARP_INSIGHT_CENTER_ADMIN_TOKEN`**：管理 token（`server.admin_token`）不再有
  env 覆盖，**唯一来源是配置文件**（生产/栈里写 `${SEC_CENTER_ADMIN_TOKEN}`，由密钥文件解析）。
  避免“文件与 env 两份值不一致、到底哪份生效”的踩坑。注：配置文件里的 `${VAR}` 仍可按名字
  从**进程环境变量**展开（orion-sec 机制），但不再有专门的 admin token env 覆盖。
  **破坏性**：依赖该 env 的部署/脚本需改为写配置文件。

## [0.9.0-alpha] - 2026-10-10

### 新增

- **网关归档 / 取消归档**：`POST /api/v1/admin/gateways/{gateway_id}/archive` —— 归档是**标记**
  （默认视图隐藏、历史保留、可一键恢复），仅允许归档**离线**网关；在线网关拒绝（要停先在网关上停）。
- **重派失败的升级目标**：`POST /api/v1/admin/rollout-plans/retry` —— 把一份失败计划里的失败目标
  重派成**一份新计划**（新 `plan_id`、单阶段、直接放行）。必须新建而非改回原计划：网关按 `plan_id`
  去重，改状态是「假重试」（网关永不重跑）；原计划原样留作历史。
- **前置环境准备脚本**：`GET /api/v1/gateway/prepare-script` —— 公开、无令牌的 `curl ... | bash`，
  补齐 `tar` / `docker` / `docker compose` 等依赖，可先于安装单独跑。

> 本版**实际随包**包含 0.8.0 变更记录中已宣告、但未随 0.8.0 制品一起发布的安装脚本能力
> （`GET /api/v1/gateway/install-script` + 宿主侧 `wist-gwlinkd` + 制品 sha256 校验）。

### 变更

- **运行日志配置化（`[log]` 段）+ 全量接入 `log` facade**：新增 `[log]`（`level` 过滤器指令、
  `format` `text`|`json`、`file` 写文件、`max_bytes`/`keep_files`/`max_age_seconds` 自轮转；相对路径
  按配置目录解析），优先级 **`RUST_LOG` > `[log] level` > 缺省 `info`**。启动 / 监听 / TLS 握手与
  连接失败 / 各面诊断从 `println!` / `eprintln!` 改走 `log`（缺省 stderr，交给容器 / journald；
  配了 `file` 就写文件并自轮转，**不要再挂 logrotate**）。日志在读到配置之后初始化；配置读不了
  时退 stderr，并打印**完整因果链**（不再只出 `Debug`）。
- **5xx 不再回内部细节**：500 / 502 的响应体只出通用话术，SQL / 路径 / 上游报错等移进 `log::error!`
  （完整因果链），避免把库内细节暴露给调用方；4xx 仍是明确的客户端错误文案。
- **错误响应统一为 `{ "error": { code, message, … } }` 信封 + 稳定错误码词表**：中心这一层
  此前是裸 `(StatusCode, String)`。现全部走 `api::error::ApiError`，`code` 来自唯一词表 `api::codes`
  （网关面 / 发布 / 灰度 / 安装脚本 / 鉴权 / 限流各域）；`severity` / `retryable` 按 status 默认填。
  **破坏性（wire）**：错误体不再是纯文本 —— 消费方（网关 / gwlinkd / 管理前端）改按 `error.message`
  / `error.code` 解析（网关侧按子串判 401 子原因仍兼容）。
- **非 handler 错误也走同一信封**：未命中路由（`404` `route_not_found`）、方法不允许（`405`
  `method_not_allowed`）、请求体 / 查询参数反序列化失败（`invalid_request_body` / `invalid_query`）
  此前绕过信封（axum 默认空体 / 纯文本且不落日志）—— 现统一折成 `ApiError`，并落 `log::warn!`。
- **灰度建计划的校验错误按具体原因给码**：`invalid_action` / `invalid_spec` / `invalid_deadline` /
  `invalid_timeout` / `invalid_phase_plan` / `no_failed_targets`（此前一律 `invalid_rollout_plan`，
  消费方无法按原因分支）。
- **一次性凭据 / 配置类响应加 `Cache-Control: no-store`**：`regist_token` / `link_token` / 客户端证书
  bundle / 初始化配置等只应交付一次的内容，以及相关 401（网关身份 / 接入券 / 管理 token）均不得被缓存。
- **瞬时上游故障的日志降噪**：`502` / `503` / `504`（依赖不可用 / 超时，接收方重试即可）改记
  `log::warn!`，不再与真 `500` 同级。

## [0.8.0-alpha] - 2026-10-09

### 新增

- **脚本安装命令内置宿主侧 `wist-gwlinkd`**：`GET /api/v1/gateway/install-script` 生成的脚本在拉起
  gops/gx 与 gateway-stack 之后，按宿主平台从中心**最新已发布**制品取 `wist-gwlinkd`：装到
  `/usr/local/bin`、配置/身份放**部署用户**家目录 `~/.wist-gwlinkd/`（`control_center_endpoint`=中心、
  `trust_bundle`=中心 CA、`gateway_self_endpoint`/`gateway_self_ca`=网关环回自述面、`upgrade_project_dir`=工程根），
  再用 `wist-gwlinkd service install --system --run-as <部署用户>` 装成**系统级、非 root 运行**的
  常驻服务（开机自启 / 崩溃拉起；身份回写与 gops 升级都落在部署用户属主下）—— 一条命令即让新网关
  既起得来、又能接入中心。`wist-gwlinkd` **未发布时不阻塞**：脚本照常生成，只跳过该步并明确提示。
- **制品下载改为带 sha256 校验**：安装脚本对 gops / gx / gwlinkd 的下载都按中心制品摘要校验
  （无 `sha256sum`/`shasum` 时跳过并提示），不再只靠 TLS 传输完整。
- **发布② 「Agent 包下发」回带多平台清单**：`GET /api/v1/gateway/upgrade-plan` 在 `action=push-agent-package`
  时回带 `artifacts`（该版本**全部平台**的 `{platform, artifact_url, artifact_sha256}`；按平台名归一化去重、
  同平台取最新、跳过缺摘要/无平台的记录），供 gwlinkd 把各平台包一并交付网关托管（机队平台可 ≠ 网关主机平台）；
  ① 升级仍用单值 `artifact_url`。契约 `wist-control 0.13.0`。见设计 `edge/agent-package-push-to-gateways.md`。

### 变更

- **对齐生态版本**：`wist-control` `0.13 → 0.14`（连带 `wist-shared` `0.1 → 0.2`）、
  `wist-error` `0.1 → 0.2`（连带 `orion-error` `0.8 → 0.9`）。纯版本 pin，无行为变更。

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
