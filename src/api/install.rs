// 网关「全量安装」：GET /api/v1/gateway/install-all?gateway_id=<id>&token=<token>
//
// 面向脚本安装形态的网关实例：中心生成一段可直接 `curl ... | bash` 的安装脚本，脚本在目标主机上
// 把 gops / gx（取中心**最新已发布**制品）装好，再用它们拉取并启动 gateway-stack：
//   a) 下载并安装 center 最新的 gops / gx 包；
//   b) `gops prj new` 生成新工程；
//   c) `gops prj import` 导入最新 gateway-stack 包；
//   c.1) 设定网关对外域名 `WEB_DOMAIN`（全新安装必需：站点证书 SAN + 网关 public_base_url 的 host）；
//   d) `gops sys localize`；
//   e) `gops run download`；
//   f) `gops run start`；
//   g) 装宿主侧 `wist-gwlinkd`（把本网关接入中心；系统服务常驻）。
//
// 鉴权：URL 里携带的一次性接入券（LINK_TOKEN，与「链接上级」同一张、短 TTL、中心只存 hash）。
// 本端点**只校验不消费** —— 券仍留给随后的 link-upstream 使用（本脚本不做接入）。

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::infra::{ReleasePackageRecord, group_release_packages, normalize_version, sha256_hex};

use super::{
    ApiState, PeerConnectInfo, admin_auth, codes,
    error::ApiError,
    extract::{ApiJson, ApiQuery},
    rate_limit,
};

/// 全量安装端点限流桶：token 在 URL 里，独立桶防暴力枚举。
const GATEWAY_INSTALL_ALL_SCOPE: &str = "gateway-install-all";
/// 手动升级脚本（网关面，短命签名）限流桶。
const GATEWAY_UPGRADE_SCRIPT_SCOPE: &str = "gateway-upgrade-script";
/// `curl ... | bash` 手动升级命令的有效期（秒）：够复制到网关宿主执行，又不长期可重放。
const GATEWAY_UPGRADE_SCRIPT_TTL_SECONDS: i64 = 30 * 60;

/// 需要解析「最新已发布」制品的组件：gops、gx、部署栈、宿主接入器。
const GOPS_COMPONENT: &str = "galaxy-ops";
const GX_COMPONENT: &str = "galaxy-flow";
const STACK_COMPONENT: &str = "wist-gateway-stack";
/// 宿主侧接入器：装了它网关才能接入中心（页面路「链接上级」）。
/// **可选**：未发布时脚本仍生成，只是跳过这一步并明确提示（不阻塞网关本体安装）。
const GWLINKD_COMPONENT: &str = "wist-gwlinkd";

/// 脚本安装查询参数：`gateway_id` + 一次性 `token`（+ 可选 `domain`）。
#[derive(serde::Deserialize)]
pub struct InstallScriptQueryParams {
    pub gateway_id: String,
    #[serde(default)]
    pub token: Option<String>,
    /// 网关对外域名（`WEB_DOMAIN`）：全新安装必须先设定；可在这里预置，否则脚本运行时再解析。
    #[serde(default)]
    pub domain: Option<String>,
}

/// 生成「全量安装」命令（放进安装指引，供 admin 页面展示/复制）。
/// 形如 `curl -fsSLk '<center>/api/v1/gateway/install-all?gateway_id=..&token=..' | bash`。
pub fn build_install_all_command(public_url: &str, gateway_id: &str, link_token: &str) -> String {
    let endpoint = format!(
        "{}/api/v1/gateway/install-all?gateway_id={}&token={}",
        public_url.trim_end_matches('/'),
        url_encode(gateway_id),
        url_encode(link_token),
    );
    // -k：新主机尚不信任中心自签 CA，脚本下载走 TLS 传输即可（端点内容由一次性 token 限定）；
    // 与网关 docker 安装命令取同一口径。
    format!("curl -fsSLk '{endpoint}' | bash")
}

/// 取脚本：校验一次性接入券（只校验不消费）→ 解析最新制品 → 渲染脚本。
/// 取全量安装脚本：GET /api/v1/gateway/install-all（一次性接入券鉴权，返回 shell 脚本）。
pub async fn get_gateway_install_all(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    ApiQuery(params): ApiQuery<InstallScriptQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) =
        rate_limit::check_rate_limit(&state, &client_key, GATEWAY_INSTALL_ALL_SCOPE)
    {
        return response;
    }
    // 一次性接入券：网关存在、券 hash 匹配、未过期。**只校验不消费**（券留给 link-upstream）。
    let (gateway_id, _token) = match validate_install_request(
        &state,
        &client_key,
        GATEWAY_INSTALL_ALL_SCOPE,
        params.gateway_id.as_str(),
        params.token.as_deref(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };

    let gops = match latest_published_package(&state, GOPS_COMPONENT).await {
        Ok(package) => package,
        Err(response) => return response,
    };
    let gx = match latest_published_package(&state, GX_COMPONENT).await {
        Ok(package) => package,
        Err(response) => return response,
    };
    let stack = match latest_published_package(&state, STACK_COMPONENT).await {
        Ok(package) => package,
        Err(response) => return response,
    };
    let (Some(gops), Some(gx), Some(stack)) = (gops, gx, stack) else {
        return super::error::ApiError::unavailable(super::codes::INSTALL_ALL_UNAVAILABLE, "install-all unavailable: publish galaxy-ops / galaxy-flow / wist-gateway-stack releases first")
            .into_response();
    };
    // 宿主接入器：**可选** —— 未发布时脚本照常生成，只是跳过这一步（见脚本内的可读提示）。
    let gwlinkd = match latest_published_package(&state, GWLINKD_COMPONENT).await {
        Ok(package) => package,
        Err(response) => return response,
    };

    let script = render_install_all_script(
        state.config.public_url.trim_end_matches('/'),
        &gateway_id,
        &gops,
        &gx,
        &stack,
        gwlinkd.as_ref(),
        sanitize_domain(params.domain.as_deref()),
        state.config.ca_cert.clone(),
    );
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    )
        .into_response()
}

/// 解析某组件**最新已发布**的安装包（`list_releases` 新→旧，取首个 `published`）。
#[allow(clippy::result_large_err)]
async fn latest_published_package(
    state: &ApiState,
    component: &str,
) -> Result<Option<ReleasePackageRecord>, Response> {
    let records = state.store.list_releases(component).await.map_err(|err| {
        super::error::internal_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            super::codes::RELEASE_LIST_FAILED,
            "failed to load releases",
            err.display_chain(),
        )
    })?;
    Ok(group_release_packages(component, records)
        .into_iter()
        .find(|package| package.status == "published"))
}

/// 券是否过期（RFC3339；`None` = 无过期时间 → 视为未过期）。
fn link_token_expired(expires_at: Option<&str>) -> bool {
    let Some(value) = expires_at else {
        return false;
    };
    match chrono::DateTime::parse_from_rfc3339(value) {
        Ok(expiry) => expiry.with_timezone(&chrono::Utc) <= chrono::Utc::now(),
        // 解析不出来（脏数据）按过期处理：宁可要求重新轮换。
        Err(_) => true,
    }
}

/// 渲染平台 → 制品地址的 `case` 分支（供脚本内按 `PLATFORM` 选件）。
fn platform_case_branches(package: &ReleasePackageRecord) -> String {
    let mut branches = String::new();
    for artifact in &package.package.artifacts {
        let Some(platform) = artifact.platform.as_deref() else {
            continue;
        };
        branches.push_str(&format!(
            "    {platform}) printf '%s' '{}' ;;\n",
            shell_single_quote_escape(&artifact.source)
        ));
    }
    branches
}

/// 渲染平台 → 制品 sha256 的 `case` 分支（供脚本内按 `PLATFORM` 校验下载）。
/// 与 [`platform_case_branches`] 同平台集；缺失摘要的制品不发分支（脚本会跳过校验）。
fn platform_sha_case_branches(package: &ReleasePackageRecord) -> String {
    let mut branches = String::new();
    for artifact in &package.package.artifacts {
        let Some(platform) = artifact.platform.as_deref() else {
            continue;
        };
        if artifact.sha256.is_empty() {
            continue;
        }
        branches.push_str(&format!(
            "    {platform}) printf '%s' '{}' ;;\n",
            shell_single_quote_escape(&artifact.sha256)
        ));
    }
    branches
}

/// 把字符串安全地放进 shell 单引号里（`'` → `'\''`）。
fn shell_single_quote_escape(value: &str) -> String {
    value.replace('\'', "'\\''")
}

/// 工程名 / 目录名清洗：只留 `[A-Za-z0-9._-]`，其余换 `-`。
fn sanitize_project_name(gateway_id: &str) -> String {
    let cleaned: String = gateway_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("gateway-{}", cleaned.trim_matches('-'))
}

/// URL query 值的最小编码（网关 ID / token 都只是字母数字与 `_.-`，其余转义）。
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// 全量安装脚本模板：用占位符替换（避免 `format!` 与 shell 花括号打架）。
const INSTALL_ALL_SCRIPT_TEMPLATE: &str = r#"#!/usr/bin/env bash
# WistCenter · 网关脚本安装（gateway_id=__GATEWAY_ID__）
#
# 由中心自动生成：装 gops / gx（取中心最新发布制品）→ gops prj new → prj import gateway-stack
# → sys localize → run download → run start → 装宿主侧 wist-gwlinkd（把本网关接入中心）。
set -euo pipefail

CENTER_URL='__CENTER_URL__'
GATEWAY_ID='__GATEWAY_ID__'
PROJECT_NAME='__PROJECT_NAME__'
INSTALL_DIR="${HOME}/bin"
CA_DIR="$HOME/.wist/ca"
CA_CENTER="$CA_DIR/control-center.pem"
CA_BUNDLE="$CA_DIR/ca-bundle.pem"

log() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }

mkdir -p "$INSTALL_DIR" "$CA_DIR"
export PATH="$INSTALL_DIR:$HOME/.local/bin:$PATH"

# 中心 CA（自签）：写盘，并组一个「系统根 + 中心CA」的 bundle 给 gops/gx/curl 验证。
# 注意：SSL_CERT_FILE 会**替换**系统根，所以要把系统 bundle 一起拼进去，否则 GitHub 等会验不过。
cat > "$CA_CENTER" <<'WIST_CENTER_CA_EOF'
__CENTER_CA_PEM__
WIST_CENTER_CA_EOF

if grep -q 'BEGIN CERTIFICATE' "$CA_CENTER" 2>/dev/null; then
  sys_bundle=''
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ -f "$f" ] && sys_bundle="$f" && break
  done
  if [ -n "$sys_bundle" ]; then cat "$sys_bundle" "$CA_CENTER" > "$CA_BUNDLE"; else cp "$CA_CENTER" "$CA_BUNDLE"; fi
  export SSL_CERT_FILE="$CA_BUNDLE"
  export CURL_CA_BUNDLE="$CA_BUNDLE"
  CURL_TLS=(--cacert "$CA_BUNDLE")
  log "已载入中心 CA（TLS 全程校验）：$CA_BUNDLE"
else
  CURL_TLS=(-k)
  log "中心未提供 CA（明文 / 未配 CA）→ curl 回退 -k"
fi

# 前置校验：先跑过「环境准备（prepare-script）」—— 缺 docker/compose 或解包工具就明确提示。
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "缺少 docker / docker compose —— 请先运行环境准备脚本：" >&2
  echo "  curl -fsSLk \"$CENTER_URL/api/v1/gateway/prepare-script\" | bash" >&2
  exit 1
fi
if ! command -v tar >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "缺少 tar 与 python3（至少一个用于解包）—— 请先运行环境准备脚本。" >&2
  exit 1
fi

# 平台探测 → target-triple（与中心制品的平台对齐）。
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)              PLATFORM='aarch64-apple-darwin' ;;
  Linux/x86_64)              PLATFORM='x86_64-unknown-linux-musl' ;;
  Linux/aarch64|Linux/arm64) PLATFORM='aarch64-unknown-linux-musl' ;;
  *) echo "unsupported platform: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

# a) 下载地址 / 摘要（按平台，取自中心最新发布）。
gops_url() {
  case "$PLATFORM" in
__GOPS_CASE__    *) return 1 ;;
  esac
}
gops_sha() {
  case "$PLATFORM" in
__GOPS_SHA_CASE__    *) return 1 ;;
  esac
}
gx_url() {
  case "$PLATFORM" in
__GX_CASE__    *) return 1 ;;
  esac
}
gx_sha() {
  case "$PLATFORM" in
__GX_SHA_CASE__    *) return 1 ;;
  esac
}
gwlinkd_url() {
  case "$PLATFORM" in
__GWLINKD_CASE__    *) return 1 ;;
  esac
}
gwlinkd_sha() {
  case "$PLATFORM" in
__GWLINKD_SHA_CASE__    *) return 1 ;;
  esac
}

# 本地 sha256（Linux: sha256sum；macOS: shasum）。
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else return 1; fi
}

# 下载 +（可选）校验 + 解包 + 安装一个组件。
#   install_component <name> <url> [sha256] [目标目录] [安装前缀: 空|sudo]
install_component() {
  name="$1"; url="$2"; want_sha="${3:-}"; dest="${4:-$INSTALL_DIR}"; use_sudo="${5:-}"
  d="$(mktemp -d)"
  log "下载 ${name}：$url"
  curl -fsSL "${CURL_TLS[@]}" "$url" -o "$d/pkg"
  if [ -n "$want_sha" ]; then
    have="$(sha256_of "$d/pkg" || true)"
    if [ -z "$have" ]; then
      log "提示：本机无 sha256sum/shasum，跳过 $name 的摘要校验"
    elif [ "$have" != "$want_sha" ]; then
      echo "下载校验失败 ${name}：期望 ${want_sha}，实际 $have" >&2
      rm -rf "$d"; return 1
    fi
  fi

  # 解包：先试 tar；部分文件系统（如 OrbStack virtiofs）上 GNU tar 会报
  # "Cannot open: Function not implemented"，回落到 python3 的 tarfile（走普通 open，不受影响）。
  tar -xzf "$d/pkg" -C "$d" 2>/dev/null || true
  bin="$(find "$d" -type f -name "$name" -print -quit 2>/dev/null)"
  if [ -z "$bin" ] && command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2])' "$d/pkg" "$d" 2>/dev/null || true
    bin="$(find "$d" -type f -name "$name" -print -quit 2>/dev/null)"
  fi
  if [ -n "$bin" ]; then
    $use_sudo install -m 0755 "$bin" "$dest/$name"
  elif [ -d "$d/artifacts" ]; then
    $use_sudo install -m 0755 "$d"/artifacts/* "$dest"/
  elif [ "$(head -c 2 "$d/pkg" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "1f8b" ]; then
    echo "解包 $name 失败（${url}）：tar 与 python3 均不可用？" >&2
    rm -rf "$d"; return 1
  else
    $use_sudo install -m 0755 "$d/pkg" "$dest/$name"
  fi
  rm -rf "$d"
}

# a) 安装 gops / gx（带摘要校验）
install_component gops "$(gops_url)" "$(gops_sha || true)"
install_component gx "$(gx_url)" "$(gx_sha || true)"
log "gops: $(gops --version 2>/dev/null || echo ok) · gx: $(gx --version 2>/dev/null || echo ok)"

# b) 生成新工程
log "gops prj new --name $PROJECT_NAME"
gops prj new --name "$PROJECT_NAME"
PROJECT_ROOT="$PWD/$PROJECT_NAME"
cd "$PROJECT_ROOT"

# c) 导入最新 gateway-stack
#    中心是自签 CA：gops 走系统/原生信任库（SSL_CERT_FILE=系统根+中心CA）验证，无需 -k、也无需先下本地。
log "gops prj import --path <gateway-stack>"
gops prj import --path '__STACK_URL__'

# c.1) 全新安装必须先设定网关对外域名（WEB_DOMAIN：站点证书 SAN + 网关 public_base_url 的 host）。
#      来源优先级：安装命令里带的 domain → 环境变量 GATEWAY_DOMAIN → 交互输入。
GATEWAY_DOMAIN="${GATEWAY_DOMAIN:-__DOMAIN__}"
if [ -z "$GATEWAY_DOMAIN" ] && [ -r /dev/tty ]; then
  printf '请输入网关对外域名（如 gw.example.com）: ' >/dev/tty
  read -r GATEWAY_DOMAIN </dev/tty || true
fi
if [ -z "$GATEWAY_DOMAIN" ]; then
  echo "缺少网关对外域名：请重跑并指定，如  curl ... | GATEWAY_DOMAIN=gw.example.com bash" >&2
  exit 1
fi
log "网关对外域名：$GATEWAY_DOMAIN"
STACK_DIR="$PROJECT_ROOT/wist-gateway-stack"
VALUES_FILE="values/wist-gateway-stack/sys_value.yml"

# 现场值统一写进 values（gops 的覆盖机制）：一份值，localize 时一致地烘进 .env / 配置 / 证书 SAN。
set_value() {
  local file="$1" key="$2" value="$3"
  mkdir -p "$(dirname "$file")"
  if grep -qE "^${key}:" "$file" 2>/dev/null; then
    sed -E "s|^${key}:.*|${key}: ${value}|" "$file" > "$file.tmp"
    mv "$file.tmp" "$file"
  else
    printf '%s: %s\n' "$key" "$value" >> "$file"
  fi
}
set_value "$VALUES_FILE" WEB_DOMAIN "$GATEWAY_DOMAIN"

# gwlinkd（宿主接入器）的接入面走同一份现场值 —— localize 会渲染进主配置（交付物），
# 而**现场选择**（中心地址 / 网关标识 / 中心信任锚）由 scripts/init-gwlinkd-pub.sh 按缺补齐到
# identity/gwlinkd/pub.toml（现场态，**升级/重渲永不覆盖**）。
# 路径一律**绝对**：gwlinkd 是系统服务，启动时 cwd 不确定（相对的 ./configs/... 会指错）。
GATEWAY_PORT_VALUE="$(sed -n 's/^GATEWAY_PORT:[[:space:]]*//p' "$VALUES_FILE" 2>/dev/null | head -n1)"
[ -n "$GATEWAY_PORT_VALUE" ] || GATEWAY_PORT_VALUE=443
if [ -z "${GATEWAY_SELF_ENDPOINT:-}" ]; then
  if [ "$GATEWAY_PORT_VALUE" = "443" ]; then GATEWAY_SELF_ENDPOINT="https://127.0.0.1"
  else GATEWAY_SELF_ENDPOINT="https://127.0.0.1:$GATEWAY_PORT_VALUE"; fi
fi
set_value "$VALUES_FILE" GWLINKD_CENTER_ENDPOINT "$CENTER_URL"
set_value "$VALUES_FILE" GWLINKD_GATEWAY_ID "$GATEWAY_ID"
set_value "$VALUES_FILE" GWLINKD_TRUST_BUNDLE "$STACK_DIR/identity/gwlinkd/control-center.pem"
# 身份材料（客户端证书 + 私钥、中心信任锚）落 identity/：不可再生 ⇒ 进 contract（不进交付包）。
set_value "$VALUES_FILE" GWLINKD_IDENTITY_DIR "$STACK_DIR/identity/gwlinkd"
# 运行态（单实例锁 / 升级簿记 / 临时注册券）：可删可重建，与身份分开。
set_value "$VALUES_FILE" GWLINKD_STATE_DIR "$STACK_DIR/configs/gwlinkd/state"
set_value "$VALUES_FILE" GATEWAY_SELF_ENDPOINT "$GATEWAY_SELF_ENDPOINT"
set_value "$VALUES_FILE" GATEWAY_SELF_CA "$STACK_DIR/identity/gateway/public/gateway-ca.crt.pem"
# gwlinkd 驱动升级：gops 工程根（含 ops-prj.yml，**绝对路径**）——gops 从 cwd 解析工程。
# 执行器也写**绝对路径**：gwlinkd 是系统服务，PATH 只有 /usr/local/bin:/usr/bin:/bin…，
# 不含安装脚本用的 $HOME/bin；写相对名 `gops` 会在 spawn 时 ENOENT（os error 2）。
set_value "$VALUES_FILE" GWLINKD_UPGRADER_PROGRAM "$INSTALL_DIR/gops"
set_value "$VALUES_FILE" GWLINKD_UPGRADE_PROJECT_DIR "$PROJECT_ROOT"

# d) 变量解析 + 本地化（把域名等现场值烘进 .env 与渲染配置）
log "gops sys localize"
cd "$STACK_DIR"
gops sys localize

# e) 拉取制品
log "gops run download"
gops run download

# f) 启动
log "gops run start"
gops run start
log "gops run status"
gops run status

# g) 宿主侧 wist-gwlinkd：把本网关接入上级控制中心（系统服务常驻，开机自启 / 崩溃拉起）。
#    来源与 gops/gx 一致（中心最新发布制品），按宿主平台取件。
#    配置**分两份**：主配置（交付物）由 localize 渲染成 configs/gwlinkd/gwlinkd.toml；
#    现场态（中心地址 / 网关标识 / 信任锚 / 临时券）在 identity/gwlinkd/pub.toml ——
#    升级 / 重渲**永不覆盖**它，所以装服务时要把这条路径（--pub-config）显式告诉进程。
#    以**部署用户**身份常驻（非 root）：身份回写落在部署用户属主下。
GWLINKD_URL="$(gwlinkd_url || true)"
if [ -z "$GWLINKD_URL" ]; then
  log "跳过 wist-gwlinkd：中心未发布本平台制品（发布后重跑安装即可补装）"
else
  log "安装 wist-gwlinkd（宿主侧接入器）"
  DEPLOY_USER="$(id -un)"
  if [ "$(id -u)" = "0" ]; then SUDO=""
  elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
  else
    echo "安装 wist-gwlinkd 需要 root 或 sudo（写 /usr/local/lib、/usr/local/bin 与系统服务定义）" >&2
    exit 1
  fi

  GWLINKD_BIN="/usr/local/bin/wist-gwlinkd"
  # 真实二进制放**运行用户可写**的目录：gwlinkd 的自更新要在进程内就地覆盖它。
  # `/usr/local/bin` 是 root 拥有，非 root 服务写不进去（原子 rename 需要目录可写）；
  # PATH 上仍留同名符号链接，运维手敲 `wist-gwlinkd ...` 不受影响。
  GWLINKD_REAL_DIR="/usr/local/lib/wist-gwlinkd"
  GWLINKD_REAL="$GWLINKD_REAL_DIR/wist-gwlinkd"
  GWLINKD_TOML="$STACK_DIR/configs/gwlinkd/gwlinkd.toml"
  # 现场态（中心地址 / 网关标识 / 信任锚 / 临时券）与主配置**分文件**：它**不在**同目录，
  # 所以必须经 WIST_GWLINKD_PUB_CONFIG 显式告诉进程（见 wist-gwlinkd 的 service install）。
  GWLINKD_PUB="$STACK_DIR/identity/gwlinkd/gwlinkd-pub.toml"
  GWLINKD_CA="$STACK_DIR/identity/gwlinkd/control-center.pem"

  $SUDO install -d -m 0755 "$GWLINKD_REAL_DIR"
  install_component wist-gwlinkd "$GWLINKD_URL" "$(gwlinkd_sha || true)" "$GWLINKD_REAL_DIR" "$SUDO"
  # 交给运行身份：**目录与文件都归它**（原子 rename 需要目录可写，只给文件写权限不够）。
  $SUDO chown "$DEPLOY_USER" "$GWLINKD_REAL_DIR" "$GWLINKD_REAL"
  $SUDO ln -sfn "$GWLINKD_REAL" "$GWLINKD_BIN"

  # 中心 CA 信任锚：写到渲染配置里 GWLINKD_TRUST_BUNDLE 指向的路径（自签中心必需）。
  if grep -q 'BEGIN CERTIFICATE' "$CA_CENTER" 2>/dev/null; then
    mkdir -p "$(dirname "$GWLINKD_CA")"
    install -m 0644 "$CA_CENTER" "$GWLINKD_CA"
  fi

  if [ ! -f "$GWLINKD_TOML" ]; then
    echo "未找到渲染后的 ${GWLINKD_TOML}（localize 没跑成？）—— 无法安装 wist-gwlinkd。" >&2
    exit 1
  fi
  if [ ! -f "$GWLINKD_PUB" ]; then
    echo "未找到现场态配置 ${GWLINKD_PUB}（localize 没跑成？）—— 无法安装 wist-gwlinkd。" >&2
    exit 1
  fi

  # 装成**系统级服务、非 root 运行**（--run-as）：开机自启 / 崩溃拉起，进程属主 = 部署用户。
  RUN_AS_OPT=""
  if [ "$(id -u)" != "0" ]; then RUN_AS_OPT="--run-as $DEPLOY_USER"; fi
  $SUDO "$GWLINKD_BIN" service install --system $RUN_AS_OPT --bin "$GWLINKD_BIN" --config "$GWLINKD_TOML" --pub-config "$GWLINKD_PUB" --force
  $SUDO "$GWLINKD_BIN" service status --system || true
  log "wist-gwlinkd 已安装并常驻（user=${DEPLOY_USER}，config=${GWLINKD_TOML}，pub=${GWLINKD_PUB}）；到网关页「链接上级」完成接入（gateway_id=${GATEWAY_ID}）"
fi

log "完成：工程 ${PROJECT_ROOT}（gateway_id=${GATEWAY_ID}）"
"#;

/// 域名清洗：只留 `[A-Za-z0-9.-]`（空/无有效字符 → `None`）。
/// 既要能安全地嵌进 shell（`${GATEWAY_DOMAIN:-…}` 双引号里），也要能安全地进 `sed` 的 `|` 分隔替换。
fn sanitize_domain(domain: Option<&str>) -> Option<String> {
    let cleaned: String = domain?
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// 渲染全量安装脚本：把中心地址、网关身份、各组件制品（地址 + 摘要）与域名填进模板。
#[allow(clippy::too_many_arguments)]
fn render_install_all_script(
    center_url: &str,
    gateway_id: &str,
    gops: &ReleasePackageRecord,
    gx: &ReleasePackageRecord,
    stack: &ReleasePackageRecord,
    gwlinkd: Option<&ReleasePackageRecord>,
    domain: Option<String>,
    ca_pem: Option<String>,
) -> String {
    let stack_url = stack
        .package
        .artifacts
        .first()
        .map(|artifact| artifact.source.clone())
        .unwrap_or_default();
    // gwlinkd 未发布 → 空分支：脚本内 `gwlinkd_url` 对任何平台都失败，于是跳过这一步并提示。
    let (gwlinkd_url_case, gwlinkd_sha_case) = match gwlinkd {
        Some(package) => (
            platform_case_branches(package),
            platform_sha_case_branches(package),
        ),
        None => (String::new(), String::new()),
    };
    INSTALL_ALL_SCRIPT_TEMPLATE
        .replace("__CENTER_URL__", &shell_single_quote_escape(center_url))
        .replace("__GATEWAY_ID__", &shell_single_quote_escape(gateway_id))
        .replace(
            "__PROJECT_NAME__",
            &shell_single_quote_escape(&sanitize_project_name(gateway_id)),
        )
        .replace("__GOPS_CASE__", &platform_case_branches(gops))
        .replace("__GOPS_SHA_CASE__", &platform_sha_case_branches(gops))
        .replace("__GX_CASE__", &platform_case_branches(gx))
        .replace("__GX_SHA_CASE__", &platform_sha_case_branches(gx))
        .replace("__GWLINKD_CASE__", &gwlinkd_url_case)
        .replace("__GWLINKD_SHA_CASE__", &gwlinkd_sha_case)
        .replace("__STACK_URL__", &shell_single_quote_escape(&stack_url))
        .replace("__DOMAIN__", domain.as_deref().unwrap_or(""))
        .replace("__CENTER_CA_PEM__", ca_pem.as_deref().unwrap_or(""))
}

/// 前置环境准备脚本模板（**独立于安装脚本**）：补齐 tar/curl/gzip/python3/docker/docker compose。
const PREPARE_SCRIPT_TEMPLATE: &str = r#"#!/usr/bin/env bash
# WistCenter · 网关前置环境准备
# 补齐 tar / curl / gzip / python3 / docker / docker compose（缺则装），可重复执行。
set -euo pipefail

log() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }

ensure_prereqs() {
  local need_bins=''
  for c in tar curl gzip python3; do
    command -v "$c" >/dev/null 2>&1 || need_bins="$need_bins $c"
  done
  local need_docker=0 need_compose=0
  if command -v docker >/dev/null 2>&1; then
    docker compose version >/dev/null 2>&1 || need_compose=1
  else
    need_docker=1; need_compose=1
  fi
  if [ -z "$need_bins" ] && [ "$need_docker" = 0 ] && [ "$need_compose" = 0 ]; then
    log "前置就绪：tar/curl/gzip/python3/docker/docker compose"
    return 0
  fi
  log "补齐前置：${need_bins}${need_docker:+ docker docker-compose}"
  if ! command -v sudo >/dev/null 2>&1; then
    echo "缺少前置（${need_bins} docker docker-compose）且无 sudo；请用 root 跑，或先手动安装。" >&2
    exit 1
  fi
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq || true
    if [ -n "$need_bins" ]; then sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $need_bins; fi
    if [ "$need_docker" = 1 ] || [ "$need_compose" = 1 ]; then
      if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2; then
        log "apt 装不到 docker/compose → get.docker.com"
        curl -fsSL https://get.docker.com | sudo sh || { echo "docker 安装失败" >&2; exit 1; }
      fi
    fi
  elif command -v dnf >/dev/null 2>&1; then
    if [ -n "$need_bins" ]; then sudo dnf install -y $need_bins; fi
    if [ "$need_docker" = 1 ] || [ "$need_compose" = 1 ]; then
      sudo dnf install -y docker docker-compose-plugin || { curl -fsSL https://get.docker.com | sudo sh || { echo "docker 安装失败" >&2; exit 1; }; }
    fi
  elif command -v yum >/dev/null 2>&1; then
    if [ -n "$need_bins" ]; then sudo yum install -y $need_bins; fi
    if [ "$need_docker" = 1 ] || [ "$need_compose" = 1 ]; then
      sudo yum install -y docker docker-compose-plugin || { curl -fsSL https://get.docker.com | sudo sh || { echo "docker 安装失败" >&2; exit 1; }; }
    fi
  elif command -v apk >/dev/null 2>&1; then
    if [ -n "$need_bins" ]; then sudo apk add $need_bins; fi
    if [ "$need_docker" = 1 ] || [ "$need_compose" = 1 ]; then sudo apk add docker docker-cli-compose || true; fi
  else
    if [ -n "$need_bins" ]; then echo "未知发行版且缺少 ${need_bins}，请手动安装。" >&2; exit 1; fi
    curl -fsSL https://get.docker.com | sudo sh || { echo "docker 安装失败" >&2; exit 1; }
  fi
  # 启动 docker + 把当前用户加进 docker 组（新会话生效）。
  if command -v systemctl >/dev/null 2>&1; then sudo systemctl enable --now docker 2>/dev/null || true;
  elif command -v service >/dev/null 2>&1; then sudo service docker start 2>/dev/null || true; fi
  sudo usermod -aG docker "$USER" 2>/dev/null || true
  command -v docker >/dev/null 2>&1 || { echo "docker 仍不可用" >&2; exit 1; }
  docker compose version >/dev/null 2>&1 || { echo "docker compose 插件仍不可用" >&2; exit 1; }
  if ! docker info >/dev/null 2>&1; then
    # 尽力让当前会话立刻可用：把 docker.sock 交给当前用户（权限等价 docker 组；免重新登录）。
    sudo chown "$USER" /var/run/docker.sock 2>/dev/null || true
    docker info >/dev/null 2>&1 || {
      echo "docker 已装但当前会话无权限（已加入 docker 组，需重新登录生效）。请重开一个 shell 后重跑本命令。" >&2
      exit 1
    }
  fi
  log "前置就绪：$(docker --version)"
}
ensure_prereqs
log "环境准备完成；接下来运行「安装」命令。"
"#;

/// 生成前置环境准备命令：`curl -fsSLk '<center>/api/v1/gateway/prepare-script' | bash`。
pub fn build_prepare_script_command(public_url: &str) -> String {
    let endpoint = format!(
        "{}/api/v1/gateway/prepare-script",
        public_url.trim_end_matches('/')
    );
    format!("curl -fsSLk '{endpoint}' | bash")
}

/// 前置准备端点限流桶（公开、无令牌）。
const GATEWAY_PREPARE_SCRIPT_SCOPE: &str = "gateway-prepare-script";

/// 取前置环境准备脚本：GET /api/v1/gateway/prepare-script（公开，无需令牌，仅限流）。
pub async fn get_gateway_prepare_script(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) =
        rate_limit::check_rate_limit(&state, &client_key, GATEWAY_PREPARE_SCRIPT_SCOPE)
    {
        return response;
    }
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        PREPARE_SCRIPT_TEMPLATE,
    )
        .into_response()
}

// ─────────────────────────── 「只装 gwlinkd」（网关已部署时） ───────────────────────────

/// 「只装 gwlinkd」端点限流桶：与完整安装脚本分开计数（token 在 URL 里，独立桶防暴力枚举）。
const GATEWAY_INSTALL_LINKD_SCOPE: &str = "gateway-install-linkd";

/// 「只装 gwlinkd」查询参数：`gateway_id` + 一次性 `token`（无 `domain` —— 不装网关本体）。
#[derive(serde::Deserialize)]
pub struct InstallLinkdQueryParams {
    pub gateway_id: String,
    #[serde(default)]
    pub token: Option<String>,
}

/// `install-all` / `install-linkd` 的公共入参校验：非空 `gateway_id` + 一次性接入券。
/// 券**只校验、不消费**（留给 link-upstream）：网关存在 + 券 hash 匹配 + 未过期。
/// 失败时按 `scope` 记一次鉴权失败并返回构造好的错误响应；成功时清失败计数。
#[allow(clippy::result_large_err)]
async fn validate_install_request(
    state: &ApiState,
    client_key: &str,
    scope: &str,
    gateway_id_param: &str,
    token_param: Option<&str>,
) -> Result<(String, String), Response> {
    let gateway_id = gateway_id_param.trim().to_string();
    if gateway_id.is_empty() {
        return Err(super::error::ApiError::bad_request(
            super::codes::GATEWAY_ID_REQUIRED,
            "gateway_id must not be empty",
        )
        .into_response());
    }
    let Some(token) = token_param.map(str::trim).filter(|t| !t.is_empty()) else {
        rate_limit::record_auth_failure(state, client_key, scope);
        return Err(super::error::ApiError::unauthorized(
            super::codes::MISSING_INSTALL_TOKEN,
            "missing install token",
        )
        .with_no_store()
        .into_response());
    };
    let gateway = match state.store.get_gateway(&gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            rate_limit::record_auth_failure(state, client_key, scope);
            return Err(super::error::ApiError::unauthorized(
                super::codes::UNKNOWN_GATEWAY,
                "unknown gateway",
            )
            .with_no_store()
            .into_response());
        }
        Err(err) => {
            return Err(super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            ));
        }
    };
    if gateway.link_token_hash.is_empty() || sha256_hex(token) != gateway.link_token_hash {
        rate_limit::record_auth_failure(state, client_key, scope);
        return Err(super::error::ApiError::unauthorized(
            super::codes::INVALID_INSTALL_TOKEN,
            "invalid install token",
        )
        .with_no_store()
        .into_response());
    }
    if link_token_expired(gateway.link_token_expires_at.as_deref()) {
        rate_limit::record_auth_failure(state, client_key, scope);
        return Err(super::error::ApiError::unauthorized(
            super::codes::INSTALL_TOKEN_EXPIRED,
            "install token expired",
        )
        .with_no_store()
        .into_response());
    }
    rate_limit::clear_auth_failures(state, client_key, scope);
    Ok((gateway_id, token.to_string()))
}

/// 生成「只装 gwlinkd」命令：
/// `curl -fsSLk '<center>/api/v1/gateway/install-linkd?gateway_id=..&token=..' | bash`。
pub fn build_install_linkd_command(public_url: &str, gateway_id: &str, link_token: &str) -> String {
    let endpoint = format!(
        "{}/api/v1/gateway/install-linkd?gateway_id={}&token={}",
        public_url.trim_end_matches('/'),
        url_encode(gateway_id),
        url_encode(link_token),
    );
    format!("curl -fsSLk '{endpoint}' | bash")
}

/// 取「只装 gwlinkd」脚本：GET /api/v1/gateway/install-linkd（一次性接入券鉴权，返回 shell 脚本）。
///
/// 面向**网关已部署**的机器：只补装宿主侧 `wist-gwlinkd`（**不装** gops/gx/gateway-stack）。
/// 在**已部署的网关工程**里补齐 gwlinkd 配置（走栈的 `gops sys localize`）再装二进制 + 系统服务；
/// 本脚本**不做接入**（接入仍走网关「链接上级」页/gwlinkd）。
pub async fn get_gateway_install_linkd(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    ApiQuery(params): ApiQuery<InstallLinkdQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) =
        rate_limit::check_rate_limit(&state, &client_key, GATEWAY_INSTALL_LINKD_SCOPE)
    {
        return response;
    }
    let (gateway_id, _token) = match validate_install_request(
        &state,
        &client_key,
        GATEWAY_INSTALL_LINKD_SCOPE,
        params.gateway_id.as_str(),
        params.token.as_deref(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    // 本端点**就是**装 gwlinkd：未发布该组件 → 明确不可用（不像完整脚本那样可跳过）。
    let Some(gwlinkd) = (match latest_published_package(&state, GWLINKD_COMPONENT).await {
        Ok(package) => package,
        Err(response) => return response,
    }) else {
        return super::error::ApiError::unavailable(
            super::codes::INSTALL_ALL_UNAVAILABLE,
            "install-linkd unavailable: publish a wist-gwlinkd release first",
        )
        .into_response();
    };
    let script = render_linkd_script(
        state.config.public_url.trim_end_matches('/'),
        &gateway_id,
        &gwlinkd,
        state.config.ca_cert.clone(),
    );
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    )
        .into_response()
}

/// 手动升级请求：组件 + 版本（版本可带 `v` 前缀）。
#[derive(serde::Deserialize)]
pub struct GatewayUpgradeScriptRequest {
    pub component: String,
    #[serde(default)]
    pub version: String,
}

/// 手动升级脚本回执：页面展示 `curl ... | bash` 一行命令，同时附脚本内容（便于预览 / 排查）。
#[derive(serde::Serialize)]
pub struct GatewayUpgradeScriptResponse {
    pub gateway_id: String,
    pub component: String,
    pub version: String,
    pub filename: String,
    pub script: String,
    /// `curl ... | bash` 一行命令（短命签名，默认 30 分钟有效）。
    pub command: String,
    /// 命令过期时刻（RFC3339）。
    pub expires_at: String,
}

/// 网关面「手动升级脚本」查询：`curl ... | bash` 打开的那条 URL。
#[derive(serde::Deserialize)]
pub struct GatewayUpgradeScriptQuery {
    pub gateway_id: String,
    pub component: String,
    pub version: String,
    pub expires: i64,
    pub signature: String,
}

/// 生成单台网关的**手动升级执行脚本**：
/// `POST /api/v1/admin/gateways/{gateway_id}/upgrade-script`。
///
/// 只生成脚本 / 一行命令，**不建计划、不下发任务** —— 运维把 `curl ... | bash` 粘到网关宿主执行，
/// 与首次安装同一套下载 / 校验 / 安装逻辑。支持 `gwlink` / `wist-gwlinkd` 与
/// `gateway-stack` / `wist-gateway-stack` 两种命名。
pub async fn admin_gateway_upgrade_script(
    State(state): State<ApiState>,
    Path(gateway_id): Path<String>,
    headers: HeaderMap,
    client: PeerConnectInfo,
    ApiJson(request): ApiJson<GatewayUpgradeScriptRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }

    // 目标网关必须存在（与建计划同一道校验：物化到不存在的网关只会静默落库、永不命中）。
    let known = match state.store.list_gateways().await {
        Ok(gateways) => gateways
            .iter()
            .any(|gateway| gateway.gateway_id == gateway_id),
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::GATEWAY_LIST_FAILED,
                "failed to list gateways",
                err.display_chain(),
            );
        }
    };
    if !known {
        return ApiError::not_found(
            codes::GATEWAY_NOT_FOUND,
            format!("unknown gateway: {gateway_id}"),
        )
        .into_response();
    }

    // 组件命名：同时接受中心组件名与页面上的简称。
    let component = match request.component.trim() {
        GWLINKD_COMPONENT | "gwlink" => GWLINKD_COMPONENT,
        STACK_COMPONENT | "gateway-stack" => STACK_COMPONENT,
        other => {
            return ApiError::bad_request(
                codes::INVALID_COMPONENT,
                format!("unsupported upgrade component: {other}（可用：gwlink / gateway-stack）"),
            )
            .into_response();
        }
    };
    // 版本命名：中心 release 记录通常不带 `v`，手敲 tag 常带；统一去掉。
    let version = normalize_version(request.version.trim());
    if version.is_empty() {
        return ApiError::bad_request(codes::INVALID_VERSION, "version is required")
            .into_response();
    }

    let (release_version, script) =
        match build_upgrade_script(&state, &gateway_id, component, &version).await {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };

    // 一行命令：URL 里只带短命签名（不塞 admin token）；网关面端点验签后直接回脚本。
    let expires = chrono::Utc::now().timestamp() + GATEWAY_UPGRADE_SCRIPT_TTL_SECONDS;
    let signature = crate::infra::derive_upgrade_script_token(
        &state.config.hmac_secret,
        &gateway_id,
        component,
        &release_version,
        expires,
    );
    let endpoint = format!(
        "{}/api/v1/gateway/upgrade-script?gateway_id={}&component={}&version={}&expires={}&signature={}",
        state.config.public_url.trim_end_matches('/'),
        url_encode(&gateway_id),
        url_encode(component),
        url_encode(&release_version),
        expires,
        signature,
    );
    let command = format!("curl -fsSLk '{endpoint}' | bash");
    let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(expires, 0)
        .map(|value| value.to_rfc3339())
        .unwrap_or_default();
    let filename = format!("upgrade-{component}-{release_version}.sh");

    (
        StatusCode::OK,
        Json(GatewayUpgradeScriptResponse {
            gateway_id,
            component: component.to_string(),
            version: release_version,
            filename,
            script,
            command,
            expires_at,
        }),
    )
        .into_response()
}

/// 网关面：验短命签名后回升级脚本（`curl ... | bash` 打开的就是它）。
pub async fn get_gateway_upgrade_script(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    ApiQuery(params): ApiQuery<GatewayUpgradeScriptQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) =
        rate_limit::check_rate_limit(&state, &client_key, GATEWAY_UPGRADE_SCRIPT_SCOPE)
    {
        return response;
    }
    let now = chrono::Utc::now().timestamp();
    if params.expires <= now {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_UPGRADE_SCRIPT_SCOPE);
        return ApiError::unauthorized(
            codes::UPGRADE_SCRIPT_TOKEN_EXPIRED,
            "upgrade script token expired",
        )
        .with_no_store()
        .into_response();
    }
    if !crate::infra::verify_upgrade_script_token(
        &state.config.hmac_secret,
        &params.gateway_id,
        &params.component,
        &params.version,
        params.expires,
        &params.signature,
    ) {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_UPGRADE_SCRIPT_SCOPE);
        return ApiError::unauthorized(
            codes::UPGRADE_SCRIPT_TOKEN_INVALID,
            "invalid upgrade script token",
        )
        .with_no_store()
        .into_response();
    }
    rate_limit::clear_auth_failures(&state, &client_key, GATEWAY_UPGRADE_SCRIPT_SCOPE);

    let component = match params.component.as_str() {
        GWLINKD_COMPONENT => GWLINKD_COMPONENT,
        STACK_COMPONENT => STACK_COMPONENT,
        _ => {
            return ApiError::bad_request(
                codes::INVALID_COMPONENT,
                "unsupported upgrade component",
            )
            .into_response();
        }
    };
    let version = normalize_version(params.version.trim());
    let (_release_version, script) =
        match build_upgrade_script(&state, &params.gateway_id, component, &version).await {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    )
        .into_response()
}

/// 管理面与网关面共用的脚本生成：按组件 + 归一化版本解析发布记录并渲染。
#[allow(clippy::result_large_err)]
async fn build_upgrade_script(
    state: &ApiState,
    gateway_id: &str,
    component: &'static str,
    version: &str,
) -> Result<(String, String), ApiError> {
    let records = state.store.list_releases(component).await.map_err(|err| {
        ApiError::internal(
            codes::RELEASE_LIST_FAILED,
            "failed to load releases",
            err.display_chain(),
        )
    })?;
    let package = group_release_packages(component, records)
        .into_iter()
        .find(|package| {
            // 发布记录里的版本可能带 `v`（包名 / 顶层目录名带 `v` 时原样保留）；
            // 请求侧已归一，这里也归一后比 —— 两边写不写 `v` 都能命中同一条记录。
            package.status != "expired" && normalize_version(&package.package.version) == version
        })
        .ok_or_else(|| {
            ApiError::not_found(
                codes::RELEASE_NOT_FOUND,
                format!("no dispatchable {component} release: {version}"),
            )
        })?;
    // 回执与文件名用**发布记录里的原始版本**（可能带 `v`）—— 与页面上看到的一致。
    let release_version = package.package.version.clone();
    let script = match component {
        GWLINKD_COMPONENT => render_linkd_script(
            state.config.public_url.trim_end_matches('/'),
            gateway_id,
            &package,
            state.config.ca_cert.clone(),
        ),
        _ => render_stack_upgrade_script(
            state.config.public_url.trim_end_matches('/'),
            gateway_id,
            &release_version,
            &package,
            state.config.ca_cert.clone(),
        )
        .ok_or_else(|| {
            ApiError::not_found(
                codes::RELEASE_NOT_FOUND,
                format!("no artifact for {component} release: {release_version}"),
            )
        })?,
    };
    Ok((release_version, script))
}

/// 渲染「手动升级 gateway-stack」脚本：填中心地址 / 网关身份 / 指定版本制品（地址 + 摘要）与 CA。
fn render_stack_upgrade_script(
    center_url: &str,
    gateway_id: &str,
    version: &str,
    package: &ReleasePackageRecord,
    ca_pem: Option<String>,
) -> Option<String> {
    // gateway-stack 是单制品（无平台概念）；历史/异常数据里若只有带平台的制品，取第一条。
    let artifact = package
        .package
        .artifacts
        .iter()
        .find(|artifact| artifact.platform.is_none())
        .or_else(|| package.package.artifacts.first())?;
    Some(
        STACK_UPGRADE_SCRIPT_TEMPLATE
            .replace("__CENTER_URL__", &shell_single_quote_escape(center_url))
            .replace("__GATEWAY_ID__", &shell_single_quote_escape(gateway_id))
            .replace("__STACK_VERSION__", &shell_single_quote_escape(version))
            .replace(
                "__STACK_URL__",
                &shell_single_quote_escape(&artifact.source),
            )
            .replace(
                "__STACK_SHA__",
                &shell_single_quote_escape(&artifact.sha256),
            )
            .replace("__CENTER_CA_PEM__", ca_pem.as_deref().unwrap_or("")),
    )
}

/// 「手动升级 gateway-stack」脚本模板：在网关宿主的 gops 工程根下载指定版本、校验摘要，
/// 再交给 `gops prj upgrade`（与 gwlinkd 的升级驱动同一命令）。
const STACK_UPGRADE_SCRIPT_TEMPLATE: &str = r#"#!/usr/bin/env bash
# WistCenter · 手动升级网关栈（wist-gateway-stack）到 __STACK_VERSION__
#
# 在网关宿主上的 gops 工程根执行（含 ops-prj.yml）；可用 PROJECT_ROOT=<工程根> 覆盖。
# 执行者是 gops，与宿主侧 gwlinkd 的升级驱动同一命令；失败默认整份回滚。
set -euo pipefail

CENTER_URL='__CENTER_URL__'
GATEWAY_ID='__GATEWAY_ID__'
STACK_VERSION='__STACK_VERSION__'
STACK_URL='__STACK_URL__'
STACK_SHA='__STACK_SHA__'

log() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }

command -v gops >/dev/null 2>&1 || { echo '缺少 gops（网关由 gops 部署；请确认 PATH 含 $HOME/bin）' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo '缺少 curl' >&2; exit 1; }

# 中心 CA（自签）：与 install-all / install-linkd 同口径（信任锚 + bundle）。
CA_DIR="$HOME/.wist/ca"
CA_CENTER="$CA_DIR/control-center.pem"
CA_BUNDLE="$CA_DIR/ca-bundle.pem"
mkdir -p "$CA_DIR"
cat > "$CA_CENTER" <<'WIST_CENTER_CA_EOF'
__CENTER_CA_PEM__
WIST_CENTER_CA_EOF
if grep -q 'BEGIN CERTIFICATE' "$CA_CENTER" 2>/dev/null; then
  sys_bundle=''
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ -f "$f" ] && sys_bundle="$f" && break
  done
  if [ -n "$sys_bundle" ]; then cat "$sys_bundle" "$CA_CENTER" > "$CA_BUNDLE"; else cp "$CA_CENTER" "$CA_BUNDLE"; fi
  export SSL_CERT_FILE="$CA_BUNDLE" CURL_CA_BUNDLE="$CA_BUNDLE"
  CURL_TLS=(--cacert "$CA_BUNDLE")
  log "已载入中心 CA：$CA_BUNDLE"
else
  CURL_TLS=(-k)
  log "中心未提供 CA（明文 / 未配 CA）→ curl 回退 -k"
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else return 1; fi
}

# 定位已部署的 gops 工程：默认当前目录；可用 PROJECT_ROOT 覆盖。
PROJECT_ROOT="$(cd "${PROJECT_ROOT:-$PWD}" && pwd)"
[ -f "$PROJECT_ROOT/ops-prj.yml" ] || {
  echo "找不到 gops 工程：$PROJECT_ROOT/ops-prj.yml（请在工程根执行，或设 PROJECT_ROOT=<工程根>）" >&2
  exit 1
}

log "下载 wist-gateway-stack ${STACK_VERSION}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -fsSL "${CURL_TLS[@]}" "$STACK_URL" -o "$WORK/stack.tar.gz"
if [ -n "$STACK_SHA" ]; then
  have="$(sha256_of "$WORK/stack.tar.gz" || true)"
  if [ -z "$have" ]; then log '提示：本机无 sha256sum/shasum，跳过摘要校验';
  elif [ "$have" != "$STACK_SHA" ]; then
    echo "下载校验失败 wist-gateway-stack：期望 ${STACK_SHA}，实际 ${have}" >&2
    exit 1
  fi
fi

# 健康检查：优先沿用本机 gwlinkd 已渲染的 upgrade_health_cmd（与宿主侧驱动同一口径）；
# 没配就不加（gops 只会在命令失败时回滚）。
HEALTH_CMD=''
HEALTH_TIMEOUT=120
GWLINKD_TOML="$PROJECT_ROOT/configs/gwlinkd/gwlinkd.toml"
if [ -f "$GWLINKD_TOML" ]; then
  HEALTH_CMD="$(sed -n 's/^[[:space:]]*upgrade_health_cmd[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$GWLINKD_TOML" | head -n1)"
  parsed_timeout="$(sed -n 's/^[[:space:]]*upgrade_health_timeout_seconds[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$GWLINKD_TOML" | head -n1)"
  if [ -n "$parsed_timeout" ]; then HEALTH_TIMEOUT="$parsed_timeout"; fi
fi

log "gops prj upgrade --to <本地制品> --on-failure rollback-all"
cd "$PROJECT_ROOT"
# `--force 1` 跳过确认：`curl ... | bash` 时 stdin 是脚本管道，不能等交互提示。
if [ -n "$HEALTH_CMD" ]; then
  gops prj upgrade --to "$WORK/stack.tar.gz" --on-failure rollback-all --force 1 \
    --health-cmd "$HEALTH_CMD" --health-timeout "$HEALTH_TIMEOUT" --json
else
  gops prj upgrade --to "$WORK/stack.tar.gz" --on-failure rollback-all --force 1 --json
fi
log "完成：${GATEWAY_ID} 已升级到 wist-gateway-stack ${STACK_VERSION}"
"#;

/// 渲染「只装 gwlinkd」脚本：填中心地址、网关身份、宿主接入器制品（地址 + 摘要）与 CA。
fn render_linkd_script(
    center_url: &str,
    gateway_id: &str,
    gwlinkd: &ReleasePackageRecord,
    ca_pem: Option<String>,
) -> String {
    LINKD_SCRIPT_TEMPLATE
        .replace("__CENTER_URL__", &shell_single_quote_escape(center_url))
        .replace("__GATEWAY_ID__", &shell_single_quote_escape(gateway_id))
        .replace("__GWLINKD_CASE__", &platform_case_branches(gwlinkd))
        .replace("__GWLINKD_SHA_CASE__", &platform_sha_case_branches(gwlinkd))
        .replace("__CENTER_CA_PEM__", ca_pem.as_deref().unwrap_or(""))
}

/// 「只装 gwlinkd」脚本模板：在**已部署的网关工程**里补齐 gwlinkd 配置并装宿主侧接入器。
///
/// 定位工程：默认当前目录（gops 工程根，含 `ops-prj.yml`），可用 `STACK_DIR` / `PROJECT_ROOT` 覆盖。
/// 配置：把 gwlinkd 现场值写进 `values/<stack>/sys_value.yml`，跑 `gops sys localize` 渲染出
/// `configs/gwlinkd/gwlinkd.toml` 与 `identity/gwlinkd/gwlinkd-pub.toml`（+ `.env`）。
/// 不做接入：只装二进制 + 系统服务；接入仍由「链接上级」页/gwlinkd 完成。
const LINKD_SCRIPT_TEMPLATE: &str = r#"#!/usr/bin/env bash
# WistCenter · 只装宿主侧 wist-gwlinkd（网关已部署时用）
#
# 由中心自动生成：在**已部署的网关工程**里补齐 gwlinkd 配置（走栈的 `gops sys localize`）并装
# 宿主侧接入器。**不装** gops / gx / gateway-stack —— 那些由「全量安装（install-all）」负责。
# 本脚本**不做接入**：接入仍走网关「链接上级」页（或 gwlinkd 自联）。
set -euo pipefail

CENTER_URL='__CENTER_URL__'
GATEWAY_ID='__GATEWAY_ID__'
CA_DIR="$HOME/.wist/ca"
CA_CENTER="$CA_DIR/control-center.pem"
CA_BUNDLE="$CA_DIR/ca-bundle.pem"

log() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
mkdir -p "$CA_DIR"
export PATH="$HOME/bin:$HOME/.local/bin:$PATH"

# 中心 CA（自签）：写盘 + 组「系统根 + 中心CA」bundle（与 install-all 同口径）。
cat > "$CA_CENTER" <<'WIST_CENTER_CA_EOF'
__CENTER_CA_PEM__
WIST_CENTER_CA_EOF
if grep -q 'BEGIN CERTIFICATE' "$CA_CENTER" 2>/dev/null; then
  sys_bundle=''
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ -f "$f" ] && sys_bundle="$f" && break
  done
  if [ -n "$sys_bundle" ]; then cat "$sys_bundle" "$CA_CENTER" > "$CA_BUNDLE"; else cp "$CA_CENTER" "$CA_BUNDLE"; fi
  export SSL_CERT_FILE="$CA_BUNDLE" CURL_CA_BUNDLE="$CA_BUNDLE"
  CURL_TLS=(--cacert "$CA_BUNDLE")
  log "已载入中心 CA：$CA_BUNDLE"
else
  CURL_TLS=(-k)
  log "中心未提供 CA（明文 / 未配 CA）→ curl 回退 -k"
fi

# 前置：curl / 解包工具 / gops。
command -v curl >/dev/null 2>&1 || { echo '缺少 curl' >&2; exit 1; }
if ! command -v tar >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo '缺少 tar 与 python3（至少一个用于解包）' >&2; exit 1
fi
# 捕获**可执行文件**的绝对路径：`type -P` 只查 PATH，不会把 shell 函数/别名当成程序。
# gwlinkd 是系统服务，PATH 不含 $HOME/bin，配置里写相对名 `gops` 会在 spawn 时 ENOENT（os error 2）。
GOPS_BIN="$(type -P gops || true)"
[ -n "$GOPS_BIN" ] || { echo '缺少 gops（网关由 gops 部署；请确认 PATH 含 $HOME/bin）' >&2; exit 1; }

# 平台探测 → target-triple（与中心制品的平台对齐）。
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)              PLATFORM='aarch64-apple-darwin' ;;
  Linux/x86_64)              PLATFORM='x86_64-unknown-linux-musl' ;;
  Linux/aarch64|Linux/arm64) PLATFORM='aarch64-unknown-linux-musl' ;;
  *) echo "unsupported platform: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

# 宿主接入器制品地址 / 摘要（按平台，取自中心最新发布 wist-gwlinkd）。
gwlinkd_url() { case "$PLATFORM" in
__GWLINKD_CASE__    *) return 1 ;;
  esac; }
gwlinkd_sha() { case "$PLATFORM" in
__GWLINKD_SHA_CASE__    *) return 1 ;;
  esac; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else return 1; fi
}

# 定位**已部署的网关工程**：默认当前目录（gops 工程根，含 ops-prj.yml）；
# 可用 STACK_DIR（栈目录）或 PROJECT_ROOT（工程根）覆盖。
PROJECT_ROOT="$(cd "${PROJECT_ROOT:-$PWD}" && pwd)"
if [ -n "${STACK_DIR:-}" ]; then
  STACK_DIR="$(cd "$STACK_DIR" && pwd)"
elif [ -d "$PROJECT_ROOT/wist-gateway-stack" ]; then
  STACK_DIR="$PROJECT_ROOT/wist-gateway-stack"
else
  echo "找不到网关栈目录：$PROJECT_ROOT/wist-gateway-stack" >&2
  echo '请在 gops 工程根（含 ops-prj.yml）下运行，或设 STACK_DIR=<栈目录>。' >&2
  exit 1
fi
[ -f "$STACK_DIR/sys-prj.yml" ] || { echo "STACK_DIR 不像网关栈（缺 sys-prj.yml）：$STACK_DIR" >&2; exit 1; }
VALUES_FILE="$PROJECT_ROOT/values/wist-gateway-stack/sys_value.yml"

# 现场值写进 values（gops 覆盖机制）：一份值，localize 时一致地烘进渲染配置。
set_value() {
  local file="$1" key="$2" value="$3"
  mkdir -p "$(dirname "$file")"
  if grep -qE "^${key}:" "$file" 2>/dev/null; then
    sed -E "s|^${key}:.*|${key}: ${value}|" "$file" > "$file.tmp"
    mv "$file.tmp" "$file"
  else
    printf '%s: %s\n' "$key" "$value" >> "$file"
  fi
}

# gwlinkd 现场值（与完整安装脚本同一口径）。路径一律**绝对**：gwlinkd 是系统服务，cwd 不确定。
GATEWAY_PORT_VALUE="$(sed -n 's/^GATEWAY_PORT:[[:space:]]*//p' "$VALUES_FILE" 2>/dev/null | head -n1)"
[ -n "$GATEWAY_PORT_VALUE" ] || GATEWAY_PORT_VALUE=443
if [ -z "${GATEWAY_SELF_ENDPOINT:-}" ]; then
  if [ "$GATEWAY_PORT_VALUE" = "443" ]; then GATEWAY_SELF_ENDPOINT='https://127.0.0.1'
  else GATEWAY_SELF_ENDPOINT="https://127.0.0.1:$GATEWAY_PORT_VALUE"; fi
fi
set_value "$VALUES_FILE" GWLINKD_CENTER_ENDPOINT "$CENTER_URL"
set_value "$VALUES_FILE" GWLINKD_GATEWAY_ID "$GATEWAY_ID"
set_value "$VALUES_FILE" GWLINKD_TRUST_BUNDLE "$STACK_DIR/identity/gwlinkd/control-center.pem"
set_value "$VALUES_FILE" GWLINKD_IDENTITY_DIR "$STACK_DIR/identity/gwlinkd"
set_value "$VALUES_FILE" GWLINKD_STATE_DIR "$STACK_DIR/configs/gwlinkd/state"
set_value "$VALUES_FILE" GATEWAY_SELF_ENDPOINT "$GATEWAY_SELF_ENDPOINT"
set_value "$VALUES_FILE" GATEWAY_SELF_CA "$STACK_DIR/identity/gateway/public/gateway-ca.crt.pem"
set_value "$VALUES_FILE" GWLINKD_UPGRADER_PROGRAM "$GOPS_BIN"
set_value "$VALUES_FILE" GWLINKD_UPGRADE_PROJECT_DIR "$PROJECT_ROOT"

# 渲染 gwlinkd 配置（主配置 + 现场态声明/值）—— 复用栈的 localize。
log 'gops sys localize（渲染 gwlinkd 配置）'
( cd "$STACK_DIR" && gops sys localize )

# 安装宿主侧 wist-gwlinkd（系统服务常驻，非 root 运行）—— 与完整安装脚本 g) 同口径。
GWLINKD_URL="$(gwlinkd_url || true)"
if [ -z "$GWLINKD_URL" ]; then
  echo "中心未发布本平台（${PLATFORM}）的 wist-gwlinkd 制品 —— 请先在中心「包管理」发布，再重试。" >&2
  exit 1
fi
log '安装 wist-gwlinkd（宿主侧接入器）'
DEPLOY_USER="$(id -un)"
if [ "$(id -u)" = "0" ]; then SUDO=''
elif command -v sudo >/dev/null 2>&1; then SUDO='sudo'
else echo '安装 wist-gwlinkd 需要 root 或 sudo（写 /usr/local/lib、/usr/local/bin 与系统服务定义）' >&2; exit 1; fi

install_gwlinkd() {
  url="$1"; want_sha="${2:-}"; use_sudo="${3:-}"; dest="${4:-/usr/local/bin}"; name='wist-gwlinkd'
  d="$(mktemp -d)"
  log "下载 wist-gwlinkd：$url"
  curl -fsSL "${CURL_TLS[@]}" "$url" -o "$d/pkg"
  if [ -n "$want_sha" ]; then
    have="$(sha256_of "$d/pkg" || true)"
    if [ -z "$have" ]; then log '提示：本机无 sha256sum/shasum，跳过 wist-gwlinkd 的摘要校验';
    elif [ "$have" != "$want_sha" ]; then echo "下载校验失败 wist-gwlinkd：期望 ${want_sha}，实际 $have" >&2; rm -rf "$d"; return 1; fi
  fi
  tar -xzf "$d/pkg" -C "$d" 2>/dev/null || true
  bin="$(find "$d" -type f -name "$name" -print -quit 2>/dev/null)"
  if [ -z "$bin" ] && command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2])' "$d/pkg" "$d" 2>/dev/null || true
    bin="$(find "$d" -type f -name "$name" -print -quit 2>/dev/null)"
  fi
  if [ -z "$bin" ]; then echo "解包 wist-gwlinkd 失败（${url}）" >&2; rm -rf "$d"; return 1; fi
  $use_sudo install -m 0755 "$bin" "$dest/$name"
  rm -rf "$d"
}

GWLINKD_BIN='/usr/local/bin/wist-gwlinkd'
# 真实二进制放**运行用户可写**的目录（自更新要在进程内覆盖它）；`/usr/local/bin` 留符号链接。
GWLINKD_REAL_DIR='/usr/local/lib/wist-gwlinkd'
GWLINKD_REAL="$GWLINKD_REAL_DIR/wist-gwlinkd"
GWLINKD_TOML="$STACK_DIR/configs/gwlinkd/gwlinkd.toml"
GWLINKD_PUB="$STACK_DIR/identity/gwlinkd/gwlinkd-pub.toml"
GWLINKD_CA="$STACK_DIR/identity/gwlinkd/control-center.pem"

$SUDO install -d -m 0755 "$GWLINKD_REAL_DIR"
install_gwlinkd "$GWLINKD_URL" "$(gwlinkd_sha || true)" "$SUDO" "$GWLINKD_REAL_DIR"
# 交给运行身份：**目录与文件都归它**（原子 rename 需要目录可写，只给文件写权限不够）。
$SUDO chown "$DEPLOY_USER" "$GWLINKD_REAL_DIR" "$GWLINKD_REAL"
$SUDO ln -sfn "$GWLINKD_REAL" "$GWLINKD_BIN"

# 中心 CA 信任锚：写到渲染配置里 GWLINKD_TRUST_BUNDLE 指向的路径（自签中心必需）。
if grep -q 'BEGIN CERTIFICATE' "$CA_CENTER" 2>/dev/null; then
  mkdir -p "$(dirname "$GWLINKD_CA")"
  install -m 0644 "$CA_CENTER" "$GWLINKD_CA"
fi

[ -f "$GWLINKD_TOML" ] || { echo "未找到渲染后的 $GWLINKD_TOML —— 该网关栈版本可能还不支持 gwlinkd（请先升级 wist-gateway-stack 再重跑）。" >&2; exit 1; }
[ -f "$GWLINKD_PUB" ] || { echo "未找到现场态配置 $GWLINKD_PUB —— localize 没跑成？" >&2; exit 1; }

# 装成**系统级服务、非 root 运行**（--run-as）：开机自启 / 崩溃拉起，进程属主 = 部署用户。
RUN_AS_OPT=''
if [ "$(id -u)" != "0" ]; then RUN_AS_OPT="--run-as $DEPLOY_USER"; fi
$SUDO "$GWLINKD_BIN" service install --system $RUN_AS_OPT --bin "$GWLINKD_BIN" --config "$GWLINKD_TOML" --pub-config "$GWLINKD_PUB" --force
$SUDO "$GWLINKD_BIN" service status --system || true
log "wist-gwlinkd 已安装并常驻（user=${DEPLOY_USER}，config=${GWLINKD_TOML}，pub=${GWLINKD_PUB}）；到网关页「链接上级」完成接入（gateway_id=${GATEWAY_ID}）"
log '完成。'
"#;
