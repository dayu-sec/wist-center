// 网关「脚本安装」：GET /api/v1/gateway/install-script?gateway_id=<id>&token=<token>
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
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::infra::{ReleasePackageRecord, group_release_packages, sha256_hex};

use super::{ApiState, PeerConnectInfo, extract::ApiQuery, rate_limit};

/// 脚本安装端点限流桶：token 在 URL 里，独立桶防暴力枚举。
const GATEWAY_INSTALL_SCRIPT_SCOPE: &str = "gateway-install-script";

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

/// 生成脚本安装命令（放进安装指引，供 admin 页面展示/复制）。
/// 形如 `curl -fsSLk '<center>/api/v1/gateway/install-script?gateway_id=..&token=..' | bash`。
pub fn build_install_script_command(
    public_url: &str,
    gateway_id: &str,
    link_token: &str,
) -> String {
    let endpoint = format!(
        "{}/api/v1/gateway/install-script?gateway_id={}&token={}",
        public_url.trim_end_matches('/'),
        url_encode(gateway_id),
        url_encode(link_token),
    );
    // -k：新主机尚不信任中心自签 CA，脚本下载走 TLS 传输即可（端点内容由一次性 token 限定）；
    // 与网关 docker 安装命令取同一口径。
    format!("curl -fsSLk '{endpoint}' | bash")
}

/// 取脚本：校验一次性接入券（只校验不消费）→ 解析最新制品 → 渲染脚本。
pub async fn get_gateway_install_script(
    State(state): State<ApiState>,
    client: PeerConnectInfo,
    ApiQuery(params): ApiQuery<InstallScriptQueryParams>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) =
        rate_limit::check_rate_limit(&state, &client_key, GATEWAY_INSTALL_SCRIPT_SCOPE)
    {
        return response;
    }
    let gateway_id = params.gateway_id.trim();
    if gateway_id.is_empty() {
        return super::error::ApiError::bad_request(
            super::codes::GATEWAY_ID_REQUIRED,
            "gateway_id must not be empty",
        )
        .into_response();
    }
    let Some(token) = params
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_INSTALL_SCRIPT_SCOPE);
        return super::error::ApiError::unauthorized(
            super::codes::MISSING_INSTALL_TOKEN,
            "missing install token",
        )
        .with_no_store()
        .into_response();
    };
    // 校验一次性接入券：网关存在、券 hash 匹配、未过期。**不消费**（留给 link-upstream）。
    let gateway = match state.store.get_gateway(gateway_id).await {
        Ok(Some(gateway)) => gateway,
        Ok(None) => {
            rate_limit::record_auth_failure(&state, &client_key, GATEWAY_INSTALL_SCRIPT_SCOPE);
            return super::error::ApiError::unauthorized(
                super::codes::UNKNOWN_GATEWAY,
                "unknown gateway",
            )
            .with_no_store()
            .into_response();
        }
        Err(err) => {
            return super::error::internal_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                super::codes::GATEWAY_STORE_UNAVAILABLE,
                "failed to load gateway store",
                err.display_chain(),
            );
        }
    };
    if gateway.link_token_hash.is_empty() || sha256_hex(token) != gateway.link_token_hash {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_INSTALL_SCRIPT_SCOPE);
        return super::error::ApiError::unauthorized(
            super::codes::INVALID_INSTALL_TOKEN,
            "invalid install token",
        )
        .with_no_store()
        .into_response();
    }
    if link_token_expired(gateway.link_token_expires_at.as_deref()) {
        rate_limit::record_auth_failure(&state, &client_key, GATEWAY_INSTALL_SCRIPT_SCOPE);
        return super::error::ApiError::unauthorized(
            super::codes::INSTALL_TOKEN_EXPIRED,
            "install token expired",
        )
        .with_no_store()
        .into_response();
    }
    rate_limit::clear_auth_failures(&state, &client_key, GATEWAY_INSTALL_SCRIPT_SCOPE);

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
        return super::error::ApiError::unavailable(super::codes::INSTALL_SCRIPT_UNAVAILABLE, "install script unavailable: publish galaxy-ops / galaxy-flow / wist-gateway-stack releases first")
            .into_response();
    };
    // 宿主接入器：**可选** —— 未发布时脚本照常生成，只是跳过这一步（见脚本内的可读提示）。
    let gwlinkd = match latest_published_package(&state, GWLINKD_COMPONENT).await {
        Ok(package) => package,
        Err(response) => return response,
    };

    let script = render_install_script(
        state.config.public_url.trim_end_matches('/'),
        gateway_id,
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

/// 脚本模板：用占位符替换（避免 `format!` 与 shell 花括号打架）。
const SCRIPT_TEMPLATE: &str = r#"#!/usr/bin/env bash
# WarpInsightCenter · 网关脚本安装（gateway_id=__GATEWAY_ID__）
#
# 由中心自动生成：装 gops / gx（取中心最新发布制品）→ gops prj new → prj import gateway-stack
# → sys localize → run download → run start → 装宿主侧 wist-gwlinkd（把本网关接入中心）。
set -euo pipefail

CENTER_URL='__CENTER_URL__'
GATEWAY_ID='__GATEWAY_ID__'
PROJECT_NAME='__PROJECT_NAME__'
INSTALL_DIR="${HOME}/bin"
CA_DIR="$HOME/.wist-center/ca"
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
  log "下载 $name：$url"
  curl -fsSL "${CURL_TLS[@]}" "$url" -o "$d/pkg"
  if [ -n "$want_sha" ]; then
    have="$(sha256_of "$d/pkg" || true)"
    if [ -z "$have" ]; then
      log "提示：本机无 sha256sum/shasum，跳过 $name 的摘要校验"
    elif [ "$have" != "$want_sha" ]; then
      echo "下载校验失败 $name：期望 $want_sha，实际 $have" >&2
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
    echo "解包 $name 失败（$url）：tar 与 python3 均不可用？" >&2
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
VALUES_FILE="values/wist-gateway-stack/sys_value.yml"
mkdir -p "$(dirname "$VALUES_FILE")"
if grep -qE '^WEB_DOMAIN:' "$VALUES_FILE" 2>/dev/null; then
  sed -E "s|^WEB_DOMAIN:.*|WEB_DOMAIN: ${GATEWAY_DOMAIN}|" "$VALUES_FILE" > "$VALUES_FILE.tmp"
  mv "$VALUES_FILE.tmp" "$VALUES_FILE"
else
  printf 'WEB_DOMAIN: %s\n' "$GATEWAY_DOMAIN" >> "$VALUES_FILE"
fi

# d) 变量解析 + 本地化（把域名等现场值烘进 .env 与渲染配置）
log "gops sys localize"
cd "$PROJECT_ROOT/wist-gateway-stack"
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
#    以**部署用户**身份常驻（非 root）：身份回写 / gops 升级都落在部署用户属主下；
#    配置与 state 就放该用户家目录（gwlinkd 要能回写 gwlinkd.toml）。
GWLINKD_URL="$(gwlinkd_url || true)"
if [ -z "$GWLINKD_URL" ]; then
  log "跳过 wist-gwlinkd：中心未发布本平台制品（发布后重跑安装即可补装）"
else
  log "安装 wist-gwlinkd（宿主侧接入器）"
  DEPLOY_USER="$(id -un)"
  if [ "$(id -u)" = "0" ]; then SUDO=""
  elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
  else
    echo "安装 wist-gwlinkd 需要 root 或 sudo（写 /usr/local/bin 与系统服务定义）" >&2
    exit 1
  fi

  GWLINKD_BIN="/usr/local/bin/wist-gwlinkd"
  GWLINKD_HOME="$HOME/.wist-gwlinkd"
  GWLINKD_STATE="$GWLINKD_HOME/state"
  GWLINKD_CA="$GWLINKD_HOME/ca/control-center.pem"
  GWLINKD_TOML="$GWLINKD_HOME/gwlinkd.toml"

  # 配置 / state / CA 都归部署用户（gwlinkd 会回写 gwlinkd.toml、落客户端证书），无需 sudo。
  mkdir -p "$GWLINKD_HOME/ca" "$GWLINKD_STATE"
  install_component wist-gwlinkd "$GWLINKD_URL" "$(gwlinkd_sha || true)" /usr/local/bin "$SUDO"

  # 中心 CA 信任锚：gwlinkd 校验中心 TLS 用（自签中心必需）。
  if grep -q 'BEGIN CERTIFICATE' "$CA_CENTER" 2>/dev/null; then
    install -m 0644 "$CA_CENTER" "$GWLINKD_CA"
  fi

  # 网关环回自述面：页面路「链接上级」需要。端口取栈 .env 的 GATEWAY_PORT（缺省 443）。
  GATEWAY_PORT_VALUE=""
  for f in "$PROJECT_ROOT/wist-gateway-stack/.env" "$PROJECT_ROOT/wist-gateway-stack/sys/.env"; do
    if [ -f "$f" ]; then
      GATEWAY_PORT_VALUE="$(sed -n 's/^GATEWAY_PORT=//p' "$f" | head -n1)"
      if [ -n "$GATEWAY_PORT_VALUE" ]; then break; fi
    fi
  done
  [ -n "$GATEWAY_PORT_VALUE" ] || GATEWAY_PORT_VALUE=443
  if [ -z "${GATEWAY_SELF_ENDPOINT:-}" ]; then
    if [ "$GATEWAY_PORT_VALUE" = "443" ]; then GATEWAY_SELF_ENDPOINT="https://127.0.0.1"
    else GATEWAY_SELF_ENDPOINT="https://127.0.0.1:$GATEWAY_PORT_VALUE"; fi
  fi
  GATEWAY_SELF_CA="$PROJECT_ROOT/wist-gateway-stack/configs/gateway/state/gateway-ca.crt.pem"

  # 渲染 gwlinkd.toml（服务启动 cwd 不定，路径必须绝对）。以部署用户写，gwlinkd 才能回写。
  {
    printf '# 由 WarpInsightCenter 安装脚本生成（gateway_id=%s）\n' "$GATEWAY_ID"
    printf 'control_center_endpoint = "%s"\n' "$CENTER_URL"
    printf 'trust_bundle = "%s"\n' "$GWLINKD_CA"
    printf 'state_dir = "%s"\n' "$GWLINKD_STATE"
    printf 'gateway_id = "%s"\n' "$GATEWAY_ID"
    printf 'gateway_self_endpoint = "%s"\n' "$GATEWAY_SELF_ENDPOINT"
    if [ -f "$GATEWAY_SELF_CA" ]; then printf 'gateway_self_ca = "%s"\n' "$GATEWAY_SELF_CA"; fi
    printf 'upgrader_program = "gops"\n'
    printf 'upgrade_project_dir = "%s"\n' "$PROJECT_ROOT"
  } > "$GWLINKD_TOML"

  # 装成**系统级服务、非 root 运行**（--run-as）：开机自启 / 崩溃拉起，进程属主 = 部署用户。
  RUN_AS_OPT=""
  if [ "$(id -u)" != "0" ]; then RUN_AS_OPT="--run-as $DEPLOY_USER"; fi
  $SUDO "$GWLINKD_BIN" service install --system $RUN_AS_OPT --bin "$GWLINKD_BIN" --config "$GWLINKD_TOML" --force
  $SUDO "$GWLINKD_BIN" service status --system || true
  log "wist-gwlinkd 已安装并常驻（user=$DEPLOY_USER）；到网关页「链接上级」完成接入（gateway_id=$GATEWAY_ID）"
fi

log "完成：工程 $PROJECT_ROOT（gateway_id=$GATEWAY_ID）"
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

/// 渲染安装脚本：把中心地址、网关身份、各组件制品（地址 + 摘要）与域名填进模板。
#[allow(clippy::too_many_arguments)]
fn render_install_script(
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
    SCRIPT_TEMPLATE
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
# WarpInsightCenter · 网关前置环境准备
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
