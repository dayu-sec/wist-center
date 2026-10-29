#!/usr/bin/env bash
# WistCenter · 网关脚本安装（gateway_id=__GATEWAY_ID__）
#
# 由中心自动生成：装 gops / gx（取中心最新发布制品）→ git clone 部署工程（模板仓库）
# → prj import gateway-stack → sys localize → run download → run start
# → 装宿主侧 wist-gwlinkd（把本网关接入中心）。
set -euo pipefail

CENTER_URL='__CENTER_URL__'
GATEWAY_ID='__GATEWAY_ID__'
# 部署工程仓库：由中心配置 `[artifacts] gateway_project_repo`（部署栈里来自 vars 的
# GATEWAY_PRJ_TPL_REPO，可在 ops-prj 的 sys_value.yml 覆盖）。
PROJECT_REPO='__PRJ_REPO__'
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
if ! command -v git >/dev/null 2>&1; then
  echo "缺少 git（克隆部署工程 ${PROJECT_REPO} 需要）—— 请先运行环境准备脚本：" >&2
  echo "  curl -fsSLk \"$CENTER_URL/api/v1/gateway/prepare-script\" | bash" >&2
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

# b) 取部署工程：**直接 clone** 运维工程仓库（不再用 `gops prj new` 现生成）。
#    工程自带 ops-prj.yml 与 values/wist-gateway-stack/sys_value.yml（现场值模板）。
#    重跑：已是 git 仓库就拉更新（失败不阻断，沿用现有内容）；非仓库目录则明确报错。
PROJECT_ROOT="$PWD/$PROJECT_NAME"
if [ -d "$PROJECT_ROOT/.git" ]; then
  log "复用已存在的工程：$PROJECT_ROOT"
  git -C "$PROJECT_ROOT" pull --ff-only || log "提示：git pull 未完成（本地改动 / 网络），沿用现有内容"
elif [ -e "$PROJECT_ROOT" ]; then
  echo "目录已存在但不是 git 仓库：$PROJECT_ROOT —— 请移走后重跑" >&2
  exit 1
else
  log "git clone $PROJECT_REPO"
  GIT_TERMINAL_PROMPT=0 git clone --depth 1 "$PROJECT_REPO" "$PROJECT_NAME"
fi
if [ ! -f "$PROJECT_ROOT/ops-prj.yml" ]; then
  echo "工程缺少 ops-prj.yml：$PROJECT_ROOT 不是 gops 运维工程（仓库对不上？）" >&2
  exit 1
fi
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
# 绝对路径：clone 下来的工程根确定后不再依赖 cwd（且 values/ 在工程根下，不在栈目录里）。
VALUES_FILE="$PROJECT_ROOT/values/wist-gateway-stack/sys_value.yml"

# 现场值统一写进 values（gops 的覆盖机制）：一份值，localize 时一致地烘进 .env / 配置 / 证书 SAN。
# 容忍 `KEY : value`（冒号前有空格）——现场手写的 sys_value.yml 常见这种写法，
# 不认就会追加出重复键（YAML 里后者覆盖前者，看起来“写了没生效”）。
set_value() {
  local file="$1" key="$2" value="$3"
  mkdir -p "$(dirname "$file")"
  if grep -qE "^${key}[[:space:]]*:" "$file" 2>/dev/null; then
    sed -E "s|^${key}[[:space:]]*:.*|${key}: ${value}|" "$file" > "$file.tmp"
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
GATEWAY_PORT_VALUE="$(sed -n 's/^GATEWAY_PORT[[:space:]]*:[[:space:]]*//p' "$VALUES_FILE" 2>/dev/null | head -n1)"
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
  # 自检（只提示，不阻断）：安装 / 升级完立刻把「信任锚 / 中心可达 / 环回面」的问题摆出来。
  # 信任锚是**现场值**（identity/gwlinkd/.env），站点搬过目录时可能还指着旧路径 —— 这里能直接看到 FAIL。
  log '自检：wist-gwlinkd diagnose'
  "$GWLINKD_BIN" diagnose 2>&1 | sed 's/^/  /' || true
  log "wist-gwlinkd 已安装并常驻（user=${DEPLOY_USER}，config=${GWLINKD_TOML}，pub=${GWLINKD_PUB}）；到网关页「链接上级」完成接入（gateway_id=${GATEWAY_ID}）"
fi

log "完成：工程 ${PROJECT_ROOT}（gateway_id=${GATEWAY_ID}）"
