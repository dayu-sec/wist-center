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
# 宿主工具目录：gops / gx 必须落在**服务能看到的 PATH** 里 —— gwlinkd 是系统服务
# （systemd / launchd 默认 PATH 只有系统目录），它派生 `gops`，`gops` 再派生 `gx run localize`。
# 系统作用域固定以 root 运行，所以默认落 `/usr/local/bin`（root 可写、本就在服务 PATH 里，
# 且 `tool-copy` 升级是**就地 rename**，目录必须可写）。用 `--user` 作用域时用 `WIST_TOOL_DIR`
# 指到当前用户可写的目录。
LEGACY_BIN_DIR="$HOME/bin"
if [ -n "${WIST_TOOL_DIR:-}" ]; then TOOL_DIR="$WIST_TOOL_DIR"
else TOOL_DIR="/usr/local/bin"
fi
CA_DIR="$HOME/.wist/ca"
CA_CENTER="$CA_DIR/control-center.pem"
CA_BUNDLE="$CA_DIR/ca-bundle.pem"

log() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }

# 系统服务定义要 root 才能写：一次定好前缀，后面统一复用。
if [ "$(id -u)" = "0" ]; then SUDO=""
elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
else
  echo "安装 wist-gwlinkd 需要 root 或 sudo（写 /usr/local/lib 与系统服务定义）" >&2
  exit 1
fi

# 先按当前身份建（$HOME/bin 归本人，不能 sudo 建出 root 属主）；建不了再借 sudo。
mkdir -p "$TOOL_DIR" 2>/dev/null || $SUDO install -d -m 0755 "$TOOL_DIR"
# 目录不可写（典型：/usr/local/bin 而当前不是 root）→ **这次安装**借 sudo。
# 但这只解决安装：运行期自升级仍要求该目录对运行身份可写，所以上面默认按身份选目录。
TOOL_SUDO=""
if [ ! -w "$TOOL_DIR" ]; then
  TOOL_SUDO="$SUDO"
  # 变量紧邻全角括号必须写 `${TOOL_DIR}`：UTF-8 locale 下 bash 会把 `（` 吃进变量名，
  # `set -u` 直接报 `TOOL_DIR?: unbound variable`（安装第一步就挂）。
  [ "$(id -u)" = "0" ] || log "提示：本次用 sudo 写入 ${TOOL_DIR}（服务以 root 运行，运行期就地升级没问题）"
fi
mkdir -p "$CA_DIR"
export PATH="$TOOL_DIR:$LEGACY_BIN_DIR:$HOME/.local/bin:$PATH"

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
  # **git 不读 SSL_CERT_FILE**：Debian/Ubuntu 的 git 链接的是 libcurl-gnutls，GnuTLS 不认该变量
  # （curl 命令行走 OpenSSL 所以能验）。`GIT_SSL_CAINFO` → CURLOPT_CAINFO，对所有 TLS 后端都生效；
  # 不设它就是下面 `git clone` 报 `server certificate verification failed. CAfile: none`。
  export GIT_SSL_CAINFO="$CA_BUNDLE"
  CURL_TLS=(--cacert "$CA_BUNDLE")
  log "已载入中心 CA（TLS 全程校验）：$CA_BUNDLE"
  # 再落一遍**系统信任库**（Linux）：脚本退出后，运维手敲的 git/curl/docker 也直接信任这套中心，
  # 不必再记 SSL_CERT_FILE / GIT_SSL_CAINFO。幂等：同中心主机名同名覆盖，多套中心互不干扰。
  # 失败不阻断（环境变量已能盖住本脚本自己的所有下载）。
  ca_host="$(printf '%s' "$CENTER_URL" | sed -E 's#^[A-Za-z]+://##; s#[/:].*$##')"
  ca_name="wist-control-center-${ca_host}.crt"
  if command -v update-ca-certificates >/dev/null 2>&1; then
    $SUDO install -m 0644 "$CA_CENTER" "/usr/local/share/ca-certificates/$ca_name" 2>/dev/null \
      && $SUDO update-ca-certificates >/dev/null 2>&1 \
      && log "已信任中心 CA（系统库）：/usr/local/share/ca-certificates/$ca_name" \
      || log "提示：写系统信任库失败（不阻断；git 仍用 GIT_SSL_CAINFO）"
  elif command -v update-ca-trust >/dev/null 2>&1; then
    $SUDO install -m 0644 "$CA_CENTER" "/etc/pki/ca-trust/source/anchors/$ca_name" 2>/dev/null \
      && $SUDO update-ca-trust >/dev/null 2>&1 \
      && log "已信任中心 CA（系统库）：/etc/pki/ca-trust/source/anchors/$ca_name" \
      || log "提示：写系统信任库失败（不阻断；git 仍用 GIT_SSL_CAINFO）"
  elif [ "$(uname -s)" = "Darwin" ]; then
    # macOS 的 gops（rustls-platform-verifier）**只认钥匙串**，不读 SSL_CERT_FILE/GIT_SSL_CAINFO；
    # 所以这步必须**真做**，否则下面 `gops prj import` 回源会 UnknownIssuer。
    if [ "${WIST_TRUST_CENTER_CA:-1}" = "0" ]; then
      log "跳过中心 CA 入钥匙串（WIST_TRUST_CENTER_CA=0）—— gops 回源可能验不过"
    elif $SUDO security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_CENTER" 2>/dev/null; then
      log "已信任中心 CA（系统钥匙串）：$CA_CENTER"
    else
      log "提示：写钥匙串失败（可能已存在）。若 gops 报 UnknownIssuer，手工执行：sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CA_CENTER"
    fi
  fi
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
  name="$1"; url="$2"; want_sha="${3:-}"; dest="${4:-$TOOL_DIR}"; use_sudo="${5:-}"
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

# a) 安装 gops / gx（带摘要校验）→ 落 TOOL_DIR（服务 PATH 内）
install_component gops "$(gops_url)" "$(gops_sha || true)" "$TOOL_DIR" "$TOOL_SUDO"
install_component gx "$(gx_url)" "$(gx_sha || true)" "$TOOL_DIR" "$TOOL_SUDO"
hash -r 2>/dev/null || true
log "gops: $(gops --version 2>/dev/null || echo ok) · gx: $(gx --version 2>/dev/null || echo ok)"
# 旧装法的副本（$HOME/bin）会按 PATH 顺序抢先：不是错，但两份会逐渐版本不一致 —— 提醒一句。
for tool in gops gx; do
  found="$(type -P "$tool" || true)"
  [ "$found" = "$TOOL_DIR/$tool" ] || log "提示：$tool 解析到 ${found:-<无>}（不是 $TOOL_DIR/${tool}）；旧副本建议移走"
done

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
#    直接让 gops 回源取（不再先 curl 下到本地）：CA 已在上面落进**系统信任库**，
#    gops 的 rustls 在 Linux 走 rustls-native-certs（读系统 bundle）、macOS 走平台校验
#    （读钥匙串，上面已用 security 装好），两边都能验。
#    走本地临时包反而会把 `addr` 记成 /tmp 路径（随后被删）—— 后续 `gops prj upgrade -v X` 就找不到包。
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
# 执行器也写**绝对路径**（TOOL_DIR 内）：gwlinkd 是系统服务，PATH 不含 $HOME/bin；
# 写相对名 `gops` 会在 spawn 时 ENOENT（os error 2）。
set_value "$VALUES_FILE" GWLINKD_UPGRADER_PROGRAM "$TOOL_DIR/gops"
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

  # 装成**系统级服务**：开机自启 / 崩溃拉起（system 作用域固定以 root 运行）。
  $SUDO "$GWLINKD_BIN" service install --system --bin "$GWLINKD_BIN" --config "$GWLINKD_TOML" --pub-config "$GWLINKD_PUB" --force
  $SUDO "$GWLINKD_BIN" service status --system || true
  # 自检（只提示，不阻断）：安装 / 升级完立刻把「信任锚 / 中心可达 / 环回面」的问题摆出来。
  # 信任锚是**现场值**（identity/gwlinkd/.env），站点搬过目录时可能还指着旧路径 —— 这里能直接看到 FAIL。
  log '自检：wist-gwlinkd diagnose'
  "$GWLINKD_BIN" diagnose 2>&1 | sed 's/^/  /' || true
  log "wist-gwlinkd 已安装并常驻（user=${DEPLOY_USER}，config=${GWLINKD_TOML}，pub=${GWLINKD_PUB}）；到网关页「链接上级」完成接入（gateway_id=${GATEWAY_ID}）"
fi

log "完成：工程 ${PROJECT_ROOT}（gateway_id=${GATEWAY_ID}）"
