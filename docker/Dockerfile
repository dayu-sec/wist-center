# ===========================================================================
# wist-center — Runtime Docker Image (Multi-arch)
#
# 产物是 **musl 静态二进制**（release 流水线按 amd64/arm64 分目录提供），
# 运行时不需要 glibc / 发行版工具链：
#   · 基于 alpine + ca-certificates（rustls 访问 VictoriaMetrics / S3 / GitHub 时需要）；
#   · 镜像里只多一个 `apk add ca-certificates`，**原生分架构构建**下只需几秒
#     （之前 QEMU 模拟 arm64 时，`apt-get update/install` 单步要 8–10 分钟）；
#   · 镜像从 ~184MB（ubuntu 基础层 + apt）降到 ~40MB。
#
# 配置（admin token / hmac secret / CA 证书 / 存储）与环境相关，通过卷挂载注入，
# 不烘焙进镜像：
#   docker run -d -v ./configs/center:/wist-center -p 3100:3100 wist-center
#
# 部署注意：
#   - 容器内 listen_addr 必须是 0.0.0.0:3100（默认 127.0.0.1:3100，端口映射不进来）；
#   - 中心自身不做 TLS，HTTPS 由前面的反代终止；public_url 必须落在控制中心服务器
#     证书的 SAN 内，否则网关侧对 init_url 的主机名校验会失败；
#   - `state/`、`logs/`、`artifacts/` 必须由卷挂载提供（镜像内 `/wist-center` 归 root，
#     运行用户只读；compose 已按语义拆开挂载）。
# ===========================================================================

FROM docker.io/library/alpine:3.20

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-center"
LABEL org.opencontainers.image.description="Aggregation and governance service for the wist control plane"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# 仅 CA 根证书。运行身份用**数字 uid/gid**（与 compose 的 999:999 对齐）：
# Alpine 的 gid 999 已被 `ping` 组占用，不再创建同名用户，避免与基础镜像冲突。
RUN apk add --no-cache ca-certificates \
    && mkdir -p /wist-center/state /wist-center/logs /wist-center/artifacts \
    && chown -R 999:999 /wist-center

# 预编译二进制（build context 按架构提供：amd64/wist-center、arm64/wist-center）
COPY ${TARGETARCH}/wist-center /usr/local/bin/wist-center

WORKDIR /wist-center
ENV WIST_CENTER_CONFIG=/wist-center/wist-center.toml

# 控制面 HTTP/HTTPS 端口 + 规则发布兼容入口（wparse-proxy）
EXPOSE 3100 3101

USER 999:999

ENTRYPOINT ["wist-center"]
CMD []
