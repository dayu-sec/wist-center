# ===========================================================================
# wist-center — Runtime Docker Image (Multi-arch)
#
# 与 wist-gateway 同构：预编译二进制 + 最小运行时。build context 下按 amd64/ arm64/
# 分目录提供 Linux 产物（由 release 流水线的 docker job 暂存），本文件只负责打包。
#
# 配置（admin token / hmac secret / CA 证书 / 存储）与环境相关，通过卷挂载注入，
# 不烘焙进镜像：
#   docker run -d -v ./configs/center:/wist-center -p 3100:3100 wist-center
#
# 两处部署注意：
#   - 容器内 listen_addr 必须是 0.0.0.0:3100（默认 127.0.0.1:3100，端口映射不进来）；
#   - 中心自身不做 TLS，HTTPS 由前面的反代终止；public_url 必须落在控制中心服务器
#     证书的 SAN 内，否则网关侧对 init_url 的主机名校验会失败。
# ===========================================================================

FROM ubuntu:24.04

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-center"
LABEL org.opencontainers.image.description="Aggregation and governance service for the wist control plane"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# 运行时依赖：出站（VictoriaMetrics / S3）走 rustls，不依赖系统 openssl，仅保留根证书。
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false wist

# 预编译二进制（build context 按架构提供：amd64/wist-center、arm64/wist-center）
COPY ${TARGETARCH}/wist-center /usr/local/bin/wist-center

# 运行期目录：config / state（JSON store / 制品）由卷挂载到 /wist-center
RUN mkdir -p /wist-center/state && chown -R wist:wist /wist-center

USER wist
WORKDIR /wist-center
ENV WIST_CENTER_CONFIG=/wist-center/wist-center.toml

# 控制面 HTTP 端口
EXPOSE 3100

ENTRYPOINT ["wist-center"]
CMD []
