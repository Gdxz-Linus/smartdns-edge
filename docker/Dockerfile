
# 🌟 阶段一：解压器 (使用 debian:stable-slim 保持与 gnu 编译环境一致)
FROM --platform=$BUILDPLATFORM debian:stable-slim AS downloader
WORKDIR /app

# 仅创建我们保留的 2 个核心企业级平台的临时目录
RUN mkdir -p /app/x86 /app/arm64 /app/extracted/x86 /app/extracted/arm64

# 复制我们新编译的企业级 gnu 压缩包
COPY ./smartdns-x86_64-generic-linux-gnu.tar.gz /app/x86/smartdns.tar.gz
COPY ./smartdns-aarch64-generic-linux-gnu.tar.gz /app/arm64/smartdns.tar.gz

# 解压提取主程序
RUN tar -xzf /app/x86/smartdns.tar.gz -C /app/extracted/x86
RUN tar -xzf /app/arm64/smartdns.tar.gz -C /app/extracted/arm64


# 🌟 阶段二：基础运行环境 (放弃 alpine，改用内置完整 glibc 且体极其轻巧的 debian-slim)
FROM debian:stable-slim AS base
WORKDIR /app

# 拷贝入口运行脚本 (debian-slim 默认已内置 bash)
COPY ./docker/docker-entrypoint.sh /app/entrypoint.sh

# 🌟 核心优化 1：强制赋予执行权限，防止 Windows 环境下 Git 提交导致的可执行权限丢失暗坑！
RUN chmod +x /app/entrypoint.sh


# 🌟 阶段三：分流提取
# 1. 提取 x86_64 (amd64) 平台的程序和默认配置
FROM base AS amd64
COPY --from=downloader /app/extracted/x86/* /app/

# 2. 提取 aarch64 (arm64) 平台的程序 and 默认配置
FROM base AS arm64
COPY --from=downloader /app/extracted/arm64/* /app/


# 🌟 阶段四：根据构建平台动态输出最终镜像 (amd64 或 arm64)
FROM ${TARGETARCH}${TARGETVARIANT} AS final

# 🌟 核心优化 2：完善声明端口（包含标准 DNS 53 端口和 WebAPI / Swagger 网页管理控制台端口）
EXPOSE 53/udp 53/tcp 8000

# 🌟 核心优化 3：改用更符合规范的 ENTRYPOINT 作为容器主程序入口
ENTRYPOINT ["/app/entrypoint.sh"]