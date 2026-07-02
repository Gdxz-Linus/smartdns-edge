---
hide:
  - navigation
  - toc
---

## 什么是 SmartDNS Edge？

SmartDNS Edge 是使用 Rust 语言重写的本地 DNS 智能网关。它能够获取多个上游 DNS 的解析结果，并通过测速算法动态获取最快的网站 IP 响应，从而显著提升网络访问响应速度与网页加载体验。

## ✨ 13 大核心特性

*   **1. 多虚拟 DNS 智能网关**
    支持在不同端口上配置多个虚拟 DNS 智能网关，每个虚拟网关可绑定独立的解析规则与特定的客户端。
*   **2. 多 DNS 上游高可用**
    支持配置多个上游 DNS 服务器进行并发查询，即使部分上游节点异常，也完全不影响解析效率与可用性。
*   **3. 客户端独立规则控制**
    支持基于 MAC 地址或 IP 地址分配独立的 DNS 过滤与查询规则，可轻松实现精细化的家长控制等功能。
*   **4. 极速最快 IP 优选**
    多线程并发测速，自动从解析到的所有 IP 中挑选访问速度最快的 IP 返回给客户端，显著缩短网页打开时间。
*   **5. 丰富前沿协议支持**
    全面支持 UDP, TCP, DoT, DoH, DoQ, DoH3 以及非 53 端口查询；支持通过本地 SOCKS5 或 HTTP 代理网络进行安全防污染解析。
*   **6. 静态 IP 劫持与恶意拦截**
    支持将特定域名强制重定向到指定 IP（如将广告或恶意网站强制解析到 `0.0.0.0` 从而实现强力拦截过滤）。
*   **7. 20 万级规则毫秒级匹配**
    支持超高性能的域名后缀匹配算法，简化繁琐的过滤规则配置，即使匹配 20 万条黑白名单规则，耗时也小于 1 毫秒。
*   **8. 智能域名分流与 IPSet/NftSet 注入**
    支持根据域名类型进行多组上游路由，支持与 Linux iptables/nftables 的 ipset/nftset 集合深度联动，在测速失败时自动将结果注入对应集合。
*   **9. 全平台绿色部署运行**
    原生满血支持 Windows、macOS (Intel/M系列)、普通 Linux 服务器、OpenWrt 固件、华硕路由器系统以及 WSL 容器环境。
*   **10. 智能双栈优选与 AAAA 屏蔽**
    支持 A 与 AAAA 记录并发测速优选，且 TTL 自动对齐；支持完全屏蔽 IPv6 域名解析以解决无原生 IPv6 时的解析卡顿。
*   **11. 完美的 DNS64 转换**
    支持将纯 IPv4 地址动态合成为 IPv6 地址，帮助 IPv6-only 网络环境无缝访问 IPv4 互联网资源。
*   **12. 高性能异步 I/O 与乐观缓存**
    采用多线程异步 I/O 架构，具备极高性能与极轻资源占用，配合内存持久化缓存，实现零延迟、无泄露的快速解析。
*   **13. 广泛的系统软件源整合**
    集成进主流路由系统（如 OpenWrt/华硕等）的官方软件源或极客套件中，极大降低用户的部署成本。

---

## 💻 支持的操作系统

### 🪟 Windows 系列（全面覆盖企业与现代桌面）
*底层架构：`x86_64` (主流 Intel/AMD) 与 `aarch64` (现代 ARM 处理器)*

*   **企业级服务器 (Windows Server)**：完美支持 Windows Server 2016, 2019, 2022 以及最新的 Windows Server 2025。
*   **个人桌面端 (Windows Desktop)**：完美支持 Windows 10 和 Windows 11。
*   **ARM 笔电生态**：原生满血支持搭载骁龙 X 芯片的新一代 Windows 11 ARM 笔记本。

### 🐧 Linux 系列
*底层架构：`x86_64-generic-linux-gnu` 与 `aarch64-generic-linux-gnu`*

*   **主流企业服务器 (Linux Server)**：
    *   Debian 阵营：Ubuntu Server (18.04 及以上), Debian (10 及以上)。
    *   红帽阵营 (RHEL)：CentOS (7/8/9), Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, Oracle Linux。
    *   其他商业 Server：SUSE Linux Enterprise, openSUSE。
*   **国产/个人桌面端 (Linux Desktop)**：Ubuntu Desktop, Fedora, Linux Mint, Deepin (深度操作系统), 统信 UOS, Manjaro 等。
*   **云服务器 / 边缘计算节点 (VPS & Edge)**：
    *   支持所有主流云厂商（阿里云、腾讯云、华为云、AWS、Azure、Google Cloud 等）的普通 x86_64 虚拟机。
    *   **【重点】**完美支持 AWS Graviton、阿里云倚天、Oracle 等高性能 ARM64 云服务器。
    *   支持安装了 64 位 Linux 系统的微型边缘主机（如树莓派 4、树莓派 5、NanoPi 等）。

### 🍎 macOS 系列（苹果生态全家桶）
*底层架构：`x86_64-apple-darwin` 与 `aarch64-apple-darwin`*

*   **老款 Mac 设备**：完美支持搭载 Intel 处理器的老款 MacBook、iMac、Mac mini。
*   **新款 Mac 设备**：原生支持搭载 M1、M2、M3、M4 芯片 (Apple Silicon) 的所有 Mac 设备。无需开启 Rosetta 转译，发挥出苹果芯片最极限的 I/O 性能。

### 🐳 云原生与容器化环境 (Docker / NAS)
*分发形式：全自动构建的 `ghcr.io` 多架构双端镜像 (amd64 / arm64)*

*   **网络附属存储 (NAS)**：完美运行于群晖 (Synology)、威联通 (QNAP)、极空间等主流 NAS 系统的 Docker 组件中。
*   **高级网络环境**：支持在 PVE/ESXi 下的虚拟机中运行，支持部署于 Kubernetes (K8s) 企业级编排集群。
*   **Windows 容器环境**：完美支持在 Windows 的 WSL2 (Windows Subsystem for Linux) Docker Desktop 中运行。