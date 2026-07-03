## 什么是 SmartDNS Edge？

SmartDNS Edge 是使用 Rust 语言重写的本地 DNS 智能网关。它能够获取多个上游 DNS 的解析结果，并通过测速算法动态获取最快的网站 IP 响应，从而显著提升网络访问响应速度与网页加载体验。

## ✨ 13 大核心特性

*   **1. 多虚拟 DNS 网关与多上游高可用**

    支持在不同端口上配置多个虚拟 DNS 网关。支持配置多个上游 DNS 服务器进行并发查询，即使部分上游节点异常也完全不影响解析效率。多 IP 节点引入错峰延迟以减轻突发网络拥堵，并具备全局 5 秒 SLA 超时硬死线以防连接卡死。
	
*   **2. 极速最快 IP 优选与并发测速引擎**

    多线程并发网络探针测试，自动从解析到的所有 IP 中挑选延迟最低的 IP 返回给客户端，显著缩短网页打开时间。在同 IP 探测中加入微错峰延迟以规避丢包干扰；针对 HTTPS 测速自动附加 Host 头和 SNI 特征，确保穿透 CDN 节点时的测速准确。

*   **3. 局域网设备独立控制与微秒级身份检索**

    支持基于客户端物理 MAC 地址或内网 IP 分配独立的过滤规则组（如家长控制、视频拦截）。Windows 平台直接调用系统底层原生 SendARP API，将 MAC 检索耗时从毫秒级缩短至微秒级，保障高并发下的网关吞吐率。

*   **4. 丰富前沿协议支持与 DoH3 智能升维**

    全面支持 UDP, TCP, DoT, DoH, DoQ, DoH3 以及非标准端口上游查询。内置代理协议智能降级机制（若代理不支持 UDP，自动将 QUIC/H3 降级至 DoT/DoH 安全通道）。提供 DoH3 智能升维发现，主动引导现代浏览器升级至抗丢包能力极强的 HTTP/3 协议。

*   **5. 静态 IP 劫持、IP 别名与重写映射**

    支持强制将广告、恶意域名重定向到指定 IP（如 0.0.0.0）进行阻断。新增高级的 IP 别名重写映射功能，若上游返回了特定的 IP 段，系统可以在底层自动将其映射和替换为用户自定义的目标 IP。

*   **6. 20 万级规则毫秒匹配与无损平滑合并**

    底层采用超高性能域名后缀匹配算法，支持 DomainSet 规则列表（如去广告规则）通过本地代理安全下载。重构规则合并器，实现多重复杂冲突规则（如测速模式与防火墙集合重叠）的数组级无损合并，避免配置被覆盖。

*   **7. 智能分流与 Linux 防火墙内核级联动**

    支持根据域名类型进行多组上游路由，与 Linux iptables/nftables 的 ipset/nftset 集合深度联动。Linux 平台支持 Nftset 批量数组级注入以减少系统调用开销，并设有最大 512 的内核级并发通道防卡死保护，配合透明代理程序，实现高效分流。

*   **8. 智能双栈优选、AAAA 屏蔽与防空包机制**

    A 与 AAAA 记录并发测速优选，且双栈记录的过期时间强行严格对齐。引入双栈并行防空包机制（任一单栈返回空包时强制等待另一方结果），避免网络污染导致抢答失败。支持全局 AAAA 记录强行返回空 SOA，规避无原生 IPv6 时的解析卡顿。

*   **9. 智能 DNS64 转换与内网隐私防泄露**

    在纯 IPv6-only 环境下，只要上游未返回 IPv6 记录（无论是否报错），均可自动将纯 IPv4 转换为合规的 IPv6 记录。内置局域网反向查询拦截机制，自动拦截并抛弃所有内网 IP 的反向域名查询，保护内网拓扑不被泄露。

*   **10. 高性能缓存数据库分段锁革命（RFC合规）**

    弃用旧版的单线程全局锁，将缓存数据库切分为 64 个完全独立的分段（Segmented Locking）。锁竞争率骤降至 1/64，完美释放多核 CPU 并发性能。缓存完整保存 Answer、Authority 和 Additional 三大区报文，完全符合 EDNS0 与 RFC 规范。支持 CNAME 展平与离线时间精准扣除。

*   **11. 无感乐观缓存与热度预取管理**

    支持 Serve-Expired 乐观缓存，当上游断网或代理短暂卡死时，系统优先秒回历史记录让网页瞬间打开。限制只有访问热度≥2且未超过 serve_expired_prefetch_time 时间的缓存才会触发后台预取更新，杜绝冷门域名无限预取导致的僵尸缓存与流量消耗。

*   **12. 多维物理级防攻击与异常自愈运行**

    密码校验强制使用阻断编译器优化的恒定时间验证，封杀侧信道时序攻击；UDP 降载沉默丢包以防反射攻击；DoH 强行物理截断不超 64KB 报文以防内存溢出；TLS 握手套上 5 秒绝对超时。加载本地持久化文件损坏时，自动删档并重建启动，保证系统不因非正常关机坏档而陷入死循环。

*   **13. 全平台绿色部署运行**

    原生满血支持 Windows、macOS (Intel/M系列)、普通 Linux 服务器、OpenWrt 固件、华硕路由器系统以及 WSL 容器环境。

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