# What is SmartDNS Edge?

SmartDNS Edge is a local DNS intelligent gateway rewritten in the Rust programming language. It resolves DNS queries from multiple upstream servers, dynamically determines the fastest IP addresses using smart speed-testing algorithms, and significantly improves internet access speeds and web-loading experiences.

## ✨ Core Features

*   **1. Multi-Virtual DNS Gateways & High-Availability Upstreams**

    Supports configuring multiple virtual DNS gateways on different ports. Allows simultaneous queries to multiple upstream DNS servers for concurrent lookup, maintaining high resolution efficiency even if some upstream nodes are abnormal. Introduces a 250ms staggered delay for multi-IP nodes to alleviate sudden network congestion, and establishes a global 5-second SLA timeout deadline to prevent connection deadlocks.

*   **2. Ultra-Fast Optimal IP Selection & Concurrent Speed-Testing Engine**

    Uses multi-threaded concurrent network probes to automatically select and return the lowest-latency IP to the client from all resolved addresses, significantly reducing webpage loading times. Incorporates a 25ms micro-staggered delay for identical IP probes to avoid packet loss interference. Automatically attaches Host headers and SNI handshakes during HTTPS speed-testing to ensure accurate measurements when traversing CDN nodes.

*   **3. Independent LAN Device Control & Microsecond-Level Identity Retrieval**

    Supports assigning separate filtering rule groups (e.g., parental controls, video blocking) based on the client's physical MAC address or local IP address. On Windows, it directly invokes the native SendARP API at the system level, reducing MAC retrieval latency from milliseconds to microseconds and safeguarding gateway throughput under high concurrency.

*   **4. Comprehensive Future-Proof Protocol Support & Smart DoH3 Upgrade**

    Fully supports upstream queries via UDP, TCP, DoT, DoH, DoQ, DoH3, and non-standard ports. Features an intelligent proxy protocol downgrade mechanism (automatically downgrading QUIC/H3 to secure DoT/DoH channels if the proxy does not support UDP). Provides smart DoH3 upgrade discovery, proactively guiding modern browsers to upgrade to the highly loss-resistant HTTP/3 protocol.

*   **5. Static IP Hijacking, IP Aliasing & Rewrite Mapping**

    Supports forcing advertisements or malicious domains to be redirected to specified IPs (e.g., 0.0.0.0) for absolute blocking. Introduces an advanced IP alias rewriting and mapping feature; if the upstream returns specific IP segments, the system can automatically rewrite and map them to user-defined target IPs at the underlying level.

*   **6. Millisecond-Level Matching for 200K+ Rules & Lossless Smooth Merging**

    Uses an ultra-high-performance domain suffix matching algorithm at the core, supporting secure downloads of DomainSet rule lists (e.g., ad-blocking lists) through local proxies. Rebuilds the rule merger to achieve array-level, lossless merging of multiple complex and conflicting rules (e.g., overlapping speed-testing modes and firewall sets), preventing configurations from being silently overwritten.

*   **7. Intelligent Traffic Splitting & Kernel-Level Linux Firewall Integration**

    Supports routing domains to multiple upstream groups based on domain categories, deeply integrating with Linux iptables/nftables ipset/nftset collections. On Linux, it supports batch array-level injection for Nftset to reduce system call overhead, and features a maximum of 512 kernel-level concurrent channel locks to prevent deadlocks, working seamlessly with transparent proxies to achieve high-efficiency split-routing.

*   **8. Smart Dual-Stack Optimization, AAAA Blocking & Anti-Empty-Packet Mechanism**

    Optimizes concurrent speed tests for both A and AAAA records, forcing strict alignment of dual-stack TTL expiration times. Introduces a parallel dual-stack anti-empty-packet mechanism (forcing the system to wait for the other stack's results if either stack returns an empty response), preventing polluted empty packets from winning lookup races. Supports globally forcing empty SOA responses for AAAA records, completely bypassing lookup lags in environments without native IPv6.

*   **9. Intelligent DNS64 Translation & LAN Privacy Leak Prevention**

    In pure IPv6-only environments, as long as the upstream does not return an IPv6 record (regardless of errors), it automatically translates pure IPv4 addresses into compliant IPv6 records. Includes a built-in reverse DNS lookup interception mechanism for the LAN, automatically blocking and discarding all reverse queries targeting local IPs to prevent internal network topology exposure.

*   **10. High-Performance Cache DB Segmented Locking Revolution (RFC Compliant)**

    Abandons the legacy single-threaded global lock and divides the cache database into 64 fully independent segments (Segmented Locking). This slashes lock contention down to 1/64, unleashing the concurrent performance of multi-core CPUs. The cache fully preserves all three zones—Answer, Authority, and Additional—strictly complying with EDNS0 and RFC specifications. Supports CNAME flattening and precise boot-time deduction of offline duration.

*   **11. Seamless Optimistic Caching & Heat-Based Prefetching Management**

    Supports "Serve-Expired" optimistic caching; when upstream networks disconnect or proxies briefly freeze, the system prioritizes returning historical records instantly to open webpages without delay. Limits background prefetching updates to records with a query heat of $\ge 2$ that have not exceeded the `serve_expired_prefetch_time`, completely eliminating endless prefetching of inactive domains that causes zombie cache accumulation and bandwidth waste.

*   **12. Multi-Dimensional Physical-Level Attack Defense & Failure Self-Healing**

    Forces constant-time password verification with compiler optimization bypasses, neutralizing side-channel timing attacks. Employs "silent packet dropping" during UDP traffic shedding to prevent amplification and reflection attacks. Physically truncates DoH request payloads exceeding 64KB to stop memory overflow (OOM) exploits, and enforces a strict 5-second absolute timeout on TLS handshakes. Automatically purges corrupted local persistence cache files on startup and initializes from a clean slate, ensuring the system never enters boot-crash loops due to unexpected shutdowns.

*   **13. Fully Native Green Cross-Platform Deployment**

    Provides native out-of-the-box support for Windows, macOS (both Intel and Apple Silicon), standard Linux servers, OpenWrt firmware, ASUS router systems, and WSL container environments with zero external dependencies.

---

## 💻 Supported Operating Systems

### 🪟 Windows Series (Full Coverage of Enterprise & Modern Desktops)
*Underlying Architectures: `x86_64` (Mainstream Intel/AMD) & `aarch64` (Modern ARM Processors)*

*   **Enterprise Servers (Windows Server)**: Fully supports Windows Server 2016, 2019, 2022, and the latest Windows Server 2025.
*   **Personal Desktops (Windows Desktop)**: Fully supports Windows 10 and Windows 11.
*   **ARM Laptop Ecosystem**: Native out-of-the-box support for next-generation Snapdragon X Elite/Plus Windows 11 ARM laptops.

### 🐧 Linux Series
*Underlying Architectures: `x86_64-generic-linux-gnu` & `aarch64-generic-linux-gnu`*

*   **Mainstream Enterprise Servers (Linux Server)**:
    *   Debian Camps: Ubuntu Server (18.04 & above), Debian (10 & above).
    *   Red Hat Camps (RHEL): CentOS (7/8/9), Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, Oracle Linux.
    *   Other Commercial Servers: SUSE Linux Enterprise, openSUSE.
*   **Desktop & Distros (Linux Desktop)**: Ubuntu Desktop, Fedora, Linux Mint, Deepin, UnionTech UOS, Manjaro, etc.
*   **Cloud & Edge Nodes (VPS & Edge)**:
    *   Supports all mainstream cloud providers (Alibaba Cloud, Tencent Cloud, Huawei Cloud, AWS, Azure, Google Cloud, etc.) on standard x86_64 VMs.
    *   **[Highlight]** Seamlessly supports high-performance ARM64 cloud instances like AWS Graviton, Alibaba Cloud Yitian, and Oracle ARM instances.
    *   Supports micro edge servers running 64-bit Linux (e.g., Raspberry Pi 4/5, NanoPi, etc.).

### 🍎 macOS Series (Apple Ecosystem)
*Underlying Architectures: `x86_64-apple-darwin` & `aarch64-apple-darwin`*

*   **Intel Macs**: Fully supports older MacBook, iMac, and Mac mini models powered by Intel processors.
*   **Apple Silicon Macs**: Native support for all Mac models powered by M1, M2, M3, and M4 Apple Silicon chips. No Rosetta translation required, unleashing peak chip I/O performance.

### 🐳 Cloud-Native & Containerized Environments (Docker / NAS)
*Distribution: Automated multi-architecture dual-end images on `ghcr.io` (amd64 / arm64)*

*   **Network Attached Storage (NAS)**: Runs perfectly inside Docker on Synology, QNAP, Ugreen, and other mainstream NAS systems.
*   **Advanced Network Environments**: Supports running in virtual machines under PVE/ESXi, and deploying to enterprise-grade Kubernetes (K8s) orchestration clusters.
*   **Windows Containerized Environments**: Fully supported in Windows WSL2 (Windows Subsystem for Linux) and Docker Desktop.
