---
hide:
  - navigation
  - toc
---

## What is SmartDNS Edge?

SmartDNS Edge is a local DNS intelligent gateway rewritten in the Rust programming language. It resolves DNS queries from multiple upstream servers, dynamically determines the fastest IP addresses using smart speed-testing algorithms, and significantly improves internet access speeds and web-loading experiences.

## ✨ 13 Core Features

*   **1. Multiple Virtual DNS Intelligent Gateways**
    Supports configuring multiple virtual DNS intelligent gateways on different ports, with independent resolution rules and client bindings for each.
*   **2. High-Availability Upstream DNS**
    Supports concurrent querying across multiple upstream DNS servers, ensuring zero-interruption resolution even if some upstream nodes fail.
*   **3. Granular Client Control**
    Supports mapping MAC or IP addresses to independent query and filtering rules, enabling easy setup of parental controls.
*   **4. Optimal Lowest-Latency IP Selection**
    Multi-threaded concurrent speed-testing automatically selects and returns the fastest IP to the client, greatly accelerating page load.
*   **5. State-of-the-Art Encryption Protocols**
    Full support for UDP, TCP, DoT, DoH, DoQ, DoH3, and non-53 port queries; natively supports routing upstream queries via SOCKS5 or HTTP proxy tunnels.
*   **6. Static IP Hijacking & Threat Mitigation**
    Supports binding targeted domains to specific IPs (such as mapping ad or malicious sites to `0.0.0.0` for highly efficient blocking).
*   **7. Million-Scale Rule Matching in <1ms**
    Employs highly optimized suffix-matching algorithms. Matches over 200,000 domain rules in less than 1 millisecond.
*   **8. Domain Split-Routing & IPSet/NftSet Sync**
    Supports domain-based split routing and seamless injection of resolved IPs into Linux iptables/nftables ipset/nftset lists.
*   **9. Cross-Platform Native Deployment**
    Native support for Windows, macOS (Intel/Apple Silicon), Linux Servers, OpenWrt routers, Asuswrt native firmware, and WSL.
*   **10. Smart Dual-Stack (IPv4/IPv6) Optimization**
    Performs concurrent speed checks on A and AAAA records with synced TTLs; supports dropping IPv6 queries to prevent DNS bypass leaks.
*   **11. Seamless DNS64 Translation**
    Natively supports DNS64 synthesis, enabling IPv6-only networks to access IPv4-only services smoothly.
*   **12. High-Performance Async I/O & Optimistic Cache**
    Powered by a high-concurrency multi-threaded async I/O engine with optimistic caching to serve expiring records instantly.
*   **13. Out-of-the-Box Software Feed Support**
    Pre-integrated into the package feeds and package managers of mainstream router firmware and geek distributions.

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
