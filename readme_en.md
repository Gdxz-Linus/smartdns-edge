> [中文](README.md) | English

SmartDNS-edge is the Rust rewrite of the C-language SmartDNS. It keeps the same feature set, implements every feature properly, and thoroughly re-optimises the algorithms behind cache prefetching, dual-stack IP selection and speed checking — surpassing the C version across the board and serving as a drop-in replacement for it.

The project is a secondary development based on mokeyish's 0.13 release, with a free AI engine assisting the effort, delivering dual-stack IP selection and other features. No DNS leaks, no memory leaks.

This refactor keeps the original architecture in place while completely reshaping the business logic, network throughput, CPU performance, memory-leak resistance, anti-abuse defences and failure tolerance — targeting an industrial-grade, enterprise-grade edge DNS proxy gateway.

SmartDNS-edge accepts DNS queries from local or LAN clients, resolves them against multiple upstream DNS servers, and returns the fastest-responding result to the client, which speeds up web access.

SmartDNS-edge also supports pinning specific domain names to specific IP addresses with high-performance matching, which can block ads, along with multi-upstream split routing and other features.

Key features have been tested on Windows and on WSL2 (Linux).

## What has been improved
🚀 SmartDNS-edge: core architecture and feature evolution

💡 Part One: Core features and business-logic completeness
This part closes the blind spots of the old version in protocol standards (RFC), cross-platform compatibility and rule parsing, making it "enterprise-ready" even in extreme scenarios.

📦 1. Cache database fully upgraded (RFC compliance and self-healing)
1.	Dual-stack parallel query with empty-answer protection: when A and AAAA are queried in parallel and one side returns an answer with no IP, the system waits for the other side. This avoids resolution failures caused by a single-stack empty answer racing ahead, and raises the success rate on single-stack or poisoned networks.
2.	【Major】The cache database now preserves all three sections: the serialisation layer was rebuilt so that the Answer, Authority and Additional sections of a DNS message are stored completely. The cache is now fully EDNS0- and RFC-compliant, fixing resolution anomalies caused by incomplete cached information.
3.	Full isolation of split-routing cache entries: the old cache keyed only on the domain name, so domestic and overseas results for the same site got mixed together and polluted each other. The new cache tags entries with the network environment and the rule group, so the same site's domestic and overseas answers are stored separately — split routing no longer cross-contaminates.
4.	Accurate offline-time deduction: when the cache file is loaded at startup, the offline duration is computed from the file's modification time and deducted from the entries' lifetime. This makes persisted-cache expiry management more accurate, and expired records are dropped outright.
5.	Automatic CNAME flattening in the cache: multi-level CNAME chains returned by upstreams are expanded so the final resolved IP is stored directly against the main domain. This sharply cuts the latency of repeat queries and protects intermediate CNAME domains from being poisoned.
6.	Global TTL normalisation with dual-stack alignment: when a cache lifetime is modified, all records including those in the authority section are updated together; when dual-stack records are prefetched, the A and AAAA expiry times are forced into strict alignment. This prevents the split resolution that arises when A and AAAA records expire at different times.
7.	【Major】Negative caching: whether for single-stack or dual-stack selection, empty answers are cached too. This prevents cache stampedes, and eliminates the storm of endless upstream retries they used to cause.
8.	【Major】Prefetch timeout and popularity gating: a new `serve_expired_prefetch_time` parameter (default 6 hours) controls prefetching. A cached entry is prefetched only once it has passed that age and has been requested at least twice; otherwise it goes to the expired queue. After a background prefetch, an entry's popularity is reset to 1, so a further prefetch requires another real query — cold domains can no longer trigger endless prefetching.

🚦 2. Protocol compliance and answer shaping (strict RFC adherence)
1.	Generating valid empty answers (NoData + SOA): when an ad domain is blocked, or a query resolves to an empty answer without SOA, the system attaches an RFC-compliant SOA (Start of Authority) record and caches it, which stops Apple devices from retrying upstream endlessly.
2.	Address rules rebuilt to spec: IP records go into the Answer section and SOA records into the Authority section, in strict RFC order. This improves compatibility with all kinds of device systems and IoT gear.
3.	Dynamic EDNS0 truncation and fallback queries: when a large UDP response (DNSSEC, for example) exceeds the client's receive limit, the system truncates it and sets the TC=1 flag, telling the client to retry over TCP. This fixes the 10040 (WSAEMSGSIZE) crash seen on Windows when a UDP packet is too large.
4.	Dual-stack selection accepts legitimate SOA records: when an upstream returns an NXDOMAIN carrying an SOA, dual-stack selection treats it as a legitimate response, includes it in the selection and caches it. Legitimate negative responses are no longer discarded by mistake.
5.	CNAME chains kept for quality scoring: after the fastest IP is chosen by speed check, the auxiliary records of the CNAME chain are retained per RFC, so the client receives a complete resolution chain.

🗺️ 3. Rule engine and split-routing strategy extensions
1.	More tolerant parameter parsing: the configuration parser was upgraded to accept complex syntax such as `-group=abc` or `-cert=--base64--`. This raises the tolerance of configuration files and reduces errors caused by extra spaces or equals signs.
2.	DomainSet supports proxy downloads: a new `-proxy` parameter lets blocklists (ad-interception lists hosted on GitHub, for example) be fetched through a specified SOCKS5/HTTP proxy, solving failures on direct connections.
3.	MAC-based split routing and global cache: MAC matching accepts hyphens and colons in any mix, and in any case; underneath, ARP resolution gained a dedicated blocking thread pool and a global LRU cache. This greatly improves the performance of MAC-based rules (blocking ads for a specific device, for instance) under high concurrency.
4.	LAN privacy protection (reverse-query interception): rather than relying on rigid local interface configuration, the system automatically recognises and intercepts every query for a private-network IP address. Device addresses on your home or corporate LAN can never be quietly sent to the public internet — your intranet privacy is fully protected.
5.	A built-in troubleshooting tool (device identity lookup): built-in special hostnames such as `whoami.json` were added. Query it from any device and the system returns not only that device's LAN IP but also its real physical MAC address underneath. On a complex network with hundreds of devices, finding a device and working out who is making a request becomes effortless.
6.	DNS64 trigger conditions relaxed: whenever an upstream returns no IPv6 address, IPv6 synthesis is triggered, whether or not it reported an error. This greatly lowers the bar for DNS64 to take effect and improves connectivity on pure-IPv6 single-stack networks.
7.	IP aliasing and rewriting: an advanced domain-to-IP mapping feature was added. If an upstream returns a particular IP, the system can replace it underneath with one or more user-defined IPs. For streaming services or specific network services whose IPs change often, you can force the resolution result.
8.	Lossless merging of complex rules: when several potentially conflicting rules are configured for the same domain (or rule group) — a speed-check mode plus several firewall Nftset sets, say — the old version simply overwrote one with the other. The merge logic was rewritten to merge at array level, so the configuration behaves the way users intuitively expect and complex stacked rules now all take effect.

🌐 4. Intelligent upstream protocol scheduling and fallback responses
1.	Proxy-aware upstream protocol downgrade: when a SOCKS5 proxy is configured for an upstream, QUIC is automatically downgraded to DoT and HTTP/3 to DoH. This solves the broken connections that occur because most proxies do not carry UDP, and keeps the proxy path connected.
2.	DHCP dynamic upstream discovery: `server dhcp://eth0` sends a DHCP broadcast to learn the interface's default DNS. This suits multi-WAN setups and router environments where the network changes frequently, keeping upstreams in step automatically.
3.	Staggered concurrent queries across upstream IPs: when an upstream has several IPs they are connected concurrently, but later connections are delayed by 250 ms. The fastest node is still reached, while a burst of useless handshake packets is avoided — speed and resource use in balance.
4.	SNI added to HTTPS speed checks: HTTPS probes automatically carry the Host header and SNI handshake name. This fixes probe failures when a probe passing through a CDN node is blocked by a firewall.
5.	Scoring of abnormal responses: when every upstream query has failed and a fallback answer is needed, responses are ranked as "legitimate answer with SOA > error answer with SOA > abnormal empty answer without SOA > fake error answer". On badly poisoned networks this still picks the most compliant response, improving resilience.
6.	Global 5-second resolution deadline: upstream queries carry a hard 5-second timeout. As an SLA guarantee, the request is released after 5 seconds no matter whether a proxy is stuck or the network has black-holed it, so a single bad node cannot drag the whole service down.
7.	Instant switch-over on empty answers from multiple upstreams: if one upstream returns a legitimate empty answer first, it is ignored and the other upstreams are still awaited. This stops the system from believing a poisoned upstream's empty answer, greatly improving resolution success and speed on single-stack networks.
8.	DoH3 (HTTP/3) auto-discovery: when serving traditional DoH, the system injects an Alt-Svc upgrade directive into the HTTP response headers, guiding modern clients that support it to upgrade seamlessly to the faster, more robust HTTP/3 (QUIC) protocol — improving the end user's experience without them noticing.

🚀 Part Two: computing and network performance (Performance & Efficiency)
This part is the secret behind the system being "lightning fast": it opens up the data highway from the network card to every CPU core.

👑 1. CPU performance
1.	【Major】A multithreaded revolution for the cache database (sharded locking)
The old version had a single global mutex for the whole cache. Under load every thread queued for that one lock, so a single CPU core saturated while the others idled and throughput collapsed. The new version splits the database into 64 fully independent shards, each with its own lock. Lock contention drops to 1/64, fully releasing the CPU's multicore concurrency. Front-end queries never wait; background garbage collection quietly cleans shard by shard.
2.	Kernel-level multi-queue load balancing: on Linux the service opens as many UDP listeners as there are CPU cores. The kernel hashes the flood of DNS requests across cores so they are handled in parallel, breaking the single-core bottleneck.
3.	Native Windows API (IPHLPAPI): MAC lookups no longer spawn a child process but call SendARP directly. Latency drops from milliseconds to microseconds — a hundredfold improvement.
4.	Batch Nftset insertion: when updating Linux firewall IP sets, hundreds or thousands of IPs are assembled into one array and injected into the kernel in a single call, eliminating 99% of the cross-layer language overhead and sharply cutting CPU usage.

🌊 2. Network I/O and memory
1.	An extremely fast UDP send/receive engine (zero-copy): the old version allocated fresh memory for every received packet. The new version keeps a large circular memory pool and processes data where it lands, eliminating the copying and moving entirely. CPU and memory usage drop sharply and the network card's maximum speed is reached.
2.	Larger UDP send/receive buffers: the service asks the system for 4 MB UDP buffers. This improves resilience against bursts of traffic and prevents silent drops when LAN devices query heavily at once.
3.	Per-connection rate limiting for TCP/TLS: each TCP connection is capped at 200 outstanding requests. The TCP window mechanism is used to make a malicious sender slow down, preventing memory exhaustion (OOM) from pipelining attacks.
4.	Folding of concurrent identical queries: upstream queries are folded together. If 1000 clients ask for the same domain at once, only one goes out to the internet and the rest wait in memory at no cost for the result to be broadcast. Processing cost drops by 99.9%, and upstream rate-limiting bans are avoided.
5.	LRU caching of local hot data: ARP resolution has a high-speed global cache. Even with hundreds of MAC rules in play, lookups happen in memory instantly, removing the network latency caused by frequent system command calls.
6.	25 ms staggered speed-check probes: probes to the same IP are spaced out in steps. This breaks the illusion of "micro-burst tail loss" caused by firing packets at once, so the better network path is chosen more accurately.
7.	Higher network concurrency limits on Linux: at startup the program raises the system's default connection limit, fixing resolution failures on LANs with many devices caused by hidden system caps.
8.	Kernel-level congestion control for firewall updates (Nftset): when injecting firewall IP sets into the Linux kernel, a limit of 512 concurrent channels applies. When a flood of new IPs congests the kernel's network channel, the service deliberately drops new firewall write tasks, preventing a stalled kernel from causing an OOM in the main process.

💾 3. Disk I/O
1.	【Major】Background tasks fully isolated from core resolution (no more freezes): all slow operations — reading large configuration files, hot-reloading ad-blocking rules — are moved to a dedicated background blocking thread pool, expanded to 2048 threads. Updating rules or running heavy tasks no longer freezes the main thread.
2.	Extreme disk resilience and instant replacement (no stutter): cache files and rolling logs are written to a temporary file first and swapped in within 0.1 ms. When the log writer cannot keep up with the disk, new log lines are deliberately dropped rather than queued forever.
3.	Lossless shutdown: on a restart or operating-system shutdown the process holds the door shut, forcing every latest resolution record in memory to be written safely to disk before it is allowed to exit. No cache data is lost across a restart.
4.	Read/write locks for the management API: the API that changes configuration now takes a read/write lock. Frequent status polling from the management console no longer blocks core configuration reads, so front-end work is unaffected.
5.	Seamless hot reload of the local Hosts file: the Hosts resolution module watches the file's signature (modification time plus path). Editing the Hosts file takes effect instantly without restarting the SmartDNS service, and the file reading and parsing run in the background blocking thread pool so the main thread is untouched.

🛡️ Part Three: security, defence and high availability (Security & Stability)
This part of the code exists to cope with hostile network environments, resist malicious probing and isolate low-level system failures.

🛑 1. Vulnerability defence and anti-abuse
1.	Constant-time password comparison against side-channel cracking: when comparing the management API password, `black_box` is used to block compiler optimisation and the comparison is bitwise over the full length. Verification time is absolutely constant, so an attacker cannot measure the password from microsecond differences in response time — side-channel attacks are fully ruled out.
2.	Source-address poisoning scrubbing: the source IP is checked strictly before a request is handled. 0.0.0.0 and broadcast addresses are dropped outright, blocking attackers from using the DNS server as a springboard for reflection attacks into your network.
3.	Blocking UDP amplification and reflection: when the service sheds load, dropped UDP requests are answered with zero bytes and nothing is sent on the wire. Returning no error packet and spending no bandwidth — silent dropping is the highest principle in anti-reflection defence.
4.	A physical-line defence against HTTPS memory bombs: the DoH endpoint truncates request bodies at 64 KB hard. Oversized malformed payloads are cut off at the entrance and never reach memory, precisely eliminating HTTP-layer OOM attacks.
5.	Defence against slow handshake attacks: TLS/HTTPS handshakes have an absolute 5-second timeout. An attacker who connects and then dribbles data is cut off immediately, so malicious connections cannot exhaust the server's connection pool.
6.	An absolute traffic sandbox (no leaks): sockets are tagged for transparent routing before a control channel to an external proxy is established. All handshake and control traffic is guaranteed to obey the system's VPN split-routing policy 100%, preventing real-IP leaks.

🧱 2. Fault tolerance, self-healing and crash isolation
1.	Tolerant cache-file loading: loading the local cache runs in its own thread. If the cache file is corrupt or garbled, the main process is unaffected — it deletes the file, rebuilds the cache and starts empty. The service can no longer get stuck in a crash-on-start loop after an unexpected power loss.
2.	Safe release of zombie QUIC streams: on a QUIC read error the service explicitly sends a no-error close, telling the operating system to reclaim the resources. Abandoned network streams can no longer linger and slowly drain server memory.
3.	Fail fast instead of running blind: if reading the machine's interface DNS configuration fails at startup, the service raises an error and exits. Following the "never work while sick" principle, an abnormal interface does not go online in a broken, black-holing state — troubleshooting starts immediately.

📡 3. Resource limits and protocol robustness (no drag-downs, no crashes)
1.	Connection counts are capped: both the total number of simultaneous connections and the number from a single source have limits; over the limit, only new connections are refused — connections already in use are never dropped. The limits are derived automatically from the machine's physical memory (tighter on small machines, looser on large ones) and can be adjusted per listener.
2.	Unsupported requests get a clear answer: for old-fashioned or unrecognised query types the program returns a "not supported" response instead of silently discarding the request as it used to.
3.	Forged "response" packets are simply dropped: such packets usually come from spoofing or reflection traffic, and answering a response creates a loop, so they are logged but not answered.
4.	Only answers from the upstream you asked are accepted: answers whose source does not match are discarded, so resolution results cannot be substituted by a third party.
5.	Problems are visible and there is a fallback: if the program itself fails internally, the situation is logged and counted; the request is then answered with a "server failure" response where possible, rather than leaving the client waiting until it times out.

💻 Part Four: built-in tools, API and operational experience
1.	Windows service management rebuilt (major): installing and uninstalling the Windows service now uses modern synchronous PowerShell commands, and installation configures firewall rules and system network prerequisites automatically. Service install failures, start failures, broken status queries and restart failures on Windows are eliminated.
2.	Built-in `resolve` command output and JSON: modelled on dig, with automatic terminal-width detection and smart wrapping, plus JSON and Short modes. No more garbled columns from very long TXT records, and JSON output has control characters cleaned up for easy scripting and integration.
3.	Symlink elevation hints and smart completion: on Windows, a shortcut created without `.exe` is completed automatically, and insufficient privileges produce a "please run as administrator" hint. A better user experience.
4.	Duplicate-process prevention on Windows: an operating-system-level exclusive file lock stops the program starting twice. This solves the problems caused by accidentally running several instances fighting over the same port.
5.	Safe anchoring of relative paths: every log and cache file written to disk is resolved relative to the physical directory containing the configuration file, keeping files in one manageable place.
6.	Rewritten help text for the CLI and feedback messages for every command.

## Supported operating systems
### 🪟 Windows family (enterprise servers and modern desktops)
*Underlying architectures: `x86_64` (mainstream Intel/AMD) and `aarch64` (modern ARM processors)*

- **Enterprise servers (Windows Server)**: full support for Windows Server 2016, 2019, 2022 and the latest Windows Server 2025.
- **Desktops (Windows Desktop)**: full support for Windows 10 and Windows 11.
- **ARM laptop ecosystem**: native, full-speed support for the new generation of Windows 11 ARM laptops with Snapdragon X chips.

### 🐧 Linux family
*Underlying architectures: `x86_64-generic-linux-gnu` and `aarch64-generic-linux-gnu`*

- **Mainstream enterprise servers (Linux Server)**:
  - Debian family: Ubuntu Server (18.04 and later), Debian (10 and later).
  - Red Hat family (RHEL): CentOS (7/8/9), Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, Oracle Linux.
  - Other commercial servers: SUSE Linux Enterprise, openSUSE.
- **Desktop Linux**: Ubuntu Desktop, Fedora, Linux Mint, Deepin, UOS, Manjaro and more.
- **Cloud servers and edge nodes (VPS & Edge)**:
  - All mainstream cloud providers (Alibaba Cloud, Tencent Cloud, Huawei Cloud, AWS, Azure, Google Cloud and others) on ordinary x86_64 virtual machines.
  - **【Highlight】** Full support for high-performance ARM64 cloud servers such as AWS Graviton, Alibaba Cloud Yitian and Oracle.
  - Support for small edge hosts running 64-bit Linux (Raspberry Pi 4, Raspberry Pi 5, NanoPi and similar).

### 🍎 macOS family (the whole Apple ecosystem)
*Underlying architectures: `x86_64-apple-darwin` and `aarch64-apple-darwin`*

- **Older Macs**: full support for Intel-based MacBook, iMac and Mac mini.
- **Newer Macs**: native support for every Mac with M1, M2, M3 or M4 (Apple Silicon) — no Rosetta translation needed, getting the most extreme I/O performance out of Apple silicon.

### 🐳 Cloud-native and container environments (Docker / NAS)
*Distribution: fully automated `ghcr.io` multi-architecture images (amd64 / arm64)*

- **Network-attached storage (NAS)**: runs perfectly inside the Docker component of mainstream NAS systems such as Synology, QNAP and Zspace.
- **Advanced network environments**: support for running in virtual machines under PVE/ESXi, and for deployment in enterprise Kubernetes (K8s) clusters.
- **Windows container environments**: full support for running inside Docker Desktop on Windows with WSL2 (Windows Subsystem for Linux).

## 📦 Installation & Running

This program is **self-contained with no external system dependencies**. Download the latest archive for your system architecture from the [Releases page].

### 🪟 Windows (enterprise servers & desktops)

Extract the downloaded `.zip` file to a permanent directory (such as `D:\SmartDNS`).

**Method 1: foreground test run (best for testing and troubleshooting)**

PowerShell

.\smartdns.exe run -c .\smartdns.conf -v

(Note: `-v` turns on debug logging so you can watch the resolution process.)

**Method 2: background service run (recommended, starts automatically at boot)**
Run a terminal as administrator and execute the following. The system takes over the process and configures the firewall rules automatically:

PowerShell

- **1. Install the service**
.\smartdns.exe service install

- **2. Start the service**
.\smartdns.exe service start

- **3. Check the status at any time (with 🟢/🔴 indicators)**
.\smartdns.exe service status

(To remove everything, run .\smartdns.exe service uninstall)

### 🐧 Linux & 🍎 macOS (portable run)

Extract the downloaded archive into your target directory.

**Method 1: foreground test run (best for testing and troubleshooting)**

Bash

chmod +x ./smartdns

sudo ./smartdns run -c ./smartdns.conf

**Method 2: background service run (recommended, starts automatically at boot)**

Bash

chmod +x ./smartdns

sudo ./smartdns service install

sudo ./smartdns service start

sudo ./smartdns service status

(Note: binding privileged ports such as 53 on Linux requires sudo/root.)

### 🐳 Docker / NAS (one-command container deployment)

We provide a minimal container image with native amd64 and arm64 support, ideal for Docker-capable environments such as Synology. Start it quickly from the CLI:

Bash

docker run -d --name smartdns --restart always --network host -v /your/local/path/smartdns.conf:/etc/smartdns/smartdns.conf ghcr.io/gdxz-linus/smartdns-edge:latest

(Note: because DNS involves LAN broadcast and low-level network traffic, `--network host` mode is strongly recommended.)

(Note: the container image also includes the **web console**, which is **off by default**. To use it, publish the container's port 8000 — `-p 8000:8000` — and either put `api-token your-token` in the configuration or pass `-e SMARTDNS_API_TOKEN=your-token`. It is plain HTTP, so the token travels unencrypted: use it only on a trusted LAN, and for cross-network access switch to `bind-https` or a reverse proxy.)
