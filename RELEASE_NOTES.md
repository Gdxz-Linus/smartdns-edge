### 概述

本次更新修复 **74 个问题**，覆盖解析正确性、服务稳定性、安全加固与配置行为。多数问题只在特定条件下显现，一旦发生会造成解析结果错误或服务异常。升级无需修改配置文件，有两处行为变化需要留意，见文末「升级须知」。

### 解析正确性

- **主域名的规则现在对子域名生效。** 此前 `domain-rules /example.com/ -rr-ttl 33` 只对 `example.com` 本身起作用，查询 `www.example.com` 时该规则不生效。现在子域名会继承主域名的设置；子域名另写规则时，以子域名为准。
- **系统 hosts 文件此前从未被读取。** 配置了 `hosts-file` 也不生效，文件里的条目无法解析。现在正常读取。
- **双栈查询时，一个地址族探测超时会连累另一个。** 主查询已经拿到结果，却因另一族的探测超时而返回 SERVFAIL。现在主查询不受影响。
- **`ipv4only.arpa.` 的 AAAA 查询返回空应答。** 该域名用于探测 NAT64 前缀，空应答导致探测失败。现已修复。
- **DNS64 的 /56 前缀合成出错。** 合成出的 IPv6 地址不正确。现已修复。
- **同一域名配置多条 `address` 规则时只保留最后一条。** 其余规则静默丢失。现在全部生效。
- **开启访问控制后，MAC 白名单内的客户端被全部拒绝。** 现已修复。
- **一行内写多个 `-ipset` 或 `-nftset` 时只保留最后一个。** 现在全部写入。
- **嵌套 `conf-file` 的通配符找错目录。** 子目录中的 `conf.d/*.conf` 匹配不到文件。现在以当前正在加载的配置文件为基准；路径含目录时，也不再退化为只按文件名查找。
- **`bind-cert-file` 与 `bind-cert-key-file` 的相对路径找错目录。** 此前以启动时所在目录为基准，从不同目录启动会加载到不同证书，或直接加载失败。现在按配置文件所在目录解析。
- **只配置证书或只配置私钥时，程序静默生成自签证书覆盖你的配置。** 服务照常启动，TLS 照常握手，但客户端校验必然失败。现在明确报错，指出缺少哪一项。
- **域名集合文件支持制表符分隔。** 无法解析的行在启动时按条数告警，不再静默跳过。
- **缓存刷新不再清零访问热度。** 此前被反复访问的域名只要遇上刷新，访问次数就掉回 1，永远达不到后台预取的门槛。现在只有后台预取才会重置。
- **查不到记录时返回 SERVFAIL。** 程序自己构造的 SOA 记录无法还原，客户端会当成服务器故障反复重试。现在改为返回 NOERROR。

### 服务稳定性

- **DoQ 长连接不再在第 32 条查询后被断开。** 子流配额改为随子流结束归还。
- **DoH 与明文 HTTP 监听增加读超时与空闲超时。** 慢速发送请求头的客户端不再能长期占用连接配额。
- **QUIC 监听在端点关闭后不再持续占用一个处理器核心。**
- **并发上限的检查与计数合并为一次操作。** 高并发下不再短暂突破 `max-query-limit` 的上限。
- **ipset 写入在读取集合标志失败时不再整批失效。**
- **netlink 连接关闭时不再无限循环。** 此前会让 ipset 写入永久卡住。
- **DHCP 探测的收包缓冲从 1024 字节扩大到 4096 字节。** 带完整选项的应答此前被截断丢弃，表现为「该网段没有 DHCP 服务器」。
- **UDP 上游遇到 HTTP 代理时自动改用 TCP 查询。** 此前直接报错，用户看到的是「DNS 完全不能用」。
- **`log-filter` 写错不再导致启动失败。** 改为打印原始表达式与具体错误，然后回退到只记录警告及以上级别。
- **SOCKS5 代理返回 `0.0.0.0:0` 中继地址时正常工作。**
- **`max-reply-ip-num` 超出 1 至 16 时告警并取上限。**
- **`bind-cert-validity-days` 设置超大值不再生成已过期证书。** 上限为 36500 天。
- **ALT-SVC 通告的 HTTP/3 端口按地址族匹配。** 双栈监听时不再通告错误端口。
- **TTL 上下限配置倒挂会引发崩溃。** 现已修复。
- **AES-128-CBC 加密私钥解密失败。** 此前固定按 AES-256 处理。现已修复。
- **Linux 下降权启动时遗漏 DoQ 证书预生成。** 现已修复。
- **上游错误在并发合并时被丢弃。** 等待的查询只看到笼统失败。现在保留原始错误。
- **HTTP/3 监听同步等待握手。** 恶意慢速客户端可阻塞整个监听。现已修复。
- **mDNS 缺少默认端口时直接崩溃。** 现已修复。
- **ICMPv4 差错回包固定按无选项的 IP 头解析。** 带 IP Options 的报文被丢弃。现已修复。
- **ICMPv6 差错回包固定按无扩展报头解析。** 带扩展报头的报文被丢弃。现已修复。
- **IPv6 mDNS 多播未绑定网卡时崩溃。** 现已修复。
- **流关闭后并发发送消息会崩溃。** 现已修复。
- **单个畸形 DHCP 选项导致后续合法选项全部丢弃。** 现已修复。
- **`force-no-CNAME` 在监听与规则组配置下静默失效。** 现已修复。

### 安全加固

- **`/tmp` 下的锁文件可被他人预先放置的软链接利用。** 以 root 运行时，攻击者可借此截断任意文件。现在打开时会识别并拒绝软链接，同时校验文件属性。
- **私钥写入存在可被读取的时间窗口。** 此前私钥先以默认权限写入、再收紧权限，这中间同机任意用户可读；权限收紧失败时也无人知晓。现在创建时即为严格权限，失败会明确报错。
- **降权失败后不再继续以 root 运行。** 改为打印具体原因并退出。用户名写错时给出明确提示，不再输出一大段程序报错信息。
- **管理接口的令牌校验在内部异常时不再整体崩溃。**
- **口令失败计数表满后不再整表清空。** 此前可借此绕过限流。
- **DoH3 与 DoH(HTTP/2) 的上游响应体增加 64 KB 上限。** 避免异常上游耗尽内存。
- **DoH 的 `?dns=` 参数增加长度上限。** 与 POST 请求体的 64 KB 限制保持一致。
- **DNS 报文不再按报文头声明的域名数量预分配内存。** 此前 12 字节的畸形报文可触发数兆字节的内存分配。
- **配置写入接口不再静默截断回写内容。** 此前会丢掉文件中无法解析的其余行。
- **Windows 下 ARP 查询的接收缓冲区越界写。** 现已修复。
- **口令比对耗时随长度变化，可被用来推测口令。** 现已修复。
- **DHCP 与 DHCPv6 报文解析的长度校验缺失。** 畸形报文此前可能崩溃，现在作为无效报文拒绝。

### 配置行为

- **拼错规则组名称现在会告警。** 此前规则静默失效。
- **监听配置的 `enabled` 字段真正生效。** 此前写 `enabled: false` 的监听照样启动。
- **审计日志的启用条件过于严格。** 此前强行要求 `audit-num > 0`，导致只配置控制台输出时不生效。现已修复。
- **7 项配置的默认值与文档脱节。** 双语文档已校正，废弃的应急机制描述已清理。

### 升级须知

1. **主域名的规则开始对子域名生效。** 若你的配置依赖旧行为，升级后结果会变。请检查写在主域名上的 `domain-rules`。
2. **只配置证书或只配置私钥时会启动失败。** 此前会静默生成自签证书覆盖配置。请补齐另一项，或显式写 `bind-cert-generate yes`。

其余配置无需改动。

---

## English

This release fixes **74 issues** across resolution correctness, service stability, security hardening and configuration behaviour. Most surfaced only under specific conditions, but each could produce a wrong resolution result or a service failure. No configuration changes are required to upgrade; two behaviour changes deserve attention — see "Upgrade notes".

**Resolution correctness** — rules set on a parent domain now apply to its subdomains (previously `domain-rules /example.com/ -rr-ttl 33` only matched `example.com` itself); the system hosts file is now actually read, so entries in it resolve; a probe timeout in one address family no longer fails the other family's main query with SERVFAIL; `ipv4only.arpa.` AAAA queries no longer return an empty answer, so NAT64 prefix discovery works; DNS64 `/56` prefix synthesis no longer produces wrong addresses; multiple `address` rules for one name are all applied instead of only the last; MAC whitelist clients are no longer rejected wholesale when access control is enabled; multiple `-ipset` / `-nftset` entries on one line are all applied; nested `conf-file` includes resolve wildcards against the file being loaded and no longer degrade to a bare filename lookup; `bind-cert-file` / `bind-cert-key-file` relative paths are resolved against the configuration file's directory; configuring only a certificate or only a key no longer silently replaces your certificate with a self-signed one; domain-set files accept tab separators and report unparseable lines; cache refresh no longer resets the hit counter, so frequently used names still reach the prefetch threshold; a name with no records now returns NOERROR instead of SERVFAIL, so the synthesized SOA survives.

**Stability** — DoQ connections are no longer dropped after 32 queries (substream quota is returned when a substream ends); DoH and plain HTTP listeners gained header-read and idle timeouts, so slow clients can no longer hold connection quota indefinitely; QUIC listeners no longer keep a CPU core busy after the endpoint closes; the concurrency-limit check and increment now happen as one operation, so `max-query-limit` is no longer briefly exceeded; ipset batch writes survive a failed flag read; netlink no longer loops forever when the connection closes; the DHCP receive buffer grew from 1024 to 4096 bytes so full-option replies are not truncated; UDP upstreams behind an HTTP proxy fall back to TCP instead of failing the whole query; a malformed `log-filter` no longer aborts startup; SOCKS5 `0.0.0.0:0` relay addresses are handled; `max-reply-ip-num` outside 1–16 is capped with a warning; `bind-cert-validity-days` no longer produces expired certificates on huge values; the advertised HTTP/3 port matches the client's address family; inverted TTL min/max no longer crashes; AES-128-CBC private keys decrypt correctly; DoQ certificate pre-generation is no longer skipped when dropping privileges; upstream errors are no longer discarded when concurrent queries are merged; the HTTP/3 listener no longer blocks on a slow handshake; a missing mDNS default port no longer crashes; ICMPv4 error replies no longer drop packets carrying IP options; ICMPv6 error replies no longer drop packets with extension headers; IPv6 mDNS multicast no longer panics when no interface is bound; concurrent sends after stream close no longer panic; one malformed DHCP option no longer discards the valid options that follow; `force-no-CNAME` no longer silently fails at listener and rule-group level.

**Security** — the `/tmp` lock file can no longer be exploited through a link planted in advance; private keys are created with restrictive permissions from the start instead of being written world-readable and tightened afterwards; failing to drop privileges now exits instead of continuing as root; management-interface token checks survive an internal error; the failed-passphrase counter no longer clears itself when full; DoH3 and DoH(HTTP/2) upstream response bodies are capped at 64 KB; the DoH `?dns=` parameter has a length limit matching the 64 KB POST limit; DNS messages no longer pre-allocate memory from untrusted header counts; the config-write API no longer truncates unparseable lines; the Windows ARP receive buffer no longer overflows; passphrase comparison no longer takes a length-dependent amount of time that could be used to guess it; DHCP and DHCPv6 parsers now check lengths before use, so malformed packets are rejected instead of crashing.

**Configuration behaviour** — misspelled rule-group names now warn instead of failing silently; the listener `enabled` field actually takes effect; the audit log no longer requires `audit-num > 0` to be enabled; seven documented defaults were corrected and stale failover descriptions removed.

**Upgrade notes** — (1) rules set on a parent domain now apply to its subdomains; check any rules written on a parent domain if you relied on the old behaviour. (2) Configuring only a certificate or only a key now fails at startup with a clear error; supply both, or set `bind-cert-generate yes` explicitly.