### 概述

修复 **63 个问题**，集中在解析结果的准确性、服务的稳定性与安全防御；新增自签证书自动生成、加密私钥支持等四项功能。升级无需改配置，原有配置文件可直接沿用。

### 新增功能

- **自签证书自动生成**：未配置证书时，TLS/HTTPS/H3 监听自动生成自签名证书链（含根 CA，默认有效期 390 天），支持 `bind-cert-generate`、`bind-cert-validity-days`、`bind-cert-san` 等参数。
- **加密私钥支持**：TLS/HTTPS 上游与监听支持带口令的 PKCS#8 私钥；旧加密格式会给出明确的迁移提示。
- **`-fallback` 上游标记**：被标记的上游平时不参与查询，只在同组其它上游都无法给出可用答案时启用。

### 修复

**解析结果不对**

- 双栈优选（同时查 IPv4/IPv6 并择优）在部分场景下选错地址：缓存时间取了较慢的一方、空应答抢先返回、关闭测速后优选未随之失效、"强制 AAAA 返回 SOA"误拦了 A 记录查询。
- DNS64 合成地址的前缀写法此前只支持 /96 一种；现按 RFC 6052 支持全部六种合法写法，写错的前缀在启动时即报错。
- 域名中的数字转义写法（`\DDD`，如 `\067` 代表字母 C）此前按八进制解码，与 RFC 1035 不符；现改为十进制，配置解析与域名显示两端同步，超过 255 会明确报错。
- SVCB/HTTPS 记录参数的写法在配置文件与实际查询中含义不一致；现已统一。
- 同一条缓存记录只改了缓存时间时，更新被静默丢弃；现在会正常生效。
- 内网设备的反向查询（PTR）此前直接返回"不存在"，hosts 文件与 DHCP 租约里的设备主机名无法反查；现已修复。
- 带客户端子网（ECS）的缓存条目刷新时丢失子网信息，导致按地区缓存的结果被错误续期；现已修复。

**稳定性**

- 监听端口持续出错时会空转占满处理器——现在按间隔退避，并降低日志刷屏频率。
- 设备断开后连接配额未归还，导致新设备连不上——现已修复。
- 上游返回"忙"时，重试没有间隔也不限次数，形成无限空转——现在重试间隔会逐步拉长，期间不再占用处理器。
- TCP 连接上收到长度为 0 的报文时，整条连接被错误断开——现在跳过该报文、连接保持。
- 缓存文件损坏导致反复启动失败——现在自动删除损坏文件并以空缓存重建。
- 日志文件被外部工具轮转后，日志永久停写——现已自动恢复。

**安全**

- 代理地址写错时，下载外部名单会跳过代理直接连网（结果可能被污染）——现在明确报错并中止。
- 超大的 DoH 请求体现在直接拒绝，不再占用内存。
- DoH 接口的错误提示不再包含内部地址信息（详情只进日志）。
- 收到伪造的报文头时，程序会按头里声称的数量预占内存（最多数 MB）——现改为按实际数据逐步占用。

### 服务管理

- Linux 非 systemd 环境（initd）的服务脚本修正：设置/取消开机自启此前是空操作，现真正生效；默认配置文件不存在时不再卡住启动。

### 其它改进

- 内嵌组件的多处预防性修复：证书算法声明与实际能力不符、SOA 记录解析取错字段、参数名写法不一致、词法解析的转义与超长内容处理等。
- 中文文档与 README 全量语言检查：去除了行话、口语与营销式措辞。
- 配置模板修正：`ca-path` 示例拼写（/etc/ssl/certs）。

### 规模与验证

主仓库测试 **635 项全部通过**（Windows 实测），WSL 侧关键路径复测通过。变更规模：**40 文件 / +1323 −230**。

---

## English

Fixed **63 issues**, focused on resolution correctness, service stability and security; four new features including self-signed certificate auto-generation and encrypted private-key support. No config change needed to upgrade.

**Resolution correctness** — dual-stack selection no longer picks wrong addresses (TTL taken from the slower side, empty answers winning races, selection staying active with speed check off, SOA override blocking A-record queries); DNS64 prefix layout is now fully RFC 6052 compliant (all six legal prefix lengths, invalid ones rejected at startup); `\DDD` escapes in names are decoded as decimal per RFC 1035 (was octal); SVCB/HTTPS key notation is now consistent between text and wire form; cache entries that differ only in TTL are no longer silently dropped; PTR queries for private addresses are no longer short-circuited, so LAN hostnames resolve again; ECS cache entries no longer lose their subnet on refresh.

**Stability** — listeners no longer spin at 100% CPU on persistent errors; upstream "busy" responses no longer cause an unthrottled retry loop; TCP connections survive zero-length packets; corrupt cache files are rebuilt instead of failing startup; log writing resumes after external rotation.

**Security & footprint** — oversized DoH request bodies are rejected outright; DoH error responses no longer leak internal addresses; memory is no longer pre-allocated from untrusted header counts; dropped UDP requests during load shedding are never reflected; a misconfigured proxy now fails loudly instead of downloading block lists over the direct (unproxied) connection; connection-quota accounting survives internal errors.

**New features** — self-signed certificate auto-generation for TLS/HTTPS/H3 listeners (root CA included, 390-day default), with `bind-cert-generate` / `bind-cert-validity-days` / `bind-cert-san` and related options; encrypted PKCS#8 private-key support for upstreams and listeners, with clear migration hints for legacy formats; `local-domain` certificates can include the local NIS domain in their SAN (Linux); the `-fallback` upstream flag keeps a marked upstream on standby until the others fail.

**Service management** — Linux initd scripts (non-systemd) now actually enable and disable autostart, and no longer hang when the default settings file is missing.

**Verification**: 635 tests passing on Windows; key paths retested on WSL. 40 files / +1323 −230.
