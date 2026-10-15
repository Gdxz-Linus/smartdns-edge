## v1.0.4

### 概述

修复 **53 个问题**，覆盖解析正确性、稳定性、安全防御与内嵌组件四个方面；**DNSSEC 验证相关代码不再编译**（本产品的应答加工功能与该验证机制存在根本冲突，详见「升级须知」）。升级无需改配置。

### ⚠️ 升级须知

| 变化 | 说明 |
|---|---|
| **DNSSEC 验证相关代码不再包含在程序中** | 本产品的核心能力是对解析结果做测速优选与规则改写，这类加工与 DNSSEC 的"逐字节验签"机制互相冲突；且上游递归服务器通常不返回签名材料，验证在本产品的部署形态下无法成立。如需 DNSSEC 验证，请使用支持该功能的完整递归解析器。此变化会减小程序体积，不影响任何现有配置 |
| **日志与配置无格式变化** | 升级后可直接沿用原有配置文件 |

### 修复

**解析正确性**

- 双栈优选（A/AAAA 测速）在部分场景下结果错误：记录存活时间取了较长的一方（应为较短）；某些应答抢先返回导致错误结果被采用；关闭测速时双栈优选未随之失效；强制返回 SOA 的设置误拦了 A 记录查询。
- DNS64 合成的前缀布局此前与 RFC 6052 不完全一致，仅对 /96 前缀正确；现按 RFC 支持全部六种合法前缀长度，非法前缀在启动时即报错。
- 域名中的数字转义（`\DDD` 形式）按八进制解码，不符合 RFC 1035 的十进制规定；现已改为十进制（解析与显示两端同步），超出 255 的值会报错。
- 带端口的 SVCB/HTTPS 记录参数，文本写法与网络解码对同一数值给出两种含义；现已共用同一映射，往返一致。
- 缓存里"仅过期时间不同"的同条记录更新会被静默丢弃；现在会正常更新。
- 某些应答会被"来源不明的伪造包"抢先替换（多上游竞速时，无应答的空包抢跑）。
- 私网 IP 的反向查询（PTR）此前会被直接返回"不存在"，导致 hosts 文件与 DHCP 租约里的内网主机名无法反查；现已修复。
- 带客户端子网（ECS）的缓存条目刷新时丢失客户端子网信息，导致按地区缓存的结果被错误续期；现已修复。

**稳定性**

- 监听（TCP/TLS/HTTPS/DoQ）持续出错时不再空转占用处理器，按间隔退避并降低日志频率。
- 连接配额的归还过程在内部状态异常时不再丢失，避免配额被"幽灵连接"永久占用。
- 代理地址写错时，此前会**跳过代理直接连网**下载外部名单（可能被污染）；现在明确报错并中止该下载。
- mDNS 查询在系统端口极度紧张时陷入死循环（处理器 100%）；现在会按间隔退避重试。
- 上游返回"忙"信号时，重试逻辑不消耗次数且无间隔，形成无限空转；现在每次重试之间会逐步让出执行权。
- TCP 连接上收到长度为 0 的报文时，整条连接被错误断开；现在跳过该报文、连接保持。
- 缓存文件损坏时可能反复启动失败；现在自动删除损坏文件并以空缓存重建。
- 日志文件被外部工具轮转后，日志永久停写；现已自动恢复写入。

**安全**

- UDP 过载时对被丢弃的请求不再回包，避免被用作反射攻击的放大器。
- 超大 DoH 请求体现在直接拒绝，不再占用内存。
- DoH 接口的错误回显不再包含内部地址信息（公开路由只返回固定文案，详情仅进日志）。

**资源与限额**

- 每个记录集的签名数量上限实际允许多 1 个（第 9 个签名也能通过），已修正。
- 验证通过后的记录存活时间少算了"签名记录自身的接收 TTL"，现已纳入计算。
- 按报文头部声明预分配内存（最多可被伪造声明放大到数 MB）——现改为小额起步、随实际数据增长。

### 新增功能

- **自签证书自动生成**：未配置证书时，`bind-tls` / `bind-https` / `bind-h3` 监听可自动生成自签名证书链（含根 CA，默认有效期 390 天），并自动写入配置目录。证书生成支持 `bind-cert-generate`（auto/yes/no）、`bind-cert-validity-days`、`bind-cert-san`、`bind-cert-root-key-file` 参数。
- **加密私钥支持**：TLS/HTTPS 上游与监听支持带口令的 PKCS#8 私钥（`-key-pass` / `bind-cert-key-pass`）；传统加密方式会给出明确的迁移提示。Windows 服务与命令行共用同一加载路径。
- **`local-domain` 补全 NIS 域名**：证书的 SAN 支持附加本地 NIS 域名（Linux）。
- **`-fallback` 上游标记**：被标记的上游平时不参与查询，只在同组其它上游都无法给出可用答案时启用。

### 服务管理

- Linux 非 systemd 环境（initd）的服务脚本修正：启用/禁用自启此前是空操作（只打日志不生效），现真正调用系统命令并按结果返回；读取不存在的默认配置文件不再卡住启动（加超时并给出默认参数）。

### 其它改进

- DNSSEC 验证相关的三处缺陷一并修正（记录集签名数量上限多算一个、签名记录存活时间少算一项、证书算法声明与实际能力不符）——该模块当前未参与构建，修复保持代码以备未来启用。
- 内置组件的多处缺陷随本版一并修正：SOA 记录解析取错字段、参数名文本写法与网络写法不一致、词法解析的转义与超长内容处理等（这些代码大部分不参与本产品的运行路径，属预防性修复）。证书算法声明与实际能力不符、SOA 记录解析取错字段、参数名文本写法与网络写法不一致、词法解析的转义与超长内容处理等（这些代码大部分不参与本产品的运行路径，属预防性修复）。
- 内嵌的测速组件（surge-ping）账本补记与收包任务加固：探测任务在异常环境下不再中断，持续失败时按间隔退避。
- 中文文档全量语言检查：去除了行话、口语与营销式措辞，README 中英文同步修订。
- 配置模板修正：`ca-path` 示例拼写（/etc/ssl/certs）。

### 规模与验证

- 主仓库测试 **635 项全部通过**（Windows 实测）；WSL 侧关键路径复测通过。
- 组件双形态验证：DNSSEC 编译开启与关闭两种形态下测试均全绿。
- 变更规模：**40 文件 / +1323 −230**。

---

## v1.0.3


### 概述

修完 **58 个问题**；**20 个配置项支持写进 `group-begin` 规则组**。升级无需改配置。

### ⚠️ 升级须知

| 变化 | 说明 |
|---|---|
| **日志改为英文** | 依赖日志文本的脚本需更新 |
| **规则组参数只对本组生效** | 此前写在组里会**改到全局**；从 C 版迁移的用户请确认 |
| `conf-file` 不再到「工作目录 / 程序目录」找配置 | 需改用绝对路径 |
| 不再向客户端输出 NXDOMAIN | 统一回 NOERROR + SOA |
| 管理后台绑非本机地址必须设口令 | 否则拒绝启动 |
| `GET /api/config` 的配置目录以 `~` 开头 | — |
| DoH `?type=` 大小写不敏感；支持 RFC 8484 `?dns=` | — |
| `speed-check-mode` 未配置 = 要测速 | 此前两条路径口径相反 |

### 功能完善

- **规则组参数**：20 个配置项现可写进 `group-begin`，实现"同一域名、不同设备不同策略"。
- **`trusted-proxy <IP|CIDR>`**：反向代理后用真实客户端归组。只对 HTTP 类监听生效，只用于归组。
- **`dnsmasq-lease-file` + `domain`**：从 DHCP 租约解析局域网设备主机名。

### 修复

- **安全**：`conf-file` 可被同名文件劫持；代理口令明文进日志；远程名单可降级为 http；管理后台错误回显、配置未真正落盘、来源过滤漏组播。
- **解析**：双栈优选 TTL 取最长（应取短）；NXDOMAIN 抢先胜出；`speed-check-mode none` 对双栈无效；`force-AAAA-SOA` 连 A 查询也短路。
- **规则组**：没有组级写法的参数（如 `cache-size`）写在 `group-begin` 里会**静默改到全局**；现在会提示并忽略该行。
- **DoH / 缓存**：`AD` / `CD` 取值错误；不支持 RFC 8484 与 `Accept` 列表；缓存容量与配置值对不上。
- **日志**：被外部轮转后永久停写；误删审计档；`log-size 0` 每行归档。
- **服务**：`service` 失败仍返回 0；防多开可被启动参数绕过；Linux 非 root 运行启动失败。
- **官网 / 发布流程**：反馈接口与下载防盗链可绕过、CORS 过宽、页面 XSS；测试未前置于版本号提交。

### 验证

| 平台 | 新增 |
|---|---|
| Windows | **+184** |
| WSL（内核 6.18） | **+206** |

规模：**155 文件 / +21183 −5801**。

### English Summary

**58 issues fixed**; **20 options can now be set inside `group-begin` rule groups**. No config change
needed to upgrade.

**Behaviour changes**: log output is English; group-level options now affect only their own group
(previously they changed the **global** value); `conf-file` no longer searches the working/program
directory; NXDOMAIN is never returned to clients; the console requires a token when bound to a
non-local address; DoH `?type=` is case-insensitive and RFC 8484 is supported; `speed-check-mode`
unset now means "measure speed".

**Improved**: `trusted-proxy` (group clients by their real address behind a reverse proxy — HTTP
listeners only, grouping only); `dnsmasq-lease-file` + `domain` for LAN hostnames.

**Fixes**: the `conf-file` hijack; plaintext proxy passwords in logs; list downloads allowing http
downgrade; console error echo, unsynced config writes, missing multicast source filtering;
dual-stack TTL taking the longest instead of the shortest; NXDOMAIN winning races;
`speed-check-mode none` ignored by dual-stack; `force-AAAA-SOA` also short-circuiting A queries;
options without a rule-group form (e.g. `cache-size`) written inside `group-begin` silently changing
the global value (now reported and ignored);
DoH `AD`/`CD` and RFC 8484; cache capacity mismatch; logging stopping after external rotation, audit
files deleted, `log-size 0`; `service` returning 0 on failure; duplicate-instance detection bypassed
by startup flags; Linux non-root startup failure; site anti-hotlink, CORS, XSS; release process.

**Verification**: +184 tests on Windows, +206 on WSL. 155 files / +21183 −5801.
