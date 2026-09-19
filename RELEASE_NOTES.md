## 概述

这一版做完了两件事：**安全与稳定性缺陷的整改**、**补齐 21 项配置能力**。
升级**不需要改配置**（下文"升级须知"列出的行为变化除外）。

---

## 一、功能完善

**域名分流与防火墙联动**
- `ipset`：把域名解析出的地址写进 Linux 的 ipset 集合（做域名分流用）。写入失败会**明确报出原因**（集合不存在、权限不足、名字过长），每次启动只提示一次，不会静默失效。
- `nftset`：支持按域名写进 nftables 集合，新增 `nftset-debug`（写地址时打详细日志）。
- `ipset-timeout` / `nftset-timeout`：集合条目可带过期时间（按应答 TTL 的 3 倍计算，一次应答多个地址时取最小 TTL）。
- 集合规则支持三种层级：顶层 `ipset`/`nftset`、**监听级** `bind … -ipset/-nftset`、**域名规则级** `domain-rules … -ipset/-nftset`；`-no-rule-ipset` 可让某个监听跳过这类规则。
- `ip-rules`：按 IP/CIDR 或命名集合（`ip-set:`）设置黑名单、白名单、别名、bogus-NXDOMAIN 等 IP 级规则。

**上游解析**
- `-host-ip`：地址写域名时，连接改用指定 IP（域名仍用于 TLS 校验与 SNI）。
- `-http-host`：指定 DoH 请求的 Host 头（与 TLS SNI 分离）。
- `-tcp-keepalive N`：在查询里带上 EDNS TCP keepalive 选项（RFC 7828，单位为 100 毫秒）。
- `-spki-pin`：除证书链校验外，再核对对端证书公钥的 SHA-256（不替代证书链校验）。
- `-fallback`：把某台上游标为后备，正常查询不使用，仅当同组正常上游都给不出可用答案时才上场。

**缓存与解析行为**
- `prefetch-domain`：后台刷新会按原记录带上 ECS，带 ECS 的域名也能被正确预取。
- `local-domain`：把指定域名（含子域名）交给 mDNS 组处理，支持多条。
- `serve-expired` 相关的过期数据行为按明确口径执行：允许服务过期数据时照旧回源刷新；明确写了不要时立即报错，不再静默喂旧数据。

**监听与客户端控制**
- `acl-enable`：监听级访问控制（不匹配客户端规则的请求直接拒绝）。
- `max-query-limit`：同时处理的查询数上限，超限直接回 REFUSED（0 = 不限，默认 65535）。
- `group-begin … -inherit`：服务器组支持继承另一组、`none`（不继承）等写法。

**运维可观测性**
- `log-syslog`：运行日志同时送系统日志（标识 `smartdns`）。
- `audit-syslog`：审计行送系统日志（开启后不再写审计文件，系统日志自带时间戳）。
- `audit-console`：审计行同时输出到控制台。

---

## 二、升级须知（行为变化）

1. **ECS 默认只给 A/AAAA 携带**。若希望所有查询类型都带 ECS，请显式配置 `-subnet` 与 `-subnet-all-query-types`。
2. **嵌套服务器组默认继承外层组**。这一条是为与既有语义对齐；如果某组的本意是"空白组"，请写 `-inherit none`。
3. 对客户端**不再输出 NXDOMAIN**：上游明确表示"不存在"时统一回 NOERROR + SOA（避免部分设备反复重问）；真正的故障（超时、上游 SERVFAIL/REFUSED）仍回 SERVFAIL。
4. 管理接口 `GET /api/config` 回显的配置目录改为以 `~` 开头，不再暴露本机用户目录结构。
5. DoH 的 `?type=` 参数大小写不敏感（`aaaa` 与 `AAAA` 等效）；无法识别的类型仍回 400（不会被静默当成 A 查询）。

**配置无需改动即可升级**；上表 1、2 两条只在"你确实依赖旧行为"时才需要显式配置。

---

## 三、修复

**安全与稳定性**
- 管理后台不再存在写死的默认口令：未配置凭据时不再放行；对外绑定时缺少凭据会拒绝启动；失败尝试有速率限制。
- 畸形 DNS 报文不再导致处理线程崩溃（原先部分非标准报文会触发 panic 并断开连接）。
- `conf-file` 自我引用不再造成递归。
- 代理密码不再以明文出现在日志/调试输出。
- 连接数上限、首包超时、按需分块读取：不再能被极小报文耗尽内存。
- 测试编译失败与 CI 不跑测试的问题一并修复。

**功能正确性**
- 缓存：两个"处理口径不同"的监听不再互相借用答案；上游掐断 TCP 连接时会重试一次（重试只给 300 毫秒预算），不再把装不下的残缺答复交给客户端。
- 上游 UDP/DoQ 增加来源校验（只接受来自所查询上游的应答）。
- 双实例检测：第二个实例会明确退出并报告第一个实例的真实进程号（此前在 Windows 上会报 `PID 0`）。
- 配置解析：选项值以 `#` 开头不再被误当注释；`mdns-lookup` 修好（此前配置了不生效，`.local` 一并受影响）。
- `service start/stop/restart/uninstall` 未安装服务时返回错误退出码，不再让脚本误判成功。

**Linux 平台（本次实测新发现）**
- 修正两处导致 Linux 版**编译失败**的代码。
- 修正 `ipset` 协议版本取值错误 —— 此前在较新内核上写入会失败，且对外只表现为"配了像没配"。
- 后台预取刷新未携带原记录的 ECS。

**文档与工程**
- 四个上游配置行的表格在网页上会散开（命令示例里的管道符未转义）—— 已修。
- 英文文档补齐 `-host-ip` 等中文已有、英文缺失的说明。
- 统一代码格式（仅本项目代码，内嵌副本保持上游原样）；CI 的格式检查范围同步收紧，避免误判。

---

## 四、验证情况

| 范围 | 结果 |
|---|---|
| 单元测试 | 417 通过 / 0 失败 / 4 忽略 |
| 静态检查 | 0 错误 0 告警 |
| 端到端检查（Windows 真机） | 45 项全部通过 |
| 真机检查（Linux，内核 6.18） | 6 组 14 项 + 2 组 13 项，共 27 项，全部通过 |

Linux 真机覆盖：ipset 写入（含过期时间）、nftset 写入（TTL×3 过期时间）、系统日志双通道、单实例互斥、
ICMP 测速排序、无域名的全局 ipset 规则、同网段 ARP 取值（按客户端 MAC 分流）、
发行版识别与 systemd 服务安装/启动/停止/卸载（安装后服务真实应答查询）。

---

## 五、平台说明

- **ipset / nftset 只在 Linux 生效**；其它平台配置了这两项会在启动时明确提示"不会生效"。
- `log-syslog` / `audit-syslog` 只在 Linux 生效，其它平台配置后会有明确提示。

---

## English Summary

**Highlights**: 21 configuration capabilities added for parity with the reference implementation — ipset/nftset
writing (top-level, per-listener and per-domain-rule levels) with optional entry expiry, `ip-rules`, `-host-ip`,
`-http-host`, `-tcp-keepalive` (EDNS, RFC 7828), `-subnet-all-query-types`, `group-begin … -inherit`,
`acl-enable`, `max-query-limit`, `local-domain`, `log-syslog` / `audit-syslog` / `audit-console`,
upstream `-spki-pin` and `-fallback`.

**Behaviour changes**: ECS is attached to A/AAAA only unless `-subnet-all-query-types` is set; nested server
groups inherit the outer group by default (`-inherit none` opts out); NXDOMAIN is never returned to clients
(upstream "does not exist" becomes NOERROR + SOA; real failures stay SERVFAIL); `GET /api/config` reports the
config directory with a `~` prefix; DoH `?type=` is case-insensitive.

**Fixes**: all P0 security/stability findings (hard-coded console credential, malformed-packet panic,
`conf-file` recursion, plaintext proxy password, memory exhaustion via tiny datagrams, CI not running tests),
cache and upstream-source-validation issues, duplicate-instance detection, and two Linux build failures plus
a wrong ipset protocol version that made set writes fail silently.

**Verification**: 417 unit tests passing; 45 end-to-end checks on Windows; 19 checks on a real Linux kernel
(6.18) covering ipset/nftset writes, syslog, single-instance locking, ICMP speed check, same-subnet ARP lookup
and systemd service install/start/stop/uninstall.

**Note**: ipset/nftset and syslog options are Linux-only; other platforms print an explicit notice at startup.
