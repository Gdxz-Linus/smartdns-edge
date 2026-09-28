## 概述

修完 **58 个问题**；**20 个配置项支持写进 `group-begin` 规则组**。升级无需改配置。

## ⚠️ 升级须知

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

## 功能完善

- **规则组参数**：20 个配置项现可写进 `group-begin`，实现"同一域名、不同设备不同策略"。
- **`trusted-proxy <IP|CIDR>`**：反向代理后用真实客户端归组。只对 HTTP 类监听生效，只用于归组。
- **`dnsmasq-lease-file` + `domain`**：从 DHCP 租约解析局域网设备主机名。

## 修复

- **安全**：`conf-file` 可被同名文件劫持；代理口令明文进日志；远程名单可降级为 http；管理后台错误回显、配置未真正落盘、来源过滤漏组播。
- **解析**：双栈优选 TTL 取最长（应取短）；NXDOMAIN 抢先胜出；`speed-check-mode none` 对双栈无效；`force-AAAA-SOA` 连 A 查询也短路。
- **规则组**：没有组级写法的参数（如 `cache-size`）写在 `group-begin` 里会**静默改到全局**；现在会提示并忽略该行。
- **DoH / 缓存**：`AD` / `CD` 取值错误；不支持 RFC 8484 与 `Accept` 列表；缓存容量与配置值对不上。
- **日志**：被外部轮转后永久停写；误删审计档；`log-size 0` 每行归档。
- **服务**：`service` 失败仍返回 0；防多开可被启动参数绕过；Linux 非 root 运行启动失败。
- **官网 / 发布流程**：反馈接口与下载防盗链可绕过、CORS 过宽、页面 XSS；测试未前置于版本号提交。

## 验证

| 平台 | 新增 |
|---|---|
| Windows | **+184** |
| WSL（内核 6.18） | **+206** |

规模：**155 文件 / +21183 −5801**。

## English Summary

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
