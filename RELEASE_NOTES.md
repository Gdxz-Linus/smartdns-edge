## 概述

修复 **53 个问题**，覆盖解析正确性、稳定性、安全防御与内嵌组件；新增自签证书自动生成、加密私钥支持等四项功能。升级无需改配置，日志与配置文件格式无变化。

### 新增功能

- **自签证书自动生成**：未配置证书时，TLS/HTTPS/H3 监听自动生成自签名证书链（含根 CA，默认有效期 390 天），支持 `bind-cert-generate`、`bind-cert-validity-days`、`bind-cert-san` 等参数。
- **加密私钥支持**：TLS/HTTPS 上游与监听支持带口令的 PKCS#8 私钥；传统加密方式会给出明确的迁移提示。
- **`-fallback` 上游标记**：被标记的上游平时不参与查询，只在同组其它上游都无法给出可用答案时启用。

### 修复

**解析正确性**——双栈优选在部分场景下选错地址（存活时间取长舍短、空应答抢跑、关闭测速后优选未失效、SOA 设置误拦 A 记录查询）；DNS64 前缀布局不符合 RFC 6052（现支持全部六种合法前缀长度）；域名数字转义（`\DDD`）按八进制解码（应为十进制，解析与显示两端已同步）；SVCB/HTTPS 记录参数的文本写法与网络解码不一致；缓存中"仅过期时间不同"的记录更新被静默丢弃；私网反向查询（PTR）短路导致内网主机名无法反查；带客户端子网（ECS）的缓存刷新丢失子网信息。

**稳定性**

- 上游持续返回错误或"忙"时，重试无间隔、形成空转（Busy 场景还会无限循环）——现按间隔退避并让出执行权。
- TCP 连接收到长度为 0 的报文时整条连接被断开——现跳过该报文、连接保持。
- 监听持续出错、mDNS 端口耗尽、日志文件被外部轮转等场景下，服务会停止响应或停止记录——现已修复。
- 缓存文件损坏时可能反复启动失败——现自动删除损坏文件并以空缓存重建。

**安全与资源**

- 代理地址写错时此前会跳过代理直接连网下载外部名单（可能被污染）——现明确报错并中止。
- 超大 DoH 请求体现在直接拒绝；DoH 错误回显不再包含内部地址信息。
- 按报文头部声明预分配内存——现改为小额起步、随实际数据增长。
- 连接配额的归还过程在内部状态异常时不再丢失；UDP 过载时对被丢弃的请求不再回包，避免被用作反射攻击的放大器。

### 其它改进

- 内嵌组件的多处预防性修复（证书算法声明与实际能力不符、SOA 记录解析取错字段、参数名写法不一致、词法解析的转义与超长内容处理等）。
- 内嵌测速组件（surge-ping）收包任务加固：探测任务在异常环境下不再中断，持续失败时按间隔退避。
- Linux 非 systemd 环境（initd）服务脚本修正：启用/禁用自启此前是空操作，现真正生效。
- 中文文档与 README 语言全量检查；配置模板修正 `ca-path` 示例拼写。

### 规模与验证

主仓库测试 **635 项全部通过**（Windows 实测），WSL 侧关键路径复测通过。变更规模：**40 文件 / +1323 −230**。

---

## English Summary

**53 issues fixed**, covering resolution correctness, stability, security and the vendored
components; four new features including self-signed certificate auto-generation and encrypted
private-key support. No config change needed to upgrade.

**Resolution correctness**: dual-stack selection picking wrong addresses (longest TTL instead of
shortest, races won by empty answers, ignored when speed check was off); DNS64 prefix layout now
fully RFC 6052 compliant; `\DDD` escapes decoded as decimal per RFC 1035 (was octal); SVCB/HTTPS
key notation now consistent between text and wire form; identical records differing only in TTL
are no longer silently dropped; PTR queries for private addresses no longer short-circuited;
ECS cache entries no longer lose their subnet on refresh.

**Stability**: listeners no longer spin at 100% CPU on persistent errors; upstream "busy" responses
no longer cause an unthrottled retry loop; TCP connections survive zero-length packets; corrupt
cache files are rebuilt instead of failing startup; log writing resumes after external rotation.

**Security & resources**: a misconfigured proxy no longer falls back to direct (unproxied) list
downloads; oversized DoH bodies are rejected; DoH error responses no longer leak internal addresses;
memory is no longer pre-allocated from untrusted header counts; connection-quota accounting survives
internal errors; dropped UDP requests during load shedding are never reflected.

**Also**: preventive fixes in the vendored DNS library; hardened receive task in the vendored
ping component; Linux initd service scripts now actually enable/disable autostart; full language
review of the Chinese docs and README; `ca-path` example spelling fixed in the template.

**Verification**: 635 tests passing on Windows; key paths retested on WSL. 40 files / +1323 −230.
