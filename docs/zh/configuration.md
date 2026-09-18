# 配置选项说明

## 配置建议：

**smartdns 默认已设置为最优模式，适合大部分场景的 DNS 查询体验改善。一般情况只需要增加上游服务器地址即可，无需做其他配置修改；如有其他配置修改，请务必了解其用途，避免修改后起到反作用。**

| 键名 | 功能说明 | 默认值 | 可用值/要求 | 举例 |
| :--- | :--- | :--- | :--- | :--- |
| max-connections | 所有 DNS 监听合计的同时连接数上限。**不配置则按物理内存自动推算**（家庭小机器自动收紧、企业大机器自动放宽） | 自动 | 整数，0 = 自动 | max-connections 20000 |
| max-connections-per-ip | 单一来源同时连接数上限（IPv6 按 /64 前缀聚合）。不适合设太小：企业 NAT/代理后面成百上千客户端共用一个 IP | 自动 | 整数，0 = 自动 | max-connections-per-ip 1000 |
| first-packet-timeout | 连接建立后等待"第一个完整 DNS 报文"的秒数。用于阻断"只发长度前缀、不发正文"的慢速攻击；正常客户端握手后立刻发查询，不受影响 | 5 | 秒，0 = 不限制 | first-packet-timeout 5 |
| api-token | 管理后台（WebAPI / 网页控制台）的登录口令。**不设置就不会自动生成默认口令**：未配置时若后台只监听本机，会随机生成并打印在日志里；若后台绑定了非本机地址，则直接拒绝启动 | 无 | 任意字符串 | api-token my-secret-2026 |
| server | 上游 UDP DNS | 无 | 可重复。<br />[ip][:port]\|URL：服务器 IP:端口（可选）或 URL <br />[-blacklist-ip]：配置 IP 过滤结果。<br />[-whitelist-ip]：指定仅接受参数中配置的 IP 范围<br />[-g\|-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 把这条服务器设为**后备**：平时不参与查询，只有同组正常那批给不出可用答案（超时、故障、只剩截断包）时它才上场。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-subnet-all-query-types]: 配了 `-subnet`（ECS）时，让**所有**查询类型都带 ECS；不开则只有 A / AAAA 带（默认）。<br />[-interface]：绑定到对应的网口。| server 8.8.8.8:53 -blacklist-ip -group g1 -proxy proxy<br /> server tls://8.8.8.8|
| server-tcp | 上游 TCP DNS | 无 | 可重复。<br />[ip][:port]：服务器 IP:端口（可选）<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：指定仅接受参数中配置的 IP 范围。<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 把这条服务器设为**后备**：平时不参与查询，只有同组正常那批给不出可用答案（超时、故障、只剩截断包）时它才上场。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 给上游带一个 EDNS 的 TCP keepalive 选项（RFC 7828），告诉它「这条连接给我留 N 个 **100 毫秒**」；写 0 = 问上游它愿意留多久。（C 版文档写「毫秒」与 RFC 不符，我们按 RFC。）<br /> [-subnet-all-query-types]: 配了 `-subnet`（ECS）时，让**所有**查询类型都带 ECS；不开则只有 A / AAAA 带（默认）。<br />[-interface]：绑定到对应的网口。| server-tcp 8.8.8.8:53 |
| server-tls | 上游 TLS DNS | 无 | 可重复。<br />[ip][:port]：服务器 IP:端口（可选)<br />[-spki-pin [sha256-pin]]：再核对对端证书的公钥 —— pin = 证书公钥（SPKI）的 SHA-256，base64 写成一行（解码后 32 字节）。它是**额外的**确认，不替代证书链校验（要跳过链校验仍写 `-k`）；两个一起写 = 只认这把公钥（自签证书也行）。自己算 pin：`openssl x509 -in 证书 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 地址写域名时，**连接**改用这个 IP（域名仍用于 TLS 校验与 SNI）；地址本身就是 IP 时忽略并告警。<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 把这条服务器设为**后备**：平时不参与查询，只有同组正常那批给不出可用答案（超时、故障、只剩截断包）时它才上场。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 给上游带一个 EDNS 的 TCP keepalive 选项（RFC 7828），告诉它「这条连接给我留 N 个 **100 毫秒**」；写 0 = 问上游它愿意留多久。（C 版文档写「毫秒」与 RFC 不符，我们按 RFC。）<br /> [-subnet-all-query-types]: 配了 `-subnet`（ECS）时，让**所有**查询类型都带 ECS；不开则只有 A / AAAA 带（默认）。<br />[-interface]：绑定到对应的网口。| server-tls 8.8.8.8:853 |
| server-https | 上游 HTTPS DNS | 无 | 可重复。<br />https://[host>][:port]/path：服务器 IP:端口（可选）<br />[-spki-pin [sha256-pin]]：再核对对端证书的公钥 —— pin = 证书公钥（SPKI）的 SHA-256，base64 写成一行（解码后 32 字节）。它是**额外的**确认，不替代证书链校验（要跳过链校验仍写 `-k`）；两个一起写 = 只认这把公钥（自签证书也行）。自己算 pin：`openssl x509 -in 证书 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 地址写域名时，**连接**改用这个 IP（域名仍用于 TLS 校验与 SNI）；地址本身就是 IP 时忽略并告警。<br />[-http-host]：DoH 请求头里的 Host（与 TLS 的 SNI 是两件事：SNI 仍用地址里的名字）。不写时按地址推：地址是域名就用域名（不带端口），地址是 IP 就写 `IP` 或 `IP:端口`（端口是 443 就省掉）<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围。<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 把这条服务器设为**后备**：平时不参与查询，只有同组正常那批给不出可用答案（超时、故障、只剩截断包）时它才上场。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 给上游带一个 EDNS 的 TCP keepalive 选项（RFC 7828），告诉它「这条连接给我留 N 个 **100 毫秒**」；写 0 = 问上游它愿意留多久。（C 版文档写「毫秒」与 RFC 不符，我们按 RFC。）<br /> [-subnet-all-query-types]: 配了 `-subnet`（ECS）时，让**所有**查询类型都带 ECS；不开则只有 A / AAAA 带（默认）。<br />[-interface]：绑定到对应的网口。| server-https https://cloudflare-dns.com/dns-query |
| server-quic | 上游 DOQ 服务器 | 无 | 可重复。<br />[ip][:port]：服务器 IP:端口（可选)<br />[-spki-pin [sha256-pin]]：再核对对端证书的公钥 —— pin = 证书公钥（SPKI）的 SHA-256，base64 写成一行（解码后 32 字节）。它是**额外的**确认，不替代证书链校验（要跳过链校验仍写 `-k`）；两个一起写 = 只认这把公钥（自签证书也行）。自己算 pin：`openssl x509 -in 证书 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 地址写域名时，**连接**改用这个 IP（域名仍用于 TLS 校验与 SNI）；地址本身就是 IP 时忽略并告警。<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 把这条服务器设为**后备**：平时不参与查询，只有同组正常那批给不出可用答案（超时、故障、只剩截断包）时它才上场。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 给上游带一个 EDNS 的 TCP keepalive 选项（RFC 7828），告诉它「这条连接给我留 N 个 **100 毫秒**」；写 0 = 问上游它愿意留多久。（C 版文档写「毫秒」与 RFC 不符，我们按 RFC。）<br /> [-subnet-all-query-types]: 配了 `-subnet`（ECS）时，让**所有**查询类型都带 ECS；不开则只有 A / AAAA 带（默认）。<br />[-interface]：绑定到对应的网口。| server-quic 8.8.8.8:853 |
| server-h3 | 上游 HTTP3 DNS | 无 | 可重复。<br />h3://[host>][:port]/path：服务器 IP:端口（可选）<br />[-spki-pin [sha256-pin]]：再核对对端证书的公钥 —— pin = 证书公钥（SPKI）的 SHA-256，base64 写成一行（解码后 32 字节）。它是**额外的**确认，不替代证书链校验（要跳过链校验仍写 `-k`）；两个一起写 = 只认这把公钥（自签证书也行）。自己算 pin：`openssl x509 -in 证书 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 地址写域名时，**连接**改用这个 IP（域名仍用于 TLS 校验与 SNI）；地址本身就是 IP 时忽略并告警。<br />[-http-host]：DoH 请求头里的 Host（与 TLS 的 SNI 是两件事：SNI 仍用地址里的名字）。不写时按地址推：地址是域名就用域名（不带端口），地址是 IP 就写 `IP` 或 `IP:端口`（端口是 443 就省掉）<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围。<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 把这条服务器设为**后备**：平时不参与查询，只有同组正常那批给不出可用答案（超时、故障、只剩截断包）时它才上场。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 给上游带一个 EDNS 的 TCP keepalive 选项（RFC 7828），告诉它「这条连接给我留 N 个 **100 毫秒**」；写 0 = 问上游它愿意留多久。（C 版文档写「毫秒」与 RFC 不符，我们按 RFC。）<br /> [-subnet-all-query-types]: 配了 `-subnet`（ECS）时，让**所有**查询类型都带 ECS；不开则只有 A / AAAA 带（默认）。<br />[-interface]：绑定到对应的网口。| server-h3 h3://cloudflare-dns.com/dns-query |
| bind | DNS 监听端口号 | [::]:53 | 可绑定多个端口。<br />IP:PORT@DEVICE: 服务器 IP:端口号@设备名<br />[-group]: 请求时使用的 DNS 服务器组<br />[-no-rule-addr]：跳过 address 规则<br />[-no-rule-nameserver]：跳过 Nameserver 规则<br />[-no-rule-ipset]：跳过 ipset 和 nftset 规则<br />[-no-rule-soa]：跳过 SOA(#) 规则<br />[-no-dualstack-selection]：停用双栈测速<br />[-no-speed-check]：停用测速<br />[-no-cache]：停止缓存 <br />[-force-aaaa-soa]: 禁用IPV6查询 <br />[-force-https-soa]: 禁用HTTPS记录查询 <br />[-no-serve-expired]: 禁用过期缓存 <br />[-ipset [#4\|#6]:集合名]：**这个监听**收到的查询，解析出的地址都额外写进这些 ipset 集合（可与域名规则里配的集合并用，各写各的）<br />[-nftset [#4\|#6]:family#table#set]：同上，写进 nftables 的集合<br />[-no-api]: 该监听只提供 DoH，不挂管理后台 <br />[-max-connections N]: 该监听单独设置连接数上限 <br />[-max-connections-per-ip N]: 该监听单独设置单一来源连接数上限 <br />[-acl]: 该监听单独开启访问控制（没匹配到任何 client-rules 的客户端回 REFUSED） | bind :53@eth0 |
| bind-tcp | DNS TCP 监听端口号 | [::]:53 | 可绑定多个端口，规则选项同 bind | bind-tcp :53 |
| bind-tls | DNS Over TLS 监听端口号 | [::]:853 | 可绑定多个端口，规则选项同 bind | bind-tls :853 |
| bind-https | DNS Over HTTPS 监听端口号 | [::]:853 | 可绑定多个端口，规则选项同 bind | bind-https :853 |
| bind-http | 明文 HTTP 监听（**同时挂载管理后台**，不要直接暴露到公网；建议用 SSH 隧道或加 `-no-api`） | 无 | 可绑定多个端口，规则选项同 bind | bind-http 127.0.0.1:6080 |
| bind-h3 | DNS Over HTTP/3 监听端口号 | 无 | 可绑定多个端口，规则选项同 bind（挂载管理后台的方式同 bind-https） | bind-h3 :853 |
| bind-cert-file | SSL证书文件路径 | smartdns-cert.pem | 合法路径字符串 | bind-cert-file cert.pem |
| bind-cert-key-file | SSL证书KEY文件路径 | smartdns-key.pem | 合法路径字符串 | bind-cert-key-file key.pem |
| bind-cert-key-pass | SSL证书KEY文件密码 | 无 | 字符串 | bind-cert-key-pass password |
| server-name | DNS 服务器名称 | 操作系统主机名 / smartdns | 符合主机名规格的字符串 | server-name smartdns |
| cache-size | 域名结果缓存个数 | 自动调整 | 大于等于 0 的数字 | cache-size 512 |
| cache-persist | 是否持久化缓存 | 自动 | [yes\|no] (剩余空间超 128MB 时自动启用) | cache-persist yes |
| cache-file | 缓存持久化文件路径 | /var/cache/smartdns.cache | 合法路径字符串 | cache-file /tmp/smartdns.cache |
| cache-checkpoint-time | 缓存持久化时间 | 24小时 |秒， 0 或 大于120的数字, 0表示禁用周期持久化 | cache-checkpoint-time 0 |
| tcp-idle-time | TCP 链接空闲超时时间 | 120 |秒， 大于等于 0 的数字 | tcp-idle-time 120 |
| rr-ttl | 域名结果 TTL | 远程查询结果 | 大于 0 的数字 | rr-ttl 600 |
| rr-ttl-min | 允许的最小 TTL 值 | 远程查询结果 | 大于 0 的数字 | rr-ttl-min 60 |
| rr-ttl-max | 允许的最大 TTL 值 | 远程查询结果 | 大于 0 的数字 | rr-ttl-max 600 |
| rr-ttl-reply-max | 允许返回给客户端的最大 TTL 值 | 远程查询结果 | 大于 0 的数字 | rr-ttl-reply-max 60 |
| local-ttl | 本地HOST，address的TTL值 | rr-ttl-min | 大于 0 的数字 | local-ttl  60 |
| max-reply-ip-num | 允许返回给客户的最大IP数量 | IP数量 | 大于 0 的数字 | max-reply-ip-num 1 |
| max-query-limit | 整机**同时处理**的查询数上限（不是每秒、也不是每客户端）；超过就回 `REFUSED` 并每 120 秒最多告警一次 | 65535 | 整数，0 = 不限 | max-query-limit 1000 |
| log-level | 设置日志级别 | error | off、fatal、error、warn、notice、info 或 debug | log-level error |
| log-file | 日志文件路径 | /var/log/smartdns/smartdns.log | 合法路径字符串 | log-file /var/log/smartdns/smartdns.log |
| log-size | 日志大小 | 128K | 数字 + K、M 或 G | log-size 128K |
| log-num | 日志归档个数 | 8 (openwrt为2) | 大于等于 0 的数字，0表示禁用日志 | log-num 2 |
| log-file-mode | 日志归档文件权限 | 0640 | 文件权限 | log-file-mode 644 |
| log-console | 是否输出日志到控制台 | no | [yes\|no] | log-console yes |
| log-syslog | 运行日志**同时**送系统日志（Linux；标识 `smartdns`、facility `LOG_USER`，级别映射成 syslog 优先级）。其它平台配了不生效，启动时会提示 | no | [yes\|no] | log-syslog yes |
| audit-enable | 设置审计启用 | no | [yes\|no] | audit-enable yes |
| audit-file | 审计文件路径 | /var/log/smartdns-audit.log | 合法路径字符串 | audit-file /var/log/smartdns-audit.log |
| audit-size | 审计大小 | 128K | 数字 + K、M 或 G | audit-size 128K |
| audit-num | 审计归档个数 | 2 | 大于等于 0 的数字 | audit-num 2 |
| audit-file-mode | 审计归档文件权限 | 0640 | 文件权限 | log-file-mode 644 |
| audit-console | 是否输出审计日志到控制台 | no | [yes\|no] | audit-console yes |
| audit-syslog | 审计行送系统日志（Linux）。**开着就不再写审计文件**，行首也不带时间戳（系统日志自带）；需要先开 `audit-enable` | no | [yes\|no] | audit-syslog yes |
| acl-enable | 启用访问控制（ACL） | no | [yes\|no] <br />和 client-rules 搭配使用，相当于一份白名单：**开启后，没有匹配到任何 client-rules 的客户端一律收到 REFUSED**（就地拒绝，不查上游、不进缓存），匹配到的照常服务。<br />只想对某一个监听开启时，用 `bind ... -acl`；两者任一为真即生效。<br />不开（默认）时一切照旧。| acl-enable yes | 
| group-begin | 规则组开始 | 无 | [group-name]: 组名<br /> [-inherit 组名\|none\|parent\|default]：继承哪个组的规则 —— `none` = 不继承、`parent` = 继承外层组、`default` = 继承 default 组、写组名 = 继承该组；**被继承的组必须已经定义过**（不支持前向引用，写错会告警）。不写时：**嵌套组默认继承外层组**（与 C 版一致），顶层组不继承。<br />启用此参数后，其后的配置项将设置到对应的组中，直到 group-end。| group-begin group-name | 
| group-end | 规则组结束 | 无 | 和group-begin搭配使用 | group-end |
| group-match | 匹配组规则 | 无 | 当满足条件时使用对应的规则组<br />[-g\|group group-name]: 指定规则组，不指定时使用当前组。<br />[-client-ip ip-set\|ip/cidr\|mac address]: 匹配指定客户端 IP 或 MAC。<br />[-domain domain]: 匹配指定域名。 | group-match -client-ip 1.1.1.1 -domain a.com |
| conf-file | 附加配置文件 | 无 | path [-g\|group group-name]<br />path: 配置文件路径，支持通配符（如 /etc/smartdns/conf.d/*.conf，命中多个时按文件名排序依次加载）；相对路径相对当前配置文件所在目录<br />[-g\|group]：把这一段被包含进来的配置整体挂到该规则组（写在前或写在后都认）<br />仅支持本地文件（不支持 HTTP/HTTPS 在线下载；远程规则集请用 domain-set 的 -url） | conf-file /etc/smartdns/more.conf <br /> conf-file /etc/smartdns/conf.d/*.conf <br /> conf-file /etc/smartdns/company.conf -g office <br />重复包含或循环包含会被自动去重，不会递归崩溃 |
| proxy-server | 代理服务器 | 无 | 可重复。<br />[URL]: [socks5\|http]://[username:password@]host:port<br />[-name]: 代理服务器名称。 |proxy-server socks5://user:pass@1.2.3.4:1080 -name proxy|
> 日志与调试输出中的代理密码会自动打码，不会以明文出现。

| speed-check-mode | 测速模式选择 | ping,tcp:80,tcp:443 | [ping\|tcp:[80]\|none] | speed-check-mode ping,tcp:80,tcp:443 |
| response-mode | 首次查询响应模式 | first-ping |模式：[first-ping\|fastest-ip\|fastest-response]<br /> [first-ping]: 最快ping响应地址模式，DNS等待与连接体验最佳;<br />[fastest-ip]: 最快IP地址模式，强制等待IP测速完毕; <br />[fastest-response]: 最快响应DNS结果，等待最短，但可能不是最快IP。| response-mode first-ping |
| address | 指定域名 IP 地址 | 无 | address [/[*\|-.]domain/][ip1[,ip2,...]\|-\|-4\|-6\|#\|#4\|#6] <br />- 表示忽略此规则 <br /># 表示返回 SOA <br />4 表示 IPv4 <br />6 表示 IPv6 <br /> * 开头表示通配，- 开头表示主域名| address /www.example.com/1.2.3.4<br />address /example.com/1.2.3.4,5.6.7.8 |
| cname | 指定域名别名 | 无 | cname /domain/target <br />- 表示忽略此规则 <br />指定对应域名的cname | cname /www.example.com/cdn.example.com |
| srv-record | 指定SRV记录 | 无 | srv-record /domain/[target][,port][,priority][,weight] | srv-record /_vlmcs._tcp/example.com,1688,1,1|
| https-record | 指定HTTPS记录 | 无 | https-record /domain/[target=][,port=]... <br /> # 表示返回SOA<br /> - 表示忽略规则| https-record /example.com/alpn="h2,http/1.1" |
| ddns-domain | 指定DDNS域名 | 无 | ddns-domain domain.com, 将指定域名解析为 smartdns 所在主机 IP 地址。| ddns-domain example.com |
| local-domain | 把该域名（含子域名）交给 **mDNS** 那一组解析 | 无 | 可多条；写 `-` 清空。**需要同时开 `mdns-lookup yes`**，否则启动时会告警 | local-domain lan |
| dns64 | DNS64转换 | 无 | dns64 ip-prefix/mask <br /> ipv6前缀和掩码 | dns64 64:ff9b::/96 |
| mdns-lookup | 是否启用 mDNS 查询（`.local` 这类本地域名与 `local-domain` 声明的域名走 mDNS 组播解析） | no | [yes\|no] | mdns-lookup yes|
| hosts-file | 指定hosts文件 | 无 | hosts文件路径 | hosts-file /etc/hosts | 
| edns-client-subnet | DNS ECS | 无 | edns-client-subnet ip-prefix/mask <br /> 指定EDNS客户端子网 | edns-client-subnet 1.2.3.4/23 |
| nameserver | 指定域名使用 server 组解析 | 无 | nameserver /domain/[group\|-], group 为组名，- 表示忽略此规则，配套 server 中的 -group 参数使用 | nameserver /www.example.com/office |
| ipset | 域名 ipset | 无 | ipset [/domain/][ipset\|-\|#[4\|6]:[ipset\|-][,#[4\|6]:[ipset\|-]]] <br />把该域名解析出的地址写进指定的 **ipset 集合**（Linux 的 netfilter 集合，常用来做域名分流：防火墙按集合决定这些流量走哪条线）。<br />`-` 表示这一族不写；集合名上限 31 个字符。<br />**只在 Linux 上有效**（其它平台启动时会明确提示"已忽略"）。<br />写不进去（集合不存在、权限不足、名字太长）会在日志里**明确报出原因，只提示一次** —— 不会静默失效。<br />默认不给条目设过期时间（要过期时间请在建集合时用 `timeout`）。 | ipset /www.example.com/#4:dns4,#6:- |
| ipset-timeout | 写进 ipset 的条目是否带过期时间（开启后 = 应答 TTL 的 3 倍，一次答多个地址时取最小的那个 TTL） | no | [yes\|no] | ipset-timeout yes |
| ipset-no-speed | 无需设置：本实现一律把解析出的地址全部写入 ipset（已等同开启） | 无 | [yes\|no] | ipset-no-speed yes |
| nftset | 域名 nftset | 无 | nftset [/domain/][#4\|#6\|-]:[family#nftable#nftset\|-]<br />ipv4 的 family 只支持 inet 和 ip，ipv6 支持 inet 和 ip6。| nftset /www.example.com/#4:inet#tab#dns4,#6:- <br />同一域名可配置多条 nftset，会**全部合并生效**（不会互相覆盖） |
| nftset-timeout | 写进 nftset 的条目是否带过期时间（开启后 = 应答 TTL 的 3 倍，一次答多个地址时取最小的那个 TTL） | no | [yes\|no] | nftset-timeout yes |
| nftset-no-speed | 无需设置：本实现一律把解析出的地址全部写入 nftset（已等同开启） | 无 | [yes\|no] | nftset-no-speed yes |
| nftset-debug | 打开后，往 nftset 写地址时会打出详细日志（写了哪些地址、过期多久） | no | [yes\|no] | nftset-debug yes |
| domain-rules | 设置域名规则 | 无 | domain-rules /domain/ [-rules...]<br />可选参数参考 speed-check-mode, address, nameserver, ipset, nftset 等。<br />`-ipset [#4\|#6]:集合名` / `-nftset [#4\|#6]:family#table#set`：命中的域名解析出的地址写进这些集合（值里不用再写域名）。| domain-rules /www.example.com/ -speed-check-mode none |
| domain-set | 设置域名集合 | 无 | domain-set [options...]<br />[-n\|-name]：域名集合名称 <br />[-t\|-type]：域名集合类型 (list)<br />[-f\|-file]：**本地**域名集合文件路径<br />[-u\|-url]：远程域名集合地址（HTTP/HTTPS，与 -file 二选一）<br />[-i\|-interval]：自动刷新周期（秒），到期后重新读取文件 / 重新下载远程名单，不配置则不自动刷新<br />[-p\|-proxy]：指定代理服务器下载远程规则集文件 | domain-set -name set -url https://x.com/list -proxy clash |
| client-rules | 客户端规则 | 无 | [ip-set\|ip/subnet\|mac address] [-g\|group group-name] [-rules...]<br />设置客户端规则和规则组。 | client-rules 192.168.1.1 -g oversea |
| bogus-nxdomain | 假冒 IP 地址过滤 | 无 | [ip/subnet]，可重复 | bogus-nxdomain 1.2.3.4/16 |
| ignore-ip | 忽略 IP 地址 | 无 | [ip/subnet]，可重复 | ignore-ip 1.2.3.4/16 |
| whitelist-ip | 白名单 IP 地址 | 无 | [ip/subnet]，可重复 | whitelist-ip 1.2.3.4/16 |
| blacklist-ip | 黑名单 IP 地址 | 无 | [ip/subnet]，可重复 | blacklist-ip 1.2.3.4/16 |
| ip-alias | IP 地址别名 | 无 | [ip/subnet] ip1[,[ip2]...]，可重复 | ip-alias 1.2.3.4/16 4.5.6.7|
| ip-rules | 按 **IP 段**挂那几个过滤开关（与顶层的 `blacklist-ip` / `whitelist-ip` / `bogus-nxdomain` / `ignore-ip` 落到同一批表） | 无 | `[ip/subnet]` 或 `ip-set:集合名`，后面可跟多个：`-blacklist-ip`、`-whitelist-ip`、`-bogus-nxdomain`、`-ignore-ip`、`-ip-alias <IP 列表\|ip-set:集合名>` | ip-rules 1.2.3.4/16 -whitelist-ip<br />ip-rules ip-set:cn -ignore-ip |
| ip-set | 设置 IP 地址集合 | 无 | ip-set [options...]<br />[-n\|-name]：IP地址集合名称 <br />[-t\|-type]：仅支持list<br />[-f\|-file]：IP 地址集合文件路径（本地）<br />[-u\|-url]：远程 IP 地址集合 URL（http/https）<br />[-p\|-proxy]：下载远程集合时使用的代理名称（指向 `proxy-server` 定义好的代理）<br />[-i\|-interval]：自动刷新周期（秒），不写则不自动刷新<br />`-file` 与 `-url` 二选一、必须给其一 | ip-set -name set -file /path/to/list <br /> ip-set -name set -url https://example.com/ip.list -interval 86400 <br /> ip-rules ip-set:set -whitelist-ip|
| force-AAAA-SOA | 强制 AAAA 地址返回 SOA | no | [yes\|no] | force-AAAA-SOA yes |
| force-no-CNAME | 强制 不返回 CNAME | no | [yes\|no] | force-no-CNAME yes |
| prefetch-domain | 域名预先获取功能（带 ECS 的域名，刷新也按原记录的 ECS 去问） | no | [yes\|no] | prefetch-domain yes |
| serve-expired | 过期缓存服务功能 | yes | [yes\|no]，开启后响应TTL为0的旧记录以避免查询等待 | serve-expired yes |
| serve-expired-ttl | 过期缓存服务最长超时时间 | 86400 | 秒，0 表示停用超时，大于 0 表示指定的超时的秒数 | serve-expired-ttl 604800 |
| serve-expired-reply-ttl | 回应的过期缓存 TTL | 3 | 秒，过期缓存记录回复的TTL时间 | serve-expired-reply-ttl 3 |
| serve-expired-prefetch-time | 预取超时参数 | 21600 | 秒。缓存过期后，若在此时间（默认6小时）内再次被访问，将秒回旧缓存并在后台触发更新。 | serve-expired-prefetch-time 21600 |
| dualstack-ip-selection | 双栈 IP 优选 | yes | [yes\|no] | dualstack-ip-selection yes |
| dualstack-ip-selection-threshold | 双栈 IP 优选阈值 | 10ms | 单位为毫秒（ms） | dualstack-ip-selection-threshold [0-1000] |
| user | 进程运行用户 | root | user [username] | user nobody |
| ca-file | 证书文件 | /etc/ssl/.../ca-certificates.crt | 合法路径字符串 | ca-file /etc/ssl/certs/ca-certificates.crt |
| ca-path | 证书文件路径 | /etc/ssl/certs | 合法路径字符串 | ca-path /etc/ssl/certs |


---

## 管理后台（WebAPI / 网页控制台）

配置 `bind-http` / `bind-https` / `bind-h3` 中的任意一个，就会在对应端口上同时提供
DNS 服务（DoH）**和**管理后台（`/api` 下的配置、上游、地址规则、缓存、日志等接口，
以及 `/api/docs` 接口文档）。

不想在某个监听上暴露后台（例如"这个端口只想对外提供 DoH"），给它加 `-no-api` 即可：
`bind-https 0.0.0.0:8000 -ssl-certificate cert.pem -ssl-certificate-key key.pem -no-api`

（bind 行上的 `-ssl-certificate` / `-ssl-certificate-key` 与配置表里的 `bind-cert-file` / `bind-cert-key-file`
是同一件事的两种写法：前者写在 `bind*` 行上只对该监听生效，后者是全局默认。）

### 口令（必读）

后台口令按以下顺序取用：

1. 配置里的 `api-token <口令>`；
2. 环境变量 `SMARTDNS_API_TOKEN`；
3. 都没有时：**随机生成一个并打印在启动日志里**（控制台与日志文件都能看到），
   提示形如 `api-token 3f9c...`，把它填进配置即可固定下来。

程序里**没有任何写死的默认口令**。另外，如果后台被绑到了非本机地址（例如
`bind-http 0.0.0.0:8000`）却没有配置口令，程序会**直接拒绝启动**并给出提示——
因为那等于把管理后台开放给整个网络，谁都能改掉你的 DNS 解析结果。

### 怎么安全地用

| 场景 | 建议做法 |
|---|---|
| 只在本机管理 | `bind-http 127.0.0.1:8000`，浏览器开 `http://127.0.0.1:8000` |
| 远程管理（推荐） | **不要**对公网开放端口，用 SSH 隧道：`ssh -L 8000:127.0.0.1:8000 你的服务器`，然后本机浏览器开 `http://localhost:8000` |
| 必须长期远程访问 | 用 `bind-https 0.0.0.0:8000 -ssl-certificate 证书 -ssl-certificate-key 私钥`（口令仍要自己设置），并把来源限制在内网 |

⚠️ `bind-http` 是**明文 HTTP**：口令和内容在网络上是裸奔的，因此除非走 SSH 隧道，
否则请一律使用 `bind-https`。


---

## 内存保护（连接数上限与慢速攻击防护）

DNS over TCP / DoT / DoQ 的报文带 2 字节长度前缀（最大声明 65535 字节）。
如果一收到长度就按声明大小分配内存，攻击者只发 2 个字节就能白占 64 KiB；
再叠加"连接数无上限"，就可以用极小的成本把服务端内存耗尽。本项目对此做了三层防护：

| 防护 | 说明 |
|---|---|
| **不信任长度前缀**（治本） | 读取时按 4 KiB 分块、按需增长，内存只与**实际收到的字节数**成正比。攻击者发 2 字节 ⇒ 只占 4 KiB（原来 64 KiB） |
| **首包超时 `first-packet-timeout`**（默认 5 秒） | 连接建立后必须在 5 秒内发来第一个完整报文，否则断开；超时窗口从 120 秒压到 5 秒。长连接复用不受影响（后续仍按 `tcp-idle-time` 空闲超时） |
| **连接数上限** | 同时连接总数与单一来源连接数都有上限，超限拒绝新连接（已有连接不受影响）。默认按物理内存自动推算：内存预算 = clamp(物理内存/8, 16 MiB, 512 MiB)，每连接按 32 KiB 保守估算 → 总上限 clamp(预算/32 KiB, 512, 16384)，单来源上限 = 总上限/8（下限 64、上限 2048） |

**自动默认值举例**：

| 机器 | 物理内存 | 自动总上限 | 单来源上限 |
|---|---|---|---|
| 家用软路由 / NAS | 256 MB | 1024 | 128 |
| 家用服务器 | 8 GB | 16384 | 2048 |
| 企业服务器 | 32 GB 以上 | 16384（可按需调高） | 2048 |

**其它要点**：

- 本机环回（127.0.0.1 / ::1）的连接**不占配额** —— 保证被人用连接洪泛打满时，
  你仍然能通过本机或 SSH 隧道进管理后台查看情况。
- 超限只拒绝**新连接**，不会断开已有连接；日志中会记录（同一来源限流输出）。
- 当前连接数、被拒次数、总上限、以及 `panics_total`（崩溃次数，正常为 0）可通过
  `GET /api/system/status` 查看。
- **按监听单独设置**：`bind-tcp 0.0.0.0:53 -max-connections 20000` 可以给某个监听单独收紧或放宽，
  与全局限额**同时**生效（例如"内网宽松、对公网的 DoH 端口收紧"）。
- 想**几乎不限制**就填一个很大的数（没有"无上限"这个取值）；想收紧就填小值。
- **出口经 NAT 的网络请调大单来源上限**：企业出口如果是一台 NAT 网关，几千台设备共用一个源 IP，
  默认的"总上限 ÷ 8"有可能被**合法流量**顶到。先看 `GET /api/system/status` 里 `connections_rejected`
  是否持续增长，再决定调大 `max-connections-per-ip`。
- 建议先按默认值运行一段时间，用 `GET /api/system/status` 观察真实峰值，再决定是否调整上限。
- 因配置不合规（例如后台绑对外地址却没设口令）而拒绝启动时，**退出码为 2**（2 = 配置错误），
  便于服务管理器与脚本判断。


---

## 协议健壮性与崩溃防护

- **不支持的请求类型会明确应答**：收到 `IQUERY` / `STATUS` / `NOTIFY` / `UPDATE` 或其它未知
  OpCode 时，按 RFC 1035 §4.1.1 回 **NotImp**（并回带原始 ID 与 Question 段），
  而不是像过去那样不予响应、并在服务端留下一条 panic 记录。
- **收到"响应包"（QR=1）时静默丢弃**：这类报文通常来自伪造/反射流量或配置错误；
  对响应再作响应会形成回环，因此只记录、不回应。
- **上游应答来源校验（防投毒）**：直连的 UDP 上游套接字会 `connect` 到该上游，由内核丢弃
  来源 IP / 端口不符的应答；经 SOCKS5 代理时套接字已 `connect` 到中继，此外还会校验数据报头里的
  来源地址是否等于所查询的上游，不符则丢弃并计数。计数见 `GET /api/system/status` 的
  `udp_source_rejected`（只反映代理路径；直连路径由内核丢弃，应用侧看不到）。
- **崩溃可观测**：进程内发生的任何 panic 都会写进应用日志（同一处限流输出）并计数，
  可在 `GET /api/system/status` 的 `panics_total` 字段查看（正常应恒为 0）。
- **兜底应答**：万一仍有未预期的 panic，该请求会尽量回一个 **SERVFAIL**，
  而不是让客户端一直等到超时（便于排查，也避免被当成故障设备）。
