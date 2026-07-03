# 配置选项说明

## 配置建议：

**smartdns 默认已设置为最优模式，适合大部分场景的 DNS 查询体验改善。一般情况只需要增加上游服务器地址即可，无需做其他配置修改；如有其他配置修改，请务必了解其用途，避免修改后起到反作用。**

| 键名 | 功能说明 | 默认值 | 可用值/要求 | 举例 |
| :--- | :--- | :--- | :--- | :--- |
| server | 上游 UDP DNS | 无 | 可重复。<br />[ip][:port]\|URL：服务器 IP:端口（可选）或 URL <br />[-blacklist-ip]：配置 IP 过滤结果。<br />[-whitelist-ip]：指定仅接受参数中配置的 IP 范围<br />[-g\|-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 设置服务器为后备服务器。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-subnet-all-query-types]: 当设置ECS时，所有请求都发送ECS。<br />[-interface]：绑定到对应的网口。| server 8.8.8.8:53 -blacklist-ip -group g1 -proxy proxy<br /> server tls://8.8.8.8|
| server-tcp | 上游 TCP DNS | 无 | 可重复。<br />[ip][:port]：服务器 IP:端口（可选）<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：指定仅接受参数中配置的 IP 范围。<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 设置服务器为后备服务器。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 设置TCP的连接超时时间（毫秒）。<br /> [-subnet-all-query-types]: 当设置ECS时，所有请求都发送ECS。<br />[-interface]：绑定到对应的网口。| server-tcp 8.8.8.8:53 |
| server-tls | 上游 TLS DNS | 无 | 可重复。<br />[ip][:port]：服务器 IP:端口（可选)<br />[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 主机IP地址。<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 设置服务器为后备服务器。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 设置TCP的连接超时时间（毫秒）。<br /> [-subnet-all-query-types]: 当设置ECS时，所有请求都发送ECS。<br />[-interface]：绑定到对应的网口。| server-tls 8.8.8.8:853 |
| server-https | 上游 HTTPS DNS | 无 | 可重复。<br />https://[host>][:port]/path：服务器 IP:端口（可选）<br />[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 主机IP地址。<br />[-http-host]：http 协议头主机名<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围。<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 设置服务器为后备服务器。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 设置TCP的连接超时时间（毫秒）。<br /> [-subnet-all-query-types]: 当设置ECS时，所有请求都发送ECS。<br />[-interface]：绑定到对应的网口。| server-https https://cloudflare-dns.com/dns-query |
| server-quic | 上游 DOQ 服务器 | 无 | 可重复。<br />[ip][:port]：服务器 IP:端口（可选)<br />[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 主机IP地址。<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 设置服务器为后备服务器。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 设置TCP的连接超时时间（毫秒）。<br /> [-subnet-all-query-types]: 当设置ECS时，所有请求都发送ECS。<br />[-interface]：绑定到对应的网口。| server-quic 8.8.8.8:853 |
| server-h3 | 上游 HTTP3 DNS | 无 | 可重复。<br />h3://[host>][:port]/path：服务器 IP:端口（可选）<br />[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值<br />[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称。<br />[-host-ip]: 主机IP地址。<br />[-http-host]：http 协议头主机名<br />[-tls-host-verify]：TLS 证书主机名校验<br /> [-k\|-no-check-certificate]：跳过证书校验<br />[-blacklist-ip]：配置 IP 过滤结果<br />[-whitelist-ip]：仅接受参数中配置的 IP 范围。<br />[-g\|-group [group] ...]：DNS 服务器所属组<br />[-e\|-exclude-default-group]：将 DNS 服务器从默认组中排除。<br />[-set-mark]：设置数据包标记so-mark。<br />[-p\|-proxy name]：设置代理服务器。 <br />[-b\|-bootstrap-dns]：标记此服务器为bootstrap服务器。<br />[-fallback]: 设置服务器为后备服务器。<br />[-subnet]：指定服务器使用的edns-client-subnet。<br /> [-tcp-keepalive]: 设置TCP的连接超时时间（毫秒）。<br /> [-subnet-all-query-types]: 当设置ECS时，所有请求都发送ECS。<br />[-interface]：绑定到对应的网口。| server-h3 h3://cloudflare-dns.com/dns-query |
| bind | DNS 监听端口号 | [::]:53 | 可绑定多个端口。<br />IP:PORT@DEVICE: 服务器 IP:端口号@设备名<br />[-group]: 请求时使用的 DNS 服务器组<br />[-no-rule-addr]：跳过 address 规则<br />[-no-rule-nameserver]：跳过 Nameserver 规则<br />[-no-rule-ipset]：跳过 ipset 和 nftset 规则<br />[-no-rule-soa]：跳过 SOA(#) 规则<br />[-no-dualstack-selection]：停用双栈测速<br />[-no-speed-check]：停用测速<br />[-no-cache]：停止缓存 <br />[-force-aaaa-soa]: 禁用IPV6查询 <br />[-force-https-soa]: 禁用HTTPS记录查询 <br />[-no-serve-expired]: 禁用过期缓存 <br />[-ipset]: 设置IPSet，参考ipset选项 <br />[-nftset]: 设置nftset，参考nftset选项| bind :53@eth0 |
| bind-tcp | DNS TCP 监听端口号 | [::]:53 | 可绑定多个端口，规则选项同 bind | bind-tcp :53 |
| bind-tls | DNS Over TLS 监听端口号 | [::]:853 | 可绑定多个端口，规则选项同 bind | bind-tls :853 |
| bind-https | DNS Over HTTPS 监听端口号 | [::]:853 | 可绑定多个端口，规则选项同 bind | bind-https :853 |
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
| max-query-limit | 最大并发请求数量 | 65535 | 请求数量 | max-query-limit 1000 |
| log-level | 设置日志级别 | error | off、fatal、error、warn、notice、info 或 debug | log-level error |
| log-file | 日志文件路径 | /var/log/smartdns/smartdns.log | 合法路径字符串 | log-file /var/log/smartdns/smartdns.log |
| log-size | 日志大小 | 128K | 数字 + K、M 或 G | log-size 128K |
| log-num | 日志归档个数 | 8 (openwrt为2) | 大于等于 0 的数字，0表示禁用日志 | log-num 2 |
| log-file-mode | 日志归档文件权限 | 0640 | 文件权限 | log-file-mode 644 |
| log-console | 是否输出日志到控制台 | no | [yes\|no] | log-console yes |
| log-syslog | 是否输出日志到系统日志 | no | [yes\|no] | log-syslog yes |
| audit-enable | 设置审计启用 | no | [yes\|no] | audit-enable yes |
| audit-file | 审计文件路径 | /var/log/smartdns-audit.log | 合法路径字符串 | audit-file /var/log/smartdns-audit.log |
| audit-size | 审计大小 | 128K | 数字 + K、M 或 G | audit-size 128K |
| audit-num | 审计归档个数 | 2 | 大于等于 0 的数字 | audit-num 2 |
| audit-file-mode | 审计归档文件权限 | 0640 | 文件权限 | log-file-mode 644 |
| audit-console | 是否输出审计日志到控制台 | no | [yes\|no] | audit-console yes |
| audit-syslog | 是否输出审计日志到系统日志 | no | [yes\|no] | audit-syslog yes |
| acl-enable | 启用ACL | no | [yes\|no] <br /> 和client-rules搭配使用。| acl-enable yes | 
| group-begin | 规则组开始 | 无 | [group-name]: 组名<br /> [-inherit group-name]:继承配置的组, `none`表示不继承。<br />启用此参数后，其后的配置项将设置到对应的组中，直到 group-end。| group-begin group-name | 
| group-end | 规则组结束 | 无 | 和group-begin搭配使用 | group-end |
| group-match | 匹配组规则 | 无 | 当满足条件时使用对应的规则组<br />[-g\|group group-name]: 指定规则组，不指定时使用当前组。<br />[-client-ip ip-set\|ip/cidr\|mac address]: 匹配指定客户端 IP 或 MAC。<br />[-domain domain]: 匹配指定域名。 | group-match -client-ip 1.1.1.1 -domain a.com |
| conf-file | 附加配置文件 | 无 | path [-g\|group group-name] [-p\|-proxy proxy-name]<br />path: 本地路径或支持 HTTP/HTTPS 在线下载 <br />[-p\|-proxy]: 指定通过代理服务器下载远程配置文件 | conf-file /etc/smartdns/more.conf <br /> conf-file https://site.com/rule.conf -p clash |
| proxy-server | 代理服务器 | 无 | 可重复。<br />[URL]: [socks5\|http]://[username:password@]host:port<br />[-name]: 代理服务器名称。 |proxy-server socks5://user:pass@1.2.3.4:1080 -name proxy|
| speed-check-mode | 测速模式选择 | ping,tcp:80,tcp:443 | [ping\|tcp:[80]\|none] | speed-check-mode ping,tcp:80,tcp:443 |
| response-mode | 首次查询响应模式 | first-ping |模式：[first-ping\|fastest-ip\|fastest-response]<br /> [first-ping]: 最快ping响应地址模式，DNS等待与连接体验最佳;<br />[fastest-ip]: 最快IP地址模式，强制等待IP测速完毕; <br />[fastest-response]: 最快响应DNS结果，等待最短，但可能不是最快IP。| response-mode first-ping |
| address | 指定域名 IP 地址 | 无 | address [/[*\|-.]domain/][ip1[,ip2,...]\|-\|-4\|-6\|#\|#4\|#6] <br />- 表示忽略此规则 <br /># 表示返回 SOA <br />4 表示 IPv4 <br />6 表示 IPv6 <br /> * 开头表示通配，- 开头表示主域名| address /www.example.com/1.2.3.4<br />address /example.com/1.2.3.4,5.6.7.8 |
| cname | 指定域名别名 | 无 | cname /domain/target <br />- 表示忽略此规则 <br />指定对应域名的cname | cname /www.example.com/cdn.example.com |
| srv-record | 指定SRV记录 | 无 | srv-record /domain/[target][,port][,priority][,weight] | srv-record /_vlmcs._tcp/example.com,1688,1,1|
| https-record | 指定HTTPS记录 | 无 | https-record /domain/[target=][,port=]... <br /> # 表示返回SOA<br /> - 表示忽略规则| https-record /example.com/alpn="h2,http/1.1" |
| ddns-domain | 指定DDNS域名 | 无 | ddns-domain domain.com, 将指定域名解析为 smartdns 所在主机 IP 地址。| ddns-domain example.com |
| local-domain | 指定本地域名 | 无 | local-domain domain.com, smartdns 会将指定域名追加到本地主机名后面。| local-domain example.com |
| dns64 | DNS64转换 | 无 | dns64 ip-prefix/mask <br /> ipv6前缀和掩码 | dns64 64:ff9b::/96 |
| mdns-lookup | 是否启用mDNS查询 | no | [yes\|no] | mdns-lookup yes|
| hosts-file | 指定hosts文件 | 无 | hosts文件路径 | hosts-file /etc/hosts | 
| edns-client-subnet | DNS ECS | 无 | edns-client-subnet ip-prefix/mask <br /> 指定EDNS客户端子网 | edns-client-subnet 1.2.3.4/23 |
| nameserver | 指定域名使用 server 组解析 | 无 | nameserver /domain/[group\|-], group 为组名，- 表示忽略此规则，配套 server 中的 -group 参数使用 | nameserver /www.example.com/office |
| ipset | 域名 ipset | 无 | ipset [/domain/][ipset\|-\|#[4\|6]:[ipset\|-][,#[4\|6]:[ipset\|-]]] | ipset /www.example.com/#4:dns4,#6:- |
| ipset-timeout | 设置 ipset 超时功能启用  | no | [yes\|no] | ipset-timeout yes |
| ipset-no-speed | 测速失败设置结果到 ipset | 无 | ipset \| #[4\|6]:ipset | ipset-no-speed #4:ipset4,#6:ipset6 |
| nftset | 域名 nftset | 无 | nftset [/domain/][#4\|#6\|-]:[family#nftable#nftset\|-]<br />ipv4 的 family 只支持 inet 和 ip，ipv6 支持 inet 和 ip6。| nftset /www.example.com/#4:inet#tab#dns4,#6:- |
| nftset-timeout | 设置 nftset 超时功能启用  | no | [yes\|no] | nftset-timeout yes |
| nftset-no-speed | 测速失败设置结果到 nftset | 无 | nftset-no-speed [#4\|#6]:[family#nftable#nftset] | nftset-no-speed #4:inet#tab#set4|
| nftset-debug | 设置 nftset 调试功能启用  | no | [yes\|no] | nftset-debug yes |
| domain-rules | 设置域名规则 | 无 | domain-rules /domain/ [-rules...]<br />可选参数参考 speed-check-mode, address, nameserver, nftset 等。| domain-rules /www.example.com/ -speed-check-mode none |
| domain-set | 设置域名集合 | 无 | domain-set [options...]<br />[-n\|-name]：域名集合名称 <br />[-t\|-type]：域名集合类型 (list)<br />[-f\|-file]：域名集合文件路径 (支持远程URL)<br />[-p\|-proxy]：指定代理服务器下载远程规则集文件 | domain-set -name set -file https://x.com/list -proxy clash |
| client-rules | 客户端规则 | 无 | [ip-set\|ip/subnet\|mac address] [-g\|group group-name] [-rules...]<br />设置客户端规则和规则组。 | client-rules 192.168.1.1 -g oversea |
| bogus-nxdomain | 假冒 IP 地址过滤 | 无 | [ip/subnet]，可重复 | bogus-nxdomain 1.2.3.4/16 |
| ignore-ip | 忽略 IP 地址 | 无 | [ip/subnet]，可重复 | ignore-ip 1.2.3.4/16 |
| whitelist-ip | 白名单 IP 地址 | 无 | [ip/subnet]，可重复 | whitelist-ip 1.2.3.4/16 |
| blacklist-ip | 黑名单 IP 地址 | 无 | [ip/subnet]，可重复 | blacklist-ip 1.2.3.4/16 |
| ip-alias | IP 地址别名 | 无 | [ip/subnet] ip1[,[ip2]...]，可重复 | ip-alias 1.2.3.4/16 4.5.6.7|
| ip-rules | IP 地址规则 | 无 | [ip/subnet] [-rules...]<br /> 支持配置 -blacklist-ip, -whitelist-ip, -bogus-nxdomain 等。 | ip-rules 1.2.3.4/16 -whitelist-ip|
| ip-set | 设置 IP 地址集合 | 无 | ip-set [options...]<br />[-n\|-name]：IP地址集合名称 <br />[-t\|-type]：仅支持list<br />[-f\|-file]：IP地址集合文件路径 (支持远程URL)<br />[-p\|-proxy]：指定代理服务器下载远程规则集文件 | ip-set -name set -file /path/to/list <br /> ip-rules ip-set:set -whitelist-ip|
| force-AAAA-SOA | 强制 AAAA 地址返回 SOA | no | [yes\|no] | force-AAAA-SOA yes |
| force-no-CNAME | 强制 不返回 CNAME | no | [yes\|no] | force-no-CNAME yes |
| prefetch-domain | 域名预先获取功能 | no | [yes\|no] | prefetch-domain yes |
| serve-expired | 过期缓存服务功能 | yes | [yes\|no]，开启后响应TTL为0的旧记录以避免查询等待 | serve-expired yes |
| serve-expired-ttl | 过期缓存服务最长超时时间 | 86400 | 秒，0 表示停用超时，大于 0 表示指定的超时的秒数 | serve-expired-ttl 604800 |
| serve-expired-reply-ttl | 回应的过期缓存 TTL | 3 | 秒，过期缓存记录回复的TTL时间 | serve-expired-reply-ttl 3 |
| serve-expired-prefetch-time | 预取超时参数 | 21600 | 秒。缓存过期后，若在此时间（默认6小时）内再次被访问，将秒回旧缓存并在后台触发更新。 | serve-expired-prefetch-time 21600 |
| dualstack-ip-selection | 双栈 IP 优选 | yes | [yes\|no] | dualstack-ip-selection yes |
| dualstack-ip-selection-threshold | 双栈 IP 优选阈值 | 10ms | 单位为毫秒（ms） | dualstack-ip-selection-threshold [0-1000] |
| user | 进程运行用户 | root | user [username] | user nobody |
| ca-file | 证书文件 | /etc/ssl/.../ca-certificates.crt | 合法路径字符串 | ca-file /etc/ssl/certs/ca-certificates.crt |
| ca-path | 证书文件路径 | /etc/ssl/certs | 合法路径字符串 | ca-path /etc/ssl/certs |
