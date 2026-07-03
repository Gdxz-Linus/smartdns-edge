# Configurations Parameters

## Configuration Advice:

**By default, smartdns is set to the optimal mode, suitable for improving the DNS query experience in most scenarios. Generally, you only need to add upstream server addresses without making other configuration changes. If you need to make other configuration changes, be sure to understand their purpose to avoid counterproductive effects.**

| parameter | Parameter function | Default value | Value type | Example |
| :--- | :--- | :--- | :--- | :--- |
| server | Upstream UDP DNS server | None | Repeatable <br />[ip:port\|URL]: Server IP, port optional OR URL. <br />[-blacklist-ip]: filtering IPs configured by "blacklist-ip". <br />[-whitelist-ip]: only accept IP range configured in whitelist-ip. <br />[-g\|-group [group] ...]: Group to which the DNS server belongs. <br />[-e\|-exclude-default-group]: Exclude DNS servers from the default group. <br />[-set-mark mark]: set mark on packets <br /> [-p\|-proxy name]: set proxy server <br /> [-b\|-bootstrap-dns]: set as bootstrap dns server <br /> [-fallback]: set server as fallback server. <br />[-subnet]：set per server edns-client-subnet. <br /> [-subnet-all-query-types]: send all types of query with ECS. <br /> [-interface]: bind to interface. | server 8.8.8.8:53 -blacklist-ip -proxy clash<br />server tls://8.8.8.8 |
| server-tcp | Upstream TCP DNS server | None | Repeatable, same options as `server` plus `[-tcp-keepalive]`. | server-tcp 8.8.8.8:53 |
| server-tls | Upstream TLS DNS server | None | Repeatable. <br />[-spki-pin [sha256-pin]]: TLS verify SPKI value<br />[-host-name]:TLS Server name. - to disable SNI.<br />[-tls-host-verify]: TLS cert hostname to verify. <br />[-k\|-no-check-certificate]: No check certificate. <br /> Plus all `server` options. | server-tls 8.8.8.8:853 |
| server-https | Upstream HTTPS DNS server | None | Repeatable. <br />https://[host][:port]/path: Server URL. <br />[-http-host]: http header host. <br /> Plus all `server-tls` options. | server-https https://cloudflare-dns.com/dns-query |
| server-quic | Upstream Quic DNS server | None | Repeatable, same options as `server-tls`. | server-quic 8.8.8.8:853 |
| server-h3 | Upstream HTTP3 DNS server | None | Repeatable, same options as `server-https`. | server-h3 h3://cloudflare-dns.com/dns-query |
| bind | DNS listening port number | [::]:53 | Support binding multiple ports<br />`IP:PORT@DEVICE`: server IP, port number, and device. <br />[-group]: DNS server group used when requesting. <br />[-no-rule-addr / -nameserver / -ipset / -soa]: Skip specific rules. <br />[-no-dualstack-selection / -no-speed-check / -no-cache]: Disable corresponding features. <br />[-force-aaaa-soa / -force-https-soa / -no-serve-expired]: Force specific query behaviors. | bind :53@eth0 |
| bind-tcp | TCP mode DNS listening port number | [::]:53 | Support binding multiple ports. Same options as `bind`. | bind-tcp :53 |
| bind-tls | DOT mode DNS listening port number | [::]:853 | Support binding multiple ports. Same options as `bind`. | bind-tls :853 |
| bind-https | DOH mode DNS listening port number | [::]:853 | Support binding multiple ports. Same options as `bind`. | bind-https :853 |
| bind-cert-file | SSL Certificate file path | smartdns-cert.pem | path | bind-cert-file cert.pem |
| bind-cert-key-file | SSL Certificate key file path | smartdns-key.pem | path | bind-cert-key-file key.pem |
| bind-cert-key-pass | SSL Certificate key file password | None | string | bind-cert-key-pass password |
| server-name | DNS name | host name / smartdns | any string like hostname | server-name smartdns |
| cache-size | Domain name result cache number | Auto | integer | cache-size 65536 |
| cache-persist | Enable persist cache | Auto | [yes\|no] (Enabled if >128MB free space) | cache-persist yes |
| cache-file | Cache persist file | /var/cache/smartdns.cache | path | cache-file /tmp/smartdns.cache |
| cache-checkpoint-time | Cache persist time | 24 hours | seconds, 0: disable, other: persist time | cache-checkpoint-time 0 |
| tcp-idle-time | TCP connection idle timeout | 120 | seconds, integer | tcp-idle-time 120 |
| rr-ttl | Domain name TTL | Remote result | number greater than 0 | rr-ttl 600 |
| rr-ttl-min | Domain name Minimum TTL | Remote result | number greater than 0 | rr-ttl-min 60 |
| local-ttl | ttl for address and host | rr-ttl-min | number greater than 0 | local-ttl 600 |
| rr-ttl-reply-max | Domain name Minimum Reply TTL | Remote result | number greater than 0 | rr-ttl-reply-max 60 |
| rr-ttl-max | Domain name Maximum TTL | Remote result | number greater than 0 | rr-ttl-max 600 |
| max-reply-ip-num | Maximum number of IPs returned to client | 8 | number of IPs, 1~16 | max-reply-ip-num 1 |
| max-query-limit | Maximum concurrent number of requests | 65535 | Number of requests | max-query-limit 1000 |
| log-level | log level | error | off,fatal,error,warn,notice,info,debug | log-level error |
| log-file | log path | /var/log/smartdns/smartdns.log | File Pah | log-file /var/log/smartdns.log |
| log-size | log size | 128K | number+K,M,G | log-size 128K |
| log-num | archived log number | 8 (2 for openwrt) | Integer, 0 means turn off the log | log-num 2 |
| log-file-mode | archived log file mode | 0640 | Integer | log-file-mode 644 |
| log-console | enable output log to console | no | [yes\|no] | log-console yes |
| log-syslog | enable output log to syslog | no | [yes\|no] | log-syslog yes |
| audit-enable | audit log enable | no | [yes\|no] | audit-enable yes |
| audit-file | audit log file | /var/log/smartdns-audit.log | File Path | audit-file /var/log/audit.log |
| audit-size | audit log size | 128K | number+K,M,G | audit-size 128K |
| audit-num | archived audit log number | 2 | Integer | audit-num 2 |
| audit-file-mode | archived audit log file mode | 0640 | Integer | audit-file-mode 644 |
| audit-console | enable output audit log to console | no | [yes\|no] | audit-console yes |
| audit-syslog | enable output audit log to syslog | no | [yes\|no] | audit-syslog yes |
| acl-enable | enable ACL | no | [yes\|no] <br /> Used with client-rules. | acl-enable yes | 
| group-begin | rule group start | None | Group name:<br />[-inherit group-name]: inherit configuration from `group-name`.<br />Used with group-end, configurations between them belong to the group. | group-begin group-name |
| group-end | rule group end | None | Used with group-begin. | group-end |
| group-match | Match group rules | None | Use the corresponding rule group when conditions are met. <br />[-g\|group group-name]: Specify rule group.<br />[-client-ip ip-set\|ip/cidr\|mac address]: Match client.<br />[-domain domain]: Match domain name. | group-match -client-ip 1.1.1.1 -domain a.com |
| conf-file | additional conf file | None | file [-g\|-group group-name] [-p\|-proxy proxy-name]<br /> file: File path or remote URL. <br />[-p\|-proxy]: Specify proxy server to download remote conf-file. | conf-file https://site/rule.conf -p clash | 
| proxy-server | proxy server | None | Repeatable. <br />[URL]: [socks5\|http]://[username:password@]host:port<br />[-name]:  proxy server name. | proxy-server socks5://user:pass@127.0.0.1:1080 -name proxy |
| speed-check-mode | Speed ​​mode | ping,tcp:80,tcp:443 | [ping\|tcp:[80]\|none] | speed-check-mode ping,tcp:80,tcp:443 |
| response-mode | First query response mode | first-ping | Mode: [first-ping\|fastest-ip\|fastest-response]<br /> [first-ping]: Shortest DNS + ping delay;<br />[fastest-ip]: Fastest IP address mode, wait to test speed. <br />[fastest-response]: Fastest DNS response mode. | response-mode first-ping |
| address | Domain IP address | None | address /[*\|-]domain/[ip1[,ip2,...]\|-\|-4\|-6\|#\|#4\|#6]<br />`-` for ignore this rule. <br />`#` for return SOA. <br />`*` at the beginning means wildcard. | address /www.example.com/1.2.3.4 |
| cname | set cname to domain | None | cname /domain/target <br />- for ignore this rule. | cname /www.example.com/cdn.example.com |
| srv-record | add srv record | None | srv-record /domain/[target][,port][,priority][,weight] | srv-record /_vlmcs._tcp/example.com,1688,1,1 |
| https-record | Specify HTTPS record | None | https-record /domain/[target=][,port=]... <br /> # indicates return SOA<br /> - indicates ignore rule | https-record /example.com/alpn="h2,http/1.1" |
| ddns-domain | Specifies the DDNS domain | None | ddns-domain domain.com, used to resolve the specified domain to the IP of the host where smartdns resides. | ddns-domain example.com |
| local-domain | Specifies the local domain | None | local-domain domain.com, append local domain to local hostname. | local-domain example.com |
| dns64 | dns64 translation | None | dns64 ip-prefix/mask <br /> ipv6 prefix and mask. | dns64 64:ff9b::/96 |
| mdns-lookup | Enable mDNS lookup | no | [yes\|no] | mdns-lookup yes |
| hosts-file | set hosts file | None | hosts file path. | hosts-file /etc/hosts | 
| edns-client-subnet | DNS ECS | None | edns-client-subnet ip-prefix/mask <br /> set EDNS client subnet | edns-client-subnet 1.2.3.4/23 |
| nameserver | Query domain with group | None | nameserver /domain/[group\|-], `group` is the group name, `-` means ignore this rule. | nameserver /www.example.com/office |
| ipset | Domain IPSet | None | ipset [/domain/][ipset\|-\|#[4\|6]:[ipset\|-]] | ipset /www.example.com/#4:dns4,#6:- |
| ipset-timeout | ipset timeout enable | no | [yes\|no] | ipset-timeout yes |
| ipset-no-speed | Set IP to ipset when speed check fails | None | ipset \| #[4\|6]:ipset | ipset-no-speed #4:ipset4,#6:ipset6 |
| nftset | Domain nftset | None | nftset [/domain/][#4\|#6\|-]:[family#nftable#nftset\|-] <br /> valid families are inet, ip, ip6. | nftset /www.example.com/#4:inet#tab#dns4 |
| nftset-timeout | nftset timeout enable | no | [yes\|no] | nftset-timeout yes |
| nftset-no-speed | Set IP to nftset when speed check fails | None | nftset-no-speed [#4\|#6]:[family#nftable#nftset] | nftset-no-speed #4:inet#tab#set4 |
| nftset-debug | nftset debug enable | no | [yes\|no] | nftset-debug yes |
| domain-rules | set domain rules | None | domain-rules /domain/ [-rules...]<br /> Options refer to speed-check-mode, address, nameserver, nftset, etc. | domain-rules /www.example.com/ -speed-check-mode none |
| domain-set | collection of domains | None | domain-set [options...]<br />[-n\|-name]: name of set <br />[-t\|-type] [list]: set type <br />[-f\|-file]: file path or remote URL<br />[-p\|-proxy name]: Specify proxy server to download remote list. | domain-set -name set -file https://x.com/list -proxy proxy |
| client-rules | Client rules | None | [ip-set\|ip/subnet\|mac address] [-g\|group group-name] [-rules...] <br />Set client rules and rule groups. | client-rules 192.168.1.1 -g group-tv |
| bogus-nxdomain | bogus IP address | None | [IP/subnet], Repeatable | bogus-nxdomain 1.2.3.4/16 |
| ignore-ip | ignore ip address | None | [ip/subnet], Repeatable | ignore-ip 1.2.3.4/16 |
| whitelist-ip | ip whitelist | None | [ip/subnet], Repeatable | whitelist-ip 1.2.3.4/16 |
| blacklist-ip | ip blacklist | None | [ip/subnet], Repeatable | blacklist-ip 1.2.3.4/16 |
| ip-alias | IP alias | None | [ip/subnet] ip1[,[ip2]...]，Repeatable | ip-alias 1.2.3.4/16 4.5.6.7 |
| ip-rules | IP rules | None | [ip/subnet] [-rules...]<br /> Supports -blacklist-ip, -whitelist-ip, etc. | ip-rules 1.2.3.4/16 -whitelist-ip |
| ip-set | collection of IPs | None | ip-set [options...]<br />[-n\|-name]: name of ip set <br />[-t\|-type]: list <br />[-f\|-file]: file path or remote URL<br />[-p\|-proxy name]: Specify proxy server to download remote list. | ip-set -name set -file /path/to/list -proxy proxy |
| force-AAAA-SOA | force AAAA query return SOA | no | [yes\|no] | force-AAAA-SOA yes |
| force-no-CNAME | force No CNAME record | no | [yes\|no] | force-no-CNAME yes |
| prefetch-domain | domain prefetch feature | no | [yes\|no] | prefetch-domain yes |
| serve-expired | Cache serve expired feature | yes | [yes\|no], Serve stale responses instantly without waiting for resolution. | serve-expired yes |
| serve-expired-ttl | Cache serve expired limit TTL | 86400 | seconds | serve-expired-ttl 604800 |
| serve-expired-reply-ttl | TTL value to use when replying with expired data | 3 | seconds | serve-expired-reply-ttl 3 |
| serve-expired-prefetch-time | Prefetch timeout | 21600 | seconds. After cache expires, if accessed within this time (default 6h), it serves stale cache instantly and triggers async background renew. | serve-expired-prefetch-time 21600 |
| dualstack-ip-selection | Dualstack ip selection | yes | [yes\|no] | dualstack-ip-selection yes |
| dualstack-ip-selection-threshold | Dualstack ip select thresholds | 10ms | millisecond | dualstack-ip-selection-threshold [0-1000] |
| user | run as user | root | user [username] | user nobody |
| ca-file | certificate file | /etc/ssl/certs/... | path | ca-file /etc/ssl/certs/ca-certificates.crt |
| ca-path | certificates path | /etc/ssl/certs | path | ca-path /etc/ssl/certs |