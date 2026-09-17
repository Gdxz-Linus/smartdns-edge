# Configurations Parameters

## Configuration Advice:

**By default, smartdns is set to the optimal mode, suitable for improving the DNS query experience in most scenarios. Generally, you only need to add upstream server addresses without making other configuration changes. If you need to make other configuration changes, be sure to understand their purpose to avoid counterproductive effects.**

| parameter | Parameter function | Default value | Value type | Example |
| :--- | :--- | :--- | :--- | :--- |
| max-connections | Maximum number of simultaneous connections across all DNS listeners. **Auto-derived from physical memory when unset** (tighter on small home boxes, looser on enterprise servers) | auto | integer, 0 = auto | max-connections 20000 |
| max-connections-per-ip | Maximum simultaneous connections from a single source (IPv6 is aggregated by /64 prefix). Do not set it too low: many clients behind NAT/proxies share one IP | auto | integer, 0 = auto | max-connections-per-ip 1000 |
| first-packet-timeout | Seconds to wait for the first complete DNS message after a connection is established. Blocks slow attacks that send only a length prefix. Normal clients send their query right after the handshake and are unaffected | 5 | seconds, 0 = unlimited | first-packet-timeout 5 |
| api-token | Login token of the management console (WebAPI). **No built-in default password is kept**: if unset and the console listens on localhost only, a random token is generated and printed to the log; if the console is bound to a non-local address while no token is configured, the daemon refuses to start | none | any string | api-token my-secret-2026 |
| server | Upstream UDP DNS server | None | Repeatable <br />[ip:port\|URL]: Server IP, port optional OR URL. <br />[-blacklist-ip]: filtering IPs configured by "blacklist-ip". <br />[-whitelist-ip]: only accept IP range configured in whitelist-ip. <br />[-g\|-group [group] ...]: Group to which the DNS server belongs. <br />[-e\|-exclude-default-group]: Exclude DNS servers from the default group. <br />[-set-mark mark]: set mark on packets <br /> [-p\|-proxy name]: set proxy server <br /> [-b\|-bootstrap-dns]: set as bootstrap dns server <br /> [-fallback]: mark this server as a **fallback**: it does not take part in normal queries; it is used only when the group's regular servers give no usable answer (timeout, failure, or nothing but a truncated reply). <br />[-subnet]：set per server edns-client-subnet. <br /> [-subnet-all-query-types]: send all types of query with ECS. <br /> [-interface]: bind to interface. | server 8.8.8.8:53 -blacklist-ip -proxy clash<br />server tls://8.8.8.8 |
| server-tcp | Upstream TCP DNS server | None | Repeatable, same options as `server` plus `[-tcp-keepalive]`. | server-tcp 8.8.8.8:53 |
| server-tls | Upstream TLS DNS server | None | Repeatable. <br />[-spki-pin [sha256-pin]]: additionally pin the peer certificate public key — pin = base64 of the SHA-256 of the certificate SPKI (32 bytes when decoded). It is an **extra** check, not a replacement for chain validation (use `-k` to skip that); using both means only that key is accepted (self-signed certificates are fine). Compute it yourself: `openssl x509 -in cert -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`<br />[-host-name]:TLS Server name. - to disable SNI.<br />[-tls-host-verify]: TLS cert hostname to verify. <br />[-k\|-no-check-certificate]: No check certificate. <br /> Plus all `server` options. | server-tls 8.8.8.8:853 |
| server-https | Upstream HTTPS DNS server | None | Repeatable. <br />https://[host][:port]/path: Server URL. <br />[-http-host]: http header host. <br /> Plus all `server-tls` options. | server-https https://cloudflare-dns.com/dns-query |
| server-quic | Upstream Quic DNS server | None | Repeatable, same options as `server-tls`. | server-quic 8.8.8.8:853 |
| server-h3 | Upstream HTTP3 DNS server | None | Repeatable, same options as `server-https`. | server-h3 h3://cloudflare-dns.com/dns-query |
| bind | DNS listening port number | [::]:53 | Support binding multiple ports<br />`IP:PORT@DEVICE`: server IP, port number, and device. <br />[-group]: DNS server group used when requesting. <br />[-no-rule-addr / -nameserver / -ipset / -soa]: Skip specific rules. <br />[-no-dualstack-selection / -no-speed-check / -no-cache]: Disable corresponding features. <br />[-force-aaaa-soa / -force-https-soa / -no-serve-expired]: Force specific query behaviors. <br />[-no-api]: this listener serves DoH only and does not mount the console. <br />[-max-connections N]: per-listener connection cap. <br />[-max-connections-per-ip N]: per-listener per-source cap. <br />[-acl]: turn on access control for this listener alone (clients matching no client-rules get REFUSED). | bind :53@eth0 |
| bind-tcp | TCP mode DNS listening port number | [::]:53 | Support binding multiple ports. Same options as `bind`. | bind-tcp :53 |
| bind-tls | DOT mode DNS listening port number | [::]:853 | Support binding multiple ports. Same options as `bind`. | bind-tls :853 |
| bind-https | DOH mode DNS listening port number | [::]:853 | Support binding multiple ports. Same options as `bind`. | bind-https :853 |
| bind-http | Plain-HTTP listener (**also mounts the management console**; never expose it directly — use an SSH tunnel or add `-no-api`) | none | Support binding multiple ports. Same options as `bind`. | bind-http 127.0.0.1:6080 |
| bind-h3 | DNS over HTTP/3 listening port number | none | Support binding multiple ports. Same options as `bind`. | bind-h3 :853 |
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
| acl-enable | enable access control (ACL) | no | [yes\|no] <br />Used together with `client-rules` as a whitelist: **once enabled, any client that matches no `client-rules` entry gets REFUSED** (refused on the spot — the upstream is never queried and nothing is cached); matching clients are served as before.<br />To enable it for a single listener only, use `bind ... -acl`; either one being true turns it on.<br />Left off (the default), nothing changes. | acl-enable yes | 
| group-begin | rule group start | None | Group name:<br />[-inherit group-name]: inherit configuration from `group-name`.<br />Used with group-end, configurations between them belong to the group. | group-begin group-name |
| group-end | rule group end | None | Used with group-begin. | group-end |
| group-match | Match group rules | None | Use the corresponding rule group when conditions are met. <br />[-g\|group group-name]: Specify rule group.<br />[-client-ip ip-set\|ip/cidr\|mac address]: Match client.<br />[-domain domain]: Match domain name. | group-match -client-ip 1.1.1.1 -domain a.com |
| conf-file | additional conf file | None | path [-g\|group group-name]<br />path: configuration file path, wildcards are supported (e.g. /etc/smartdns/conf.d/*.conf, multiple matches are loaded in sorted file-name order); a relative path is resolved against the directory of the current configuration file<br />[-g\|group]: attach the whole included section to that rule group (accepted before or after the path)<br />Local files only (HTTP/HTTPS download is not supported; use domain-set -url for remote rule lists) | conf-file /etc/smartdns/more.conf <br /> conf-file /etc/smartdns/conf.d/*.conf <br /> conf-file /etc/smartdns/company.conf -g office <br />Duplicate or circular includes are de-duplicated automatically and never recurse |
| proxy-server | proxy server | None | Repeatable. <br />[URL]: [socks5\|http]://[username:password@]host:port<br />[-name]:  proxy server name. | proxy-server socks5://user:pass@127.0.0.1:1080 -name proxy |
> Passwords in proxy URLs are masked automatically in logs and debug output.

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
| nftset | Domain nftset | None | nftset [/domain/][#4\|#6\|-]:[family#nftable#nftset\|-] <br /> valid families are inet, ip, ip6. | nftset /www.example.com/#4:inet#tab#dns4 <br />Multiple `nftset` entries for the same domain are **all applied** (merged, not overwritten) |
| nftset-timeout | nftset timeout enable | no | [yes\|no] | nftset-timeout yes |
| nftset-no-speed | Set IP to nftset when speed check fails | None | nftset-no-speed [#4\|#6]:[family#nftable#nftset] | nftset-no-speed #4:inet#tab#set4 |
| nftset-debug | nftset debug enable | no | [yes\|no] | nftset-debug yes |
| domain-rules | set domain rules | None | domain-rules /domain/ [-rules...]<br /> Options refer to speed-check-mode, address, nameserver, etc. (`-nftset` is not supported yet; use the top-level `nftset /domain/…` directive instead) | domain-rules /www.example.com/ -speed-check-mode none |
| domain-set | collection of domains | None | domain-set [options...]<br />[-n\|-name]: name of set <br />[-t\|-type] [list]: set type <br />[-f\|-file]: **local** file path of the set<br />[-u\|-url]: remote list URL (HTTP/HTTPS; use instead of -file)<br />[-i\|-interval]: auto-refresh period in seconds; re-reads the file / re-downloads the remote list when it elapses (no refresh when omitted)<br />[-p\|-proxy name]: Specify proxy server to download remote list. | domain-set -name set -url https://x.com/list -proxy proxy |
| client-rules | Client rules | None | [ip-set\|ip/subnet\|mac address] [-g\|group group-name] [-rules...] <br />Set client rules and rule groups. | client-rules 192.168.1.1 -g group-tv |
| bogus-nxdomain | bogus IP address | None | [IP/subnet], Repeatable | bogus-nxdomain 1.2.3.4/16 |
| ignore-ip | ignore ip address | None | [ip/subnet], Repeatable | ignore-ip 1.2.3.4/16 |
| whitelist-ip | ip whitelist | None | [ip/subnet], Repeatable | whitelist-ip 1.2.3.4/16 |
| blacklist-ip | ip blacklist | None | [ip/subnet], Repeatable | blacklist-ip 1.2.3.4/16 |
| ip-alias | IP alias | None | [ip/subnet] ip1[,[ip2]...]，Repeatable | ip-alias 1.2.3.4/16 4.5.6.7 |
| ip-rules | IP rules | None | [ip/subnet] [-rules...]<br /> Supports -blacklist-ip, -whitelist-ip, etc. | ip-rules 1.2.3.4/16 -whitelist-ip |
| ip-set | collection of IPs | None | ip-set [options...]<br />[-n\|-name]: name of ip set <br />[-t\|-type]: list <br />[-f\|-file]: file path of the IP set (local file)<br />[-u\|-url]: remote URL of the IP set (http/https)<br />[-p\|-proxy]: name of the proxy used to download a remote set (defined by `proxy-server ... -name xxx`)<br />[-i\|-interval]: auto refresh interval in seconds (no refresh when omitted)<br />Exactly one of `-file` / `-url` must be given | ip-set -name set -file /path/to/list <br /> ip-set -name set -url https://example.com/ip.list -interval 86400 |
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

---

## Management console (WebAPI)

Configuring any of `bind-http` / `bind-https` / `bind-h3` exposes both DNS service (DoH)
and the management console on that port (the `/api` endpoints for config, upstreams,
address rules, cache and logs, plus `/api/docs` for the API reference).
The console can be turned off per listener with the `-no-api` option, e.g.
`bind-https 0.0.0.0:8000 -ssl-certificate cert.pem -ssl-certificate-key key.pem -no-api`.

### Token (must read)

The token is resolved in this order:

1. `api-token <token>` in the configuration file;
2. the `SMARTDNS_API_TOKEN` environment variable;
3. otherwise a random token is generated and printed to the console/log at startup
   (a ready-to-paste `api-token <token>` line is printed as well).

There is **no hard-coded default password**. If the console is bound to a non-local
address without a configured token, the daemon (and `smartdns test`) **refuses to start**,
because that would expose the console to the whole network.

### How to use it safely

| Scenario | Recommendation |
|---|---|
| Local administration only | `bind-http 127.0.0.1:8000`, open `http://127.0.0.1:8000` |
| Remote administration (recommended) | do **not** expose the port; use an SSH tunnel: `ssh -L 8000:127.0.0.1:8000 your-server`, then open `http://localhost:8000` |
| Long-term remote access | use `bind-https 0.0.0.0:8000 -ssl-certificate ... -ssl-certificate-key ...` with a token you set yourself, and restrict the source network |

⚠️ `bind-http` is plain HTTP: the token travels unencrypted. Unless you are using an SSH
tunnel, always use `bind-https`.

---

## Memory protection (connection limits and slow-attack defence)

DNS over TCP / DoT / DoQ messages carry a 2-byte length prefix (declaring up to 65535 bytes).
Allocating the declared size up front means an attacker occupies 64 KiB by sending just 2 bytes;
combined with unlimited connections that is enough to exhaust the server's memory. Three layers of
protection are in place:

| Protection | What it does |
|---|---|
| **The length prefix is not trusted** (root fix) | Reads are chunked at 4 KiB and grow on demand, so memory is proportional to the **bytes actually received**. 2 bytes sent ⇒ 4 KiB used (previously 64 KiB) |
| **First-packet timeout `first-packet-timeout`** (default 5 s) | The first complete message must arrive within 5 s of connection setup, otherwise the connection is closed; the window shrinks from 120 s to 5 s. Long-lived connection reuse is unaffected (afterwards `tcp-idle-time` applies) |
| **Connection limits** | Both the total number of simultaneous connections and the number per source are capped; over-limit connections are refused (existing ones are untouched). Defaults are derived from physical memory: budget = clamp(RAM/8, 16 MiB, 512 MiB), 32 KiB per connection → total = clamp(budget/32 KiB, 512, 16384), per source = total/8 (min 64, max 2048) |

**Auto-derived defaults, for reference:**

| Machine | Physical memory | Auto total | Per source |
|---|---|---|---|
| Home router / NAS | 256 MB | 1024 | 128 |
| Home server | 8 GB | 16384 | 2048 |
| Enterprise server | 32 GB+ | 16384 (raise as needed) | 2048 |

**Other points:**

- Connections from loopback (127.0.0.1 / ::1) **do not consume quota**, so you can always reach the
  console locally or over an SSH tunnel even while a connection flood is going on.
- Over-limit traffic is refused for **new** connections only; existing connections are never dropped,
  and a rate-limited log line is written.
- `GET /api/system/status` exposes the current connection count, the number refused, the limit, and
  `panics_total` (should stay 0).
- **Per-listener override**: `bind-tcp 0.0.0.0:53 -max-connections 20000` tightens or relaxes a single
  listener; it applies **in addition to** the global limit (e.g. relaxed on the LAN, tight on a public DoH port).
- There is no "unlimited" value: to lift the limit in practice, set a very large number.
- **Networks behind NAT should raise the per-source limit**: if an enterprise egress is a single NAT
  gateway, thousands of devices share one source IP and the default (total/8) can be reached by
  **legitimate** traffic. Watch `connections_rejected` in `GET /api/system/status` and raise
  `max-connections-per-ip` if it keeps growing.
- It is advisable to run with the defaults for a while and watch the real peak before tuning.
- When startup is refused because of an invalid configuration (e.g. the console bound to a public
  address without a token), the process exits with **code 2** (2 = configuration error).

---

## Protocol robustness

- Requests with an unsupported `OpCode` (`IQUERY` / `STATUS` / `NOTIFY` / `UPDATE` / unknown)
  are answered with **NotImp** (RFC 1035 §4.1.1), echoing the original ID and question section.
- A DNS **response** packet (QR=1) arriving at the server is silently dropped: such traffic is
  usually spoofed/reflected or misconfigured, and answering a response would create a loop.
- **Upstream response source verification (anti-poisoning)**: direct UDP upstream sockets are
  `connect`ed to the upstream, so the kernel drops responses whose source IP/port does not match.
  Over a SOCKS5 proxy the socket is already `connect`ed to the relay, and the source address carried
  in the datagram header is additionally checked against the upstream being queried; mismatches are
  dropped and counted. See `udp_source_rejected` in `GET /api/system/status` (proxy path only — on the
  direct path the kernel drops them and the application cannot see them).
- Any panic inside the process is logged (rate-limited) and counted; check the `panics_total`
  field of `GET /api/system/status` (it should stay 0).
- As a safety net, a request that hits an unexpected panic is answered with **SERVFAIL**
  instead of leaving the client waiting until timeout.
