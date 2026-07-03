# 2. 上游 DNS 与代理通道

SmartDNS Edge 支持多种主流与前沿的 DNS 查询协议，并深度集成了本地代理功能。本模块将指导您如何配置上游服务器、防污染代理隧道，以及后备与引导解析。

## 2.1 配置上游 DNS 服务器 (UDP/TCP/加密协议)

您可以根据网络环境，混合搭配不同的协议。加密协议（DoT/DoH/DoQ/DoH3）能够有效防止 DNS 劫持和窃听。

   ```shell
   1. 常规 UDP 查询 (极速，但存在被劫持风险)
   server 119.29.29.29 -group cn
   server 8.8.8.8 -group overseas

   2. TCP 查询 (作为 UDP 被阻断时的可靠后备)
   server-tcp 223.5.5.5

   3. DNS-over-TLS (DoT) (安全加密，使用 853 端口)
   server-tls 1.1.1.1:853
   指定 TLS SNI 名称进行证书校验
   server-tls 8.8.8.8:853 -host-name dns.google

   4. DNS-over-HTTPS (DoH) (伪装为 443 网页流量，兼容性极强)
   server-https https://cloudflare-dns.com/dns-query

   5. DNS-over-QUIC (DoQ) (新一代 UDP+TLS 协议，极速抗丢包)
   server-quic dns.adguard-dns.com:853

   6. DNS-over-HTTP/3 (DoH3) (最高性能并发加密协议)
   server-h3 h3://dns.alidns.com/dns-query
   ```
   
   常用附加参数说明：
   -group [name]：将服务器加入指定分组，可配合 nameserver 实现域名分流。
   -exclude-default-group：将该服务器从默认测速组中排除（防泄露必备）。
   
## 2.2 本地代理防污染隧道（核心特性）

SmartDNS Edge 支持通过本地代理客户端（如 Clash、Xray）安全地向海外 DNS 发起查询，彻底解决 SNI 阻断和 DNS 污染问题。

   ```Shell
   1. 注册本地 SOCKS5 代理客户端（格式支持用户名密码认证）
   proxy-server socks5://user:pass@127.0.0.1:1080 -name local-clash

   2. 配置海外加密上游，并强制其走 local-clash 代理通道
   server-tls 8.8.8.8 -group overseas -proxy local-clash -exclude-default-group
   server-https https://cloudflare-dns.com/dns-query -group overseas -proxy local-clash -exclude-default-group

   3. 将海外敏感域名路由至上述安全组
   nameserver /google.com/overseas
   nameserver /github.com/overseas
   ```
   
## 2.3 引导 DNS (Bootstrap DNS)

当您的上游 DNS 配置为域名形式（如 https://cloudflare-dns.com/dns-query）时，程序必须先解析该域名才能建立连接。专门用于解析此类上游服务器域名的 DNS 称为 Bootstrap DNS。

   ```Shell
   方案 A：直接标记某 IP 服务器为 bootstrap-dns
   server 223.5.5.5 -bootstrap-dns

   方案 B：为特定上游域名指定解析组
   server 114.114.114.114 -group bootstrap
   nameserver /cloudflare-dns.com/bootstrap
   ```
   
## 2.4 后备 DNS (Fallback DNS)

当主用 DNS 全部失效、超时或不响应时，Fallback DNS 将作为最后的防线提供查询服务。这非常适合用来节约按流量计费的昂贵节点。
 
   ```Shell
   设置指定 DNS 为后备服务器
   server 8.8.4.4 -fallback
   ```
