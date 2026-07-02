---
hide:
  - toc
---

# 模块 1：基础服务与监听配置

本模块涵盖了如何将 SmartDNS Edge 作为基础 DNS 网关运行，以及如何开启加密服务端口和加固系统安全。

## 1.1 基础极速解析（最简入门）

作为最基本的 DNS 服务，您只需要配置监听端口和上游服务器即可。其他参数保持默认，对于家庭和局域网已经是最佳配置。

   ```shell
   # 监听本网 IPv4 & IPv6 的标准 DNS 53 端口
   bind [::]:53

   # 配置高可用国内主流公共上游 DNS 服务器
   server 119.29.29.29
   server 223.5.5.5
   server 114.114.114.114

   # 配置安全的海外 DoT/DoQ/DoH3 上游加密解析服务
   server-tls 8.8.8.8:853
   server-quic dns.adguard-dns.com:853
   server-h3 https://dns.alidns.com/dns-query
   ```
   
   注意：如果不指定 server，程序将会自动读取系统 /etc/resolv.conf 中的 DNS 地址。

## 1.2 开启多服务端模式 (TCP / DoT / DoH)

SmartDNS Edge 除了能够作为标准的 UDP DNS 服务端，还可以作为加密 DNS 服务端对外提供安全查询。

   ```Shell
   # 开启 TCP 模式 DNS 监听
   bind-tcp [::]:53

   # 开启 DNS-over-TLS (DoT) 服务端，监听 853 端口
   bind-tls [::]:853

   # 开启 DNS-over-HTTPS (DoH) 服务端，监听 443 端口
   bind-https [::]:443
   
   # 配置 SSL 证书（适用于 DoT/DoH）：
   # 启用加密服务时，需要提供有效的 SSL 证书与密钥文件。
   bind-cert-file /etc/smartdns/cert.pem
   bind-cert-key-file /etc/smartdns/key.pem
   ```
   
   如果密钥有密码，可通过 bind-cert-key-pass 指定
   
   提示：若开启加密服务且未指定证书，SmartDNS Edge 将自动生成自签名的根证书和服务器证书链。
   
## 1.3 附加属性：第二 DNS 服务

bind 参数支持高级附加属性，可用于建立特殊的“第二 DNS 服务器”（如专用于特定域名的纯净解析）。

   ```Shell
   # 绑定另一个端口，并关闭测速、缓存及屏蔽特定的过滤规则
   bind :6053 -group public -no-rule-addr -no-speed-check -no-cache
   ```
   
## 1.4 安全加固与审计日志

作为面向公网或局域网的基础设施，可以通过降权运行、绑定特定网卡以及开启审计来加固安全防线。

   ```Shell
   # 降权运行：使用非 root 用户 (如 nobody) 运行进程防止越权
   user nobody

   # 绑定特定网口：仅在局域网 eth0 接口上提供服务，防止公网滥用
   bind [::]:53@eth0

   # 开启审计日志：详细记录客户端的每一次 DNS 查询请求
   audit-enable yes
   audit-num 16
   audit-size 16M
   audit-file /var/log/smartdns/smartdns-audit.log
   ```

---

