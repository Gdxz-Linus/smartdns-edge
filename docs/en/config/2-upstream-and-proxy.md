---
hide:
  - toc
---


# Module 2: Upstream DNS & Proxy Tunnels

SmartDNS Edge supports a variety of mainstream and cutting-edge DNS query protocols, and deeply integrates local proxy capabilities. This module guides you on configuring upstream servers, anti-pollution proxy tunnels, as well as fallback and bootstrap resolution.

## 2.1 Configuring Upstream DNS (UDP/TCP/Encrypted)

You can mix and match different protocols based on your network environment. Encrypted protocols (DoT/DoH/DoQ/DoH3) effectively prevent DNS hijacking and eavesdropping.

   ```shell
   1. Standard UDP query (Fastest, but vulnerable to hijacking)
   server 119.29.29.29 -group cn
   server 8.8.8.8 -group overseas

   2. TCP query (Reliable fallback when UDP is blocked)
   server-tcp 223.5.5.5

   3. DNS-over-TLS (DoT) (Secure encryption using port 853)
   server-tls 1.1.1.1:853
   Specify TLS SNI hostname for certificate verification
   server-tls 8.8.8.8:853 -host-name dns.google

   4. DNS-over-HTTPS (DoH) (Disguised as port 443 web traffic, highly compatible)
   server-https https://cloudflare-dns.com/dns-query

   5. DNS-over-QUIC (DoQ) (Next-gen UDP+TLS protocol, excellent in lossy links)
   server-quic dns.adguard-dns.com:853

   6. DNS-over-HTTP/3 (DoH3) (Highest performance concurrent encrypted protocol)
   server-h3 h3://dns.alidns.com/dns-query
   ```
   
   Common Flag Descriptions:
   
   -group [name]: Assigns the server to a specific group. Used with nameserver for split-routing.
   
   -exclude-default-group: Excludes the server from the default speed-testing pool (essential for preventing DNS leaks).
   
## 2.2 Local Proxy Anti-Pollution Tunnels (Core Feature)

SmartDNS Edge supports routing overseas DNS queries securely through local proxy clients (such as Clash or Xray), completely resolving SNI blocking and DNS pollution issues.

   ```Shell
   1. Register a local SOCKS5 proxy client (supports username/password authentication)
   proxy-server socks5://user:pass@127.0.0.1:1080 -name local-clash

   2. Configure overseas encrypted upstreams and force them through the local-clash proxy
   server-tls 8.8.8.8 -group overseas -proxy local-clash -exclude-default-group
   server-https https://cloudflare-dns.com/dns-query -group overseas -proxy local-clash -exclude-default-group

   3. Route sensitive overseas domains to the secure group above
   nameserver /google.com/overseas
   nameserver /github.com/overseas
   ```
   
## 2.3 Bootstrap DNS

When your upstream DNS is configured as a domain name (e.g., https://cloudflare-dns.com/dns-query), the program must first resolve that domain before it can establish a connection. The DNS dedicated to resolving such upstream server domains is called Bootstrap DNS.

   ```Shell
   # Method A: Directly mark an IP server as bootstrap-dns
   server 223.5.5.5 -bootstrap-dns

   # Method B: Specify a resolution group for a specific upstream domain
   server 114.114.114.114 -group bootstrap
   nameserver /cloudflare-dns.com/bootstrap
   ```
   
## 2.4 Fallback DNS

When all primary DNS servers fail, timeout, or stop responding, the Fallback DNS acts as the last line of defense to provide query services. This is highly useful for saving data on expensive pay-per-traffic nodes.

   ```Shell
   Set the specified DNS as a fallback server
   server 8.8.4.4 -fallback
   ```
   
 ---