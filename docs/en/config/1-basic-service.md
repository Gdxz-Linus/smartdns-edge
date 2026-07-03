# Module 1: Basic Service & Listener Setup

This module covers how to run SmartDNS Edge as a basic DNS gateway, enable encrypted service ports, and harden system security.

## 1.1 Minimal Basic Setup

For a standard DNS service, you only need to configure the listening port and upstream servers. The default parameters are already optimized for home and LAN environments.

   ```shell
   # Listen on standard DNS port 53 for both IPv4 & IPv6
    bind [::]:53

   # Configure low-latency local upstream DNS servers
   server 119.29.29.29
   server 223.5.5.5
   server 114.114.114.114

   # Configure secure DoT/DoQ/DoH3 encrypted upstreams
   server-tls 8.8.8.8:853
   server-quic dns.adguard-dns.com:853
   server-h3 https://dns.alidns.com/dns-query
   ```
   *Note: If no server is specified, the program will automatically read the system's DNS addresses from /etc/resolv.conf.*
   
## 1.2 Enable Encrypted Servers (TCP / DoT / DoH)
In addition to standard UDP, SmartDNS Edge can act as an encrypted DNS server to provide secure queries to clients.

   ``` Shell
   # Enable TCP mode DNS listener
   bind-tcp [::]:53

   # Enable DNS-over-TLS (DoT) server on port 853
   bind-tls [::]:853

   # Enable DNS-over-HTTPS (DoH) server on port 443
   bind-https [::]:443
   
   # cConfiguring SSL Certificates (for DoT/DoH):
   # When enabling encrypted services, you need to provide valid SSL certificate and key files.
   bind-cert-file /etc/smartdns/cert.pem
   bind-cert-key-file /etc/smartdns/key.pem
   ```   
   Use bind-cert-key-pass if your key requires a password
   *Tip: If encrypted services are enabled but no certificate is specified, SmartDNS Edge will automatically generate a self-signed root and server certificate chain.*
   
## 1.3 Additional Flags: Secondary DNS Service
The bind parameter supports advanced flags to create specialized "Secondary DNS Servers" (e.g., dedicated clean resolution for specific domains).

   ```Shell
   # Bind to another port, disable speed checks, caching, and bypass specific filtering rules
   bind :6053 -group public -no-rule-addr -no-speed-check -no-cache
   ```
   
## 1.4 Security Hardening & Audit Logs
As critical network infrastructure, you can harden security by dropping root privileges, binding to specific network interfaces, and enabling audit logs.

   ```Shell
   # Drop privileges: run as a non-root user (e.g. nobody) to prevent privilege escalation
   user nobody

   # Bind to a specific interface: serve only on LAN (e.g. eth0) to prevent public internet abuse
   bind [::]:53@eth0

   # Enable audit logs: comprehensively record every DNS query requested by clients
   audit-enable yes
   audit-num 16
   audit-size 16M
   audit-file /var/log/smartdns/smartdns-audit.log
   ```
