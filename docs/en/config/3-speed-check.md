# Module 3: Speed Check & IP Selection
SmartDNS Edge can concurrently query multiple upstream DNS servers and perform real-network speed tests on the returned IPs, ensuring clients always connect to the server with the lowest physical latency.

## 3.1 Speed Check Mode
By default, the program uses ping, tcp:80, and tcp:443 for comprehensive speed testing. You can adjust the global speed check mode based on your network environment, or disable it for specific domains.
Global speed check mode (defaults to ping, falls back to tcp on timeout)

Shell
speed-check-mode ping,tcp:80,tcp:443
Only use ping for speed checking or disable global speed checking

Shell
speed-check-mode ping
speed-check-mode none
Disable speed check for specific domains going through proxies (prevents mismatch between local ping and actual proxy exit latency)

Shell
domain-rules /google.com/ -speed-check-mode none

## 3.2 First Query Response Mode
The response mode determines how SmartDNS Edge returns speed-test results to the client on the first query when there is no cache.
First-ping response mode (Default & Recommended)
Shortest combination of DNS query wait time + Ping latency. Balances initial load and connection speed.

Shell
response-mode first-ping
Fastest-ip mode
Forces waiting for all IP speed tests to finish, returning the absolute lowest latency IP (Longer DNS wait time).

Shell
response-mode fastest-ip
Fastest-response mode
Shortest DNS query wait time. Ignores Ping latency and returns whichever DNS responds first.

Shell
response-mode fastest-response
Set response mode for a specific domain

Shell
domain-rules /example.com/ -r first-ping

## 3.3 Dual-stack Smart Selection
In dual-stack networks (IPv4 + IPv6), IPv6 routing for some websites might be sub-optimal and slower than IPv4. With dual-stack selection enabled, the program tests both A and AAAA records concurrently and prioritizes the faster IP.
Enable dual-stack smart speed selection (Enabled by default)

Shell
dualstack-ip-selection yes
Set the selection threshold (in milliseconds)
Intervention only occurs if the speed difference between the two IPs is greater than this value.

Shell
dualstack-ip-selection-threshold 10

## 3.4 Blocking IPv6 & DNS64
If your network lacks native IPv6, or if specific domains suffer from severe IPv6 lag, you can force block IPv6 resolution by returning empty SOA records.
Globally force AAAA queries to return empty SOA (Completely block IPv6)

Shell
force-AAAA-SOA yes
Disable IPv6 resolution only for specific domains

Shell
address /example.com/#6
Add an exception to allow IPv6 for a specific domain while globally blocked

Shell
address /ipv6-only.site.com/-6
Configure DNS64 translation
If you are in an IPv6-only network, SmartDNS Edge natively supports DNS64, which dynamically synthesizes pure IPv4 addresses into IPv6 addresses (Note: recommended to disable dual-stack selection in pure IPv6 environments).

Shell
dns64 64:ff9b::/96