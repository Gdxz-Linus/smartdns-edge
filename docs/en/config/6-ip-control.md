# 6 IP Control & CDN Acceleration

SmartDNS Edge provides robust IP-level routing and filtering capabilities. You can block ISP hijacked IPs, leverage aliasing for massive CDN acceleration, and optimize cross-subnet routing via ECS.

## 6.1 Bogus IP Filtering & Black/Whitelists

When a website does not exist, some unscrupulous ISPs will return a specific IP address to hijack and redirect you to their ad-filled 404 pages. You can use bogus IP filtering to correct this and return a clean SOA record instead.

   1. Set bogus IP filters and ignore specific dirty IPs:

    ```shell
    Treat the ISP's hijacked ad IP subnet as bogus
    bogus-nxdomain 1.2.3.4/24

    Directly drop/ignore a specific dirty IP returned by the upstream
    ignore-ip 4.5.6.7
    ```

   2. Apply strict pass or drop policies to upstream results using blacklists and whitelists:

    ```shell
    Blacklist: If the returned IP is in this range, immediately discard the result
    blacklist-ip 192.168.1.0/24

    Whitelist: Only accept IPs within this specified range; discard all others
    whitelist-ip 10.0.0.0/8
    ```

## 6.2 IP Aliasing & CDN Acceleration

CDN providers like Cloudflare use Anycast routing. You can use speed-testing tools to find the single "super node IP" with the lowest latency from your local network, and forcefully map the entire Cloudflare subnet to this node. This massively accelerates access to millions of websites hosted on that CDN.

   Force map broad CDN subnets to your tested fastest node IP:

    ```shell
    Map two large Cloudflare subnets entirely to your fastest tested node (e.g., 104.16.0.1)
    ip-alias 104.16.0.0/13 104.16.0.1
    ip-alias 172.64.0.0/13 104.16.0.1
    ```

## 6.3 IP Sets & Remote Rule Downloading

Similar to domain sets, for massive domestic/overseas IP routing tables (like chnroute), you can use `ip-set` combined with your proxy tunnel for centralized management and fast downloading.

   Download and apply large-scale IP rules using a proxy tunnel:

    ```shell
    # Create an IP set and force it to fetch the remote IP list via the local 'clash' proxy
    ip-set -name cn-ip -type list -file https://example.com/china_ip_list.txt -proxy clash

    # Apply the set to a rule (e.g., whitelist these IPs for direct connection)
    ip-rules ip-set:cn-ip -whitelist-ip
    ```

## 6.4 EDNS Client Subnet (ECS)

EDNS Client Subnet allows SmartDNS Edge to carry your specified subnet IP info when querying upstream servers. This is particularly crucial when querying overseas DNS via a proxy, ensuring the upstream CDN returns node IPs optimized for your physical location, rather than the proxy server's location.

   Configure the client subnet globally, or specifically for an upstream server:

    ```shell
    # Set ECS globally (exposing a broad subnet, like /24, to get the most accurate CDN resolution)
    edns-client-subnet 1.2.3.4/24

    # Send specific local subnet info only to a specific upstream via proxy, correcting CDN dispatch deviations
    server 8.8.8.8 -proxy clash -subnet 1.2.3.4/24
    ```