# Module 5: Domain Control & Ad Blocking

SmartDNS Edge offers extremely flexible domain management capabilities. You can easily implement domain redirection, granular rule control, and highly efficient ad-blocking supporting millions of rules.

## 5.1 Domain IP & CNAME Override

You can forcefully resolve specific domains to designated IP addresses or aliases. This is typically used for intranet service overrides or specific DNS hijacking.

   1. Map a domain to single or multiple IPs (multiple IPs will be returned randomly):

    ```shell
    address /example.com/1.2.3.4
    address /example.com/1.2.3.4,5.6.7.8
    ```

   2. Configure CNAME alias mapping:

    ```shell
    cname /www.example.com/cdn.example.com
    ```

   3. Support for prefix wildcard and exact main-domain matching:

    ```shell
    address /*-a.example.com/1.2.3.4  # Prefix wildcard
    address /-.example.com/1.2.3.4   # Exact main-domain match (excludes subdomains)
    ```

## 5.2 Domain Rules & Advanced Control

To conveniently set multiple rules for the same domain, `domain-rules` allows you to apply various attributes simultaneously.

   Uniformly configure a dedicated upstream group, speed-check mode, and cache policy for a domain:

    ```shell
    domain-rules /example.com/ -nameserver overseas -speed-check-mode none -no-cache
    ```

## 5.3 Ad Blocking in Practice

By making advertising or tracking domains directly return an empty SOA record, you achieve the most efficient and zero-latency ad blocking.

   Block all queries for a specific domain, or only block its IPv6 resolution:

    ```shell
    1. Block all resolutions for the domain (Returns SOA)
    address /ad.example.com/#

    2. Only block IPv6 resolution for the domain
    address /ad.example.com/#6

    3. Ignore interception (Whitelist exception for a falsely blocked subdomain)
    address /pass.ad.example.com/-
    ```

## 5.4 Domain Sets & Remote Rule Downloading

For massive ad-blocking or split-routing domain lists, writing them directly in the config file is extremely bloated. `domain-set` allows you to manage them via external list files.

   **SmartDNS Edge Exclusive Feature**: Natively supports the `-proxy` flag to tunnel through your local proxy client, fetching and updating huge remote ad-blocking rules (like Anti-AD with 100,000+ lines) instantly from GitHub or other blocked sites!

    ```shell
     1. Define your local SOCKS5 proxy client
    proxy-server socks5://127.0.0.1:1080 -name clash

     2. Create a domain set named 'ad-list' and securely fetch the real-time updated rules via the proxy
    domain-set -name ad-list -type list -file https://anti-ad.net/anti-ad-for-smartdns.conf -proxy clash

     3. Apply the 100,000+ domains from the set to the ad-blocking rule with one click
    address /domain-set:ad-list/#
    ```