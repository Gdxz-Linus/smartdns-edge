# 8 Advanced Firewall Integration (Transparent Proxy)

SmartDNS Edge supports deep integration with Linux kernel firewalls (iptables/nftables) by dynamically injecting resolved target IPs into system `ipset` or `nftset` collections. Combined with a transparent proxy program (like TPROXY or REDIRECT) on a soft-router, this achieves the ultimate split-routing architecture: "direct connection for domestic traffic, proxy for overseas."

## 8.1 IPSet Configuration (For iptables)

By automatically storing the resolution results of specified domains into an ipset, you can let the iptables firewall intercept and route the traffic for these IPs at the kernel level.

```shell
# Globally configure ipset: put all unmatched domain results into the 'public' ipset
ipset public

# Put the resolution results of specific domains into a specified ipset
ipset /google.com/overseas_set

# Store IPv4 and IPv6 results into separate sets (differentiated by #4 and #6)
ipset /youtube.com/#4:dns_v4,#6:dns_v6
```

## 8.2 NftSet Configuration (For nftables)

nftables is the modern, high-performance successor to iptables. Due to underlying nft limitations, IPv4 (inet/ip) and IPv6 (inet/ip6) addresses must be stored in completely separate sets.

```shell
# Specify domains and assign them to different nftset collections
# Format: #Protocol:family#table#set
nftset /example.com/#4:inet#router#dns4_set,#6:inet#router#dns6_set
```

## 8.3 Set Timeout

To prevent firewall sets from accumulating too many stale IPs and degrading routing performance, you can enable the set timeout feature.

```shell
# Enable automatic timeout cleanup for ipset or nftset
# (entry expiry = 3x the answer TTL)
ipset-timeout yes
nftset-timeout yes
```

> ⚠️ **About `ipset-no-speed` / `nftset-no-speed`**: these are **boolean switches**
> (`yes` / `no`) and take **no set name**.
>
> Their purpose is to control whether IPs that fail the speed check are still written
> to the set. This program **always writes every resolved address** (i.e. equivalent to
> on), so these two lines **change nothing either way**.
>
> They are still **accepted** (you will not get an "unrecognised config line" warning),
> but startup prints a notice saying they are unnecessary — so that configuring them
> does not leave you wondering whether they took effect.

```shell
# These two lines can stay as they are;
# this program always writes all addresses, so they change nothing
ipset-no-speed yes
nftset-no-speed yes
```