# 7 Smart Split-Routing & Client Control

SmartDNS Edge offers multi-dimensional intelligent split-routing. You can selectively route queries based on domain names or enforce strictly independent network rules (such as parental controls) based on the IP or MAC addresses of different devices in your LAN.

## 7.1 Domain Split-Routing & Groups

By grouping upstream servers and mapping specific domain suffixes to those groups, you can easily achieve perfect split routing (e.g., domestic domains via local DNS, overseas domains via encrypted offshore DNS).

   1. Configure independent resolution groups for domestic and overseas traffic:

```shell
# Configure local upstream, add to 'cn' group, and exclude from the default global pool
server 119.29.29.29 -group cn -exclude-default-group

# Configure overseas upstream, add to 'overseas' group, and exclude from the default pool
server-tls 8.8.8.8:853 -group overseas -exclude-default-group

# Forcefully route specific domains to their corresponding groups
nameserver /.cn/cn
nameserver /google.com/overseas
```

   2. You can also achieve coarse-grained port-based routing (often used with soft-router plugins):

```shell
# All queries sent to port 7053 will exclusively use the 'overseas' group
bind :7053 -group overseas

# All queries sent to port 8053 will exclusively use the 'cn' group
bind :8053 -group cn
```

## 7.2 Rule Groups Configuration

When defining a large set of conditions for a specific scenario, you can use `group-begin` and `group-end` to encapsulate an independent scope, making the configuration highly readable.

   Create a standalone rule scope and specify its trigger conditions:

```shell
# Begin a rule group named 'rule-guest' without inheriting global defaults
group-begin rule-guest -inherit none

# Trigger this group if the client IP is 192.168.1.100
group-match -client-ip 192.168.1.100

# Block all video sites for guests
address /youtube.com/#

# Uniform 600-second TTL for guests
rr-ttl 600

group-end
```

> ⚠️ **Writing `server` inside a group does not scope it to that group** — it becomes a
> **global** upstream. To point a group at particular upstreams, declare them as a server group
> and reference it with `nameserver`:
>
> ```shell
> server 223.5.5.5 -group guest -exclude-default-group
> group-begin rule-guest
> nameserver /a.com/guest
> group-end
> ```
>
> ⚠️ Only the options listed in [7.2.1](#721-setting-parameters-inside-a-rule-group) have a
> rule-group form; other options (e.g. `cache-size`) are ignored with a notice when written inside
> a group, and the global config is left unchanged.

### 7.2.1 Setting Parameters Inside a Rule Group

A rule group can hold not only **rules** (`server`, `address`, `nameserver`, ...) but also
**switch-style parameters**, so that the same domain can follow different policies per device.

Parameters accepted inside a rule group (20 in total):

| Levels | Parameters |
|---|---|
| bind > group > global | `force-no-CNAME`, `force-AAAA-SOA` |
| domain rule > group > global | `rr-ttl`, `speed-check-mode`, `response-mode`, `dualstack-ip-selection` |
| group > global | `rr-ttl-min`, `rr-ttl-max`, `rr-ttl-reply-max`, `local-ttl`, `max-reply-ip-num`, `dualstack-ip-allow-force-AAAA`, `dualstack-ip-selection-threshold`, `dns64`, `prefetch-domain`, `serve-expired`, `serve-expired-reply-ttl`, `ipset-timeout`, `nftset-timeout` |
| client-supplied > domain rule > group > global | `edns-client-subnet` |

The **Levels** column shows where a parameter can be written; earlier wins.

Parameters other than those (e.g. `cache-size`, `max-connections`) **can only be written globally**;
written inside a rule group the line is reported as ignored and the global config is not changed.

```shell
group-begin office

# uniform TTL of 600 for this group
rr-ttl 600

# no speed check in this group (e.g. domains routed through a proxy)
speed-check-mode none

# never return CNAME in this group
force-no-CNAME yes

group-end
```

`serve-expired-ttl` and `serve-expired-prefetch-time` **cannot** be written inside a rule group;
doing so produces an error. They are process-wide policies used only by background tasks and never
appear in a reply.

#### Notes

**`rr-ttl-min` / `rr-ttl-max` follow this group's `rr-ttl`.** If the group writes `rr-ttl`, the
group's min/max take that value rather than the global one:

```shell
rr-ttl-min 500

group-begin office
rr-ttl 111        # this group's rr-ttl-min / rr-ttl-max are 111, not 500
group-end
```

**`prefetch-domain` / `serve-expired` only affect this one query** — the background task is not
changed. A group writing `prefetch-domain no` only stops that group's queries from being scheduled;
it does not switch off prefetch for the whole program.

**Priority**: when the same parameter is written in several places, **domain rule > rule group >
global**. `force-no-CNAME` and `force-AAAA-SOA` also support listener level, i.e.
**bind > rule group > global**.

Nested groups follow the same rule: a value set in the inner group wins, and only unset values are
inherited from the outer group.

> ⚠️ Group parameters and the **cache**: the same domain may have different answers in
> different rule groups, so the rule group is already part of the cache key — groups never
> borrow each other's answers.

## 7.3 Client Control & Parental Control

SmartDNS Edge supports targeted access control based on the IP, IP sets, or MAC addresses of requesting devices on your local network.

   Restrict network access behavior for specific devices via MAC or IP:

```shell
# Enable Access Control List (ACL) support
acl-enable yes

# Bind a dedicated 'child' rule group to a specific MAC address (e.g., child's tablet)
client-rules 00:11:22:33:44:55 -g child

# Bind a specific IP subnet to the overseas resolution group
client-rules 192.168.1.10/24 -g overseas
```

## 7.3.1 Behind a Reverse Proxy (Trusted Proxy)

If a reverse proxy (nginx / HAProxy, etc.) sits in front of SmartDNS Edge, then **every client looks like the same address** to the program — the proxy's address. That has three consequences:

| Affected area | Symptom |
|---|---|
| Connection cap | All devices **share one quota**; one device exhausting it gets everyone refused |
| `client-rules` grouping | Cannot apply per-device policy (everything falls into the proxy's entry) |
| Console token-throttling | Someone deliberately failing a few times locks the administrator out too |

The fix is to **explicitly declare that proxy trustworthy**:

```shell
# Trust this one reverse proxy (a CIDR works too: 192.168.1.0/24)
trusted-proxy 10.0.0.1

# Multiple lines accumulate into one list
trusted-proxy 172.16.0.0/12
```

After that, **only requests arriving from those addresses** have their `X-Forwarded-For` read and are grouped by the real client.

> ⚠️ **It only helps for HTTP-based protocols** (DoH / `bind-http` / the console).
> Plain DNS runs over **UDP**, whose packets have **no such thing as a "request header"**;
> a proxy can only SNAT, so the real source is unknowable — on that path clients are
> still grouped by the proxy address.
>
> ⚠️ **It is used for grouping only, never for allow/deny**.
> `X-Forwarded-For` is an ordinary header the client itself can set; using it for ACL
> would let anyone add `X-Forwarded-For: <a whitelisted address>` and **bypass access
> control**. ACL decisions always use the **real peer address** (supplied by the kernel,
> which cannot be forged).
>
> ⚠️ **Unset = no proxy header is trusted at all**, i.e. exactly the previous behaviour.
> That is a deliberate **safe default**: better to have imprecise rate limiting than to
> hand security decisions to something the caller reports about itself.

## 7.4 Local Hostname Resolution (Local Domain & mDNS)

Remembering IP addresses for every device in a home or office intranet is tedious. By enabling local resolution features, you can access LAN devices (like NAS or printers) directly via their hostnames.

   Enable mDNS resolution and set a local domain suffix:

```shell
# Enable mDNS lookup to automatically resolve other smart devices broadcasting on the LAN
mdns-lookup yes

# Set the local domain suffix. Requests for plain hostnames will have this suffix appended
local-domain home.lan
```

### 7.4.1 Resolving LAN devices from a DHCP lease file (dnsmasq)

If dnsmasq (or a router firmware using the same lease-file format) hands out DHCP leases on your LAN, the program can **read its lease file directly** and map every device's IP to its hostname — no hand-maintained `hosts` file needed.

```shell
# Read the dnsmasq DHCP lease file
dnsmasq-lease-file /var/lib/misc/dnsmasq.leases

# Hostnames in the lease file are usually a single label (e.g. "nas"), so
# declare this machine's LAN domain suffix; afterwards both "nas.home.lan"
# and "nas" resolve
domain home.lan
```

**How the two options divide the work**: `dnsmasq-lease-file` points at the lease file and turns
this capability on; `domain` appends the LAN domain suffix to the short hostnames in it.

> ⚠️ **`domain` affects lease-file resolution only** — it is not the same thing as
> `local-domain` (which hands a domain to the mDNS group). Do not mix them up.
>
> ⚠️ The lease file is **re-checked for changes every 2 seconds**, so devices joining
> or leaving are picked up without restarting the program.
>
> ⚠️ Looking up a name that is **not** on the LAN does not fabricate a result — the
> query proceeds upstream as usual, so LAN hostnames and public domains coexist.