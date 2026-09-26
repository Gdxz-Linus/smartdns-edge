# 7. 智能分流与客户端控制

SmartDNS Edge 提供多维度的智能分流能力。您不仅可以按域名进行国内外线路解析分流，还可以根据局域网中不同设备的 IP 或 MAC 地址下发完全独立的网络规则（如家长控制）。

## 7.1 域名分流与绑定组 (Domain Split-Routing)

通过将上游服务器划分到不同的组（Group），并指定特定后缀的域名去特定的组查询，可以完美实现“国内域名走国内 DNS，国外域名走海外 DNS”。

   1. 配置国内与海外的独立解析组：

```shell
# 配置国内上游，加入 'cn' 组，并将其从默认全局组中排除
server 119.29.29.29 -group cn -exclude-default-group

# 配置海外上游，加入 'overseas' 组，并将其从默认全局组中排除
server-tls 8.8.8.8:853 -group overseas -exclude-default-group

# 将指定域名的解析请求强行路由至对应分组
nameserver /.cn/cn
nameserver /google.com/overseas
```

   2. 您还可以直接通过监听不同的端口来实现物理级的粗粒度分流（如配合软路由插件使用）：

```shell
# 发送到 7053 端口的查询请求，全部强制使用 overseas 组解析
bind :7053 -group overseas

# 发送到 8053 端口的查询请求，全部强制使用 cn 组解析
bind :8053 -group cn
```

## 7.2 规则组配置 (Rule Groups)

当针对某一类场景需要设置大量包含关系时，可以使用 `group-begin` 和 `group-end` 来圈定一个独立的作用域，使配置极其清晰。

   创建一个独立的规则作用域，并为其指定触发条件：

```shell
# 开始定义名为 'rule-guest' 的访客规则组，且不继承全局默认配置
group-begin rule-guest -inherit none

# 当客户端 IP 是 192.168.1.100 时，触发此组规则
group-match -client-ip 192.168.1.100

# 访客组屏蔽所有视频网站
address /youtube.com/#

# 访客组统一用 600 秒 TTL
rr-ttl 600

group-end
```

> ⚠️ **在组里写 `server` 不会"只对该组生效"** —— 它会成为**全局**上游。
> 要按组指定上游，请把上游声明成组，再用 `nameserver` 指过去：
>
> ```shell
> server 223.5.5.5 -group guest -exclude-default-group
> group-begin rule-guest
> nameserver /a.com/guest
> group-end
> ```
>
> ⚠️ 只有[7.2.1](#721-在规则组里设置参数)列出的参数才有组级写法；
> 其它参数（如 `cache-size`）写进组里会被忽略并提示，不会改变全局配置。

### 7.2.1 在规则组里设置参数

规则组内除了**规则**（`server`、`address`、`nameserver` 等），还能写**开关类参数**，
实现"同一个域名、不同设备用不同策略"。

支持写进规则组的参数（共 20 个）：

| 层级 | 参数 |
|---|---|
| bind > 组 > 全局 | `force-no-CNAME`、`force-AAAA-SOA` |
| 域名规则 > 组 > 全局 | `rr-ttl`、`speed-check-mode`、`response-mode`、`dualstack-ip-selection` |
| 组 > 全局 | `rr-ttl-min`、`rr-ttl-max`、`rr-ttl-reply-max`、`local-ttl`、`max-reply-ip-num`、`dualstack-ip-allow-force-AAAA`、`dualstack-ip-selection-threshold`、`dns64`、`prefetch-domain`、`serve-expired`、`serve-expired-reply-ttl`、`ipset-timeout`、`nftset-timeout` |
| 客户端自带 > 域名规则 > 组 > 全局 | `edns-client-subnet` |

**层级**一列表示能在哪几层写，越靠前优先级越高。

上面这些之外的参数（如 `cache-size`、`max-connections`）**只能写在全局**；
写进规则组时会提示该行被忽略，不会改变全局配置。

```shell
group-begin office

# 这个组的解析结果 TTL 统一为 600
rr-ttl 600

# 这个组不做测速（比如走代理隧道的域名）
speed-check-mode none

# 这个组不返回 CNAME
force-no-CNAME yes

group-end
```

`serve-expired-ttl` 与 `serve-expired-prefetch-time` **不能**写进规则组，写了会报错。
它们是进程级策略，只由后台任务使用、不体现在应答里。

#### 几点说明

**`rr-ttl-min` / `rr-ttl-max` 跟着本组的 `rr-ttl` 走**。组里写了 `rr-ttl`，本组的 min/max 就取它，
不会去取全局的值：

```shell
rr-ttl-min 500

group-begin office
rr-ttl 111        # 本组的 rr-ttl-min / rr-ttl-max 都是 111，不是 500
group-end
```

**`prefetch-domain` / `serve-expired` 只影响这次查询**，不会改动后台任务。
例如某个组写 `prefetch-domain no`，只让这个组的查询不再安排预取，
不会关闭整个程序的预取功能，其它组照旧。

**优先级**：同一个参数写在多个地方时，**域名规则 > 规则组 > 全局**。
`force-no-CNAME`、`force-AAAA-SOA` 还支持监听级，即 **bind > 规则组 > 全局**。

嵌套组同样规则：本组写了就用本组的，本组没写才从外层继承。

> ⚠️ 组级参数与**缓存**的关系：同一个域名在不同规则组下答案可能不同，
> 系统已把「规则组」纳入缓存区分依据，不同组之间不会串答案。

## 7.3 客户端控制与家长管控 (Client Rules)

SmartDNS Edge 支持根据局域网内请求设备的 IP、IP 集合或 MAC 地址，执行定向的访问控制。

   通过 MAC 地址或 IP 限制特定设备的网络访问行为：

```shell
# 开启 ACL（访问控制列表）支持
acl-enable yes

# 为指定 MAC 地址的设备（如孩子的平板）绑定专用的 'child' 规则组
client-rules 00:11:22:33:44:55 -g child

# 为指定 IP 网段绑定专门的海外解析组
client-rules 192.168.1.10/24 -g overseas
```

## 7.3.1 前面挂了反向代理怎么办（可信代理）

如果 SmartDNS Edge 前面还有一层反向代理（nginx / HAProxy 等），那么**所有客户端在程序看来都是同一个地址** —— 代理的地址。这会带来三个后果：

| 受影响的对方 | 症状 |
|---|---|
| 连接数上限 | 所有设备**共用一个额度**，一台设备占满，全网被拒连 |
| `client-rules` 分组 | 没法按设备做策略（全都归到代理那一条） |
| 管理后台口令试错限流 | 有人故意错几次，管理员也被一起挡住 |

解决办法是**显式告诉程序"这台代理可信"**：

```shell
# 只信任这一台反向代理（也可以写网段：192.168.1.0/24）
trusted-proxy 10.0.0.1

# 可写多行，会累加成一份清单
trusted-proxy 172.16.0.0/12
```

配上之后，**只有来自这些地址的请求**，程序才会去读 `X-Forwarded-For`、按真实客户端归组。

> ⚠️ **它只对 HTTP 类协议有用**（DoH / `bind-http` / 管理后台）。
> 普通 DNS 查询走 **UDP**，报文里**没有"请求头"这种东西**，代理只能做 SNAT，
> 真实来源无从得知 —— 所以 UDP 那条路径上，客户端仍然按代理地址归组。
>
> ⚠️ **它只用于"归组"，不用于"放行"**。
> `X-Forwarded-For` 是客户端自己也能填的普通请求头；如果拿它做 ACL 判定，
> 任何人加一行 `X-Forwarded-For: <白名单地址>` 就**绕过了访问控制**。
> 所以 ACL 的判断始终依据**真实对端地址**（内核给出，无法伪造）。
>
> ⚠️ **不配 = 完全不信任任何代理头**，也就是与以前完全一样。
> 这是一条**安全默认**：宁可让限流不准，也不把安全性交给调用方自报。

## 7.4 局域网主机名解析 (Local Domain & mDNS)

在家庭或办公内网中，记住每台设备的 IP 是非常困难的。开启相关功能后，您可以使用主机名直接访问内网设备（如 NAS、打印机）。

   开启 mDNS 解析与局域网域名后缀：

```shell
# 启用 mDNS 查询，自动解析局域网内其他支持 mDNS 广播的智能设备
mdns-lookup yes

# 设置本地域名后缀。设置后，请求主机名会自动追加该后缀进行查询
local-domain home.lan
```

### 7.4.1 用 DHCP 租约文件解析内网设备（dnsmasq）

如果内网由 dnsmasq（或使用同样租约文件格式的路由器固件）发放 DHCP，可以让程序**直接读它的租约文件**，把每台设备的 IP 与主机名对应起来 —— 不必手工维护 `hosts`。

```shell
# 读 dnsmasq 的 DHCP 租约文件
dnsmasq-lease-file /var/lib/misc/dnsmasq.leases

# 租约文件里的主机名通常只有一段（如 "nas"），
# 这里声明本机的局域网域名后缀；之后 "nas.home.lan" 与 "nas" 都能解析
domain home.lan
```

**两个配置项的分工**：`dnsmasq-lease-file` 指定租约文件路径、开启这项能力；
`domain` 给租约里的短主机名补上本地域名后缀。

> ⚠️ **`domain` 只影响租约文件的解析**，与 `local-domain`（把域名交给 mDNS 组）
> 是两件不同的事，不要混用。
>
> ⚠️ 租约文件会**每 2 秒检查一次变化**，设备加入或离开后无需重启程序。
>
> ⚠️ 查一个**不存在于内网**的名字时，程序不会伪造结果，而是正常向上游查询 ——
> 所以内网主机名与公网域名可以共存，不会互相影响。