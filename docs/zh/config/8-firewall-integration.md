# 8. 高级防火墙联动 (透明代理分流)

SmartDNS Edge 支持与 Linux 内核防火墙（iptables / nftables）深度联动，将解析到的目标 IP 动态注入至系统的 ipset 或 nftset 集合中。配合软路由上的透明代理程序（如 TPROXY 或 REDIRECT），可完美实现“国内直连、海外走代理”的究极白名单分流架构。

## 8.1 IPSet 配置 (适用于 iptables)

通过将指定域名的解析结果自动存入 ipset，您可以让 iptables 防火墙在底层接管这些 IP 的流量分发。

```shell
# 全局配置 ipset，将所有无规则的域名结果放入名为 public 的 ipset 集合中
ipset public

# 将特定域名的解析结果放入指定的 ipset
ipset /google.com/overseas_set

# 针对 IPv4 和 IPv6 分别存入不同的集合（使用 #4 和 #6 区分）
ipset /youtube.com/#4:dns_v4,#6:dns_v6
```

## 8.2 NftSet 配置 (适用于 nftables)

nftables 是 iptables 的现代替代品，性能更强。由于 nft 的底层限制，IPv4 (inet/ip) 和 IPv6 (inet/ip6) 的地址必须分开存放在不同的集合中。

```shell
# 指定域名并分别归入不同的 nftset 集合
# 格式：#协议:family#table#set
nftset /example.com/#4:inet#router#dns4_set,#6:inet#router#dns6_set
```

## 8.3 集合超时

为防止防火墙集合中堆积过多陈旧的 IP 导致路由性能下降，可以开启集合超时清理功能。

```shell
# 开启 ipset 或 nftset 的自动超时清理（条目过期时间 = 应答 TTL 的 3 倍）
ipset-timeout yes
nftset-timeout yes
```

> ⚠️ **关于 `ipset-no-speed` / `nftset-no-speed`**：这两个是**布尔开关**（`yes` / `no`），
> **不带集合名**。
>
> 它们的作用是"**测速失败的 IP 是否也写进集合**"，而本程序**一律把所有解析出的地址
> 都写进集合**（已等同开启），所以这两行**配不配都一样**。
>
> 本程序仍然**认得**这两行（不会报"未识别配置行"），但会在启动时提示它们无需配置 ——
> 免得你配了之后怀疑"是不是没生效"。

```shell
# 这两行可以原样保留，不必删；
# 本程序一律写入全部地址，它们不会改变行为
ipset-no-speed yes
nftset-no-speed yes
```