# 模块 6：IP 控制与 CDN 加速

SmartDNS Edge 提供强大的 IP 级路由和过滤控制能力。您可以屏蔽网络运营商的劫持 IP、利用别名技术实现全球 CDN 的降维加速，以及通过 ECS 优化跨网段访问。

## 6.1 假冒 IP 过滤与黑白名单 (Bogus IP & Black/Whitelists)

当网站不存在时，某些不良网络运营商（ISP）会固定返回一个特定的 IP 地址，强行将您重定向到他们的广告 404 页面。您可以通过假冒 IP 过滤将其直接纠正为 SOA 记录（即干净的拦截）。

   1. 设置假冒 IP 过滤与忽略特定 IP：

    ```shell
    # 将运营商劫持的固定广告 IP 设置为假冒 IP
    bogus-nxdomain 1.2.3.4/24

    # 直接丢弃/忽略上游返回的某个特定脏 IP
    ignore-ip 4.5.6.7
    ```

   2. 利用黑白名单对上游解析结果进行强制放行或阻断：

    ```shell
    # 黑名单：如果上游返回的 IP 在此网段内，则直接丢弃该结果
    blacklist-ip 192.168.1.0/24

    # 白名单：只接受指定范围内的 IP，范围外的结果全部抛弃
    whitelist-ip 10.0.0.0/8
    ```

## 6.2 IP 别名与 CDN 加速 (IP Aliasing)

Cloudflare 等 CDN 提供商的节点通常使用 Anycast（任播）技术。您可以利用测速工具找出您本地网络访问 Cloudflare 延迟最低的那个“超级节点 IP”，并强制将整个 Cloudflare 的网段映射到这个节点上，实现对数以百万计的网站的极速加速。

   将指定的 CDN 宽泛网段全部强行重定向到您测出的最快节点 IP 上：

    ```shell
    # 将 Cloudflare 的两个大网段，全部重映射到您测出的最快节点 104.16.0.1
    ip-alias 104.16.0.0/13 104.16.0.1
    ip-alias 172.64.0.0/13 104.16.0.1
    ```

## 6.3 IP 集合与远程规则下载 (IP Set & Proxy)

类似于域名集合，对于庞大的境内外 IP 路由表（如国内 IP 段 chnroute），您可以使用 `ip-set` 结合代理通道进行集中管理与极速下载。

   使用代理隧道下载并应用大规模 IP 规则表：

    ```shell
    # 创建 IP 集合，强制通过本地 clash 代理去远端下载中国大陆 IP 段列表
    ip-set -name cn-ip -type list -file https://example.com/china_ip_list.txt -proxy clash

    # 将集合应用到规则中（例如：这些 IP 走白名单直连）
    ip-rules ip-set:cn-ip -whitelist-ip
    ```

## 6.4 EDNS 客户端子网 (ECS)

EDNS Client Subnet 允许 SmartDNS 在向上游 DNS 发起查询时，携带您指定的子网 IP 信息。这在您通过代理服务器查询海外 DNS 时尤为重要，可以确保上游 CDN 返回最适合您本地物理网络的节点 IP，而不是代理服务器所在地的 IP。

   全局设置客户端子网，或为特定上游单独设置：

    ```shell
    # 全局设置 EDNS 客户端子网（暴露您的粗略网段，如 /24，以获取最准的 CDN 解析）
    edns-client-subnet 1.2.3.4/24

    # 仅针对走代理的特定上游发送指定的国内子网信息，纠正 CDN 调度偏差
    server 8.8.8.8 -proxy clash -subnet 1.2.3.4/24
    ```