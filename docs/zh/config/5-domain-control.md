# 模块 5：域名控制与广告拦截

SmartDNS Edge 提供极度灵活的域名管理能力，您可以轻松实现域名重定向、精细化的属性管控，以及搭载百万级规则的高效广告屏蔽。

## 5.1 指定域名 IP 与别名 (Address & CNAME)

您可以强制将特定域名解析到您指定的 IP 地址或别名，这通常用于内网服务覆盖或特定的路由劫持。

   1. 指定域名到单个或多个 IP（多 IP 时会随机排序返回）：

    ```shell
    address /example.com/1.2.3.4
    address /example.com/1.2.3.4,5.6.7.8
    ```

   2. 配置 CNAME 别名映射：

    ```shell
    cname /www.example.com/cdn.example.com
    ```

   3. 支持前缀通配与主域名精确匹配：

    ```shell
    address /*-a.example.com/1.2.3.4  # 通配前缀
    address /-.example.com/1.2.3.4   # 仅匹配主域名，不包含子域名
    ```

## 5.2 域名规则与高级控制 (Domain Rules)

为方便对同一个域名设置多个控制规则，`domain-rules` 允许您一次性赋予其多种属性。

统一设置某域名的专属上游、测速模式与缓存控制：

    ```shell
    domain-rules /example.com/ -nameserver overseas -speed-check-mode none -no-cache
    ```

## 5.3 广告拦截实战 (Ad Blocking)

通过让广告或跟踪域名直接返回空 SOA 记录，可以实现最高效、零延迟的广告屏蔽。

   拦截特定域名的所有请求，或仅拦截其 IPv6 解析：

    ```shell
    # 屏蔽特定域名的所有解析 (直接返回 SOA)
    address /ad.example.com/#

    # 仅屏蔽该域名的 IPv6 解析
    address /ad.example.com/#6

    # 忽略拦截（为被误杀的特定子域名添加例外放行）
    address /pass.ad.example.com/-
    ```

## 5.4 域名集合与远程规则下载 (Domain Set & Proxy)

对于海量的广告拦截或国内外分流域名，直接写在配置文件里会极度臃肿。通过 `domain-set` 可以使用外部列表文件集中管理。

   **SmartDNS Edge 专属绝杀**：原生支持通过 `-proxy` 参数，使用本地代理隧道穿透网络墙，去 GitHub 等远端极速下载、更新十几万行的 Anti-AD 等去广告规则集！

    ```shell
    # 声明本地 SOCKS5 代理客户端
    proxy-server socks5://127.0.0.1:1080 -name clash

    # 创建名为 ad-list 的域名集，并强制通过代理去远端下载实时更新的屏蔽规则
    domain-set -name ad-list -type list -file https://anti-ad.net/anti-ad-for-smartdns.conf -proxy clash

    # 将该集合中的所有十万级域名，一键应用到广告拦截规则中
    address /domain-set:ad-list/#
    ```