# 模块 7：智能分流与客户端控制

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
    
    # 当查询匹配到 a.com，或者客户端 IP 是 192.168.1.100 时，触发此组规则
    group-match -client-ip 192.168.1.100 -domain a.com
    
    # 访客组只能使用此特定的 DNS 服务器
    server 223.5.5.5
    
    # 访客组屏蔽所有视频网站
    address /youtube.com/#
    
    group-end
    ```

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

## 7.4 局域网主机名解析 (Local Domain & mDNS)

在家庭或办公内网中，记住每台设备的 IP 是非常困难的。开启相关功能后，您可以使用主机名直接访问内网设备（如 NAS、打印机）。

   开启 mDNS 解析与局域网域名后缀：

    ```shell
    # 启用 mDNS 查询，自动解析局域网内其他支持 mDNS 广播的智能设备
    mdns-lookup yes
    
    # 设置本地域名后缀。设置后，请求主机名会自动追加该后缀进行查询
    local-domain home.lan
    ```