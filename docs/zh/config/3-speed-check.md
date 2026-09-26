# 3. 解析测速与 IP 优选
SmartDNS Edge 能够并发请求多个上游 DNS，并对返回的众多 IP 进行真实网络测速，确保客户端始终连接到物理延迟最低的服务器。

## 3.1 测速模式 (Speed Check Mode)

程序默认会使用 ping、tcp:443 两种方式进行综合测速（不含 tcp:80，以减少多余探测开销）。您可以根据网络环境调整全局测速模式，或者为特定域名关闭测速。

**不写 `speed-check-mode` 时（默认）= 会测速**；只有显式写 `none` 才是关闭测速。

   ```Shell
   # 全局测速模式配置（默认优先 ping，超时后使用 tcp:443）
   speed-check-mode ping,tcp:443

   # 仅使用 ping 测速或关闭全局测速
   speed-check-mode ping
   speed-check-mode none

   # 针对走代理隧道的特定域名关闭测速（避免测速与真实出口不一致）
   domain-rules /google.com/ -speed-check-mode none
   ```
   
## 3.2 首次查询响应模式 (Response Mode)

响应模式决定了在首次查询且没有缓存时，SmartDNS Edge 如何向客户端返回测速结果。

   ```Shell
   # 最快 ping 响应模式（默认推荐）
   # DNS 查询等待时间 + Ping 时延最短，兼顾首屏打开速度与连接速度。
   response-mode first-ping

   # 最快 IP 地址模式
   # 强制等待所有 IP 测速完毕，绝对返回延迟最低的 IP（DNS 查询等待时间较长）。
   response-mode fastest-ip

   # 最快响应的 DNS 模式
   # DNS 查询等待时间最短，不关心 Ping 延迟，谁先返回 DNS 结果就用谁。
   response-mode fastest-response

   # 对特定域名单独设置响应模式
   domain-rules /example.com/ -r first-ping
   ```
   
## 3.3 双栈智能优选 (Dual-stack IP Selection)

在同时拥有 IPv4 和 IPv6 的双栈网络中，部分网站可能存在 IPv6 路由绕远、速度慢于 IPv4 的情况。开启双栈优选后，程序会同时测速 A 和 AAAA 记录，并优先返回速度更快的 IP。

   ```Shell
   # 启用双栈测速智能优选（默认开启）
   dualstack-ip-selection yes

   # 设置优选阈值（单位：毫秒）
   # 只有两个 IP 的速度差大于此阈值时，才会进行优选干预。
   dualstack-ip-selection-threshold 10
   ```

> ⚠️ **双栈优选的前提是开启测速**（默认开启）。如果测速被关闭，双栈优选也会随之失去作用。
>
> 关闭测速有两种写法，**两种都生效**：
>
>    ```Shell
>    # ① 全局关闭（对所有监听生效）
>    speed-check-mode none
>
>    # ② 只对某一条监听关闭（bind 级，优先级最高）
>    bind :6053 -no-speed-check
>    ```
>
> 出现"双栈优选开着、测速却关着"时，启动日志会提示：
>
> ```
> dualstack ip selection: ON, but INACTIVE (`speed-check-mode none` disables speed measurement, ...)
> ```
>
> 看到 `INACTIVE` 就说明优选此刻不起作用。
   
## 3.4 屏蔽 IPv6 与 DNS64

如果您的网络环境没有原生 IPv6，或者某些特定域名的 IPv6 极其卡顿，可以通过返回空的 SOA 记录来强制屏蔽 IPv6 解析。

   ```Shell
   # 全局强制 AAAA 记录返回空 SOA（彻底屏蔽 IPv6）
   force-AAAA-SOA yes

   # 仅禁用特定域名的 IPv6 解析
   address /example.com/#6

   # 在全局屏蔽 IPv6 的情况下，为特定域名添加例外放行
   address /ipv6-only.site.com/-6
   ```
   
## 配置 DNS64 转换
如果您处于纯 IPv6-only 网络，SmartDNS Edge 原生支持 DNS64，可将纯 IPv4 地址动态合成为 IPv6 地址（注：纯 IPv6 环境下建议关闭双栈优选）。

   ```Shell
   dns64 64:ff9b::/96
   ```