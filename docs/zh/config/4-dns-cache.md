# 模块 4：高性能 DNS 缓存机制

SmartDNS Edge 提供极速的内存缓存与持久化机制，并支持先进的乐观缓存（Serve Expired）与域名预取（Prefetch），实现毫秒级 DNS 响应体验。

## 4.1 基础缓存与持久化 (Basic Cache & Persistence)

SmartDNS Edge 会根据系统内存自动调整缓存大小。为避免重启进程后缓存丢失，建议开启缓存持久化并定期保存。

   1. 基础缓存与持久化配置

    ```shell
    # 设置内存缓存的域名条目个数
    cache-size 32768

    # 启用缓存持久化（当所在磁盘剩余空间大于 128MB 时才会生效）
    cache-persist yes

    # 指定持久化缓存文件的存储路径
    cache-file /var/cache/smartdns.cache

    # 设置定时保存周期（秒）。86400 为 24 小时定期保存一次，0 为禁用周期保存
    cache-checkpoint-time 86400
    ```

   2. 强制修改缓存 TTL
   如果您认为上游返回的 TTL 时间过短或过长，可以强制设定 TTL 的上下限。

    ```shell
    # 设置允许的最小 TTL 值（秒）
    rr-ttl-min 60

    # 设置允许的最大 TTL 值（秒）
    rr-ttl-max 600

    # 限制返回给客户端的最大 TTL 值
    rr-ttl-reply-max 60
    ```

## 4.2 乐观缓存 (Serve Expired)

乐观缓存是指：当域名的 TTL 过期时，如果此时由于断网或上游故障导致无法获取新 IP，程序会立刻将过期的旧 IP 返回给客户端，避免客户端卡顿等待，并在后台静默重试。

    开启乐观缓存及相关超时时间

    ```shell
    # 开启乐观缓存服务（极力推荐开启）
    serve-expired yes

    # 过期缓存的最长保留时间（秒）。超过此时长的旧缓存将被彻底丢弃
    serve-expired-ttl 604800

    # 当返回过期旧缓存时，强制指定其 TTL（秒），让客户端短时间内再次查询以获取最新 IP
    serve-expired-reply-ttl 3
    ```

## 4.3 缓存预取 (Prefetch)

配合乐观缓存使用，在缓存即将过期或已被访问触发过期时，后台会自动去上游预先获取最新解析结果。

    开启域名预取及超时设置

    ```shell
    # 开启缓存自动预取功能
    prefetch-domain yes

    # 预取超时参数（秒）。缓存过期后，若在此时间（默认6小时，即21600秒）内再次被访问，将秒回旧缓存并在后台触发更新
    serve-expired-prefetch-time 21600
    ```

## 4.4 特定域名的缓存控制

对于动态更新极频繁的域名（如 DDNS），您可能需要彻底关闭其缓存。

    针对特定域名关闭缓存

    ```shell
    domain-rules /example.com/ -no-cache
    ```
	
---