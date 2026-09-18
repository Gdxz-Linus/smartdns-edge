# 4. High-Performance DNS Cache Mechanism

SmartDNS Edge provides ultra-fast memory caching and persistence mechanisms. It also supports advanced optimistic caching (Serve Expired) and domain prefetching, ensuring millisecond-level DNS response times.

## 4.1 Basic Cache & Persistence

SmartDNS Edge automatically adjusts the cache size based on available system memory. To prevent cache loss after process restarts, it is recommended to enable cache persistence.

    1. Basic Cache and Persistence Configuration

    ```shell
    # Set the maximum number of domain entries in the memory cache
    cache-size 32768

    # Enable cache persistence (only takes effect if the target disk has >128MB of free space)
    cache-persist yes

    # Specify the file path for persistent cache storage
    cache-file /var/cache/smartdns.cache

    # Set periodic save interval (in seconds). 86400 means saving every 24 hours. 0 disables periodic saving.
    cache-checkpoint-time 86400
    ```

    2. Force Override Cache TTL
	
    If you believe the TTL returned by upstream servers is too short or too long, you can enforce TTL bounds.

    ```shell
    # Set the minimum allowed TTL value (in seconds)
    rr-ttl-min 60

    # Set the maximum allowed TTL value (in seconds)
    rr-ttl-max 600

    # Limit the maximum TTL value returned to the client
    rr-ttl-reply-max 60
    ```

## 4.2 Optimistic Cache (Serve Expired)

Optimistic caching means that when a domain's TTL expires, and the program cannot fetch a new IP due to network or upstream failures, it immediately returns the expired old IP to the client. This prevents the client from hanging while the program silently retries in the background.

    Enable Serve Expired and Timeout Settings

    ```shell
    # Enable the serve-expired feature (Highly recommended)
    serve-expired yes

    # Maximum retention time for expired cache (in seconds). Cache older than this will be completely discarded.
    serve-expired-ttl 604800

    # Force a specific TTL (in seconds) when returning expired cache, instructing clients to query again soon for the updated IP.
    serve-expired-reply-ttl 3
    ```

## 4.3 Cache Prefetching

Used in conjunction with optimistic caching, this feature automatically fetches the latest resolution results from upstream in the background before the cache expires or when it is triggered upon expiration.

    Enable Domain Prefetching and Timeout Settings

    ```shell
    # Enable automatic cache prefetching
    prefetch-domain yes

    # Prefetch timeout parameter (in seconds). After the cache expires, if accessed within this time (default 6 hours, i.e., 21600s), it instantly serves the stale cache and triggers a background update.
    serve-expired-prefetch-time 21600
    ```

## 4.4 Domain-Specific Cache Control

For domains that update dynamically and frequently (such as DDNS), you may want to completely disable caching for them.

    Disable caching for a specific domain

    ```shell
    domain-rules /example.com/ -no-cache
    ```
	
---