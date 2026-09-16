use chrono::DateTime;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::config::ServerOpts;
use crate::dns_conf::RuntimeConfig;
use crate::libdns::proto::ProtoError;
use crate::log;
use crate::server::DnsHandle;
use crate::{
    dns::*,
    libdns::proto::{
        op::{Message, Query},
        rr::DNSClass,
    },
    log::{debug, error, info},
    middleware::*,
};
use lru::LruCache;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use std::sync::Mutex;
use tokio::time::sleep;

// 🌟 核心升维：全局唯一的安全缓存主键
// 彻底杜绝 EDNS0 ECS 导致的跨地域缓存污染与多分组重写踩踏！
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub query: Query,
    pub group: String,
    pub ecs: Option<String>,
}

pub struct DnsCacheMiddleware {
    cfg: Arc<RuntimeConfig>,
    cache: Arc<DnsCache>,
    client: DnsHandle,
    inflight: Arc<Mutex<std::collections::HashMap<CacheKey, tokio::sync::broadcast::Sender<Option<DnsResponse>>>>>,
}

impl DnsCacheMiddleware {
    pub fn new(cfg: &Arc<RuntimeConfig>, dns_handle: DnsHandle) -> Self {
        let cache = Arc::new(DnsCache::new(
            cfg.cache_size(),
            cfg.serve_expired(),
            cfg.serve_expired_ttl(),
            cfg.serve_expired_reply_ttl(),
            cfg.serve_expired_prefetch_time(),
        ));

        // 🌟 最小改动 2：必须先读完硬盘 cache 文件，再开门迎客（防击穿）
        if cfg.cache_persist() {
            let cache_file = cfg.cache_file();
            if cache_file.exists() {
                let cache_clone = cache.clone();
                let path = cache_file.to_path_buf();
                
                // 🌟 核心防御：捕获子线程可能的 Panic 崩溃！
                // 绝对不允许一个损坏的缓存文件，把整个 DNS 服务给拖垮！
                let res = std::thread::spawn(move || {
                    cache_clone.load_cache(path.as_path());
                }).join();

                if let Err(e) = res {
                    // 如果子线程读取因为文件损坏而当场崩溃了，我们把它拦截下来，打一条红字警告！
                    crate::log::error!("🔥 FATAL: Cache file corrupted or read panic: {:?}. Ignoring old cache and starting fresh!", e);
                    // 🔐 P2：坏档**不再直接删除** —— 改名存档（只留最近 1 份），方便用户排查后再清
                    let _ = archive_cache_file(&cache_file, "load-panic");
                }
            }
        }

        Self::spawn_background_tasks(cfg, &cache, dns_handle.clone());

        Self {
            cfg: cfg.clone(),
            cache,
            client: dns_handle.with_new_opt(ServerOpts {
                is_background: true,
                ..Default::default()
            }),
            inflight: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
	
    pub fn with_cache(cfg: &Arc<RuntimeConfig>, dns_handle: DnsHandle, cache: Arc<DnsCache>) -> Self {
        // 🔐 P2：热重载时缓存策略必须跟着换 —— 原来直接复用旧 DnsCache，
        // 改完 serve-expired / cache-persist / cache-size 之后一部分生效一部分不生效。
        cache.reload_config(cfg);

        Self {
            cfg: cfg.clone(),
            cache,
            client: dns_handle.with_new_opt(ServerOpts {
                is_background: true,
                ..Default::default()
            }),
            inflight: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn spawn_background_tasks(cfg: &Arc<RuntimeConfig>, cache: &Arc<DnsCache>, client_handle: DnsHandle) {
        if cfg.cache_persist() {
            let cache_file = cfg.cache_file();
            let cache_weak = Arc::downgrade(cache);
            let cache_checkpoint_time = cfg.cache_checkpoint_time();
            tokio::spawn(async move {
                // 🌟 最小改动 3：删除了这里原有的异步 load_cache，因为它已经在上面同步执行过了
                
                let checkpoint_duration = Duration::from_secs(cache_checkpoint_time);
                let mut interval = tokio::time::interval_at(
                    tokio::time::Instant::now() + checkpoint_duration,
                    checkpoint_duration,
                );
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Some(c) = cache_weak.upgrade() {
                                let cache_file = cache_file.clone();
                                // 落盘依然是异步外包给 spawn_blocking，绝不影响主进程解析 DNS
                                tokio::task::spawn_blocking(move || c.persist_cache(cache_file.as_path()));
                            } else {
                                break;
                            }
                        }
                        _ = crate::signal::terminate() => {
                            break;
                        }
                    };
                }
            });
        }

        let gc_cache_weak = Arc::downgrade(cache);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(900));
            loop {
                interval.tick().await;
                if let Some(cache_clone) = gc_cache_weak.upgrade() {
                    let purged = cache_clone.purge_dead_records(Instant::now()).await;
                    if purged > 0 {
                        log::info!("Cache GC: purged {} totally dead records from memory", purged);
                    }
                } else {
                    break;
                }
            }
        });

        if cfg.prefetch_domain() {
            let prefetch_notify = cache.prefetch_notify.clone();
            let client = client_handle.with_new_opt(ServerOpts {
                is_background: true,
                ..Default::default()
            });
            let cache_weak = Arc::downgrade(cache);
            
            tokio::spawn(async move {
                let min_interval = Duration::from_secs(
                    std::env::var("PREFETCH_MIN_INTERVAL").as_deref().unwrap_or("60").parse().unwrap_or(60),
                );
                let mut last_check = Instant::now();

                loop {
                    prefetch_notify.notified().await;
                    
                    let cache_arc = match cache_weak.upgrade() {
                        Some(c) => c,
                        None => break,
                    };

                    let now = Instant::now();
                    let most_recent;
                    if now - last_check > min_interval {
                        last_check = now;
                        let expired = {
                            let (expired, most_recent0) = cache_arc.get_expired(now, Some(5)).await;
                            most_recent = most_recent0;
                            expired
                        };

                        if !expired.is_empty() {
                            // Cache 只需要忠实地把过期的 CacheKey 重新派发即可。
                            // 如果启用了双栈，底层的 dualstack 和 ns 模块会自动完成裂变和 Single-Flight 折叠。
                            for cache_key in expired {
                                // 🔐 P2（用户定策）：`cache_key.group` 是 **服务器组** 名（来自
                                // `server_group_name()`：`-group` 或域规则链里的 `nameserver`），
                                // 所以必须放进 `group` 字段 —— 原来放进 `rule_group` 属于"名字放错字段"，
                                // 再加上 search() 会按来源 IP 重算，结果预取走的是**默认上游**，
                                // 目标组的过期条目永远刷不到、还会在默认键上多写一份。
                                let opts = ServerOpts {
                                    is_background: true,
                                    group: Some(cache_key.group.clone()),
                                    ..Default::default()
                                };
                                let req_client = client.with_new_opt(opts);
                                let cache_clone = cache_arc.clone(); 
                                
                                tokio::spawn(async move {
                                    let _guard = PrefetchGuard { cache: cache_clone, key: cache_key.clone() };
                                    let mut msg = Message::query();
                                    msg.add_query(cache_key.query.clone());
                                    req_client.send(msg).await;
                                });
                            }
                        }
                    } else {
                        most_recent = Duration::ZERO;
                    }
                    let dura = most_recent.max(min_interval);
                    prefetch_notify.notify_after(dura).await;
                }
            });
        }
    }

    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsCacheMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let original_query = req.query().original().to_owned();

        // 🌟 辅助闭包：强制 CNAME 展平器。
        // 无论是否走缓存，只要返回给客户端或存入冰柜，统统展平为极速 IP 直达包！
        let flatten_cname = |lookup: &mut DnsResponse, query: &Query| {
            if query.query_type().is_ip_addr() {
                let target_type = query.query_type();
                let has_target = lookup.answers().iter().any(|r| r.record_type() == target_type);

                if has_target {
                    let original_name = query.name().clone();
                    // 在毁掉 CNAME 之前，提取整个包裹真实的最短存活时间，防止底层 IP 寿命过长成为僵尸
                    let real_min_ttl = lookup.answers().iter().map(|r| r.ttl()).min().unwrap_or(60);

                    // 清理门户：干掉 CNAME，只留下终点 IP
                    lookup.answers_mut().retain(|record| record.record_type() == target_type);

                    // 移花接木：把终点 IP 的 Name 强行改成用户最初请求的主域名
                    for record in lookup.answers_mut() {
                        if record.name() != &original_name {
                            record.set_name(original_name.clone());
                        }
                        record.set_ttl(real_min_ttl);
                    }
                }
            }
        };

        // 🌟 核心拦截：即使是不走缓存的请求，也必须拦下来展平后再发给客户端！
        if ctx.server_opts.no_cache() || ctx.no_cache {
            let res = next.run(ctx, req).await;
            return match res {
                Ok(mut lookup) => {
                    flatten_cname(&mut lookup, &original_query);
                    Ok(lookup)
                }
                Err(err) => Err(err),
            };
        }

        // 🌟 提取 EDNS0 ECS 子网信息
        let ecs_str = req.extensions()
            .as_ref()
            .and_then(|edns| edns.option(crate::libdns::proto::rr::rdata::opt::EdnsCode::Subnet))
            .and_then(|opt| match opt {
                crate::libdns::proto::rr::rdata::opt::EdnsOption::Subnet(subnet) => {
                    // 请求侧要用 source_prefix（客户端声明的"我的地址前 N 位"）；
                    // scope_prefix 是上游在应答里回填的作用域，请求里恒为 0，用它等于丢掉前缀。
                    Some(format!("{}/{}", subnet.addr(), subnet.source_prefix()))
                }
                _ => None,
            })
            .or_else(|| ctx.domain_rule.get_ref(|r| r.subnet.as_ref()).map(|s| format!("{}/{}", s.addr(), s.source_prefix())));

        let cache_key = CacheKey {
            query: req.query().original().to_owned(),
            group: ctx.server_group_name().to_string(),
            ecs: ecs_str.clone(),
        };

        // 🌟 过期条目的处置（用户定调）：过期数据只分两种下场，没有第三种。
        //   ① 允许服务过期数据（serve-expired 开、且该域名没写 no-serve-expired）→ 秒回旧数据 + 后台刷新（见下）；
        //   ② 明确写了不要（全局 serve-expired no / 域名级 -no-serve-expired）→ 就地丢弃。
        //   旧行为是把过期条目一直攥在手里，等上游一出错就当成功返回（原 `Err` 分支的 `cached_res` 兜底）：
        //   于是"写了不要过期数据"的人照样静默拿到旧数据，还带着入库时的原始 TTL（客户端会当新数据再缓存一轮），
        //   日志也看不出降级。该兜底已按定调移除，不再恢复。
        if !ctx.server_opts.is_background {
            // 过期数据能不能喂：域名规则与监听选项**任一**显式关闭即不许喂。
            // 监听级那份（`bind 127.0.0.1:53 -no-serve-expired`）以前解析了却没人读，
            // 挂在上面的监听照样会喂旧数据 —— 死开关，这里接上。
            let no_serve_expired = ctx
                .domain_rule
                .get(|r| r.no_serve_expired)
                .unwrap_or_default()
                || ctx.server_opts.no_serve_expired();

            match self.cache.get(&cache_key, Instant::now()).await {
                // 🌟 因为 Key 已经包含了 Group，命中必定是同组，免去判断！
                Some((res, status)) => {
                    match status {
                        CacheStatus::Valid => {
                            debug!("name: {} {} using caching (ECS: {:?})", cache_key.query.name(), cache_key.query.query_type(), cache_key.ecs);
                            ctx.source = LookupFrom::Cache;
                            return Ok(res);
                        }
                        CacheStatus::Expired if ctx.cfg().serve_expired() && !no_serve_expired => {
                            if self.cache.mark_prefetching(&cache_key).await {
                                // 🌟 核心修复 3：生成全局唯一的同步时间戳基准！
                                let reply_ttl = Duration::from_secs(self.cache.expired_reply_ttl());
                                let sync_valid_until = Instant::now() + reply_ttl;
                                
                                self.cache.set_valid_until_for_prefetch(&cache_key, sync_valid_until).await;

                                let mut guards = vec![PrefetchGuard { cache: self.cache.clone(), key: cache_key.clone() }];
                                let mut opts = ctx.server_opts.clone();
                                opts.is_background = true;
                                let client = self.client.with_new_opt(opts);
                                
                                if cache_key.query.query_type().is_ip_addr() {
                                    let other_type = match cache_key.query.query_type() {
                                        RecordType::A => RecordType::AAAA,
                                        RecordType::AAAA => RecordType::A,
                                        other => {
                                            // 🔐 P0-2：上游已用 is_ip_addr() 过滤（仅 A/AAAA），
                                            // 到不了这里；真到了也不 panic，退回缓存结果。
                                            crate::log::warn!(
                                                "prefetch: unexpected record type {other:?}, skip prefetch"
                                            );
                                            return Ok(res);
                                        }
                                    };
                                    let other_key = CacheKey {
                                        query: Query::query(cache_key.query.name().clone(), other_type),
                                        group: cache_key.group.clone(),
                                        ecs: cache_key.ecs.clone(),
                                    };
                                    
                                    if self.cache.mark_prefetching(&other_key).await {
                                        // 🌟 核心修复 4：双栈兄弟使用完全一样的基准时间戳，绝对对齐！
                                        self.cache.set_valid_until_for_prefetch(&other_key, sync_valid_until).await;
                                        guards.push(PrefetchGuard { cache: self.cache.clone(), key: other_key });
                                    }
                                }

                                let client_clone = client.clone();
                                let self_key = cache_key.clone();
                                tokio::spawn(async move {
                                    let _guards = guards; 
                                    let mut msg = Message::query();
                                    msg.add_query(self_key.query);
                                    client_clone.send(msg).await;
                                });
                                
                                // 🌟 统一公式：触发者也老老实实算时间！同样向上取整！
                                let mut resurrected_res = res;
                                let ttl_duration = sync_valid_until.saturating_duration_since(Instant::now());
                                let mut actual_ttl = ttl_duration.as_secs() as u32;
                                if ttl_duration.subsec_nanos() > 0 {
                                    actual_ttl += 1;
                                }
                                resurrected_res.set_new_ttl(actual_ttl);
                                
                                debug!("name: {} {} using caching (Expired) (ECS: {:?})", cache_key.query.name(), cache_key.query.query_type(), cache_key.ecs);
                                ctx.source = LookupFrom::Cache;
                                return Ok(resurrected_res); 
                            }

                            // 极小概率兜底：如果有其他并发已经拿了预取锁，但时间戳还未更新完毕
                            let reply_ttl_secs = self.cache.expired_reply_ttl() as u32;
                            let mut fallback_res = res;
                            fallback_res.set_new_ttl(reply_ttl_secs);
                            debug!("name: {} {} using caching (Expired) (ECS: {:?})", cache_key.query.name(), cache_key.query.query_type(), cache_key.ecs);
                            ctx.source = LookupFrom::Cache;
                            return Ok(fallback_res); 
                        }
                        // 明确不要过期数据（全局 serve-expired no / 域名级 no-serve-expired）：
                        // 就地丢弃 —— 上游失败时也不拿它兜底（用户定调）。
                        CacheStatus::Expired => {}
                    }
                }
                None => {}
            }
        }

        // 🌟 并发折叠（Single Flight），同样按 CacheKey 精准隔离
        let rx = {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.get(&cache_key) {
                Some(tx.subscribe()) 
            } else {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                map.insert(cache_key.clone(), tx);
                None 
            }
        };

        if let Some(mut receiver) = rx {
            return match receiver.recv().await {
                Ok(Some(res)) => {
                    ctx.source = LookupFrom::Cache;
                    Ok(res)
                }
                _ => Err(ProtoErrorKind::NoConnections.into()),
            };
        }

        let mut inflight_guard = InflightCacheGuard {
            inflight: self.inflight.clone(),
            key: cache_key.clone(),
            done: false,
        };
        let res = next.run(ctx, req).await;

        match res {
            Ok(mut lookup) => {
                // 🌟 主响应展平
                flatten_cname(&mut lookup, &cache_key.query);

                if !ctx.no_cache {
                    // 🚫 截断包（TC=1）不入缓存：它只是"答案太大装不下"的半成品，一旦入库就会在整个
                    // TTL 内把所有客户端都喂成残缺结果，而且不会自我纠正（P1-5）。
                    if lookup.truncated() {
                        debug!(
                            "name: {} {}: response is truncated (TC=1), not cached",
                            cache_key.query.name(),
                            cache_key.query.query_type()
                        );
                    } else {
                        self.cache.insert_full_response(cache_key.clone(), lookup.clone(), Instant::now()).await;
                    }

                    // 🌟 完美收取双栈探针带回的战利品，同样组装完整 CacheKey
                    let extra_records = std::mem::take(&mut ctx.extra_cache_records);
                    for (extra_query, mut extra_resp) in extra_records {
                        // 🚨 核心防线：双栈淘汰带回来的“副包裹”也要展平后再入库！
                        // 否则冰柜里会混入带有 CNAME 的脏数据！
                        flatten_cname(&mut extra_resp, &extra_query);
                        
                        let extra_key = CacheKey {
                            query: extra_query,
                            group: ctx.server_group_name().to_string(), // 现在可以畅通无阻地读取 ctx 了
                            ecs: ecs_str.clone(),
                        };
                        if extra_resp.truncated() {
                            debug!(
                                "name: {} {}: dual-stack extra response is truncated (TC=1), not cached",
                                extra_key.query.name(),
                                extra_key.query.query_type()
                            );
                        } else {
                            self.cache.insert_full_response(extra_key, extra_resp, Instant::now()).await;
                        }
                    }

                    // 截断包没有进缓存，也就没有"到期再预取"这回事
                    if !lookup.truncated()
                        && ctx.cfg().prefetch_domain()
                        && let Some(ttl) = lookup.min_ttl() {
                            self.cache.prefetch_notify
                                .notify_after(Duration::from_secs(ttl as u64))
                                .await;
                        }
                }
                
                {
                    let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(tx) = map.remove(&cache_key) {
                        let broadcast_res = Some(lookup.clone());
                        let _ = tx.send(broadcast_res);
                    }
                }
                inflight_guard.done = true;
                Ok(lookup)
            }
            Err(err) => {
                {
                    let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(tx) = map.remove(&cache_key) {
                        let _ = tx.send(None);
                    }
                }
                inflight_guard.done = true;
                // 上游失败时**不再**拿过期数据当成功返回（用户定调）：
                // "允许服务过期数据"的配置在命中过期条目时就已经秒回了，根本走不到这里；
                // 走到这里的只有"明确不要过期数据"的配置 —— 那就如实报错，让故障看得见。
                Err(err)
            }
        }
    }
}

pub struct DomainPrefetchingNotify {
    notity: Arc<Notify>,
    tick: RwLock<Instant>,
}

impl DomainPrefetchingNotify {
    pub fn new() -> Self {
        Self {
            notity: Default::default(),
            tick: RwLock::new(Instant::now()),
        }
    }

    async fn notify_after(&self, duration: Duration) {
        if duration.is_zero() {
            self.notity.notify_one()
        } else {
            let tick = *self.tick.read().await;
            let now = Instant::now();
            let next_tick = now + duration;
            if tick > now && next_tick > tick {
                debug!(
                    "Domain prefetch check will be performed in {:?}.",
                    tick - now
                );
                return;
            }

            *self.tick.write().await.deref_mut() = next_tick;
            debug!("Domain prefetch check will be performed in {:?}.", duration);
            let notify = self.notity.clone();
            tokio::spawn(async move {
                sleep(duration).await;
                notify.notify_one();
            });
        }
    }
}

impl Deref for DomainPrefetchingNotify {
    type Target = Notify;

    fn deref(&self) -> &Self::Target {
        self.notity.as_ref()
    }
}

const MAX_TTL: u32 = 86400_u32;
const SHARD_COUNT: usize = 64;

pub struct DnsCache {
    shards: Arc<Vec<Mutex<LruCache<CacheKey, DnsCacheEntry>>>>,
    // 🔐 P2：这些"缓存策略"字段改成原子量 —— 热重载时可以就地更新。
    // 原来是普通字段，而热重载走的是 `with_cache`（复用同一个 Arc<DnsCache>），
    // 于是改完 serve-expired / cache-size 之后"一部分生效一部分不生效"，
    // 同一次请求会走两套互相矛盾的判断。
    serve_expired: AtomicBool,
    expired_ttl: AtomicU64,
    expired_reply_ttl: AtomicU64,
    expired_prefetch_time: AtomicU64,
    /// 当前生效的配置容量（分片在创建时就固定了，用来检测"容量被改过"并如实告警）
    cache_size: AtomicUsize,
    pub prefetch_notify: Arc<DomainPrefetchingNotify>, 
}

impl DnsCache {
    fn new(
        cache_size: usize,
        serve_expired: bool,
        expired_ttl: u64,
        expired_reply_ttl: u64,
        expired_prefetch_time: u64,
    ) -> Self {
        let shard_size = std::cmp::max(1, cache_size / SHARD_COUNT);
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(LruCache::new(
                NonZeroUsize::new(shard_size).unwrap(),
            )));
        }

        Self {
            shards: Arc::new(shards),
            serve_expired: AtomicBool::new(serve_expired),
            expired_ttl: AtomicU64::new(expired_ttl),
            expired_reply_ttl: AtomicU64::new(expired_reply_ttl),
            expired_prefetch_time: AtomicU64::new(expired_prefetch_time),
            cache_size: AtomicUsize::new(cache_size),
            prefetch_notify: Arc::new(DomainPrefetchingNotify::new()),
        }
    }

    /// 🔐 P2：热重载时把可变的缓存策略换成新配置（见结构体上的注释）。
    pub fn reload_config(&self, cfg: &crate::dns_conf::RuntimeConfig) {
        self.serve_expired
            .store(cfg.serve_expired(), Ordering::Relaxed);
        self.expired_ttl
            .store(cfg.serve_expired_ttl(), Ordering::Relaxed);
        self.expired_reply_ttl
            .store(cfg.serve_expired_reply_ttl(), Ordering::Relaxed);
        self.expired_prefetch_time
            .store(cfg.serve_expired_prefetch_time(), Ordering::Relaxed);

        let new_size = cfg.cache_size();
        let old_size = self.cache_size.swap(new_size, Ordering::Relaxed);
        if old_size != new_size {
            // 分片容量在创建时就定死了，改容量只能重建缓存（会丢内容）——
            // 所以这里如实告警，而不是静默装作已经生效。
            crate::log::warn!(
                "cache-size 从 {} 改成 {} 需要重启才生效（缓存分片容量在启动时固定，其余缓存策略已即时生效）",
                old_size,
                new_size
            );
        }
    }

    #[inline]
    fn serve_expired(&self) -> bool {
        self.serve_expired.load(Ordering::Relaxed)
    }

    #[inline]
    fn expired_ttl(&self) -> u64 {
        self.expired_ttl.load(Ordering::Relaxed)
    }

    #[inline]
    fn expired_reply_ttl(&self) -> u64 {
        self.expired_reply_ttl.load(Ordering::Relaxed)
    }

    #[inline]
    fn expired_prefetch_time(&self) -> u64 {
        self.expired_prefetch_time.load(Ordering::Relaxed)
    }

    #[inline]
    fn get_shard(&self, key: &CacheKey) -> &Mutex<LruCache<CacheKey, DnsCacheEntry>> {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) & (SHARD_COUNT - 1);
        &self.shards[idx]
    }

    pub async fn clear(&self) {
        for shard in self.shards.iter() {
            shard.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
    }

    pub async fn mark_prefetching(&self, key: &CacheKey) -> bool {
        let mut cache = self.get_shard(key).lock().unwrap_or_else(|e| e.into_inner()); 
        if let Some(entry) = cache.get_mut(key) {
            if entry.is_in_prefetching { return false; }
            entry.is_in_prefetching = true;
        }
        true
    }
	
	// 🌟 核心修复 2：改为接收外部绝对基准时间，确保双栈微秒级一致！
    pub async fn set_valid_until_for_prefetch(&self, key: &CacheKey, new_valid_until: Instant) {
        let mut cache = self.get_shard(key).lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(key)
            && entry.valid_until < new_valid_until {
                entry.valid_until = new_valid_until;
            }
    }

    pub async fn purge_dead_records(&self, now: Instant) -> usize {
        let mut count = 0;
        let grace_period = if self.serve_expired() { Duration::from_secs(self.expired_ttl()) } else { Duration::ZERO };

        for shard in self.shards.iter() {
            {
                let mut cache = shard.lock().unwrap_or_else(|e| e.into_inner());
                let mut to_remove = Vec::new();
                for (key, entry) in cache.iter() {
                    if now > entry.valid_until + grace_period {
                        to_remove.push(key.clone());
                    }
                }
                count += to_remove.len();
                for q in to_remove { cache.pop(&q); }
            }
            tokio::task::yield_now().await;
        }
        count
    }

    pub async fn cached_records_paginated(&self, offset: usize, limit: usize) -> (usize, Vec<CachedQueryRecord>) {
        let mut total = 0;
        let mut records = Vec::new();
        let mut current_offset = 0;

        for shard in self.shards.iter() {
            let cache = shard.lock().unwrap_or_else(|e| e.into_inner());
            total += cache.len();

            for (key, entry) in cache.iter() {
                if records.len() >= limit {
                    continue; 
                }
                if current_offset < offset {
                    current_offset += 1;
                    continue; 
                }
                records.push(CachedQueryRecord {
                    name: key.query.name().clone(),
                    query_type: key.query.query_type(),
                    query_class: key.query.query_class(),
                    records: entry.data.records().to_vec().into_boxed_slice(),
                    hits: entry.stats.hits,
                    last_access: entry.stats.last_access,
                });
                current_offset += 1;
            }
        }
        (total, records)
    }

    pub async fn insert_full_response(&self, key: CacheKey, response: DnsResponse, now: Instant) -> DnsResponse {
        let mut min_ttl = MAX_TTL;

        if !response.answers().is_empty() {
            let ans_ttl = response.answers().iter().map(|r| r.ttl()).min().unwrap_or(60);
            min_ttl = min_ttl.min(ans_ttl);
        } else {
            let soa_record = response.message().authorities().iter().find(|r| r.record_type() == RecordType::SOA)
                .or_else(|| response.answers().iter().find(|r| r.record_type() == RecordType::SOA));
            if let Some(soa) = soa_record {
                let mut negative_ttl = soa.ttl();
                if let RData::SOA(soa_data) = soa.data() { negative_ttl = negative_ttl.min(soa_data.minimum()); }
                min_ttl = min_ttl.min(negative_ttl);
            } else {
                min_ttl = 5;
            }
        }
        min_ttl = min_ttl.min(MAX_TTL);

        let valid_until = now + Duration::from_secs(min_ttl as u64);
        let mut cache_resp = response.clone();
        
        // 🌟 将组名刻印进 Response
        cache_resp = cache_resp.with_name_server_group(key.group.clone());
        cache_resp = cache_resp.with_valid_until(valid_until);
        cache_resp.set_new_ttl(min_ttl);

        // 🌟 核心优化：同步直接写入分段锁缓存（耗时 <0.05微秒），保障时序一致性（Read-After-Write）
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) & (SHARD_COUNT - 1);

        let mut cache = self.shards[idx].lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(&key) {
            entry.data = cache_resp.clone();
            entry.valid_until = valid_until;
            entry.is_in_prefetching = false;
            entry.stats.hits = 1; 
        } else {
            cache.put(key.clone(), DnsCacheEntry::new(cache_resp.clone(), valid_until, key.ecs.clone()));
        }

        // 🌟 修复报错点：直接返回已构建好的 cache_resp 对象
        cache_resp
    }

    async fn get(&self, key: &CacheKey, now: Instant) -> Option<(DnsResponse, CacheStatus)> {
        let mut cache = self.get_shard(key).lock().unwrap_or_else(|e| e.into_inner()); 
        cache.get_mut(key).map(|value| {
            value.stats.hit();
            let mut res = value.data.clone();
            if value.is_current(now) {
                // 🌟 统一公式：计算剩余寿命，遇到毫秒零头直接向上取整！
                let ttl_duration = value.ttl(now);
                let mut ttl_secs = ttl_duration.as_secs() as u32;
                if ttl_duration.subsec_nanos() > 0 {
                    ttl_secs += 1;
                }
                res.set_new_ttl(ttl_secs);
                (res, CacheStatus::Valid)
            } else {
                (res, CacheStatus::Expired)
            }
        })
    }

    // 🌟 返回类型变更为精准的 CacheKey
    async fn get_expired(&self, now: Instant, seconds_ahead: Option<u64>) -> (Vec<CacheKey>, Duration) {
        let mut most_recent = Duration::from_secs(MAX_TTL as u64);
        let mut to_prefetch = std::collections::HashMap::new();
        let ahead_secs = seconds_ahead.unwrap_or(5);

        for shard in self.shards.iter() {
            {
                let mut cache = shard.lock().unwrap_or_else(|e| e.into_inner());
                if cache.is_empty() { continue; }

                for (key, entry) in cache.iter_mut() {
                    if entry.is_in_prefetching { continue; }
                    if !key.query.query_type().is_ip_addr() { continue; }

                    let is_frequent = entry.stats.hits >= 2;

                    if self.serve_expired() {
                        if entry.is_current(now) {
                            most_recent = most_recent.min(entry.ttl(now));
                            continue; 
                        }
                        if self.expired_prefetch_time() > 0 {
                            let expired_for = now.saturating_duration_since(entry.valid_until).as_secs();
                            if expired_for < self.expired_prefetch_time() { continue; }
                            if !is_frequent { continue; }
                        } else if !is_frequent {
                            continue;
                        }
                    } else {
                        let prefetch_now = now + Duration::from_secs(ahead_secs);
                        if entry.is_current(prefetch_now) {
                            most_recent = most_recent.min(entry.ttl(now));
                            continue; 
                        }
                        if !is_frequent { continue; }
                    }

                    entry.is_in_prefetching = true;
                    entry.stats.hits = entry.stats.hits.saturating_sub(1);
                    
                    // 🌟 保持 CacheKey 的原汁原味，不丢失 RecordType 和 ECS 信息
                    let current_hits = to_prefetch.get(key).copied().unwrap_or(0);
                    to_prefetch.insert(key.clone(), std::cmp::max(current_hits, entry.stats.hits));
                }
            } 

            tokio::task::yield_now().await;
        }

        let mut expired: Vec<_> = to_prefetch.into_iter().collect();
        expired.sort_by_key(|(_, hits)| std::cmp::Reverse(*hits));
        let res = expired.into_iter().map(|(target, _)| target).collect();
        (res, most_recent)
    }

    pub fn persist_cache(&self, path: &Path) {
        // 🔐 P2：同一时刻只允许一次落盘 —— 周期落盘（后台任务）与退出落盘（app.rs）走的是同一条路，
        // 以前两者各写各的同一个 `.tmp`、又没有互斥：撞在一起就会写出"半新半旧"的撕裂档，
        // 下次启动读不开 → 又触发"整份删档"（两个问题会连环）。
        let _one_at_a_time = PERSIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let cache_to_file = || {
            // 临时名带 PID：多个实例各写各的，不再互相踩（进程内由上面的锁串行）
            let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));

            let mut file = File::options().create(true).truncate(true).write(true).open(&tmp_path)?;

            // 🔐 P2：先写文件头（魔数 + 格式版本 + 条目数）——
            // 以后读到不认识的版本，就能明确说"版本不兼容"，而不是含混的"可能损坏"。
            let mut header = Vec::with_capacity(CACHE_HEADER_LEN);
            emit_cache_header(&mut header, self.total_len() as u32);
            std::io::Write::write_all(&mut file, &header)?;

            for shard in self.shards.iter() {
                let mut shard_buffer = Vec::new();
                {
                    let cache = shard.lock().unwrap_or_else(|e| e.into_inner());
                    DnsCacheEntry::serialize_many(cache.iter().map(|(_, entry)| entry), &mut shard_buffer)?;
                }

                std::io::Write::write_all(&mut file, &shard_buffer)?;
            }

            file.sync_all()?;

            // 释放文件句柄（Windows 上独占会导致 rename 失败）
            drop(file);

            // 🔐 P2：**不再"先删旧档再改名"** —— Rust 的 rename 在 Windows 上本就是"替换已存在文件"
            // 的语义，先删只会凭空造出"旧档已删、新档还没就位"的窗口：这一步改名失败，用户就一份
            // 缓存都没有了。现在失败也**绝不破坏旧档**：退避重试，实在不行就留着新档并点名日志。
            let mut rename_err = None;
            for attempt in 0..=PERSIST_RENAME_RETRIES {
                match std::fs::rename(&tmp_path, path) {
                    Ok(()) => {
                        rename_err = None;
                        break;
                    }
                    Err(err) => {
                        rename_err = Some(err);
                        if attempt < PERSIST_RENAME_RETRIES {
                            std::thread::sleep(Duration::from_millis(PERSIST_RENAME_RETRY_MS));
                        }
                    }
                }
            }

            if let Some(err) = rename_err {
                crate::log::warn!(
                    "替换缓存文件失败（旧档已保留、新档仍在 {}）：{}。\
                     常见原因是杀毒/索引/备份软件正占用该文件，或另一个实例在同时写盘",
                    tmp_path.display(),
                    err
                );
                return Err(ProtoError::from(err));
            }

            Ok::<_, ProtoError>(())
        };

        match cache_to_file() {
            Ok(_) => {
                info!("save DNS cache to file \"{}\" successfully.", path.display());
                // 顺手清掉历史遗留的固定名临时档（旧版本用的是 `.tmp`）
                let _ = std::fs::remove_file(path.with_extension("tmp"));
            }
            Err(err) => error!("failed to save DNS cache to file {}", err),
        }
    }
	
	pub fn load_cache(&self, path: &Path) {
        // 🌟 视觉净化：尝试将路径转化为绝对路径，如果失败则保持原样
        let display_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        #[allow(unused_mut)]
        let mut display_str = display_path.to_string_lossy().to_string();
        
        // 🌟 终极清洗：剥离 Windows 丑陋的 UNC 长路径前缀 (\\?\)
        #[cfg(windows)]
        if display_str.starts_with("\\\\?\\") {
            display_str = display_str[4..].to_string();
        }
        
        info!("reading DNS cache from file: {}", display_str);
        let now = Instant::now();

        // 核心修复：计算时间冻结偏差（离线时长）
        let offline_duration = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|sys_time| std::time::SystemTime::now().duration_since(sys_time).ok())
            .unwrap_or(Duration::ZERO);

        // 🔐 P2：先把整个文件读进来，再"认头 → 尽力挽救"。
        // 以前是"任何一条读错 → 整份作废 → 删掉整个文件"，且不管什么原因都只报一句 corrupted。
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(err) => {
                error!("failed to read DNS cache file {}: {}", display_str, err);
                return;
            }
        };

        let mut payload: &[u8] = &data;
        let mut declared: Option<u32> = None;

        // 🔐 P2：有文件头才分得清"版本不兼容"和"文件损坏" —— 这正是加头的意义。
        if let Some((version, entries_in_file)) = parse_cache_header(&data) {
            if version != CACHE_FORMAT_VERSION {
                let archived = archive_cache_file(path, &format!("v{version}-incompatible"));
                error!(
                    "缓存文件 {} 的格式版本是 v{}，本程序只认 v{}：**未删除**，已改名存档为 {}；本次按冷启动继续运行",
                    display_str,
                    version,
                    CACHE_FORMAT_VERSION,
                    archived
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(存档失败，原文件保留)".to_string()),
                );
                return;
            }

            declared = Some(entries_in_file);
            payload = &data[CACHE_HEADER_LEN..];
        } else {
            info!("缓存文件没有文件头：按旧格式读取（本次兼容；下次落盘会补上头）");
        }

        let (entries, stopped_at) = deserialize_best_effort(payload);

        if let Some(err) = stopped_at.as_ref() {
            let archived = archive_cache_file(path, "corrupt");
            error!(
                "缓存文件 {} 读取中断：{}（文件声明 {} 条，已挽救 {} 条）—— **未删除**，已改名存档为 {}",
                display_str,
                err,
                declared.map(|c| c.to_string()).unwrap_or_else(|| "未知".to_string()),
                entries.len(),
                archived
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(存档失败，原文件保留)".to_string()),
            );
        }

        let count = entries.len();
        for mut entry in entries {
            // ... 冻结时间扣除逻辑保持原样 ...
            if entry.valid_until > now {
                let remaining = entry.valid_until - now;
                if remaining > offline_duration {
                    entry.valid_until -= offline_duration;
                } else {
                    // 离线时间太长，已经过期，将其推入死亡状态
                    entry.valid_until = now - (offline_duration - remaining);
                }
            } else {
                entry.valid_until -= offline_duration; 
            }

            let query = entry.data.query().clone();
            let group = entry.data.name_server_group().unwrap_or("default").to_string();
            let key = CacheKey { query, group, ecs: entry.ecs.clone() };
            
            let mut cache = self.get_shard(&key).lock().unwrap_or_else(|e| e.into_inner());
            cache.put(key, entry);
        }
        info!(
            "DNS cache {} records loaded (offset {}s), elapsed {:?}",
            count,
            offline_duration.as_secs(),
            now.elapsed()
        );
    }

    pub fn total_len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len()).sum()
    }
}

/// 缓存文件的魔数（8 字节，hexdump 一眼可辨）
const CACHE_MAGIC: &[u8; 8] = b"SMCACHE\0";
/// 缓存文件的格式版本。**改动记录格式时必须 +1**（这样旧程序读到新文件能说清"版本不兼容"）
const CACHE_FORMAT_VERSION: u16 = 1;
/// 文件头长度：魔数 8 + 版本 2 + 条目数 4
const CACHE_HEADER_LEN: usize = 14;
/// 替换缓存文件失败时的重试次数与间隔（200ms × 2）
const PERSIST_RENAME_RETRIES: usize = 2;
const PERSIST_RENAME_RETRY_MS: u64 = 200;
/// 落盘互斥：周期落盘与退出落盘串行，避免两个线程写同一个临时档（撕裂档 → 下次读失败 → 整份删档）
static PERSIST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 写入缓存文件头：魔数 + 格式版本 + 条目数（little-endian）
fn emit_cache_header(buf: &mut Vec<u8>, entry_count: u32) {
    buf.extend_from_slice(CACHE_MAGIC);
    buf.extend_from_slice(&CACHE_FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(&entry_count.to_le_bytes());
}

/// 解析缓存文件头；返回 (格式版本, 文件里声明的条目数)。
/// 不是本格式（即没有文件头的**旧版**缓存文件）返回 None，由调用方按旧格式兼容读取。
fn parse_cache_header(data: &[u8]) -> Option<(u16, u32)> {
    if data.len() < CACHE_HEADER_LEN || &data[..8] != CACHE_MAGIC {
        return None;
    }

    let version = u16::from_le_bytes([data[8], data[9]]);
    let count = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
    Some((version, count))
}

/// 🔐 P2：**尽力挽救**式解析 —— 遇到坏条目就停在那里，保留前面已经解析出来的条目。
///
/// 以前是"任何一条出错就整份作废"，再由调用方删掉整个文件：几万条里坏一条，全没。
/// 现在返回 (救回的条目, 停下来的原因)；全部读成功时第二个值为 None。
fn deserialize_best_effort(data: &[u8]) -> (Vec<DnsCacheEntry>, Option<ProtoError>) {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let mut decoder = BinDecoder::new(&data[offset..]);
        match DnsCacheEntry::read(&mut decoder) {
            Ok(entry) => {
                let consumed = decoder.index();
                if consumed == 0 {
                    // 防御：解析器没前进就必须停下，否则死循环
                    return (entries, Some(DecodeError::InsufficientBytes.into()));
                }
                entries.push(entry);
                offset += consumed;
            }
            Err(err) => return (entries, Some(err)),
        }
    }

    (entries, None)
}

/// 🔐 P2：坏档 / 版本不兼容档**不直接删**，改名存档（只保留最近 1 份），便于用户排查。
fn archive_cache_file(path: &Path, tag: &str) -> Option<PathBuf> {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let file_name = path.file_name()?.to_string_lossy().to_string();
    let archived = path.with_file_name(format!("{file_name}.{tag}-{stamp}"));

    if let Err(err) = std::fs::rename(path, &archived) {
        error!(
            "缓存文件改名存档失败（{} → {}）：{}。原文件保留不动。",
            path.display(),
            archived.display(),
            err
        );
        return None;
    }

    // 只留最近 1 份存档（含历史遗留的临时档），免得长期占磁盘
    if let Some(dir) = path.parent()
        && let Ok(entries) = std::fs::read_dir(dir) {
            let prefix = format!("{file_name}.");
            let mut siblings: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p != &archived
                        && p.file_name()
                            .map(|n| n.to_string_lossy().starts_with(&prefix))
                            .unwrap_or(false)
                })
                .collect();
            siblings.sort();
            for old in &siblings {
                let _ = std::fs::remove_file(old);
            }
        }

    Some(archived)
}

#[derive(Debug, Clone, Copy)]
enum CacheStatus {
    Valid,
    Expired,
}

#[derive(Deserialize, Serialize)]
pub struct CachedQueryRecord {
    name: Name,
    hits: usize,
    last_access: DateTime<Local>,
    query_type: RecordType,
    query_class: DNSClass,
    records: Box<[Record]>,
}

#[derive(Clone)]
struct DnsCacheEntry<T = DnsResponse> {
    data: T,
    valid_until: Instant,
    is_in_prefetching: bool,
    stats: DnsCacheStats,
    ecs: Option<String>, // 🌟 保存 ECS 以备持久化恢复
}

impl<T> DnsCacheEntry<T> {
    fn new(data: T, valid_until: Instant, ecs: Option<String>) -> Self {
        Self {
            data,
            valid_until,
            is_in_prefetching: false,
            stats: DnsCacheStats::new(),
            ecs,
        }
    }

    fn set_data(&mut self, data: T) {
        self.data = data;
        self.is_in_prefetching = false;
    }

    fn set_valid_until(&mut self, valid_until: Instant) {
        self.valid_until = valid_until;
    }

    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }

    fn ttl(&self, now: Instant) -> Duration {
        self.valid_until.saturating_duration_since(now)
    }
}

#[derive(Clone)]
struct DnsCacheStats {
    hits: usize,
    last_access: DateTime<Local>,
	last_access_ins: std::time::Instant,
}

impl DnsCacheStats {
    fn new() -> Self {
        Self {
            hits: 0,
            last_access: Local::now(),
			last_access_ins: std::time::Instant::now(),
        }
    }

    fn hit(&mut self) {
        self.hits += 1;
        self.last_access = Local::now();
    }
}

use crate::libdns::proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder, DecodeError,
};

impl BinEncodable for DnsCacheEntry<DnsResponse> {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), ProtoError> {
        let res = &self.data;

        encoder.emit_u8(1)?;
        res.deref().emit(encoder)?;

        let now = Instant::now();
        if self.valid_until > now {
            encoder.emit_u8(2)?;
            let ttl = (self.valid_until - now).as_secs() as u32;
            encoder.emit_u32(ttl)?;
        } else {
            encoder.emit_u8(5)?;
            let dead_for = (now - self.valid_until).as_secs() as u32;
            encoder.emit_u32(dead_for)?;
        }

        encoder.emit_u8(3)?;
        if let Some(group_name) = res.name_server_group().map(|n| n.as_bytes()) {
            encoder.emit_u16(group_name.len() as u16)?;
            encoder.emit_vec(group_name)?;
        } else {
            encoder.emit_u16(0)?;
        }

        encoder.emit_u8(4)?;
        encoder.emit_u32(self.stats.hits as u32)?;

        // 🌟 序列化 ECS 数据（向前兼容设计）
        encoder.emit_u8(6)?;
        if let Some(ecs_str) = &self.ecs {
            let bytes = ecs_str.as_bytes();
            encoder.emit_u16(bytes.len() as u16)?;
            encoder.emit_vec(bytes)?;
        } else {
            encoder.emit_u16(0)?;
        }

        Ok(())
    }
}

impl<'r> BinDecodable<'r> for DnsCacheEntry {
    fn read(decoder: &mut BinDecoder<'r>) -> Result<Self, ProtoError> {
        if !decoder.read_u8()?.verify(|v| *v == 1).is_valid() {
            return Err(DecodeError::InsufficientBytes.into());
        }
        let message = Message::read(decoder)?;

        let tag = decoder.read_u8()?.unverified();
        let valid_until = if tag == 2 {
            let ttl_secs = decoder.read_u32()?.unverified();
            Instant::now() + Duration::from_secs(ttl_secs as u64)
        } else if tag == 5 {
            let dead_for_secs = decoder.read_u32()?.unverified();
            Instant::now() - Duration::from_secs(dead_for_secs as u64)
        } else {
            return Err(DecodeError::InsufficientBytes.into());
        };

        if !decoder.read_u8()?.verify(|v| *v == 3).is_valid() {
            return Err(DecodeError::InsufficientBytes.into());
        }
        let group_name = {
            let name_len = decoder.read_u16()?.unverified();
            if name_len > 0 {
                let name_bytes = decoder.read_slice(name_len as usize)?.unverified();
                String::from_utf8(name_bytes.to_vec()).ok()
            } else {
                None
            }
        };

        if !decoder.read_u8()?.verify(|v| *v == 4).is_valid() {
            return Err(DecodeError::InsufficientBytes.into());
        }
        let hits = decoder.read_u32()?.unverified();

        // 🌟 安全读取 ECS 字段，如果读不到说明是旧版缓存文件，兼容降级
        let mut ecs = None;
        if let Ok(tag) = decoder.read_u8()
            && tag.unverified() == 6
                && let Ok(len) = decoder.read_u16() {
                    let len = len.unverified();
                    if len > 0
                        && let Ok(bytes) = decoder.read_slice(len as usize) {
                            ecs = String::from_utf8(bytes.unverified().to_vec()).ok();
                        }
                }

        let mut res: DnsResponse = message.into();
        res = res.with_valid_until(valid_until);
        if let Some(g) = group_name {
            res = res.with_name_server_group(g);
        }
        let mut entry = DnsCacheEntry::new(res, valid_until, ecs);
        entry.stats.hits = hits as usize;

        Ok(entry)
    }
}

impl DnsCacheEntry {
    fn serialize_many<'a>(
        entries: impl Iterator<Item = &'a DnsCacheEntry>,
        writer: &mut impl std::io::Write,
    ) -> Result<(), ProtoError> {
        let mut buf = vec![];

        for entry in entries {
            buf.clear();
            let mut encoder = BinEncoder::new(&mut buf);
            if (*entry).emit(&mut encoder).is_ok() {
                let _ = writer.write_all(&buf);
            }
        }
        Ok(())
    }

    fn deserialize_many(data: &[u8]) -> Result<Vec<DnsCacheEntry>, ProtoError> {
        let mut entries = vec![];
        let mut offset = 0;

        while offset < data.len() {
            let mut decoder = BinDecoder::new(&data[offset..]);
            entries.push(DnsCacheEntry::read(&mut decoder)?);
            offset += decoder.index();
        }

        Ok(entries)
    }
}

struct PrefetchGuard {
    cache: Arc<DnsCache>,
    key: CacheKey,
}

impl Drop for PrefetchGuard {
    fn drop(&mut self) {
        let mut cache = self.cache.get_shard(&self.key).lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(&self.key) {
            entry.is_in_prefetching = false;
        }
    }
}

struct InflightCacheGuard {
    inflight: Arc<Mutex<std::collections::HashMap<CacheKey, tokio::sync::broadcast::Sender<Option<DnsResponse>>>>>,
    key: CacheKey,
    done: bool,
}

impl Drop for InflightCacheGuard {
    fn drop(&mut self) {
        if !self.done {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.remove(&self.key) {
                let _ = tx.send(None); 
            }
        }
    }
}

#[cfg(test)]
mod cache_reload_tests {
    use super::*;

    /// 🔐 P2：热重载必须把缓存策略真正换掉。
    /// 原来 `with_cache` 复用同一个 Arc<DnsCache>，于是改完 serve-expired 之后
    /// "一部分生效一部分不生效"，同一次请求会走两套互相矛盾的判断。
    #[test]
    fn reload_config_updates_policy_in_place() {
        let cache = DnsCache::new(1024, false, 0, 0, 0);
        assert!(!cache.serve_expired());
        assert_eq!(cache.expired_reply_ttl(), 0);

        let cfg = RuntimeConfig::builder()
            .with("serve-expired yes")
            .with("serve-expired-ttl 1800")
            .with("serve-expired-reply-ttl 42")
            .with("serve-expired-prefetch-time 7")
            .build()
            .unwrap();

        cache.reload_config(&cfg);

        assert!(cache.serve_expired(), "serve-expired 应即时生效");
        assert_eq!(cache.expired_ttl(), 1800);
        assert_eq!(cache.expired_reply_ttl(), 42, "过期答复的 TTL 应即时生效");
        assert_eq!(cache.expired_prefetch_time(), 7);
    }

    /// 容量变更无法就地生效（分片容量启动时固定），但记录的值要跟着配置更新，
    /// 并走"如实告警"那条分支 —— 而不是静默装作已生效。
    #[test]
    fn reload_config_records_new_cache_size() {
        let cache = DnsCache::new(1024, false, 0, 0, 0);
        assert_eq!(cache.cache_size.load(Ordering::Relaxed), 1024);

        let cfg = RuntimeConfig::builder()
            .with("cache-size 4096")
            .build()
            .unwrap();
        cache.reload_config(&cfg);

        assert_eq!(cache.cache_size.load(Ordering::Relaxed), 4096);
    }

    /// 造 n 条测试缓存记录（A 记录，TTL 300 秒）
    fn make_test_entries(n: usize) -> Vec<DnsCacheEntry> {
        use crate::libdns::proto::{
            op::{Message, Query},
            rr::{Name, RData, Record, RecordType},
        };
        use std::net::Ipv4Addr;

        (0..n)
            .map(|i| {
                let name = Name::from_ascii(format!("t{i}.cache.test.")).unwrap();
                let mut msg = Message::query();
                msg.add_query(Query::query(name.clone(), RecordType::A));
                msg.add_answer(Record::from_rdata(
                    name,
                    300,
                    RData::A(Ipv4Addr::new(10, 0, 0, i as u8 + 1).into()),
                ));
                let res: DnsResponse = msg.into();
                DnsCacheEntry::new(res, Instant::now() + Duration::from_secs(300), None)
            })
            .collect()
    }

    /// 🔐 P2：缓存文件头 —— 写进去必须能原样认出来；旧版"无头"文件必须仍被判为旧格式。
    #[test]
    fn cache_header_roundtrip_and_legacy_detection() {
        let mut buf = Vec::new();
        emit_cache_header(&mut buf, 12345);
        assert_eq!(buf.len(), CACHE_HEADER_LEN);
        assert_eq!(&buf[..8], CACHE_MAGIC, "文件开头必须是魔数");

        let (version, count) = parse_cache_header(&buf).expect("应能认出自己写的头");
        assert_eq!(version, CACHE_FORMAT_VERSION);
        assert_eq!(count, 12345);

        // 旧版无头文件：不能误判成"有头"
        let legacy = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(parse_cache_header(legacy).is_none(), "无头文件必须被判为旧格式");

        // 太短/空文件也不能崩
        assert!(parse_cache_header(b"SMCA").is_none());
        assert!(parse_cache_header(&[]).is_none());
    }

    /// 🔐 P2：**尽力挽救** —— 尾部被截断时，坏条目前面那些必须救回来（以前是整份作废 + 删档）。
    #[test]
    fn best_effort_salvages_prefix_of_truncated_file() {
        let entries = make_test_entries(3);
        let mut buf = Vec::new();
        DnsCacheEntry::serialize_many(entries.iter(), &mut buf).unwrap();
        assert!(!buf.is_empty());

        let (all, stopped) = deserialize_best_effort(&buf);
        assert_eq!(all.len(), 3, "完整数据应能读全 3 条");
        assert!(stopped.is_none(), "完整数据不该报「读到坏条目就停了」");

        // 砍掉最后 5 个字节：必须救回 2 条，并给出停下来的原因
        let truncated = &buf[..buf.len() - 5];
        let (salvaged, stopped) = deserialize_best_effort(truncated);
        assert_eq!(salvaged.len(), 2, "尾部坏掉的第 3 条不该连累前面 2 条");
        assert!(stopped.is_some(), "必须报告「读到坏条目就停了」");
    }

    /// 🔐 P2：坏档/不兼容档**改名存档**而不是删除，并且只保留最近 1 份。
    #[test]
    fn archive_keeps_latest_snapshot_only() {
        let dir = std::env::temp_dir().join(format!("smartdns-cache-arch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("smartdns.cache");

        // 先造一份"历史存档"，验证只留最近 1 份
        std::fs::write(path.with_file_name("smartdns.cache.old-20200101-000000"), b"old").unwrap();
        std::fs::write(&path, b"current").unwrap();

        let archived = archive_cache_file(&path, "corrupt").expect("应能改名存档");
        assert!(!path.exists(), "原文件应被改名（不再留在原位置）");
        assert!(archived.exists(), "存档必须存在 —— 是改名，不是删除");
        assert_eq!(std::fs::read(&archived).unwrap(), b"current");

        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left.len(), 1, "只应保留最近 1 份存档，实际还有 {left:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 P2：落盘必须写出文件头，且"读回来"能拿到同样的条目（完整往返）；
    /// 反复落盘要能覆盖同一个文件、不留临时档。
    #[test]
    fn persist_writes_header_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("smartdns-cache-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("smartdns.cache");

        let cache = DnsCache::new(1024, false, 0, 0, 0);
        for entry in make_test_entries(2) {
            let query = entry.data.query().clone();
            let key = CacheKey { query, group: "default".to_string(), ecs: None };
            cache
                .get_shard(&key)
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .put(key, entry);
        }
        assert_eq!(cache.total_len(), 2);

        cache.persist_cache(&path);

        let data = std::fs::read(&path).expect("落盘后文件应存在");
        let (version, count) = parse_cache_header(&data).expect("落盘必须写文件头");
        assert_eq!(version, CACHE_FORMAT_VERSION);
        assert_eq!(count, 2, "头里的条目数应等于缓存里的条目数");

        // 读回来必须拿到同样的 2 条，且没有"读坏"的中断
        let (entries, stopped) = deserialize_best_effort(&data[CACHE_HEADER_LEN..]);
        assert_eq!(entries.len(), 2);
        assert!(stopped.is_none());

        // 再落一次：应当直接覆盖同一个文件（不依赖"先删旧档"），且不留临时档
        cache.persist_cache(&path);
        let again = std::fs::read(&path).unwrap();
        assert!(parse_cache_header(&again).is_some(), "第二次落盘后文件仍应是合法格式");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "不该留下临时档，实际有 {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 P2：替换失败时**绝不破坏旧档**（旧版本是"先删旧档再改名"，失败就一份都没有了）。
    /// 这里用一个"非空目录"占住目标路径，让 rename 必然失败。
    #[test]
    fn persist_keeps_old_file_when_replace_fails() {
        let dir = std::env::temp_dir().join(format!("smartdns-cache-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("smartdns.cache");

        // 目标位置放一个非空目录：rename(文件 → 非空目录) 在任何平台都会失败
        std::fs::create_dir_all(path.join("occupied")).unwrap();
        std::fs::write(path.join("occupied").join("keep.txt"), b"old-must-survive").unwrap();

        let cache = DnsCache::new(1024, false, 0, 0, 0);
        cache.persist_cache(&path); // 失败路径：只应当打日志，不得 panic、不得删掉旧档

        assert!(path.is_dir(), "替换失败后，原位置的东西（这里是目录）必须还在");
        assert_eq!(
            std::fs::read(path.join("occupied").join("keep.txt")).unwrap(),
            b"old-must-survive",
            "旧档内容必须完好无损"
        );
        // 新档应被保留在临时文件里（下次还能用），而不是被丢掉
        let tmp: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert_eq!(tmp.len(), 1, "新档应保留在临时文件里，实际 {tmp:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
