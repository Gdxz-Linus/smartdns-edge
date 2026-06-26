use chrono::DateTime;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
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
                    // 顺手把那个坏掉的文件删了，防止下次开机又崩溃
                    let _ = std::fs::remove_file(&cache_file);
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
                                let opts = ServerOpts {
                                    is_background: true,
                                    rule_group: Some(cache_key.group.clone()),
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
                    Some(format!("{}/{}", subnet.addr(), subnet.scope_prefix()))
                }
                _ => None,
            })
            .or_else(|| ctx.domain_rule.get_ref(|r| r.subnet.as_ref()).map(|s| format!("{}/{}", s.addr(), s.scope_prefix())));

        let cache_key = CacheKey {
            query: req.query().original().to_owned(),
            group: ctx.server_group_name().to_string(),
            ecs: ecs_str.clone(),
        };

        let cached_res = if ctx.server_opts.is_background {
            None
        } else {
            let no_serve_expired = ctx
                .domain_rule
                .get(|r| r.no_serve_expired)
                .unwrap_or_default();

            let cached_res = self.cache.get(&cache_key, Instant::now()).await;

            match cached_res {
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
                                let reply_ttl = Duration::from_secs(self.cache.expired_reply_ttl as u64);
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
                                        _ => unreachable!(),
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
                            let reply_ttl_secs = self.cache.expired_reply_ttl as u32;
                            let mut fallback_res = res;
                            fallback_res.set_new_ttl(reply_ttl_secs);
                            debug!("name: {} {} using caching (Expired) (ECS: {:?})", cache_key.query.name(), cache_key.query.query_type(), cache_key.ecs);
                            ctx.source = LookupFrom::Cache;
                            return Ok(fallback_res); 
                        }
                        _ => Some(res),
                    }
                }
                _ => None,
            }
        };

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
                    self.cache.insert_full_response(cache_key.clone(), lookup.clone(), Instant::now()).await;

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
                        self.cache.insert_full_response(extra_key, extra_resp, Instant::now()).await;
                    }

                    if ctx.cfg().prefetch_domain() {
                        if let Some(ttl) = lookup.min_ttl() {
                            self.cache.prefetch_notify
                                .notify_after(Duration::from_secs(ttl as u64))
                                .await;
                        }
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
                if let Some(res) = cached_res {
                    return Ok(res);
                }
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
    serve_expired: bool,
    expired_ttl: u64,
    expired_reply_ttl: u64,
    expired_prefetch_time: u64,
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
            serve_expired,
            expired_ttl,
            expired_reply_ttl,
            expired_prefetch_time,
            prefetch_notify: Arc::new(DomainPrefetchingNotify::new()),
        }
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
        if let Some(entry) = cache.get_mut(key) {
            if entry.valid_until < new_valid_until {
                entry.valid_until = new_valid_until;
            }
        }
    }

    pub async fn purge_dead_records(&self, now: Instant) -> usize {
        let mut count = 0;
        let grace_period = if self.serve_expired { Duration::from_secs(self.expired_ttl) } else { Duration::ZERO };

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
                if let RData::SOA(soa_data) = soa.data() { negative_ttl = negative_ttl.min(soa_data.minimum() as u32); }
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

        let shards = self.shards.clone();
        let lookup = cache_resp.clone();
        tokio::spawn(async move {
            use std::hash::{Hash, Hasher};
            use std::collections::hash_map::DefaultHasher;
            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            let idx = (hasher.finish() as usize) & (SHARD_COUNT - 1);

            let mut cache = shards[idx].lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.get_mut(&key) {
                // 🌟 1. 覆写旧缓存：用预取回来的新鲜数据（新IP）和新寿命（TTL）彻底覆盖旧数据
                entry.data = cache_resp;
                entry.valid_until = valid_until;
                entry.is_in_prefetching = false;
                
                // 🌟 2. 核心修复：彻底消灭僵尸缓存！
                // 将历史访问次数重置为 1（清零+1）。
                // 剥夺它的免死金牌，它必须在新的生命周期里再次被用户真实访问（>=2），才有资格被再次预取！
                entry.stats.hits = 1; 
                
            } else {
                // 如果是全新插入的缓存，默认 hits 会在 new() 里面初始化为 0
                cache.put(key.clone(), DnsCacheEntry::new(cache_resp, valid_until, key.ecs.clone()));
            }
        });
        lookup
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

                    if self.serve_expired {
                        if entry.is_current(now) {
                            most_recent = most_recent.min(entry.ttl(now));
                            continue; 
                        }
                        if self.expired_prefetch_time > 0 {
                            let expired_for = now.saturating_duration_since(entry.valid_until).as_secs();
                            if expired_for < self.expired_prefetch_time { continue; }
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
        let cache_to_file = || {
            let tmp_path = path.with_extension("tmp");
            
            let mut file = File::options().create(true).truncate(true).write(true).open(&tmp_path)?;
            for shard in self.shards.iter() {
                let mut shard_buffer = Vec::new();
                {
                    let cache = shard.lock().unwrap_or_else(|e| e.into_inner());
                    DnsCacheEntry::serialize_many(cache.iter().map(|(_, entry)| entry), &mut shard_buffer)?;
                } 
                
                std::io::Write::write_all(&mut file, &shard_buffer)?;
            }
            
            file.sync_all()?;
            
            // 🌟 最小改动 4：强制释放文件句柄，彻底解决 Windows 独占导致 rename 失败的 183/32 报错
            drop(file);
            
            // 在 Windows 系统下，安全覆盖必须先删旧文件
            #[cfg(windows)]
            let _ = std::fs::remove_file(path);
            
            std::fs::rename(&tmp_path, path)?;
            
            Ok::<_, ProtoError>(())
        };

        match cache_to_file() {
            // 🌟 核心修复 3：将 {:?} 改为 "{}"，并调用 .display() 消除转义字符！
            // 让输出符合人类正常的阅读习惯，不再出现 \\ 这种反人类转义。
            Ok(_) => info!("save DNS cache to file \"{}\" successfully.", path.display()),
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

        let read_from_cache_file = || -> Result<Vec<DnsCacheEntry>, ProtoError> {
            let mut file = File::options().read(true).open(path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;

            // 🌟 核心防御：反序列化本身可能因为文件截断而抛出普通的 Error
            DnsCacheEntry::deserialize_many(&data)
        };

        match read_from_cache_file() {
            Ok(entries) => {
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
            Err(err) => {
                // 如果是常规的文件解析错误，走到这里报错，并顺手把坏档删了
                error!("🔥 failed to read DNS cache file, file might be corrupted: {}. Ignored.", err);
                let _ = std::fs::remove_file(path);
            }
        }
    }

    pub fn total_len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len()).sum()
    }
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
        if let Ok(tag) = decoder.read_u8() {
            if tag.unverified() == 6 {
                if let Ok(len) = decoder.read_u16() {
                    let len = len.unverified();
                    if len > 0 {
                        if let Ok(bytes) = decoder.read_slice(len as usize) {
                            ecs = String::from_utf8(bytes.unverified().to_vec()).ok();
                        }
                    }
                }
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
            buf.truncate(0);
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
