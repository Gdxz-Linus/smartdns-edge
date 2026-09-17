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

use crate::config::AnswerAffectingOpts;
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
use tokio_util::sync::CancellationToken;

// 🌟 核心升维：全局唯一的安全缓存主键
// 彻底杜绝 EDNS0 ECS 导致的跨地域缓存污染与多分组重写踩踏！
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub query: Query,
    pub group: String,
    pub ecs: Option<String>,
    /// 📌 会影响"答案内容"的监听级选项（见 `AnswerAffectingOpts` 的说明）。
    /// 不进标记的后果实测过：一个监听写 `-no-speed-check`、另一个不写时，两边会互相借用
    /// 对方算出来的答案，且"谁先查谁说了算"。
    pub opts: AnswerAffectingOpts,
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

        // 🔐 A8（2026-09-17）：持久化这三项（cache-persist / cache-file / cache-checkpoint-time）
        // 原来改了等于没改 —— 周期落盘任务在启动时一次性建死（路径和节拍当场抄在自己身上），
        // 重载路径管都不管。现在按新配置停掉/重建；并且运行期"从关到开"时顺带把磁盘上
        // 已有的缓存读回来（只补内存里没有的条目，绝不覆盖运行期已经拿到的更新答案）。
        // 🔐 域名预取同样是"启动时才判断一次"的老毛病，这里一并按新配置停/建。
        Self::sync_prefetch_task(cfg, &cache, dns_handle.clone());

        let started_from_off = Self::sync_persist_task(cfg, &cache);
        if started_from_off {
            let cache_file = cfg.cache_file();
            if cache_file.exists() {
                let cache_for_load = cache.clone();
                // 运行期读档不拖住重载本身：丢给阻塞线程池去做
                tokio::task::spawn_blocking(move || cache_for_load.load_cache_only_missing(&cache_file));
            }
        }

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

    /// 🔐 A8：让"周期落盘任务"跟着（新）配置走 —— 该停的停、该按新路径/新节拍重建的重建。
    ///
    /// 返回 `true` 表示这次是**从"没有任务"变成"有任务"**（即运行期刚把持久化打开），
    /// 调用方可以据此顺带把磁盘上已有的缓存读回来。
    fn sync_persist_task(cfg: &Arc<RuntimeConfig>, cache: &Arc<DnsCache>) -> bool {
        let want: Option<(PathBuf, u64)> = if cfg.cache_persist() {
            Some((cfg.cache_file(), cfg.cache_checkpoint_time()))
        } else {
            None
        };

        let mut slot = cache
            .persist_task
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let current: Option<(PathBuf, u64)> =
            slot.as_ref().map(|t| (t.file.clone(), t.checkpoint_secs));

        let action = persist_action(
            current.as_ref().map(|(f, c)| (f.as_path(), *c)),
            want.as_ref().map(|(f, c)| (f.as_path(), *c)),
        );

        match action {
            PersistAction::Keep => false,
            PersistAction::Stop => {
                if let Some(old) = slot.take() {
                    old.cancel.cancel();
                }
                log::info!("缓存持久化：已按新配置关闭，周期落盘任务停止（内存缓存不再往硬盘写）");
                false
            }
            PersistAction::Restart {
                file,
                checkpoint_secs,
            } => {
                if let Some(old) = slot.take() {
                    old.cancel.cancel();
                }
                let task = spawn_persist_task(cache, file.clone(), checkpoint_secs);
                match current.as_ref() {
                    None => log::info!(
                        "缓存持久化：已打开 —— 立刻开始周期落盘（每 {} 秒一次，写入 {}）",
                        checkpoint_secs,
                        file.display()
                    ),
                    Some((old_file, old_cadence)) => {
                        if old_file != &file {
                            log::info!(
                                "缓存持久化：落盘路径已从 {} 改为 {}（周期落盘已按新路径重建，旧任务已停）",
                                old_file.display(),
                                file.display()
                            );
                        }
                        if *old_cadence != checkpoint_secs {
                            log::info!(
                                "缓存持久化：落盘节拍已从 {} 秒改为 {} 秒",
                                old_cadence,
                                checkpoint_secs
                            );
                        }
                    }
                }
                *slot = Some(task);
                current.is_none()
            }
        }
    }

    fn spawn_background_tasks(cfg: &Arc<RuntimeConfig>, cache: &Arc<DnsCache>, client_handle: DnsHandle) {
        // 🔐 A8（2026-09-17）：周期落盘任务改由 `sync_persist_task` 统一管理 ——
        // 启动时按配置建一个，热重载时按新配置停掉/重建（原来是在这里一次性建死，
        // 于是运行期改 cache-persist / cache-file / cache-checkpoint-time 全都半生效）。
        // 这里剩下的两个后台任务与这三项配置无关：缓存 GC 与域名预取。
        Self::sync_persist_task(cfg, cache);

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

        Self::sync_prefetch_task(cfg, cache, client_handle);
    }

    /// 🔐 域名预取任务：运行期把 `prefetch-domain` 打开/关掉也都要**即时生效**。
    ///
    /// 原来只在启动时判断一次（`if cfg.prefetch_domain()` 里直接把任务建死），于是运行期
    /// "关→开"改了不生效：查询路径上那道闸门（`ctx.cfg().prefetch_domain()`）会开始发预取通知，
    /// 但**没有任务在听**，到期的条目一直没人刷新，直到重启才恢复。
    /// （反方向"开→关"因为查询路径那道闸门本来就按新配置走，实际上会停 —— 但任务还挂着，
    ///   这里一并按新配置把任务收掉，让"关了就是真关"。）
    fn sync_prefetch_task(cfg: &Arc<RuntimeConfig>, cache: &Arc<DnsCache>, client: DnsHandle) {
        let want = cfg.prefetch_domain();
        let mut slot = cache
            .prefetch_task
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        match (slot.is_some(), want) {
            // 现状已符合配置：不动（避免每次重载都把任务停掉重建、白白丢掉 last_check 节流状态）
            (true, true) | (false, false) => {}
            (true, false) => {
                if let Some(cancel) = slot.take() {
                    cancel.cancel();
                }
                log::info!("域名预取：已按新配置关闭（预取任务停止，到期条目不再自动刷新）");
            }
            (false, true) => {
                *slot = Some(spawn_prefetch_task(cache, client));
                log::info!("域名预取：已打开，立即生效（到期条目会按配置自动刷新）");
            }
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
            opts: AnswerAffectingOpts::from_server_opts(&ctx.server_opts),
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
                                        opts: cache_key.opts.clone(),
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
                            opts: AnswerAffectingOpts::from_server_opts(&ctx.server_opts),
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

/// 🔐 A8：一个"周期落盘"任务当前的形态 —— 热重载时拿它和新配置比对，决定要不要停掉重建。
struct PersistTask {
    /// 停这个任务的取消牌（`cancel()` 之后，任务在下一个循环点退出）
    cancel: CancellationToken,
    /// 建它时用的落盘路径
    file: PathBuf,
    /// 建它时用的落盘节拍（秒）
    checkpoint_secs: u64,
}

/// 🔐 A8：热重载时对"周期落盘任务"该做的动作（纯决策函数，各分支由单测直接覆盖）。
#[derive(Debug, PartialEq, Eq)]
enum PersistAction {
    /// 现状已经符合配置，什么都不用做
    Keep,
    /// 配置里关掉了持久化 → 停掉任务
    Stop,
    /// 没任务 → 建一个；路径或节拍变了 → 停掉重建
    Restart {
        file: PathBuf,
        checkpoint_secs: u64,
    },
}

/// 🔐 A8：比对"现在这个任务"和"配置想要的"，得出该做什么。
fn persist_action(current: Option<(&Path, u64)>, want: Option<(&Path, u64)>) -> PersistAction {
    match (current, want) {
        (None, None) => PersistAction::Keep,
        (Some(_), None) => PersistAction::Stop,
        (Some((cf, cc)), Some((wf, wc))) if cf == wf && cc == wc => PersistAction::Keep,
        (_, Some((wf, wc))) => PersistAction::Restart {
            file: wf.to_path_buf(),
            checkpoint_secs: wc,
        },
    }
}

/// 🔐 起一个域名预取任务，返回取消牌（运行期把 prefetch-domain 关掉时用它把任务停掉）。
///
/// 与周期落盘任务一样，任务句柄要挂在 `DnsCache` 上 —— 热重载会重建中间件、复用同一个
/// `Arc<DnsCache>`，挂中间件上就找不回来了。
fn spawn_prefetch_task(cache: &Arc<DnsCache>, client_handle: DnsHandle) -> CancellationToken {
    let cancel = CancellationToken::new();
    let cancel_in_task = cancel.clone();
    let prefetch_notify = cache.prefetch_notify.clone();
    let client = client_handle.with_new_opt(ServerOpts {
        is_background: true,
        ..Default::default()
    });
    let cache_weak = Arc::downgrade(cache);

    tokio::spawn(async move {
        let min_interval = Duration::from_secs(
            std::env::var("PREFETCH_MIN_INTERVAL")
                .as_deref()
                .unwrap_or("60")
                .parse()
                .unwrap_or(60),
        );
        let mut last_check = Instant::now();

        loop {
            tokio::select! {
                _ = prefetch_notify.notified() => {}
                // 🔐 运行期把 prefetch-domain 关掉 → 由重载路径把我们停掉
                _ = cancel_in_task.cancelled() => break,
                _ = crate::signal::terminate() => break,
            }

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
                        // 🔐 处理选项也要跟着复原：刷新必须按**原来那套口径**去算，
                        // 否则算出来的答案会写到"默认口径"的标记下面，这条永远刷不到。
                        let opts = cache_key.opts.into_server_opts(cache_key.group.clone());
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

    cancel
}

/// 🔐 A8：按给定路径与节拍起一个周期落盘任务，返回它的形态（供热重载时对比 / 停掉）。
fn spawn_persist_task(cache: &Arc<DnsCache>, file: PathBuf, checkpoint_secs: u64) -> PersistTask {
    let cancel = CancellationToken::new();
    let cancel_in_task = cancel.clone();
    let cache_weak = Arc::downgrade(cache);
    // 节拍最小 1 秒：`tokio::time::interval` 收到 0 会 panic，配置写成 0 时别把任务炸掉
    let checkpoint_secs = checkpoint_secs.max(1);
    let file_in_task = file.clone();

    tokio::spawn(async move {
        let checkpoint_duration = Duration::from_secs(checkpoint_secs);
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + checkpoint_duration,
            checkpoint_duration,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(c) = cache_weak.upgrade() {
                        let path = file_in_task.clone();
                        // 落盘依然是异步外包给 spawn_blocking，绝不影响主进程解析 DNS
                        tokio::task::spawn_blocking(move || c.persist_cache(path.as_path()));
                    } else {
                        break;
                    }
                }
                // 🔐 A8：配置改了（关掉持久化 / 换路径 / 改节拍）→ 由重载路径把我们停掉
                _ = cancel_in_task.cancelled() => break,
                _ = crate::signal::terminate() => break,
            };
        }
    });

    PersistTask {
        cancel,
        file,
        checkpoint_secs,
    }
}

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
    /// 🔐 A8：当前这个周期落盘任务长什么样（`None` = 没有任务，即持久化关着）。
    /// 句柄放在 `DnsCache` 里而不是中间件里 —— 热重载会重建中间件、但复用同一个
    /// `Arc<DnsCache>`，任务只有挂在这儿才能跨重载被找到并停掉。
    persist_task: Mutex<Option<PersistTask>>,
    /// 🔐 当前这个域名预取任务的取消牌（`None` = 没有任务，即预取关着）
    prefetch_task: Mutex<Option<CancellationToken>>,
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
            persist_task: Mutex::new(None),   // 🔐 A8：任务由 sync_persist_task 建，这里只是占位
            prefetch_task: Mutex::new(None),  // 🔐 任务由 sync_prefetch_task 建
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
            cache.put(
                key.clone(),
                DnsCacheEntry::new(
                    cache_resp.clone(),
                    valid_until,
                    key.ecs.clone(),
                    key.opts.clone(),
                ),
            );
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
	
    /// 启动时读档：文件里的条目**覆盖**内存（启动时内存本来就是空的，这是正常路径）。
    pub fn load_cache(&self, path: &Path) {
        self.load_cache_impl(path, false)
    }

    /// 🔐 A8：运行期"打开持久化"时读已有缓存 —— **只补内存里还没有的条目**。
    /// 运行期内存里可能已经有更新鲜的答案，绝不能用磁盘上的旧条目把它换回去。
    pub fn load_cache_only_missing(&self, path: &Path) {
        self.load_cache_impl(path, true)
    }

    fn load_cache_impl(&self, path: &Path, only_missing: bool) {
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
        let mut skipped = 0usize;
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
            let key = CacheKey {
                query,
                group,
                ecs: entry.ecs.clone(),
                opts: entry.opts.clone(),
            };
            
            let mut cache = self.get_shard(&key).lock().unwrap_or_else(|e| e.into_inner());
            if only_missing && cache.peek(&key).is_some() {
                // 🔐 A8：内存里已经有这个条目了（运行期刚查到的更新答案）→ 不覆盖
                skipped += 1;
                continue;
            }
            cache.put(key, entry);
        }
        if only_missing {
            info!(
                "DNS cache: {} records loaded from file ({} kept from memory), offset {}s, elapsed {:?}",
                count - skipped,
                skipped,
                offline_duration.as_secs(),
                now.elapsed()
            );
        } else {
            info!(
                "DNS cache {} records loaded (offset {}s), elapsed {:?}",
                count,
                offline_duration.as_secs(),
                now.elapsed()
            );
        }
    }

    pub fn total_len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len()).sum()
    }
}

/// 缓存文件的魔数（8 字节，hexdump 一眼可辨）
const CACHE_MAGIC: &[u8; 8] = b"SMCACHE\0";
/// 缓存文件的格式版本。**改动记录格式时必须 +1**（这样旧程序读到新文件能说清"版本不兼容"）
///
/// - v1：文件头 + 条目（message / TTL / 上游组 / 命中数 / ECS）
/// - v2（2026-09-17）：条目新增 tag 7 = "会影响答案的监听级选项"（见 `AnswerAffectingOpts`）。
///   缓存标记跟着变了，v1 的条目不能再当成本版本的口径使用，所以旧档一律按"版本不兼容"
///   改名存档、本次按冷启动继续（这条路径本来就有，见 `load_cache`）。
const CACHE_FORMAT_VERSION: u16 = 2;
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

/// 判断一个文件名是不是**我们自己产出**的缓存存档（`{原文件名}.{tag}-YYYYMMDD-HHMMSS`）。
///
/// 🔐 B6：清理旧存档时只许删自己造的文件 —— 用户在缓存目录里放的备份
///（`smartdns.cache.2024.bak`、`smartdns.cache.bak` 之类）不能被顺手删掉。
fn is_our_archive(file_name: &str, candidate: &str) -> bool {
    let Some(rest) = candidate.strip_prefix(&format!("{file_name}.")) else {
        return false;
    };
    let tag_ok = rest.starts_with("corrupt-")
        || rest.starts_with("load-panic-")
        || (rest.starts_with('v') && rest.contains("-incompatible-"));
    tag_ok && rest.len() > 15 && {
        // 末尾是 `YYYYMMDD-HHMMSS`
        let stamp = &rest[rest.len() - 15..];
        let b = stamp.as_bytes();
        b[8] == b'-' && b.iter().enumerate().all(|(i, c)| i == 8 || c.is_ascii_digit())
    }
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

    // 只留最近 1 份**我们自己产出的**存档，免得长期占磁盘。
    // 🔐 B6：旧实现按 `{缓存文件名}.*` 前缀一刀切，会把用户放在同一个目录里的备份
    //（例如 `smartdns.cache.2024.bak`）一起**静默**删掉。现在只认我们自己的命名：
    // `{缓存文件名}.{corrupt|load-panic|vN-incompatible}-YYYYMMDD-HHMMSS`，
    // 并且每次清理都在日志里点名删了哪个文件。
    if let Some(dir) = path.parent()
        && let Ok(entries) = std::fs::read_dir(dir) {
            let mut siblings: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p != &archived
                        && p.file_name()
                            .map(|n| is_our_archive(&file_name, &n.to_string_lossy()))
                            .unwrap_or(false)
                })
                .collect();
            siblings.sort();
            for old in &siblings {
                match std::fs::remove_file(old) {
                    Ok(()) => info!("清理旧缓存存档：{}", old.display()),
                    Err(err) => crate::log::warn!("清理旧缓存存档失败 {}：{}", old.display(), err),
                }
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
    /// 🌟 保存"会影响答案的监听级选项"以备持久化恢复 —— 重启后重建标记时要用它，
    /// 不然带 `-no-speed-check` 之类的条目会被当成默认口径的条目，又把答案串起来。
    opts: AnswerAffectingOpts,
}

impl<T> DnsCacheEntry<T> {
    fn new(data: T, valid_until: Instant, ecs: Option<String>, opts: AnswerAffectingOpts) -> Self {
        Self {
            data,
            valid_until,
            is_in_prefetching: false,
            stats: DnsCacheStats::new(),
            ecs,
            opts,
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

        // 🌟 序列化"会影响答案的监听级选项"（tag 7，v2 起）。用 JSON 存，便于人眼看缓存文件时看得懂；
        // 老文件没有这一段，读侧按默认值处理（何况格式版本已经 +1，老档会被当作不兼容存档）。
        encoder.emit_u8(7)?;
        let opt_bytes = serde_json::to_vec(&self.opts).unwrap_or_else(|_| b"{}".to_vec());
        encoder.emit_u16(opt_bytes.len() as u16)?;
        encoder.emit_vec(&opt_bytes)?;

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

        // 🌟 读取"会影响答案的监听级选项"（v2 新增，tag 7）。
        //
        // ⚠️ 必须**先偷看再决定吃不吃**：条目在文件里是**背靠背**排列的，没有分隔符，
        // 上一条读完之后紧跟的就是下一条的起始字节（恒为 tag 1）。如果这里无脑 read_u8()，
        // 读到的是下一条的 `0x01`，会被误判成"本条目里有未知 tag"→ 整份文件被判坏
        // （实测：无头旧格式文件会 0 条救回并改名存档）。
        //
        // 两种情形要分清：
        //   ① 后面不是 7（含读到文件尾）→ 本条没有这一段，按默认值，正常；
        //   ② 确实是 7、但内容读不全 / 不是合法 JSON（条目被截断）→ **必须报错**，
        //      让上层"读到坏条目就停下、并说明原因"，不能把半截条目当好条目救回来。
        let mut opts = AnswerAffectingOpts::default();
        if decoder.peek().map(|t| t.unverified()) == Some(7) {
            decoder.read_u8()?;
            let len = decoder.read_u16()?.unverified();
            let bytes = decoder.read_slice(len as usize)?.unverified();
            opts = serde_json::from_slice(bytes).map_err(|_| DecodeError::InsufficientBytes)?;
        }

        let mut res: DnsResponse = message.into();
        res = res.with_valid_until(valid_until);
        if let Some(g) = group_name {
            res = res.with_name_server_group(g);
        }
        let mut entry = DnsCacheEntry::new(res, valid_until, ecs, opts);
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
    /// 🔐 A8：热重载时对"周期落盘任务"该做什么 —— 开 / 关 / 换路径 / 换节拍 四种转换都要对。
    #[test]
    fn persist_action_covers_all_transitions() {
        let p1 = Path::new("smartdns.cache");
        let p2 = Path::new("another.cache");

        assert_eq!(
            persist_action(None, None),
            PersistAction::Keep,
            "本来没任务、配置也不要 → 什么都不做"
        );
        assert_eq!(
            persist_action(Some((p1, 2)), Some((p1, 2))),
            PersistAction::Keep,
            "路径与节拍都没变 → 不许白停白建"
        );
        assert_eq!(
            persist_action(Some((p1, 2)), None),
            PersistAction::Stop,
            "配置把持久化关掉了 → 停任务"
        );
        assert_eq!(
            persist_action(None, Some((p1, 2))),
            PersistAction::Restart {
                file: p1.to_path_buf(),
                checkpoint_secs: 2
            },
            "本来没任务、配置要开 → 建一个"
        );
        assert_eq!(
            persist_action(Some((p1, 2)), Some((p2, 2))),
            PersistAction::Restart {
                file: p2.to_path_buf(),
                checkpoint_secs: 2
            },
            "换了落盘路径 → 按新路径重建"
        );
        assert_eq!(
            persist_action(Some((p1, 2)), Some((p1, 30))),
            PersistAction::Restart {
                file: p1.to_path_buf(),
                checkpoint_secs: 30
            },
            "换了落盘节拍 → 按新节拍重建"
        );
    }

    /// 造一条指定名字/答案的缓存条目（A 记录）
    fn test_entry_for(name: &str, ip: std::net::Ipv4Addr) -> DnsCacheEntry {
        use crate::libdns::proto::{
            op::{Message, Query},
            rr::{Name, RData, Record, RecordType},
        };

        let name = Name::from_ascii(name).unwrap();
        let mut msg = Message::query();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(name, 300, RData::A(ip.into())));
        let res: DnsResponse = msg.into();
        DnsCacheEntry::new(
            res,
            Instant::now() + Duration::from_secs(300),
            None,
            AnswerAffectingOpts::default(),
        )
    }

    /// 取出条目对应的缓存标记（与实际入库时用的是同一套字段）
    fn test_key_of(entry: &DnsCacheEntry) -> CacheKey {
        CacheKey {
            query: entry.data.query().clone(),
            group: entry.data.name_server_group().unwrap_or("default").to_string(),
            ecs: entry.ecs.clone(),
            opts: entry.opts.clone(),
        }
    }

    /// 读回缓存里该标记当前的 A 记录答案
    fn cached_answer_ip(cache: &DnsCache, key: &CacheKey) -> Option<std::net::Ipv4Addr> {
        use crate::libdns::proto::rr::RData;

        let shard = cache.get_shard(key).lock().unwrap_or_else(|e| e.into_inner());
        let entry = shard.peek(key)?;
        entry.data.answers().iter().find_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
    }

    /// 🔐 A8：运行期"打开持久化"时读已有缓存档，**只补内存里没有的条目** ——
    /// 绝不能用磁盘上的旧答案把内存里更新的答案换回去。
    #[test]
    fn load_cache_only_missing_keeps_fresher_in_memory_entry() {
        let dir = std::env::temp_dir().join(format!("smartdns-cache-a8-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("smartdns.cache");

        // 磁盘上的旧答案：t0.cache.test. → 10.0.0.1
        let writer = DnsCache::new(1024, false, 0, 0, 0);
        let old = make_test_entries(1).remove(0);
        let key = test_key_of(&old);
        writer
            .get_shard(&key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key.clone(), old);
        writer.persist_cache(&path);
        assert!(path.exists(), "先得有一份缓存档");

        // 内存里的新答案：同一个名字 → 10.9.9.9
        let cache = DnsCache::new(1024, false, 0, 0, 0);
        let fresh = test_entry_for("t0.cache.test.", std::net::Ipv4Addr::new(10, 9, 9, 9));
        cache
            .get_shard(&key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key.clone(), fresh);

        cache.load_cache_only_missing(&path);
        assert_eq!(
            cached_answer_ip(&cache, &key),
            Some(std::net::Ipv4Addr::new(10, 9, 9, 9)),
            "内存里更新鲜的答案不许被磁盘旧档覆盖"
        );

        // 对照：启动路径的完整读档就是"文件说了算"（既有行为，不改）
        cache.load_cache(&path);
        assert_eq!(
            cached_answer_ip(&cache, &key),
            Some(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            "完整读档以文件为准（启动路径的既有行为）"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

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
                DnsCacheEntry::new(
                    res,
                    Instant::now() + Duration::from_secs(300),
                    None,
                    AnswerAffectingOpts::default(),
                )
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

        // 先造一份"历史存档"（用**我们真实的命名**），验证只留最近 1 份；
        // 再造一份"用户自己的备份"（不是我们产出的命名）—— 它必须原地不动（B6）。
        std::fs::write(
            path.with_file_name("smartdns.cache.corrupt-20200101-000000"),
            b"old",
        )
        .unwrap();
        std::fs::write(path.with_file_name("smartdns.cache.2024.bak"), b"user-backup").unwrap();
        std::fs::write(&path, b"current").unwrap();

        let archived = archive_cache_file(&path, "corrupt").expect("应能改名存档");
        assert!(!path.exists(), "原文件应被改名（不再留在原位置）");
        assert!(archived.exists(), "存档必须存在 —— 是改名，不是删除");
        assert_eq!(std::fs::read(&archived).unwrap(), b"current");

        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left.len(), 2, "应只剩【最新存档 + 用户的备份】，实际 {left:?}");
        assert!(
            left.iter().any(|n| n == "smartdns.cache.2024.bak"),
            "用户自己放在同目录的备份不许被删（B6）：{left:?}"
        );
        assert!(
            left.iter().any(|n| n.starts_with("smartdns.cache.corrupt-")),
            "应保留最新那份存档：{left:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔐 2026-09-17：缓存标记必须区分"会影响答案的监听级选项"。
    /// 不区分的话，一个监听写 `-no-speed-check`、另一个不写时，两边会互相借用对方算出来的答案。
    #[test]
    fn cache_key_separates_answer_affecting_opts() {
        use crate::libdns::proto::op::Query;
        use crate::libdns::proto::rr::{Name, RecordType};

        let query = Query::query(Name::from_ascii("sep.cache.test.").unwrap(), RecordType::A);
        let base = CacheKey {
            query: query.clone(),
            group: "default".to_string(),
            ecs: None,
            opts: AnswerAffectingOpts::default(),
        };

        // 只差一个 `-no-speed-check` → 必须是两个不同的标记
        let mut no_speed = ServerOpts::default();
        no_speed.no_speed_check = Some(true);
        let with_no_speed = CacheKey {
            opts: AnswerAffectingOpts::from_server_opts(&no_speed),
            ..base.clone()
        };
        assert_ne!(base, with_no_speed, "带 -no-speed-check 的监听不能与默认监听共用同一份缓存");

        // 不影响答案的选项（`-no-api` / 连接数上限）不许把缓存拆开
        let mut cosmetic = ServerOpts::default();
        cosmetic.no_api = Some(true);
        cosmetic.max_connections = Some(123);
        assert_eq!(
            base.opts,
            AnswerAffectingOpts::from_server_opts(&cosmetic),
            "不影响答案的选项（-no-api / 连接数上限）不该进标记，否则白白降低命中率"
        );

        // 其余每一项都要能区分开
        for (name, o) in [
            ("-no-dualstack-selection", {
                let mut o = ServerOpts::default();
                o.no_dualstack_selection = Some(true);
                o
            }),
            ("-force-aaaa-soa", {
                let mut o = ServerOpts::default();
                o.force_aaaa_soa = Some(true);
                o
            }),
            ("-force-https-soa", {
                let mut o = ServerOpts::default();
                o.force_https_soa = Some(true);
                o
            }),
            ("-no-rule-addr", {
                let mut o = ServerOpts::default();
                o.no_rule_addr = Some(true);
                o
            }),
            ("-no-rule-nameserver", {
                let mut o = ServerOpts::default();
                o.no_rule_nameserver = Some(true);
                o
            }),
            ("-no-rule-soa", {
                let mut o = ServerOpts::default();
                o.no_rule_soa = Some(true);
                o
            }),
        ] {
            let k = CacheKey { opts: AnswerAffectingOpts::from_server_opts(&o), ..base.clone() };
            assert_ne!(base, k, "{name} 会改变答案，必须体现在缓存标记里");
        }

        // rule_group 也要能区分
        let mut rg = ServerOpts::default();
        rg.rule_group = Some("guest".to_string());
        let k = CacheKey { opts: AnswerAffectingOpts::from_server_opts(&rg), ..base.clone() };
        assert_ne!(base, k, "rule_group 决定用哪套域名规则，必须体现在缓存标记里");
    }

    /// 🔐 2026-09-17：这组选项要能随条目落盘、再读回来（重启后重建标记时要用）。
    #[test]
    fn entry_round_trips_answer_affecting_opts() {
        let mut entries = make_test_entries(1);
        let mut opts = AnswerAffectingOpts::default();
        opts.no_speed_check = true;
        opts.rule_group = Some("guest".to_string());
        entries[0].opts = opts.clone();

        let mut buf = Vec::new();
        DnsCacheEntry::serialize_many(entries.iter(), &mut buf).unwrap();
        let (back, stopped) = deserialize_best_effort(&buf);
        assert!(stopped.is_none(), "不该读坏：{stopped:?}");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].opts, opts, "选项必须原样读回");
    }

    /// 🔐 2026-09-17：格式版本不认识时必须**改名存档**、按冷启动继续，绝不当成正常数据加载。
    #[test]
    fn version_mismatch_is_archived_and_not_loaded() {
        let dir = std::env::temp_dir().join(format!("smartdns-cache-ver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("smartdns.cache");

        // 造一份"未来版本"的缓存文件：头里版本号 +1，后面跟一条合法条目
        let mut payload = Vec::new();
        DnsCacheEntry::serialize_many(make_test_entries(1).iter(), &mut payload).unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(CACHE_MAGIC);
        data.extend_from_slice(&(CACHE_FORMAT_VERSION + 1).to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&payload);
        std::fs::write(&path, &data).unwrap();

        let cache = DnsCache::new(1024, false, 0, 0, 0);
        cache.load_cache(&path);
        assert_eq!(cache.total_len(), 0, "版本不兼容的缓存不许被加载");

        let archived: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("-incompatible"))
            .collect();
        assert_eq!(archived.len(), 1, "必须留下一个 -incompatible 的存档，实际 {archived:?}");

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
            let key = CacheKey {
                query,
                group: "default".to_string(),
                ecs: None,
                opts: AnswerAffectingOpts::default(),
            };
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

#[cfg(test)]
mod archive_naming_tests {
    use super::is_our_archive;

    /// 🔐 B6：清理旧存档时**只许删自己造的文件**，用户放在同目录的备份一份都不能动。
    #[test]
    fn only_our_own_archives_may_be_pruned() {
        // 我们产出的三种命名（tag 见 archive_cache_file 的调用点）
        assert!(is_our_archive("smartdns.cache", "smartdns.cache.corrupt-20260916-231530"));
        assert!(is_our_archive("smartdns.cache", "smartdns.cache.load-panic-20260101-000000"));
        assert!(is_our_archive(
            "smartdns.cache",
            "smartdns.cache.v2-incompatible-20260916-231530"
        ));
        // 用户自己的备份 / 名字长得像但不是我们造的：一律不删
        for user_file in [
            "smartdns.cache.2024.bak",
            "smartdns.cache.bak",
            "smartdns.cache.old",
            "smartdns.cache.corrupt",
            "smartdns.cache.corrupt-20260916",
            "other.cache.corrupt-20260916-231530",
            "smartdns.cache.tmp-1234",
        ] {
            assert!(
                !is_our_archive("smartdns.cache", user_file),
                "{user_file} 不该被当成我们的存档"
            );
        }
    }
}
