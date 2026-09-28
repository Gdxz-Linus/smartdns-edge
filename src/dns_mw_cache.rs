use chrono::DateTime;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use std::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::RwLock;
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
    inflight: Arc<
        Mutex<
            std::collections::HashMap<
                CacheKey,
                tokio::sync::broadcast::Sender<Option<DnsResponse>>,
            >,
        >,
    >,
}

impl DnsCacheMiddleware {
    pub fn new(cfg: &Arc<RuntimeConfig>, dns_handle: DnsHandle) -> Self {
        let configured = cfg.cache_size();
        let cache = Arc::new(DnsCache::new(
            configured,
            cfg.serve_expired(),
            cfg.serve_expired_ttl(),
            cfg.serve_expired_reply_ttl(),
            cfg.serve_expired_prefetch_time(),
        ));

        // 🔐 问题 34：**必须把实际分配的容量说清楚**。
        //
        // 配置值 ≠ 实际值（向上取整到 64 的倍数；小值还会被抬到 64）。
        // 不说清楚的话，用户按 `cache-size 1000` 去估内存/命中率，
        // 拿到的是另一个数 —— 这正是本问题"配置与实得对不上"的根源，
        // 光改取整方向不够，**还要让人看得见**。
        //
        // 只在两者**确实不同**时才提"实际值"，避免正常情况刷无关信息；
        // 且用 info 级（这是正常启动摘要，不是告警）。
        if configured != cache.actual_cache_size() {
            info!(
                "DNS cache: `cache-size {}` is rounded up to {} entries \
                 (the cache has {} fixed shards and each shard holds at least one entry, \
                 so the total is always a multiple of {})",
                configured,
                cache.actual_cache_size(),
                SHARD_COUNT,
                SHARD_COUNT,
            );
        }

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
                })
                .join();

                if let Err(e) = res {
                    // 如果子线程读取因为文件损坏而当场崩溃了，我们把它拦截下来，打一条红字警告！
                    crate::log::error!(
                        "cache file corrupted or unreadable ({:?}); ignoring the old cache and starting fresh",
                        e
                    );
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

    pub fn with_cache(
        cfg: &Arc<RuntimeConfig>,
        dns_handle: DnsHandle,
        cache: Arc<DnsCache>,
    ) -> Self {
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
                tokio::task::spawn_blocking(move || {
                    cache_for_load.load_cache_only_missing(&cache_file)
                });
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

        let mut slot = cache.persist_task.lock().unwrap_or_else(|e| e.into_inner());
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
                log::info!(
                    "cache persistence: disabled by the new configuration; the periodic flush task has stopped (the in-memory cache no longer writes to disk)"
                );
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
                        "cache persistence: enabled; periodic flushing starts now (every {} s, writing to {})",
                        checkpoint_secs,
                        file.display()
                    ),
                    Some((old_file, old_cadence)) => {
                        if old_file != &file {
                            log::info!(
                                "cache persistence: flush path changed from {} to {} (the periodic task was rebuilt on the new path, the old one stopped)",
                                old_file.display(),
                                file.display()
                            );
                        }
                        if *old_cadence != checkpoint_secs {
                            log::info!(
                                "cache persistence: flush interval changed from {} s to {} s",
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

    fn spawn_background_tasks(
        cfg: &Arc<RuntimeConfig>,
        cache: &Arc<DnsCache>,
        client_handle: DnsHandle,
    ) {
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
                        log::info!(
                            "Cache GC: purged {} totally dead records from memory",
                            purged
                        );
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
        // 🔐 **这里必须读全局值，不能读组级**（`prefetch_domain_in_group`）。
        //
        // 后台预取任务是**一个进程一份**：它遍历所有缓存条目、按热度挑选预取对象，
        // 不是"某个规则组在预取"。若改成按组取值，就会出现
        // "某个组写了 `prefetch-domain no`、把整个进程的后台任务停掉"——
        // 那是**跨组误伤**：其它组明明没写这个参数，预取却一起没了。
        //
        // 分工（丙-1 的边界）：
        //   · **逐查询**的"这条应答要不要安排预取" → 按组（查询路径上的 `ctx.prefetch_domain()`）；
        //   · **进程级**的"要不要启动后台预取任务"   → 只认全局（就是这里）。
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
                log::info!(
                    "domain prefetch: disabled by the new configuration; the prefetch task has stopped and expired entries are no longer refreshed automatically"
                );
            }
            (false, true) => {
                *slot = Some(spawn_prefetch_task(cache, client));
                log::info!(
                    "domain prefetch: enabled and in effect immediately (expired entries are refreshed automatically as configured)"
                );
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
                let has_target = lookup
                    .answers()
                    .iter()
                    .any(|r| r.record_type() == target_type);

                if has_target {
                    let original_name = query.name().clone();
                    // 在毁掉 CNAME 之前，提取整个包裹真实的最短存活时间，防止底层 IP 寿命过长成为僵尸
                    let real_min_ttl = lookup.answers().iter().map(|r| r.ttl()).min().unwrap_or(60);

                    // 清理门户：干掉 CNAME，只留下终点 IP
                    lookup
                        .answers_mut()
                        .retain(|record| record.record_type() == target_type);

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
        let ecs_str = req
            .extensions()
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
            .or_else(|| {
                ctx.domain_rule
                    .get_ref(|r| r.subnet.as_ref())
                    .map(|s| format!("{}/{}", s.addr(), s.source_prefix()))
            });

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
                            debug!(
                                "name: {} {} using caching (ECS: {:?})",
                                cache_key.query.name(),
                                cache_key.query.query_type(),
                                cache_key.ecs
                            );
                            ctx.source = LookupFrom::Cache;
                            return Ok(res);
                        }
                        // 📌 丙-1：这两个现在按规则组取值（逐查询）。
                        // `ctx.serve_expired()` 是"组级 > 全局"；
                        // `ctx.serve_expired_reply_ttl()` 同理。
                        CacheStatus::Expired if ctx.serve_expired() && !no_serve_expired => {
                            if self.cache.mark_prefetching(&cache_key).await {
                                // 🌟 核心修复 3：生成全局唯一的同步时间戳基准！
                                // ⚠️ 这个基准必须与本次判断同源：既然"要不要喂"是按组判断的，
                                // 喂出去的寿命也必须按同一条取值链取，否则两个组会共用同一个
                                // 时间戳、双栈兄弟记录会对不齐。
                                let reply_ttl = Duration::from_secs(ctx.serve_expired_reply_ttl());
                                let sync_valid_until = Instant::now() + reply_ttl;

                                self.cache
                                    .set_valid_until_for_prefetch(&cache_key, sync_valid_until)
                                    .await;

                                let mut guards = vec![PrefetchGuard {
                                    cache: self.cache.clone(),
                                    key: cache_key.clone(),
                                }];
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
                                        query: Query::query(
                                            cache_key.query.name().clone(),
                                            other_type,
                                        ),
                                        group: cache_key.group.clone(),
                                        ecs: cache_key.ecs.clone(),
                                        opts: cache_key.opts.clone(),
                                    };

                                    if self.cache.mark_prefetching(&other_key).await {
                                        // 🌟 核心修复 4：双栈兄弟使用完全一样的基准时间戳，绝对对齐！
                                        self.cache
                                            .set_valid_until_for_prefetch(
                                                &other_key,
                                                sync_valid_until,
                                            )
                                            .await;
                                        guards.push(PrefetchGuard {
                                            cache: self.cache.clone(),
                                            key: other_key,
                                        });
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
                                let ttl_duration =
                                    sync_valid_until.saturating_duration_since(Instant::now());
                                let mut actual_ttl = ttl_duration.as_secs() as u32;
                                if ttl_duration.subsec_nanos() > 0 {
                                    actual_ttl += 1;
                                }
                                resurrected_res.set_new_ttl(actual_ttl);

                                debug!(
                                    "name: {} {} using caching (Expired) (ECS: {:?})",
                                    cache_key.query.name(),
                                    cache_key.query.query_type(),
                                    cache_key.ecs
                                );
                                ctx.source = LookupFrom::Cache;
                                return Ok(resurrected_res);
                            }

                            // 极小概率兜底：如果有其他并发已经拿了预取锁，但时间戳还未更新完毕
                            // 📌 丙-1：这里同样按组取值 —— 它已经处在"决定要喂过期数据"之后，
                            // 若这里退回全局值，同一组的两次应答会带出**两个不同的 TTL**。
                            let reply_ttl_secs = ctx.serve_expired_reply_ttl() as u32;
                            let mut fallback_res = res;
                            fallback_res.set_new_ttl(reply_ttl_secs);
                            debug!(
                                "name: {} {} using caching (Expired) (ECS: {:?})",
                                cache_key.query.name(),
                                cache_key.query.query_type(),
                                cache_key.ecs
                            );
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
                        self.cache
                            .insert_full_response(cache_key.clone(), lookup.clone(), Instant::now())
                            .await;
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
                            self.cache
                                .insert_full_response(extra_key, extra_resp, Instant::now())
                                .await;
                        }
                    }

                    // 截断包没有进缓存，也就没有"到期再预取"这回事
                    //
                    // 📌 丙-1：这里按规则组取值 —— 它管的是"**这条应答**要不要安排预取"。
                    // ⚠️ 后台预取任务的**启停**不在这里，仍读全局（见 `sync_prefetch_task`）：
                    // 任务是一个进程一份、遍历所有缓存条目，不是"某个组在预取"。
                    if !lookup.truncated()
                        && ctx.prefetch_domain()
                        && let Some(ttl) = lookup.min_ttl()
                    {
                        self.cache
                            .prefetch_notify
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

/// 🔐 问题 13-③：测试专用 —— 统计 `cached_records_paginated` 第二趟迭代了多少条。
///
/// 只在测试构建下存在（`#[cfg(test)]`），**不进生产二进制**。
/// 它存在的唯一理由：这项修复只改变"代价"、不改变"返回值"
/// （退回旧实现，返回的 `total` 与 `records` 完全一样），所以
/// "结果对不对"测不出它；而**用时间测也不可靠** —— 我实测两次反向验证都没抓住。
/// 只有在实现内部计这个确定量，反向验证才能稳定复现。
///
/// ⚠️ `static` 不能放在 `impl` 块里（第一版放进去、编译直接报
/// "associated `static` items are not allowed"），所以放在模块层级。
#[cfg(test)]
static PAGINATION_SCAN_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
use std::sync::atomic::Ordering as AtomicOrdering;

/// 🔐 问题 34：把配置的 `cache-size` 换算成**实际生效**的总容量。
///
/// 规则：**向上取整到 `SHARD_COUNT`(64) 的倍数**（至少 64）。
///
/// 为什么是"向上"而不是原来的向下：分片数固定 64、每片至少 1 条，
/// 原先的 `size / 64` 会让**实得少于配置**（`1000` → 960），
/// 用户按 1000 估的内存/命中率都会偏乐观。向上取整保证**只会多、不会少**。
///
/// ⚠️ 已知边界（如实记录，不是缺陷漏修）：**小值仍会被抬到 64**
/// （`cache-size 10` → 64），因为 64 片 × 1 条是这套分片结构的硬下限。
/// 要让 10 精确等于 10 必须改分片数（大动作，本次不做）——
/// 所以启动日志会打印**实际值**，让用户看得见。
///
/// 抽成独立函数是为了让**写入侧（构造）、告警侧（重载）、测试**共用同一口径；
/// 三处各写一遍的话，将来改规则必然漂移。
#[inline]
fn effective_cache_size(configured: usize) -> usize {
    configured.div_ceil(SHARD_COUNT).max(1) * SHARD_COUNT
}

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
    Restart { file: PathBuf, checkpoint_secs: u64 },
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
/// 🔐 预取组包：刷新必须按**原记录的口径**去问，关键是 ECS。
///
/// 不带 ECS 的后果（2026-09-18 定的）：这条刷新会被算成"不带 ECS"那份答案，
/// 回来后自然写进**另一条缓存记录** —— 于是客户端发过 ECS 的那些域名，过期条目
/// 永远刷不到（不会答错，只是"后台帮忙刷"对它们不生效）。
///
/// 出站 ECS 的来源见 `src/dns_mw_ns.rs` 的 `LookupOptions.client_subnet`：它读的是
/// **请求里的 EDNS Subnet 选项**，所以只要把原记录的 ECS 原样装回查询里，
/// 出站 ECS 与回来时的缓存记录就都对得上。
fn prefetch_query_for(key: &CacheKey) -> Message {
    let mut msg = Message::query();
    msg.add_query(key.query.clone());
    if let Some(subnet) = key.ecs.as_deref().and_then(|s| {
        s.parse::<crate::libdns::proto::rr::rdata::opt::ClientSubnet>()
            .ok()
    }) {
        msg.extensions_mut()
            .get_or_insert_with(crate::libdns::proto::op::Edns::new)
            .options_mut()
            .insert(crate::libdns::proto::rr::rdata::opt::EdnsOption::Subnet(
                subnet,
            ));
    }
    msg
}

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

                        let msg = prefetch_query_for(&cache_key);
                        tokio::spawn(async move {
                            let _guard = PrefetchGuard {
                                cache: cache_clone,
                                key: cache_key.clone(),
                            };
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
    /// 🔐 问题 34：**实际分配**的总容量（= 每片容量 × 分片数）。
    ///
    /// 与 `cache_size` 的区别：后者是**配置值**（用户写的数），这里是**真实可用条数**。
    /// 两者可能不等（向上取整到 64 的倍数；小值还会被抬到 64）。
    /// 分开存是为了让管理接口与日志能**如实**报告实际值，
    /// 而不是把配置值当成实际值糊弄用户。
    actual_cache_size: AtomicUsize,
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
        // 🔐 问题 34：分片容量**向上取整到 64 的倍数**，并对"实际值"如实交代。
        //
        // 背景：分片数固定为 `SHARD_COUNT`(64)，每片容量为 `LruCache::new(NonZeroUsize)`
        // ⇒ **每片至少 1 条**，于是总容量的下限被钉死在 64。
        // 原先用 `cache_size / 64`（向下取整）：
        //   · `cache-size 1000` → 每片 15 → 实得 **960**（比配置**少** 40）；
        //   · `cache-size 10`   → 每片 0 被夹到 1 → 实得 **64**（比配置**多** 6.4 倍）。
        //
        // 现在改为向上取整（**只会多、不会少**）：
        //   · `1000` → **1024**（多 24）；`512` → **512**（正好）；`4096` → **4096**（正好）。
        //
        // ⚠️ 边界如实说明：**小值仍然会被抬到 64**（`cache-size 10` → 64）。
        // 详见 `effective_cache_size()` 的文档。
        let actual_total = effective_cache_size(cache_size);
        let shard_size = actual_total / SHARD_COUNT;

        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            // `shard_size` 已由 `.max(1)` 保证非零，这里的 expect 不可能触发
            shards.push(Mutex::new(LruCache::new(
                NonZeroUsize::new(shard_size).expect("shard_size is at least 1"),
            )));
        }

        Self {
            persist_task: Mutex::new(None), // 🔐 A8：任务由 sync_persist_task 建，这里只是占位
            prefetch_task: Mutex::new(None), // 🔐 任务由 sync_prefetch_task 建
            shards: Arc::new(shards),
            serve_expired: AtomicBool::new(serve_expired),
            expired_ttl: AtomicU64::new(expired_ttl),
            expired_reply_ttl: AtomicU64::new(expired_reply_ttl),
            expired_prefetch_time: AtomicU64::new(expired_prefetch_time),
            // ⚠️ 这里存**配置值**，不是 actual_total —— 见 `reload_config` 的比较语义
            // 与 `cache_size()` 的注释，两者用途不同，别混。
            cache_size: AtomicUsize::new(cache_size),
            actual_cache_size: AtomicUsize::new(actual_total),
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
            //
            // 🔐 问题 34：告警里要带上**重启后实际会得到的容量**，
            // 而不是只说"需要重启"。原提示只说"改了要重启"，用户重启后
            // 看到的是另一个数（向上取整到 64 的倍数），按提示理解会得到错误结论。
            crate::log::warn!(
                "changing cache-size from {} to {} requires a restart \
                 (shard capacity is fixed at startup; all other cache policies take effect immediately). \
                 After a restart the cache will actually hold {} entries ({} x {} shards)",
                old_size,
                new_size,
                effective_cache_size(new_size),
                effective_cache_size(new_size) / SHARD_COUNT,
                SHARD_COUNT,
            );
        }
    }

    /// 🔐 问题 34：**实际生效**的总容量（向上取整到 64 的倍数）。
    ///
    /// 公开出来是为了让启动摘要与管理接口都能如实报告 ——
    /// 配置值 ≠ 实际值，把两者混为一谈会让用户按错的数去估算内存与命中率。
    #[inline]
    pub fn actual_cache_size(&self) -> usize {
        self.actual_cache_size.load(Ordering::Relaxed)
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
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
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
        let mut cache = self
            .get_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(key) {
            if entry.is_in_prefetching {
                return false;
            }
            entry.is_in_prefetching = true;
        }
        true
    }

    // 🌟 核心修复 2：改为接收外部绝对基准时间，确保双栈微秒级一致！
    pub async fn set_valid_until_for_prefetch(&self, key: &CacheKey, new_valid_until: Instant) {
        let mut cache = self
            .get_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(key)
            && entry.valid_until < new_valid_until
        {
            entry.valid_until = new_valid_until;
        }
    }

    pub async fn purge_dead_records(&self, now: Instant) -> usize {
        let mut count = 0;
        let grace_period = if self.serve_expired() {
            Duration::from_secs(self.expired_ttl())
        } else {
            Duration::ZERO
        };

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
                for q in to_remove {
                    cache.pop(&q);
                }
            }
            tokio::task::yield_now().await;
        }
        count
    }

    pub async fn cached_records_paginated(
        &self,
        offset: usize,
        limit: usize,
    ) -> (usize, Vec<CachedQueryRecord>) {
        // 🔐 问题 13-③：分两趟做，让"离谱的 offset"付出零代价。
        //
        // 原实现把"数总数"和"收集这一页"混在同一个循环里，于是：
        //   · `records.len() >= limit` 用的是 `continue` —— 收集够了**仍把 64 个分片跑完**；
        //   · `current_offset < offset` 会把偏移之前的条目**逐个走一遍**，
        //     调用方给个 `?offset=1000000000` 就是一个可控的 CPU 消耗点。
        //
        // 现在：
        //   第一趟只做 `len()` 求和（不碰条目内容，极便宜）；
        //   若 `offset >= total`，这一页必然为空 ⇒ **直接返回，一条都不扫**；
        //   否则第二趟收集，且收满 `limit` 就**立刻跳出**（不再遍历剩余条目）。
        let total: usize = self
            .shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum();

        if offset >= total || limit == 0 {
            return (total, Vec::new());
        }

        let mut records = Vec::new();
        let mut current_offset = 0;
        let mut done = false;

        for shard in self.shards.iter() {
            if done {
                break;
            }
            let cache = shard.lock().unwrap_or_else(|e| e.into_inner());

            for (key, entry) in cache.iter() {
                // 🔐 问题 13-③：测试专用埋点 —— 统计第二趟**实际迭代了多少条**。
                // 之所以要这个埋点：这项修复**只影响代价、不影响返回值**
                // （退回旧实现，返回的 `total` 与 `records` 完全一样），
                // 所以"结果对不对"测不出它；用时间测也不可靠（实测两次都没抓住）。
                // 只有在实现内部计这个确定量，反向验证才能稳定复现。
                #[cfg(test)]
                PAGINATION_SCAN_COUNT.fetch_add(1, AtomicOrdering::SeqCst);

                // 跳过本页之前的条目（此时 `offset < total`，因此这段最多走 offset 步）
                if current_offset < offset {
                    current_offset += 1;
                    continue;
                }
                if records.len() >= limit {
                    done = true;
                    break;
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

    pub async fn insert_full_response(
        &self,
        key: CacheKey,
        response: DnsResponse,
        now: Instant,
    ) -> DnsResponse {
        let mut min_ttl = MAX_TTL;

        if !response.answers().is_empty() {
            let ans_ttl = response
                .answers()
                .iter()
                .map(|r| r.ttl())
                .min()
                .unwrap_or(60);
            min_ttl = min_ttl.min(ans_ttl);
        } else {
            let soa_record = response
                .message()
                .authorities()
                .iter()
                .find(|r| r.record_type() == RecordType::SOA)
                .or_else(|| {
                    response
                        .answers()
                        .iter()
                        .find(|r| r.record_type() == RecordType::SOA)
                });
            if let Some(soa) = soa_record {
                let mut negative_ttl = soa.ttl();
                if let RData::SOA(soa_data) = soa.data() {
                    negative_ttl = negative_ttl.min(soa_data.minimum());
                }
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
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
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
        let mut cache = self
            .get_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
    async fn get_expired(
        &self,
        now: Instant,
        seconds_ahead: Option<u64>,
    ) -> (Vec<CacheKey>, Duration) {
        let mut most_recent = Duration::from_secs(MAX_TTL as u64);
        let mut to_prefetch = std::collections::HashMap::new();
        let ahead_secs = seconds_ahead.unwrap_or(5);

        for shard in self.shards.iter() {
            {
                let mut cache = shard.lock().unwrap_or_else(|e| e.into_inner());
                if cache.is_empty() {
                    continue;
                }

                for (key, entry) in cache.iter_mut() {
                    if entry.is_in_prefetching {
                        continue;
                    }
                    if !key.query.query_type().is_ip_addr() {
                        continue;
                    }

                    let is_frequent = entry.stats.hits >= 2;

                    if self.serve_expired() {
                        if entry.is_current(now) {
                            most_recent = most_recent.min(entry.ttl(now));
                            continue;
                        }
                        if self.expired_prefetch_time() > 0 {
                            let expired_for =
                                now.saturating_duration_since(entry.valid_until).as_secs();
                            if expired_for < self.expired_prefetch_time() {
                                continue;
                            }
                            if !is_frequent {
                                continue;
                            }
                        } else if !is_frequent {
                            continue;
                        }
                    } else {
                        let prefetch_now = now + Duration::from_secs(ahead_secs);
                        if entry.is_current(prefetch_now) {
                            most_recent = most_recent.min(entry.ttl(now));
                            continue;
                        }
                        if !is_frequent {
                            continue;
                        }
                    }

                    entry.is_in_prefetching = true;

                    // 🔐 问题 27-3：排序键取"判定时"的热度，扣减**不再兼任**排序键。
                    //
                    // ⚠️ 先记一个复核结论：报告说的"两个口径不一致 ⇒ 顺序轻微错序"
                    // **经穷举实验判定不成立**。`x.saturating_sub(1)` 是**单调非减**函数，
                    // 而唯一会产生并列的 `hits=1` 根本不够格入选（门槛是扣减前 `hits >= 2`），
                    // 所以"按扣减前排序"与"按扣减后排序"的结果**恒等**。
                    // 证据：`tests/e2e/_p27_3_monotonic.py`（穷举 4680 种组合，顺序不一致 0 种）。
                    //
                    // 那这段改动为什么保留？因为它把**不变量**写显了：
                    // 排序口径与准入口径从此是同一个量，将来若有人调整准入门槛
                    // （例如降到 `hits >= 1`），并列点出现、两者才会真正分叉，
                    // 那时这里不必再改。扣减保留，它服务的是**热度衰减**语义
                    // （"这一轮已经安排过预取了，热度回落一格"）。
                    let hits_for_ordering = entry.stats.hits;

                    // 热度衰减：表示"这一轮已经把它安排出去了"
                    entry.stats.hits = entry.stats.hits.saturating_sub(1);

                    // 🌟 保持 CacheKey 的原汁原味，不丢失 RecordType 和 ECS 信息。
                    // 同一 key 可能出现在多个分片（理论上不该，但取 max 更稳），
                    // 因此这里也让"排序键"取较大者，避免被一次低热度覆盖。
                    let current_hits = to_prefetch.get(key).copied().unwrap_or(0);
                    to_prefetch.insert(key.clone(), std::cmp::max(current_hits, hits_for_ordering));
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

            let mut file = File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)?;

            // 🔐 P2：先写文件头（魔数 + 格式版本 + 条目数）——
            // 以后读到不认识的版本，就能明确说"版本不兼容"，而不是含混的"可能损坏"。
            let mut header = Vec::with_capacity(CACHE_HEADER_LEN);
            emit_cache_header(&mut header, self.total_len() as u32);
            std::io::Write::write_all(&mut file, &header)?;

            for shard in self.shards.iter() {
                let mut shard_buffer = Vec::new();
                {
                    let cache = shard.lock().unwrap_or_else(|e| e.into_inner());
                    DnsCacheEntry::serialize_many(
                        cache.iter().map(|(_, entry)| entry),
                        &mut shard_buffer,
                    )?;
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
                    "failed to replace the cache file (the old file is kept and the new one remains at {}): {}. Common causes: antivirus, indexing or backup software holding the file, or another instance writing to disk concurrently",
                    tmp_path.display(),
                    err
                );
                return Err(ProtoError::from(err));
            }

            Ok::<_, ProtoError>(())
        };

        match cache_to_file() {
            Ok(_) => {
                info!(
                    "save DNS cache to file \"{}\" successfully.",
                    path.display()
                );
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
                    "cache file {} has format version v{}, this build only supports v{}: the file is kept and archived as {}; continuing as a cold start",
                    display_str,
                    version,
                    CACHE_FORMAT_VERSION,
                    archived
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(
                            || "(archiving failed; the original file is kept)".to_string()
                        ),
                );
                return;
            }

            declared = Some(entries_in_file);
            payload = &data[CACHE_HEADER_LEN..];
        } else {
            info!(
                "cache file has no header: reading it in the legacy format (supported this time; the header is written on the next flush)"
            );
        }

        let (entries, stopped_at) = deserialize_best_effort(payload);

        if let Some(err) = stopped_at.as_ref() {
            let archived = archive_cache_file(path, "corrupt");
            error!(
                "cache file {} read interrupted: {} (the file declares {} records, {} were recovered); the file is kept and archived as {}",
                display_str,
                err,
                declared
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                entries.len(),
                archived
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(archiving failed; the original file is kept)".to_string()),
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
            let group = entry
                .data
                .name_server_group()
                .unwrap_or("default")
                .to_string();
            let key = CacheKey {
                query,
                group,
                ecs: entry.ecs.clone(),
                opts: entry.opts.clone(),
            };

            let mut cache = self
                .get_shard(&key)
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
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
/// - v3（组级参数机制）：`AnswerAffectingOpts` 新增 bind 级 `force-no-CNAME`。
///   同样是"缓存标记变了" —— v2 的条目是按旧口径算出来的（那时还没有这个键位），
///   混用会让两个配得不一样的监听互相借用答案，所以必须 +1 让旧档走"版本不兼容"路径。
const CACHE_FORMAT_VERSION: u16 = 3;
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

/// 🔐 问题 35：把从缓存文件读出的"秒数"钳制到合理范围，越界时告警一次。
///
/// 上限 = [`MAX_TTL`]（86400 秒）。这个值是**写入侧**的上限
/// （`insert_full_response` 里 `min_ttl.min(MAX_TTL)`），
/// 因此正常产出的文件不可能超过它 —— 超过即说明文件损坏或被改写。
///
/// ⚠️ **不是崩溃防护**：实测 `Instant ± Duration` 溢出时会**饱和**、不 panic。
/// 这道校验挡的是**语义污染**（超大值让条目"永不新鲜"或"瞬间远古"，
/// 带偏 `serve-expired` 与预取/清理判断），并让异常**可见**。
///
/// 为什么是"钳制"而不是"丢弃整条"：见 `BinDecodable for DnsCacheEntry` 里的说明
/// （越界通常只是个别字段被破坏，整条丢掉会连带扔掉完好的答案）。
///
/// 告警做**限流**（每进程只喊一次）：一份被大范围改写的文件会有成百上千条越界，
/// 每条都喊会刷屏，反而把真正要看的信息挤掉。
fn clamp_file_duration(secs: u32, field: &'static str) -> u64 {
    use std::sync::atomic::{AtomicBool, Ordering};

    static WARNED: AtomicBool = AtomicBool::new(false);

    if secs <= MAX_TTL {
        return secs as u64;
    }

    if !WARNED.swap(true, Ordering::Relaxed) {
        crate::log::warn!(
            "cache file contains an out-of-range time value ({} = {} seconds, limit is {}); \
             it was clamped to the limit. This usually means the cache file was corrupted or \
             modified by hand; the affected entries are kept but treated as short-lived. \
             (further occurrences are not logged)",
            field,
            secs,
            MAX_TTL
        );
    }

    MAX_TTL as u64
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
        b[8] == b'-'
            && b.iter()
                .enumerate()
                .all(|(i, c)| i == 8 || c.is_ascii_digit())
    }
}

/// 🔐 P2：坏档 / 版本不兼容档**不直接删**，改名存档（只保留最近 1 份），便于用户排查。
fn archive_cache_file(path: &Path, tag: &str) -> Option<PathBuf> {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let file_name = path.file_name()?.to_string_lossy().to_string();
    let archived = path.with_file_name(format!("{file_name}.{tag}-{stamp}"));

    if let Err(err) = std::fs::rename(path, &archived) {
        error!(
            "failed to archive the cache file ({} -> {}): {}; the original file is left untouched",
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
        && let Ok(entries) = std::fs::read_dir(dir)
    {
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
                Ok(()) => info!("removing an old cache archive: {}", old.display()),
                Err(err) => crate::log::warn!(
                    "failed to remove an old cache archive {}: {}",
                    old.display(),
                    err
                ),
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
        // 🔐 问题 35：**时间字段必须做范围校验**。
        //
        // 原实现把从文件里读出的秒数**直接采信**：
        //   · `tag == 2`（还剩多久）→ `Instant::now() + Duration`；
        //   · `tag == 5`（已过期多久）→ `Instant::now() - Duration`。
        //
        // ⚠️ **实测更正**：这两个运算**不会 panic** ——
        // `Instant ± Duration` 在溢出时**饱和**处理（实测 `u32::MAX` 秒既不加爆也不减崩，
        // 减法饱和到"约 136 年之前"）。报告原文也写明"不会造成崩溃"。
        // 所以本项**不是崩溃类缺陷**，危害是**语义污染**：
        //   · `tag == 2` 写入超大值 ⇒ 该条目在**极长时间内**都被当成"新鲜"，
        //     永远不会被预取/清理，`serve-expired` 的判断也被带偏；
        //   · `tag == 5` 写入超大值 ⇒ 条目一下子变成"远古数据"，
        //     `serve-expired-ttl` 的窗口被瞬间跳过，本该还能喂的旧数据提前作废。
        //
        // 处置：**钳制到合理范围并告警**，而不是丢弃整条。
        // 理由：越界值最可能来自"文件损坏/被改写"，而该条目其余部分（域名、答案）
        // 往往仍然完好；直接丢弃会把还能用的数据一起扔掉。
        //
        // 上限取 `MAX_TTL`（= 86400），与写入侧 `min_ttl.min(MAX_TTL)` 对称 ——
        // 正常写出的文件**不可能**超过它，所以超过就一定是异常。
        let valid_until = if tag == 2 {
            let ttl_secs = clamp_file_duration(decoder.read_u32()?.unverified(), "remaining TTL");
            Instant::now() + Duration::from_secs(ttl_secs)
        } else if tag == 5 {
            let dead_for_secs =
                clamp_file_duration(decoder.read_u32()?.unverified(), "expired duration");
            Instant::now() - Duration::from_secs(dead_for_secs)
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
            && let Ok(len) = decoder.read_u16()
        {
            let len = len.unverified();
            if len > 0
                && let Ok(bytes) = decoder.read_slice(len as usize)
            {
                ecs = String::from_utf8(bytes.unverified().to_vec()).ok();
            }
        }

        // 🌟 读取"会影响答案的监听级选项"（v2 新增，tag 7）。
        //
        // ⚠️ 必须**先偷看再决定吃不吃**：条目在文件里是**背靠背**排列的，没有分隔符，
        // 上一条读完之后紧跟的就是下一条的起始字节（恒为 tag 1）。如果这里无脑 read_u8()，
        // 读到的是下一条的 `0x01`，会被误判成"本条目里有unknown tag"→ 整份文件被判坏
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
        let mut cache = self
            .cache
            .get_shard(&self.key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get_mut(&self.key) {
            entry.is_in_prefetching = false;
        }
    }
}

struct InflightCacheGuard {
    inflight: Arc<
        Mutex<
            std::collections::HashMap<
                CacheKey,
                tokio::sync::broadcast::Sender<Option<DnsResponse>>,
            >,
        >,
    >,
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

    /// 🔐 问题 34：`cache-size` 与实际容量必须"**只会多、不会少**"。
    ///
    /// 原实现是 `size / 64`（向下取整），导致实得**少于**配置（1000 → 960）；
    /// 现在向上取整到 64 的倍数。
    #[test]
    fn cache_size_rounds_up_to_shard_multiple() {
        // 精确值保持不变
        assert_eq!(effective_cache_size(64), 64);
        assert_eq!(effective_cache_size(512), 512);
        assert_eq!(effective_cache_size(4096), 4096);

        // 非整倍：向上取整，**不得少于配置**
        assert_eq!(effective_cache_size(1), 64);
        assert_eq!(effective_cache_size(10), 64);
        assert_eq!(effective_cache_size(32), 64);
        assert_eq!(effective_cache_size(65), 128);
        assert_eq!(effective_cache_size(1000), 1024);
        assert_eq!(effective_cache_size(1025), 1088);

        // 不变量：结果总是 64 的倍数，且 >= 配置值
        for n in [1usize, 7, 10, 32, 63, 64, 100, 1000, 4096, 65536] {
            let got = effective_cache_size(n);
            assert_eq!(got % SHARD_COUNT, 0, "{n} → {got} 必须是 64 的倍数");
            assert!(got >= n, "{n} → {got} 不得少于配置值（原实现会少）");
            assert!(
                got - n < SHARD_COUNT,
                "{n} → {got} 向上取整最多多出一个分片"
            );
        }

        // ⚠️ 0 是"关闭缓存"的哨兵值（调用方在 `cache_size() > 0` 时才建缓存），
        // 这里不做特判，返回 64 只是为了不产生 0 容量的 LruCache；
        // **绝不能**把它当成"用户要 64 条缓存"—— 关闭由调用方判断。
        assert_eq!(effective_cache_size(0), 64);
    }

    /// 🔐 问题 34：实际分配的总容量要与 `effective_cache_size()` 一致 ——
    /// 光算对不够，**真的按这个数分配**才算数。
    #[test]
    fn actual_capacity_matches_the_rounded_value() {
        for (configured, expected) in [(10usize, 64usize), (512, 512), (1000, 1024), (4096, 4096)] {
            let cache = DnsCache::new(configured, false, 0, 0, 0);
            assert_eq!(
                cache.actual_cache_size(),
                expected,
                "cache-size {configured} 的实际容量应为 {expected}"
            );

            // 逐片核对：每片容量 × 片数 == 实际总容量
            let per_shard = expected / SHARD_COUNT;
            for shard in cache.shards.iter() {
                let s = shard.lock().unwrap_or_else(|e| e.into_inner());
                assert_eq!(
                    s.cap().get(),
                    per_shard.max(1),
                    "每片容量应为 {per_shard}（cache-size {configured}）"
                );
            }
        }
    }

    /// 🔐 问题 34：`cache_size`（配置值）与 `actual_cache_size`（实际值）**是两个东西**，
    /// 不许混用 —— 管理接口与日志要报后者。
    #[test]
    fn configured_and_actual_sizes_are_kept_distinct() {
        let cache = DnsCache::new(1000, false, 0, 0, 0);
        assert_eq!(
            cache.cache_size.load(Ordering::Relaxed),
            1000,
            "配置值要原样保留（重载时比对用的是它）"
        );
        assert_eq!(
            cache.actual_cache_size(),
            1024,
            "实际值要如实反映向上取整的结果"
        );
    }

    /// 🔐 问题 35：缓存文件里的时间字段必须做范围校验。
    ///
    /// ⚠️ 危害是**语义污染**而非崩溃（`Instant ± Duration` 溢出会饱和、不 panic）：
    /// 超大值会让条目"永不新鲜"（tag 2）或"瞬间远古"（tag 5），带偏 `serve-expired`。
    #[test]
    fn file_time_fields_are_range_checked() {
        // 正常范围内：原样采信（不能把合法值也改掉）
        assert_eq!(clamp_file_duration(0, "t"), 0);
        assert_eq!(clamp_file_duration(60, "t"), 60);
        assert_eq!(clamp_file_duration(MAX_TTL, "t"), MAX_TTL as u64);

        // 越界：钳到上限（**不得**原样返回）
        assert_eq!(clamp_file_duration(MAX_TTL + 1, "t"), MAX_TTL as u64);
        assert_eq!(clamp_file_duration(u32::MAX, "t"), MAX_TTL as u64);
    }

    /// 🔐 问题 35 的核心回归：**越界时间必须被钳制，且异常可见**。
    ///
    /// ⚠️ **实测更正（重要）**：`Instant ± Duration` 溢出**不会 panic**（饱和处理），
    /// 所以本项**不是崩溃类缺陷**。它挡的是**语义污染**：
    /// 未钳制时该条目会变成"约 136 年之前的数据"，`serve-expired` 的窗口被整个跳过。
    ///
    /// 做法：先**正常序列化**一条真实条目（保证格式与实现一致、不随布局漂移），
    /// 再把它的时间字段定点改成 `u32::MAX`。
    #[test]
    fn oversized_time_in_file_is_clamped_and_does_not_panic() {
        // 造一条"刚过期 10 秒"的条目（tag 5 分支），正常序列化
        let mut entry = make_test_entries(1).remove(0);
        entry.valid_until = Instant::now() - Duration::from_secs(10);

        let mut buf = Vec::new();
        DnsCacheEntry::serialize_many(std::iter::once(&entry), &mut buf).unwrap();

        // 定位 tag 5 后的 4 字节时间字段并改写为 u32::MAX。
        //
        // ⚠️ 不能只找"字节 == 5"：**域名/报文里本来就可能出现 0x05**（实测踩到过）。
        // 可靠判据是"结构"：时间字段之后紧跟 `tag3`(0x03) + 组名长度(u16)。
        // 因此要求 `buf[i]==5` 且 `buf[i+5]==3`，再从**后往前**找（时间字段更靠近尾部，
        // 避免选中报文里的巧合字节）。
        //
        // ⚠️⚠️ 字节序：hickory 的 `emit_u32`/`read_u32` 是 **DNS 网络序（大端）**，
        // 所以这里必须用 `from_be_bytes` / `to_be_bytes` ——
        // 用 `ne_bytes` 会读出 0x0a000000 这种离谱值（实测就是这么踩到的）。
        let pos = (0..buf.len().saturating_sub(5))
            .rev()
            .find(|&i| {
                if buf[i] != 5 || buf[i + 5] != 3 {
                    return false;
                }
                let v = u32::from_be_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
                // 刚设置成"过期 10 秒"，所以值应当很小（留足余量）
                v < 600
            })
            .expect("应能定位到 tag5 的时间字段（tag5 + u32 + tag3 结构）");
        buf[pos + 1..pos + 5].copy_from_slice(&u32::MAX.to_be_bytes());

        // 读档：必须成功、条目必须保留（钳制而非丢弃）
        let (entries, stopped) = deserialize_best_effort(&buf);
        assert_eq!(entries.len(), 1, "越界时间不该让条目被丢弃（钳制后仍保留）");
        assert!(stopped.is_none(), "不该被判成坏档：{stopped:?}");

        // 🔐 核心断言：钳制后，"已过期时长"被压到 MAX_TTL 之内，
        // 而不是原来的 u32::MAX 秒（≈136 年）。
        let got = &entries[0];
        let now = Instant::now();
        let expired_for = now.saturating_duration_since(got.valid_until).as_secs();
        assert!(
            expired_for <= MAX_TTL as u64 + 5,
            "已过期时长应被钳到 MAX_TTL({}) 之内，实际 {expired_for} 秒\
             （未钳制会是 {} 秒 ⇒ serve-expired 窗口被整个跳过）",
            MAX_TTL,
            u32::MAX
        );

        // 对照：未钳制时确实会得到"远古"时间（证明这道校验不是多余的）
        let unclamped = Instant::now() - Duration::from_secs(u32::MAX as u64);
        let unclamped_expired = Instant::now()
            .saturating_duration_since(unclamped)
            .as_secs();
        assert!(
            unclamped_expired > MAX_TTL as u64 * 1000,
            "未钳制的 u32::MAX 会得到约 136 年的'远古'值（{unclamped_expired} 秒），\
             这正是钳制要挡住的情形"
        );
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
            group: entry
                .data
                .name_server_group()
                .unwrap_or("default")
                .to_string(),
            ecs: entry.ecs.clone(),
            opts: entry.opts.clone(),
        }
    }

    /// 读回缓存里该标记当前的 A 记录答案
    fn cached_answer_ip(cache: &DnsCache, key: &CacheKey) -> Option<std::net::Ipv4Addr> {
        use crate::libdns::proto::rr::RData;

        let shard = cache
            .get_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
                    // ⚠️ 原来写的是 `i as u8 + 1`：n > 255 时会**算术溢出 panic**
                    // （debug 构建下）。翻页测试需要造几百条记录，所以改成不溢出的写法。
                    // 语义不变（前 255 条地址与原来完全相同）。
                    RData::A(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 255) as u8 + 1).into()),
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

    /// 把 n 条记录放进缓存（按各自的分片散开）
    fn fill_cache(cache: &DnsCache, n: usize) {
        for entry in make_test_entries(n) {
            let key = test_key_of(&entry);
            cache
                .get_shard(&key)
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .put(key, entry);
        }
    }

    /// 🔐 问题 13-③：分页必须（a）结果正确、（b）`total` 如实、（c）**离谱 offset 不付出代价**。
    ///
    /// 原实现的两个毛病：
    ///   · 收集够了用 `continue`（不是 `break`）⇒ 仍把 64 个分片跑完；
    ///   · `offset` 无上限 ⇒ `?offset=1000000000` 会逐个走完缓存里的每一条。
    ///
    /// ⚠️ **这条测试怎么证明"没有白干活"**（第一版做不到，值得记）：
    /// "结果对不对"是**测不出这个改动的** —— 退回旧实现，返回值**完全一样**，
    /// 差别只在"多遍历了多少条目"。所以这里用 `DnsCacheEntry` 的**克隆计数**来计量工作量：
    /// 只有"真的取了一条记录"才会克隆它，因此计数 = 实际取出的条数。
    /// `offset` 超界时**不该克隆任何一条**；收满一页后**也不该再克隆**。
    ///
    /// 若把提前返回去掉，第二条断言就会失败（大 offset 会走完整个缓存）。
    #[tokio::test]
    async fn pagination_is_correct_and_bounded() {
        let cache = DnsCache::new(4096, false, 0, 0, 0);
        const N: usize = 100;
        fill_cache(&cache, N);

        // ① total 如实反映全量（翻页器依赖它）
        let (total, first) = cache.cached_records_paginated(0, 10).await;
        assert_eq!(total, N, "total 必须是缓存里的全部条数");
        assert_eq!(first.len(), 10, "第一页应拿满 limit 条");

        // ② 翻页不重不漏：把每页的名字收集起来，应当正好覆盖全部且无重复
        let mut seen = std::collections::HashSet::new();
        for offset in (0..N).step_by(10) {
            let (t, page) = cache.cached_records_paginated(offset, 10).await;
            assert_eq!(t, N, "每一页返回的 total 都应是全量");
            for r in page {
                assert!(
                    seen.insert(r.name.to_ascii()),
                    "第 {offset} 页出现了重复条目"
                );
            }
        }
        assert_eq!(seen.len(), N, "所有页合起来应当正好是全部条目、不重不漏");

        // ③ 超界与极端值：必须返回空页
        let (total_over, over) = cache.cached_records_paginated(N, 10).await;
        assert_eq!(total_over, N, "超界时 total 仍要如实");
        assert!(over.is_empty(), "offset == total 时应返回空页");

        let (t_huge, huge) = cache.cached_records_paginated(usize::MAX, 10).await;
        assert_eq!(t_huge, N);
        assert!(huge.is_empty(), "offset=usize::MAX 应返回空页");

        let (t0, none) = cache.cached_records_paginated(0, 0).await;
        assert_eq!(t0, N);
        assert!(none.is_empty(), "limit=0 应返回空页");

        // ④ 最后一页（不足 limit）也要正确截断
        let (_, tail) = cache.cached_records_paginated(N - 3, 10).await;
        assert_eq!(tail.len(), 3, "末尾不足一页时应只返回剩下的条数");
    }

    /// 🔐 问题 13-③ 的**代价侧**断言：`offset` 超界时**不得遍历缓存条目**。
    ///
    /// ## ⚠️ 这条测试的判别力边界（实测得出，如实标注）
    ///
    /// 我一开始想用"时间"来测（超界那路应当更快），**实测两次都没能通过反向验证抓住**：
    /// 把提前返回禁用之后它**仍然通过** —— 时间断言必须留足余量以免受调度噪声影响，
    /// 而余量一留宽，就盖过了遍历 2000 条记录的代价。**用时间测"有没有白干活"不可靠。**
    ///
    /// 所以改成**确定性计量**：在被测函数内埋一个只在测试构建下生效的计数器，
    /// 统计它**在第二趟里实际迭代了多少条**。断言于是变成"遍历条数"这种确定量：
    ///   · `offset` 超界 ⇒ **必须 0**（旧实现会走完整个缓存 ⇒ 计数 = N）；
    ///   · `limit=5`    ⇒ **必须 5**（旧实现收满后仍继续遍历 ⇒ 计数更大）。
    ///
    /// 这个计数**不依赖时间**，所以反向验证能稳定复现。
    #[tokio::test]
    async fn pagination_does_not_scan_entries_it_does_not_need() {
        let cache = DnsCache::new(4096, false, 0, 0, 0);
        const N: usize = 300;
        fill_cache(&cache, N);

        // ① offset 远超总数：应当**一条都不遍历**
        PAGINATION_SCAN_COUNT.store(0, AtomicOrdering::SeqCst);
        let (_, page) = cache.cached_records_paginated(usize::MAX, 10).await;
        let scanned = PAGINATION_SCAN_COUNT.load(AtomicOrdering::SeqCst);
        assert!(page.is_empty());
        assert_eq!(
            scanned, 0,
            "offset 远超总数时不该遍历任何一条，实际遍历了 {scanned} 条\
             （旧实现会走完整个缓存 —— 这正是问题 13-③ 要消除的可控消耗）"
        );

        // ② 收满一页就停：limit=5 时遍历量应当"恰好 5 + 至多 1 条用于发现该停"
        //
        // ⚠️ 实测得出的**真实语义**（第一版断言写 5、结果实际是 6，测试当场抓出来）：
        // 循环是"先计数、再判断收满没有"，所以收满后还会**多探一条**才 break。
        // 1 条的额外代价可以忽略；这里按真实行为断言，并同时钉住"**不能多探很多**" ——
        // 旧实现会把整个缓存（300 条）走完，所以上界取 limit+1 就能区分两者。
        PAGINATION_SCAN_COUNT.store(0, AtomicOrdering::SeqCst);
        let (_, page) = cache.cached_records_paginated(0, 5).await;
        let scanned = PAGINATION_SCAN_COUNT.load(AtomicOrdering::SeqCst);
        assert_eq!(page.len(), 5);
        assert!(
            (5..=6).contains(&scanned),
            "limit=5 时最多只应碰 6 条（5 条 + 1 条用来发现该停），实际 {scanned} 条 —— \
             旧实现收满后仍继续遍历（用 `continue`），会碰 300 条"
        );

        // ③ 中间页：跳过 offset 条 + 取 limit 条（同样允许"多探 1 条"）
        PAGINATION_SCAN_COUNT.store(0, AtomicOrdering::SeqCst);
        let (_, page) = cache.cached_records_paginated(10, 7).await;
        let scanned = PAGINATION_SCAN_COUNT.load(AtomicOrdering::SeqCst);
        assert_eq!(page.len(), 7);
        assert!(
            (17..=18).contains(&scanned),
            "offset=10 + limit=7 应当只碰约 17 条（跳过的 10 + 取的 7，至多多探 1 条），\
             实际 {scanned} 条"
        );

        // ④ 对照：埋点必须真的在工作（防"计数恒为 0 导致上面断言假通过"）
        PAGINATION_SCAN_COUNT.store(0, AtomicOrdering::SeqCst);
        let _ = cache.cached_records_paginated(0, 3).await;
        assert!(
            PAGINATION_SCAN_COUNT.load(AtomicOrdering::SeqCst) > 0,
            "埋点没有计数 —— 上面那些 0 的断言将毫无意义（假通过）"
        );
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
        assert!(
            parse_cache_header(legacy).is_none(),
            "无头文件必须被判为旧格式"
        );

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
        std::fs::write(
            path.with_file_name("smartdns.cache.2024.bak"),
            b"user-backup",
        )
        .unwrap();
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
        assert_eq!(
            left.len(),
            2,
            "应只剩【最新存档 + 用户的备份】，实际 {left:?}"
        );
        assert!(
            left.iter().any(|n| n == "smartdns.cache.2024.bak"),
            "用户自己放在同目录的备份不许被删（B6）：{left:?}"
        );
        assert!(
            left.iter()
                .any(|n| n.starts_with("smartdns.cache.corrupt-")),
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
        assert_ne!(
            base, with_no_speed,
            "带 -no-speed-check 的监听不能与默认监听共用同一份缓存"
        );

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
            let k = CacheKey {
                opts: AnswerAffectingOpts::from_server_opts(&o),
                ..base.clone()
            };
            assert_ne!(base, k, "{name} 会改变答案，必须体现在缓存标记里");
        }

        // rule_group 也要能区分
        let mut rg = ServerOpts::default();
        rg.rule_group = Some("guest".to_string());
        let k = CacheKey {
            opts: AnswerAffectingOpts::from_server_opts(&rg),
            ..base.clone()
        };
        assert_ne!(
            base, k,
            "rule_group 决定用哪套域名规则，必须体现在缓存标记里"
        );
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
        assert_eq!(
            archived.len(),
            1,
            "必须留下一个 -incompatible 的存档，实际 {archived:?}"
        );

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
        assert!(
            parse_cache_header(&again).is_some(),
            "第二次落盘后文件仍应是合法格式"
        );
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

        assert!(
            path.is_dir(),
            "替换失败后，原位置的东西（这里是目录）必须还在"
        );
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
        assert!(is_our_archive(
            "smartdns.cache",
            "smartdns.cache.corrupt-20260916-231530"
        ));
        assert!(is_our_archive(
            "smartdns.cache",
            "smartdns.cache.load-panic-20260101-000000"
        ));
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

#[cfg(test)]
mod prefetch_query_tests {
    //! 预取组包的口径：带 ECS 的记录，刷新必须把同一段 ECS 带上；
    //! 不带 ECS 的记录，刷新也不该凭空多带一段（成对检查 —— 只查一半会漏掉"一刀切全带"这种改法）。

    use super::*;

    fn key(ecs: Option<&str>) -> CacheKey {
        CacheKey {
            query: Query::query(
                Name::from_ascii("ecs-prefetch.test.").unwrap(),
                RecordType::A,
            ),
            group: String::new(),
            ecs: ecs.map(str::to_string),
            opts: AnswerAffectingOpts::default(),
        }
    }

    fn ecs_of(msg: &Message) -> Option<String> {
        use crate::libdns::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
        msg.extensions()
            .as_ref()
            .and_then(|edns| edns.option(EdnsCode::Subnet))
            .and_then(|opt| match opt {
                EdnsOption::Subnet(subnet) => {
                    Some(format!("{}/{}", subnet.addr(), subnet.source_prefix()))
                }
                _ => None,
            })
    }

    /// 🔐 问题 27-3：把"排序口径 == 准入口径"这个**不变量**钉住。
    ///
    /// ⚠️ **诚实标注**：这条测试**不具备判别力**，撤掉 27-3 的改动它照样通过 ——
    /// 因为 `x.saturating_sub(1)` 单调非减，两种排序键的结果本来就恒等
    /// （穷举证据见 `tests/e2e/_p27_3_monotonic.py`：4680 种组合，顺序不一致 0 种）。
    /// 保留它是为了钉住**行为契约**：够格预取的门槛用的是**扣减前**的 hits，
    /// 排序也必须用同一个量。将来若有人把门槛降到 `hits >= 1`，并列点才会出现，
    /// 这条测试就能立刻拦住"低热度排前面"。
    #[tokio::test]
    async fn prefetch_order_follows_hits_at_decision_time() {
        // serve_expired 打开、expired_prefetch_time = 0 ⇒ 走"够格即预取"那条分支
        let cache = DnsCache::new(1024, true, 600, 5, 0);

        let low = insert_expired_with_hits(&cache, "low.prefetch.test.", 2);
        let high = insert_expired_with_hits(&cache, "high.prefetch.test.", 3);

        let (order, _most_recent) = cache.get_expired(Instant::now(), Some(5)).await;
        let names: Vec<String> = order.iter().map(|k| k.query.name().to_ascii()).collect();

        assert_eq!(
            names,
            vec!["high.prefetch.test.", "low.prefetch.test."],
            "热度的条目必须排在前面（排序键取判定时的 hits）"
        );

        // 扣减照旧发生 —— 它服务的是"这一轮已经安排过了"的热度衰减语义，
        // 只是不再兼任排序键。
        assert_eq!(hits_of(&cache, &high), 2, "hits=3 扣减一格 → 2");
        assert_eq!(hits_of(&cache, &low), 1, "hits=2 扣减一格 → 1");
    }

    /// 造一条"已过期 + 指定热度"的 A 记录，放进缓存，返回它的标记
    fn insert_expired_with_hits(cache: &DnsCache, name: &str, hits: usize) -> CacheKey {
        use std::net::Ipv4Addr;

        let name = Name::from_ascii(name).unwrap();
        let mut msg = Message::query();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 1).into()),
        ));
        let res: DnsResponse = msg.into();

        let mut entry = DnsCacheEntry::new(
            res,
            Instant::now() - Duration::from_secs(1), // 已过期
            None,
            AnswerAffectingOpts::default(),
        );
        entry.stats.hits = hits;

        let key = CacheKey {
            query: entry.data.query().clone(),
            group: "default".to_string(),
            ecs: None,
            opts: entry.opts.clone(),
        };
        cache
            .get_shard(&key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key.clone(), entry);
        key
    }

    /// 读回某条缓存记录当前的热度
    fn hits_of(cache: &DnsCache, key: &CacheKey) -> usize {
        let shard = cache
            .get_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        shard.peek(key).map(|e| e.stats.hits).unwrap_or(0)
    }

    #[test]
    fn refresh_carries_the_records_ecs() {
        let msg = prefetch_query_for(&key(Some("203.0.113.0/24")));
        assert_eq!(ecs_of(&msg).as_deref(), Some("203.0.113.0/24"));
        // 查询本身照旧（别只顾着装 ECS 把域名/类型弄丢）
        assert_eq!(msg.queries().len(), 1);
        assert_eq!(msg.queries()[0].name().to_ascii(), "ecs-prefetch.test.");
    }

    #[test]
    fn refresh_without_ecs_stays_without_ecs() {
        let msg = prefetch_query_for(&key(None));
        assert_eq!(
            ecs_of(&msg),
            None,
            "原记录不带 ECS 时，刷新不该凭空带上一段"
        );
    }
}

/// 🔐 问题 27-4：「正在预取」标记**不得**在任务结束后卡住。
///
/// ## 这组测试的定位：钉住**判定不成立**这个结论
///
/// 报告原文说：*「'正在预取'标记只靠任务收尾清除，任务在建立标记前被取消时该条目会一直卡住，
/// 该记录在本进程内不再被预取」*。
///
/// 本轮**逐条走完了 `is_in_prefetching` 的全部读写点**，判定**该场景在当期代码里不可达**：
///
/// | 事件 | 位置 | 说明 |
/// |---|---|---|
/// | 置位 ① | `mark_prefetching` | 唯一的置位入口，成功即返回 true |
/// | 置位 ② | `get_expired` 遍历时 | 与 `to_prefetch` 配对，随后由 guard 收尾 |
/// | 复位 ① | `PrefetchGuard::drop` | **无条件**复位，是主要保障 |
/// | 复位 ② | `insert_full_response` | 上游拿到新结果时清掉 |
/// | 复位 ③ | `DnsCacheEntry::set_data` | 同上的另一条入口 |
/// | 复位 ④ | `deserialize_many` | 读缓存文件时**强制**为 false（不落盘） |
///
/// **关键在于 `PrefetchGuard` 的构造时机**：两个调用点
/// （`dns_mw_cache.rs` 的"过期复活"与 `spawn_prefetch_task`）都是
/// **先 `mark_prefetching`、紧接着就构造 guard**，中间**没有** `?`、`return`
/// 或可被取消的 `await`；而 guard 被 `async move` 捕获后，
/// **任务无论正常结束、panic 还是被取消，`Drop` 都必然执行**。
///
/// 报告描述的"标记建立前就被取消"需要这样一个窗口：**置位之后、guard 构造之前**
/// 存在一个可取消的挂起点。当期代码里**不存在**这样的窗口。
///
/// ## 所以这组测试不证明"修复有效"，而是：
///
///   1. 用**可执行的形式**记录这条结论（避免日后重复排查）；
///   2. 钉住**不变量**：任何"标记过又被丢弃"的路径都必须让标记回到 false；
///   3. 万一将来有人在置位与 guard 之间插入 `await`/`?`，这里的断言会立刻暴露风险。
#[cfg(test)]
mod prefetch_marker_tests {
    use super::*;

    /// 造一条**已过期**的 A 记录并放进缓存，返回它的键。
    fn insert_expired(cache: &DnsCache, name: &str) -> CacheKey {
        use std::net::Ipv4Addr;

        let name = Name::from_ascii(name).unwrap();
        let mut msg = Message::query();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 1).into()),
        ));
        let res: DnsResponse = msg.into();

        let entry = DnsCacheEntry::new(
            res,
            Instant::now() - Duration::from_secs(1),
            None,
            AnswerAffectingOpts::default(),
        );
        let key = CacheKey {
            query: entry.data.query().clone(),
            group: "default".to_string(),
            ecs: None,
            opts: entry.opts.clone(),
        };
        cache
            .get_shard(&key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key.clone(), entry);
        key
    }

    /// 读回"正在预取"标记
    fn marker_of(cache: &DnsCache, key: &CacheKey) -> bool {
        cache
            .get_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peek(key)
            .map(|e| e.is_in_prefetching)
            .unwrap_or(false)
    }

    /// 🔐 **核心不变量**：`PrefetchGuard` 一旦被丢弃，标记必须回到 false。
    ///
    /// 这是整套"不会卡死"结论的基石 —— guard 由 `async move` 捕获，
    /// 因此**任务正常结束、panic、被取消，三种情况下 `Drop` 都会跑**。
    ///
    /// 判别力：把 `PrefetchGuard::drop` 里的复位去掉，本测试必然失败。
    #[tokio::test]
    async fn dropping_the_guard_always_clears_the_marker() {
        let cache = Arc::new(DnsCache::new(1024, true, 600, 5, 0));
        let key = insert_expired(&cache, "guard-drop.prefetch.test.");

        // 标记成功
        assert!(
            cache.mark_prefetching(&key).await,
            "首次标记应当成功（返回 true 表示'我来做这次预取'）"
        );
        assert!(
            marker_of(&cache, &key),
            "标记成功后，条目的 is_in_prefetching 必须是 true"
        );

        // 模拟"预取任务结束"：guard 被丢弃
        {
            let _guard = PrefetchGuard {
                cache: cache.clone(),
                key: key.clone(),
            };
        }

        assert!(
            !marker_of(&cache, &key),
            "⚠️ guard 丢弃后标记必须复位 —— 否则该条目在本进程内再也不会被预取（问题 27-4）"
        );
    }

    /// 🔐 标记**确实会拦住重复预取**，而复位之后又能重新预取。
    ///
    /// 这一条是"两面的"：既证明标记在起作用（不是个死字段），
    /// 也证明**复位之后能恢复**（不会永久卡住）。
    #[tokio::test]
    async fn marker_blocks_then_recovers_after_reset() {
        let cache = Arc::new(DnsCache::new(1024, true, 600, 5, 0));
        let key = insert_expired(&cache, "recover.prefetch.test.");

        assert!(cache.mark_prefetching(&key).await, "第一次应当成功");
        assert!(
            !cache.mark_prefetching(&key).await,
            "标记还在时，第二次必须被拒（否则同一记录会被并发预取多次）"
        );

        // 任务收尾 → 复位
        {
            let _guard = PrefetchGuard {
                cache: cache.clone(),
                key: key.clone(),
            };
        }

        assert!(
            cache.mark_prefetching(&key).await,
            "⚠️ 复位之后必须能再次预取 —— 这说明标记不会永久卡住（问题 27-4 的结论）"
        );
    }

    /// 🔐 **异常路径**（guard 提前被丢弃，模拟"任务中途出错/被取消"）同样会复位。
    ///
    /// 报告描述的卡死前提是"任务在建立标记**之前**被取消"。当期代码里，
    /// `mark_prefetching` 与 guard 构造**之间没有任何可取消的挂起点**，
    /// 所以真实场景是"任务拿到标记后中途死掉" —— 而这种情况由 `Drop` 兜住。
    ///
    /// 本测试显式模拟后者（拿到标记后立刻丢弃 guard，就像任务刚起步就失败），
    /// 断言标记回到 false。
    #[tokio::test]
    async fn early_drop_on_failure_path_still_resets() {
        let cache = Arc::new(DnsCache::new(1024, true, 600, 5, 0));
        let key = insert_expired(&cache, "early-drop.prefetch.test.");

        assert!(cache.mark_prefetching(&key).await);

        // 模拟"任务拿到标记后立刻失败退出"：构造 guard 后马上丢弃
        let guard = PrefetchGuard {
            cache: cache.clone(),
            key: key.clone(),
        };
        drop(guard);

        assert!(
            !marker_of(&cache, &key),
            "任务提前退出也必须复位标记（Drop 是无条件的，这是不卡死的依据）"
        );
    }

    /// 🔐 **成对反证**：上游真的拿到新结果时，标记也会被清掉。
    ///
    /// `insert_full_response` 是复位点之一 —— 它保证"预取成功写入新数据"之后
    /// 标记不会残留（否则下轮又会被误判为'正在预取中'）。
    #[tokio::test]
    async fn inserting_a_fresh_response_clears_the_marker() {
        use std::net::Ipv4Addr;

        let cache = Arc::new(DnsCache::new(1024, true, 600, 5, 0));
        let key = insert_expired(&cache, "fresh.prefetch.test.");
        assert!(cache.mark_prefetching(&key).await);

        // 造一份"新鲜"的应答写回去（模拟预取成功）
        let name = Name::from_ascii("fresh.prefetch.test.").unwrap();
        let mut msg = Message::query();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 2).into()),
        ));
        let fresh: DnsResponse = msg.into();

        cache
            .insert_full_response(key.clone(), fresh, Instant::now())
            .await;

        assert!(
            !marker_of(&cache, &key),
            "写入新结果后必须清掉'正在预取'标记（否则下轮预取会被自己的残留标记挡住）"
        );
    }
}
