use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{RwLock, Semaphore},
    task::JoinSet,
};

use crate::{
    config::ServerOpts,
    dns::{DnsRequest, DnsResponse, SerialMessage},
    dns_client::DnsClient,
    dns_conf::RuntimeConfig,
    dns_mw::{DnsMiddlewareBuilder, DnsMiddlewareHandler},
    dns_mw_cache::DnsCache,
    log,
    server::{DnsHandle, IncomingDnsRequest, ServerHandle},
    third_ext::FutureJoinAllExt as _,
};

#[derive(Clone)]
pub struct App(Arc<AppState>);

impl App {
    fn new(cfg: Arc<RuntimeConfig>) -> (IncomingDnsRequest, Self) {
        let handler = DnsMiddlewareBuilder::new().build(cfg.clone());

        let (rx, dns_handle) = DnsHandle::new();

        (
            rx,
            Self(
                AppState {
                    dns_handle,
                    cfg: RwLock::new(cfg),
                    mw_handler: RwLock::new(Arc::new(handler)),
                    listeners: Default::default(),
                    cache: RwLock::const_new(None),
                    uptime: Instant::now(),
                    loaded_at: RwLock::const_new(Instant::now()),
                    active_queries: Default::default(),
                    guard: AppGuard,
                }
                .into(),
            ),
        )
    }

    pub async fn cache(&self) -> Option<Arc<DnsCache>> {
        self.cache.read().await.clone()
    }

    pub async fn cfg(&self) -> Arc<RuntimeConfig> {
        self.cfg.read().await.clone()
    }

    pub async fn reload(&self) -> anyhow::Result<()> {
        log::info!("reloading configuration...");
        let cfg = self.cfg().await;

        // 🌟 核心修复：将极其耗时的同步 I/O（含 HTTP 规则下载、本地文件读取、百万规则编译）
        // 全部扔给 Tokio 的专用阻塞线程池！在下载规则的这几十秒内，
        // 现有的 DNS 解析业务绝不会受到任何卡顿影响，继续用老规则飞速奔跑！
        let new_cfg = tokio::task::spawn_blocking(move || {
            cfg.reload_new()
        })
        .await
        .map_err(|e| anyhow::anyhow!("Background config reload task panicked: {}", e))??;

        *self.cfg.write().await = new_cfg;
        self.update_middleware_handler().await;
        self.update_listeners().await;
        *self.loaded_at.write().await = Instant::now();
        log::info!("configuration reloaded");
        Ok(())
    }

    pub async fn loaded_at(&self) -> Duration {
        let now = Instant::now();
        now.duration_since(*self.loaded_at.read().await)
    }

    pub fn uptime(&self) -> Duration {
        let now = Instant::now();
        now.duration_since(self.uptime)
    }

    pub fn active_queries(&self) -> usize {
        self.active_queries.load(Ordering::Relaxed)
    }

    async fn init(&self) {
        self.update_middleware_handler().await;
        self.update_listeners().await;
        crate::banner();
        log::info!("awaiting connections...");
        log::info!("server starting up");
    }

    async fn update_listeners(&self) {
        use crate::server;

        let cfg = self.cfg().await;

        let (new_bind_addrs, shutdowns) = {
            let listeners = self.listeners.read().await;
            let new_bind_addrs = cfg
                .binds()
                .iter()
                .filter(|l| !listeners.contains_key(l))
                .collect::<Vec<_>>();

            let shutdowns = listeners
                .keys()
                .filter(|l| !cfg.binds().contains(l))
                .cloned()
                .collect::<Vec<_>>();

            (new_bind_addrs, shutdowns)
        };

        if !shutdowns.is_empty() {
            let mut listeners = self.listeners.write().await;
            let shutdowns = shutdowns
                .iter()
                .flat_map(|k| listeners.remove(k))
                .collect::<Vec<_>>();
            tokio::spawn(async move {
                for shutdown in shutdowns {
                    shutdown.shutdown().await;
                }
            });
        }

        if !new_bind_addrs.is_empty() {
            let dns_handle = &self.dns_handle;

            let idle_time = cfg.tcp_idle_time();
            let certificate_file = cfg.bind_cert_file();
            let certificate_key_file = cfg.bind_cert_key_file();

            for bind_addr in new_bind_addrs {
                let serve_handle = server::serve(
                    self,
                    &cfg,
                    bind_addr,
                    dns_handle,
                    idle_time,
                    certificate_file,
                    certificate_key_file,
                );

                match serve_handle {
                    Ok(server) => {
                        if let Some(prev_server) = self
                            .listeners
                            .write()
                            .await
                            .insert(bind_addr.clone(), server)
                        {
                            tokio::spawn(async move {
                                prev_server.shutdown().await;
                            });
                        }
                    }
                    Err(err) => {
                        log::error!("{}", err)
                    }
                }
            }
        }
    }

    async fn update_middleware_handler(&self) {
        let cfg = self.cfg.read().await.clone();
        let mut cache = self.cache.write().await;
        let middleware_handler = build_middleware(
            &cfg,
            &self.dns_handle,
            cfg.create_dns_client().await,
            &mut cache,
        );

        *self.mw_handler.write().await = middleware_handler;
    }
}

impl std::ops::Deref for App {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

pub struct AppState {
    cfg: RwLock<Arc<RuntimeConfig>>,
    mw_handler: RwLock<Arc<DnsMiddlewareHandler>>,
    dns_handle: DnsHandle,
    listeners: RwLock<HashMap<crate::config::BindAddrConfig, ServerHandle>>,
    cache: RwLock<Option<Arc<DnsCache>>>,
    uptime: Instant,
    loaded_at: RwLock<Instant>,
    active_queries: AtomicUsize,
    guard: AppGuard,
}

pub fn serve(cfg: Arc<RuntimeConfig>) {
    let (mut incoming_request, app) = App::new(cfg.clone());
    let app = Arc::new(app);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.num_workers())
        // 🌟 核心扩容：暴力拉升外包保安上限到 2048！
        // 彻底解决 Windows 底层 ICMP (IcmpSendEcho) 阻塞导致的线程池耗尽问题。
        .max_blocking_threads(2048) 
        .enable_all()
        .thread_name("smartdns-runtime")
        // 🚨 删除了原有的 on_thread_start 和 on_thread_stop
        .build()
        .expect("failed to initialize Tokio Runtime");

    let _guard = runtime.enter();

    runtime.block_on(app.init());

    {
    let app = app.clone();
        runtime.spawn(async move {
            use futures::FutureExt; // 引入此特性以使用 now_or_never() 快速清理

            let mut inner_join_set = JoinSet::new();

            const BATCH_SIZE: usize = 256;

            let background_concurrency = Arc::new(Semaphore::new(16));
            let foreground_concurrency = Arc::new(Semaphore::new(10240));
            let mut requests = Vec::with_capacity(BATCH_SIZE);

            loop {
                tokio::select! {
                    // 分支 1：等待接收外部新请求
                    count = incoming_request.recv_many(&mut requests, BATCH_SIZE) => {
                        // 【修复】：如果通道关闭(count == 0)，说明服务正在关闭，应当 break 退出，而不是 continue 死循环空转 CPU
                        if count == 0 {
                            break;
                        }

                        app.active_queries.fetch_add(count, Ordering::Relaxed);

                        let handler = app.mw_handler.read().await.clone();
                        let mut dropped_count = 0; // 🌟 新增：记录因为限流而丢弃的请求数

                        for (message, server_opts, sender) in requests.drain(..) {
                            let handler = handler.clone();
                            if server_opts.is_background {
                                // 🌟 核心修复：后台请求尝试获取通行证，获取不到直接丢弃，绝不在内存中排队！
                                if let Ok(permit) = background_concurrency.clone().try_acquire_owned() {
                                    inner_join_set.spawn(async move {
                                        let _permit = permit;
                                        let _ = sender.send(process(handler, message, server_opts).await);
                                        1 // 任务完成，返回 1
                                    });
                                } else {
                                    dropped_count += 1;
                                }
                            } else {
                                // 🌟 核心修复：前台请求尝试获取通行证，获取不到直接丢弃防 OOM！
                                if let Ok(permit) = foreground_concurrency.clone().try_acquire_owned() {
                                    inner_join_set.spawn(async move {
                                        let _permit = permit;
                                        let _ = sender.send(process(handler, message, server_opts).await);
                                        1 // 任务完成，返回 1
                                    });
                                } else {
                                    dropped_count += 1;
                                    // 仅在 Trace 级别打印，防止被恶意攻击时日志写盘把 IO 打满
                                    crate::log::trace!("Foreground concurrency limit reached, dropping request to prevent OOM.");
                                }
                            }
                        }

                        // 🌟 修正活跃计数：把因为超载而丢弃的请求数量减掉，防止统计指标发生永久性泄漏
                        if dropped_count > 0 {
                            app.active_queries.fetch_sub(dropped_count, Ordering::Relaxed);
                        }
                    }

                    // 分支 2：等待 JoinSet 中的异步任务完成 (0 毫秒延迟唤醒)
                    // 只有当 inner_join_set 里面有任务时，这个分支才会被激活
                    res = inner_join_set.join_next(), if !inner_join_set.is_empty() => {
                        if let Some(Ok(count)) = res {
                            let mut total_finished = count;
                            
                            // 顺手牵羊：如果此刻还有其他刚好完成的任务，一次性全部回收掉，减少 select 的轮询开销
                            while let Some(Some(Ok(c))) = inner_join_set.join_next().now_or_never() {
                                total_finished += c;
                            }
                            
                            app.active_queries.fetch_sub(total_finished, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
    }

    let shutdown_timeout = Duration::from_secs(5);

    runtime.block_on(async move {
        use crate::signal;
        let _ = signal::terminate().await;
        
        // 🌟 最小修复点 4：老板接管强制落盘权
        // 收到关机命令后，必须等内存缓存安全写进硬盘，才允许拔掉服务器电源
        if let Some(cache_mw) = app.cache().await {
            let cfg = app.cfg().await;
            if cfg.cache_persist() {
                let cache_file = cfg.cache_file().clone();
                crate::log::info!("Saving DNS cache to file {} before shutdown...", cache_file.display());
                
                // 使用 spawn_blocking().await 进行阻断式存盘，绝对保证写完再关机
                let _ = tokio::task::spawn_blocking(move || {
                    cache_mw.persist_cache(cache_file.as_path());
                }).await;
            }
        }

        // close all servers. (保持原有代码不变)
        let mut shutdown_listeners = Default::default();
        std::mem::swap(
            app.listeners.write().await.deref_mut(),
            &mut shutdown_listeners,
        );
        shutdown_listeners
            .into_values()
            .map(|server| server.shutdown())
            .join_all()
            .await;
    });

    runtime.shutdown_timeout(shutdown_timeout);
}

struct AppGuard;

async fn process(
    handler: Arc<DnsMiddlewareHandler>,
    message: SerialMessage,
    server_opts: ServerOpts,
) -> SerialMessage {
    use crate::libdns::proto::ProtoError;
    use crate::libdns::proto::op::{Header, Message, MessageType, OpCode, ResponseCode};

    let addr = message.addr();
    let protocol = message.protocol();

    match DnsRequest::try_from(message) {
        Ok(request) => {
            match request.message_type() {
                MessageType::Query => {
                    match request.op_code() {
                        OpCode::Query => {
                            // start process
                            let request_header = request.header();
                            let mut response_header = Header::response_from_request(request_header);

                            response_header.set_recursion_available(true);
                            response_header.set_authoritative(false);

                            let response = {
                                let start = Instant::now();
                                let res = handler.search(&request, &server_opts).await;

                                log::debug!(
                                    "{}Request: {:?}",
                                    if server_opts.is_background {
                                        "Background"
                                    } else {
                                        ""
                                    },
                                    request
                                );
                                match res {
                                    Ok(lookup) => {
                                        log::debug!(
                                            "Response: {}, Duration: {:?}",
                                            lookup.deref(),
                                            start.elapsed()
                                        );
                                        lookup
                                    }
                                    Err(e) => {
                                        if e.is_nx_domain() {
                                            log::debug!(
                                                "{}Response: error resolving: NXDomain, Duration: {:?}",
                                                if server_opts.is_background {
                                                    "Background"
                                                } else {
                                                    ""
                                                },
                                                start.elapsed()
                                            );
                                            response_header
                                                .set_response_code(ResponseCode::NXDomain);
                                        }
                                        let original = request.query().original();
                                        match e.as_soa(original) {
                                            Some(soa) => soa,
                                            None => {
                                                log::debug!(
                                                    "{}Response: error resolving: {}, Duration: {:?}",
                                                    if server_opts.is_background {
                                                        "Background"
                                                    } else {
                                                        ""
                                                    },
                                                    e,
                                                    start.elapsed()
                                                );
                                                response_header
                                                    .set_response_code(ResponseCode::ServFail);
                                                let mut res = DnsResponse::empty();
                                                res.add_query(original.to_owned());
                                                res
                                            }
                                        }
                                    }
                                }
                            };

                            let mut response_message: Message =
                                response.into_message(Some(response_header));

                            // 🌟 核心修复：遵循 RFC 1035 及 EDNS0 标准，动态决定 UDP 报文截断阈值
                            if protocol == crate::libdns::Protocol::Udp {
                                // 1. 动态查验客户端订单 (EDNS0)：
                                //    如果客户端带有 EDNS0，读取其接收能力。
                                //    【防 10040 报错核心】：加上 4096 的服务端天花板，防止恶意客户端申请 65535 导致服务端发送时触发 WSAEMSGSIZE！
                                //    同时兜底 512 字节，保护老旧设备不被分片撑爆丢包。
                                let max_payload = request.extensions()
                                    .as_ref()
                                    .map(|edns| edns.max_payload().clamp(512, 4096))
                                    .unwrap_or(512) as usize;

                                if let Ok(bytes) = response_message.to_vec() {
                                    if bytes.len() > max_payload {
                                        // 2. 超过动态尺子限制，贴上黄牌 (TC 截断标志)
                                        response_message.set_truncated(true);
                                        
                                        // 🌟 核心优化：杜绝阶梯式反复 to_vec() 序列化（避免 AST 树深拷贝浪费 CPU）！
                                        // 根据 RFC 规范，一旦 TC=1，客户端通常会自动使用 TCP 重试。
                                        // 所以我们直接一次性清空 Additional 和 Authority 区，换取极致性能！
                                        response_message.take_additionals();
                                        response_message.take_authorities();
                                        
                                        // 仅做最后一次防线校验：防止恶意超大 TXT/Answer 依然撑爆 Payload
                                        if let Ok(shrunk_bytes) = response_message.to_vec() {
                                            if shrunk_bytes.len() > max_payload {
                                                response_message.take_answers();
                                            }
                                        }
                                    }
                                }
                            }

                            SerialMessage::raw(response_message, addr, protocol)
                        }
                        OpCode::Status => todo!(),
                        OpCode::Notify => todo!(),
                        OpCode::Update => todo!(),
                        OpCode::Unknown(_) => todo!(),
                    }
                }
                MessageType::Response => todo!(),
            }
        }
        Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
            // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
            let (request_header, error) = kind
                .into_form_error()
                .expect("as form_error already confirmed this is a FormError");

            // debug for more info on why the message parsing failed
            log::debug!(
                "request:{id} src:{proto}://{addr}#{port} type:{message_type} {op}:FormError:{error}",
                id = request_header.id(),
                proto = protocol,
                addr = addr.ip(),
                port = addr.port(),
                message_type = request_header.message_type(),
                op = request_header.op_code(),
                error = error,
            );

            let mut response_header = Header::response_from_request(&request_header);
            response_header.set_response_code(ResponseCode::FormErr);
            let mut response_message = Message::query().to_response();
            response_message.set_header(response_header);
            SerialMessage::raw(response_message, addr, protocol)
        }
        _ => SerialMessage::raw(Message::query(), addr, protocol),
    }
}

fn build_middleware(
    cfg: &Arc<RuntimeConfig>,
    dns_handle: &DnsHandle,
    dns_client: DnsClient,
    dns_cache: &mut Option<Arc<DnsCache>>,
) -> Arc<DnsMiddlewareHandler> {
    use crate::dns_mw_addr::AddressMiddleware;
    use crate::dns_mw_audit::DnsAuditMiddleware;
    use crate::dns_mw_bogus::DnsBogusMiddleware;
    use crate::dns_mw_cache::DnsCacheMiddleware;
    use crate::dns_mw_cname::DnsCNameMiddleware;
    use crate::dns_mw_dns64::Dns64Middleware;
    use crate::dns_mw_dnsmasq::DnsmasqMiddleware;
    use crate::dns_mw_dualstack::DnsDualStackIpSelectionMiddleware;
    use crate::dns_mw_hosts::DnsHostsMiddleware;
    use crate::dns_mw_ns::NameServerMiddleware;
    use crate::dns_mw_zone::DnsZoneMiddleware;

    let middleware_handler = {
        let mut builder = DnsMiddlewareBuilder::new();
		
		// 🌟 将客户端分流拦截器插在最前面
        builder = builder.with(ClientRuleMiddleware::new()); // 🌟 挂载带有 LRU 缓存的实体实例

        // check if audit enabled.
        if cfg.audit_enable() && cfg.audit_file().is_some() {
            builder = builder.with(DnsAuditMiddleware::new(
                cfg.audit_file().unwrap(),
                cfg.audit_size(),
                cfg.audit_num(),
                cfg.audit_file_mode().into(),
            ));
        }

        if cfg.rule_groups().values().any(|x| !x.cnames.is_empty()) {
            builder = builder.with(DnsCNameMiddleware);
        }

        if let Some(dns64_prefix) = cfg.dns64_prefix {
            builder = builder.with(Dns64Middleware::new(dns64_prefix));
        }

        builder = builder.with(DnsZoneMiddleware::new());

        builder = builder.with(AddressMiddleware);

        if cfg.resolv_hostanme() {
            builder = builder.with(DnsHostsMiddleware::new());
        }

        if cfg
            .dnsmasq_lease_file()
            .map(|x| x.is_file())
            .unwrap_or_default()
        {
            builder = builder.with(DnsmasqMiddleware::new(
                cfg.dnsmasq_lease_file().unwrap(),
                cfg.domain().cloned(),
            ));
        }

        // nftset
        #[cfg(all(feature = "nft", target_os = "linux"))]
        {
            use crate::dns_mw_nftset::DnsNftsetMiddleware;
            builder = builder.with(DnsNftsetMiddleware);
        }

        // check if cache enabled.
        if cfg.cache_size() > 0 {
            let cache_middleware = if let Some(existing_cache) = dns_cache.take() {
                // 🌟 核心修复：热重载时无缝复用内存中的老冰柜，防止 Cache Nuke！
                DnsCacheMiddleware::with_cache(cfg, dns_handle.clone(), existing_cache)
            } else {
                DnsCacheMiddleware::new(cfg, dns_handle.clone())
            };
            *dns_cache = Some(cache_middleware.cache().clone());
            builder = builder.with(cache_middleware);
        } else {
            *dns_cache = None;
        }

        builder = builder.with(DnsDualStackIpSelectionMiddleware::new());

        if !cfg.bogus_nxdomain().is_empty() {
            builder = builder.with(DnsBogusMiddleware);
        }

        builder = builder.with(NameServerMiddleware::new(dns_client));

        builder.build(cfg.clone())
    };

    Arc::new(middleware_handler)
}

// 🌟 终极形态：支持 IP 与 MAC 双重分流的客户端规则中间件（搭载全局 LRU 缓存防雪崩）
struct ClientRuleMiddleware {
    // 缓存结构：IP -> (MAC, 过期时间)
    arp_cache: std::sync::Arc<std::sync::Mutex<lru::LruCache<std::net::IpAddr, (Option<String>, std::time::Instant)>>>,
}

impl ClientRuleMiddleware {
    fn new() -> Self {
        Self {
            // 🌟 严格设置 4096 的容量上限。即使面对极端恶意的局域网源 IP 泛洪扫描，
            // LRU 机制也会自动淘汰旧记录，绝不引发 OOM 内存溢出。
            arp_cache: std::sync::Arc::new(std::sync::Mutex::new(
                lru::LruCache::new(std::num::NonZeroUsize::new(4096).unwrap())
            )),
        }
    }
}

#[async_trait::async_trait]
impl crate::middleware::Middleware<crate::dns::DnsContext, crate::dns::DnsRequest, crate::dns::DnsResponse, crate::dns::DnsError> for ClientRuleMiddleware {
    async fn handle(
        &self,
        ctx: &mut crate::dns::DnsContext,
        req: &crate::dns::DnsRequest,
        next: crate::middleware::Next<'_, crate::dns::DnsContext, crate::dns::DnsRequest, crate::dns::DnsResponse, crate::dns::DnsError>,
    ) -> Result<crate::dns::DnsResponse, crate::dns::DnsError> {
        let client_ip = req.src().ip();
        let mut matched_group = None;
        
        // 🌟 局部懒加载：确保即使配置文件里有几百条 MAC 规则，当前请求也只向系统或缓存查一次！
        let mut client_mac: Option<Option<String>> = None;

        for rule in ctx.cfg().client_rules() {
            let matches = match &rule.client {
                crate::config::Client::IpAddr(net) => net.contains(&client_ip),
                crate::config::Client::Mac(mac_rule) => {
                    let mac_opt = match &client_mac {
                        Some(m) => m.clone(), 
                        None => {
                            let now = std::time::Instant::now();
                            
                            // 1. 尝试从全局 LRU 缓存中光速读取 (极低竞争的 Mutex，0 阻塞)
                            let cached_mac = {
                                let mut cache = self.arp_cache.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some((mac, expire_at)) = cache.get(&client_ip) {
                                    if now < *expire_at {
                                        Some(mac.clone()) // 命中且未过期
                                    } else {
                                        None // 已过期
                                    }
                                } else {
                                    None // 未命中
                                }
                            };
                            
                            let m = if let Some(mac) = cached_mac {
                                mac // 缓存命中，极速返回！
                            } else {
                                // 2. 缓存穿透：
                                // 🌟 核心修复：把极耗时的系统调用（查底层 ARP 表 / 执行系统命令）扔给专属的阻塞线程池。
                                // 彻底杜绝使用 block_in_place 导致 Tokio 核心工作线程被挂起和引发线程重建雪崩！
                                let ip = client_ip;
                                let fetched_mac = tokio::task::spawn_blocking(move || {
                                    crate::infra::arp::lookup_client_mac_from_arp(ip)
                                }).await.unwrap_or(None);
                                
                                // 3. 将结果写回全局 LRU 缓存，并赋予它 60 秒 的生命周期
                                let mut cache = self.arp_cache.lock().unwrap_or_else(|e| e.into_inner());
                                cache.put(client_ip, (fetched_mac.clone(), now + std::time::Duration::from_secs(60)));
                                
                                fetched_mac
                            };
                            
                            client_mac = Some(m.clone());
                            m
                        }
                    };
                    
                    if let Some(m) = mac_opt {
                        // 忽略大小写比对 MAC 地址
                        m.eq_ignore_ascii_case(&mac_rule.to_string())
                    } else {
                        false
                    }
                }
            };
            
            if matches {
                matched_group = Some(rule.group.clone());
                break;
            }
        }

        if let Some(group) = matched_group {
            if ctx.server_opts.rule_group.as_deref() != Some(group.as_str()) {
                crate::log::debug!("Client {} matched client-rule, routing to group: {}", client_ip, group);
                ctx.server_opts.rule_group = Some(group.clone());
                ctx.domain_rule = ctx.cfg().find_domain_rule(req.query().original().name(), &group);
            }
        }

        next.run(ctx, req).await
    }
}