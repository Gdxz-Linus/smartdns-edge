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
                    bind_retry: Default::default(),
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
                        // 🔐 P1-10：绑定失败不再"记一条日志就永久放弃"。
                        // 原来该地址在**整个进程生命周期**内都不会再被尝试 —— 开机时 53 端口
                        // 被别的程序短暂占用，DNS 就永远不开门，只能手动重启。
                        // 现在记进重试队列，按指数退避自动再试。
                        self.schedule_bind_retry(bind_addr.clone(), format!("{err}"))
                            .await;
                    }
                }
            }
        }
    }

    /// 🔐 P1-10：把一个绑不上的监听记进重试队列。
    ///
    /// 首次失败写一条 error（含地址、原因、"多久后重试"），后续失败只在**次数为 2 的幂**时
    /// 写一条 warn —— 既不会被永久失败刷爆日志/磁盘，也不会静默到没人知道。
    async fn schedule_bind_retry(&self, bind_addr: crate::config::BindAddrConfig, err: String) {
        use crate::config::IBindConfig as _;
        use std::collections::hash_map::Entry;

        let now = Instant::now();
        let addr = bind_addr.sock_addr();
        let mut retry = self.bind_retry.write().await;

        match retry.entry(bind_addr) {
            Entry::Vacant(v) => {
                let state = BindRetry::new(now, format!("{addr}: {err}"));
                log::error!(
                    "❌ 监听 {} 绑定失败，已加入自动重试队列（{} 秒后重试第一次，\
                     之后指数退避、最长 60 秒一次；端口只是被短暂占用的话会自行恢复，无需手动重启）：{}",
                    addr,
                    retry_backoff(1).as_secs(),
                    state.last_error
                );
                v.insert(state);
            }
            Entry::Occupied(mut o) => {
                let state = o.get_mut();
                state.failed_again(now, format!("{addr}: {err}"));
                if state.attempts.is_power_of_two() {
                    log::warn!(
                        "⏳ 监听 {} 仍然绑不上（第 {} 次失败，{} 秒后再试）：{}",
                        addr,
                        state.attempts,
                        retry_backoff(state.attempts).as_secs(),
                        state.last_error
                    );
                }
            }
        }
    }

    /// 🔐 P1-10：把所有"到点了"的失败监听再试一遍。
    ///
    /// `now` 由调用方注入（心跳传 `Instant::now()`），单测可以直接"快进时间"，
    /// 不必真的 sleep 等退避。
    async fn retry_pending_binds_at(&self, now: Instant) {
        use crate::config::IBindConfig as _;
        use crate::server;

        let due: Vec<crate::config::BindAddrConfig> = {
            let retry = self.bind_retry.read().await;
            retry
                .iter()
                .filter(|(_, state)| state.is_due(now))
                .map(|(addr, _)| addr.clone())
                .collect()
        };

        if due.is_empty() {
            return;
        }

        let cfg = self.cfg().await;
        let idle_time = cfg.tcp_idle_time();
        let certificate_file = cfg.bind_cert_file();
        let certificate_key_file = cfg.bind_cert_key_file();

        for bind_addr in due {
            // 配置里已经不要这个监听了（例如用户改完配置并 reload 过）→ 放弃重试
            if !cfg.binds().contains(&bind_addr) {
                self.bind_retry.write().await.remove(&bind_addr);
                log::info!(
                    "监听 {} 已不在当前配置中，放弃重试",
                    bind_addr.sock_addr()
                );
                continue;
            }

            match server::serve(
                self,
                &cfg,
                &bind_addr,
                &self.dns_handle,
                idle_time,
                certificate_file,
                certificate_key_file,
            ) {
                Ok(server) => {
                    let addr = bind_addr.sock_addr();
                    let state = self.bind_retry.write().await.remove(&bind_addr);
                    let (attempts, waited) = match state.as_ref() {
                        Some(state) => (
                            state.attempts,
                            now.saturating_duration_since(state.first_failed_at),
                        ),
                        None => (0, Duration::ZERO),
                    };

                    if let Some(prev) = self.listeners.write().await.insert(bind_addr, server) {
                        tokio::spawn(async move {
                            prev.shutdown().await;
                        });
                    }

                    log::info!(
                        "✅ 监听 {} 已恢复：第 {} 次重试成功（从首次失败起累计 {:?}）",
                        addr,
                        attempts,
                        waited
                    );
                }
                Err(err) => {
                    let mut retry = self.bind_retry.write().await;
                    if let Some(state) = retry.get_mut(&bind_addr) {
                        state.failed_again(now, format!("{}: {err}", bind_addr.sock_addr()));
                        if state.attempts.is_power_of_two() {
                            log::warn!(
                                "⏳ 监听 {} 仍然绑不上（第 {} 次失败，{} 秒后再试）：{}",
                                bind_addr.sock_addr(),
                                state.attempts,
                                retry_backoff(state.attempts).as_secs(),
                                state.last_error
                            );
                        }
                    }
                }
            }
        }
    }

    /// 🔐 P1-10：给状态接口用 —— 当前有几个监听在重试、最近一条失败原因是什么。
    ///
    /// 加了这两个值以后，"端口被占导致 DNS 不开门"从**完全静默**变成一眼可见。
    pub async fn bind_retry_status(&self) -> (usize, Option<String>) {
        let retry = self.bind_retry.read().await;
        let count = retry.len();
        let last = retry
            .values()
            .max_by_key(|state| state.last_failed_at)
            .map(|state| state.last_error.clone());
        (count, last)
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

/// 🔐 P1-10：一个"绑定失败、正在重试"的监听的状态。
#[derive(Debug, Clone)]
struct BindRetry {
    /// 已经失败过多少次（1 = 首次失败）
    attempts: u32,
    /// 下一次允许重试的时刻
    next_at: Instant,
    /// 首次失败时刻（用来算"已经等了多久"）
    first_failed_at: Instant,
    /// 最近一次失败时刻（用来在状态接口里挑出"最新那条错误"）
    last_failed_at: Instant,
    /// 最近一次失败原因（含地址，直接给运维看）
    last_error: String,
}

impl BindRetry {
    fn new(now: Instant, err: String) -> Self {
        Self {
            attempts: 1,
            next_at: now + retry_backoff(1),
            first_failed_at: now,
            last_failed_at: now,
            last_error: err,
        }
    }

    /// 又失败一次：次数 +1，并推迟下一次重试的时间。
    fn failed_again(&mut self, now: Instant, err: String) {
        self.attempts += 1;
        self.next_at = now + retry_backoff(self.attempts);
        self.last_failed_at = now;
        self.last_error = err;
    }

    fn is_due(&self, now: Instant) -> bool {
        now >= self.next_at
    }
}

/// 指数退避：第 `attempts` 次重试前要等多久 —— 1s, 2s, 4s, 8s, 16s, 32s, 60s（封顶）。
///
/// 抽成纯函数是为了能直接单测：不用真的去占端口就能验证退避序列。
fn retry_backoff(attempts: u32) -> Duration {
    /// 退避上限：再惨也就是每分钟试一次，不会变成刷日志的机器。
    const CAP_SECS: u64 = 60;
    let shift = attempts.saturating_sub(1).min(6); // 0..=6 → 1,2,4,8,16,32,64
    Duration::from_secs((1u64 << shift).min(CAP_SECS))
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
    /// 🔐 P1-10：绑定失败、正在自动重试的监听（键 = 那个绑不上的绑定配置）。
    /// 这是"开机时端口被占了一下就永久不开门"的自愈机制的核心状态。
    bind_retry: RwLock<HashMap<crate::config::BindAddrConfig, BindRetry>>,
    guard: AppGuard,
}


/// 这个监听是不是"管理后台"（WebAPI / 网页控制台）用的？
/// 后台路由同时挂在 bind-http / bind-https / bind-h3 三种监听上（见 src/server/*.rs）。
fn is_api_bind(b: &crate::config::BindAddrConfig) -> bool {
    match b {
        crate::config::BindAddrConfig::Http(_) => true,
        #[cfg(feature = "dns-over-https")]
        crate::config::BindAddrConfig::Https(_) => true,
        #[cfg(feature = "dns-over-h3")]
        crate::config::BindAddrConfig::H3(_) => true,
        _ => false,
    }
}

/// 🔐 P0-2：进程级 panic 计数与日志钩子。
///
/// 原实现没有 panic 钩子 —— panic 只会写 stderr，而服务方式运行时 stderr 往往没人看，
/// 等于"出事了但没人知道"。钩子把 panic 记进应用日志（带限流）并计数，
/// 计数暴露在 /api/system/status，运维一眼能看到。
pub static PANIC_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let count = PANIC_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        // 限流：前 5 次每次都记，之后每 100 次记一条，避免被刷爆日志/磁盘
        if count <= 5 || count % 100 == 0 {
            crate::log::warn!("⚠️ 捕获到 panic（累计第 {count} 次）：{info}");
        }
    }));
}

/// 🔐 P0-2 顺手修：在途请求计数改用 RAII。
///
/// 原实现是"批量加、按任务返回值批量减"，一旦请求任务 panic（例如命中 todo!()），
/// 那个任务的计数就永远减不掉 —— 状态页上的"当前查询数"只增不减。
/// 用守卫则无论正常返回、报错还是 panic，退出作用域时都会归还。
struct ActiveQueryGuard(Arc<App>);

impl ActiveQueryGuard {
    fn new(app: Arc<App>) -> Self {
        app.active_queries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(app)
    }
}

impl Drop for ActiveQueryGuard {
    fn drop(&mut self) {
        self.0.active_queries.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn serve(cfg: Arc<RuntimeConfig>) {

    // 🔐 P0-1：管理后台的启动前检查（必须在任何监听启动之前完成）
    //   1. 拦住危险组合：后台绑到非本机地址、却又没有配置口令 —— 直接拒绝启动；
    //   2. 检查通过后把口令定下来（没配置就随机生成并打印一次），
    //      让用户在启动日志里立刻看到，而不是等第一次访问失败才发现。
    {
        if let Err(msg) = crate::api::check_exposure(cfg.binds(), cfg.api_token()) {
            crate::log::error!("{msg}");
            eprintln!("[smartdns] {msg}");
            std::process::exit(crate::dns_conf::EXIT_CODE_CONFIG_ERROR);
        }

        crate::api::set_configured_token(cfg.api_token().map(ToString::to_string));

        // 🔐 P0-5：初始化连接数上限（未配置则按物理内存自动推算，家庭/企业自适应）
        crate::server::limit::init(cfg.max_connections(), cfg.max_connections_per_ip());

        // 🔐 P0-2：让任何 panic 都走应用日志 + 计数（默认只写 stderr，服务方式下没人看得见）
        install_panic_hook();

        let api_binds = cfg.binds().iter().filter(|b| is_api_bind(b)).count();
        if api_binds > 0 && !crate::api::api_token_configured() {
            let _ = crate::api::api_token();
        }
    }

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

            // 🔐 P1-10：绑定失败重试的心跳。1 秒粒度足够（退避最小也是 1 秒），
            // 用 Delay 而不是 Burst，免得机器忙时积压的 tick 被一次性补跑。
            let mut bind_retry_tick = tokio::time::interval(Duration::from_secs(1));
            bind_retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // interval 的第一次 tick 会立刻到期，先消耗掉（启动时本来也没有待重试的监听）
            bind_retry_tick.tick().await;

            loop {
                tokio::select! {
                    // 分支 1：等待接收外部新请求
                    count = incoming_request.recv_many(&mut requests, BATCH_SIZE) => {
                        // 【修复】：如果通道关闭(count == 0)，说明服务正在关闭，应当 break 退出，而不是 continue 死循环空转 CPU
                        if count == 0 {
                            break;
                        }

                        let handler = app.mw_handler.read().await.clone();

                        for (message, server_opts, sender) in requests.drain(..) {
                            let handler = handler.clone();
                            if server_opts.is_background {
                                // 🌟 核心修复：后台请求尝试获取通行证，获取不到直接丢弃，绝不在内存中排队！
                                if let Ok(permit) = background_concurrency.clone().try_acquire_owned() {
                                    let app = app.clone();
                                    inner_join_set.spawn(async move {
                                        let _permit = permit;
                                        let _active = ActiveQueryGuard::new(app);
                                        if let Some(response) = process(handler, message, server_opts).await {
                                            let _ = sender.send(response);
                                        }
                                    });
                                } else {
                                    // 并发上限已满：直接丢弃该请求（不计数也不再补偿）
                                }
                            } else {
                                // 🌟 核心修复：前台请求尝试获取通行证，获取不到直接丢弃防 OOM！
                                if let Ok(permit) = foreground_concurrency.clone().try_acquire_owned() {
                                    let app = app.clone();
                                    inner_join_set.spawn(async move {
                                        let _permit = permit;
                                        let _active = ActiveQueryGuard::new(app);
                                        if let Some(response) = process(handler, message, server_opts).await {
                                            let _ = sender.send(response);
                                        }
                                    });
                                } else {
                                    // 仅在 Trace 级别打印，防止被恶意攻击时日志写盘把 IO 打满
                                    crate::log::trace!("Foreground concurrency limit reached, dropping request to prevent OOM.");
                                }
                            }
                        }

                    }

                    // 分支 2：等待 JoinSet 中的异步任务完成 (0 毫秒延迟唤醒)
                    // 只有当 inner_join_set 里面有任务时，这个分支才会被激活
                    res = inner_join_set.join_next(), if !inner_join_set.is_empty() => {
                        if let Some(Err(e)) = res {
                            // 请求任务异常退出（例如 panic）：记一条警告便于运维发现。
                            // 计数已由 ActiveQueryGuard 归还，这里不需要再补偿。
                            crate::log::warn!("request task failed: {e}");
                        }

                        // 顺手牵羊：把此刻已完成的任务一次性全部回收，减少 select 轮询开销
                        while inner_join_set
                            .join_next()
                            .now_or_never()
                            .flatten()
                            .is_some()
                        {}
                    }

                    // 分支 3：🔐 P1-10 —— 定期把"绑定失败"的监听再试一遍。
                    // 没有待重试项时这个分支只有一次 HashMap 读锁 + 一个空 Vec，代价可忽略。
                    _ = bind_retry_tick.tick() => {
                        app.retry_pending_binds_at(Instant::now()).await;
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

/// 🔐 P0-2 兜底：请求处理的外层包装。
///
/// 即使将来又出现"没预料到的 panic"，也不会表现为"客户端苦等超时"，
/// 而是**尽力给出一个 SERVFAIL**（可诊断），同时由 panic 钩子记进日志并计数。
/// 提醒：正常流量只是多包了一层（几乎零开销），行为完全不变。
async fn process(
    handler: Arc<DnsMiddlewareHandler>,
    message: SerialMessage,
    server_opts: ServerOpts,
) -> Option<SerialMessage> {
    use futures::FutureExt;

    // 🔐 P0-2 兜底：先抽出"万一 panic 也要回一个 SERVFAIL"所需的素材
    //（地址、协议、ID、问题段）—— 报文马上会被消费掉，事后再查就晚了。
    let fallback = servfail_stub(&message);

    match std::panic::AssertUnwindSafe(process_inner(handler, message, server_opts))
        .catch_unwind()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            crate::log::warn!("请求处理发生未预期的 panic，已改为回 SERVFAIL（详见上面的 panic 记录）");
            fallback
        }
    }
}

/// 从原始报文里预抽构造 SERVFAIL 所需的素材；连报文都解析不了就返回 None（只能放弃应答）。
fn servfail_stub(message: &SerialMessage) -> Option<SerialMessage> {
    use crate::libdns::proto::op::{Header, Message, ResponseCode};

    let (header, queries, addr, protocol) = match message {
        SerialMessage::Raw(raw, addr, protocol) => {
            (raw.header().clone(), raw.queries().to_vec(), *addr, *protocol)
        }
        SerialMessage::Bytes(bytes, addr, protocol) => {
            let parsed = Message::from_vec(bytes.as_ref()).ok()?;
            (
                parsed.header().clone(),
                parsed.queries().to_vec(),
                *addr,
                *protocol,
            )
        }
    };

    let mut response_header = Header::response_from_request(&header);
    response_header.set_response_code(ResponseCode::ServFail);
    let mut response_message = Message::query().to_response();
    response_message.set_header(response_header);
    for query in queries {
        response_message.add_query(query);
    }

    Some(SerialMessage::raw(response_message, addr, protocol))
}

async fn process_inner(
    handler: Arc<DnsMiddlewareHandler>,
    message: SerialMessage,
    server_opts: ServerOpts,
) -> Option<SerialMessage> {
    // 返回 None 表示"静默丢弃、不作应答"——只有收到 DNS 响应包（QR=1）时才这样：
    // 对响应再回响应会形成回环，RFC 的做法就是丢弃。
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
                                                "{}Response: upstream answered NXDomain, Duration: {:?}",
                                                if server_opts.is_background {
                                                    "Background"
                                                } else {
                                                    ""
                                                },
                                                start.elapsed()
                                            );
                                        }
                                        let original = request.query().original();
                                        let background = if server_opts.is_background {
                                            "Background"
                                        } else {
                                            ""
                                        };
                                        // 🌟 设计意图（README 第 33 条，用户定调）：**对客户端一律不输出
                                        // NXDOMAIN**。部分设备（尤其苹果设备）会把 NXDOMAIN 理解成"整个名字
                                        // 不存在"，从而反复重问；改用 NOERROR + SOA（"名字在，但没有该类型记录"）
                                        // 客户端会当作有效的否定答案缓存下来，于是安静。这里严格区分两件事：
                                        //   · 上游**明确说**不存在（NXDOMAIN，带不带 SOA 都算）→ NOERROR + SOA；
                                        //   · 我们**没问到**（超时/网络故障）→ 维持 SERVFAIL，让客户端重试。
                                        match e.as_soa(original) {
                                            Some(soa) => soa,
                                            None if e.is_nx_domain() => {
                                                log::debug!(
                                                    "{}Response: NXDomain without SOA, reply as NOERROR+SOA, Duration: {:?}",
                                                    background,
                                                    start.elapsed()
                                                );
                                                // 自造一条否定 SOA：TTL 跟随 rr-ttl（管理员统一指定），
                                                // 未配置时用 60 秒——足够让客户端安静，又不会把一次上游异常长期固化。
                                                let soa_ttl = handler
                                                    .cfg()
                                                    .rr_ttl()
                                                    .map(|v| v as u32)
                                                    .unwrap_or(60);
                                                let mut res = DnsResponse::empty();
                                                res.add_query(original.to_owned());
                                                res.add_authority(crate::dns::forge_soa_record(
                                                    original.name().clone(),
                                                    soa_ttl,
                                                ));
                                                res
                                            }
                                            None => {
                                                log::debug!(
                                                    "{}Response: error resolving: {}, Duration: {:?}",
                                                    background,
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

                            // ⚠️ 这里**有意**沿用 response_header 的状态码，而不搬运 response 对象上的 rcode：
                            // 对客户端一律不输出 NXDOMAIN（理由见上面 Err 分支的注释与 README 第 33 条），
                            // 统一用 NOERROR+SOA 表达"不存在"；真正的故障由错误分支给出 SERVFAIL。
                            let mut response_message: Message =
                                response.into_message(Some(response_header));

                            // 🌟 核心修复：遵循 RFC 1035 及 EDNS0 标准，动态决定 UDP 报文截断阈值
                            if protocol == crate::libdns::Protocol::Udp {
                                use crate::libdns::proto::op::message::{HeaderCounts, update_header_counts};

                                // 1. 动态查验客户端接收能力
                                let max_payload = request.extensions()
                                    .as_ref()
                                    .map(|edns| edns.max_payload().clamp(512, 4096))
                                    .unwrap_or(512) as usize;

                                if let Ok(bytes) = response_message.to_vec()
                                    && bytes.len() > max_payload {
                                        // 2. 超过动态接收尺寸限制，贴上黄牌 (TC 截断标志)
                                        response_message.set_truncated(true);
                                        
                                        // 一次性清空 Additional 和 Authority 区域记录
                                        response_message.take_additionals();
                                        response_message.take_authorities();
                                        
                                        // 仅做最后一次防线校验：防止极端超大的 Answer 依然撑爆 Payload
                                        if let Ok(shrunk_bytes) = response_message.to_vec()
                                            && shrunk_bytes.len() > max_payload {
                                                response_message.take_answers();
                                            }

                                        // 🌟 核心修复（治理影响 A）：一旦触发物理截断，必须重新核对并覆写 Header 计数清单！
                                        let counts = HeaderCounts {
                                            query_count: response_message.queries().len(),
                                            answer_count: response_message.answers().len(),
                                            authority_count: response_message.authorities().len(),
                                            additional_count: response_message.additionals().len(),
                                        };
                                        let synced_header = update_header_counts(response_message.header(), response_message.truncated(), counts);
                                        response_message.set_header(synced_header);
                                    }
                            }

                            Some(SerialMessage::raw(response_message, addr, protocol))
                        }
                        // 🔐 P0-2：这些 OpCode 本项目不提供相应服务。
                        // RFC 1035 §4.1.1 要求：服务器不支持这类查询时回 NotImp。
                        // 原实现是 todo!()——每个这样的包都会让请求任务 panic：
                        // 请求永远没有应答、stderr 反复输出崩溃堆栈（可被刷爆日志/磁盘）。
                        OpCode::Status | OpCode::Notify | OpCode::Update | OpCode::Unknown(_) => {
                            crate::log::debug!(
                                "unsupported opcode {} from {}://{}: reply NotImp",
                                request.op_code(),
                                protocol,
                                addr
                            );
                            not_imp_response(request.header(), request.queries(), addr, protocol)
                        }
                    }
                }
                // 🔐 P0-2：收到的是一个"响应包"（QR=1）——正常情况下不该发到服务器。
                // 多半是伪造/反射流量或配置错误。绝不回应（会形成回环），静默丢弃。
                MessageType::Response => {
                    crate::log::debug!(
                        "dropping unsolicited DNS response from {}://{}",
                        protocol,
                        addr
                    );
                    None
                }
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
            Some(SerialMessage::raw(response_message, addr, protocol))
        }
        _ => Some(SerialMessage::raw(Message::query(), addr, protocol)),
    }
}

/// 构造一个 NotImp（"不支持这类查询"）应答，并回带原始 ID 与 Question 段，
/// 让客户端能把应答和请求对上号（RFC 1035 §4.1.1）。
fn not_imp_response(
    request_header: &crate::libdns::proto::op::Header,
    queries: &[crate::libdns::proto::op::Query],
    addr: std::net::SocketAddr,
    protocol: crate::libdns::Protocol,
) -> Option<SerialMessage> {
    use crate::libdns::proto::op::{Header, Message, ResponseCode};

    let mut response_header = Header::response_from_request(request_header);
    response_header.set_response_code(ResponseCode::NotImp);
    let mut response_message = Message::query().to_response();
    response_message.set_header(response_header);
    // 回带 Question 段：客户端要能把这个应答和它发的请求对上号
    for query in queries {
        response_message.add_query(query.clone());
    }

    Some(SerialMessage::raw(response_message, addr, protocol))
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

        if let Some(group) = matched_group
            && ctx.server_opts.rule_group.as_deref() != Some(group.as_str()) {
                crate::log::debug!("Client {} matched client-rule, routing to group: {}", client_ip, group);
                ctx.server_opts.rule_group = Some(group.clone());
                ctx.domain_rule = ctx.cfg().find_domain_rule(req.query().original().name(), &group);
            }

        next.run(ctx, req).await
    }
}

#[cfg(test)]
mod p0_2_tests {
    use super::*;
    use crate::libdns::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use crate::libdns::proto::rr::RecordType;
    use std::net::SocketAddr;

    fn query_message(op_code: OpCode, message_type: MessageType) -> Message {
        // 直接用 new(id, message_type, op_code)，避免依赖各版本 setter 的差异
        let mut message = Message::new(0x1234, message_type, op_code);
        message.set_recursion_desired(true);
        message.add_query(Query::query("example.com".parse().unwrap(), RecordType::A));
        message
    }

    /// 从应答里取出 Message（SerialMessage 是本项目自己的枚举，直接匹配即可）
    fn unwrap_message(response: SerialMessage) -> Box<Message> {
        match response {
            SerialMessage::Raw(message, _, _) => message,
            SerialMessage::Bytes(_, _, _) => panic!("本测试期望 Raw 应答"),
        }
    }

    #[test]
    fn test_not_imp_response_uses_right_code_and_id() {
        // 不支持的 OpCode 必须回 NotImp，并带回原始 ID 与 Question（RFC 1035 §4.1.1）
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        for op in [
            OpCode::Unknown(1), // IQUERY（已废弃，本 fork 归入 Unknown）
            OpCode::Status,
            OpCode::Notify,
            OpCode::Update,
            OpCode::Unknown(15),
        ] {
            let request = query_message(op, MessageType::Query);
            let response = not_imp_response(&request.header(), request.queries(), addr, crate::libdns::Protocol::Udp)
                .expect("必须产生应答");
            let message = unwrap_message(response);

            assert_eq!(message.id(), 0x1234, "ID 必须与请求一致");
            assert_eq!(message.message_type(), MessageType::Response);
            assert_eq!(message.response_code(), ResponseCode::NotImp);
            assert_eq!(message.queries().len(), 1, "应回带 Question 段");
        }
    }

    #[test]
    fn test_servfail_stub_builds_servfail_from_raw_and_bytes() {
        let request = query_message(OpCode::Query, MessageType::Query);
        let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();

        // Raw 变体
        let raw = SerialMessage::raw(request.clone(), addr, crate::libdns::Protocol::Udp);
        let message = unwrap_message(servfail_stub(&raw).expect("应能构造 SERVFAIL"));
        assert_eq!(message.response_code(), ResponseCode::ServFail);
        assert_eq!(message.id(), 0x1234);

        // Bytes 变体（真实 UDP/TCP 走的就是这条）
        let bytes_message =
            SerialMessage::binary(request.to_vec().unwrap(), addr, crate::libdns::Protocol::Tcp);
        let message = unwrap_message(servfail_stub(&bytes_message).expect("应能构造 SERVFAIL"));
        assert_eq!(message.response_code(), ResponseCode::ServFail);
        assert_eq!(message.id(), 0x1234);

        // 连报文都解析不了时只能放弃（返回 None，不 panic）
        let garbage = SerialMessage::binary(vec![0u8, 1, 2], addr, crate::libdns::Protocol::Udp);
        assert!(servfail_stub(&garbage).is_none());
    }
}

/// 🔐 P1-10 的回归测试：绑定失败的退避序列与重试状态机。
///
/// 这些都是纯逻辑，不占端口、不用等时间；真实的"端口被占 → 自动恢复"行为由端到端实测覆盖
/// （先占住端口启动 → 观察错误日志 → 释放端口 → 观察恢复日志 + 端口能正常查询）。
#[cfg(test)]
mod p1_10_tests {
    use super::*;

    #[test]
    fn retry_backoff_doubles_then_caps_at_60s() {
        let got: Vec<u64> = (1..=8).map(|n| retry_backoff(n).as_secs()).collect();
        assert_eq!(
            got,
            vec![1, 2, 4, 8, 16, 32, 60, 60],
            "退避必须是 1,2,4,8… 并在 60 秒封顶"
        );
        // 极端输入也不能溢出、不能失控
        assert_eq!(retry_backoff(u32::MAX).as_secs(), 60);
        assert_eq!(retry_backoff(0).as_secs(), 1);
    }

    #[test]
    fn retry_backoff_is_monotonic_and_capped() {
        let mut prev = 0;
        for attempts in 1..=100 {
            let secs = retry_backoff(attempts).as_secs();
            assert!(secs >= prev, "退避不能越试越短（attempts={attempts}）");
            assert!(secs <= 60, "退避不能超过封顶 60 秒（attempts={attempts}）");
            prev = secs;
        }
    }

    #[test]
    fn bind_retry_state_machine() {
        let t0 = Instant::now();

        // 首次失败：attempts=1，要等 1 秒才允许重试（不是立刻重试、也不是放弃）
        let mut state = BindRetry::new(t0, "127.0.0.1:53: address in use".to_string());
        assert_eq!(state.attempts, 1);
        assert!(!state.is_due(t0), "刚失败时不该立刻重试");
        assert!(!state.is_due(t0 + Duration::from_millis(999)));
        assert!(state.is_due(t0 + Duration::from_secs(1)), "到点必须允许重试");

        // 又失败一次：次数 +1、下次时间按 2 秒推后、错误信息更新
        let t1 = t0 + Duration::from_secs(1);
        state.failed_again(t1, "127.0.0.1:53: address in use (again)".to_string());
        assert_eq!(state.attempts, 2);
        assert!(!state.is_due(t1 + Duration::from_millis(1500)));
        assert!(state.is_due(t1 + Duration::from_secs(2)));
        assert!(state.last_error.contains("again"), "错误信息必须更新为最新那条");

        // 首次失败时刻不能被后续失败覆盖 —— 状态页上"累计等了多久"要算对
        assert_eq!(state.first_failed_at, t0);
        assert_eq!(state.last_failed_at, t1);
    }
}
