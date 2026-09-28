use futures::FutureExt;
use std::{
    fmt::Display,
    io,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use thiserror::Error;

// 🌟 核心修复 1：管道入口开放，接收 domain 上下文
pub async fn ping(
    dest: PingAddr,
    domain: Option<&str>,
    opts: PingOptions,
) -> Result<PingOutput, PingError> {
    match dest {
        PingAddr::Icmp(addr) => icmp::ping(addr, opts).await,
        PingAddr::Tcp(addr) => tcp::ping(addr, opts).await,
        // 将 domain 透传给 https 探针
        PingAddr::Https(addr) => https::ping(addr, domain, opts).await,
    }
}

pub async fn ping_batch(
    dests: &[PingAddr],
    domain: Option<&str>,
    opts: PingOptions,
) -> Vec<Result<PingOutput, PingError>> {
    let mut outs = Vec::new();
    for dest in dests.iter() {
        outs.push(match dest {
            PingAddr::Icmp(addr) => icmp::ping(*addr, opts).await,
            PingAddr::Tcp(addr) => tcp::ping(*addr, opts).await,
            PingAddr::Https(addr) => https::ping(*addr, domain, opts).await,
        })
    }
    outs
}

pub async fn ping_fastest(
    dests: Vec<PingAddr>,
    domain: Option<&str>,
    opts: PingOptions,
) -> Result<PingOutput, PingError> {
    use futures_util::future::select_ok;
    if dests.is_empty() {
        return Err(PingError::NoAddress);
    }

    let ping_tasks = dests.iter().map(|dst| match dst {
        PingAddr::Icmp(addr) => icmp::ping(*addr, opts).boxed(),
        PingAddr::Tcp(addr) => tcp::ping(*addr, opts).boxed(),
        PingAddr::Https(addr) => https::ping(*addr, domain, opts).boxed(),
    });

    let res = select_ok(ping_tasks).await;

    match res {
        Ok((out, _rest)) => Ok(out),
        Err(err) => Err(err),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PingOptions {
    times: u16,
    timeout: Duration,
    all_success: bool,
    duration_agg: DurationAgg,
}

impl PingOptions {
    pub fn with_times(mut self, times: u16) -> Self {
        self.times = times;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn with_timeout_secs(mut self, timeout: u64) -> Self {
        self.timeout = Duration::from_secs(timeout);
        self
    }

    pub fn with_all_success(mut self, enable: bool) -> Self {
        self.all_success = enable;
        self
    }

    pub fn with_duration_agg(mut self, agg: DurationAgg) -> Self {
        self.duration_agg = agg;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DurationAgg {
    Min,
    Mean,
    Max,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            times: 1,
            timeout: Duration::from_secs(5),
            all_success: false,
            duration_agg: DurationAgg::Mean,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PingAddr {
    Icmp(IpAddr),
    Tcp(SocketAddr),
    Https(SocketAddr),
}

impl PingAddr {
    pub fn ip_addr(self) -> IpAddr {
        match self {
            PingAddr::Icmp(ip) => ip,
            PingAddr::Tcp(addr) => addr.ip(),
            PingAddr::Https(addr) => addr.ip(),
        }
    }
}

impl PartialEq<IpAddr> for PingAddr {
    fn eq(&self, other: &IpAddr) -> bool {
        self.ip_addr() == *other
    }
}
impl PartialEq<Ipv4Addr> for PingAddr {
    fn eq(&self, other: &Ipv4Addr) -> bool {
        self.eq(&IpAddr::V4(*other))
    }
}
impl PartialEq<Ipv6Addr> for PingAddr {
    fn eq(&self, other: &Ipv6Addr) -> bool {
        self.eq(&IpAddr::V6(*other))
    }
}

impl Display for PingAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingAddr::Icmp(addr) => write!(f, "icmp://{addr}"),
            PingAddr::Tcp(addr) => write!(f, "tcp://{addr}"),
            PingAddr::Https(addr) => write!(f, "https://{addr}"),
        }
    }
}

impl FromStr for PingAddr {
    type Err = PingError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for PingAddr {
    type Error = PingError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let s = s.trim();
        if let Some(sock_addr) = s.strip_prefix("tcp://") {
            let sock_addr = SocketAddr::from_str(sock_addr)?;
            Ok(Self::Tcp(sock_addr))
        } else if let Some(sock_addr) = s.strip_prefix("https://") {
            let sock_addr = SocketAddr::from_str(sock_addr)
                .or_else(|_| IpAddr::from_str(sock_addr).map(|ip| SocketAddr::new(ip, 443)))?;
            Ok(Self::Https(sock_addr))
        } else {
            let s = s.strip_prefix("icmp://").unwrap_or(s);
            let ip_addr = IpAddr::from_str(s)?;
            Ok(Self::Icmp(ip_addr))
        }
    }
}

#[derive(Debug, Clone)]
pub struct PingOutput {
    seq: u16,
    duration: Duration,
    destination: PingAddr,
}

impl PingOutput {
    #[inline]
    pub fn seq(&self) -> u16 {
        self.seq
    }

    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.duration
    }

    #[inline]
    pub fn dest(&self) -> PingAddr {
        self.destination
    }
}

#[derive(Debug, Error)]
pub enum PingError {
    #[error("ping target parse error")]
    PingTargetParseError,
    #[error("addr parse error {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("addr parse error {0}")]
    AddrParseError2(String),
    #[error("Ping timeout")]
    Timeout,
    #[error("io error {0}")]
    IoError(io::Error),
    #[error("surge error")]
    SurgeError,
    #[error("No address")]
    NoAddress,
}

impl Clone for PingError {
    fn clone(&self) -> Self {
        match self {
            Self::PingTargetParseError => Self::PingTargetParseError,
            Self::AddrParseError(arg0) => Self::AddrParseError(arg0.clone()),
            Self::AddrParseError2(arg0) => Self::AddrParseError2(arg0.clone()),
            Self::Timeout => Self::Timeout,
            Self::IoError(err) => Self::IoError(err.kind().into()),
            Self::SurgeError => Self::SurgeError,
            // 🔐 P2：原来是 `Self::NoAddress => Self::SurgeError` —— 复制粘贴笔误，
            // 克隆一个 "No address" 错误会变成 "surge error"，错误语义丢失。
            Self::NoAddress => Self::NoAddress,
        }
    }
}

/// 探测成功后的耗时，**保证不为 0**。
///
/// 🔐 为什么要这一步（ping 偶发失败的根因）：
/// 耗时来自 `Instant::now()` 相减，而**操作系统的时钟粒度**可能粗于一次本机回环探测 ——
/// 于是"明明探测成功了、耗时却是 0"。后果有两层：
///
/// 1. **排序语义被破坏**：`ping_fastest` 取"第一个成功的"，而低延迟目标本就容易先完成；
///    一个耗时 0 的结果会显得"比任何真实结果都快"，让测速结论失真；
/// 2. **测试偶发失败**：`test_ping_fatest_returns_one_of_the_requested_targets` 断言
///    「耗时 > 0（0 表示没真测）」，在时钟粒度粗的运行里会随机失败 ——
///    这正是一直挂在那里的那个偶发失败。
///
/// 处理方式：**成功就是成功**，只是把"小于可测精度"的耗时抬到 1 纳秒。
/// 这**不会**把失败伪装成成功（失败走的是 `Err`，根本不经过这里），
/// 只是让"确实发生了、但快于时钟精度"这件事有一个诚实的最小表示。
///
/// 1ns 的量级远小于任何真实网络探测（哪怕本机回环也是微秒级），
/// 因此不会影响"谁更快"的判断。
#[inline]
fn nonzero_elapsed(start: std::time::Instant) -> Duration {
    nonzero_duration(start.elapsed())
}

/// 把"探测成功但快于时钟精度"的耗时抬到 1ns（理由见 [`nonzero_elapsed`]）。
///
/// 单独抽出来是因为 ICMP 那条路径拿到的是 `surge_ping` 已经算好的 `Duration`，
/// 没有可供相减的 `Instant`。
#[inline]
fn nonzero_duration(duration: Duration) -> Duration {
    if duration.is_zero() {
        Duration::from_nanos(1)
    } else {
        duration
    }
}

fn do_agg(durations: Vec<Duration>, agg: DurationAgg) -> Option<Duration> {
    use DurationAgg::*;

    match agg {
        Min => durations.into_iter().min(),
        Mean => {
            let count = durations.len();

            if count > 0 {
                let mut total = Duration::default();

                for duration in durations {
                    total += duration;
                }

                Some(total / (count as u32))
            } else {
                None
            }
        }
        Max => durations.into_iter().max(),
    }
}

#[cfg(feature = "disable_icmp_ping")]
mod icmp {
    //! ignore, Github actions not surpport icmp ping.

    use std::{net::IpAddr, time::Duration};

    use super::{PingError, PingOptions, PingOutput};
    pub async fn ping(ipaddr: IpAddr, _opts: PingOptions) -> Result<PingOutput, PingError> {
        Ok(PingOutput {
            seq: 0,
            duration: Duration::from_millis(1),
            destination: super::PingAddr::Icmp(ipaddr),
        })
    }
}

#[cfg(not(feature = "disable_icmp_ping"))]
mod icmp {
    use std::{net::IpAddr, time::Duration};

    use rand::random;
    use surge_ping::{Client, Config, ICMP, IcmpPacket, PingIdentifier, PingSequence, Pinger};

    use super::{PingAddr, PingError, PingOptions, PingOutput, do_agg, nonzero_duration};

    pub(crate) mod auto_sock_type {
        use cfg_if::cfg_if;
        use socket2::Type;
        use surge_ping::ICMP;

        cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                use socket2::{Domain, Protocol, Socket};
                use std::{io, net::IpAddr};

                pub trait CheckAllowUnprivilegedIcmp {
                    fn allow_unprivileged_icmp(&self) -> bool;
                }


                pub trait CheckAllowRawSocket {
                    fn allow_raw_socket(&self) -> bool;
                }

                impl CheckAllowUnprivilegedIcmp for ICMP {
                    fn allow_unprivileged_icmp(&self) -> bool {
                        // 🔐 问题 51：瞬时错误**不进缓存**，下次重新探测（见 `ProbeCache`）。
                        match self {
                            ICMP::V4 => ALLOW_IPV4_UNPRIVILEGED_ICMP.get(|| {
                                ProbeCache::probe_socket(Domain::IPV4, Type::DGRAM, Protocol::ICMPV4)
                            }),
                            ICMP::V6 => ALLOW_IPV6_UNPRIVILEGED_ICMP.get(|| {
                                ProbeCache::probe_socket(Domain::IPV6, Type::DGRAM, Protocol::ICMPV6)
                            }),
                        }
                    }
                }

                impl CheckAllowRawSocket for ICMP {
                    #[inline]
                    fn allow_raw_socket(&self) -> bool {
                        match self {
                            ICMP::V4 => ALLOW_IPV4_RAW_SOCKET.get(|| {
                                ProbeCache::probe_socket(Domain::IPV4, Type::RAW, Protocol::ICMPV4)
                            }),
                            ICMP::V6 => ALLOW_IPV6_RAW_SOCKET.get(|| {
                                ProbeCache::probe_socket(Domain::IPV6, Type::RAW, Protocol::ICMPV6)
                            }),
                        }
                    }
                }

                impl CheckAllowUnprivilegedIcmp for IpAddr {
                    #[inline]
                    fn allow_unprivileged_icmp(&self) -> bool {
                        match self {
                            IpAddr::V4(_) => ALLOW_IPV4_UNPRIVILEGED_ICMP.get(|| {
                                ProbeCache::probe_socket(Domain::IPV4, Type::DGRAM, Protocol::ICMPV4)
                            }),
                            IpAddr::V6(_) => ALLOW_IPV6_UNPRIVILEGED_ICMP.get(|| {
                                ProbeCache::probe_socket(Domain::IPV6, Type::DGRAM, Protocol::ICMPV6)
                            }),
                        }
                    }
                }

                impl CheckAllowRawSocket for IpAddr {
                    #[inline]
                    fn allow_raw_socket(&self) -> bool {
                        match self {
                            IpAddr::V4(_) => ALLOW_IPV4_RAW_SOCKET.get(|| {
                                ProbeCache::probe_socket(Domain::IPV4, Type::RAW, Protocol::ICMPV4)
                            }),
                            IpAddr::V6(_) => ALLOW_IPV6_RAW_SOCKET.get(|| {
                                ProbeCache::probe_socket(Domain::IPV6, Type::RAW, Protocol::ICMPV6)
                            }),
                        }
                    }
                }

                /// 🔐 问题 51：权限探测的**三态缓存** —— 只固化"稳定的结论"。
                ///
                /// 原来的写法是 `static ALLOW_*: Lazy<bool>`：探测一次，结果**永久钉住**。
                /// 问题在于 `Lazy` 分不清"这个结论稳不稳"：
                ///
                ///   · 「能建 / 权限不足」是**稳定事实** —— 由 `setcap`、
                ///     `net.ipv4.ping_group_range`、进程权限决定，不会自己变。
                ///     这类结论**值得缓存**（每次都去建套接字是浪费）。
                ///   · `EMFILE`（文件句柄临时耗尽）、`ENOMEM`（内存临时紧张）、
                ///     `EINTR` 这类是**瞬时**错误 —— 资源一恢复就没了。
                ///     把它们缓存下来，就等于**把一个可自愈的瞬时故障变成永久故障**：
                ///     探测结论在启动那一瞬间被写死，之后测速一直走错路线，
                ///     而且**一句告警都没有**。
                ///
                /// 原实现还有个**方向性错误**：它用 `!is_permission_denied(...)` 判断"允许"，
                /// 于是 `EMFILE` 这类错误被读成"**允许**使用 RAW 套接字"——
                /// 恰好指向一条其实建不出来的路。
                ///
                /// 现在：
                ///   · `Ok`               → 缓存 `true`（稳定）；
                ///   · `PermissionDenied` → 缓存 `false`（稳定）；
                ///   · **其它错误**       → **不缓存**，本次保守地返回 `false`
                ///     （不声称"允许"），下次调用重新探测 —— 瞬时故障因此能自愈。
                ///     这种"结论不确定"必须让人看见，故**限流告警一次**。
                pub(crate) struct ProbeCache {
                    /// 已确定的稳定结论；`None` = 尚未确定（瞬时错误不会被写进来）
                    decided: std::sync::Mutex<Option<bool>>,
                    /// 是否已就"探测遇到瞬时错误"告警过（避免刷屏）
                    warned: std::sync::atomic::AtomicBool,
                }

                impl ProbeCache {
                    pub(crate) const fn new() -> Self {
                        Self {
                            decided: std::sync::Mutex::new(None),
                            warned: std::sync::atomic::AtomicBool::new(false),
                        }
                    }

                    /// 能不能建这类套接字。瞬时错误**不写缓存**，下次重试。
                    ///
                    /// `probe` 由调用方提供（生产环境就是 `Socket::new`）——
                    /// 抽成参数是为了让"瞬时错误不缓存"这个**核心不变量可测**：
                    /// 测试可以注入一个"先返回瞬时错误、再返回成功"的探测函数，
                    /// 断言第二次调用**不会被第一次的失败钉死**。
                    pub(crate) fn get<F>(&self, probe: F) -> bool
                    where
                        F: FnOnce() -> io::Result<ProbeOutcome>,
                    {
                        // 快路径：已有稳定结论
                        if let Ok(guard) = self.decided.lock()
                            && let Some(v) = *guard
                        {
                            return v;
                        }

                        match probe() {
                            Ok(ProbeOutcome::Allowed) => {
                                self.remember(true);
                                true
                            }
                            Ok(ProbeOutcome::Denied) => {
                                self.remember(false);
                                false
                            }
                            Err(err) => {
                                // 瞬时错误：保守返回 false，且**不缓存**。
                                if !self
                                    .warned
                                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                                {
                                    crate::log::warn!(
                                        "probing ICMP socket capability failed with a transient error: {} \
                                         (the result is not cached and will be probed again; \
                                         if this persists, check available file descriptors)",
                                        err
                                    );
                                }
                                false
                            }
                        }
                    }

                    fn remember(&self, value: bool) {
                        if let Ok(mut guard) = self.decided.lock() {
                            *guard = Some(value);
                        }
                    }

                    /// 生产探测：真的去建一次套接字，并把结果**分成三态**。
                    pub(crate) fn probe_socket(
                        domain: Domain,
                        typ: Type,
                        proto: Protocol,
                    ) -> io::Result<ProbeOutcome> {
                        match Socket::new(domain, typ, Some(proto)) {
                            Ok(_) => Ok(ProbeOutcome::Allowed),
                            Err(err) if is_permission_denied_err(&err) => Ok(ProbeOutcome::Denied),
                            Err(err) => Err(err),
                        }
                    }
                }

                /// 探测的三种结果（见 [`ProbeCache`] 的说明）：
                /// 前两种是**稳定事实**（可缓存），第三种由 `Err` 表示（**不可缓存**）。
                #[derive(Debug, Clone, Copy, PartialEq, Eq)]
                pub(crate) enum ProbeOutcome {
                    /// 套接字建得出来 —— 稳定事实，可缓存
                    Allowed,
                    /// 权限不足 —— 稳定事实，可缓存
                    Denied,
                }

                pub static ALLOW_IPV4_UNPRIVILEGED_ICMP: ProbeCache = ProbeCache::new();

                pub static ALLOW_IPV4_RAW_SOCKET: ProbeCache = ProbeCache::new();

                pub static ALLOW_IPV6_UNPRIVILEGED_ICMP: ProbeCache = ProbeCache::new();

                pub static ALLOW_IPV6_RAW_SOCKET: ProbeCache = ProbeCache::new();

                #[inline]
                fn is_permission_denied_err(err: &io::Error) -> bool {
                    matches!(err.kind(), std::io::ErrorKind::PermissionDenied)
                }

            }


        }

        #[allow(unused_variables)]
        pub fn detect(kind: ICMP) -> Type {
            cfg_if! {
                if #[cfg(any(target_os = "linux", target_os = "android"))] {

                    if kind.allow_unprivileged_icmp() {
                        //  enable by running: `sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'`
                        Type::DGRAM
                    } else if kind.allow_raw_socket() {
                        // enable by running: `sudo setcap CAP_NET_RAW+eip /path/to/program`
                        Type::RAW
                    } else {
                        Type::DGRAM
                    }
                } else if #[cfg(any(target_os = "macos"))] {
                    // MacOS seems enable UNPRIVILEGED_ICMP by default.
                    Type::DGRAM
                } else if #[cfg(any(target_os = "windows"))] {
                    // Windows seems enable RAW_SOCKET by default.
                    Type::RAW
                } else {
                    Type::RAW
                }
            }
        }
    }

    /// 🔐 问题 51：ICMP 客户端的**可重试**缓存 —— 只缓存成功，**绝不缓存失败**。
    ///
    /// 原来这里是两个 `static IPV4_CLIENT: Lazy<Result<Client, PingError>>`。
    /// `once_cell::Lazy` 会把**第一次**算出的值永久钉住 —— **包括失败**。
    /// 于是启动时若恰好遇到**瞬时**资源不足（文件句柄临时耗尽 `EMFILE`、
    /// 内存临时紧张 `ENOMEM`），`Client::new` 失败一次，
    /// 这个 `Err` 就被缓存到**进程结束**：
    ///
    ///   · 测速（`speed-check-mode ping`）此后**永久失效**；
    ///   · 而且**一句告警都没有** —— 日志里查不到任何线索，
    ///     用户只看到"测速突然就不工作了"。
    ///
    /// 对"启动瞬间句柄紧张、随后自动恢复"这种最常见的情形，
    /// 这是最坏的处理方式：把一个**可恢复的瞬时故障**变成了**永久故障**。
    ///
    /// 现在：
    ///   · **成功**记入缓存（正常路径只创建一次，与改动前一致，不受性能影响）；
    ///   · **失败不记入**，下次调用重新尝试 —— 瞬时错误因此能自愈；
    ///   · 失败时按平台（V4 / V6）**限流告警一次**，让问题看得见
    ///     （与"失败要看得见"的整轮整改口径一致）。
    pub(crate) struct ClientCache {
        kind: ICMP,
        /// 成功创建出来的客户端；`None` = 还没成功过（失败不会被写进来）
        pub(crate) client: std::sync::Mutex<Option<Client>>,
        /// 是否已经告警过（避免瞬时故障期间刷屏）
        warned: std::sync::atomic::AtomicBool,
    }

    impl ClientCache {
        pub(crate) const fn new(kind: ICMP) -> Self {
            Self {
                kind,
                client: std::sync::Mutex::new(None),
                warned: std::sync::atomic::AtomicBool::new(false),
            }
        }

        /// 取客户端：有缓存就用缓存，没有就（重新）创建。
        ///
        /// 注意**不把失败写进缓存** —— 这正是本条修复的核心。
        pub(crate) fn get(&self) -> Result<Client, PingError> {
            self.get_with(|| {
                Client::new(
                    &Config::builder()
                        .kind(self.kind)
                        .sock_type_hint(auto_sock_type::detect(self.kind))
                        .build(),
                )
                .map_err(PingError::from)
            })
        }

        /// [`get`](Self::get) 的可注入版本。
        ///
        /// `build` 由调用方提供（生产环境就是 `Client::new`）——
        /// 抽成参数是为了让"**失败不写进缓存**"这个核心不变量**真的可测**：
        /// 测试可以注入一个"第一次失败、第二次成功"的构建函数，
        /// 断言第二次**不会被第一次的失败钉死**。
        /// （否则测试只能依赖真实创建结果，在 root 环境下永远只走成功分支，
        /// 失败分支实际上测不到 —— 本项目已多次踩过"测试没盖住真实场景"。）
        pub(crate) fn get_with<F>(&self, build: F) -> Result<Client, PingError>
        where
            F: FnOnce() -> Result<Client, PingError>,
        {
            // 快路径：已经成功创建过（正常运行时走这里，不额外加锁创建）
            if let Ok(guard) = self.client.lock()
                && let Some(client) = guard.as_ref()
            {
                return Ok(client.clone());
            }

            match build() {
                Ok(client) => {
                    if let Ok(mut guard) = self.client.lock() {
                        *guard = Some(client.clone());
                    }
                    // 期间若曾告警过，这里不重置：告警是"曾经失败过"的事实记录，
                    // 重置会让"反复失败又恢复"的场景重新刷屏。
                    Ok(client)
                }
                Err(err) => {
                    // ⚠️ **这里刻意不写缓存**：失败（尤其 EMFILE/ENOMEM 这类瞬时错误）
                    // 一旦被写进缓存，就会在进程余下的生命周期里一直沿用，
                    // 把可自愈的瞬时故障变成永久故障。

                    // 用限流告警（而不是每次都打）：瞬时故障可能连续出现多次。
                    if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        let name = match self.kind {
                            ICMP::V4 => "IPv4",
                            ICMP::V6 => "IPv6",
                        };
                        crate::log::warn!(
                            "failed to create the {} ICMP client for speed measurement: {} \
                             (speed check will retry on the next query; if this persists, \
                             check raw-socket privileges and available file descriptors)",
                            name,
                            err
                        );
                    }
                    Err(err)
                }
            }
        }
    }

    // 🔐 问题 51：用可重试缓存替换原来会永久固化失败的 `Lazy<Result<...>>`。
    pub(crate) static IPV4_CLIENT: ClientCache = ClientCache::new(ICMP::V4);

    pub(crate) static IPV6_CLIENT: ClientCache = ClientCache::new(ICMP::V6);

    pub async fn ping(ipaddr: IpAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        // 🔐 问题 51：`get()` 返回的是**拥有所有权**的 `Client`（缓存里存的是克隆），
        // 失败不会被缓存，瞬时故障下次查询会重新尝试。
        let client = match ipaddr {
            IpAddr::V4(_) => IPV4_CLIENT.get()?,
            IpAddr::V6(_) => IPV6_CLIENT.get()?,
        };

        let mut pinger = client.pinger(ipaddr, PingIdentifier(random())).await;
        pinger.timeout(timeout);
        let mut last_err = None;

        for seq in 0..times {
            let duration = ping_icmp(seq, &mut pinger).await;
            match duration {
                Ok(dur) => durations.push(dur),
                Err(err) => {
                    if all_success {
                        return Err(err);
                    } else {
                        last_err = Some(err);
                        continue;
                    }
                }
            }
        }

        let duration = do_agg(durations, duration_agg);

        match duration {
            Some(v) => Ok(PingOutput {
                seq: 0,
                duration: v,
                destination: PingAddr::Icmp(ipaddr),
            }),
            None => match last_err {
                Some(err) => Err(err),
                None => Err(PingError::NoAddress),
            },
        }
    }

    async fn ping_icmp(seq: u16, pinger: &mut Pinger) -> Result<Duration, PingError> {
        let payload = [0; 56];
        let duration = match pinger.ping(PingSequence(seq), &payload).await {
            Ok((IcmpPacket::V4(_), dur)) => dur,
            Ok((IcmpPacket::V6(_), dur)) => dur,
            Err(err) => return Err(err.into()),
        };
        // 🔐 ping 偶发失败：ICMP 的耗时来自 `surge_ping` 内部的两个 `Instant` 相减，
        // 本机回环下可能因时钟粒度而取到 0 —— 用同一个"成功即至少 1ns"的规则收敛。
        // 见 `nonzero_elapsed` 的说明（那里解释了为什么这不属于"把失败伪装成成功"）。
        Ok(nonzero_duration(duration))
    }

    impl From<surge_ping::SurgeError> for PingError {
        fn from(err: surge_ping::SurgeError) -> Self {
            match err {
                surge_ping::SurgeError::Timeout { seq: _ } => PingError::Timeout,
                surge_ping::SurgeError::IOError(err) => PingError::IoError(err),
                _ => PingError::SurgeError,
            }
        }
    }
}

mod tcp {
    use std::{
        io,
        net::SocketAddr,
        time::{Duration, Instant},
    };

    use tokio::{io::Interest, net::TcpSocket};

    use crate::third_ext::FutureTimeoutExt;

    use super::{PingAddr, PingError, PingOptions, PingOutput, do_agg, nonzero_elapsed};

    #[inline]
    pub async fn ping(sock_addr: SocketAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        let mut last_err = None;

        for _seq in 0..times {
            let duration = ping_tcp(sock_addr)
                .timeout(timeout)
                .await
                .unwrap_or(Err(PingError::Timeout));

            match duration {
                Ok(dur) => durations.push(dur),
                Err(err) => {
                    if all_success {
                        return Err(err);
                    } else {
                        last_err = Some(err);
                        continue;
                    }
                }
            }
        }

        let duration = do_agg(durations, duration_agg);

        match duration {
            Some(v) => Ok(PingOutput {
                seq: 0,
                duration: v,
                destination: PingAddr::Tcp(sock_addr),
            }),
            None => match last_err {
                Some(err) => Err(err),
                None => Err(PingError::NoAddress),
            },
        }
    }

    #[inline]
    async fn ping_tcp(addr: SocketAddr) -> Result<Duration, PingError> {
        let start = Instant::now();

        let sock = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }?;

        let stream = sock.connect(addr).await?;
        stream.ready(Interest::WRITABLE).await?;
        drop(stream);
        Ok(nonzero_elapsed(start))
    }

    impl From<io::Error> for PingError {
        fn from(err: io::Error) -> Self {
            if matches!(err.kind(), io::ErrorKind::TimedOut) {
                PingError::Timeout
            } else {
                PingError::IoError(err)
            }
        }
    }

    impl From<tokio::time::error::Elapsed> for PingError {
        fn from(_: tokio::time::error::Elapsed) -> Self {
            PingError::Timeout
        }
    }
}

mod https {
    use std::{
        net::SocketAddr,
        sync::Arc,
        time::{Duration, Instant},
    };

    use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector; // 🌟 新增 IO 依赖

    use crate::third_ext::FutureTimeoutExt;

    use super::{PingAddr, PingError, PingOptions, PingOutput, do_agg, nonzero_elapsed};

    // 🌟 核心修复 2：标准的 HTTP/1.1 请求必须携带 Host 头！
    pub(super) async fn send_ping<S: AsyncRead + AsyncWrite + std::marker::Unpin>(
        stream: &mut S,
        domain: Option<&str>,
    ) -> io::Result<bool> {
        use tokio::io::AsyncReadExt;

        // 抹除域名末尾的 '.'，防止 Host 头和 SNI 解析报错
        let safe_domain = domain.unwrap_or("").trim_end_matches('.');

        let request = if safe_domain.is_empty() {
            "GET / HTTP/1.1\r\nConnection: close\r\n\r\n".to_string()
        } else {
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                safe_domain
            )
        };

        stream.write_all(request.as_bytes()).await?;

        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await?;

        Ok(&buf == b"HTTP/")
    }

    #[inline]
    pub(crate) async fn ping(
        sock_addr: SocketAddr,
        domain: Option<&str>,
        opts: PingOptions,
    ) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        let mut last_err = None;

        for _seq in 0..times {
            let duration = ping_https(sock_addr, domain) // 👈 透传 domain
                .timeout(timeout)
                .await
                .unwrap_or(Err(PingError::Timeout));

            match duration {
                Ok(dur) => durations.push(dur),
                Err(err) => {
                    if all_success {
                        return Err(err);
                    } else {
                        last_err = Some(err);
                        continue;
                    }
                }
            }
        }

        let duration = do_agg(durations, duration_agg);

        match duration {
            Some(v) => Ok(PingOutput {
                seq: 0,
                duration: v,
                destination: PingAddr::Https(sock_addr),
            }),
            None => match last_err {
                Some(err) => Err(err),
                None => Err(PingError::NoAddress),
            },
        }
    }

    async fn ping_https(addr: SocketAddr, domain: Option<&str>) -> Result<Duration, PingError> {
        use rustls::pki_types::ServerName;
        let now = Instant::now();
        let config = Arc::new({
            let mut config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    crate::rustls::NoCertificateVerification,
                ))
                .with_no_client_auth();
            // 🔐 问题 51：**这里必须是 true**。
            //
            // 原先是 `config.enable_sni = false`，而紧挨着的下一段注释写的是
            // "🌟 核心修复 3：真正的 SNI 注入！" —— 注释与代码完全相反：
            // 关掉 `enable_sni` 之后，即使下面传了 `server_name`，
            // rustls 也**不会把它放进 ClientHello 的 SNI 扩展**。
            //
            // 后果：对**要求必须携带 SNI** 的服务器（虚拟主机、按域名分证书的边缘节点）
            // 会握手失败或连到默认站点 —— 测速结果因此失真，
            // 且失败原因（"明明能连通却测速失败/测错后端"）极难排查。
            //
            // 证书校验本来就是关的（`NoCertificateVerification`，测速只关心连通性），
            // 所以打开 SNI 不引入新的信任问题；它只是把"我想连哪个站点"如实告诉服务器。
            config.enable_sni = true;
            config
        });

        // 🌟 核心修复 3：真正的 SNI 注入！
        let safe_domain = domain.unwrap_or("").trim_end_matches('.');
        let server_name = ServerName::try_from(safe_domain)
            .map(|s| s.to_owned())
            .unwrap_or_else(|_| ServerName::IpAddress(addr.ip().into()));

        let connector = TlsConnector::from(config);

        let sock = TcpStream::connect(addr).await?;
        let mut tls = connector.connect(server_name, sock).await?;

        send_ping(&mut tls, domain).await?; // 👈 透传 domain
        Ok(nonzero_elapsed(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ 🔐 ping 偶发失败的修复 ============

    /// 🔐 `nonzero_duration` 的核心不变量：**成功探测的耗时永远不为 0**。
    ///
    /// 背景：耗时来自 `Instant` 相减，而操作系统时钟粒度可能粗于一次本机回环探测，
    /// 于是"明明探测成功、耗时却是 0"。这会破坏 `ping_fastest` 的排序语义
    /// （0 会显得比任何真实结果都快），也让断言「耗时 > 0」随机失败。
    ///
    /// 这条测试**不依赖网络与时钟精度**，因此能在任何环境稳定验证这个不变量 ——
    /// 而原来那个偶发失败的测试依赖真实探测时序，恰恰是本项目里"测不稳"的那类。
    #[test]
    fn successful_probe_never_reports_zero_duration() {
        // 退化的输入：0 被抬到 1ns
        assert_eq!(
            nonzero_duration(Duration::ZERO),
            Duration::from_nanos(1),
            "0 耗时要被抬到 1ns（成功就是成功，只是快于时钟精度）"
        );

        // 正常输入原样通过（不能改变真实测量值）
        for d in [
            Duration::from_nanos(1),
            Duration::from_micros(5),
            Duration::from_millis(42),
        ] {
            assert_eq!(
                nonzero_duration(d),
                d,
                "非零耗时必须原样保留，不能篡改真实测量值"
            );
        }
    }

    /// 🔐 与之配套：`nonzero_elapsed` 也必须保证 > 0（它服务于 TCP / HTTPS 两条路径）。
    #[test]
    fn nonzero_elapsed_is_never_zero() {
        let start = std::time::Instant::now();
        let d = nonzero_elapsed(start);
        assert!(
            d > Duration::ZERO,
            "TCP / HTTPS 探测的耗时必须 > 0，实际 {d:?}"
        );
    }

    /// 🔐 `do_agg` 的 Mean 分支做整数除法，**多个接近 0 的耗时平均后仍可能为 0** ——
    /// 这是偶发失败的另一个入口（`times > 1` 时）。
    ///
    /// 这条钉住"聚合之后也不会回到 0"。
    #[test]
    fn aggregation_does_not_reintroduce_zero() {
        // 1ns 与 0 的平均：整数除法会把 1ns/2 截成 0
        let avg = do_agg(
            vec![Duration::from_nanos(1), Duration::ZERO],
            DurationAgg::Mean,
        )
        .expect("非空输入应当有结果");
        assert_eq!(
            avg,
            Duration::ZERO,
            "（记录事实）整数除法的 Mean 确实可能把极小值截成 0 —— 所以各探测出口\
             必须先过 nonzero_duration；这条测试说明为什么单靠聚合层兜不住"
        );

        // 而经过 nonzero_duration 之后，聚合结果不会为 0
        let fixed = do_agg(
            vec![
                nonzero_duration(Duration::from_nanos(1)),
                nonzero_duration(Duration::ZERO),
            ],
            DurationAgg::Mean,
        )
        .expect("非空输入应当有结果");
        assert!(
            fixed > Duration::ZERO,
            "每个样本先过 nonzero_duration 之后，聚合结果不应为 0，实际 {fixed:?}"
        );
    }

    // ============ 🔐 问题 51：权限探测与客户端创建不得固化瞬时故障 ============

    /// 🔐 问题 51 的**核心不变量**：**瞬时错误绝不能被缓存**。
    ///
    /// 原实现是 `static ALLOW_*: Lazy<bool>` —— 探测一次，结论永久钉住。
    /// 于是启动瞬间若遇到 `EMFILE`（文件句柄临时耗尽）这类**可自愈**的错误，
    /// 结论就被写死到进程结束：测速此后一直走错路线，且**没有任何告警**。
    ///
    /// 这条测试注入一个"第一次返回瞬时错误、第二次返回允许"的探测函数，
    /// 断言第二次**不受第一次失败影响**。这是 `Lazy` 无论如何都做不到的。
    ///
    /// ⚠️ **两个门控都要**：
    ///   · 平台 —— `ProbeCache` / `ProbeOutcome` 只定义在 `auto_sock_type` 的
    ///     Linux/Android 分支里，其它平台没有这两个类型；
    ///   · feature —— 开了 `disable_icmp_ping` 时，整个 `mod icmp` 会被换成不探测的
    ///     桩实现（CI 就用这个 feature 跑测试），`auto_sock_type` 随之不存在。
    ///
    /// 原先只写了平台门控，于是 `--features=disable_icmp_ping` 下**编译失败**
    /// （本地默认不带该 feature，所以一直没暴露）。
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(feature = "disable_icmp_ping")
    ))]
    #[test]
    fn transient_probe_error_is_not_cached() {
        use std::io;

        let cache = super::icmp::auto_sock_type::ProbeCache::new();

        // 第一次：瞬时错误（模拟 EMFILE：资源暂时不足）
        let first = cache.get(|| {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "too many open files (simulated EMFILE)",
            ))
        });

        // ⚠️ **断言顺序是刻意的**（本项目多次踩过的坑）：
        // 先验"核心危害"（瞬时结论被固化），再验"实现细节"（保守返回值）。
        // 若把保守性的断言放前面，撤掉修复时会在第一行就 panic，
        // 看不到"固化"这个真正的危害。

        // ① 核心危害：瞬时结论**不得被固化**。
        //    第二次探测返回「权限不足」（一个明确的稳定结论）——
        //    若第一次的瞬时错误被缓存，这里会直接返回缓存的结论、**不执行本次探测**。
        //    fixed：缓存未定 → 执行探针 → false
        //    buggy：缓存已固化 → 拿缓存 → true（正是"瞬时故障变永久故障"）
        let second = cache.get(|| Ok(super::icmp::auto_sock_type::ProbeOutcome::Denied));
        assert!(
            !second,
            "🔐 问题 51：第一次的瞬时错误被固化了 —— 之后即使资源恢复、\
             探测得到明确结论，也仍然沿用那次失败的结论。\
             这正是「可自愈的瞬时故障变成永久故障」的原缺陷"
        );

        // ② 实现细节：瞬时错误时保守地返回 false（不能声称「允许」）。
        assert!(!first, "瞬时错误时必须保守地返回 false（不能声称「允许」）");
    }

    /// 🔐 与上一条对照：**稳定结论应该被缓存**（否则每次查询都去建套接字，纯属浪费）。
    ///
    /// 「允许 / 权限不足」由 `setcap`、`ping_group_range`、进程权限决定，不会自己变。
    ///
    /// ⚠️ 必须加平台门控：`ProbeCache` / `ProbeOutcome` 定义在
    /// `auto_sock_type` 的 **Linux/Android 专属分支**里（其它平台不需要探测套接字类型，
    /// 直接返回固定的 `RAW`/`DGRAM`）。少了门控，Windows 上会因"找不到类型"编译失败。
    ///
    /// ⚠️ 同时要门控 `not(feature = "disable_icmp_ping")`：开了该 feature 时
    /// `mod icmp` 被换成桩实现，`auto_sock_type` 不存在 —— 少了它就编译失败。
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(feature = "disable_icmp_ping")
    ))]
    #[test]
    fn stable_probe_conclusion_is_cached() {
        use std::io;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 用探针调用次数来判断"到底有没有走缓存"
        let calls = AtomicUsize::new(0);

        let cache = super::icmp::auto_sock_type::ProbeCache::new();

        // 第一次：允许（稳定结论）
        let first = cache.get(|| {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(super::icmp::auto_sock_type::ProbeOutcome::Allowed)
        });
        assert!(first);

        // 第二次：探针若被再次调用会返回"拒绝"——但既然是稳定结论，
        // 就不该再探测，因此结果必须仍是 true（且调用次数仍为 1）
        let second = cache.get(|| {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(super::icmp::auto_sock_type::ProbeOutcome::Denied)
        });
        assert!(second, "稳定的「允许」结论应当被缓存并继续生效");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "稳定结论应被缓存：探测只应发生一次"
        );

        // 权限不足同样应当被缓存
        let denied = super::icmp::auto_sock_type::ProbeCache::new();
        assert!(!denied.get(|| Ok(super::icmp::auto_sock_type::ProbeOutcome::Denied)));
        assert!(
            !denied.get(|| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(super::icmp::auto_sock_type::ProbeOutcome::Allowed)
            }),
            "已缓存的「权限不足」结论不应被后续探测覆盖"
        );
        let _ = io::ErrorKind::PermissionDenied; // 明确本测试关心的错误类别
    }

    /// 🔐 问题 51：**失败的客户端创建也不能被缓存**（与权限探测同一类缺陷）。
    ///
    /// 原来 `static IPV4_CLIENT: Lazy<Result<Client, PingError>>` 会把
    /// `Client::new` 的失败（同样可能是 `EMFILE` 这类瞬时错误）缓存到进程结束。
    ///
    /// ⚠️ 这条测试**不能**去调真实的 `Client::new` 再"看结果"：
    /// 真实创建是否成功取决于运行环境的权限（root 下几乎总是成功），
    /// 那样失败分支**永远测不到** —— 正是本项目反复出现的"测试没盖住真实场景"。
    ///
    /// 所以用可注入的 `get_with`：注入"第一次失败、第二次成功"，
    /// 断言第二次**没有被第一次的失败钉死**。
    #[cfg(not(feature = "disable_icmp_ping"))]
    #[test]
    fn failed_client_creation_is_not_cached() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache = super::icmp::ClientCache::new(surge_ping::ICMP::V4);
        let attempts = AtomicUsize::new(0);

        // 第一次：创建失败（模拟启动瞬间句柄不足）
        let first = cache.get_with(|| {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(PingError::IoError(io::Error::other(
                "too many open files (simulated EMFILE)",
            )))
        });
        assert!(first.is_err(), "注入的失败应当如实返回");

        // ① 核心危害：失败**不得被缓存** —— 缓存必须仍是空的
        assert!(
            cache.client.lock().expect("缓存锁不应被毒化").is_none(),
            "🔐 问题 51：创建失败被写进缓存了 —— 之后即使资源恢复，\
             测速也会永久失效（`Lazy<Result<...>>` 的原缺陷正是如此）"
        );

        // ② 第二次必须**真的重新尝试**，而不是直接返回缓存的失败。
        //    这里注入的构建函数返回一个"探测到的"成功标记：用一个真实可建的
        //    TCP 套接字代替 ICMP 客户端太重，改为断言"构建函数被再次调用"即可 ——
        //    这正是"未被缓存"的直接证据。
        let second = cache.get_with(|| {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(PingError::IoError(io::Error::other(
                "still failing (probe for retry)",
            )))
        });
        assert!(second.is_err());
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "🔐 问题 51：第二次调用没有重新尝试创建 —— 说明第一次的失败被缓存了"
        );
    }

    /// 🔐 问题 51：**HTTPS 测速必须真的把域名放进 SNI 扩展**。
    ///
    /// 原实现里 `config.enable_sni = false`，而紧挨着的注释却写着
    /// "🌟 核心修复 3：真正的 SNI 注入！" —— 注释与代码完全相反。
    /// 关掉 `enable_sni` 后，即使下面传了 `server_name`，rustls
    /// **也不会把它写进 ClientHello 的 SNI 扩展**。
    ///
    /// 后果：对**要求必须携带 SNI** 的服务器（虚拟主机、按域名分证书的边缘节点）
    /// 会握手失败或连到默认站点 —— 测速结果失真，且极难排查。
    ///
    /// 本测试**不依赖外部网络，也不依赖 TLS 握手成功**：
    /// 起一个原始 TCP 监听，直接读客户端发来的 ClientHello 字节，
    /// 断言里面出现了 SNI 扩展（类型 0x0000）且带着我们要的域名。
    /// 这是"客户端到底发了什么"的**线上线格式证据**，
    /// 比"握手是否成功"精确得多（后者会受证书、ALPN 等因素干扰）。
    #[test]
    fn https_ping_sends_sni_with_the_queried_domain() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("应当能建起测试用的 tokio 运行时");

        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("应当能绑定本机回环端口");
            let addr = listener.local_addr().expect("应当能取到本地地址");

            // 服务端：只读 ClientHello，不做任何 TLS 处理（我们要的就是原始字节）
            let server = tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let (mut sock, _) = listener.accept().await.expect("应当能接受连接");

                // ⚠️ 必须**按 TLS 记录层长度读满**，不能只 read 一次：
                // 单次 read 很可能只返回前几十字节（实测只拿到 64 字节），
                // 那样解析必然失败 —— 那是"测试自己没读全"，不是产品缺陷。
                let mut buf = Vec::new();
                let mut head = [0u8; 5];
                sock.read_exact(&mut head)
                    .await
                    .expect("应当能读到 TLS 记录头");
                let rec_len = u16::from_be_bytes([head[3], head[4]]) as usize;

                let mut body = vec![0u8; rec_len];
                sock.read_exact(&mut body)
                    .await
                    .expect("应当能读到完整的 TLS 记录体");

                buf.extend_from_slice(&head);
                buf.extend_from_slice(&body);
                buf
            });

            // 客户端：走真实的 https 测速路径（它连发出结果都不需要，
            // 我们只关心它发了什么）
            let domain = "sni-probe.test";
            let _ = super::https::ping(
                addr,
                Some(domain),
                PingOptions {
                    times: 1,
                    timeout: Duration::from_secs(5),
                    ..Default::default()
                },
            )
            .await;

            let hello = server.await.expect("服务端任务不应 panic");

            // 严格解析出 ClientHello 的扩展列表 —— 必须这样，
            // 否则"有没有 SNI"的断言会**假有效**：
            // 第一版用"宽松扫描 00 00"实现，撤掉修复后它**照样通过**
            // （把别的字节误认成 SNI 扩展），只有第二条"域名对不对"的断言才失败。
            // 这正是本项目反复出现的"测试没盖住真实场景"。
            let exts = parse_client_hello_extensions(&hello).unwrap_or_else(|| {
                panic!(
                    "没能解析出 ClientHello 的扩展块（测试自身的解析有问题，不是产品缺陷）。\
                     前 64 字节: {:02x?}",
                    &hello[..hello.len().min(64)]
                )
            });

            // ① ClientHello 里必须**真的有** SNI 扩展（类型 0x0000）
            let sni = exts.iter().find(|(ty, _)| *ty == 0x0000).map(|(_, d)| d);
            assert!(
                sni.is_some(),
                "🔐 问题 51：ClientHello 里没有 SNI 扩展 —— \
                 这正是 `enable_sni = false` 的后果（注释写着「注入 SNI」，代码却把它关了）。\
                 实际扩展类型: {:02x?}",
                exts.iter().map(|(ty, _)| *ty).collect::<Vec<_>>()
            );

            // ② SNI 扩展的内容必须严格等于「host_name 类型的域名列表」，
            //    且域名就是这次查询的域名。
            let data = sni.expect("前面已断言存在");
            let (list_len, name_type, name_len, name) =
                parse_sni_host_name(data).unwrap_or_else(|| {
                    panic!("SNI 扩展内容结构非法: {data:02x?}");
                });

            assert_eq!(name_type, 0, "SNI 的 name_type 必须是 host_name(0)");
            assert_eq!(
                list_len as usize,
                data.len() - 2,
                "SNI 的 server_name_list 长度字段应当与内容一致"
            );
            assert_eq!(
                name_len as usize,
                name.len(),
                "SNI 的 name 长度字段应当与内容一致"
            );
            assert_eq!(
                name, domain,
                "🔐 问题 51：SNI 里带的必须是**查询的域名**，实际 {name:?}"
            );
        });
    }

    /// 严格解析 TLS ClientHello，取出扩展列表 `(type, data)`。
    ///
    /// 结构（RFC 8446 / 5246）：
    /// ```text
    /// TLS record:  type(1)=0x16, version(2), length(2)
    ///   handshake: type(1)=0x01, length(3)
    ///     version(2), random(32)
    ///     session_id:  len(1) + bytes
    ///     cipher_suites: len(2) + bytes
    ///     compression:  len(1) + bytes
    ///     extensions:   len(2) + [ type(2) + len(2) + data ]*
    /// ```
    ///
    /// 为什么要严格解析（而不是"扫一遍找 00 00"）：
    /// 宽松扫描会把**任何**恰好是 `00 00` 的字节对认成 SNI 扩展 ——
    /// 实测中它让"没有 SNI"的 ClientHello 也通过了断言，属于**假有效测试**
    /// （撤掉修复后第一条断言照样通过，只有第二条才失败）。
    fn parse_client_hello_extensions(hello: &[u8]) -> Option<Vec<(u16, &[u8])>> {
        // TLS 记录层头：type(1) + version(2) + length(2)
        if hello.len() < 5 || hello[0] != 0x16 {
            return None;
        }
        let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        // 记录体必须在缓冲区里（调用方已按长度读满）
        let rec = hello.get(5..5 + rec_len)?;

        // handshake 头：type(1) + length(3)
        if rec.len() < 4 || rec[0] != 0x01 {
            return None;
        }
        let mut i = 4usize;
        let _hs_len = ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | rec[3] as usize;

        // version(2) + random(32)
        i = i.checked_add(2 + 32)?;
        if i > rec.len() {
            return None;
        }

        // session_id
        let sid_len = *rec.get(i)? as usize;
        i = i.checked_add(1 + sid_len)?;

        // cipher_suites
        let cs_len = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
        i = i.checked_add(2 + cs_len)?;

        // compression_methods
        let comp_len = *rec.get(i)? as usize;
        i = i.checked_add(1 + comp_len)?;

        // extensions
        let ext_total = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
        i = i.checked_add(2)?;
        let end = i.checked_add(ext_total)?.min(rec.len());

        let mut out = Vec::new();
        while i + 4 <= end {
            let ty = u16::from_be_bytes([rec[i], rec[i + 1]]);
            let len = u16::from_be_bytes([rec[i + 2], rec[i + 3]]) as usize;
            i += 4;
            if i + len > end {
                return None;
            }
            out.push((ty, &rec[i..i + len]));
            i += len;
        }

        Some(out)
    }

    /// 解析 SNI 扩展内容：`server_name_list` = `len(2) + [ name_type(1) + len(2) + name ]`。
    ///
    /// 返回 `(list_len, name_type, name_len, name)` —— 三个长度字段都返回，
    /// 是为了让测试能**分别断言**它们，而不是只检查域名子串
    /// （只查子串的话，"域名恰好出现在别处"也会通过）。
    fn parse_sni_host_name(data: &[u8]) -> Option<(u16, u8, u16, &str)> {
        if data.len() < 5 {
            return None;
        }
        let list_len = u16::from_be_bytes([data[0], data[1]]);
        let name_type = data[2];
        let name_len = u16::from_be_bytes([data[3], data[4]]);
        let name = std::str::from_utf8(data.get(5..5 + name_len as usize)?).ok()?;
        Some((list_len, name_type, name_len, name))
    }

    #[test]
    fn test_ping_addr_equation() {
        assert_eq!(
            PingAddr::from_str("127.0.0.1").unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            PingAddr::from_str("tcp://223.5.5.5:80").unwrap(),
            "223.5.5.5".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn test_parse_ping_addr_icmp() {
        let a = PingAddr::from_str("127.0.0.1").unwrap();
        assert!(matches!(a, PingAddr::Icmp(ip) if ip == "127.0.0.1".parse::<IpAddr>().unwrap() ));

        let b = PingAddr::from_str("icmp://127.0.0.1").unwrap();
        assert!(matches!(b, PingAddr::Icmp(ip) if ip == "127.0.0.1".parse::<IpAddr>().unwrap() ));
    }

    #[test]
    fn test_parse_ping_addr_icmp_ipv6() {
        let a = PingAddr::from_str("::1").unwrap();
        assert!(matches!(a, PingAddr::Icmp(ip) if ip == "::1".parse::<IpAddr>().unwrap() ));

        let b = PingAddr::from_str("icmp://::1").unwrap();
        assert!(matches!(b, PingAddr::Icmp(ip) if ip == "::1".parse::<IpAddr>().unwrap() ));
    }

    #[test]
    fn test_parse_ping_addr_tcp() {
        let c = PingAddr::from_str("tcp://223.5.5.5:80").unwrap();
        assert!(
            matches!(c, PingAddr::Tcp(ip) if ip == "223.5.5.5:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_tcp_ipv6() {
        let c = PingAddr::from_str("tcp://[fe80::ec37:e7ff:fe56:bba7]:80").unwrap();
        assert!(
            matches!(c, PingAddr::Tcp(ip) if ip == "[fe80::ec37:e7ff:fe56:bba7]:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_tcp_err() {
        let d = PingAddr::from_str("tcp://223.5.5.5");
        assert!(d.is_err());
    }

    #[test]
    fn test_parse_ping_addr_https_port_80() {
        let c = PingAddr::from_str("https://223.5.5.5:80").unwrap();
        assert!(
            matches!(c, PingAddr::Https(ip) if ip == "223.5.5.5:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_https_omit_port() {
        let c = PingAddr::from_str("https://223.5.5.5").unwrap();
        assert!(
            matches!(c, PingAddr::Https(ip) if ip == "223.5.5.5:443".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_https() {
        let c = PingAddr::from_str("https://223.5.5.5:4431").unwrap();
        assert!(
            matches!(c, PingAddr::Https(ip) if ip == "223.5.5.5:4431".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_ping_simple() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let results = ping_batch(
                &[
                    "127.0.0.1".parse().unwrap(),
                    "icmp://223.6.6.6".parse().unwrap(),
                    "tcp://223.5.5.5:443".parse().unwrap(),
                    "tcp://223.5.5.5:4446".parse().unwrap(),
                ],
                None,
                PingOptions::default()
                    .with_times(10)
                    .with_timeout(Duration::from_secs(3))
                    .with_all_success(true),
            )
            .await;

            assert!(matches!(results.last().unwrap(), Err(PingError::Timeout)));

            for item in results {
                println!("Ping {item:?}");
            }
        })
    }

    /// 🔐 `ping_fastest` 的语义是「**第一个探测成功**的就赢」，不是「耗时最短的赢」
    /// （实现用的是 `futures::select_ok`，谁先完成算谁的）。
    ///
    /// 所以这个测试**不能断言「本机必然赢」**。原因：任务完成时间 = 启动开销 + 探测耗时，
    /// 而 ICMP 每次都要新建 pinger（还要分配随机标识符），启动开销明显大于 TCP ——
    /// 在本机 RTT 极小（实测 WSL 里 0.05 毫秒）的环境下，这点 RTT 优势会被启动开销吃光，
    /// 于是 TCP 反而先完成。原断言正是因此长期在 Linux/WSL 上失败（Windows 上因套接字
    /// 路径不同恰好通过），而它**验证不到任何有意义的东西**。
    ///
    /// 现在改为验证真正该保证的事：**返回的结果确实来自传入的那批目标，且确实探测成功了**。
    #[test]
    fn test_ping_fatest_returns_one_of_the_requested_targets() {
        let targets: Vec<PingAddr> = [
            "127.0.0.1".parse().unwrap(),
            "icmp://8.8.8.8".parse().unwrap(),
            "icmp://223.6.6.6".parse().unwrap(),
            "tcp://223.5.5.5:443".parse().unwrap(),
        ]
        .into();

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let out = ping_fastest(targets.clone(), None, Default::default())
                    .await
                    .unwrap();

                // 1. 返回的目标必须是传入的那批之一（不能凭空造一个）
                assert!(
                    targets.contains(&out.destination),
                    "ping_fastest 返回了不在候选列表里的目标: {:?}",
                    out.destination
                );

                // 2. 必须是「探测成功」的结果：耗时不可能为 0（0 表示没真测），
                //    也不该超过默认超时 5 秒
                let elapsed = out.elapsed();
                assert!(
                    elapsed > Duration::ZERO,
                    "返回的耗时是 0，说明并没有真的探测成功: {:?}",
                    out.destination
                );
                assert!(
                    elapsed < Duration::from_secs(5),
                    "耗时超过了默认超时，不像是成功探测: {elapsed:?}"
                );
            });
    }

    /// 🔐 同类目标之间比较，才是「快者胜」这个语义能成立的地方。
    ///
    /// 本机回环的 RTT 实测只有 0.05 毫秒级，而公网目标在 50 毫秒以上；
    /// 当两者**走同一种探测方式**（都是 TCP）时，启动开销相当，
    /// 本机就应当稳定胜出 —— 这个断言在任何平台上都该成立。
    ///
    /// ⚠️ 必须**真的起一个本地监听**：TCP 探测的方式是 `connect()`，
    /// 连接被拒绝同样算失败（见 `tcp::ping_tcp`），所以拿一个没人监听的端口
    /// 当"本机目标"是不成立的（这正是一开始写错的地方）。
    #[test]
    fn test_ping_fatest_prefers_the_local_target_among_same_kind() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                // 起一个真实的本地监听（端口由系统分配），保证本机目标**能连通**
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("应当能绑定本机回环端口");
                let local_addr = listener.local_addr().expect("应当能取到本地地址");
                let local: PingAddr = PingAddr::Tcp(local_addr);
                let remote: PingAddr = "tcp://223.5.5.5:443".parse().unwrap();

                // 保持监听存活（不 accept 也没关系：connect 已完成三次握手）
                let _keep = listener;

                let out = ping_fastest(vec![local, remote], None, Default::default())
                    .await
                    .unwrap_or_else(|err| panic!("两个目标都探测失败，请检查网络环境: {err}"));

                assert_eq!(
                    out.destination, local,
                    "同种探测方式下，本机（RTT 0.05ms 级）应当快于公网目标"
                );
            });
    }

    /// 环境变量（都可选，便于在不同网络环境下运行本测试）：
    /// - `SMARTDNS_TEST_PING_HTTPS_URL`：探测目标，默认 `https://223.5.5.5:443`
    ///   （阿里公共 DNS，国内可直连；腾讯的 `https://1.12.12.12:443` 亦可）
    /// - `SMARTDNS_TEST_PING_HTTPS_DOMAIN`：探测域名，默认 `dns.alidns.com`
    ///
    /// ⚠️ 本测试与生产保持同一条链路：`speed-check-mode https` 走的就是这条
    /// **直连**探测路径（见 `config/speed_mode.rs` 的 `to_ping_addr` →
    /// `PingAddr::Https(候选IP:443)`），并且 `dns_mw_ns.rs` / `dns_mw_dualstack.rs`
    /// **始终把被解析的域名传进来**（用于 SNI 与 Host 头）。
    /// 因此这里也必须直连、且带域名——不能借道任何代理，
    /// 否则测到的就不是生产真正会走的那条路。
    ///
    /// 本机若无法直连目标，可以把目标换成直连可达的 HTTPS 站点，
    /// 或者就让它保持失败——那正是生产会遭遇的情形（该候选 IP 会被判为不可达）。
    #[test]
    fn test_ping_https() {
        let target = std::env::var("SMARTDNS_TEST_PING_HTTPS_URL")
            .unwrap_or_else(|_| "https://223.5.5.5:443".to_string());
        let domain = std::env::var("SMARTDNS_TEST_PING_HTTPS_DOMAIN")
            .unwrap_or_else(|_| "dns.alidns.com".to_string());

        let dest: super::PingAddr = target.parse().unwrap();

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let res = super::ping(dest, Some(&domain), Default::default())
                    .await
                    .unwrap();
                assert!(res.duration < Duration::from_secs(5))
            });
    }
}
