#![allow(dead_code)]
// #![feature(test)]

use cli::*;
use config::NameServerInfo;
use dns_url::DnsUrl;
use std::str::FromStr;

mod api;
mod app;
mod cli;
mod collections;
mod config;
mod dns;
mod dns_client;
mod dns_conf;
mod dns_error;
mod dns_mw;
mod dns_mw_addr;
mod dns_mw_audit;
mod dns_mw_bogus;
mod dns_mw_cache;
mod dns_mw_cname;
mod dns_mw_dns64;
mod dns_mw_dnsmasq;
mod dns_mw_dualstack;
mod dns_mw_force_no_cname;
mod dns_mw_hosts;
// 这个模块本身**所有平台都编译**：写内核集合的那半边按平台/特性门控，
// 而"从应答算过期时间"这类纯计算要能在本机（Windows）单测。
// 真正不做事的地方在 `handle` 里：非 Linux 直接放行（启动时另有提示）。
mod dns_mw_ipset_nftset;
mod dns_mw_ns;
mod dns_mw_zone;
mod dns_rule;
mod dns_url;
mod dnsmasq;
mod error;
mod ffi;
mod infra;
mod libdns;
mod log;
mod preset_ns;
mod proxy;
pub mod socks5;
pub use socks5 as async_socks5;
#[cfg(feature = "resolve-cli")]
mod resolver;
mod rustls;
mod server;
#[cfg(feature = "service")]
mod service;
mod third_ext;
mod trusted_proxy;
mod zone;

use error::Error;
use infra::middleware;

use crate::{
    dns_client::DnsClient,
    dns_conf::RuntimeConfig,
    infra::process_guard::ProcessGuardError,
    log::{error, info, warn},
};

fn banner() {
    info!("");
    info!(r#"     _____                      _       _____  _   _  _____ "#);
    info!(r#"    / ____|                    | |     |  __ \| \ | |/ ____|"#);
    info!(r#"   | (___  _ __ ___   __ _ _ __| |_    | |  | |  \| | (___  "#);
    info!(r#"    \___ \| '_ ` _ \ / _` | '__| __|   | |  | | . ` |\___ \ "#);
    info!(r#"    ____) | | | | | | (_| | |  | |_    | |__| | |\  |____) |"#);
    info!(r#"   |_____/|_| |_| |_|\__,_|_|   \__|   |_____/|_| \_|_____/ "#);
    info!("");
}

/// The app name
const NAME: &str = "SmartDNS";

include!(concat!(env!("OUT_DIR"), "/build_time_vars.rs"));

/// The default configuration.
const DEFAULT_CONF: &str = include_str!("../etc/smartdns/smartdns.conf");

#[cfg(unix)]
fn maximize_fd_limit() {
    // 🌟 核心修复：解除 Linux/macOS 默认的 1024 文件描述符并发封印，极大提升网络吞吐上限
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            rl.rlim_cur = rl.rlim_max; // 将软限制提升至硬限制
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                eprintln!("Warning: Failed to increase FD limit.");
            }
        }
    }
}

#[cfg(not(windows))]
fn main() {
    #[cfg(unix)]
    maximize_fd_limit(); // 启动时立即提权

    Cli::parse().run();
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    if matches!(std::env::args().next_back(), Some(flag) if flag == "--ws7642ea814a90496daaa54f2820254f12")
    {
        return service::windows::run();
    }

    Cli::parse().run();
    Ok(())
}

impl Cli {
    #[inline]
    pub fn run(self) {
        // 🌟 核心修复 1：重命名日志锁，避免被下方的变量同名覆盖！
        let log_guard = self.log_level().map(log::console);

        match self.command {
            Commands::Run {
                directory,
                conf,
                pid,
                ..
            } => {
                let pid_path = pid
                    .or_else(|| {
                        directory
                            .as_ref()
                            .map(|d| d.join("managed").join("smartdns.pid"))
                    })
                    .unwrap_or_else(|| {
                        std::env::current_exe()
                            .ok()
                            .and_then(|exe| {
                                exe.parent().map(|p| p.join("managed").join("smartdns.pid"))
                            })
                            .unwrap_or_else(|| std::env::temp_dir().join("smartdns.pid"))
                    });

                if let Some(parent) = pid_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }

                // 🌟 核心修复 2：重命名进程锁为 _pid_guard，恢复防多开保护！
                let _pid_guard = match crate::infra::process_guard::create(&pid_path) {
                    Ok(guard) => Some(guard),
                    // 🔐「顺手修」：PID 读不到时**不再报 "PID 0"**（那是编出来的，见 process_guard.rs）。
                    Err(ProcessGuardError::AlreadyRunning(Some(id))) => {
                        error!(
                            "SmartDNS is already running with PID {}! Only one instance is allowed.",
                            id
                        );
                        std::process::exit(1);
                    }
                    Err(ProcessGuardError::AlreadyRunning(None)) => {
                        error!(
                            "SmartDNS is already running (but its PID could not be read from {}). \
                             Only one instance is allowed.",
                            pid_path.display()
                        );
                        std::process::exit(1);
                    }
                    Err(err) => {
                        error!(
                            "Failed to acquire PID lock at {}: {}. Another instance is likely running.",
                            pid_path.display(),
                            err
                        );
                        std::process::exit(1);
                    }
                };

                // 屏幕优先打印起始横幅和 DomainSet 加载信息
                hello_starting();
                let cfg = RuntimeConfig::load(directory, conf);

                // 🔐 13-⑥：把可信代理清单交给管理后台的鉴权中间件。
                //
                // 中间件是**无状态**的（`middleware::from_fn` 形式的函数，手上只有 `Request`），
                // 拿不到 `ServeState`，所以与 `api_token()` 一样走全局存储。
                // 未初始化时它取到的是**空清单** = 不信任任何代理头 = 原本行为。
                crate::api::init_trusted_proxies(cfg.trusted_proxies());

                // 🌟 核心修复 3：精确击杀日志锁！
                // 因为改了名字，这次绝对不会杀错人，主线程的霸权彻底终结！
                drop(log_guard);

                // 万物之始，全局通电！
                let log_dispatch = crate::log::make_dispatch(
                    cfg.log_file(),
                    cfg.log_enabled(),
                    cfg.log_level(),
                    cfg.log_filter(),
                    cfg.log_size(),
                    cfg.log_num(),
                    cfg.log_file_mode().into(),
                    cfg.log_config().console(),
                    // 🔐 Q7：`log-syslog`（运行日志也送系统日志；Linux 之外的平台会在启动时提示无效）
                    cfg.log_syslog(),
                );
                // 🔐 P3：这里原来用 `.ok()` 吞掉失败 —— 一旦日志系统没装上，之后所有
                // log::info!/warn!/error! 全部石沉大海，而且没人知道。日志宏此刻不可用，只能直写 stderr。
                if let Err(err) = tracing::dispatcher::set_global_default(log_dispatch) {
                    eprintln!(
                        "log system initialisation failed (later log output may be missing): {err}"
                    );
                }

                // 此时日志系统已完美交接，这几十行配置摘要将一字不漏印入硬盘文件！
                cfg.summary();

                #[cfg(target_os = "linux")]
                {
                    // 🔐 必须在降权**之前**把日志/审计相关的属主交出去。
                    // 降权之后就没有权限改了；而那正是日志写满需要归档、却因目录属于 root
                    // 而归档失败、进而静默停写的根因。
                    let target_user = cfg.user().unwrap_or(run_user::DEFAULT_USER);
                    let target_group = if cfg.user().is_some() {
                        None
                    } else {
                        Some(run_user::DEFAULT_GROUP)
                    };

                    if let Some((uid, gid)) = run_user::target_ids(target_user, target_group) {
                        let mut paths = vec![cfg.log_file()];
                        if let Some(audit) = cfg.audit_file() {
                            paths.push(audit);
                        }
                        crate::infra::mapped_file::prepare_owner_for_drop(&paths, uid, gid);
                    }

                    match cfg.user() {
                        Some(user) => run_user::with(user, None).expect("switch user failed"),
                        None => run_user::try_drop_privs(),
                    }
                }
                app::serve(cfg);
                good_bye();

                // 🌟 P1-14：退出前把日志队列里还没写进文件的内容真正排空。
                // 日志 dispatch 是进程的全局默认值，退出时不会被 Drop，所以必须在这里显式调用，
                // 否则"关机/重启前后的关键日志"会随进程一起消失（这正是原来最容易被吞掉的一段）。
                let (flushed, total) =
                    crate::infra::mapped_file::flush_all(std::time::Duration::from_secs(2));
                if flushed < total {
                    eprintln!(
                        "[smartdns] WARN: only {flushed}/{total} log writer(s) were flushed before exit; \
                         some log lines may be missing."
                    );
                }
            }
            #[cfg(feature = "service")]
            Commands::Service {
                command: service_command,
            } => {
                use ServiceCommands::*;
                let sm = crate::service::service_manager();
                let output = match service_command {
                    Install => sm.install(),
                    Uninstall { purge } => sm.uninstall(purge, false),
                    Start => sm.start(),
                    Stop => sm.stop(),
                    Restart => sm.restart(),
                    Status => match sm.status() {
                        Ok(status) => {
                            let out = match status {
                                service::ServiceStatus::Running(out) => Some(out),
                                service::ServiceStatus::Dead(out) => Some(out),
                                // 🌟 核心修复：补上被遗漏的新状态分支，并输出友好的未安装提示！
                                service::ServiceStatus::NotInstalled => {
                                    println!("\n❌ SmartDNS service is NOT installed.");
                                    println!(
                                        "💡 Hint: Install it via 'smartdns service install'\n"
                                    );
                                    None
                                }
                                service::ServiceStatus::Unknown => None,
                            };
                            if let Some(out) = out {
                                if let Ok(out) = String::from_utf8(out.stdout) {
                                    print!("{out}");
                                } else {
                                    warn!("get service status failed.");
                                }
                            }
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                };

                if let Err(err) = output {
                    // 🔐 用户可见的错误文案：原文案写的是「无法创建符号链接」，
                    // 那是从 Symlink 子命令抄过来的，跟服务管理毫无关系。
                    let detail = match err.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            #[cfg(windows)]
                            {
                                format!("{err} (administrator privileges are required)")
                            }
                            #[cfg(unix)]
                            {
                                format!("{err} (root privileges are required)")
                            }
                            #[cfg(not(any(unix, windows)))]
                            {
                                format!("{err} (elevated privileges are required)")
                            }
                        }
                        _ => err.to_string(),
                    };

                    // 🔐 必须同时写 stderr 与日志：Service 分支不会初始化日志系统
                    // （`log_guard` 只在带 -x/-v 时存在），此时单靠 log::error! 用户什么也看不到。
                    eprintln!("[smartdns] service command failed: {detail}");
                    log::error!("service command failed: {detail}");

                    // 🔐 关键：以非 0 退出码结束。脚本与 CI 靠退出码判断成功与否，
                    // 之前这里只打印不退出，`service install` 失败也会被当成成功，
                    // 部署脚本会带着「装好了」的错误认知继续往下走。
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "service"))]
            Commands::Service { command: _ } => {
                warn!("please enable `service` feature")
            }
            Commands::Test { directory, conf } => {
                let cfg = RuntimeConfig::load(directory, conf);

                // 🔐 13-⑥：`test` 也与真正启动走同一套准备（见上面 `Run` 分支的说明），
                // 这样"配置自检通过"与"真能启动"才是一致的。
                crate::api::init_trusted_proxies(cfg.trusted_proxies());

                // 打印出解析到的配置摘要，让用户确信读取成功了
                crate::hello_starting();
                cfg.summary();

                // 🔐 用和真正启动时完全相同的一套检查：
                // 配置自检说"通过"，就必须真的能启动——否则用户会被"✅ 通过"骗到，
                // 等到重启服务时才发现起不来。
                // 🔐 P2：`smartdns test` 时也把"明文 HTTP 上挂后台"的风险说清楚
                crate::api::warn_plaintext_api(cfg.binds());
                if let Err(msg) = crate::api::check_exposure(cfg.binds(), cfg.api_token()) {
                    crate::log::error!("{msg}");
                    eprintln!("[smartdns] {msg}");
                    std::process::exit(crate::dns_conf::EXIT_CODE_CONFIG_ERROR);
                }

                // 🌟 明确告诉用户测试通过！
                crate::log::info!("configuration test passed");
            }
            #[cfg(feature = "resolve-cli")]
            Commands::Resolve(command) => {
                drop(log_guard);
                command.execute();
            }
            #[cfg(all(feature = "resolve-cli", any(unix, windows)))]
            // `link` 只在 Windows 分支里会被改（补 .exe 后缀），Linux 上用不到 mut
            #[cfg_attr(not(windows), allow(unused_mut))]
            Commands::Symlink { mut link } => {
                let original = std::env::current_exe().expect("failed to get current exe path");

                // 🌟 修复暗坑一：Windows 体验优化！如果用户忘了加 .exe，贴心地自动补全！
                // 防止用户创建出无法在 CMD/PowerShell 中直接运行的废物链接。
                #[cfg(windows)]
                if link.extension().is_none() {
                    link.set_extension("exe");
                }

                if link.exists() {
                    eprintln!(
                        "\x1b[33;1m[WARNING]\x1b[0m Symlink or file already exists at: {}",
                        link.display()
                    );
                    return;
                }

                #[cfg(unix)]
                let res = std::os::unix::fs::symlink(&original, &link);

                #[cfg(windows)]
                let res = std::os::windows::fs::symlink_file(&original, &link);

                match res {
                    Ok(()) => println!(
                        "\x1b[32;1m[SUCCESS]\x1b[0m Symlink created: {} -> {}",
                        link.display(),
                        original.display()
                    ),
                    Err(err) => {
                        // 🌟 修复暗坑二：拦截臭名昭著的 Win32 OS Error 1314！
                        // 不再扔出冰冷的报错，而是用大红字高亮引导用户去提权，彻底解决用户痛点！
                        #[cfg(windows)]
                        if err.raw_os_error() == Some(1314) {
                            eprintln!(
                                "\x1b[31;1m[FATAL ERROR]\x1b[0m Privilege not held (OS Error 1314)."
                            );
                            eprintln!(
                                "On Windows, creating symbolic links requires \x1b[31;1mAdministrator privileges\x1b[0m or enabling \x1b[32;1mDeveloper Mode\x1b[0m."
                            );
                            eprintln!(
                                "👉 \x1b[33mHint: Please right-click your terminal (PowerShell/CMD) and select 'Run as Administrator', then try again.\x1b[0m"
                            );
                            std::process::exit(1);
                        }

                        eprintln!("\x1b[31;1m[ERROR]\x1b[0m Failed to create symlink: {}", err);
                        std::process::exit(1);
                    }
                }
            }
            #[allow(unreachable_patterns)]
            _ => {
                unimplemented!()
            }
        }
    }
}

#[inline]
fn hello_starting() {
    info!("{} 🐋 {} starting", NAME, BUILD_VERSION);
}

#[inline]
fn good_bye() {
    info!("{} {} shutdown", crate::NAME, crate::BUILD_VERSION);
}

impl RuntimeConfig {
    pub async fn create_dns_client(&self) -> DnsClient {
        let servers = self.servers();
        let ca_path = self.ca_path();
        let ca_file = self.ca_file();
        let proxies = self.proxies().clone();

        let mut builder = DnsClient::builder();

        #[cfg(feature = "mdns")]
        if self.mdns_lookup() {
            use crate::libdns::proto::multicast::{MDNS_IPV4, MDNS_IPV6};
            // 🔐 Q11（顺带修一个静默失效的既有功能）：这里原来拼的是 `mdns://<地址>`，
            // 而我们的 URL 解析器**没有 `mdns` 这个协议** —— 解析失败后被下面的 `.ok()`
            // 悄悄丢掉，结果 `mdns-lookup` 配了也永远不起作用（连一句日志都没有）。
            // 正确写法是普通 `udp://` + 组播地址：连接层是靠"协议是 UDP 且地址是 mDNS 组播地址"
            // 认出 mDNS 的（见 `src/libdns/custom/connection_provider.rs` 的 UDP 分支）。
            let mdns_servers = [*MDNS_IPV4, *MDNS_IPV6]
                .into_iter()
                .filter_map(|ip| {
                    let s = format!("udp://{ip}");
                    match DnsUrl::from_str(&s) {
                        Ok(url) => Some(url),
                        Err(err) => {
                            // 🌟 拒绝静默吞错：解析不了就说出来，别让用户以为配了就能用
                            log::error!("mDNS upstream address `{s}` failed to resolve and was skipped: {err:?}");
                            None
                        }
                    }
                })
                .map(|url| {
                    let mut config = NameServerInfo::from(url);
                    config.group = vec!["mdns".to_string()];
                    config.exclude_default_group = true;
                    config
                })
                .collect::<Vec<_>>();
            builder = builder.add_servers(mdns_servers.to_vec());
        }
        builder = builder.add_servers(servers.to_vec());
        if let Some(path) = ca_path {
            builder = builder.with_ca_path(path.to_owned());
        }
        if let Some(file) = ca_file {
            builder = builder.with_ca_path(file.to_owned());
        }
        if let Some(subnet) = self.edns_client_subnet() {
            builder = builder.with_client_subnet(subnet);
        }
        builder = builder.with_proxies(proxies);
        builder.build().await
    }
}

// 🌟 核心修复 1：加上 pub，让它对外可见
pub mod signal {
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;

    // 🌟 核心修复 2：暴露出一个安全的、原生的内存关机通知器
    pub static SHUTDOWN_NOTIFY: LazyLock<Notify> = LazyLock::new(Notify::new);

    /// 进程是否已经收到过关机请求。
    ///
    /// 🔐 问题 47：这个标志位是"**通知不丢**"的关键 —— 理由见
    /// [`request_shutdown`] 与 [`wait_for_shutdown`] 的说明。
    static TERMINATING: AtomicBool = AtomicBool::new(false);

    /// 是否已经收到过关机请求（幂等：重复调用也返回 `true`）。
    #[inline]
    pub fn is_terminating() -> bool {
        TERMINATING.load(Ordering::Relaxed)
    }

    /// 🔐 问题 47：**发出关机请求 —— 通知不会丢**。
    ///
    /// 原实现的 Windows 服务停止处理是：
    ///
    /// ```ignore
    /// crate::signal::SHUTDOWN_NOTIFY.notify_waiters();
    /// ```
    ///
    /// `notify_waiters()` 只唤醒**此刻已经在等待**的任务，**不保留任何许可**：
    /// 如果系统要求停止服务时，主流程**还没走到** `terminate()` 里的
    /// `SHUTDOWN_NOTIFY.notified()`（例如正在启动、正在加载配置、
    /// 或正要进入等待点），这条通知就**直接丢了**。
    ///
    /// 后果（正是报告描述的"Stop 被完全忽略"）：服务不响应停止指令，
    /// 只能等系统强制杀掉；而强制杀掉的路径下，
    /// 退出前"把日志队列排空"这一步**不会执行** ——
    /// 恰好是代码注释里最担心的"关机前后日志被吞"。
    ///
    /// 修法分两层：
    ///   1. **置标志位**（本函数的 `swap`）—— 这是**永久可查**的事实，
    ///      与"此刻有没有人在等"无关，因此不会丢；
    ///   2. 仍然 `notify_waiters()` 唤醒当前正在等待的那些任务，让它们立刻响应。
    ///
    /// 标志位还能顺带解决另一个问题：`terminate()` 被**多处**同时等待
    /// （服务监听循环、名单刷新循环、缓存预取循环…），
    /// 而通知机制本质上只会唤醒"当时在等的人"；有了标志位，
    /// 每一处等待都能在**自己的下一轮**立刻看到"该退出了"。
    ///
    /// 返回 `true` 表示这是**第一次**请求关机（可用于打一次"terminating"日志）。
    pub fn request_shutdown() -> bool {
        let first = !TERMINATING.swap(true, Ordering::Relaxed);
        SHUTDOWN_NOTIFY.notify_waiters();
        first
    }

    /// 🔐 问题 47：**等待关机请求 —— 不会错过已经发生的那次**。
    ///
    /// 与 [`request_shutdown`] 配套。关键差别在于**先查标志位**：
    ///
    /// * 若关机请求**已经来过**（标志位为真），立即返回 —— 即使当时没有人在等、
    ///   通知已经"丢"了，也能补上。（这正是原实现漏掉的一步。）
    /// * 否则挂起等待；被唤醒后标志位必然已经是真（由 `request_shutdown` 设置）。
    ///
    /// ⚠️ 这里刻意**不把 `notified()` 的 future 提前构造**：
    /// `Notify::notified()` 只有在**首次被 poll** 时才注册到等待队列，
    /// 因此"先查标志、再 await"的顺序是安全的 ——
    /// 两者之间即使发生 `request_shutdown`，标志位检查也会兜住。
    pub async fn wait_for_shutdown() {
        if is_terminating() {
            return;
        }

        SHUTDOWN_NOTIFY.notified().await;

        // 被唤醒后标志位一定为真；这里再设一次是**幂等**的（`store` 写入相同的值），
        // 让"等待方自己"也能把状态固化下来（例如未来有别的唤醒来源时）。
        TERMINATING.store(true, Ordering::Relaxed);
    }

    /// 等待关机信号（Ctrl+C、SIGTERM，或 Windows 服务停止）。
    ///
    /// Windows 服务停止走的是 [`request_shutdown`]，因此本函数在
    /// **服务环境下也可靠**（不会像原来那样丢掉通知）。
    pub async fn terminate() -> std::io::Result<()> {
        use tokio::signal::ctrl_c;

        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            match signal(SignalKind::terminate()) {
                Ok(mut terminate) => tokio::select! {
                    _ = terminate.recv() => SignalKind::terminate(),
                    _ = ctrl_c() => SignalKind::interrupt()
                },
                _ => {
                    ctrl_c().await?;
                    SignalKind::interrupt()
                }
            };
        }

        #[cfg(not(unix))]
        {
            // 🌟 核心修复 3：谁先触发（人为按 Ctrl+C，或系统服务发来原生关机命令），就响应谁！
            tokio::select! {
                res = ctrl_c() => { res?; },
                // 🔐 问题 47：改走 `wait_for_shutdown()` —— 它会**先查标志位**，
                // 因此"服务停止通知比等待点更早到达"这种情形不再丢。
                _ = wait_for_shutdown() => {},
            }
        }

        // 标志位已经在 `wait_for_shutdown` / `request_shutdown` 里置好；
        // 这里只负责打一次日志（人为 Ctrl+C 的那条路径也会走到）。
        if !TERMINATING.swap(true, Ordering::Relaxed) {
            crate::log::info!("terminating...");
        }

        Ok(())
    }

    // ============ 🔐 问题 47 的回归测试 ============
    //
    // 这一组测试**刻意不依赖 Windows 服务环境**：它钉住的是问题 47 的**核心不变量**
    // ——「关机通知不会因为'来早了'而丢掉」。
    // 原实现用 `notify_waiters()`，这个不变量在**所有平台**上都是不成立的；
    // 只是 Windows 服务场景最容易踩到（停止指令常在启动/加载配置期间到达）。
    //
    // 为什么不用"真的装一个 Windows 服务再停它"来验证：
    // 那会操作到用户的生产服务（本项目已有过事故，见报告 §27.0），
    // 而且服务安装是编译期常量 `smartdns-rs`、无法隔离。
    #[cfg(test)]
    mod tests {
        use super::*;

        /// 测试串行锁。
        ///
        /// ⚠️ **必须串行**：这些用例共享进程级的 `TERMINATING` 标志位与
        /// `SHUTDOWN_NOTIFY`，而 cargo 默认**并行**跑测试 ——
        /// 不串行就会出现"A 用例刚置位、B 用例把它归零"的互相干扰
        /// （第一版就是这么失败的：断言"第一次应当是 true"随机失败）。
        ///
        /// 不用 `serial_test` 之类的额外依赖：一把 `Mutex` 就够，
        /// 且不引入新的依赖（离线 registry 里也未必有）。
        ///
        /// ⚠️ 注意 `Mutex` 中毒：某个用例 panic 后锁会中毒，
        /// 后续用例会连带失败。这里用 `unwrap_or_else(|e| e.into_inner())`
        /// 忽略中毒 —— 测试的目的就是让每个用例都独立地跑出自己的结论。
        static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        /// 取得测试串行锁，并把标志位重置为"未收到"。
        fn lock_and_reset() -> std::sync::MutexGuard<'static, ()> {
            let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            TERMINATING.store(false, Ordering::Relaxed);
            guard
        }

        /// 🔐 问题 47 的**核心不变量**：**通知来得比等待更早时，也不会丢**。
        ///
        /// 这正是原实现（`notify_waiters()`）做不到的事：
        /// 它只唤醒"此刻已在等"的任务、不保留任何许可 ——
        /// 服务停止通知若在主流程走到等待点之前到达，就**永久消失**，
        /// 服务于是不响应停止，只能等系统强杀（日志与缓存都来不及落盘）。
        ///
        /// 本测试的顺序是刻意的：**先发通知，后等待**。
        /// 撤掉修复（把 `wait_for_shutdown` 换回裸 `SHUTDOWN_NOTIFY.notified()`）
        /// 之后这条测试会**卡住直到超时**——那正是"通知丢了"的表现。
        #[tokio::test]
        async fn shutdown_request_is_not_lost_when_it_arrives_early() {
            let _guard = lock_and_reset();

            // ① 通知先到（此刻**没有任何人在等**）
            let first = request_shutdown();
            assert!(first, "第一次请求关机应当返回 true");
            assert!(
                is_terminating(),
                "置了标志位之后，`is_terminating()` 必须为真 —— 这是「不丢」的依据"
            );

            // ② 之后才有人来等：必须**立刻**返回，而不是永久挂起
            let waited =
                tokio::time::timeout(std::time::Duration::from_secs(2), wait_for_shutdown()).await;

            assert!(
                waited.is_ok(),
                "🔐 问题 47：早到的关机通知丢了 —— 后来的等待者一直等不到它。\
                 这正是「服务 Stop 被完全忽略、只能等系统强杀」的原缺陷"
            );
        }

        /// 🔐 对照：**正在等待时**收到通知，同样要能醒来（正常路径不能被改坏）。
        #[tokio::test]
        async fn shutdown_request_wakes_a_waiting_task() {
            let _guard = lock_and_reset();

            let waiter = tokio::spawn(async { wait_for_shutdown().await });

            // 给等待方一点时间真正注册到等待队列
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            request_shutdown();

            let waited = tokio::time::timeout(std::time::Duration::from_secs(2), waiter).await;
            assert!(waited.is_ok(), "正在等待的任务应当被唤醒");
        }

        /// 🔐 幂等性：重复请求关机是安全的，且只有**第一次**返回 `true`。
        ///
        /// 为什么重要：`request_shutdown()` 会在"第一次"时打一条日志。
        /// 系统可能连续下发多次 Stop/Shutdown，若每次都返回 `true` 就会刷屏；
        /// 而如果实现成"后来者覆盖"，又可能让日志与状态判断出错。
        #[tokio::test]
        async fn repeated_shutdown_requests_are_idempotent() {
            let _guard = lock_and_reset();

            assert!(request_shutdown(), "第一次应当是 true");
            assert!(!request_shutdown(), "第二次应当是 false（已经处理过了）");
            assert!(!request_shutdown(), "第三次同理");

            assert!(is_terminating(), "标志位始终为真");
        }

        /// 🔐 等待方**自己**也要能读到状态：多处等待点使用同一套判断。
        ///
        /// `terminate()` 被服务监听循环、名单刷新循环、缓存预取循环**多处**同时等待，
        /// 而通知机制只会唤醒"当时在等的人"。标志位的意义就在于：
        /// 每一处都能在**自己的下一轮**立刻看到"该退出了"。
        #[tokio::test]
        async fn flag_is_visible_to_all_waiters() {
            let _guard = lock_and_reset();

            assert!(!is_terminating(), "初始状态应当是「未收到」");

            request_shutdown();

            // 模拟"多个等待点各自检查"，全部应当看到同一事实
            for i in 0..5 {
                assert!(
                    is_terminating(),
                    "第 {i} 个等待点没有看到关机标志（多处等待点会读到不一致的状态）"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod run_user {
    use std::{collections::HashSet, io};

    use crate::log;
    use caps::{
        CapSet::{Effective, Permitted},
        Capability::{self, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW},
        securebits::set_keepcaps,
    };
    use users::{
        get_current_gid, get_current_uid, get_effective_gid, get_effective_uid, get_group_by_name,
        get_user_by_name,
        switch::{set_current_gid, set_current_uid},
    };
    use uzers as users;

    pub static DEFAULT_USER: &str = "nobody";
    pub static DEFAULT_GROUP: &str = "nobody";

    pub fn with(username: &str, groupname: Option<&str>) -> io::Result<()> {
        let mut caps = HashSet::new();
        caps.insert(CAP_NET_ADMIN); // nftset
        caps.insert(CAP_NET_BIND_SERVICE); // bind
        caps.insert(CAP_NET_BROADCAST); // mdns
        caps.insert(CAP_NET_RAW); // ping
        switch_user(username, groupname, &caps)
    }

    pub fn try_drop_privs() {
        if let Err(err) = with(DEFAULT_USER, Some(DEFAULT_GROUP)) {
            log::error!("failed to drop privs: {}", err);
        }
    }

    /// 🔐 解析「即将降权到哪个用户/组」，但**不真的降权**。
    ///
    /// 用途：在仍持有 root 权限时，把日志/审计文件的目录与文件属主交给这个账号，
    /// 否则降权后日志写满没法归档，会静默停写（见 `mapped_file::prepare_owner_for_drop`）。
    ///
    /// 返回 `None` 的两种情形：当前不是 root（没有降权这回事），或用户不存在。
    pub fn target_ids(username: &str, groupname: Option<&str>) -> Option<(u32, u32)> {
        if !(get_current_uid() == 0 || get_effective_uid() == 0) {
            return None; // 本来就不是 root，不需要改属主
        }

        let user = get_user_by_name(username)?;
        let gid = groupname
            .map(get_group_by_name)
            .unwrap_or_default()
            .map(|g| g.gid())
            .unwrap_or_else(|| user.primary_group_id());

        Some((user.uid(), gid))
    }

    #[inline]
    fn switch_user(
        username: &str,
        groupname: Option<&str>,
        caps: &HashSet<Capability>,
    ) -> io::Result<()> {
        let (uid, gid, euid, egid) = (
            get_current_uid(),
            get_current_gid(),
            get_effective_uid(),
            get_effective_gid(),
        );

        if uid == 0 || euid == 0 {
            log::info!(
                "running as root: {uid}, gid: {gid} (euid: {euid}, egid: {egid})...dropping privileges."
            );
        } else {
            return Ok(()); // already running as non-root, nothing to do.
        }

        let user = get_user_by_name(username);
        let Some(user) = user else {
            return Err(io::Error::other(format!("User {username} not found")));
        };

        let group = groupname.map(get_group_by_name).unwrap_or_default();

        let uid = user.uid();
        let gid = group
            .map(|g| g.gid())
            .unwrap_or_else(|| user.primary_group_id());

        keepcaps()?;
        set_gid(gid)?;
        set_uid(uid)?;

        let (uid, gid, euid, egid) = (
            get_current_uid(),
            get_current_gid(),
            get_effective_uid(),
            get_effective_gid(),
        );

        set_caps(caps)?;

        log::info!("now running as uid: {uid}, gid: {gid} (euid: {euid}, egid: {egid})");

        Ok(())
    }

    #[inline]
    fn set_gid(gid: u32) -> io::Result<()> {
        set_current_gid(gid)
            .map_err(|err| io::Error::other(format!("Failed to set gid: {gid}, {err}")))
    }

    #[inline]
    fn set_uid(uid: u32) -> io::Result<()> {
        set_current_uid(uid)
            .map_err(|err| io::Error::other(format!("Failed to set uid: {uid}, {err}")))
    }

    #[inline]
    fn set_caps(caps: &caps::CapsHashSet) -> io::Result<()> {
        caps::set(None, Effective, caps)
            .and(caps::set(None, Permitted, caps))
            .map_err(|err| io::Error::other(format!("Failed to set capabilities: {err}")))
    }

    #[inline]
    fn keepcaps() -> io::Result<()> {
        set_keepcaps(true).map_err(|err| io::Error::other(format!("Failed to set keepcaps: {err}")))
    }
}
