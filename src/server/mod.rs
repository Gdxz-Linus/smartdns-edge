#[cfg(feature = "dns-over-h3")]
mod h3;
pub(crate) mod limit;

mod http;
#[cfg(feature = "dns-over-https")]
mod https;
mod net;
#[cfg(feature = "dns-over-quic")]
mod quic;
mod tcp;
#[cfg(feature = "dns-over-tls")]
mod tls;
mod udp;

use crate::{
    config::SslConfig,
    dns_conf::RuntimeConfig,
    libdns::proto::op::{Header, Message, ResponseCode},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

use futures_util::FutureExt;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::{
    app::App,
    config::{BindAddrConfig, IBindConfig as _, ServerOpts},
    dns::{DnsRequest, SerialMessage},
};

/// 🔐 P2：收包 / accept 出错后的退避间隔。
///
/// 原实现出错只 `continue`：一旦是持续性错误（网卡消失、fd 耗尽、防火墙一直丢），
/// 循环会以 100% CPU 空转，并且每一轮都写一条日志把日志文件刷爆。
/// 这里按连续错误次数做指数退避（5ms → 1s 封顶），成功一次就归零。
pub(crate) fn error_backoff_delay(streak: u32) -> std::time::Duration {
    const BASE_MS: u64 = 5;
    const MAX_MS: u64 = 1000;
    let shift = streak.saturating_sub(1).min(8);
    std::time::Duration::from_millis((BASE_MS << shift).min(MAX_MS))
}

/// 出错日志降频：前 3 次逐条打，之后每 100 次打一条（避免日志被刷爆）。
pub(crate) fn should_log_stream_error(streak: u32) -> bool {
    streak <= 3 || streak % 100 == 0
}

pub fn serve(
    app: &App,
    cfg: &RuntimeConfig,
    bind_addr_config: &BindAddrConfig,
    handle: &DnsHandle,
    idle_time: u64,
    certificate_file: Option<&Path>,
    certificate_key_file: Option<&Path>,
) -> Result<ServerHandle, crate::Error> {
    // 🔐 P0-5：连接建立后等待"第一个完整 DNS 报文"的超时（默认 5 秒，0 = 不限制）
    let first_packet_timeout = cfg.first_packet_timeout();

    // 🔐 逐监听连接上限：内网端口可以宽松、对公网端口单独收紧
    crate::server::limit::register_listener(
        bind_addr_config.sock_addr(),
        bind_addr_config.server_opts().max_connections,
        bind_addr_config.server_opts().max_connections_per_ip,
    );

    use crate::rustls::TlsServerCertResolver;
    use net::{bind_to, setup_tcp_socket, setup_udp_socket};
    use std::time::Duration;

    let dns_handle = handle.with_new_opt(bind_addr_config.server_opts().clone());

    fn create_cert_resolver(
        ssl_config: &SslConfig,
        certificate_file: Option<&Path>,
        certificate_key_file: Option<&Path>,
        typ: &'static str,
    ) -> Result<Arc<TlsServerCertResolver>, crate::Error> {
        let certificate_file = ssl_config
            .certificate
            .as_deref()
            .or(certificate_file)
            .ok_or(crate::Error::CertificatePathNotDefined(typ))?;
        let certificate_key_file = ssl_config
            .certificate_key
            .as_deref()
            .or(certificate_key_file)
            .ok_or(crate::Error::CertificateKeyPathNotDefined(typ))?;
        let resolver = TlsServerCertResolver::new(certificate_file, certificate_key_file)?;
        Ok(Arc::new(resolver))
    }

    let token = match bind_addr_config {
        BindAddrConfig::Udp(bind_addr_config) => {
            let token = CancellationToken::new();

            // 🌟 核心优化：仅在 Linux 下开启极限多路复用，其他系统保持单路以防兼容性问题
            #[cfg(target_os = "linux")]
            let workers = cfg.num_workers();
            #[cfg(not(target_os = "linux"))]
            let workers = 1;

            // 根据配置的 Worker 线程数，利用 SO_REUSEPORT 让内核帮我们分发 UDP 包。
            //
            // 🔐 A9（2026-09-17）：分两步走 —— 先把所有 worker 的 socket 都绑好，再统一开始收包。
            // 原来是一边绑一边 spawn，第 2 个 worker 绑失败时会 `?` 直接返回：前面已经绑好、
            // 已经在收包的那些 socket 谁都不管了 —— 它们继续占着端口（调用方拿不到句柄，
            // 重试永远绑不上），也不在 `listeners` 里（配置变更/关机都关不掉它们），变成幽灵监听。
            // 先绑后服务的话，中途失败时前面那些 socket 随 Vec 一起释放，端口立刻还回去，重试才有意义。
            let mut sockets = Vec::with_capacity(workers);
            for i in 0..workers {
                let bind_type = if i == 0 { "UDP" } else { "UDP (REUSEPORT)" };
                sockets.push(bind_to(
                    setup_udp_socket,
                    bind_addr_config.sock_addr(),
                    bind_addr_config.device(),
                    bind_type,
                )?);
            }
            for socket in sockets {
                // 将克隆好的统一 Token 传进去，确保关机时所有线程都能正确结束
                udp::serve(socket, dns_handle.clone(), token.clone());
            }

            token
        }
        BindAddrConfig::Tcp(bind_addr_config) => {
            let listener = bind_to(
                setup_tcp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                "TCP",
            )?;
            tcp::serve(
                listener,
                dns_handle,
                Duration::from_secs(idle_time),
                first_packet_timeout,
            )
        }
        #[cfg(feature = "dns-over-tls")]
        BindAddrConfig::Tls(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over TLS";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_tcp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            )?;

            tls::serve(
                listener,
                dns_handle,
                Duration::from_secs(idle_time),
                server_cert_resolver,
                first_packet_timeout,
            )?
        }
        BindAddrConfig::Http(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over HTTP";

            let listener = bind_to(
                setup_tcp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            )?;

            let app = app.clone();

            http::serve(app, listener, dns_handle, !bind_addr_config.opts.no_api())?
        }
        #[cfg(feature = "dns-over-https")]
        BindAddrConfig::Https(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over HTTPS";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_tcp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            )?;

            let app = app.clone();

            let h3_port = cfg
                .binds()
                .iter()
                .filter(|c| matches!(c, BindAddrConfig::H3(_)))
                .map(|c| c.port())
                .next();
            https::serve(app, listener, dns_handle, !bind_addr_config.opts.no_api(), server_cert_resolver, h3_port)?
        }
        #[cfg(feature = "dns-over-h3")]
        BindAddrConfig::H3(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over H3";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_udp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            )?;

            let app = app.clone();
            h3::serve(app, listener, dns_handle, !bind_addr_config.opts.no_api(), server_cert_resolver)?
        }
        #[cfg(feature = "dns-over-quic")]
        BindAddrConfig::Quic(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over QUIC";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_udp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            )?;

            quic::serve(
                listener,
                dns_handle,
                Duration::from_secs(idle_time),
                server_cert_resolver,
                ssl_config.server_name.clone(),
                first_packet_timeout,
            )?
        }
        #[cfg(not(feature = "dns-over-tls"))]
        BindAddrConfig::Tls(_) => {
            warn!("Bind DoT not enabled")
        }
        #[cfg(not(feature = "dns-over-https"))]
        BindAddrConfig::Https(_) => {
            warn!("Bind DoH not enabled")
        }
        #[cfg(not(feature = "dns-over-h3"))]
        BindAddrConfig::H3(_) => {
            warn!("Bind DoH3 not enabled")
        }
        #[cfg(not(feature = "dns-over-quic"))]
        BindAddrConfig::Quic(_) => {
            warn!("Bind DoQ not enabled")
        }
    };

    Ok(ServerHandle(token))
}

pub struct ServerHandle(CancellationToken);

impl ServerHandle {
    pub async fn shutdown(self) {
        self.0.cancel()
    }
}

impl From<CancellationToken> for ServerHandle {
    fn from(value: CancellationToken) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
pub struct DnsHandle {
    // 🌟 修复 1：使用有界发送器，拒绝无底洞
    sender: mpsc::Sender<IncomingDnsMessage>,
    opts: ServerOpts,
}

pub type IncomingDnsMessage = (SerialMessage, ServerOpts, oneshot::Sender<SerialMessage>);

// 🌟 修复 2：使用有界接收器
pub type IncomingDnsRequest = mpsc::Receiver<IncomingDnsMessage>;

impl DnsHandle {
    pub fn new() -> (IncomingDnsRequest, Self) {
        // 🌟 修复 3：最高缓冲 20000 个待处理请求（约占用 10MB 内存），超出直接丢包，抗死 DDoS！
        let (tx, rx) = mpsc::channel(20000);
        (
            rx,
            Self {
                sender: tx,
                opts: Default::default(),
            },
        )
    }

    pub async fn send<T: Into<SerialMessage>>(&self, message: T) -> SerialMessage {
        let message = message.into();
        let addr = message.addr();
        let protocol = message.protocol();
        let (tx, rx) = oneshot::channel();

        // 🔐 A4：报文马上会被移动进队列，所以**先**把"万一请求被丢弃，也要回一个能对上号的应答"
        // 所需的素材（原始 ID + 问题段）抽出来。UDP 不需要（外层是沉默丢弃，不做应答），
        // 也正好让最常见的 UDP 路径不为此多付一次解析。
        let refusal_material = if protocol == crate::libdns::Protocol::Udp {
            None
        } else {
            crate::app::response_material(&message)
        };

        // 🌟 修复 4：使用 try_send。如果队列满了，触发 Load Shedding (系统降载)
        if let Err(err) = self.sender.try_send((message, self.opts.clone(), tx)) {
            let message = match err {
                tokio::sync::mpsc::error::TrySendError::Full((msg, _, _)) => msg,
                tokio::sync::mpsc::error::TrySendError::Closed((msg, _, _)) => msg,
            };
            crate::log::trace!("System overloaded or closed, dropped DNS request from {}", addr);
            
            if protocol == crate::libdns::Protocol::Udp {
                // 🌟 核心修复 1：在 UDP 协议下，遇到超载直接生成空字节包！
                // 这将通知外层 Socket 触发沉默丢包（Silent Drop），彻底防止沦为 DDoS 反射放大器！
                return SerialMessage::binary(vec![], addr, protocol);
            } else {
                // TCP / TLS / QUIC 等面向连接的协议，依然老老实实返回 Refused 以优雅关闭流
                let mut response_message = DnsRequest::try_from(message)
                    .map(|req| req.to_response())
                    .unwrap_or_else(|_| Message::query().to_response());
                response_message.set_response_code(ResponseCode::Refused);
                return SerialMessage::raw(response_message, addr, protocol);
            }
        }

        match rx.await {
            Ok(msg) => msg,
            Err(_) => {
                // 内部超时或因为某种原因被抛弃
                if protocol == crate::libdns::Protocol::Udp {
                    SerialMessage::binary(vec![], addr, protocol)
                } else {
                    match refusal_material {
                        // 🔐 A4：回带**原始 ID 与问题段** —— 客户端（dig / 内嵌 hickory 等按 ID 配对的实现）
                        // 才认得出这是给它的应答；以前那条 ID 随机的 Refused 会被直接丢掉，用户看到的仍是超时。
                        Some((header, queries, _, _)) => {
                            let mut response_header = Header::response_from_request(&header);
                            response_header.set_response_code(ResponseCode::Refused);
                            let mut response_message = Message::query().to_response();
                            response_message.set_header(response_header);
                            for query in queries {
                                response_message.add_query(query);
                            }
                            SerialMessage::raw(response_message, addr, protocol)
                        }
                        // 连报文头都解析不出来：只能回一条不带 ID 的（客户端会忽略它，但至少不悬挂）
                        None => {
                            let mut response_message = Message::query().to_response();
                            response_message.set_response_code(ResponseCode::Refused);
                            SerialMessage::raw(response_message, addr, protocol)
                        }
                    }
                }
            }
        }
    }

    pub fn with_new_opt(&self, opts: ServerOpts) -> Self {
        Self {
            sender: self.sender.clone(),
            opts,
        }
    }
}

/// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
pub fn reap_tasks(join_set: &mut JoinSet<()>) {
    while FutureExt::now_or_never(join_set.join_next())
        .flatten()
        .is_some()
    {}
}

/// Checks if the IP address is safe for returning messages
///
/// Examples of unsafe addresses are any with a port of `0`
///
/// # Returns
///
/// Error if the address should not be used for returned requests
fn sanitize_src_address(src: SocketAddr) -> Result<(), String> {
    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    if src.port() == 0 {
        return Err(format!("cannot respond to src on port 0: {src}"));
    }

    fn verify_v4(src: Ipv4Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v4 addr: {src}"));
        }

        if src.is_broadcast() {
            return Err(format!("cannot respond to broadcast v4 addr: {src}"));
        }

        // TODO: add check for is_reserved when that stabilizes

        Ok(())
    }

    fn verify_v6(src: Ipv6Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v6 addr: {src}"));
        }

        Ok(())
    }

    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    match src.ip() {
        IpAddr::V4(v4) => verify_v4(v4),
        IpAddr::V6(v6) => verify_v6(v6),
    }
}

#[cfg(test)]
mod stream_error_backoff_tests {
    use super::*;

    /// 🔐 P2：持续性错误（网卡消失、fd 耗尽）不能让循环 100% CPU 空转。
    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(error_backoff_delay(0).as_millis(), 5, "0 次也不能 panic");
        assert_eq!(error_backoff_delay(1).as_millis(), 5);
        assert_eq!(error_backoff_delay(2).as_millis(), 10);
        assert_eq!(error_backoff_delay(3).as_millis(), 20);
        assert_eq!(error_backoff_delay(8).as_millis(), 640);
        assert_eq!(error_backoff_delay(9).as_millis(), 1000);
        // 封顶 1 秒，且再涨也不超过（保证错误消失后能很快恢复正常）
        assert_eq!(error_backoff_delay(10).as_millis(), 1000);
        assert_eq!(error_backoff_delay(u32::MAX).as_millis(), 1000);
    }

    /// 日志降频：前 3 次逐条打，之后每 100 次一条。
    #[test]
    fn error_log_is_throttled() {
        assert!(should_log_stream_error(1));
        assert!(should_log_stream_error(2));
        assert!(should_log_stream_error(3));
        assert!(!should_log_stream_error(4));
        assert!(!should_log_stream_error(99));
        assert!(should_log_stream_error(100));
        assert!(!should_log_stream_error(101));
    }
}

/// 收包错误是不是"这条报文本身超过了我们的接收缓冲"（单包可恢复，不代表 socket 出了故障）。
///
/// 为什么要单独识别：这类错误每次**消费掉一条报文**，收包循环不会空转 —— 拿它走"持续性故障"
/// 的指数退避，等于让一条 16 KB 的攻击包换来最多 1 秒的处理停顿（A5）。
pub(crate) fn is_oversized_datagram(e: &std::io::Error) -> bool {
    // Windows: WSAEMSGSIZE(10040)；Linux: EMSGSIZE(90)；macOS/BSD: EMSGSIZE(40)
    const WSAEMSGSIZE: i32 = 10040;

    match e.raw_os_error() {
        Some(code) if code == WSAEMSGSIZE => true,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Some(code) if code == 90 => true,
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        Some(code) if code == 40 => true,
        _ => false,
    }
}

#[cfg(test)]
mod oversized_datagram_tests {
    use super::is_oversized_datagram;

    /// 🔐 A5：只有"报文过大"这一类错误走"不退避"的通道，其它错误仍按持续性故障处理。
    #[test]
    fn only_message_too_long_is_classified() {
        assert!(
            is_oversized_datagram(&std::io::Error::from_raw_os_error(10040)),
            "WSAEMSGSIZE(10040) 必须被识别为报文过大"
        );
        assert!(!is_oversized_datagram(&std::io::Error::from_raw_os_error(0)));
        assert!(!is_oversized_datagram(&std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "test"
        )));
    }
}

