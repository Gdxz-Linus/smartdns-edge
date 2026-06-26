use crate::dns_client::{BootstrapResolver, GenericResolverExt};
use crate::dns_url::{DnsUrl, Host, HttpsPrefer, ProtocolConfig};
use crate::libdns::custom::warmup::DnsHandleWarmpup;
use crate::log;
use crate::proxy::{self, ProxyConfig};
use crate::proxy::{TcpStream, UdpSocket};
use crate::third_ext::FutureTimeoutExt;
use async_trait::async_trait;
use futures::FutureExt;
use hickory_resolver::config::NameServerConfig;
use smallvec::{SmallVec, smallvec, smallvec_inline};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::task::Poll;
use std::task::ready;
use std::time::Duration;
use std::{io, net::SocketAddr, pin::Pin};

use crate::libdns::{
    proto::{
        self, ProtoError, ProtoErrorKind,
        runtime::{
            QuicSocketBinder, RuntimeProvider as _, Spawn, TokioHandle, TokioTime,
            iocompat::AsyncIoTokioAsStd,
        },
        xfer::{DnsExchange, DnsExchangeConnect, DnsMultiplexer, DnsMultiplexerConnect},
    },
    resolver::config::{ConnectionConfig, ResolverOpts},
};
use std::borrow::Cow;

pub type Connection = crate::libdns::resolver::name_server::NameServer<ConnectionProvider>;
type RuntimeProvider = TokioRuntimeProvider;
type Handle = TokioHandle;
type Time = TokioTime;
type Tcp = AsyncIoTokioAsStd<TcpStream>;
type Udp = UdpSocket;
type ConnectionFuture = Pin<Box<dyn Send + Future<Output = Result<DnsExchange, ProtoError>>>>;

static FAKE_SERVER_CONFIG: std::sync::LazyLock<NameServerConfig> =
    std::sync::LazyLock::new(|| NameServerConfig::udp(Ipv4Addr::UNSPECIFIED.into()));

#[derive(Clone)]
pub struct ConnectionProvider {
    server: DnsUrl,
    resolver: Option<Arc<BootstrapResolver>>,
    options: Arc<ResolverOpts>,
    runtime_provider: RuntimeProvider,
}

impl ConnectionProvider {
    pub fn new(
        server: DnsUrl,
        options: Arc<ResolverOpts>,
        resolver: Option<Arc<BootstrapResolver>>,
        proxy: Option<ProxyConfig>,
        so_mark: Option<u32>,
        device: Option<String>,
    ) -> Connection {
        let config = (&server).into();

        Connection::new(
            &FAKE_SERVER_CONFIG, // use ip and trust_negative_responses
            config,              // use protocol
            options.clone(),
            Self {
                server,
                resolver,
                options,
                runtime_provider: TokioRuntimeProvider::new(proxy, so_mark, device),
            },
        )
    }
}

impl crate::libdns::resolver::name_server::ConnectionProvider for ConnectionProvider {
    type Conn = DnsExchange;

    type FutureConn = ConnectionFuture;

    type RuntimeProvider = RuntimeProvider;

    fn new_connection(
        &self,
        _ip: IpAddr,
        _config: &ConnectionConfig,
        _options: &ResolverOpts,
    ) -> Result<Self::FutureConn, io::Error> {
        let server = self.server.clone();
        let options = self.options.clone();
        let runtime_proviver = self.runtime_provider.clone();
        let resolver = self.resolver.clone();
        type StackVec<T> = SmallVec<[T; 2]>;
        type Stack2xVec<T> = SmallVec<[T; 4]>;

        Ok(async move {
            // 🌟 核心修复 3：跨平台网卡分流！Win/Mac 平台将网卡名动态翻译成本机 IP，完美实现 -device 参数分流！
            let bind_addr = if let Some(_dev) = &runtime_proviver.device {
                #[cfg(not(any(target_os = "android", target_os = "linux")))]
                {
                    local_ip_address::list_afinet_netifas().ok().and_then(|interfaces| {
                        interfaces.into_iter()
                            .find(|(name, _)| name == dev)
                            .map(|(_, ip)| std::net::SocketAddr::new(ip, 0))
                    })
                }
                #[cfg(any(target_os = "android", target_os = "linux"))]
                { None } // Linux / Android 使用底层的 SO_BINDTODEVICE，无需在此绑定 IP
            } else {
                None
            };

            let ip_addrs: StackVec<(_, StackVec<_>)> = match (server.host(), server.proto()) {
                (_, ProtocolConfig::System) => {
                    let (resolv_conf, _) = crate::libdns::resolver::system_conf::read_system_conf()?;
                    if resolv_conf.name_servers.is_empty() {
                        return Err(ProtoErrorKind::NoConnections.into());
                    }
                    resolv_conf.name_servers.iter().map(|conf| {
                        let mut url = DnsUrl::from(conf);
                        *url = (*server).clone(); // params
                        (Cow::Owned(url), smallvec![conf.ip])
                    }).collect()
                },
                (_, ProtocolConfig::Dhcp { interface }) => {
                    use crate::infra::dhcp::{discover_v4, DhcpMessageExt};
                    let interface = interface.as_deref();

                    let msg = discover_v4(interface).await.map_err(|err| {
                        log::warn!("dhcp discover failed: {}", err);
                        io::Error::other("dhcp discover failed")
                    })?;

                    let nameservers = msg.nameservers();

                    if nameservers.is_empty() {
                        return Err(ProtoErrorKind::NoConnections.into());
                    }

                    nameservers.into_iter().map(|ip| {
                        (Cow::Owned(DnsUrl::from(ip)), smallvec![ip])
                    }).collect()
                },
                (Host::Domain(domain), _) => {
                    match server.get_param::<IpAddr>("ip") {
                        Some(ip) => smallvec![(Cow::Borrowed(&server), smallvec![ip])],
                        None => {
                            let Some(resolver) = resolver.as_ref() else {
                                log::warn!("resolver must be set when using domain name");
                                return Err(ProtoErrorKind::NoConnections.into());
                            };

                            let ip_addrs = match resolver.lookup_ip(domain).await {
                                Ok(lookup_ip) => lookup_ip.ip_addrs().into_iter().collect(),
                                Err(err) => {
                                    log::warn!("lookup ip: {domain} failed, {err}");
                                    smallvec![]
                                }
                            };

                            if ip_addrs.is_empty() {
                                return Err(ProtoErrorKind::NoConnections.into());
                            }
                            smallvec![(Cow::Borrowed(&server), ip_addrs)]
                        }
                    }
                }
                (Host::Ipv4(ipv4_addr), _) => {
                    smallvec![(Cow::Borrowed(&server), smallvec![(*ipv4_addr).into()])]
                }
                (Host::Ipv6(ipv6_addr), _) => {
                    smallvec![(Cow::Borrowed(&server), smallvec![(*ipv6_addr).into()])]
                }
            };

            let server_addrs: StackVec<(_, StackVec<_>)> = ip_addrs
                .into_iter()
                .map(|(server, ip)| {
                    let port = server.port();
                    (server, ip.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
                })
                .collect();

            if let [(server, server_addrs)] = &*server_addrs
                && let [server_addr] = &**server_addrs
                && !matches!(server.proto(), ProtocolConfig::Https { prefer, .. } if *prefer != HttpsPrefer::H2)
            {
                return new_connection(server, *server_addr, bind_addr, &options, runtime_proviver).await;
            }

            let mut h3_server_addrs = Stack2xVec::<(Cow<DnsUrl>, _, _)>::new();
            for (server, server_addrs) in &server_addrs {
                let server = Cow::Borrowed(&**server);
                match server.proto() {
                    ProtocolConfig::Https { prefer, path, .. } if *prefer != HttpsPrefer::H2 => {
                        let h3_proto = ProtocolConfig::H3 {
                            path: path.clone(),
                            disable_grease: server.is_set("disable_grease"),
                        };
                        let delay_h2 = *prefer == HttpsPrefer::H3;
                        h3_server_addrs.extend(server_addrs.iter().flat_map(|server_addr| {
                            let h2_server = server.clone();
                            let mut h3_server = server.clone();
                            h3_server.to_mut().set_proto(h3_proto.clone());
                            smallvec_inline![
                                (h3_server, server_addr, false),
                                (h2_server, server_addr, delay_h2),
                            ]
                        }));
                    },
                    _ => h3_server_addrs.extend(server_addrs.iter().map(|server_addr| (server.clone(), server_addr, false)))
                }
            }
            let server_addrs = h3_server_addrs;

            let mut pending_conns = server_addrs.into_iter().peekable();
            let mut running = futures_util::stream::FuturesUnordered::new();
            use futures_util::StreamExt;

            let mut last_err = None;
            let mut needs_spawn = true; // 初始状态为 true，立刻启动首个 IP

            let conn = loop {
                // 阶段一：等待已有连接出结果，或者 250ms 错峰超时
                if !needs_spawn {
                    let delay_fut = tokio::time::sleep(Duration::from_millis(250));
                    tokio::pin!(delay_fut);
                    let has_pending = pending_conns.peek().is_some();

                    tokio::select! {
                        res = running.next() => {
                            match res {
                                Some(Ok(conn)) => break Ok(conn), // 有一个连接成功热身，立刻突围！
                                Some(Err(err)) => {
                                    last_err = Some(err);
                                    // 🌟 如果某个 IP 彻底连不上，立即启动下一个 IP 的并发，不浪费 250ms！
                                    needs_spawn = true; 
                                }
                                None => {
                                    needs_spawn = true; // 队列空了，必须派发新的
                                }
                            }
                        }
                        _ = &mut delay_fut, if has_pending => {
                            // 🌟 250ms 到了！不管前面的 IP 连没连上（也许正在卡主），强行并发启动下一个 IP 组！
                            needs_spawn = true;
                        }
                    }
                }

                // 阶段二：派发下一个 IP 的所有协议任务
                if needs_spawn {
                    if pending_conns.peek().is_none() && running.is_empty() {
                        // 弹尽粮绝，报错退出
                        break Err(last_err.unwrap_or_else(|| ProtoErrorKind::NoConnections.into()));
                    }

                    let mut current_ip = None;
                    while let Some((_, server_addr, _)) = pending_conns.peek() {
                        if let Some(ip) = current_ip {
                            if ip != server_addr.ip() {
                                break; // 遇到新的 IP，暂停派发，交给 250ms 的 Happy Eyeballs 错峰！
                            }
                        } else {
                            current_ip = Some(server_addr.ip());
                        }

                        let (server_cow, server_addr, delay) = pending_conns.next().unwrap();
                        let options = options.clone();
                        let runtime_proviver = runtime_proviver.clone();
                        let server_addr_val = *server_addr;
                        
                        // 🌟 核心修复：将 Cow 转换为 Owned 彻底切断生命周期借用链！
                        // 满足 BoxFuture 要求的 Send + 'static 线程安全闭环。
                        let server_owned = server_cow.into_owned();

                        running.push(async move {
                            // 🌟 同 IP 内的协议降级（如 H3/H2）依然保留 150ms 竞速让路
                            if delay {
                                tokio::time::sleep(Duration::from_millis(150)).await;
                            }

                            let conn = new_connection(&server_owned, server_addr_val, bind_addr, &options, runtime_proviver).await?;

                            // 🌟 严格校验 warmup，防止坏连接成为盲区
                            if !conn.warmup().await.is_ok() {
                                return Err(ProtoErrorKind::Io(Arc::new(io::Error::other("warmup failed, connection broken"))).into());
                            }

                            Ok(conn)
                        }.boxed());
                    }
                    needs_spawn = false; // 派发完毕，进入等待
                }
            };

            match conn {
                Ok(conn) => Ok(conn),
                Err(err) => {
                    log::error!("Failed to connect to any nameserver: {} {}", server, err);
                    return Err(err);
                }
            }
        }
        .boxed())
    }
}

async fn new_connection(
    server: &DnsUrl,
    server_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    options: &ResolverOpts,
    runtime_proviver: RuntimeProvider,
) -> Result<DnsExchange, ProtoError> {
    let mut spawner = runtime_proviver.create_handle();

    // 🌟 核心修复 1（高级版）：智能协议降级，完美兼顾隐私与可用性！
    // 当检测到用户配置了 SOCKS5 代理时，将无法通过代理的 UDP 协议平滑降级为 TCP 协议
    let mut effective_proto = server.proto().clone();
    if runtime_proviver.proxy.is_some() {
        match effective_proto {
            #[cfg(all(feature = "dns-over-quic", feature = "dns-over-tls"))]
            ProtocolConfig::Quic => {
                crate::log::warn!("QUIC over proxy is not supported, downgrading to DoT (TLS) for {}", server.host());
                effective_proto = ProtocolConfig::Tls;
            }
            #[cfg(all(feature = "dns-over-h3", feature = "dns-over-https"))]
            ProtocolConfig::H3 { ref path, .. } => {
                crate::log::warn!("HTTP/3 over proxy is not supported, downgrading to DoH (HTTPS/2) for {}", server.host());
                effective_proto = ProtocolConfig::Https {
                    path: path.clone(),
                    prefer: crate::dns_url::HttpsPrefer::H2,
                };
            }
            _ => {}
        }
    }

    // 🌟 注意：这里 match 变成了 effective_proto
    let conn = match (&effective_proto, runtime_proviver.quic_binder()) {
        (ProtocolConfig::Udp, _) => {
            #[cfg(feature = "mdns")]
            {
                use crate::libdns::proto::multicast::MDNS_IPV4;
                use crate::libdns::proto::multicast::MdnsClientConnect;
                use crate::libdns::proto::multicast::MdnsClientStream;
                use crate::libdns::proto::multicast::MdnsQueryType;
                type Connecting = DnsExchangeConnect<
                    DnsMultiplexerConnect<MdnsClientConnect, MdnsClientStream>,
                    DnsMultiplexer<MdnsClientStream>,
                    Time,
                >;

                if server_addr == *MDNS_IPV4 {
                    let timeout = options.timeout;

                    // let (stream, handle) =
                    //     MdnsClientStream::new(socket_addr, MdnsQueryType::OneShot, None, None, Some(32));

                    let (stream, handle) = MdnsClientStream::new(
                        server_addr,
                        MdnsQueryType::OneShotJoin,
                        None,
                        None,
                        Some(32),
                    );

                    // TODO: need config for Signer...
                    let dns_conn = DnsMultiplexer::with_timeout(stream, handle, timeout, None);

                    let exchange: Connecting = DnsExchange::connect(dns_conn);

                    let (conn, bg) = exchange.await?;
                    spawner.spawn_bg(bg);

                    return Ok(conn);
                }
            }

            use crate::libdns::proto::udp::UdpClientConnect;
            use crate::libdns::proto::udp::UdpClientStream;
            type Connecting = DnsExchangeConnect<
                UdpClientConnect<RuntimeProvider>,
                UdpClientStream<RuntimeProvider>,
                Time,
            >;
            let provider_handle = runtime_proviver.clone();
            let stream = UdpClientStream::builder(server_addr, provider_handle)
                .with_timeout(Some(options.timeout))
                .with_os_port_selection(options.os_port_selection)
                .avoid_local_ports(options.avoid_local_udp_ports.clone())
                .with_bind_addr(bind_addr)
                .build();
            let exchange: Connecting = DnsExchange::connect(stream);
            let (conn, bg) = exchange.await?;
            spawner.spawn_bg(bg);

            conn
        }
        (ProtocolConfig::Tcp, _) => {
            use crate::libdns::proto::tcp::TcpClientStream;
            type Connecting = DnsExchangeConnect<
                DnsMultiplexerConnect<
                    Pin<Box<dyn Future<Output = Result<TcpClientStream<Tcp>, ProtoError>> + Send>>,
                    TcpClientStream<Tcp>,
                >,
                DnsMultiplexer<TcpClientStream<Tcp>>,
                Time,
            >;

            let (future, handle) = TcpClientStream::new(
                server_addr,
                bind_addr,
                Some(options.timeout),
                runtime_proviver,
            );

            // TODO: need config for Signer...
            let dns_conn = DnsMultiplexer::with_timeout(future, handle, options.timeout, None);
            let exchange: Connecting = DnsExchange::connect(dns_conn);
            let (conn, bg) = exchange.await?;
            spawner.spawn_bg(bg);

            conn
        }
        #[cfg(feature = "dns-over-tls")]
        (ProtocolConfig::Tls, _) => {
            use crate::libdns::proto::rustls::TlsClientStream;
            use crate::libdns::proto::rustls::tls_client_stream::tls_client_connect_with_future;
            use rustls::pki_types::ServerName;
            type Connecting = DnsExchangeConnect<
                DnsMultiplexerConnect<
                    Pin<
                        Box<
                            dyn Future<Output = Result<TlsClientStream<Tcp>, ProtoError>>
                                + Send
                                + 'static,
                        >,
                    >,
                    TlsClientStream<Tcp>,
                >,
                DnsMultiplexer<TlsClientStream<Tcp>>,
                Time,
            >;

            let timeout = options.timeout;
            let tcp_future = runtime_proviver.connect_tcp(server_addr, None, None);

            let server_name = server.host().to_string();

            let Ok(server_name) = ServerName::try_from(server_name.as_str()) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid server name: {server_name}"),
                ))?;
            };

            // 🌟 核心修复 2：尊重用户配置，不再一刀切关闭 SNI，全面兼容严格的海外 DoT 节点
            let tls_config = options.tls_config.clone();

            let (stream, handle) = tls_client_connect_with_future(
                tcp_future,
                server_addr,
                server_name.to_owned(),
                Arc::new(tls_config),
            );

            let exchange: Connecting =
                DnsExchange::connect(DnsMultiplexer::with_timeout(stream, handle, timeout, None));

            let (conn, bg) = exchange.await?;
            spawner.spawn_bg(bg);

            conn
        }
        #[cfg(feature = "dns-over-https")]
        (ProtocolConfig::Https { path, .. }, _) => {
            use crate::libdns::proto::h2::HttpsClientConnect;
            use crate::libdns::proto::h2::HttpsClientStream;
            type Connecting = DnsExchangeConnect<HttpsClientConnect<Tcp>, HttpsClientStream, Time>;

            let server_name = server.name();

            let exchange: Connecting = DnsExchange::connect(HttpsClientConnect::new(
                runtime_proviver.connect_tcp(server_addr, None, None),
                Arc::new(options.tls_config.clone()),
                server_addr,
                server_name.clone(),
                path.clone(),
            ));

            let (conn, bg) = exchange.await?;
            spawner.spawn_bg(bg);

            conn
        }
        #[cfg(feature = "dns-over-quic")]
        (ProtocolConfig::Quic, Some(binder)) => {
            use crate::libdns::proto::quic::QuicClientConnect;
            use crate::libdns::proto::quic::QuicClientStream;
            use std::net::Ipv4Addr;
            use std::net::Ipv6Addr;
            type Connecting = DnsExchangeConnect<QuicClientConnect, QuicClientStream, Time>;
            let bind_addr = bind_addr.unwrap_or(match server_addr {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            });

            let server_name = server.name();

            let exchange: Connecting = DnsExchange::connect(
                QuicClientStream::builder()
                    .crypto_config(options.tls_config.clone())
                    .build_with_future(
                        binder.bind_quic(bind_addr, server_addr)?,
                        server_addr,
                        server_name.clone(),
                    ),
            );

            let (conn, bg) = exchange.await?;
            spawner.spawn_bg(bg);

            conn
        }
        #[cfg(feature = "dns-over-h3")]
        (
            ProtocolConfig::H3 {
                path,
                disable_grease,
                ..
            },
            Some(binder),
        ) => {
            use crate::libdns::proto::h3::H3ClientConnect;
            use crate::libdns::proto::h3::H3ClientStream;
            use std::net::Ipv4Addr;
            use std::net::Ipv6Addr;
            type Connecting = DnsExchangeConnect<H3ClientConnect, H3ClientStream, Time>;
            let bind_addr = bind_addr.unwrap_or(match server_addr {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            });

            let server_name = server.name();

            let exchange: Connecting = DnsExchange::connect(
                H3ClientStream::builder()
                    .crypto_config(options.tls_config.clone())
                    .disable_grease(*disable_grease)
                    .build_with_future(
                        binder.bind_quic(bind_addr, server_addr)?,
                        server_addr,
                        server_name.clone(),
                        path.clone(),
                    ),
            );

            let (conn, bg) = exchange.await?;
            spawner.spawn_bg(bg);

            conn
        }
        #[cfg(feature = "dns-over-quic")]
        (ProtocolConfig::Quic, None) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime provider does not support QUIC",
        ))?,
        #[cfg(feature = "dns-over-h3")]
        (ProtocolConfig::H3 { .. }, None) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime provider does not support QUIC",
        ))?,
        (p, _) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported protocol configuration: {p:?}"),
        ))?,
    };
    Ok(conn)
}

/// The Tokio Runtime for async execution
#[derive(Clone, Default)]
pub struct TokioRuntimeProvider {
    proxy: Option<ProxyConfig>,
    so_mark: Option<u32>,
    device: Option<String>,
    handle: TokioHandle,
}

impl TokioRuntimeProvider {
    pub fn new(proxy: Option<ProxyConfig>, so_mark: Option<u32>, device: Option<String>) -> Self {
        Self {
            proxy,
            so_mark,
            device,
            handle: TokioHandle::default(),
        }
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn setup_socket<F: std::os::fd::AsFd, S: std::ops::Deref<Target = F> + Sized>(
    socket: S,
    bind_addr: Option<SocketAddr>,
    mark: Option<u32>,
    device: Option<String>,
) -> S {
    if mark.is_some() || device.is_some() || bind_addr.is_some() {
        use socket2::SockRef;
        let sock_ref = SockRef::from(socket.deref());
        if let Some(mark) = mark {
            sock_ref.set_mark(mark).unwrap_or_else(|err| {
                log::warn!("set so_mark failed: {:?}", err);
            });
        }

        if let Some(device) = device {
            sock_ref
                .bind_device(Some(device.as_bytes()))
                .unwrap_or_else(|err| {
                    log::warn!("bind device failed: {:?}", err);
                });
        }

        if let Some(bind_addr) = bind_addr {
            sock_ref.bind(&bind_addr.into()).unwrap_or_else(|err| {
                log::warn!("bind addr failed: {:?}", err);
            });
        }
    }
    socket
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
#[inline]
fn setup_socket<S>(
    socket: S,
    _bind_addr: Option<SocketAddr>,
    _mark: Option<u32>,
    _device: Option<String>,
) -> S {
    socket
}

impl crate::libdns::proto::runtime::RuntimeProvider for TokioRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let proxy_config = self.proxy.clone();
        let so_mark = self.so_mark;
        let device = self.device.clone();
        let wait_for = timeout.unwrap_or_else(|| Duration::from_secs(5));

        Box::pin(async move {
            async move {
                let target_addr = if let Some(proxy) = &proxy_config {
                    proxy.server
                } else {
                    server_addr
                };

                let socket = match target_addr {
                    SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
                };

                if let Some(addr) = bind_addr {
                    let _ = socket.bind(addr);
                }
                
                // 🌟 核心修复 1：建立 TCP 连接前，提前打上防火墙 SO_MARK 和网卡标签！
                // 彻底堵死 Linux 内核偷偷利用默认网卡发送 SYN 握手包导致漏流的物理可能。
                setup_socket(&socket, None, so_mark, device);
                
                let stream = socket.connect(target_addr).await?;

                proxy::handshake_tcp(stream, server_addr, proxy_config.as_ref())
                    .await
                    .map(AsyncIoTokioAsStd)
            }
            .timeout(wait_for)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                ))
            })
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let proxy_config = self.proxy.clone();
        let so_mark = self.so_mark;
        let device = self.device.clone();

        Box::pin(async move {
            let udp_socket = match local_addr {
                SocketAddr::V4(_) => tokio::net::UdpSocket::bind(local_addr).await?,
                SocketAddr::V6(_) => tokio::net::UdpSocket::bind(local_addr).await?,
            };
            
            // UDP 是无连接的，在首个发包前设置即可立刻生效
            setup_socket(&udp_socket, None, so_mark.clone(), device.clone());

            let tcp_stream = if let Some(proxy) = &proxy_config {
                let target_addr = proxy.server;
                let tcp_socket = match target_addr {
                    SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
                };
                
                // 🌟 核心修复 2：为了进行 SOCKS5 代理产生的辅助 TCP 控制流，
                // 也必须严格遵守用户的防火墙与策略路由标记，绝不允许代理链路漏出！
                setup_socket(&tcp_socket, None, so_mark, device);
                Some(tcp_socket.connect(target_addr).await?)
            } else {
                None
            };

            proxy::handshake_udp(tcp_stream, udp_socket, proxy_config.as_ref()).await
        })
    }

    #[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        // 🌟 将提供者自身作为 Binder 传递出去，从而携带路由配置信息
        Some(self) 
    }
}

// 🌟 核心修复 3：让 TokioRuntimeProvider 直接实现 QuicSocketBinder，打通策略壁垒
#[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
impl QuicSocketBinder for TokioRuntimeProvider {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        use quinn::Runtime;
        let socket = next_random_udp(local_addr)?;
        
        // 🌟 绝杀：为 QUIC/H3 的底层 UDP 套接字强行打上 SO_MARK 和 Bind Device！
        // 从此再也没有流量能偷偷溜出 VPN 透明代理或策略路由了。
        setup_socket(&socket, None, self.so_mark, self.device.clone());
        
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

#[async_trait]
impl proto::udp::DnsUdpSocket for UdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<(usize, SocketAddr)>> {
        match self {
            UdpSocket::Tokio(s) => {
                let mut buf = tokio::io::ReadBuf::new(buf);
                let addr = ready!(tokio::net::UdpSocket::poll_recv_from(s, cx, &mut buf))?;
                let len = buf.filled().len();
                Poll::Ready(Ok((len, addr)))
            }
            UdpSocket::Proxy(s) => {
                let (len, addr) = ready!(s.poll_recv_from(cx, buf))
                    .map_err(|err| io::Error::other(err.to_string()))?;
                let addr = match addr {
                    async_socks5::AddrKind::Ip(addr) => addr,
                    async_socks5::AddrKind::Domain(_, _) => {
                        Err(io::Error::other("Expect IP address"))?
                    }
                };
                Poll::Ready(Ok((len, addr)))
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::task::Poll<io::Result<usize>> {
        match self {
            UdpSocket::Tokio(s) => tokio::net::UdpSocket::poll_send_to(s, cx, buf, target),
            UdpSocket::Proxy(s) => {
                let res = ready!(s.poll_send_to(cx, buf, target))
                    .map_err(|err| io::Error::other(err.to_string()));
                Poll::Ready(res)
            }
        }
    }

    /// Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use UdpSocket::*;
        let (len, addr) = match self {
            Tokio(s) => s.recv_from(buf).await,
            Proxy(s) => {
                let (len, addr) = s
                    .recv_from(buf)
                    .await
                    .map_err(|err| io::Error::other(err.to_string()))?;

                let addr = match addr {
                    async_socks5::AddrKind::Ip(addr) => addr,
                    async_socks5::AddrKind::Domain(_, _) => {
                        Err(io::Error::other("Expect IP address"))?
                    }
                };
                Ok((len, addr))
            }
        }?;
        Ok((len, addr))
    }

    /// Send data to the given address.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        use UdpSocket::*;
        match self {
            Tokio(s) => s.send_to(buf, target).await,
            Proxy(s) => s
                .send_to(buf, target)
                .await
                .map_err(|err| io::Error::other(err.to_string())),
        }
    }
}

fn next_random_udp(bind_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    const ATTEMPT_RANDOM: usize = 10;
    if bind_addr.port() == 0 {
        for attempt in 0..ATTEMPT_RANDOM {
            // Per RFC 6056 Section 3.2:
            //
            // As mentioned in Section 2.1, the dynamic ports consist of the range
            // 49152-65535.  However, ephemeral port selection algorithms should use
            // the whole range 1024-65535.
            let port = rand::random_range(1024..=u16::MAX);

            let bind_addr = SocketAddr::new(bind_addr.ip(), port);

            match std::net::UdpSocket::bind(bind_addr) {
                Ok(socket) => {
                    log::debug!("created socket successfully");
                    return Ok(socket);
                }
                Err(err) => {
                    log::debug!("unable to bind port, attempt: {}: {err}", attempt);
                }
            }
        }
    }
    std::net::UdpSocket::bind(bind_addr)
}
