// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// 本文件派生自 hickory-dns 的 crates/resolver/src/name_server/connection_provider.rs
// （上游源文件与许可证头见本仓库内嵌副本 hickory-dns/crates/resolver/src/name_server/）。
// 上游的版权与双许可声明按 Apache-2.0 / MIT 的要求保留于此；本文件在其基础上按本项目
// 的需要做了修改（例如为补上"上游把 UDP 的 connect() 注释掉"这个安全缺口，见下面 P1-9 的改动）。
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
            #[allow(unused_variables)]
            let bind_addr = if let Some(dev) = &runtime_proviver.device {
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
                    Err(err)
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
                crate::log::warn!(
                    "QUIC over proxy is not supported, downgrading to DoT (TLS) for {}",
                    server.host()
                );
                effective_proto = ProtocolConfig::Tls;
            }
            #[cfg(all(feature = "dns-over-h3", feature = "dns-over-https"))]
            ProtocolConfig::H3 { ref path, .. } => {
                crate::log::warn!(
                    "HTTP/3 over proxy is not supported, downgrading to DoH (HTTPS/2) for {}",
                    server.host()
                );
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
                // 🔐 Q15：请求头里的 Host（`-http-host`，或按 C 版规则由地址推出来）
                Some(http_authority(&server, &server_name, server_addr.port())),
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
                    // 🔐 Q15：请求头里的 Host（`-http-host`，或按 C 版规则由地址推出来）
                    .http_host_opt(Some(http_authority(
                        &server,
                        &server_name,
                        server_addr.port(),
                    )))
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
        server_addr: SocketAddr,
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
            setup_socket(&udp_socket, None, so_mark, device.clone());

            // 🌟 P1-9 修复：直连 UDP 上游必须真正 connect ——
            // 否则应答只按 16 位事务 ID 认领，任何能到达该临时端口并猜中 ID 的主机
            // 都能注入伪造应答（C 原版 client_udp.c:144 就是这么 connect 的）。
            // connect 后由内核完成源 IP + 源端口过滤，防护等级最高、成本为零。
            // 多播（mDNS 等，如 224.0.0.251）必须排除：它本来就允许多个来源。
            if proxy_config.is_none() && !server_addr.ip().is_multicast() {
                udp_socket.connect(server_addr).await?;
            }

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

            let socket =
                proxy::handshake_udp(tcp_stream, udp_socket, proxy_config.as_ref()).await?;

            // 🌟 P1-9 修复（代理路径的补充防护）：SOCKS5 数据报头部带着应答来源地址
            // （RFC 1928 §7）。握手已经把 UDP 套接字 connect 到中继地址（内核挡掉非中继来源），
            // 这里再登记"我们查询的上游"，让 SocksDatagram 丢弃头部来源不符的数据报。
            if let proxy::UdpSocket::Proxy(datagram) = &socket {
                datagram.set_expected_source(server_addr);
            }

            Ok(socket)
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
        server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        use quinn::Runtime;
        let socket =
            prepare_quic_socket(local_addr, server_addr, self.so_mark, self.device.clone())?;
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

/// DoQ / DoH3 的底层 UDP 套接字：随机端口 + 路由选项（SO_MARK / 绑定网卡）+ **connect 到上游**。
///
/// 拆成独立函数是为了让单测能直接看 `peer_addr()` —— `bind_quic` 交出去的
/// `Arc<dyn quinn::AsyncUdpSocket>` 从外面看不到对端。
///
/// 🔐 ## P1-9 的同款收口，补到 DoQ / DoH3 这一侧（2026-09-17）
///
/// 把底层 UDP 套接字 `connect()` 到上游地址，让**内核**只把该对端的数据报交给我们；
/// 其他来源（伪造应答、扫描、垃圾流量）在到达用户态之前就被丢掉。
///
/// 三条依据：
/// 1. **与 C 版一致**：C 版的 DoQ 同样是 `connect(fd, &server_info->addr, ...)`
///    （`src/dns_client/client_quic.c`）；本项目先前只补了普通 UDP 上游那一条（内嵌
///    `udp_stream.rs` 的 `connect_with_bind()`），DoQ/H3 漏了。
/// 2. **发送侧不受影响**：MSDN `connect` 写明"连接后，来自非指定地址的数据报会被丢弃"
///    （datagram 套接字），而发送依旧可用 —— quinn 在 Windows 用 `WSASendMsg`、Linux 用
///    `sendmsg` 带上目的地，那个目的地恒等于本次 `connect` 的上游（`WSASendTo`/`WSASendMsg`
///    的文档：已连接的数据报套接字上，报文里的地址只覆盖本次发送）。
///    单测 `p1_9_quic_source_filter_tests` 覆盖"机制 + 收得到上游 + 挡得住第三方"；
///    端到端 `run_p2quicsrc.py`（真实二进制 + 真 QUIC）覆盖"改前 netstat 显示 `*:*`、
///    改后显示上游地址，且经 DoQ 上游的解析照旧成功"。
/// 3. **一 socket 一对端成立**：每个连接都单独 `next_random_udp` 开新端口，
///    而且 binder 是在 `new_connection` 里按具体上游地址调用的（见上一层的调用点），
///    所以"认死"不会妨碍同实例使用多个 DoQ 上游。
///
/// ⚠️ connect 失败只告警、继续用未连接的套接字：可用性优先。QUIC 本身有握手校验，
/// 伪造的答案进不来；这里省下的是"内核提前丢包"的开销，不值得为它牺牲一条能用的上游。
///
/// 已知边界：如果上游在握手后通告备用地址、要求客户端迁过去（RFC 9000 的 preferred address），
/// 连接型套接字会拒绝发往新地址的报文。本项目只做客户端、quinn 也未启用该迁移，暂不构成问题；
/// QUIC 本身没有多播上游，所以不像 UDP 那条路需要给多播开豁免。
#[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
fn prepare_quic_socket(
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    so_mark: Option<u32>,
    device: Option<String>,
) -> io::Result<std::net::UdpSocket> {
    let socket = next_random_udp(local_addr)?;

    // 🌟 绝杀：为 QUIC/H3 的底层 UDP 套接字强行打上 SO_MARK 和 Bind Device！
    // 从此再也没有流量能偷偷溜出 VPN 透明代理或策略路由了。
    setup_socket(&socket, None, so_mark, device);

    if let Err(err) = socket.connect(server_addr) {
        crate::log::warn!(
            "failed to connect the QUIC socket to upstream {server_addr}, \
             source filtering is OFF for this upstream: {err}"
        );
    }

    Ok(socket)
}

#[cfg(all(test, any(feature = "dns-over-quic", feature = "dns-over-h3")))]
mod p1_9_quic_source_filter_tests {
    use super::*;

    /// P1-9 的同款收口：DoQ/DoH3 的底层 UDP 套接字必须 connect 到上游 ——
    /// 内核只放行该上游 IP + 端口发来的报文，同时**发送/接收本身照常可用**
    /// （quinn 仍要能跟这个对端收发，不能把上游弄成"连上但发不出去"）。
    #[test]
    fn test_quic_socket_is_connected_and_filters_sources() {
        const WAIT: std::time::Duration = std::time::Duration::from_millis(5);

        let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let socket = prepare_quic_socket("0.0.0.0:0".parse().unwrap(), upstream_addr, None, None)
            .expect("prepare_quic_socket 应成功");

        // ① 机制：确实连到了上游（未连接的套接字 peer_addr() 会报错）
        assert_eq!(
            socket.peer_addr().expect("DoQ/DoH3 套接字必须已 connect"),
            upstream_addr,
            "P1-9：DoQ/DoH3 的底层套接字必须 connect 到上游，否则谁来敲门都收"
        );

        socket.set_nonblocking(true).unwrap();
        let local = socket.local_addr().unwrap();
        let mut buf = [0u8; 64];

        // ② 功能：上游发来的包必须收得到
        upstream.send_to(b"ok", local).unwrap();
        let mut got = None;
        for _ in 0..40 {
            match socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    got = Some(n);
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(WAIT);
                }
                Err(e) => panic!("收包异常：{e}"),
            }
        }
        assert_eq!(got, Some(2), "上游发来的报文必须能正常收到");

        // ③ 效果：第三方来源（同机、只是端口不同）的伪造包必须被内核丢弃
        let attacker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        attacker.send_to(b"forged", local).unwrap();
        let mut leaked = false;
        for _ in 0..30 {
            match socket.recv_from(&mut buf) {
                Ok(_) => {
                    leaked = true;
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(WAIT);
                }
                Err(e) => panic!("收包异常：{e}"),
            }
        }
        assert!(
            !leaked,
            "来源不符的报文必须被内核丢弃（这就是本项要的效果）"
        );
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
                    crate::async_socks5::AddrKind::Ip(addr) => addr,
                    crate::async_socks5::AddrKind::Domain(_, _) => {
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
            // 🔐 P1-9 的配套修复（2026-09-18）：直连 UDP 上游的套接字已由本文件的 `bind_udp()`
            // connect() 到该上游（内核按源 IP + 源端口过滤伪造应答），而这里依旧按"带地址发送"
            // 调用 `sendto()`。POSIX 允许已连接的数据报套接字再带地址发送（Linux / Windows 如此），
            // 但 **macOS / BSD 直接返回 EISCONN**（errno 56，"Socket is already connected"）——
            // 结果是 macOS 上所有直连 UDP 上游都发不出去（CI 的 macOS 真机测试因此全挂）。
            // 两种做法语义完全等价（对端就是 connect 的那个地址），故遇到 EISCONN 时退回不带地址的
            // `send()`；多播上游（mDNS 等）本就没有 connect，走的仍是原路径，不受影响。
            UdpSocket::Tokio(s) => {
                let res = tokio::net::UdpSocket::poll_send_to(s, cx, buf, target);
                if let Poll::Ready(Err(err)) = &res {
                    if is_eisconn(err) {
                        return tokio::net::UdpSocket::poll_send(s, cx, buf);
                    }
                }
                res
            }
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
                    crate::async_socks5::AddrKind::Ip(addr) => addr,
                    crate::async_socks5::AddrKind::Domain(_, _) => {
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
            // 🔐 上游查询实际走的就是这个入口（内嵌 hickory 的 `udp/udp_client_stream.rs`
            // 里 `socket.send_to(bytes, addr)`，错误直接向上抛）。直连 UDP 上游的套接字已由
            // `bind_udp()` connect 到上游（P1-9 的防伪造应答），此时再带地址发送，
            // macOS / BSD 返回 EISCONN（errno 56），Linux / Windows 允许 —— 见 `is_eisconn`。
            Tokio(s) => match s.send_to(buf, target).await {
                Ok(n) => Ok(n),
                Err(err) if is_eisconn(&err) => s.send(buf).await,
                Err(err) => Err(err),
            },
            Proxy(s) => s
                .send_to(buf, target)
                .await
                .map_err(|err| io::Error::other(err.to_string())),
        }
    }
}

/// macOS / BSD 对"已连接的 UDP 套接字再带地址发送"返回 EISCONN（errno 56，
/// "Socket is already connected"），Linux / Windows 则允许带地址发送。
///
/// 背景：P1-9 把直连 UDP 上游的套接字 `connect()` 到上游，让内核过滤掉其他来源的应答；
/// 此后发送仍按"带地址"调用。两种做法语义完全等价（对端就是 `connect` 的那个地址），
/// 因此这里识别出 EISCONN 后，调用方退回**不带地址**的 `send()`。
///
/// 影响面：仅当套接字处于已连接状态才会命中；多播上游（mDNS 等）刻意不 connect，
/// 走的仍是原来的带地址发送，不受影响。
#[cfg(unix)]
fn is_eisconn(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EISCONN)
}

#[cfg(not(unix))]
fn is_eisconn(_err: &io::Error) -> bool {
    false
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

/// 🔐 Q15：DoH（https / h3）请求头里的 Host（`:authority`）。
///
/// 规则与 C 版一致（`src/utils/misc.c:274` 的 `set_http_host` +
/// `src/dns_client/server_info.c:348`）：
/// * 用户写了 `-http-host` → 原样用（他写什么发什么）；
/// * 地址写的是**域名** → 就用域名，**不带端口**；
/// * 地址写的是 **IP** → 写 `IP` 或 `IP:端口`（IPv6 加方括号；端口是 443 就省掉）。
///
/// 注意与 TLS 的 SNI 分开：SNI 始终是地址里的名字，这里的 Host 可以被 `-http-host` 改掉。
fn http_authority(server: &DnsUrl, server_name: &Arc<str>, port: u16) -> Arc<str> {
    if let Some(host) = server.http_host() {
        return host;
    }

    match server.host() {
        // 域名：原样，不带端口（与 C 版一致）
        Host::Domain(_) => Arc::clone(server_name),
        Host::Ipv4(_) | Host::Ipv6(_) => {
            let ip = server_name;
            let bracketed = matches!(server.host(), Host::Ipv6(_));

            let base = if bracketed {
                format!("[{ip}]")
            } else {
                ip.to_string()
            };

            if port == 443 {
                Arc::from(base.as_str())
            } else {
                Arc::from(format!("{base}:{port}").as_str())
            }
        }
    }
}

#[cfg(test)]
mod p1_9_direct_udp_tests {
    use super::*;
    use crate::libdns::proto::runtime::RuntimeProvider;
    use crate::libdns::proto::udp::DnsUdpSocket;
    use std::ops::Deref;
    use std::time::Duration;

    /// macOS 回归点（CI 2026-09-18 实测）：直连 UDP 上游的套接字已被 `bind_udp()` connect 到上游，
    /// 此时再按"带地址发送"调用 `send_to`，macOS / BSD 返回 EISCONN（errno 56），Linux / Windows 允许。
    /// 这条用例走的正是上游查询的真实入口（内嵌 hickory 的 `udp/udp_client_stream.rs` 调的就是
    /// `socket.send_to(bytes, addr)`）：修复前在 macOS 上必然失败，修复后各平台一致。
    #[tokio::test]
    async fn test_connected_socket_can_send_with_address() {
        // 假上游（本机的一个 UDP 端口）
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        // 客户端套接字：先 connect 到上游（等价于 bind_udp() 里的 P1-9 动作）
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(upstream_addr).await.unwrap();
        let socket = UdpSocket::Tokio(client);

        // 已连接的套接字上"带地址发送"：macOS 会报 EISCONN，交给 send_to 里的回退处理
        let sent = socket.send_to(b"ping", upstream_addr).await.unwrap();
        assert_eq!(sent, 4);

        let mut buf = [0u8; 8];
        let (len, _from) = upstream.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
    }

    /// P1-9：直连 UDP 上游的套接字必须真的 connect ——
    /// 这样内核只放行该上游 IP + 端口发来的报文，杜绝伪造应答注入。
    #[tokio::test]
    async fn test_direct_upstream_socket_is_connected_and_filters_sources() {
        let provider = TokioRuntimeProvider::new(None, None, None);

        // 假上游（本机的一个 UDP 端口）
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let socket = provider
            .bind_udp("0.0.0.0:0".parse().unwrap(), upstream_addr)
            .await
            .expect("bind_udp 应成功");

        // ① 机制：已连接到上游（未连接的套接字 peer_addr 会报错）
        assert_eq!(
            socket
                .deref()
                .peer_addr()
                .expect("直连上游套接字必须已 connect"),
            upstream_addr,
            "P1-9：直连 UDP 上游套接字必须 connect 到该上游"
        );

        // ② 效果：上游发来的包能正常收到（功能没被 connect 弄坏）
        let local = socket.deref().local_addr().unwrap();
        upstream.send_to(b"ok", local).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .expect("应当能收到上游的应答")
            .unwrap();
        assert_eq!(&buf[..n], b"ok");

        // ③ 效果：第三方来源（同机、只是端口不同）的伪造包必须被内核丢弃
        let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker.send_to(b"forged", local).await.unwrap();
        let res =
            tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await;
        assert!(res.is_err(), "来源不符的报文必须被丢弃，实际收到 {res:?}");
    }

    /// 多播（mDNS 等）必须排除在 connect 之外：它本来就允许多个来源。
    #[tokio::test]
    async fn test_multicast_upstream_is_not_connected() {
        let provider = TokioRuntimeProvider::new(None, None, None);
        let socket = provider
            .bind_udp(
                "0.0.0.0:0".parse().unwrap(),
                "224.0.0.251:5353".parse().unwrap(),
            )
            .await
            .expect("bind_udp 应成功");
        assert!(
            socket.deref().peer_addr().is_err(),
            "多播上游不能被 connect，否则 mDNS 会彻底失效"
        );
    }
}
