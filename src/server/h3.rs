use axum_h3::H3Router;

use quinn::{Endpoint, ServerConfig, TokioRuntime, crypto::rustls::QuicServerConfig};
use quinn::{TransportConfig, VarInt};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net;
use tokio_util::sync::CancellationToken;

use super::DnsHandle;

use crate::{
    api::ServeState,
    app::App,
    log,
    rustls::{ResolvesServerCert, tls_server_config},
};

pub fn serve(
    app: App,
    socket: net::UdpSocket,
    dns_handle: DnsHandle,
    api_enabled: bool,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<CancellationToken> {
    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    log::debug!("registered HTTP/3: {:?}", socket);

    let tls_config = tls_server_config(b"h3", server_cert_resolver)
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?;

    let server_config = {
        // 🔐 P2：原来这里是 `.unwrap()` —— TLS 配置一旦不被 QUIC 接受就直接 panic 崩掉整个进程，
        // 而 DoT/DoH 路径遇到同类失败都是干净报错。这里改成同样的干净报错。
        let crypto = QuicServerConfig::try_from(tls_config)
            .map_err(|e| io::Error::other(format!("error creating QUIC server config: {e}")))?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));

        server_config.transport_config(Arc::new(transport()));
        server_config
    };

    // 🔐 A6（2026-09-17）：逐监听连接数上限需要监听地址 —— socket 随后会被移交，先在这里取出来。
    // 与 DoQ / DoT / DoH / HTTP / TCP 那几条监听的做法一致（对应 `bind-h3 ... -max-connections N`）。
    let listener_limiter = socket
        .local_addr()
        .ok()
        .and_then(crate::server::limit::for_listener);

    let config = Default::default();
    let endpoint = Endpoint::new(
        config,
        Some(server_config),
        socket.into_std()?,
        Arc::new(TokioRuntime),
    )?;

    let state = Arc::new(ServeState { app, dns_handle });

    // 🔐 P2：DoH3 现在能拿到客户端真实来源地址了 —— 内嵌的 axum-h3（见 axum-h3/VENDORED.md）
    // 会把对端地址注入每个请求，下游照常用 `ConnectInfo<SocketAddr>` 提取，
    // 与 HTTP/1、HTTP/2 路径完全一致（基于 IP 的规则、审计日志都恢复正常）。
    let router = (if api_enabled {
        crate::api::routes()
    } else {
        crate::api::dns_only_routes()
    })
    .with_state(state.clone());
    let router = H3Router::new(router);

    let acceptor = QuinnPeerAcceptor::new(endpoint, listener_limiter);

    tokio::spawn(async move {
        if let Err(err) = router
            .serve_with_shutdown(acceptor, cancellation_token.cancelled())
            .await
        {
            crate::log::warn!("HTTP/3 连接处理失败（已忽略该连接）: {err:#}");
        }
    });

    Ok(token)
}

/// 🔐 P2：我们自己的 QUIC acceptor。
///
/// 与 h3-util 的 `H3QuinnAcceptor` 等价，但**额外把每个连接的对端地址带出来** ——
/// `h3_quinn::Connection` 把内部的 `quinn::Connection` 藏了起来（没有公开访问器），
/// 所以"接受连接"这一步是唯一能拿到客户端地址的时机。
struct QuinnPeerAcceptor {
    endpoint: Endpoint,
    /// 🔐 A6：该监听单独配置的连接上限（`bind-h3 ... -max-connections*` 才有；没配就是 None）。
    /// 全局限额（按物理内存自动推算）另外单独取。
    listener_limiter: Option<Arc<crate::server::limit::ConnectionLimiter>>,
}

impl QuinnPeerAcceptor {
    fn new(
        endpoint: Endpoint,
        listener_limiter: Option<Arc<crate::server::limit::ConnectionLimiter>>,
    ) -> Self {
        Self {
            endpoint,
            listener_limiter,
        }
    }
}

impl axum_h3::PeerAcceptor for QuinnPeerAcceptor {
    type CONN = h3_quinn::Connection;
    type OS = h3_quinn::OpenStreams;
    type SS = h3_quinn::SendStream<axum::body::Bytes>;
    type RS = h3_quinn::RecvStream;
    type BS = h3_quinn::BidiStream<axum::body::Bytes>;

    async fn accept(&mut self) -> Result<Option<(Self::CONN, Option<SocketAddr>)>, h3_util::Error> {
        loop {
            let Some(incoming) = self.endpoint.accept().await else {
                // endpoint 已关闭
                return Ok(None);
            };

            match incoming.await {
                Ok(conn) => {
                    let peer = conn.remote_address();

                    // 🔐 A6（2026-09-17）：连接数上限。DoH3 以前是**唯一没有闸门**的监听，
                    // 攻击者可以无限开 QUIC 连接；现在与其它五条监听同口径：
                    // ① 全局限额（按物理内存自动推算，家庭小机器自动收紧、企业机器自动放宽）
                    // ② 该监听单独配置的那一份（`bind-h3 ... -max-connections N`）
                    // 超出就丢弃这次新连接，**不影响已有连接**（与 DoQ/DoT/DoH 一致）。
                    // 计数位置也与 DoQ 一致：握手完成之后才占名额，没握完的不算。
                    let Some(conn_guard) = crate::server::limit::global().acquire(peer.ip()) else {
                        log::debug!("DoH3 连接数超出上限，拒绝 {peer} 的新连接");
                        continue;
                    };
                    let listener_guard = match self.listener_limiter.as_ref() {
                        Some(limiter) => match limiter.acquire(peer.ip()) {
                            Some(guard) => Some(guard),
                            None => {
                                log::debug!("DoH3 该监听连接数超限，拒绝 {peer} 的新连接");
                                continue; // 全局限额随作用域结束自动归还
                            }
                        },
                        None => None,
                    };

                    // 配额要活到这条连接结束为止：accept() 之后连接就交给 axum-h3 了，
                    // 我们拿不到 Drop 时机，所以克隆一份 quinn 连接、起个守护任务等它关闭 ——
                    // 连接一关（对端断开或 endpoint 关闭），两份配额自动归还。
                    {
                        let watcher = conn.clone();
                        tokio::spawn(async move {
                            let _conn_guard = conn_guard;
                            let _listener_guard = listener_guard;
                            let _ = watcher.closed().await;
                        });
                    }

                    return Ok(Some((h3_quinn::Connection::new(conn), Some(peer))));
                }
                Err(err) => {
                    // 单个连接握手失败不该拖垮整个监听（与上游行为一致：记录后继续）
                    log::warn!("DoH3 连接建立失败，已忽略：{err}");
                    continue;
                }
            }
        }
    }
}

/// Returns a default endpoint configuration for DNS-over-H3
fn transport() -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    transport_config.datagram_receive_buffer_size(None);
    transport_config.datagram_send_buffer_size(0);
    // clients never accept new bidirectional streams
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(16));
    // - SETTINGS
    // - QPACK encoder
    // - QPACK decoder
    // - RESERVED (GREASE)
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(16));

    transport_config
}
