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
    }).with_state(state.clone());
    let router = H3Router::new(router);

    let acceptor = QuinnPeerAcceptor::new(endpoint);

    tokio::spawn(async move {
        if let Err(err) = router
            .serve_with_shutdown(acceptor, cancellation_token.cancelled())
            .await
        {
            eprintln!("failed to serve connection: {err:#}");
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
}

impl QuinnPeerAcceptor {
    fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }
}

impl axum_h3::PeerAcceptor for QuinnPeerAcceptor {
    type CONN = h3_quinn::Connection;
    type OS = h3_quinn::OpenStreams;
    type SS = h3_quinn::SendStream<axum::body::Bytes>;
    type RS = h3_quinn::RecvStream;
    type BS = h3_quinn::BidiStream<axum::body::Bytes>;

    async fn accept(
        &mut self,
    ) -> Result<Option<(Self::CONN, Option<SocketAddr>)>, h3_util::Error> {
        loop {
            let Some(incoming) = self.endpoint.accept().await else {
                // endpoint 已关闭
                return Ok(None);
            };

            match incoming.await {
                Ok(conn) => {
                    let peer = conn.remote_address();
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
