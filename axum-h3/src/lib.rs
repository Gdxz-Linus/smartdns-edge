//! HTTP/3 server adapter for [axum], built on the [h3] crate.
//!
//! Developed as part of [`tonic-h3`]. This crate serves an [`axum::Router`]
//! over HTTP/3 by accepting QUIC connections and dispatching each request
//! to the router.
//!
//! # ⚠️ 本项目（smartdns-edge）的本地改动
//!
//! 见仓库根的 `axum-h3/VENDORED.md`。这里是与上游 0.0.6 的**唯一差别**：
//!
//! **把客户端对端地址注入每个请求**，让下游能像 HTTP/1、HTTP/2 路径那样用
//! `axum::extract::ConnectInfo<SocketAddr>` 拿到真实来源 IP。
//!
//! 上游至今没做这件事（本文件下面原本有一行
//! `.add_extension(Arc::new(ConnInfo { .. }))`，从 0.0.1 到 0.0.6 一直是注释状态），
//! 后果是 DoH3 路径上"基于客户端 IP 的规则"完全不生效、审计日志里的来源地址失真。
//!
//! 另外把 acceptor 的抽象从上游 `h3_util::server::H3Acceptor` 换成了本文件里的
//! [`PeerAcceptor`]：因为 `h3_quinn::Connection` 把内部的 `quinn::Connection` 藏了起来，
//! 从外面拿不到对端地址，只能在"接受连接"的那一步顺手记下来。
//!
//! [axum]: https://github.com/tokio-rs/axum
//! [h3]: https://github.com/hyperium/h3
//! [`tonic-h3`]: https://github.com/youyuanwu/tonic-h3

use std::future::Future;
use std::net::SocketAddr;

use axum::body::Bytes;
use h3_util::{executor::SharedExec, server_body::H3IncomingServer};
use hyper::{Request, Response, body::Body, rt::Executor};

/// 🔐 本地改动：接受 QUIC 连接的抽象。
///
/// 与上游 [`h3_util::server::H3Acceptor`] 的唯一区别是 `accept` 会**一并返回对端地址**
/// （拿不到时为 `None`），供上层注入 `ConnectInfo<SocketAddr>`。
pub trait PeerAcceptor {
    type CONN: h3::quic::Connection<
            Bytes,
            OpenStreams = Self::OS,
            SendStream = Self::SS,
            RecvStream = Self::RS,
            BidiStream = Self::BS,
        > + Send
        + 'static;
    type OS: h3::quic::OpenStreams<Bytes, BidiStream = Self::BS> + Clone + Send;
    type SS: h3::quic::SendStream<Bytes> + Send;
    type RS: h3::quic::RecvStream + Send + 'static;
    type BS: h3::quic::BidiStream<Bytes, RecvStream = Self::RS, SendStream = Self::SS>
        + Send
        + 'static;

    fn accept(
        &mut self,
    ) -> impl Future<Output = Result<Option<(Self::CONN, Option<SocketAddr>)>, h3_util::Error>> + Send;
}

/// Accept each connection from acceptor, then for each connection
/// accept each request. Spawn a task to handle each request.
async fn serve_inner<AC, F>(
    svc: axum::Router,
    executor: &SharedExec,
    mut acceptor: AC,
    signal: F,
) -> Result<(), h3_util::Error>
where
    AC: PeerAcceptor,
    F: Future<Output = ()>,
{
    let svc = tower::ServiceBuilder::new().service(svc);

    let h_svc = hyper_util::service::TowerToHyperService::new(svc);

    let mut sig = std::pin::pin!(signal);
    tracing::trace!("loop start");
    loop {
        tracing::trace!("loop");
        let conn = tokio::select! {
            res = acceptor.accept() => match res {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!("accept error : {e}");
                    return Err(e);
                }
            },
            _ = &mut sig => {
                tracing::trace!("cancellation triggered");
                return Ok(());
            }
        };

        let Some((conn, peer)) = conn else {
            tracing::trace!("acceptor end of conn");
            return Ok(());
        };

        // server each connection in the background
        let h_svc_cp = h_svc.clone();
        let executor_clone = executor.clone();
        executor.execute(async move {
            let mut conn = match h3::server::Connection::new(conn).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("server connection failed: {}", e);
                    return;
                }
            };
            loop {
                let resolver = match conn.accept().await {
                    Ok(req) => match req {
                        Some(r) => r,
                        None => {
                            tracing::trace!("server connection ended:");
                            break;
                        }
                    },
                    Err(e) => {
                        if e.is_h3_no_error() {
                            tracing::trace!("server connection ended with h3 no error:");
                        } else {
                            tracing::warn!("server connection accept failed: {}", e);
                        }
                        break;
                    }
                };
                let h_svc_cp = h_svc_cp.clone();
                executor_clone.execute(async move {
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(req) => req,
                        Err(e) => {
                            tracing::warn!("fail resolve request {e:#?}");
                            return;
                        }
                    };
                    if let Err(e) = serve_request::<AC, _, _>(req, stream, h_svc_cp.clone(), peer).await
                    {
                        tracing::warn!("server request failed: {}", e);
                    }
                });
            }
        });
    }
}

async fn serve_request<AC, SVC, BD>(
    request: Request<()>,
    stream: h3::server::RequestStream<
        <<AC as PeerAcceptor>::CONN as h3::quic::OpenStreams<Bytes>>::BidiStream,
        Bytes,
    >,
    service: SVC,
    peer: Option<SocketAddr>,
) -> Result<(), h3_util::Error>
where
    AC: PeerAcceptor,
    SVC: hyper::service::Service<
            Request<H3IncomingServer<AC::RS, Bytes>>,
            Response = Response<BD>,
            Error = std::convert::Infallible,
        >,
    SVC::Future: 'static,
    BD: Body + 'static,
    BD::Error: Into<h3_util::Error>,
    <BD as Body>::Error: Into<h3_util::Error> + std::error::Error + Send + Sync,
    <BD as Body>::Data: Send + Sync,
{
    tracing::trace!("serving request");
    let (mut parts, _) = request.into_parts();

    // 🔐 本地改动：把对端地址放进请求扩展 —— axum 的 `ConnectInfo<SocketAddr>` 提取器
    // 读的正是这个扩展（`axum::serve` 在 HTTP/1、HTTP/2 路径上也是这么注入的）。
    if let Some(addr) = peer {
        parts.extensions.insert(axum::extract::ConnectInfo(addr));
    }

    let (mut w, r) = stream.split();

    let req = Request::from_parts(parts, H3IncomingServer::new(r));
    tracing::trace!("serving request call service");
    let res = service.call(req).await?;

    let (res_h, res_b) = res.into_parts();

    // write header
    tracing::trace!("serving request write header");
    w.send_response(Response::from_parts(res_h, ())).await?;

    // write body or trailer.
    h3_util::server_body::send_h3_server_body::<BD, AC::BS>(&mut w, res_b).await?;

    tracing::trace!("serving request end");
    Ok(())
}

pub struct H3Router {
    inner: axum::Router,
    executor: SharedExec, // expose this for the user.
}

impl H3Router {
    pub fn new(inner: axum::Router) -> Self {
        Self {
            inner,
            executor: SharedExec::tokio(),
        }
    }
}

impl From<axum::Router> for H3Router {
    fn from(value: axum::Router) -> Self {
        Self::new(value)
    }
}

impl H3Router {
    /// Runs the service on acceptor until shutdown.
    pub async fn serve_with_shutdown<AC, F>(
        self,
        acceptor: AC,
        signal: F,
    ) -> Result<(), h3_util::Error>
    where
        AC: PeerAcceptor,
        F: Future<Output = ()>,
    {
        serve_inner(self.inner, &self.executor, acceptor, signal).await
    }

    /// Runs all services on acceptor
    pub async fn serve<AC>(self, acceptor: AC) -> Result<(), h3_util::Error>
    where
        AC: PeerAcceptor,
    {
        self.serve_with_shutdown(acceptor, async {
            // never returns
            futures::future::pending().await
        })
        .await
    }
}
