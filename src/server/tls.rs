use std::{io, sync::Arc, time::Duration};

use futures_util::StreamExt as _;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{DnsHandle, reap_tasks, sanitize_src_address};

use crate::{
    dns::SerialMessage,
    libdns::{
        Protocol,
        proto::{runtime::iocompat::AsyncIoTokioAsStd, xfer::DnsStreamHandle as _},
    },
    log,
    rustls::ResolvesServerCert,
    third_ext::FutureTimeoutExt,
};

pub fn serve(
    listener: net::TcpListener,
    handler: DnsHandle,
    timeout: Duration,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    first_packet_timeout: Option<std::time::Duration>,
) -> io::Result<CancellationToken> {
    use crate::libdns::proto::rustls::tls_from_stream;
    use crate::rustls::tls_server_config;
    use tokio_rustls::TlsAcceptor;

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    let tls_config = tls_server_config(b"dot", server_cert_resolver)
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?;

    let handler = handler.clone();

    log::debug!(
        "TLS listener successfully registered on {}",
        listener.local_addr().unwrap()
    );

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tokio::spawn(async move {
        // 🔐 逐监听连接上限（若该监听单独配了 max-connections*，与全局限额同时生效）
        let listener_limiter = listener
            .local_addr()
            .ok()
            .and_then(crate::server::limit::for_listener);

        let mut inner_join_set = JoinSet::new();
        loop {
            let (tcp_stream, src_addr) = tokio::select! {
                tcp_stream = listener.accept() => match tcp_stream {
                    Ok((t, s)) => (t, s),
                    Err(e) => {
                        log::debug!("error receiving TLS tcp_stream error: {}", e);
                        continue;
                    },
                },
                _ = cancellation_token.cancelled() => {
                    // A graceful shutdown was initiated. Break out of the loop.
                    break;
                },
            };

            // verify that the src address is safe for responses
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!(
                    "address can not be responded to {src_addr}: {e}",
                    src_addr = src_addr,
                    e = e
                );
                continue;
            }

            // 🔐 P0-5：连接数上限。超出预算就拒绝新连接（不影响已有连接），保护进程内存。
            // 默认上限按物理内存自动推算：家庭小机器自动收紧，企业大机器自动放宽。
            let Some(conn_guard) = crate::server::limit::global().acquire(src_addr.ip()) else {
                log::debug!("global connection limit reached; refusing the new connection from {src_addr}");
                continue;
            };

            // 🔐 该监听自身（若单独配置过）的限额也要通过
            let listener_guard = match listener_limiter.as_ref() {
                Some(l) => match l.acquire(src_addr.ip()) {
                    Some(guard) => Some(guard),
                    None => {
                        log::debug!("per-listener connection limit reached; refusing the new connection from {src_addr}");
                        continue;
                    }
                },
                None => None,
            };

            let handler = handler.clone();
            let tls_acceptor = tls_acceptor.clone();

            // kick out to a different task immediately, let them do the TLS handshake
            inner_join_set.spawn(async move {
                let _conn_guard = conn_guard; // 连接结束时自动归还配额
                let _listener_guard = listener_guard;
                log::debug!("starting TLS request from: {}", src_addr);

                // perform the TLS
                // 🌟 核心修复：为 TLS 握手套上 5 秒绝对枷锁，防 Slowloris 半连接耗尽资源攻击！
                let tls_stream =
                    tokio::time::timeout(Duration::from_secs(5), tls_acceptor.accept(tcp_stream))
                        .await;

                let tls_stream = match tls_stream {
                    Ok(Ok(tls_stream)) => AsyncIoTokioAsStd(tls_stream),
                    Ok(Err(e)) => {
                        log::debug!("tls handshake src: {} error: {}", src_addr, e);
                        return;
                    }
                    Err(_) => {
                        // 超时拦截
                        log::debug!("tls handshake src: {} timeout (dropped)", src_addr);
                        return;
                    }
                };
                log::debug!("accepted TLS request from: {}", src_addr);
                let (mut buf_stream, stream_handle) = tls_from_stream(tls_stream, src_addr);

                // 🌟 核心修复：单连接并发数上限 (防 Pipelining 任务爆炸与 OOM)
                let conn_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(200));

                // 🔐 P0-5：连接建立后，"第一个完整报文"必须在首包超时内到达；之后回落到空闲超时。
                // 攻击者"只发长度前缀、不发正文"的路子会被迅速切断，长连接复用不受影响。
                let mut is_first_packet = true;
                loop {
                    let wait = if is_first_packet {
                        first_packet_timeout.unwrap_or(timeout)
                    } else {
                        timeout
                    };
                    let next = buf_stream.next().timeout(wait).await;
                    is_first_packet = false;
                    let message = match next {
                        Ok(Some(Ok(message))) => message,
                        Ok(Some(Err(e))) => {
                            log::debug!(
                                "error in DNS request_stream src: {} error: {}",
                                src_addr,
                                e
                            );
                            return; // 网络中断，断开连接
                        }
                        Ok(None) => break,
                        Err(_) => {
                            log::debug!("timed out waiting for a DNS message; closing the connection: {}", src_addr);
                            return;
                        }
                    };

                    // 🚦 申请并发许可，超限触发底层网络层面的背压
                    let permit = match conn_semaphore.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    let (bytes, addr) = message.into_parts();
                    let req_message = SerialMessage::binary(bytes, addr, Protocol::Tls);

                    let handler = handler.clone();
                    let mut stream_handle = stream_handle.clone();

                    tokio::spawn(async move {
                        let _permit = permit; // 🌟 绑定许可的生命周期
                        let res_message = handler.send(req_message).await;

                        if let Err(err) = res_message
                            .try_into()
                            .map(|buffer| stream_handle.send(buffer))
                        {
                            log::trace!("TLS stream sending failed: {:?}", err);
                        }
                    });
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    Ok(token)
}
