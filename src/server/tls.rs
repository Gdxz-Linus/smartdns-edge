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
) -> io::Result<CancellationToken> {
    use crate::libdns::proto::rustls::tls_from_stream;
    use crate::rustls::tls_server_config;
    use tokio_rustls::TlsAcceptor;

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    let tls_config = tls_server_config(b"dot", server_cert_resolver)
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?;

    let handler = handler.clone();

    log::debug!("TLS listener successfully registered on {}", listener.local_addr().unwrap());

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tokio::spawn(async move {
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

            let handler = handler.clone();
            let tls_acceptor = tls_acceptor.clone();

            // kick out to a different task immediately, let them do the TLS handshake
            inner_join_set.spawn(async move {
                log::debug!("starting TLS request from: {}", src_addr);

                // perform the TLS
                // 🌟 核心修复：为 TLS 握手套上 5 秒绝对枷锁，防 Slowloris 半连接耗尽资源攻击！
                let tls_stream = tokio::time::timeout(
                    Duration::from_secs(5), 
                    tls_acceptor.accept(tcp_stream)
                ).await;

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

                while let Ok(Some(message)) = buf_stream.next().timeout(timeout).await {
                    let message = match message {
                        Ok(message) => message,
                        Err(e) => {
                            log::debug!("error in TLS request_stream src: {:?} error: {}", src_addr, e);
                            return; // kill this connection
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
