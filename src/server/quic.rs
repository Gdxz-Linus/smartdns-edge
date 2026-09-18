use std::{io, sync::Arc, time::Duration};

use crate::rustls::ResolvesServerCert;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{DnsHandle, reap_tasks, sanitize_src_address};

use crate::{dns::SerialMessage, libdns::Protocol, log};

pub fn serve(
    socket: net::UdpSocket,
    handler: DnsHandle,
    _timeout: Duration,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    _dns_hostname: Option<String>,
    first_packet_timeout: Option<std::time::Duration>,
) -> io::Result<CancellationToken> {
    use crate::libdns::proto::quic::{DoqErrorCode, QuicServer};

    log::debug!("registered quic: {:?}", socket);

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    // 🔐 逐监听限额需要监听地址：socket 随后会被移交，先在这里取出来
    let listener_local_addr = socket.local_addr().ok();
    let mut server = QuicServer::with_socket(socket, server_cert_resolver)?;

    tokio::spawn(async move {
        // 🔐 逐监听连接上限（若该监听单独配了 max-connections*，与全局限额同时生效）
        let listener_limiter = listener_local_addr.and_then(crate::server::limit::for_listener);

        let mut inner_join_set = JoinSet::new();
        loop {
            let (mut quic_streams, src_addr) = tokio::select! {
                result = server.next() => match result {
                    Ok(Some(c)) => c,
                    Ok(None) => continue,
                    Err(e) => {
                        log::debug!("error receiving quic connection: {e}");
                        continue;
                    }
                },
                _ = cancellation_token.cancelled() => {
                    // A graceful shutdown was initiated. Break out of the loop.
                    break;
                },
            };

            // verify that the src address is safe for responses
            // TODO: we're relying the quinn library to actually validate responses before we get here, but this check is still worth doing
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
                log::debug!("连接数超出上限，拒绝 {src_addr} 的新连接");
                continue;
            };

            // 🔐 该监听自身（若单独配置过）的限额也要通过
            let listener_guard = match listener_limiter.as_ref() {
                Some(l) => match l.acquire(src_addr.ip()) {
                    Some(guard) => Some(guard),
                    None => {
                        log::debug!("该监听连接数超限，拒绝 {src_addr} 的新连接");
                        continue;
                    }
                },
                None => None,
            };

            let handler = handler.clone();
            let cancellation_token = cancellation_token.clone();

            inner_join_set.spawn(async move {
                let _conn_guard = conn_guard; // 连接结束时自动归还配额
                let _listener_guard = listener_guard;
                log::debug!("starting quic stream request from: {src_addr}");

                // 🔐 P0-5：单条 QUIC 连接允许的子流数。原值 100 会让一条连接最坏占到
                // 100 × 64 KiB ≈ 6.4 MiB；配合按需分配后单流占用已很小，
                // 这里再收紧到 32：对任何正常 DoQ 客户端的并发都绰绰有余。
                let mut max_requests = 32u32;

                // Accept all inbound quic streams sent over the connection.
                loop {
                    let mut request_stream = tokio::select! {
                        result = quic_streams.next() => match result {
                            Some(Ok(next_request)) => next_request,
                            Some(Err(err)) => {
                                log::warn!("error accepting request {}: {}", src_addr, err);
                                break;
                            }
                            None => break,
                        },
                        _ = cancellation_token.cancelled() => break,
                    };

                    let handler = handler.clone();

                    // 🌟 核心修复：拿到一个新的 QUIC Stream 后，立刻派发后台处理！
                    // 主循环秒级回归，疯狂接收该 QUIC 连接发来的下一个并发查询流，彻底实现 QUIC 多路复用。
                    tokio::spawn(async move {
                        // 🔐 P0-5：单条子流的"首包"同样要限时——
                        // 否则只发 2 字节长度前缀就能长期占住这条流（DoQ 是最便宜的放大面）。
                        let read_result = match first_packet_timeout {
                            Some(t) => {
                                match tokio::time::timeout(t, request_stream.receive_bytes()).await
                                {
                                    Ok(r) => r,
                                    Err(_) => {
                                        log::debug!("QUIC 子流首包超时，关闭该子流: {src_addr}");
                                        let _ = request_stream.stop(DoqErrorCode::NoError);
                                        return;
                                    }
                                }
                            }
                            None => request_stream.receive_bytes().await,
                        };
                        let bytes = match read_result {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                log::warn!("error receiving bytes {}", err);
                                // 🌟 核心修复：即使读取失败，也必须显式向操作系统和内核宣告关闭该 QUIC 子流！
                                // 否则底层的 Quinn 状态机将永远残留，导致僵尸 Stream 最终耗尽服务器内存。
                                let _ = request_stream.stop(DoqErrorCode::NoError);
                                return; // 局部流接收失败，仅退出当前流，保持主 QUIC 连接不断！
                            }
                        };

                        log::debug!("Received bytes {} from {src_addr} {bytes:?}", bytes.len());

                        let req_message = SerialMessage::binary(bytes, src_addr, Protocol::Quic);
                        let res_message = handler.send(req_message).await;

                        if let Err(err) = match res_message.try_into() {
                            Ok(buffer) => request_stream.send_bytes(buffer).await,
                            Err(err) => Err(err),
                        } {
                            log::trace!("quic stream processing failed from {src_addr}: {err}");
                        }

                        // DOQ_NO_ERROR (0x0): No error. 完美关闭当前子流。
                        let _ = request_stream.stop(DoqErrorCode::NoError);
                    });

                    max_requests -= 1;

                    if max_requests == 0 {
                        log::warn!(
                            "exceeded max request count (32), shutting down quic conn: {src_addr}"
                        );
                        break; // 触发反滥用机制，关闭整个 QUIC 连接
                    }
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    Ok(token)
}
